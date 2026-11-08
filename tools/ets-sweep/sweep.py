# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""ETS sweep (epic #419): make ETS download a product into knx-sim and capture it.

    uv run tools/ets-sweep/sweep.py --knxprod <file> --app <application id> --search <order number>
                                    [--ia 1.1.1] [--mode application|full] [--variant plain-defaults]

Per run:
  1. write a knx-sim config with one device (the product, `initial_state: unloaded`)
     and start the simulator, inside the VM by default (see --sim-where);
  2. the sim records its own datagrams to a pcap (gateway.pcap);
  3. ask the ETS driver (tools/ets-sweep/driver) to put the device into the sweep
     project and start a full download onto the sim's gateway;
  4. wait for the sim's load-state events to settle (every loadable object Loaded,
     then no telegram for a quiet period) or a timeout;
  5. stop the sim, fetch the capture, decode with tools/knxtrace.

Outputs: captures/ets-sweep/<app>/<variant>/{sim.yaml,sim.log,ets.pcapng,driver.json,ops.txt}
(captures/ is gitignored). Nothing here links into bussard; knx-sim is a process.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SIM_BIN = REPO / "knx-sim" / "target" / "debug" / "knx-sim"
KNXTRACE = REPO / "tools" / "knxtrace" / "knxtrace.py"
CAPTURES = REPO / "captures" / "ets-sweep"


def write_sim_config(out: Path, knxprod: Path, app: str, ia: str, host: str, port: int, secure: dict | None) -> Path:
    """A knx-sim config for one device; the sim records its own datagrams to
    ets.pcapng next to the config (gateway.pcap), so no sniffer is needed."""
    dev = {
        "address": ia,
        "knxprod": os.path.relpath(knxprod, out),
        "application": app,
        "initial_state": "unloaded",
    }
    if secure:
        dev["security"] = secure
    cfg = {"gateway": {"host": host, "port": port, "tunnel_address": "1.1.254", "pcap": "ets.pcapng"}, "devices": [dev]}
    path = out / "sim.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return path


class Sim:
    """knx-sim as a child process with its log tailed for load-state events."""

    # The sim logs the LoadState as its number: 1 = Loaded, 2 = Loading, 0 = Unloaded.
    LOADED = re.compile(r"load-state changed.*state=\"?(1|Loaded)\b")
    TELEGRAM = re.compile(r"direction=")

    def __init__(self, config: Path, log: Path):
        self.log = log
        self.proc = subprocess.Popen(
            [str(SIM_BIN), str(config)],
            stdout=open(log, "w"),
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info")},
        )
        self.start = time.time()

    ANSI = re.compile(r"\x1b\[[0-9;]*m")

    def lines(self) -> list[str]:
        # tracing-subscriber colours the log even on a pipe; strip before matching.
        return self.ANSI.sub("", self.log.read_text(errors="replace")).splitlines()

    def loaded_objects(self) -> set[str]:
        out = set()
        for line in self.lines():
            if self.LOADED.search(line):
                m = re.search(r"object=(\d+)", line)
                if m:
                    out.add(m.group(1))
        return out

    def last_telegram_age(self) -> float:
        """Seconds since the log last grew (telegrams are the bulk of it)."""
        return time.time() - self.log.stat().st_mtime

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def stale_compat_prompt(error: str) -> bool:
    """Whether ETS's compatibility-mode prompt came before a flow of the
    sweep's own (project_tab, catalog_import, ...) rather than on this
    product's download: the prompt belongs to a device the previous product
    left in the project. The driver checks before every flow; a prompt before
    `catalog_import` went unrecovered and failed ten products in a row within
    seconds (2026-11-05, `M-0006_A-D013-10` onwards)."""
    return "compatibility mode before " in error


def _zip_texts(knxprod: Path, predicate, *, first: bool = False,
               limit: int | None = None) -> list[tuple[str, str]] | None:
    """The members of a product file whose name `predicate` accepts, as
    (name, text) pairs in archive order: only the first with `first`, only
    the first `limit` octets of each with `limit`. None when the file cannot
    be read. The archive is closed on return."""
    import zipfile

    try:
        with zipfile.ZipFile(knxprod) as z:
            out: list[tuple[str, str]] = []
            for name in z.namelist():
                if not predicate(name):
                    continue
                with z.open(name) as fh:
                    raw = fh.read() if limit is None else fh.read(limit)
                out.append((name, raw.decode("utf-8", "replace")))
                if first:
                    break
            return out
    except (OSError, zipfile.BadZipFile):
        return None


def ip_enabled(knxprod: Path, app: str) -> bool:
    """Whether the hardware that carries `app` declares IsIPEnabled. The
    attribute is an xs:boolean, "true" or "1": the older-schema files write
    "1" (the Jung Sonos gateway `M-0004_A-B015-21` in Gesamt_JUNG_ETS5_EN,
    whose sim then lacked the KNXnet/IP object ETS looks for at index 6,
    2026-11-05), and the start tag can run past 600 characters."""
    m = re.match(r"(M-[0-9A-F]{4})_A-(.+)$", app)
    if not m:
        return False
    hp = "_HP-" + m.group(2)
    for _, xml in _zip_texts(knxprod, lambda n: n.endswith("Hardware.xml")) or []:
        for hw in re.finditer(r"<Hardware [^>]*>.*?</Hardware>", xml, re.S):
            start = re.match(r"<Hardware [^>]*>", hw.group(0))
            if hp in hw.group(0) and start and re.search(r'\bIsIPEnabled="(?:true|1)"', start.group(0)):
                return True
    return False


class RemoteSim:
    """knx-sim.exe INSIDE the VM (ETS reaches it on 127.0.0.1, where its ping
    check passes; the Mac's managed firewall drops ping). The process runs over
    a held ssh channel with its log redirected to a file we poll by sftp."""

    LOADED = Sim.LOADED
    ANSI = Sim.ANSI
    EXE = vm.REMOTE_DIR + r"\sim\knx-sim.exe"
    DIR = vm.REMOTE_DIR + r"\sim"

    def __init__(self, c, knxprod: Path, app: str, ia: str, port: int, secure: dict | None, local_log: Path, mask: str = "",
                 properties: list[dict] | None = None, device_options: dict | None = None):
        self.c = c
        self.local_log = local_log
        self.start = time.time()
        vm.run(c, f'mkdir "{self.DIR}"')
        vm.run(c, "taskkill /f /im knx-sim.exe")
        sftp = c.open_sftp()
        remote_prod = f"{self.DIR}/{knxprod.name}".replace("\\", "/")
        try:
            sftp.stat(remote_prod)
        except OSError:
            sftp.put(str(knxprod), remote_prod)
        # The load-state realisation the sim catalog loop uses (bussard-cli
        # tests/it/sim_catalog_loop.rs): memory-mapped on 0701, the property
        # (PID 5) machine elsewhere; it also selects the property-only device
        # model for mask 0021.
        dev = {"address": ia, "knxprod": knxprod.name, "application": app, "initial_state": "unloaded",
               "lsm_access": "memory" if mask == "0701" else "property"}
        if secure:
            dev["security"] = secure
        if properties:
            dev["properties"] = properties
        # Device options a run variant sets (synthetic/capture.py VARIANTS
        # "sim"), e.g. `master_reset: refuse` (#611).
        dev.update(device_options or {})
        if ip_enabled(knxprod, app):
            # Hardware with a KNX IP interface built in: ETS looks for its
            # KNXnet/IP parameter object (type 11) after the download and
            # aborts without it (Zennio ALLinBOX 1612, 2026-10-28).
            # ETS writes as many additional tunnelling addresses (PID 53)
            # as the product declares (5 on the ALLinBOX 1612): room for 16.
            dev["knxnet"] = {"tunnel_slots": 16}
        # tunnel_address on the TP line 1.1: ETS compares the tunnel's line medium
        # with the project's and asks otherwise (the sim's default 1.0.0 is on the IP main line).
        # The sim records its own datagrams (gateway.pcap): dumpcap killed over
        # ssh left truncated files, and this needs no sniffer at all.
        gw = {"host": "127.0.0.1", "port": port, "tunnel_address": "1.1.254", "pcap": "sim.pcap"}
        cfg = yaml.safe_dump({"gateway": gw, "devices": [dev]}, sort_keys=False)
        with sftp.open(f"{self.DIR}/sim.yaml".replace("\\", "/"), "w") as fh:
            fh.write(cfg)
        self.remote_log = f"{self.DIR}\\sim.log"
        self.chan = c.get_transport().open_session()
        self.chan.exec_command(f'set RUST_LOG=info&& "{self.EXE}" "{self.DIR}\\sim.yaml" > "{self.remote_log}" 2>&1')
        time.sleep(2)
        if self.chan.exit_status_ready():
            raise RuntimeError(f"knx-sim.exe exited at once: {self.text()[-800:]}")

    def text(self) -> str:
        try:
            with self.c.open_sftp().open(self.remote_log.replace("\\", "/"), "r") as fh:
                raw = fh.read().decode("utf-8", "replace")
        except OSError:
            raw = ""
        self.local_log.write_text(raw)
        return self.ANSI.sub("", raw)

    def lines(self) -> list[str]:
        return self.text().splitlines()

    def loaded_objects(self) -> set[str]:
        out = set()
        for line in self.lines():
            if self.LOADED.search(line):
                m = re.search(r"object=(\d+)", line)
                if m:
                    out.add(m.group(1))
        return out

    def last_telegram_age(self) -> float:
        n = len(self.text())
        last = getattr(self, "_last", (n, time.time()))
        if n != last[0]:
            last = (n, time.time())
        self._last = last
        return time.time() - last[1]

    def stop(self) -> None:
        vm.run(self.c, "taskkill /f /im knx-sim.exe")
        self.chan.close()
        self.text()

    def fetch_pcap(self, local: Path) -> None:
        self.c.open_sftp().get(f"{self.DIR}/sim.pcap".replace("\\", "/"), str(local))


def app_version(app: str) -> str:
    """The application version ETS shows in its catalog ("2.3") from an
    application id (M-0083_A-000E-23-2274 -> 0x23 -> "2.3")."""
    m = re.match(r"M-[0-9A-F]{4}_A-[0-9A-F]{4}-([0-9A-F]{2})-", app)
    if not m:
        return ""
    v = int(m.group(1), 16)
    return f"{v >> 4}.{v & 0xF}"


def ets_status(history: list[str] | None) -> str:
    """ok / failed / unknown from the newest entry of ETS's history pane."""
    for line in history or []:
        if "Programmieren" in line or "Entladen" in line:
            if "Abgeschlossen" in line or "Abgeschl" in line:
                return "ok"
            if "fehlgeschlagen" in line or "Abgebrochen" in line or "abgebrochen" in line:
                return "failed"
    return "unknown"


ETS_LOG = r"C:\Users\macremote\AppData\Local\KNX\ETS6\Log\ETS6.log"
MISMATCH = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*Required data mismatch at SystemProperty\((\d+)/(\d+)\)\[\$([0-9A-Fa-f]+)\]: ([0-9A-Fa-f]*) instead of ([0-9A-Fa-f]+)"
)


def vm_now(c) -> str:
    """The VM's local time, the clock ETS writes its log in."""
    return vm.run(c, 'powershell -NoProfile -Command "Get-Date -Format \'yyyy-MM-dd HH:mm:ss\'"')[1].strip()


def ets_required(c, since: str) -> list[dict]:
    """The identity ETS required and did not get, from its log since `since`:
    'Required data mismatch at SystemProperty(0/78)[$0000]: <device> instead of
    <expected>' (ETS's VerifyAdditionalResourcesTask, the check behind 'inkompatible
    Produktdaten'). Returned as sim property overrides."""
    cmd = ("powershell -NoProfile -Command \"Select-String -Path '" + ETS_LOG +
           "' -Pattern 'Required data mismatch' | Select-Object -Last 20 | ForEach-Object { $_.Line }\"")
    out = []
    for line in vm.run(c, cmd, 120)[1].splitlines():
        m = MISMATCH.match(line.strip())
        if not m or m.group(1) < since:
            continue
        offset = int(m.group(4), 16)
        value = "00" * offset + m.group(6)
        prop = {"object": int(m.group(2)), "pid": int(m.group(3)), "value": value.lower()}
        if prop not in out:
            out.append(prop)
    return out


def ets_failure_lines(log: str, since: str) -> list[str]:
    """The LoadDeviceTask WARN/ERROR lines of an ETS6.log excerpt written at
    or after `since` (VM local time, the log's own timestamp format), in log
    order and without repeats."""
    out: list[str] = []
    for line in log.splitlines():
        line = line.strip()
        if line[:19] >= since and (" WARN " in line or " ERROR " in line) and line not in out:
            out.append(line)
    return out


def ets_failed_since(c, since: str) -> list[str]:
    """The ETS6.log lines of a failed download (LoadDeviceTask WARN/ERROR)
    since `since` (VM local time); empty when ETS logged none. Reads the
    log's tail only, cheap enough to poll. The lines name what ETS refused
    (a run that ends 'ets logged a failure' while the history pane says
    'Abgeschlossen' is otherwise unexplained: ekinex A-4945, 2026-11-04)."""
    cmd = ("powershell -NoProfile -Command \"Get-Content -Path '" + ETS_LOG +
           "' -Tail 60 | Select-String -Pattern 'LoadDeviceTask' | ForEach-Object { $_.Line }\"")
    return ets_failure_lines(vm.run(c, cmd, 60)[1], since)


def ets_log_failed(lines: list[str] | None) -> bool:
    """Whether ETS's log lines of a download name a failure: an ERROR line
    or an exception, not a WARN that ETS went on after."""
    return any(" ERROR " in l or "Exception" in l for l in lines or [])


HISTORY_HEADER = "Historie löschen"
HISTORY_LABELS = ("Verbindung:", "Start:", "Ende:")
_STATUS = ("Programmieren", "Entladen", "Herunterladen")
_IA_ONLY = re.compile(r"^\d+\.\d+\.\d+$")


def is_history_status(line: str) -> bool:
    """Whether a history line is an entry's status ('Programmieren(Appl.):
    Abgeschlossen', 'Entladen: fehlgeschlagen', ...), as `ets_status` reads it."""
    return any(k in line for k in _STATUS)


def newest_history_entry(history: list[str] | None) -> list[str]:
    """The newest entry of ETS's history pane (the OCR'd lines the driver's
    `history` flow returns, newest first): the device lines before its status
    line, the status line, and the message lines under it ('Keine Details
    verfügbar', 'SystemB/300: failed to read association table format', ...).
    The pane's header, the Verbindung/Start/Ende labels, the connection under
    them and the older entries are dropped. The OCR splits the address column
    off the names at times ('1.1.1' four times, then 'KNX IP interface
    secure'): a repeated line is kept once, a bare address under the status
    line not at all. Without a status line the first four lines after the
    header are kept."""
    lines = [l for l in (history or []) if l.strip() and l.strip() != HISTORY_HEADER]
    status = next((i for i, l in enumerate(lines) if is_history_status(l)), None)
    if status is None:
        return lines[:4]
    head: list[str] = []
    for l in lines[:status]:
        if l not in head:
            head.append(l)
    detail: list[str] = []
    for l in lines[status + 1:status + 1 + 8]:
        if l in HISTORY_LABELS or is_history_status(l):
            break
        if not _IA_ONLY.match(l):
            detail.append(l)
    return head + [lines[status]] + detail


def product_properties(knxprod: Path, app: str) -> list[dict]:
    """The device properties the application binds parameters to, with the
    values those parameters hold: `<Parameter ...><Property ObjectIndex
    PropertyId/>`. ETS compares them before a download (Configuration
    Procedures 3/5/3 §3.5.2: the hardware type, PID 78, against a parameter
    of the application program), so a factory device of that hardware holds
    them. The value is the selected Enumeration member's BinaryValue of a
    TypeRestriction, or the number or text encoded to the property's size.
    (Found by the coordinator session, 2026-10-28: 72 of 73 learned PID 78
    values sit in the product's own XML.)"""
    import base64

    texts = _zip_texts(knxprod, lambda n: n.endswith(f"{app}.xml"), first=True)
    if not texts:
        return []
    # A module definition's parameters name objects relative to the
    # module instance's base (the Schneider STXF121's `ObjectIndex="0"`
    # PID 208 is objects 6 to 9): not the device object (2026-11-06).
    xml = re.sub(r"<ModuleDefs>.*?</ModuleDefs>", "", texts[0][1], flags=re.S)

    def attr(tag: str, key: str) -> str | None:
        m = re.search(rf'\b{key}="([^"]*)"', tag)
        return m.group(1) if m else None

    out: list[dict] = []
    for m in re.finditer(r"(<Parameter\s[^>]*>)\s*(<Property\s[^>]*/>)", xml):
        param, prop = m.group(1), m.group(2)
        obj, pid = attr(prop, "ObjectIndex"), attr(prop, "PropertyId")
        # A parameter that names the device object by type (`ObjectType="0"`)
        # is not seeded: the Schneider M-0009 programs bind `HardwareType`
        # (`09 FF FF FF FF FF`) that way while their own CompareProp expects
        # `00 00 09 72 09 00`, and seeding it made ETS refuse four products
        # ("Device not compatible", 2026-11-06). knx-sim serves the compared
        # value; for the Gira IR-Gateway both agree.
        pid_ = attr(param, "Id")
        ptype, value = attr(param, "ParameterType"), attr(param, "Value") or "0"
        if obj is None or pid is None or not ptype:
            continue
        ref = re.search(rf'<ParameterRef\s[^>]*RefId="{re.escape(pid_ or "")}"[^>]*>', xml)
        if ref and attr(ref.group(0), "Value") is not None:
            value = attr(ref.group(0), "Value") or value
        t = xml.find(f'<ParameterType Id="{ptype}"')
        block = xml[t: xml.find("</ParameterType>", t)] if t >= 0 else ""
        size_m = re.search(r'SizeInBit="(\d+)"', block)
        size = (int(size_m.group(1)) + 7) // 8 if size_m else 0
        data: bytes | None = None
        if "<TypeRestriction" in block:
            for e in re.finditer(r"<Enumeration\s[^>]*>", block):
                if attr(e.group(0), "Value") == value:
                    b64 = attr(e.group(0), "BinaryValue")
                    data = base64.b64decode(b64) if b64 else int(value).to_bytes(max(size, 1), "big")
                    break
        elif "<TypeNumber" in block and size:
            try:
                data = int(float(value)).to_bytes(size, "big", signed=int(float(value)) < 0)
            except (ValueError, OverflowError):
                data = None
        elif "<TypeText" in block and size:
            data = value.encode("latin-1", "replace")[:size].ljust(size, b"\0")
        if data is not None:
            out.append({"object": int(obj), "pid": int(pid), "value": data.hex()})
    return out


PID_MANUFACTURER_ID = 12


def _brand_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def oem_identity(knxprod: Path, app: str) -> list[dict]:
    """The manufacturer id (obj0 PID 12) of the brand an OEM hardware names,
    as a sim property seed (bussard issue #881).

    The Gewiss-branded sensor GW10966 (`GS4x12_v1.1.knxprod`) is hardware
    `LP-579-401_GEWISS` of Hugo Müller (M-00FC) running an M-00FC program.
    The sim answered PID 12 `00 fc`, the program's manufacturer, and ETS
    refused it right after that read as a device "von einem anderen
    Hersteller als das Applikationsprogramm" (2026-11-06 and 2026-11-08),
    while the unbranded sibling of the same file passed with the same
    answer. So the brand is what ETS checks: a hardware whose serial number
    ends in `_<name>` of another manufacturer of the file's knx_master gets
    that manufacturer's KNX id. One hardware of the 1491 corpus files matches
    (2026-11-08), so the rule touches nothing else. Empty when the hardware
    names no other manufacturer.
    """
    texts = _zip_texts(knxprod, lambda n: n == "knx_master.xml" or n.endswith("/Hardware.xml")) or []
    master = next((t for n, t in texts if n == "knx_master.xml"), None)
    hardware = [t for n, t in texts if n.endswith("/Hardware.xml")]
    if master is None:
        return []
    own = app.split("_", 1)[0]
    brands = {_brand_key(name): (mid, int(knx))
              for mid, knx, name in re.findall(
                  r'<Manufacturer Id="(M-[0-9A-F]{4})" KnxManufacturerId="(\d+)" Name="([^"]*)"', master)}
    for xml in hardware:
        for m in re.finditer(r"<Hardware\s[^>]*>.*?</Hardware>", xml, flags=re.S):
            block = m.group(0)
            if f'RefId="{app}"' not in block:
                continue
            serial = re.search(r'\bSerialNumber="([^"]*)"', block[:block.find(">") + 1])
            if not serial or "_" not in serial.group(1):
                continue
            brand = brands.get(_brand_key(serial.group(1).rsplit("_", 1)[1]))
            if brand and brand[0] != own:
                return [{"object": 0, "pid": PID_MANUFACTURER_ID, "value": f"{brand[1]:04x}"}]
    return []


def compare_properties(knxprod: Path, app: str) -> list[dict]:
    """The device-object properties the application's load procedure compares
    against a range (`LdCtrlCompareProp ObjIdx="0" Range=...`), with a value
    that passes the compare: the lower bound (the upper one when there is no
    lower bound) at the octets the range's widest bound needs. The Jung F50
    Secure room controller compares PID 201 against `[281492156579840,]`; a sim
    without that property answers ETS's description read with "no such
    property" and ETS gives up before loading anything (#966).

    An `InlineData` compare is left to knx-sim, which serves every
    device-object one and picks among alternatives by the parameters' choose
    blocks; a seed would override that pick (757 applications of the corpus
    would change seed, 2026-11-08)."""
    texts = _zip_texts(knxprod, lambda n: n.endswith(f"{app}.xml"), first=True)
    if not texts:
        return []
    xml = texts[0][1]
    out: list[dict] = []
    for m in re.finditer(r"<LdCtrlCompareProp\s[^>]*>", xml):
        value = compare_value(m.group(0))
        pid = re.search(r'\bPropId="(\d+)"', m.group(0))
        ranged = re.search(r'\bRange="', m.group(0)) and not re.search(r'\bInlineData="', m.group(0))
        if ranged and value is not None and pid and re.search(r'\bObjIdx="0"', m.group(0)):
            prop = {"object": 0, "pid": int(pid.group(1)), "value": value.hex()}
            if prop not in out:
                out.append(prop)
    return out


def compare_value(tag: str) -> bytes | None:
    """A value an `LdCtrlCompareProp` element accepts, or None when it names
    another element than the first (knx-sim merges those, #422) or carries
    neither `InlineData` nor a usable `Range`."""
    def attr(key: str) -> str | None:
        m = re.search(rf'\b{key}="([^"]*)"', tag)
        return m.group(1) if m else None

    if int(attr("StartElement") or "1") > 1:
        return None
    inline = attr("InlineData")
    if inline:
        try:
            data = bytes.fromhex(inline)
        except ValueError:
            return None
        # As knx-sim reads it: InlineData longer than the Count elements it
        # can hold keeps its last Count octets (Gira IR-Gateway, 2026-11-06).
        count = int(attr("Count") or "0")
        if count and len(data) > count and len(data) % count:
            data = data[-count:]
        return data or None
    rng = re.fullmatch(r"\s*([\[(])\s*(-?\d*)\s*,\s*(-?\d*)\s*([\])])\s*", attr("Range") or "")
    if not rng:
        return None
    lo = int(rng.group(2)) + (rng.group(1) == "(") if rng.group(2) else None
    hi = int(rng.group(3)) - (rng.group(4) == ")") if rng.group(3) else None
    value = lo if lo is not None else hi
    if value is None or value < 0 or (hi is not None and value > hi):
        return None
    width = max(max(b.bit_length() for b in (lo or 0, hi or 0, 1)) + 7, 8) // 8
    return value.to_bytes(width, "big")


def secure_enabled(knxprod: Path, app: str) -> bool:
    """Whether the application declares IsSecureEnabled (ETS then asks for a
    project password a few seconds after the device is added)."""
    texts = _zip_texts(knxprod, lambda n: app in n and n.endswith(".xml"), first=True, limit=4000)
    if texts:
        return 'IsSecureEnabled="true"' in texts[0][1]
    return True  # unknown: keep the wait


ETS_EXE = r"C:\Program Files (x86)\ETS6\ETS6N.exe"
_ETS_VERSION: dict = {}


def ets_version(c) -> str | None:
    """ETS's file version in the VM (`6.4.8718...`), read once per session:
    the sweep is pinned to one ETS version, and a driver failure after an
    ETS update is a driver repair (#419, #425)."""
    if "v" not in _ETS_VERSION:
        try:
            out = vm.run(c, "powershell -NoProfile -Command \"(Get-Item '" + ETS_EXE + "').VersionInfo.FileVersion\"", 60)[1]
            _ETS_VERSION["v"] = out.strip().splitlines()[-1].strip() if out.strip() else None
        except Exception:  # noqa: BLE001 - a version we cannot read is recorded as unknown
            _ETS_VERSION["v"] = None
    return _ETS_VERSION["v"]


def save_repair(c, out: Path, error: str, failed: dict | None = None) -> dict:
    """The repair loop (#425): when a run fails, keep what the driver saw next
    to the outcome, so the fix is a diff against the driver: a screenshot of
    the desktop, the UI Automation trees of ETS's popups and main window,
    the failing flow's trace, and the ETS version. Read-only driver calls;
    each one that fails is noted, none raises."""
    repair = out / "repair"
    repair.mkdir(parents=True, exist_ok=True)
    trace = (failed or {}).get("trace") or ""
    (repair / "error.txt").write_text(error + ("\n\n" + trace if trace else "") + "\n")
    saved: dict = {"dir": str(repair), "ets_version": ets_version(c)}
    for name, path, body in (("screen.png", "/screenshot", {"window": "desktop", "scale": 0.5}),
                             ("popups.txt", "/popups", {"depth": 8}),
                             ("tree.txt", "/tree", {"depth": 3})):
        try:
            r = vm.driver(c, "POST", path, body, timeout=120)
            if name.endswith(".png") and r.get("png_base64"):
                import base64

                (repair / name).write_bytes(base64.b64decode(r["png_base64"]))
            else:
                (repair / name).write_text(r.get("tree") or json.dumps(r)[:20000])
            saved[name] = "ok"
        except Exception as exc:  # noqa: BLE001 - evidence, not a step
            saved[name] = f"failed: {exc}"[:200]
    (repair / "repair.json").write_text(json.dumps(saved, indent=1))
    return saved


def is_coupler_address(ia: str) -> bool:
    """Whether `ia` is a line's coupler address (device part 0, `1.1.0`)."""
    parts = ia.split(".")
    return len(parts) == 3 and parts[2] == "0"


def added_address(add: dict, requested: str) -> str:
    """The individual address ETS gave the device `catalog_add` added
    (bussard issue #876): the one entry under `added` when there is exactly
    one, else `requested`.

    ETS puts a product at the next free address of the line, 1.1.1 in the
    sweep's empty project, but gives a coupler (a media coupler on mask 0701,
    S85050100 and STR131, 2026-11-05/06) the line's coupler address 1.1.0.
    """
    added = [d.get("ia") for d in add.get("added") or [] if isinstance(d, dict) and d.get("ia")]
    return added[0] if len(added) == 1 else requested


def run_one(c, knxprod: Path, app: str, search: str, *, version: str | None = None, ia: str = "1.1.1",
            variant: str = "plain-defaults", mode: str = "application", project: str = "ets-sweep",
            connection: str = "knx-sim", sim_port: int = 3672, timeout: int = 900, quiet: int = 45,
            first_traffic: int = 120, mask: str = "", properties: list[dict] | None = None,
            fallback_search: str = "", before_download=None, after_download=None,
            secure: dict | None = None, repair: bool = True, flow_extra: dict | None = None) -> dict:
    """One ETS download of `app` into a sim inside the VM; returns the result
    and leaves capture, sim log, driver.json and ops.txt in the run directory.

    `before_download(flow, out, ia)` runs after the device is added and the
    connection selected (the links variant links objects there, #478);
    `after_download(flow, out)` once the download ended (the secure variant
    exports the keyring, #423). Each returns a dict kept in the result under
    `before` / `after`. `secure` is the sim device's `security:` config.
    `flow_extra` goes into every driver call's body (the secure pass sends the
    project password and the device certificate, #423). A failed run keeps
    the repair artefacts (`save_repair`) unless `repair` is off."""
    out = CAPTURES / app / variant
    out.mkdir(parents=True, exist_ok=True)
    version = app_version(app) if version is None else version
    result: dict = {"app": app, "variant": variant, "ia": ia, "search": search, "version": version,
                    "properties": properties or []}
    t0 = time.time()
    since = vm_now(c)
    try:
        sim = RemoteSim(c, knxprod.resolve(), app, ia, sim_port, secure, out / "sim.log", mask=mask, properties=properties)
    except RuntimeError as exc:
        result.update({"outcome": "sim-refused", "error": str(exc)[-600:], "seconds": round(time.time() - t0)})
        (out / "driver.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        return result
    steps: dict = {}
    try:

        def flow(flow_name: str, /, **body) -> dict:
            r = vm.driver(c, "POST", f"/ets/{flow_name}", {"project": project, **(flow_extra or {}), **body}, timeout=600)
            steps[flow_name if flow_name not in steps else f"{flow_name}#{len(steps)}"] = r
            if not r.get("ok", True):
                raise RuntimeError(f"{flow_name}: {r.get('error')}")
            return r

        result["driver"] = steps
        flow("project_tab", name=project)
        for d in flow("devices")["devices"]:
            if not flow("delete_device", ia=d["ia"]).get("deleted"):
                raise RuntimeError(f"could not delete {d['ia']} before the add")
        add = flow("catalog_add", search=search, version=version, fallback_search=fallback_search,
                   password_wait=12 if secure_enabled(knxprod, app) else 2)
        if not add.get("added"):
            raise RuntimeError(f"catalog add added nothing: {add.get('row')}")
        result["catalog_row"] = add.get("row")
        got = added_address(add, ia)
        if got != ia:
            if not is_coupler_address(got):
                # Any other address means a device was left in the project
                # and pushed the new one along: the clean-up failed.
                raise RuntimeError(f"ETS added the device at {got}, not {ia}: device {ia} not in list after the clean-up")
            # A coupler at the line's coupler address (#876): restart the sim
            # where ETS will look for the device, and download that address.
            result["ia_requested"], result["ia"], ia = ia, got, got
            sim.stop()
            try:
                # Rebinding `sim` makes the `finally` stop the new process and
                # fetch its capture; a refused start leaves the old object,
                # already stopped (stop is idempotent).
                sim = RemoteSim(c, knxprod.resolve(), app, ia, sim_port, secure, out / "sim.log", mask=mask,
                                properties=properties)
            except RuntimeError as exc:
                result["sim_refused"] = str(exc)[-600:]
                raise
        flow("select_connection", name=connection)
        if before_download is not None:
            # The hook gets the address ETS gave the device (#876).
            result["before"] = before_download(flow, out, ia)
        flow("download", ia=ia, mode=mode)
        # Wait for the end of the download, whichever signal comes first:
        # - success: the device restarted (not a master reset) after its load
        #   states went Loaded, the last step of every ETS download;
        # - failure: ETS logged a LoadDeviceTask warning or error (it logs
        #   failures, never successes);
        # - fallback: the bus quiet for `quiet` seconds after traffic, or no
        #   traffic within `first_traffic`.
        started = time.time()
        while time.time() - started < timeout:
            time.sleep(3)
            lines = sim.lines()
            seen = any("direction=" in l for l in lines)
            loaded_at = max((i for i, l in enumerate(lines) if Sim.LOADED.search(l)), default=-1)
            if loaded_at >= 0 and any("device restarted" in l and "master_reset=false" in l for l in lines[loaded_at:]):
                time.sleep(3)
                result["end"] = "device restarted"
                break
            failure = ets_failed_since(c, since)
            if failure:
                result["end"] = "ets logged a failure"
                result["ets_log"] = failure
                break
            age = sim.last_telegram_age()
            if seen and age > quiet:
                result["end"] = "bus quiet"
                break
            if not seen and time.time() - started > first_traffic:
                result["end"] = "no traffic"
                break
        # ETS may go on after the restart (an IP-enabled device gets its
        # KNXnet/IP parameters written next, ALLinBOX 1612, 2026-10-28): while
        # the newest entry still reads 'Herunterladen', keep the sim up and look
        # again.
        settle = time.time()
        while True:
            result["history"] = vm.driver(c, "POST", "/ets/history", {"project": project, **(flow_extra or {})}, timeout=120).get("lines")
            result["ets"] = ets_status(result["history"])
            if result["ets"] != "unknown" or time.time() - settle > 120:
                break
            time.sleep(5)
        if after_download is not None:
            result["after"] = after_download(flow, out)
    except Exception as exc:  # noqa: BLE001 - recorded per application, the batch goes on
        result["error"] = str(exc)[:600]
        if repair:
            failed = next((r for r in reversed(list(steps.values())) if not r.get("ok", True)), None)
            result["repair"] = save_repair(c, out, str(exc), failed)
    finally:
        sim.stop()
        try:
            sim.fetch_pcap(out / "ets.pcapng")
        except OSError as exc:
            result.setdefault("error", f"no capture: {exc}")
    result["loaded_objects"] = sorted(sim.loaded_objects())
    result["seconds"] = round(time.time() - t0)
    if (out / "ets.pcapng").exists():
        result["ops"] = write_ops(out, ia)
    err = result.get("error") or ""
    result["outcome"] = (
        # A prompt met before this product was even added belongs to the
        # previous one (it kept coming back for a device left in the project,
        # 2026-10-29): retry, do not skip.
        "driver-error" if stale_compat_prompt(err)
        # The sim refused the address ETS gave the device (#876), like a
        # refused first start.
        else "sim-refused" if result.get("sim_refused")
        else "skipped-compat-mode" if "compatibility mode" in err
        else "skipped-ets-invalid-product" if "ETS product data invalid" in err
        else "skipped-catalog-version" if "catalog version mismatch" in err
        else "skipped-not-in-catalog" if "not found in catalog search" in err
        # The device is not at the address the download looks for (#876): a
        # device left in the project, or an address the sweep did not follow.
        # Not `skipped-*`, so `--redo-failed` runs it again after a clean-up.
        else "driver-error-address" if re.search(r"device \S+ not in list", err)
        # An exception ETS logged for the download outranks the history pane
        # (the secure run read 'Abgeschlossen' off another project's pane
        # while ETS logged 'Das Gerät ist mit einem in diesem Projekt nicht
        # bekannten Schlüssel gesichert', 2026-11-04). A plain WARN is not a
        # failure (ekinex A-4945: AssignedIPAddress discovery).
        else "ets-failed" if ets_log_failed(result.get("ets_log"))
        else "captured" if result.get("ets") == "ok" and result.get("ops")
        else "ets-failed" if result.get("ets") == "failed"
        else "driver-error" if result.get("error")
        else "unknown"
    )
    if result["outcome"] == "ets-failed":
        result["ets_required"] = ets_required(c, since)
    (out / "driver.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
    return result


def write_ops(out: Path, ia: str, keyring: Path | None = None, password: str | None = None) -> int:
    """`knxtrace ops` of the run's capture into `ops.txt`; the number of
    operations. With `keyring` (and its password) the Data Secure frames are
    decrypted and their inner APDUs listed (#423): without it a secure
    download's writes show as `secure-data` only."""
    cmd = ["uv", "run", "--quiet", str(KNXTRACE), "ops", str(out / "ets.pcapng"), "--device", ia]
    env = dict(os.environ)
    if keyring is not None:
        cmd += ["--keyring", str(keyring)]
        env["BUSSARD_KEYRING_PASSWORD"] = password or ""
    ops = subprocess.run(cmd, capture_output=True, text=True, env=env)
    (out / "ops.txt").write_text(ops.stdout + ops.stderr)
    return sum(1 for l in ops.stdout.splitlines() if re.match(r"\s+\d+\s", l))


def run_learning(c, knxprod: Path, app: str, search: str, *, attempts: int = 3,
                 learned: list[dict] | None = None, **kw) -> dict:
    """run_one, and when ETS refuses the device for an identity mismatch,
    again with the identity ETS logged as required, up to `attempts` runs.

    `learned` is what earlier runs learned from ETS. The result's
    `learned_properties` holds that, updated with what ETS required in these
    runs, and nothing else: the seeded `properties` (product parameters,
    guessed identities) are not learned. Recording the whole seed made a bad
    seed stick to the row after its source was fixed (the Schneider STJA rows
    kept `09ffffffffff` for PID 78, 2026-11-06)."""
    props: list[dict] = list(kw.pop("properties", None) or [])
    learned = list(learned or [])
    r: dict = {}
    for attempt in range(attempts):
        r = run_one(c, knxprod, app, search, properties=props or None, **kw)
        r["attempt"] = attempt + 1
        new = [p for p in r.get("ets_required", []) if p not in props]
        if new:
            keys = {(n["object"], n["pid"]) for n in new}
            learned = [p for p in learned if (p["object"], p["pid"]) not in keys] + new
        if r["outcome"] != "ets-failed" or not new:
            break
        # A later requirement on the same property replaces the earlier one.
        props = [p for p in props if (p["object"], p["pid"]) not in keys] + new
    r["learned_properties"] = learned
    return r


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knxprod", required=True, type=Path)
    ap.add_argument("--app", required=True, help="application id, e.g. M-00FA_A-2500-10-51CB")
    ap.add_argument("--search", required=True, help="catalog search term that finds the product (its order number)")
    ap.add_argument("--version", help="application version as ETS shows it; default from the application id")
    ap.add_argument("--mode", default="application", choices=["application", "full", "partial"])
    ap.add_argument("--ia", default="1.1.1")
    ap.add_argument("--variant", default="plain-defaults")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--mask", default="")
    ap.add_argument("--prop", action="append", default=[], help="OBJ:PID:HEX property override for the sim device, repeatable")
    args = ap.parse_args()
    props = [{"object": int(o), "pid": int(p), "value": v} for o, p, v in (x.split(":", 2) for x in args.prop)]
    c = vm.connect()
    r = run_learning(c, args.knxprod, args.app, args.search, version=args.version, ia=args.ia,
                     variant=args.variant, mode=args.mode, timeout=args.timeout, mask=args.mask, properties=props or None)
    print(json.dumps({k: r.get(k) for k in ("outcome", "ets", "loaded_objects", "ops", "seconds", "error", "attempt", "learned_properties")}, ensure_ascii=False))
    return 0 if r["outcome"] == "captured" else 1


if __name__ == "__main__":
    sys.exit(main())
