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


class RemoteSim:
    """knx-sim.exe INSIDE the VM (ETS reaches it on 127.0.0.1, where its ping
    check passes; the Mac's managed firewall drops ping). The process runs over
    a held ssh channel with its log redirected to a file we poll by sftp."""

    LOADED = Sim.LOADED
    ANSI = Sim.ANSI
    EXE = vm.REMOTE_DIR + r"\sim\knx-sim.exe"
    DIR = vm.REMOTE_DIR + r"\sim"

    def __init__(self, c, knxprod: Path, app: str, ia: str, port: int, secure: dict | None, local_log: Path, mask: str = "",
                 properties: list[dict] | None = None):
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


def run_one(c, knxprod: Path, app: str, search: str, *, version: str | None = None, ia: str = "1.1.1",
            variant: str = "plain-defaults", mode: str = "application", project: str = "ets-sweep",
            connection: str = "knx-sim", sim_port: int = 3672, timeout: int = 900, quiet: int = 45,
            first_traffic: int = 120, mask: str = "", properties: list[dict] | None = None) -> dict:
    """One ETS download of `app` into a sim inside the VM; returns the result
    and leaves capture, sim log, driver.json and ops.txt in the run directory."""
    out = CAPTURES / app / variant
    out.mkdir(parents=True, exist_ok=True)
    version = app_version(app) if version is None else version
    result: dict = {"app": app, "variant": variant, "ia": ia, "search": search, "version": version,
                    "properties": properties or []}
    t0 = time.time()
    since = vm_now(c)
    try:
        sim = RemoteSim(c, knxprod.resolve(), app, ia, sim_port, None, out / "sim.log", mask=mask, properties=properties)
    except RuntimeError as exc:
        result.update({"outcome": "sim-refused", "error": str(exc)[-600:], "seconds": round(time.time() - t0)})
        (out / "driver.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        return result
    try:
        steps: dict = {}

        def flow(flow_name: str, /, **body) -> dict:
            r = vm.driver(c, "POST", f"/ets/{flow_name}", {"project": project, **body}, timeout=600)
            steps[flow_name if flow_name not in steps else f"{flow_name}#{len(steps)}"] = r
            if not r.get("ok", True):
                raise RuntimeError(f"{flow_name}: {r.get('error')}")
            return r

        result["driver"] = steps
        flow("project_tab", name=project)
        for d in flow("devices")["devices"]:
            if not flow("delete_device", ia=d["ia"]).get("deleted"):
                raise RuntimeError(f"could not delete {d['ia']} before the add")
        add = flow("catalog_add", search=search, version=version)
        if not add.get("added"):
            raise RuntimeError(f"catalog add added nothing: {add.get('row')}")
        result["catalog_row"] = add.get("row")
        flow("select_connection", name=connection)
        flow("download", ia=ia, mode=mode)
        # Wait: the download is over when the bus has been quiet for `quiet`
        # seconds after traffic, or never started within `first_traffic`.
        started = time.time()
        while time.time() - started < timeout:
            time.sleep(5)
            seen = bool(sim.lines()) and any("direction=" in l for l in sim.lines())
            age = sim.last_telegram_age()
            if seen and age > quiet:
                break
            if not seen and time.time() - started > first_traffic:
                break
        result["history"] = vm.driver(c, "POST", "/ets/history", {}, timeout=120).get("lines")
        result["ets"] = ets_status(result["history"])
    except Exception as exc:  # noqa: BLE001 - recorded per application, the batch goes on
        result["error"] = str(exc)[:600]
    finally:
        sim.stop()
        try:
            sim.fetch_pcap(out / "ets.pcapng")
        except OSError as exc:
            result.setdefault("error", f"no capture: {exc}")
    result["loaded_objects"] = sorted(sim.loaded_objects())
    result["seconds"] = round(time.time() - t0)
    if (out / "ets.pcapng").exists():
        ops = subprocess.run(["uv", "run", "--quiet", str(KNXTRACE), "ops", str(out / "ets.pcapng"), "--device", ia],
                             capture_output=True, text=True)
        (out / "ops.txt").write_text(ops.stdout + ops.stderr)
        result["ops"] = sum(1 for l in ops.stdout.splitlines() if re.match(r"\s+\d+\s", l))
    err = result.get("error") or ""
    result["outcome"] = (
        "skipped-compat-mode" if "compatibility mode" in err
        else "skipped-catalog-version" if "catalog version mismatch" in err
        else "skipped-not-in-catalog" if "not found in catalog search" in err
        else "captured" if result.get("ets") == "ok" and result.get("ops")
        else "ets-failed" if result.get("ets") == "failed"
        else "driver-error" if result.get("error")
        else "unknown"
    )
    if result["outcome"] == "ets-failed":
        result["ets_required"] = ets_required(c, since)
    (out / "driver.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
    return result


def run_learning(c, knxprod: Path, app: str, search: str, *, attempts: int = 3, **kw) -> dict:
    """run_one, and when ETS refuses the device for an identity mismatch,
    again with the identity ETS logged as required, up to `attempts` runs.
    The learned properties are kept in the result."""
    props: list[dict] = list(kw.pop("properties", None) or [])
    r: dict = {}
    for attempt in range(attempts):
        r = run_one(c, knxprod, app, search, properties=props or None, **kw)
        r["attempt"] = attempt + 1
        new = [p for p in r.get("ets_required", []) if p not in props]
        if r["outcome"] != "ets-failed" or not new:
            break
        # A later requirement on the same property replaces the earlier one.
        props = [p for p in props if (p["object"], p["pid"]) not in {(n["object"], n["pid"]) for n in new}] + new
    r["learned_properties"] = props
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
