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

    def __init__(self, c, knxprod: Path, app: str, ia: str, port: int, secure: dict | None, local_log: Path):
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
        dev = {"address": ia, "knxprod": knxprod.name, "application": app, "initial_state": "unloaded"}
        if secure:
            dev["security"] = secure
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
            raise SystemExit(f"knx-sim.exe exited at once: {self.text()[-800:]}")

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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knxprod", required=True, type=Path)
    ap.add_argument("--app", required=True, help="application id, e.g. M-00FA_A-2500-10-51CB")
    ap.add_argument("--search", required=True, help="catalog search term that finds the product (its order number)")
    ap.add_argument("--project", default="ets-sweep", help="the ETS project tab the sweep works in")
    ap.add_argument("--connection", default="knx-sim", help="the configured ETS connection that points at the sim")
    ap.add_argument("--mode", default="application", choices=["application", "full", "partial"])
    ap.add_argument("--ia", default="1.1.1", help="the sim device's address; ETS gives the first device on an empty line 1.1 this address")
    ap.add_argument("--variant", default="plain-defaults")
    ap.add_argument("--sim-where", choices=["vm", "mac"], default="vm",
                    help="vm: knx-sim.exe inside the VM on 127.0.0.1 (default; ETS pings the interface host and the Mac drops ping); mac: the Mac's LAN address")
    ap.add_argument("--sim-host", default=os.environ.get("ETS_SWEEP_SIM_HOST", "192.168.1.79"), help="only for --sim-where mac")
    ap.add_argument("--sim-port", type=int, default=3672, help="3672 in the VM (KNX Virtual holds 3671 there)")
    ap.add_argument("--timeout", type=int, default=600, help="seconds to wait for the download")
    ap.add_argument("--quiet", type=int, default=20, help="seconds of bus silence after Loaded that end the wait")
    ap.add_argument("--no-ets", action="store_true", help="start sim and capture only; drive ETS by hand")
    args = ap.parse_args()

    out = CAPTURES / args.app / args.variant
    out.mkdir(parents=True, exist_ok=True)
    c = vm.connect()
    if args.sim_where == "vm":
        sim = RemoteSim(c, args.knxprod.resolve(), args.app, args.ia, args.sim_port, None, out / "sim.log")
        print(f"sim in the VM on 127.0.0.1:{args.sim_port}, log {out / 'sim.log'}")
        cap = None
    else:
        cfg = write_sim_config(out, args.knxprod.resolve(), args.app, args.ia, args.sim_host, args.sim_port, None)
        sim = Sim(cfg, out / "sim.log")
        print(f"sim {sim.proc.pid} on {args.sim_host}:{args.sim_port}, log {out / 'sim.log'}")
        cap = None
    result: dict = {"app": args.app, "variant": args.variant, "ia": args.ia}
    try:
        if not args.no_ets:
            t0 = time.time()
            steps = {}
            flow = lambda flow_name, **body: vm.driver(c, "POST", f"/ets/{flow_name}", {"project": args.project, **body}, timeout=300)
            steps["tab"] = flow("project_tab", name=args.project)
            # A clean line 1.1: whatever a previous run left behind goes first, so
            # the device added now gets 1.1.1, the address the sim device has.
            for d in flow("devices")["devices"]:
                steps[f"delete {d['ia']}"] = flow("delete_device", ia=d["ia"])
            steps["add"] = flow("catalog_add", search=args.search)
            if not steps["add"].get("added"):
                raise SystemExit(f"catalog add failed: {steps['add']}")
            steps["connection"] = flow("select_connection", name=args.connection)
            steps["download"] = flow("download", ia=args.ia, mode=args.mode)
            for k, v in steps.items():
                if not v.get("ok", True):
                    raise SystemExit(f"driver step {k} failed: {v}")
            result["driver"] = steps
            print("driver: download started", f"({time.time() - t0:.0f}s)")
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            loaded = sim.loaded_objects()
            if loaded and sim.last_telegram_age() > args.quiet:
                break
            if args.no_ets and not loaded and sim.last_telegram_age() > args.timeout:
                break
            time.sleep(2)
        result["loaded_objects"] = sorted(sim.loaded_objects())
        result["seconds"] = round(time.time() - sim.start)
        if not args.no_ets:
            result["history"] = vm.driver(c, "POST", "/ets/history", {}, timeout=120).get("lines")
    finally:
        sim.stop()
        if isinstance(sim, RemoteSim):
            sim.fetch_pcap(out / "ets.pcapng")
    (out / "driver.json").write_text(json.dumps(result, indent=1))
    ops = subprocess.run(
        ["uv", "run", "--quiet", str(KNXTRACE), "ops", str(out / "ets.pcapng"), "--device", args.ia],
        capture_output=True, text=True,
    )
    (out / "ops.txt").write_text(ops.stdout + ops.stderr)
    print(f"loaded objects: {result['loaded_objects']} in {result['seconds']}s; ops: {len(ops.stdout.splitlines())} lines -> {out}")
    return 0 if result["loaded_objects"] else 1


if __name__ == "__main__":
    sys.exit(main())
