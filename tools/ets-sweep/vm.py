# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko"]
# ///
"""Reach the Windows VM that runs ETS: ssh commands, file transfer, the driver.

    uv run tools/ets-sweep/vm.py run "<cmd>" [timeout]
    uv run tools/ets-sweep/vm.py put <local> <remote>      # sftp
    uv run tools/ets-sweep/vm.py get <remote> <local>
    uv run tools/ets-sweep/vm.py driver GET /health
    uv run tools/ets-sweep/vm.py driver POST /tree '{"depth": 2}'
    uv run tools/ets-sweep/vm.py exec "<python code>"      # dev endpoint
    uv run tools/ets-sweep/vm.py install                   # upload the driver (it re-execs itself)
    uv run tools/ets-sweep/vm.py screenshot <out.png> [x0,y0,x1,y1|-] [scale]

The driver listens on 127.0.0.1:8765 inside the VM; every call here rides an
ssh direct-tcpip channel, so the VM needs no inbound firewall rule.
Credentials: WINDOWS_SSH_PW in the repo's .env (never committed); host and user
below. The driver must run in the VM's interactive desktop session (the one that
shows ETS). It is started there once by hand (ssh lands in session 0, and
scheduled tasks or PsExec are not used from here); afterwards `install` only
uploads, and the running driver re-execs itself when its file changes.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import paramiko

HOST = os.environ.get("ETS_VM_HOST", "192.168.1.26")
USER = os.environ.get("ETS_VM_USER", "macremote")
DRIVER_PORT = 8765
REMOTE_DIR = rf"C:\Users\{USER}\ets-sweep"
PYTHON = r"C:\Program Files\Python312\python.exe"
REPO = Path(__file__).resolve().parents[2]


def password() -> str:
    env = os.environ.get("WINDOWS_SSH_PW")
    if env:
        return env
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith("WINDOWS_SSH_PW="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("WINDOWS_SSH_PW not set and not in .env")


def connect() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=password(), timeout=10)
    return c


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 60) -> tuple[int, str]:
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = (o.read() + e.read()).decode("utf-8", "replace").replace("\r", "")
    return o.channel.recv_exit_status(), out.strip()


def driver(c: paramiko.SSHClient, method: str, path: str, body: dict | None = None, timeout: int = 600) -> dict:
    """One HTTP/1.0 request to the driver over an ssh direct-tcpip channel.

    Written by hand (not http.client) because paramiko's channel file does not
    behave like a socket file at EOF and http.client then drops the body."""
    ch = c.get_transport().open_channel("direct-tcpip", ("127.0.0.1", DRIVER_PORT), ("127.0.0.1", 0))
    ch.settimeout(timeout)
    data = json.dumps(body or {}).encode() if method == "POST" else b""
    head = f"{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n"
    ch.sendall(head.encode() + data)
    buf = b""
    while True:
        chunk = ch.recv(65536)
        if not chunk:
            break
        buf += chunk
    ch.close()
    header, _, raw = buf.partition(b"\r\n\r\n")
    status = header.split(b" ", 2)[1].decode() if b" " in header else "?"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": status, "raw": raw.decode("utf-8", "replace")}


def driver_token(c: paramiko.SSHClient) -> str:
    code, out = run(c, f'type "{REMOTE_DIR}\\driver.token"')
    if code != 0:
        raise SystemExit(f"no driver token yet: {out}")
    return out.strip()


START_CMD = f'Start-Process "{PYTHON}" -ArgumentList "{REMOTE_DIR}\\ets_driver.py" -WindowStyle Hidden'


def install(c: paramiko.SSHClient) -> None:
    """Upload the driver. A running driver re-execs itself when the file changes;
    the first start happens by hand in the VM's desktop session (see README)."""
    src = Path(__file__).resolve().parent / "driver" / "ets_driver.py"
    run(c, f'mkdir "{REMOTE_DIR}"')
    c.open_sftp().put(str(src), REMOTE_DIR.replace("\\", "/") + "/ets_driver.py")
    print("uploaded", src.name)
    exe = REPO / "knx-sim" / "target-win" / "x86_64-pc-windows-gnu" / "release" / "knx-sim.exe"
    if exe.exists():
        run(c, f'mkdir "{REMOTE_DIR}\\sim"')
        run(c, "taskkill /f /im knx-sim.exe")
        c.open_sftp().put(str(exe), REMOTE_DIR.replace("\\", "/") + "/sim/knx-sim.exe")
        print("uploaded knx-sim.exe", exe.stat().st_size, "bytes (build with tools/ets-sweep/winbuild-knx-sim.sh)")
    code, out = run(c, "tasklist /v | findstr /i python.exe")
    if code != 0:
        print("driver is not running; start it once in a PowerShell window of the VM's desktop session:")
        print("  " + START_CMD)
    else:
        print("running driver will re-exec itself within a few seconds")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    c = connect()
    cmd, args = argv[0], argv[1:]
    if cmd == "run":
        code, out = run(c, args[0], int(args[1]) if len(args) > 1 else 60)
        print(out)
        return code
    if cmd == "put":
        c.open_sftp().put(args[0], args[1])
        print("put", args[1])
    elif cmd == "get":
        c.open_sftp().get(args[0], args[1])
        print("got", args[1])
    elif cmd == "driver":
        body = json.loads(args[2]) if len(args) > 2 else None
        print(json.dumps(driver(c, args[0], args[1], body), indent=1)[:20000])
    elif cmd == "exec":
        out = driver(c, "POST", "/exec", {"code": args[0], "token": driver_token(c)})
        print(out.get("stdout", ""), end="")
        if out.get("result") not in (None, "None"):
            print("result:", out.get("result"))
        if "error" in out:
            print("ERROR", out["error"], out.get("trace", ""))
            return 1
    elif cmd == "screenshot":
        # vm.py screenshot out.png [x0,y0,x1,y1] [scale]
        body: dict = {"window": "desktop"}
        if len(args) > 1 and args[1] != "-":
            body["bbox"] = [int(v) for v in args[1].split(",")]
        if len(args) > 2:
            body["scale"] = float(args[2])
        out = driver(c, "POST", "/screenshot", body)
        Path(args[0]).write_bytes(base64.b64decode(out["png_base64"]))
        print("wrote", args[0])
    elif cmd == "install":
        install(c)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
