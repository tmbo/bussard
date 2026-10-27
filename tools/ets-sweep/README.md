# ets-sweep

Runs ETS against knx-sim and records what ETS writes, for every product in the
corpus (epic #419). ETS has no scripting interface, so a driver inside the
Windows VM operates the ETS 6 GUI through Windows UI Automation; a sweep script
on the Mac starts a simulated device per product, has ETS download into it, and
keeps the capture. Nothing here links into the bussard crates: this directory
is Python run with `uv`, and knx-sim is a separate process.

## Pieces

- `driver/ets_driver.py` runs **inside the VM** in the interactive desktop
  session (the one showing ETS). It is a small HTTP service on
  `127.0.0.1:8765` wrapping pywinauto's `uia` backend: control-tree dumps,
  screenshots, a token-guarded `exec` for developing flows, and the hardcoded
  `/ets/<flow>` endpoints the sweep calls.
- `vm.py` reaches the VM from the Mac: ssh commands, sftp, and the driver over
  an ssh port forward (no inbound firewall rule in the VM). `vm.py install`
  uploads the driver; a running driver re-execs itself when its file changes.
- `sweep.py` is the per-run orchestrator: knx-sim config and process, dumpcap in
  the VM, the driver call, the wait on the sim's load-state events, the fetch of
  the capture and a `knxtrace ops` decode.

## VM facts (2026-10-26)

| what | value |
| --- | --- |
| host, user | `192.168.1.26`, `macremote` (password `WINDOWS_SSH_PW` in the repo `.env`) |
| ETS | 6.4.1 build 6.4.8718, `C:\Program Files (x86)\ETS6`, GUI process `ETS6N.exe` |
| desktop session | the RDP session of `macremote`; ssh commands run in session 0 and cannot see it |
| Python | 3.12 at `C:\Program Files\Python312\python.exe`, `pywinauto`, `pillow` |
| capture | the sim writes its own pcap (`gateway.pcap`); dumpcap exists but files were truncated when it was killed over ssh |
| driver files | `C:\Users\macremote\ets-sweep\` (`ets_driver.py`, `driver.log`, `driver.token`, `cap\`) |
| network | the VM reaches the Mac (`192.168.1.79`) over UDP; the Mac's stealth mode drops ping only |

PowerShell script files are blocked by the Restricted execution policy, which is
why the driver is Python.

## Starting the driver (once per VM boot)

ssh commands run in session 0 and cannot reach the desktop, and a scheduled
task with an interactive logon never ran from there (`schtasks /run` answered
"Element nicht gefunden", a one-shot trigger stayed at "has not run"). So the
driver is started by hand in the VM's RDP session, once; it then survives until
the VM reboots and re-execs itself whenever `vm.py install` uploads a new file:

    # in a PowerShell window of the RDP session (detached, no console)
    Start-Process "C:\Program Files\Python312\python.exe" -ArgumentList "C:\Users\macremote\ets-sweep\ets_driver.py" -WindowStyle Hidden

`uv run tools/ets-sweep/vm.py driver GET /health` confirms it answers and lists
the windows it sees (ETS must be among them).

## One run

```sh
tools/ets-sweep/winbuild-knx-sim.sh             # knx-sim.exe for the VM (Docker, once per sim change)
uv run tools/ets-sweep/vm.py install            # uploads the driver and knx-sim.exe
uv run tools/ets-sweep/vm.py driver GET /health
uv run tools/ets-sweep/sweep.py --knxprod knx-sim/tests/fixtures/KNX_Virtual_M-00FA.knxprod \
    --app M-00FA_A-2500-10-51CB --search DA.tp
```

Outputs land in `captures/ets-sweep/<app>/<variant>/` (gitignored): `ets.pcapng`
(the sim's own pcap of every datagram), `sim.log`, `driver.json` (every driver
step and ETS's history pane), `ops.txt` (`knxtrace ops`). The sim runs **inside
the VM** on `127.0.0.1:3672` (KNX Virtual holds 3671 there): ETS pings the
interface host before a download and the Mac's managed firewall drops ping.
ETS has `knx-sim (127.0.0.1:3672 Udp)` as a configured connection bound to the
`ets-sweep` project. First green run: 2026-10-27, DA.tp, "Programmieren(Appl.):
Abgeschlossen", all four objects Loaded, 50 operations in the capture.

## What ETS 6.4.1 exposes to automation (found 2026-10-27)

- The main window has **no UI Automation tree**: every view (control, raw,
  `FindAll`, `ElementFromPoint`, focus) returns the window itself and nothing
  below it, although the WPF provider answers `WM_GETOBJECT`. Menus, dropdowns
  and the `+` tab menu are separate popup windows **with** a normal tree, so
  the driver clicks the main window by screen position (Windows OCR for
  anchors, `LAYOUT` in the driver) and operates popups by UI Automation.
  The `Panels` dropdown is a popup without a tree; its submenu has one.
- Dialogs drawn inside the window (new project, connection manager, delete
  confirmation, "Schnittstellen-Prüfung") are overlays, read by OCR; the rest
  of the window is dimmed meanwhile, which hides grey text from OCR at native
  size, hence the magnified, contrast-stretched OCR for grid cells.
- A configured tunnelling connection is added under the toolbar connection
  dropdown, "Konfigurierte Verbindungen verwalten...": name `knx-sim`, server
  `192.168.1.79`, port 3671, protocol **Udp** (not Auto: the TCP attempt stalls
  against the Mac). "Für dieses Projekt verwenden" binds it to the sweep project.
- ETS **pings** the interface host before a download ("Ping Ergebnis:
  TimedOut" in the connection manager, then "Verbindungsqualität mit 1.1.1 ist
  zu schlecht" with no KNX packet sent). The Mac's firewall stealth mode drops
  ping and is a managed setting, so the sim runs in the VM instead
  (`winbuild-knx-sim.sh` cross-builds it; `vm.py install` uploads it).
- With the sim's default tunnel address 1.0.0 ETS asks about the medium of
  line 1.0 (IP in the standard topology); the sweep sets
  `gateway.tunnel_address: 1.1.254` (TP line 1.1) and the download flow
  answers "Beibehalten" should the dialog still appear.

## What ETS needs from the device that bussard never asked for

Each of these ended a run until the sim did it (all 2026-10-27, DA.tp):

| ETS behaviour | sim change |
| --- | --- |
| `TUNNELLING_FEATURE_GET 0x07` right after CONNECT, re-sent once, then disconnect | feature services, acknowledged like tunnelling requests, response under the server's sequence |
| waits for `L_Data.con` of every request | the gateway confirms each request (source filled with the tunnel address) |
| waits for the transport `T_ACK` before the answer | the bus puts a T_ACK in front of every application-layer response |
| expects the answer under the request's sequence number | responses mirror the request's NDT sequence |
| reads the description of PID_TABLE on object 2 before the download | a PDT 0x14 writable one-element description, as the house devices report |
| reads PID_DEVICE_CONTROL and, with verify mode set, waits for an `A_Memory_Response` after each write | verify-mode echo of every memory write |
| probes with a plain `SEARCH_REQUEST` | answered |

`tools/knxtrace` could not read dumpcap files that were killed over ssh
(truncated), which is why the sim writes its own pcap (`gateway.pcap`).
- The device added to an empty line 1.1 gets 1.1.1; the sweep deletes leftovers
  first, so the sim device is always 1.1.1.

## Part 2: the corpus in ETS's catalog (#421)

`uv run tools/ets-sweep/catalog.py [--filter a,b] [--limit N] [--redo]` uploads
each corpus `.knxprod` (`tests-support/product-corpus/cache/vendor`, vendor
data, never committed) to `C:\Users\macremote\ets-sweep\products\` and has
the driver run ETS's catalog import: the Katalog panel's Import button, the
`Produktdatei öffnen` file dialog (a Win32 dialog, driven by UI Automation),
`Alle Produkte importieren` on the selection page of a multi-product file,
`Alle Sprachen importieren`, then the result panel ("Import erfolgreich" with
`Produkt:` lines, read magnified). Outcomes land in `tools/ets-sweep/catalog.json`
(labels and the product names ETS printed; a file with an outcome is skipped
unless `--redo`). Importing a file ETS already holds just converts it again
and reports success, so a resumed run is idempotent. A large multi-product
file (the ABB i-bus catalogue) converts for well over 15 minutes; the flow
attaches to a conversion that is still running when a previous call timed out.
