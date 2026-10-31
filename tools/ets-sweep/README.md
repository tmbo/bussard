# ets-sweep

Runs ETS against knx-sim and records what ETS writes, for every product in the
corpus (epic #419). ETS has no scripting interface, so a driver inside the
Windows VM operates the ETS 6 GUI through Windows UI Automation; a sweep script
on the Mac starts a simulated device per product, has ETS download into it, and
keeps the capture. Nothing here links into the bussard crates: this directory
is Python run with `uv`, and knx-sim is a separate process.

In the triangle of ETS, bussard and knx-sim (`dev/testing.md`, "ETS, bussard
and knx-sim: the triangle"), the sweep is how ETS gets into the tests: ETS is a
capture tool, and the captures it takes here feed the offline oracle rows and
knx-sim's calibration replays. The synthetic product catalogue planned in #596
will run this sweep over fabricated `M-00FA` products whose captures can be
committed and replayed in CI.

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

**Stale catalogue entries.** ETS's catalogue keeps the first application it
imported under an order number and application version; a later import of
changed XML under the same version reports "imported" and changes nothing
(#650). The VM's catalogue still holds `NEST-TWIG5` version 1.0
(`syn-s7-lsm5` at application version 0x10, the variant ETS failed with
"System.ArgumentException: lsm") next to the captured 1.1; the
driver has no flow that removes a catalogue entry, so it stays. `capture.py`
refuses a re-capture of changed XML without a version bump and checks the
downloaded `PID_PROGRAM_VERSION` against the spec
(`tests-support/synthetic-products/README.md`, "Captures").

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

Result of the first full run (2026-10-27): 497 of 498 corpus files imported,
1 refused by ETS itself (`helios_kwl_knx_connect.knxprod`: "Masterdaten konnte
nicht gelesen werden"). `catalog-apps.json` maps every file to its 1354
application programs (id, name, mask, order numbers) via `bussard
import-product`; it is the join part 3 uses (order number = ETS catalog search
term, application id = what the sim and the oracle run).

Three things interrupted the run and are handled by the driver now: a missed
click on the result panel's OK left it covering the Import button (closed by
position and checked); an internal ETS error dialog ("Die Sammlung wurde
geändert") after a few hundred imports (dismissed and recorded); and ETS
restarting itself, reopening the project in its default panel layout
(`ensure_layout` maximizes, closes panels above Topologie, opens one Katalog
panel, and the catalog coordinates follow the panel's actual position).

## Part 3: the defaults sweep (#422)

```sh
uv run tools/ets-sweep/defaults.py [--filter ...] [--mask 07B0] [--shard k/n] [--redo-failed]
uv run tools/ets-sweep/oracle.py
```

`defaults.py` runs every corpus application (one job per application id, from
`catalog-apps.json`): sim in the VM, delete what line 1.1 holds, add the
catalog row whose order number and application version match, select the
knx-sim connection, application download, wait for the bus to go quiet, read
ETS's history. Results land in `results/defaults.json`; a run directory per
application under `captures/ets-sweep/<app>/plain-defaults/`.

**Identity learned from ETS.** Before a download ETS compares the device's
identity with what the product requires, and refuses with "inkompatible
Produktdaten" on a mismatch. Its log
(`%LOCALAPPDATA%\KNX\ETS6\Log\ETS6.log`) names the value it wanted:
`Required data mismatch at SystemProperty(0/78)[$0000]: <device> instead of
<required>`. `sweep.run_learning` reads those lines after a refusal and runs
again with the required values as sim property overrides (`properties:` in
the knx-sim device config); the learned values are kept per application.

`oracle.py` builds a scratch model per captured application (one device
1.1.1 at its defaults, no links; `oracle_model.py`) and runs the offline
oracle row against the capture into `results/oracle.json`, the load-control
verdict and its differences under `loadctl` (#419). Each product file is
imported once, into `.oracle-products/<sha>/`, and every row's model links
that import and pins its own device: a row of the 152 MB ABB catalogue takes
seconds and 228 KB instead of 3.5 minutes and 1.6 GB. From a worktree, read the
main checkout's captures and write nothing under them:
`--captures <main>/captures/ets-sweep --work <scratch> --seed-models` (the last
takes the model the sweep already imported as the product import, once per
file). `BUSSARD_PRODUCT_CORPUS` points a worktree at the main checkout's
corpus (`<main>/tests-support/product-corpus`).

**Wrong catalog row.** The driver takes the sole local catalog row of an order
number without checking its version cell (OCR truncates it). When the version
the row shows is readable and is not the job's, `defaults.py` records the job
as `skipped-catalog-version` instead of `captured` (Busch-Jaeger
`A-6109-50-71A0` ran against the row of version 1.1, 2026-10-29). ETS prints
the version octet's nibbles in decimal (0x1C is `1.12`, 0xB1 is `11.1`).
`defaults.py --relabel` applies the rule to the results already recorded,
without the VM.

What ETS needed from the sim in this part: connectionless
`A_DeviceDescriptor_Read` / `A_PropertyValue_Read` (ETS probes KNX Secure
capable devices before connecting), and the device identity above. A KNX
Secure capable product makes ETS ask for a project password a few seconds
after it is added and again at download; the plain pass answers Abbrechen,
which leaves the device's secure commissioning off.

## Manifest and parity summary

    uv run tools/ets-sweep/summary.py [--results DIR] [--no-history]

writes, next to the results: `manifest.json` (per application its labels only:
product file, mask, manufacturer, sweep outcome, oracle and load-control
verdict, coverage, and the ETS version of the run), `summary.md` (outcome
counts, identical / benign / differs per mask family and per manufacturer,
the verdict changes since the previous manifest) and `changes.json`; each
manifest is also kept as `history/manifest-<stamp>.json`. `benign.json`
(application id to reason, kept by hand) turns an explained `differs` into
`benign`. An application whose capture is newer than its oracle row is
`pending`.

Offline tests of the Mac-side pieces: `uv run tools/ets-sweep/test_ets_sweep.py`.

## Partial-download rows (#469)

A partial download (`bussard apply`, ETS's "Partiell") writes into a device
that already holds a full download, so its oracle row needs that device:

    uv run tools/ets-sweep/apply_rows.py captures/ets-sweep/<app> --product <file.knxprod> \
        --app <application id> [--work DIR] --run

reads a series directory (one run directory per step in name order, the first
a full download with links, each later one an ETS partial download after a
link change, each with `ets.pcapng`, `sim.yaml` and the `objects.json` the
driver read after the change), builds the bussard model of every partial step
(links from `objects.json`: an object with the transmit flag sends on its
first address and listens to the others) and writes one `run=apply` row per
step. `95-offline-oracle.sh` then starts knx-sim on loopback with the
captures of every earlier step replayed (`replay:` in the sim config, knx-sim
`src/replay.rs`), runs `bussard apply` against it, and `knxtrace statediff`
compares the device memory after it and the load-control records with ETS's
step. ETS rewrites a whole table in 12-octet chunks where bussard writes one
octet, so the comparison is on the final state of every octet either side
wrote, not on frames.

The captures stay where the sweep recorded them, under `captures/` (gitignored,
like every sweep capture); the rows file and the step models are generated
next to them or under `--work` with absolute paths and are not committed.
`apply_rows.py` is the tracked part. knx-sim must be built
(`cargo build` in `knx-sim/`, or `KNX_SIM_BIN`).

First run, EK-E72 series of 2026-10-28 (`M-00B6_A-4537-03-DE59`, steps B, C, D):
association table, group-object table and C flags identical in all three;
two differences in every step, both in `apply` only (the full download of step
A is identical under `flash`): `apply` writes the address table's first entry
(the device's own address, 2 octets) that ETS never writes, and its
`AbsSegment` records allocate the written table length with access `f2`
where ETS allocates the whole segment (`0x00ED`, `0x00EB`) with `ff`. In step
D ETS also restarts LSM 3 and rewrites the unchanged group-object table, which
`apply` skips.
`apply_rows.py --line-step b` adds a `run=apply-line` row for step B (`apply
--line 1.1`, the line mode's own path to the tables); on the EK-E72 it gives
the same verdict as the device row.

## Part 7: links variant and partial-download series (#478)

**Links variant, every product.** `defaults.py --variant links` runs the
applications the defaults sweep captured once more, with a few links made
before the download (`series.links_hook`: three objects linked to 1/0/1..,
transmitting objects first, and a second address on one of them), into
`captures/ets-sweep/<app>/links/` with the object table ETS showed after
linking (`objects.json`); outcomes in `results/links.json`.
`oracle.py --variant links` builds each row's model with those links
(`apply_rows.links_from_objects`) and writes `results/oracle-links.json`;
`summary.py` adds the links variant's parity per mask family.

**Partial-download series, representative products.**

    uv run tools/ets-sweep/series.py partial [--only M-00B6] [--steps abcd] [--oracle]

runs steps A to D (`a-full-links`, `b-partial-add-<n>`, `c-partial-remove-<n>`,
`d-partial-second-ga`) in one sim process per product, each step's slice of
the sim's pcap kept in its own run directory with `objects.json` and
`objects.png`. The objects come from what ETS shows at defaults
(`series.plan_links`; `series.py plan <objects.json>` prints the plan
offline). `results/series.json` records per product why it was chosen and each
step's outcome, and `summary.py` lists it. `--oracle` writes and runs the
`run=apply` rows plus the `line apply` row of step B on the Mac
(`--no-ets --oracle` for series already recorded). The representatives
(`series.REPRESENTATIVES`): Jung 3361-1M (0705, load control through
properties), MDT AKK (0705, through memory), Ekinex EK-E72 (0705,
group-object table in its own segment), Zennio ACTinBOX MAX6 (0701; the
Theben 4940275 the issue names failed the defaults sweep), KNX Virtual DA.tp
(07B0).

## Part 6: nightly run, manifests and the repair loop (#425)

**What runs.** `uv run tools/ets-sweep/nightly.py` (`--dry-run` prints the
commands): preflight (the driver answers and ETS is among its windows, else
the run stops), `cargo build` of bussard and knx-sim, every shard of
`defaults.py --redo-failed` one after the other and the links variant, the
oracle over every row again (`--redo`, so a bussard change shows as a verdict
change), `summary.py`, and `followups.py`. Log: `results/nightly/<stamp>.log`;
`results/run.json` holds the run id, the ETS version (the file version of
`ETS6N.exe`) and every command's exit code and seconds. A lock directory
(`results/nightly/lock`) keeps a second run out. Nothing is committed.

**Install (launchd, the default).** The agent is
`dev.bussard.ets-sweep.nightly`, 01:30 local time:

    sed -e "s|__REPO__|$PWD|g" -e "s|__HOME__|$HOME|g" \
        tools/ets-sweep/schedule/dev.bussard.ets-sweep.nightly.plist \
        > ~/Library/LaunchAgents/dev.bussard.ets-sweep.nightly.plist
    mkdir -p tools/ets-sweep/results/nightly
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.bussard.ets-sweep.nightly.plist
    launchctl kickstart gui/$(id -u)/dev.bussard.ets-sweep.nightly   # one run now, to check

Remove it with `launchctl bootout gui/$(id -u)/dev.bussard.ets-sweep.nightly`.
`schedule/crontab.txt` is the cron alternative (cron skips a night the Mac
slept through). The checkout the agent points at must not be a worktree that
gets removed, and nothing else may drive ETS during the run.

**Follow-up issues.** `followups.py` drafts an issue for every application
whose verdict went from identical to differs (application id, mask, product
file, capture path, the oracle summary and the first 30 lines of its diff)
and prints it; `--create` (`nightly.py --create-issues`) opens them with the
labels `bug`, `ets-sweep`, `oracle`, skipping an application an open issue
already names; `results/followups.json` remembers what was opened.

**Repair loop.** When a run of `sweep.run_one` fails, it keeps
`<run dir>/repair/`: `screen.png` (the desktop at half size), `popups.txt`
and `tree.txt` (UI Automation trees of ETS's popups and main window; the main
window has none, see above), `error.txt` (the error and the failing flow's
trace from the driver) and `repair.json` (the ETS version, which of these
worked). After an ETS update the fix is a diff against `driver/ets_driver.py`
made from those; the sweep is pinned to 6.4.1 build 6.4.8718.

**Manifest format** (`results/manifest.json`, labels only):

    {"generated": "<UTC iso>", "ets_version": "6.4.8718.0", "run": "<stamp>",
     "apps": {"<application id>": {"file": "<product file>", "mask": "07B0",
              "manufacturer": "M-0083", "outcome": "captured",
              "verdict": "identical|benign|differs|differs-props|not-comparable|oracle-error|pending|<outcome>",
              "loadctl": "identical", "coverage": "100.0%", "benign": "<reason>"}},
     "links": {...same per application, the links variant...},
     "series": {"<application id>": {"why": "...", "steps": {...}}}}

**One application by hand**: `uv run tools/ets-sweep/defaults.py --filter <application id> --redo`
then `uv run tools/ets-sweep/oracle.py --filter <application id> --redo`.

**Ports and names**: the driver on `127.0.0.1:8765` in the VM (reached over
ssh), the sim on `127.0.0.1:3672` in the VM, ETS's connection `knx-sim` and
project `ets-sweep`; on the Mac the `run=apply` rows bind a free loopback UDP
port per row.

## Part 4: KNX Data Secure (#423), not yet run

    export ETS_SWEEP_PROJECT_PASSWORD=<8-64 letters and digits>
    uv run tools/ets-sweep/secure.py jobs                    # the secure-capable captured applications
    uv run tools/ets-sweep/secure.py run --filter <app> --limit 1

`secure.py` runs every application the defaults sweep captured whose program
declares `IsSecureEnabled="true"` once more, in a project of its own
(`ets-sweep-secure`: set up once by hand as a copy of `ets-sweep` with the
`knx-sim` connection bound to it, because a project password would also lock
the plain sweep's project). The sim device starts in factory state with a
synthetic FDSK as its tool key and a synthetic serial number (PID 11), both
derived from the application id. The driver sets the project password when
ETS asks (`set_project_password`), types the device certificate when ETS asks
for one at the download (`enter_certificate`), and after the download exports
the keyring (`export_keyring`: the project tab's context menu, the save
dialog, the export password). The keyring lands next to the capture as
`project.knxkeys` (gitignored with the capture) and `knxtrace devices
--keyring` decides `decoded` / `partial` / `undecoded`; outcomes in
`results/secure.json`.

The driver's secure flows were written without ETS at hand (2026-10-30):
they anchor on dialog text and fail with what they saw, and the repair loop
keeps a screenshot. The certificate's 4-bit check is not confirmed either:
`secure.py cert --check "<label>"` on a real device's FDSK label prints its
serial and which check (`crc4-itu`, `crc4-plain`, `none`) it carries, never
the key; `run --check-variant` picks the one ETS takes.

## Part 5: generated parameter sets (#424), not yet run

    uv run tools/ets-sweep/params.py plan --app <application id> [--seed 1] [--n 3]   # offline
    uv run tools/ets-sweep/params.py run --filter <application id> --limit 1
    uv run tools/ets-sweep/params.py oracle --filter <application id>

`plan` draws N configurations per application, seeded: half of each
configuration's changes switch a page on (the parameter and value bussard's
`device --json` names for an inactive page, so only parameters ETS shows at
defaults), the rest are other enumeration and integer parameters of the
product model, each off its default. `run` adds the device as the defaults
sweep does, sets the changes through the driver (`param_pages`, `set_param`:
the device's parameter view, the page list and each parameter's row read by
OCR), downloads, and exports the project (`export_project`) next to the
capture in `captures/ets-sweep/<app>/params-<seed>-<n>/`; `params.json` there
says per change whether it was set, unreachable (not on any page the editor
found) or failed. `oracle` imports each export with `bussard import` and runs
the oracle row with the export as the product data, so the model holds
exactly what ETS downloaded; verdicts in `results/oracle-params.json`.

The parameter editor was written without ETS at hand (2026-10-30) and first
ran on 2026-10-31 (the synthetic run variants `partial` and `calc-input`):
the view is the device's `Parameter` tab (the device's context menu has no
parameter entry; the first version picked another entry and restarted the
device), the page list ends at x 1120 and the labels start at x 1140, both
above the catalogue pane (y 1300). Setting an integer by typing into its
field works (`Delay (s)`); enumerations and multi-page products are
unverified.

## Synthetic products: signing (#596)

    uv run tools/ets-sweep/synthetic/clone_datp.py              # DA.tp clone -> synthetic/out/ (gitignored)
    uv run tools/ets-sweep/synthetic/sign.py synthetic/out/KNX_Synthetic_DA_M-00FA.knxprod
    uv run tools/ets-sweep/synthetic/sign.py --dir-only <in.knxprod> [<out>]   # step 4 only, no hashes
    uv run tools/ets-sweep/synthetic/sign.py --verify <file.knxprod>   # the library's verdict per hash

A fabricated product under `M-00FA` carries the same integrity data as one
ETS exports: a `Hash` on the `ApplicationProgram`, on each `Product` and
`Hardware2Program`, `RegistrationSignature`s on their `RegistrationInfo`, and
an application id whose last four hex digits are a fingerprint of the
program's hash. bussard and knx-sim ignore all of it; ETS checks it.

`sign.py` uploads `synthetic/signer.cs` to `C:\Users\macremote\ets-sweep\signer\`,
compiles it with the .NET Framework `csc.exe` once per source change
(`signer.sha` holds the source digest), runs it on the product and downloads
the result (`<in>-signed.knxprod`). The signer is our own C#; it loads ETS's
`Knx.Ets.XmlSigning.dll` from the ETS 6 folder and calls its internal classes
by reflection (the DLL is obfuscated, the classes below keep readable names).
No ETS library is compiled against, copied or committed. Per manufacturer
folder it runs:

1. `Signer.ApplicationProgramHasher(file, {}, patchIds: true, null).HashFile()`
   per `*_A-*.xml`: computes the program's `Hash`, derives the fingerprint and
   rewrites the program under its new id (`A-2600-10-0001` becomes
   `A-2600-10-731A`), file renamed to match. The hasher deletes its input, so
   the signer hands it a renamed copy.
2. `Signer.HardwareSigner(Hardware.xml, oldToNewAppIds, appHashes, patchIds: true).SignFile()`:
   new `Hash` on `Product` and `Hardware2Program`, new
   `RegistrationSignature`s, `Hardware2Program` ids and `ApplicationProgramRef`s
   patched to the new application id.
3. `Signer.CatalogIdPatcher(Catalog.xml, oldToNewHardware2ProgramIds, null).Patch()`:
   `CatalogItem` ids and `Hardware2ProgramRefId`s follow.
4. `XmlSigning.SignDirectory(folder, false, null)`: writes `M-00FA.signature`
   next to the folder. The folder path must be **absolute**: with a relative
   path the library signs something else (the first signer ran on `work\M-00FA`
   and ETS refused its output), and its own check calls that signature
   invalid; with the absolute path the check says valid.

A product in another schema (`[application] schema = 11` of the generator,
#448) is signed in that schema: `sign.py` reads the namespace of the
application and passes `signer.exe --schema 11`, which hands the library's
hasher, hardware signer and catalog patcher that `targetSchemaVersion` (by
default they rewrite each file in project/23 and fail on a project/11 root:
"Das Präfix '' kann nicht von '.../project/23' in '.../project/11' ... neu
definiert werden", 2026-10-30), and the stub master becomes
`C:\ProgramData\KNX\XML\project-11\knx_master.xml`. ETS 6.4.1 imported the
signed project/11 product without complaint.

`knx_master.xml` is left as it is, except that a stub (no `<MasterData>`, the
`<KNX/>` of `tests-support/synthetic-products`) is replaced with ETS's own
`C:\ProgramData\KNX\XML\project-23\knx_master.xml` (`signer.exe --master`,
`sign.py --keep-master` to skip it): ETS 6.4 refuses the stub on import with
"Die Eingabezeichenfolge hat das falsche Format" (ETS6.log: a FormatException
in `MasterDataVersion.Update`, 2026-10-30). Check of the library: the KNX Virtual file
signed unchanged comes out byte-identical in every entry (plus the
`.signature`), and `--verify` reports every hash, registration signature and
the directory signature of the signed clone valid, the hashes of the unsigned
clone invalid. (`--verify`'s master data check calls every `knx_master.xml`
invalid, vendor files included; it is not what ETS checks.)

**What ETS 6.4.1 needs (2026-10-30)**: a valid `<manufacturer>.signature`.
Every refusal read "Import fehlgeschlagen! ... Projektdatei hat keine gültige
Signatur"; ETS6.log records nothing for it.

| file imported through `/ets/catalog_import` | ETS |
| --- | --- |
| unsigned clone (stale hashes, no `.signature`) | refused, "Projektdatei hat keine gültige Signatur" |
| signed, directory signed from a relative path | refused, same message |
| the same without `M-00FA.signature` | refused, same message |
| the same with the master data of an imported MDT ETS6 product | refused, same message |
| `knx-sim/tests/fixtures/KNX_Virtual_M-00FA.knxprod` itself, and a plain re-zip of it | refused, same message (the fixture has no `.signature`; it is not an importable product file) |
| signed with the absolute path (`sign.py` now) | **imported**, "Import erfolgreich ... Produkt: Synthetic Dimming Actuator"; `/ets/catalog_search SYN.da` finds "KNX Association, Synthetic Dimming Actuator, SYN.da, Dimmen, 1.0" |
| `--dir-only` (stale hashes, ids `A-2700-10-0001`, order number `SYN.db`) | **imported**, so ETS's import checks the directory signature and not the hashes |
| `--dir-only` of the `SYN.da` clone after the signed one | refused, "The product has a different hash than the existing product." |

`RegistrationInfo` stays `Registered` with the signatures the library writes;
`NotRegistered` was not needed. The catalogue shows the manufacturer as "KNX
Association" (M-00FA). Use the full signer for synthetic products: a download
or a project may look at the hashes the import does not.

**First download of the clone** (`sweep.py --knxprod <signed> --app
M-00FA_A-2600-10-731A --search SYN.da`): ETS added the device and downloaded,
51 operations, the same as the original DA.tp run of the same day except the
`PID_PROGRAM_VERSION` value (application number 0x2600). Both failed the same
way ("Programmieren(Appl.): fehlgeschlagen, Ein interner Gerätefehler ist
aufgetreten"): the sim's master reset with erase code 4 dropped the segment ETS
allocated before it (#600, fixed by #602).

## Synthetic products: calibration (#596 step 2)

    uv run tools/ets-sweep/synthetic/calibrate.py \
        --knxprod tools/ets-sweep/synthetic/out/KNX_Synthetic_DA_M-00FA-signed.knxprod \
        --app M-00FA_A-2600-10-731A --search SYN.da \
        --reference-knxprod knx-sim/tests/fixtures/KNX_Virtual_M-00FA.knxprod \
        --reference-app M-00FA_A-2500-10-51CB --reference-search DA.tp [--no-ets]

A synthetic product is only useful if ETS treats it like the product it
stands for. `calibrate.py` runs each product through the sweep
(`captures/ets-sweep/<app>/plain-defaults/`), writes `requests.txt` next to
the capture (`synthetic/distil.py`: the tool's `L_Data.req`s, retransmissions
once, the format of `knx-sim/tests/fixtures/*_requests.txt`), runs the defaults
oracle row of each (`oracle.run_row`), and compares: the `ops.txt` sequences
apart from `PID_PROGRAM_VERSION`, the request streams apart from the
application number, the oracle verdict, coverage and load-control verdict, and
knx-sim's replay of both fixtures (`ets_calibration.rs`,
`test_replay_spec_synthetic_matches_reference`, gated on
`KNX_SIM_CALIBRATE` and `KNX_SIM_CALIBRATE_REFERENCE`): each must reach Loaded
with no rejection and both must leave the same memory image. Without a
reference it runs the download, the fixture and the oracle row of one product.
Nothing it writes is committed: the clone is KNX Association data renamed.

Result for the signed DA.tp clone (2026-10-30, VM sim with #602): ETS
"Abgeschlossen" for both, 50 operations each, identical apart from the
`PID_PROGRAM_VERSION` value; 95 requests each, identical apart from the
application number octet in that property write (`00fa25..` vs `00fa26..`);
oracle `identical`, coverage 100.0%, load control `identical` for both; the
replay reaches Loaded on objects 1 to 4 with the same segments and images
(0xA000 2, 0xC000 2, 0x8000 148, 0x6000 256 octets) for both.

## Synthetic products: the generator (#596 step 3)

    uv run tests-support/synthetic-products/generate.py --zip syn-minimal
    uv run tools/ets-sweep/synthetic/sign.py tests-support/synthetic-products/syn-minimal/build/syn-minimal.knxprod
    uv run tests-support/synthetic-products/generate.py syn-minimal \
        --signed-id tests-support/synthetic-products/syn-minimal/build/syn-minimal-signed.knxprod
    uv run tools/ets-sweep/synthetic/calibrate.py \
        --knxprod tests-support/synthetic-products/syn-minimal/build/syn-minimal-signed.knxprod \
        --app M-00FA_A-2700-10-D80E --search SYN.min

The products are TOML specs under `tests-support/synthetic-products/` (its
README has the schema, the id rule and the flow). Result for `syn-minimal`
(2026-10-30, ETS 6.4.1, VM sim with #602): signed id `M-00FA_A-2700-10-D80E`;
the import with the stub master was refused (see the signing section), with
ETS's master put in by the signer it imported ("Import erfolgreich ...
Produkt: Synthetic minimal", catalogue row "KNX Association, Synthetic
minimal, SYN.min, Synthetisch minimal, 1.0"); the download ended
"Programmieren(Appl.): Abgeschlossen" with objects 1 to 4 Loaded, 43
operations, 83 tool requests; the oracle row is `identical`, coverage
100.0%, load control `identical` (17 records), `par=ok(256) gobj=ok(4)
assoc=ok(2) addr=ok(2) props=ok(1)`.

## Synthetic products: committed captures (#596 step 5)

    uv run tools/ets-sweep/synthetic/capture.py syn-minimal

`capture.py` runs render, zip, sign, `--signed-id`, the catalogue import and
search, the `defaults` download (`calibrate.py`) and the oracle row of the
committed files, and writes `captures/synthetic/<product>/defaults/`,
`captures/synthetic/rows.txt` and `captures/synthetic/manifest.json` (the
flow and layout: `tests-support/synthetic-products/README.md`, "Captures").
`winbuild-knx-sim.sh` writes the commit it built from next to `knx-sim.exe`
(`knx-sim.exe.git`) for the manifest.

Result for `syn-minimal` ("Nest-side light switch", `NEST-LIGHT`,
2026-10-30, ETS 6.4.1 build 6.4.8718, VM sim built from 06a27ec0): the first
import of the renamed product broke ETS's catalogue ("Der angegebene
Schlüssel war nicht im Wörterbuch angegeben", a KeyNotFoundException in the
catalogue refresh, on every later catalogue action and after a restart):
`generate.py` left the `-` of `NEST-LIGHT` unescaped in the product and
catalogue item ids, where ETS escapes it (`.2D`, as in Enertex
`M-00A6_H-00000030-0_P-1176.2D08`). With the id fixed, the `M-00FA` product
store moved aside (`C:\ProgramData\KNX\ETS6\ProductStore-aside-M-00FA-20261030-145024`)
and `SYN.da` and `SYN.db` imported again, the product imported and
`catalog_search NEST-LIGHT` finds it. The download ended "Programmieren(Appl.):
Abgeschlossen", objects 1 to 4 Loaded, 43 operations, 83 tool requests; the
signed id is unchanged (`M-00FA_A-2700-10-D80E`: the application's hash does
not cover the product texts). `PID_PROGRAM_VERSION` on the wire is
`00fa 2700 10` (manufacturer, application number, version), so the rows name
the rendered id. The row of the committed files (the `xml/` zipped with the
stub master): `identical`, coverage 100.0%, load control `identical` (17
records), `par=ok(256) gobj=ok(4) assoc=ok(2) addr=ok(2) props=ok(1)`.

## Synthetic products: run variants (#596 step 5)

    uv run tools/ets-sweep/synthetic/capture.py <product> --variant <variant> [--sim-build SHA]

A run variant is another download of a synthetic product (#604, "Run
variants"; the table is in `tests-support/synthetic-products/README.md`,
"Run variants"). `capture.py` signs and imports every product the variant
downloads, starts ONE knx-sim in the VM with the variant's product (as
`series.py` does for the partial series), and runs the downloads in order:
for each, the device added to the project when its product changes
(`other-app`), the links (`link` flow), the parameter changes
(`param_pages`/`set_param`, as `params.py` uses them), the object table
(`objects`), the download in the step's mode (`application`, or `partial`
for ETS's "Partiell"), the wait for the device's restart, ETS's history, and
the step's slice of the sim's pcap. The run directory is
`captures/ets-sweep/<signed id>/<variant>/<step>/` (gitignored); the last
step is copied to `captures/synthetic/<product>/<variant>/`, the earlier
ones as `base.pcapng` and `base-requests.txt`. The row's options follow the
variant: `state=loaded` for a System 7 download into a programmed device,
`dir=<variant>/model` for a model template with links or a parameter value,
`run=params base=<variant>/base.pcapng` for the partial download
(`95-offline-oracle.sh` replays the base into a loopback knx-sim, runs
`bussard flash --parameters-only` against it and compares the device state).

Results (ETS 6.4.1 build 6.4.8718, VM sim 06a27ec0):

- `reload` of `syn-s7-0705` (2026-10-30): both downloads "Programmieren(Appl.):
  Abgeschlossen", 44 operations each. The second download's 85 tool requests
  are identical to the first's and to the `defaults` capture: on a device
  that holds the same application ETS runs no pre-download unload of LSM 1
  to 4 and no restart, it goes straight to the procedure's own unloads of
  LSM 1 to 3 (#488). Row: memory `identical` (100.0 %), load control
  `differs(1, first obj4#1 unload)`: bussard plans the pass on a device with
  loaded LSMs (`state=loaded`). With `state=fresh` the same capture compares
  `loadctl=ok(19)`.
- `reload` of `syn-s7-0701` (2026-10-31): both downloads "Abgeschlossen"
  (77 and 57 operations). The second one also starts with the procedure's
  own unloads of LSM 1 to 3 (`14`, `24`, `34` at `0x0104`), no LSM 4 record,
  no restart, and read-compares instead of writing: every segment it would
  write is read back in 12-octet reads and found equal, so it writes no
  memory, only the load-state records. Row: written octets `not-comparable`
  (none), read-confirmed octets `identical`, load control
  `differs(1, first obj4#1 unload)` (`expect=not-comparable
  confirmed=identical loadctl=differs state=loaded`).
- `other-app` of `syn-s7-0705` (2026-10-31): `syn-s7-hidden-default` (0705)
  downloaded first, then `syn-s7-0705` into the same sim; both "Abgeschlossen".
  The second download is request for request the `defaults` download: no
  pre-download pass for a device that holds another application either.
  Row: memory `identical`, load control `differs(1, first obj4#1 unload)`.
- `other-app` of `syn-s7-0701` (2026-10-31): `syn-s7-lsm5` first, then
  `syn-s7-0701`; the second download equals the `reload` one (unloads of LSM 1
  to 3, read-compare, no memory written, the TaskSegment records name
  `syn-s7-0701`). Row as `reload`. ETS reads no application id before a
  System 7 download, so it cannot tell a programmed device from a fresh one,
  and it sends the same stream (#488).
- `no-ga` of `syn-minimal` (2026-10-31): ETS's object table before the
  download shows both objects without an address (`objects.json`). The
  download is request for request the `defaults` one: both tables loaded with
  a count of 0 (`00 00` at `0xA000` and `0xC000`) and completed (#542). Row:
  `identical`, `addr=ok(2) assoc=ok(2)`, load control `identical`.

Driver fixes the variants needed (2026-10-31): the objects tab is clicked
where OCR reads it (with no `Kanäle` tab the fixed position hit `Parameter`);
the line view's `Geräte` tab is clicked before the device list is read (after
a device view the line reopened on `Segmente`, so no device was deleted and
`catalog_add` stacked devices at 1.1.2, 1.1.3); `objects`, `link` and
`unlink` take `numbers`, the object numbers the table lists, because Windows
OCR reads neither a lone `0` nor a lone `1`; `link` waits up to 12 s for its
dialog, answers ETS's question about an address that already has another
object size with OK, and clears the row selection before it reads the link
back (OCR reads nothing on a selected row).
- `links` of `syn-minimal` (2026-10-31): the switch object linked to 1/0/1
  and 1/0/2, the status object to 1/0/3, then the application download. ETS
  writes the address table `0003 0801 0802 0803`, the association table
  `0003 0001 0000 0003 0001 0002 0000` (1/0/1 to object 0, 1/0/3 to object
  1, 1/0/2 to object 0) and the group-object table `00014f00`
  (`00014b00` with no links). Row (`dir=` the committed model template with
  those links): `identical`, `addr=ok(8) assoc=ok(14) gobj=ok(4)`, load
  control `identical` (#478, #540).
- `partial` of `syn-minimal` (2026-10-31): a defaults download, then
  `Delay (s)` set from 300 to 500 in the parameter editor and ETS's
  "Partiell" download (23 operations): reads of obj 4's load state and
  `PID_PROGRAM_VERSION`, obj 5's load state and obj 4's
  `PID_TABLE_REFERENCE`, then obj 4 Unload, StartLoading, `LdCtrlRelSegment`
  256 octets Mode 0 without fill, `PID_TABLE_REFERENCE` again, 3 octets at
  `0x6000` (`01 01 f4`), `PID_PROGRAM_VERSION`, LoadCompleted, restart.
  Objects 1 to 3 are not touched. Row (`run=params`, knx-sim replaying the
  defaults download, then `bussard flash --parameters-only`): `identical`,
  `memory 0x6000=ok(3)`, load control `identical` (4 records) (#543, #490).
  `bussard apply` refuses this device, which has no links (#542).
- `calc-input` of `syn-param-calculation` (2026-10-31): `Delay (s)`, the
  calculation's input, set from 300 to 500, then the application download
  into a fresh sim. ETS wrote `01 01 f4 03 e9 01 fb` at `0x6000`: both
  outputs computed (1001 and 507), the hidden `LegacyPatchAlways` one
  included. At defaults it wrote `00 00` for both: ETS runs the script when
  an input changes. Row (`dir=` the model template with `delay-s = 500`):
  `differs`, `par=4/256@+0x3` (bussard runs no calculation), pinned
  `expect=differs` (#427).
