# Commissioning devices

This is the device lifecycle guide: getting a physical KNX device onto the bus and into
your model, without ETS. It covers the guided wizard (`adopt`), fetching product data by
order number (`import-product`), the Terraform-shaped link downloader (`plan` / `apply`),
the first application download (`flash`), and the ETS-free bootstrap of a whole line
(`reconstruct --line`).

For install, monitoring, and reading/writing group values, start with
[getting-started.md](getting-started.md). For the `.knxprod` format and the models it
generates, see [product-data.md](product-data.md).

## Safety model

Every bus-writing command follows the same ladder: read the live state first, show a plan,
confirm on a terminal (`y/N`), write, then verify the result by reading it back. `apply`
also writes a backup before touching anything. Two hard gates apply:

- **System B only.** `plan`, `apply`, `reconstruct` and `flash` support mask `07B0`
  devices for now, and refuse anything else cleanly before writing.
- **A terminal to confirm on.** Without a TTY these commands refuse unless you pass `--yes`
  (`--yes-download` for `import-product`). That is deliberate: a bus write moves actuators.

The real first writes should happen against a spare device, the [virtual test
harness](#power-users-the-virtual-device-harness), or KNX Virtual, not straight onto a
live installation.

## adopt: the guided new-device wizard

You wired in a new device and want it in the model. `bussard adopt` orchestrates the
whole flow: get product data, assign an address in programming mode, verify the write
against the product's order numbers, write a rich device file, and hand you ready-to-paste
`groups.yaml` / `links.yaml` snippets plus the next commands.

Point it at the device's `.knxprod` (or omit `--product` to pick a cached model, or go
product-less). Then press the programming button when it asks.

```console
$ bussard adopt --product MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
bussard adopt — the guided new-device flow
  step 1/5  product data
  cached vendor file: knx/vendor/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
  using application MDT Switch Actuator AKK (M-0083_A-000D-23-5BFD)
  step 2/5  assign an address
device in programming mode: 15.15.255 (its current address)
adopt 15.15.255 → 1.1.5? [y/N] y
wrote 1.1.5; verifying…
  step 3/5  write the device file
  wrote knx/devices/1.1.5-mdt-switch-actuator-akk.yaml
  step 4/5  wire the group objects
  most-useful com objects (transmit-capable first):
    #0   dpt 1.001    flags CRWT   Switch channel A
    #4   dpt 1.001    flags CRT    Status channel A
    ...

  ready-to-paste snippets (edit the group address to a free one):
    # ---8<--- groups.yaml (under `groups:`)
    "0/0/1":
      name: "Switch channel A"
      dpt: "1.001"
    # ---8<--- links.yaml (under `links:`)
    "1.1.5":
      - object: 0
        name: "Switch channel A"
        send: "0/0/1"     # or `listen: ["0/0/1"]` for a receiving object
    # --->8---
  step 5/5  summary

adopted 15.15.255 → 1.1.5
  verified: mask 0x07b0 (System B)
  device file: knx/devices/1.1.5-mdt-switch-actuator-akk.yaml
  product: MDT Switch Actuator AKK (28 com objects)

what remains manual:
  1. edit the name/room in knx/devices/1.1.5-mdt-switch-actuator-akk.yaml
  2. wire the group objects: edit links.yaml (snippet above)
  3. `bussard plan 1.1.5`   — preview the tables
  4. `bussard apply 1.1.5`  — write them to the device

if this device is factory-fresh (never downloaded), it needs its first application
download before links take effect:
  - `bussard flash 1.1.5`  — download the application
```

The target address defaults to the next free device number on the model's dominant line;
adopt confirms it before writing. If it finds more than one device in programming mode it
stops and tells you to leave prog-mode on all but the one you want.

**Order-number cross-check.** After writing the address, adopt reads the device's order
number back and compares it to the product's. A mismatch does not abort, but it prints a
loud warning that the `.knxprod` may not match the hardware, so double-check before wiring
links.

`adopt` is an interactive wizard and needs a terminal. To drive it from a test or script,
supply both `--product` and the target address via the `BUSSARD_ADOPT_ADDRESS` environment
variable.

## import-product by order number

If you know the order number but not where to find the file, let the pointer index fetch
it. `bussard import-product --list` shows what is indexed; `--order-number` looks it up,
confirms, downloads, and verifies the checksum before importing.

```console
$ bussard import-product --order-number "AKK-0216.03"
Found in the product-data index:
  MDT — MDT Switch Actuator AKK (compact, REG)
  order number: AKK-0216.03
  download:     https://www.mdt.de/fileadmin/.../MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
  file:         MDT_KP_AKK_03_Switch_Actuator_V23.knxprod (334088 bytes)
  sha256:       05b20395667510c16b83c47d46935a69f52b4534d71371f848f96141b74ca1b9

This downloads copyrighted vendor product data over the network. It is cached locally
under knx/vendor/ and never committed.
Download this file? [y/N] y
Downloading…
Downloaded and verified 334088 bytes.
Cached vendor file (downloaded): knx/vendor/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
Generated 1 model file in knx/models:
  models/M-0083_A-000D-23-5BFD.yaml
```

The byte size **and** SHA-256 are checked against the index; a mismatch is a hard error
(the vendor may have re-published the file). Pass `--yes-download` to skip the prompt (or
to consent on a non-TTY). Order-number matching is case- and whitespace-insensitive but
keeps interior separators, so `AKK-0216.03` matches `akk-0216.03` but not `AKK021603`. The
full index schema and the never-redistribute rule live in
[product-data.md](product-data.md).

## plan and apply: the link downloader

Once a device has its address and its com-objects are wired in `links.yaml`, `plan` and
`apply` are the read/write pair that pushes those links onto the device. `plan` is
**read-only on the bus**: it reads the device's live group-address and association tables
and shows exactly what `apply` would change.

```console
$ bussard plan 1.1.5
plan for 1.1.5 — mask 07B0 (System B)

2 addition(s), 1 removal(s), 3 unchanged:
  + add:    object    0 → 0/0/1
  + add:    object    4 → 0/1/1
  - remove: object    7 → 2/4/9

table sizes: group addresses 4 → 5, associations 4 → 5

load operations `apply` would run (in order):
  StartLoading → write → LoadCompleted: address table
  StartLoading → write → LoadCompleted: association table

run `bussard apply 1.1.5` to write these changes (with confirmation).
```

The removal is the point: a `2/4/9` link left on the device but absent from `links.yaml`
(a ghost link from an earlier ETS download) shows up as a `- remove`, so you see what
`apply` will prune, not just what it adds. If the model already matches the device, `plan`
prints `nothing to do` and `apply` exits 0 without touching any load state.

`apply` runs the same plan, then confirms, backs up, writes, and verifies:

```console
$ bussard apply 1.1.5
plan for 1.1.5 — mask 07B0 (System B)

2 addition(s), 1 removal(s), 3 unchanged:
  + add:    object    0 → 0/0/1
  + add:    object    4 → 0/1/1
  - remove: object    7 → 2/4/9
...
apply 3 change(s) to 1.1.5? [y/N] y
backup written to knx/captures/backups/1.1.5-1758042000.json

apply verified: address table Loaded (5 entries), association table Loaded (5 entries)
```

The pre-state tables are written to `knx/captures/backups/<ia>-<timestamp>.json` before
any write. On any failure `apply` prints that backup path and recovery guidance: the
tables are rewritten wholesale, so re-running `apply` is safe and idempotent. Pass `--yes`
to skip the prompt in scripts. `plan` refuses to compute an empty table set for a device
with no links in the model (that would wipe it); add links first, or check the address.

## flash: the first application download

A factory-fresh device needs its application program downloaded before any links take
effect. `bussard flash` does that first download straight from the vendor `.knxprod`, with
no ETS in the loop. Give it the device address and the product file; it selects the
application (the sole one, or `--application <REF>`), builds a pre-flight plan, and refuses
before writing anything if the device or the procedure is unsupported.

```console
$ bussard flash 1.1.5 --product MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
Flash plan for 1.1.5
  application : M-0083_A-000D-23-5BFD MDT Switch Actuator AKK
  app number  : 13 (version 35)
  mask        : app 07B0 vs device 07B0 — compatible
  writes      : 512 byte(s) across 8 step(s), ~8 memory frame(s), est. 2.4s on TP1
  procedure   :
      1. unload application
      2. open application for loading
      3. allocate segment (480 bytes)
      4. write code image (480 bytes) at segment+0
      5. allocate segment (32 bytes)
      6. write parameters image (32 bytes) at segment+0
      7. complete load
      8. restart device

NOTE: a first flash assumes the device is factory-fresh; no backup is
possible (there is no prior application to save). Recovery from a failed
flash is re-running `bussard flash`.
flash M-0083_A-000D-23-5BFD (2 memory write(s)) to 1.1.5? [y/N] y
  [1/8] unload application
  [2/8] open application for loading
  ...
      512/512 bytes

flash verified: application program M-0083_A-000D-23-5BFD is Loaded on 1.1.5
```

The safety story is the pre-flight plan. `flash` refuses **before any write** when:

- the device is not System B: `device 1.1.5 reports mask 57B0 (…) — bussard flash supports
  System B (mask 07B0) only for now`;
- the app's mask does not match the device;
- the load procedure contains an operation the downloader cannot execute (see below).

Unlike `apply`, a first flash has **no backup**: there is no prior application to save, so
the note says so plainly. Recovery from a failed flash is re-running `bussard flash`: the
download is idempotent (it re-unloads and rewrites the application wholesale) or you fall
back to ETS. After writing, `flash` verifies two things: the application object reads back
as `Loaded`, and a sample of each written segment is read back and compared byte-for-byte.

### Honest limitation

`flash` executes the common single-LSM System B download path:
`Unload`/`Load`/`LoadCompleted`/`RelSegment`/`WriteRelMem`/`WriteMem`/`WriteProp`/`Restart`.
Some devices use load procedures with operations bussard does not yet execute:
`LdCtrlAbsSegment` (absolute segment allocation, unverified), `LdCtrlTaskSegment`,
`LdCtrlTaskCtrl1`, or vendor ops like `LdCtrlLoadImageProp`. For those the pre-flight
refuses the whole procedure rather than leave the device half-flashed:

```console
$ bussard flash 1.1.7 --product some-device.knxprod
cannot flash: load procedure contains the unsupported operation LdCtrlLoadImageProp —
`bussard flash` cannot execute it and refuses the procedure rather than leaving the device
partially flashed (supported: Unload/Load/LoadCompleted/RelSegment/WriteRelMem/WriteMem/
WriteProp/Restart on a single-LSM System B device)
```

Those procedures remain an ETS-only path for now, and are a documented follow-up.

## reconstruct: onboarding without ETS

If you inherited an installation with no `.knxproj`, `reconstruct` bootstraps a model from
what the devices already carry. Two modes:

**One device.** `bussard reconstruct 1.1.4` reads a System B device's group-address and
association tables and diffs them against your `links.yaml`, so you can see where the model
drifted from reality:

```console
$ bussard reconstruct 1.1.4
device 1.1.4 — mask 07B0 (System B)
  address table read via memory
  association table read via memory

inventory: 4 group address(es), 4 association(s), 2 linked object(s)
  object   12: 3/0/4
  object   13: 3/0/5

diff against the model (3 match, 1 only on device, 0 only in model):
  + on device, not in model: object   12 → 1/6/2
  note: send/listen direction is not recoverable from the address and association tables
  alone (the transmit flag lives in the group object table); the diff compares GA sets per
  object
```

The diff compares GA **sets** per object: the address and association tables recover which
GAs an object links to, but not the transmit direction (that flag lives in the group
object table, which many devices do not expose), so a `send:` and a `listen:` are treated
alike.

**A whole line.** `bussard reconstruct --line 1.1 --out fresh/` sweeps the line like `scan`
(sequentially, so it takes a while), reads every System B device's tables, and synthesizes
a brand-new model into a fresh directory. `--out` must be absent or empty; reconstruction
never merges into an existing model.

```console
$ bussard reconstruct --line 1.1 --out fresh
sweeping line 1.1.0–255 sequentially — estimated up to 13m38s on TP1
sweep complete: 3 device(s) found
reconstructed line 1.1 into fresh

3 device(s) responded: 2 read (System B), 1 recorded as stubs
  1.1.4  mask 07B0 (System B)  — 4 GA(s), 2 link(s)
  1.1.7  mask 07B0 (System B)  — 6 GA(s), 3 link(s)
  1.1.30 mask 0705 (System ?)  — stub: not System B; tables skipped, recorded as a device stub

synthesized 9 group address(es) and 5 link(s)

next steps:
  • names & DPTs are placeholders — run `bussard monitor --dir fresh` to observe live
    traffic and name what each GA does; add `dpt:` in groups.yaml as you learn it.
  • send/listen direction is unknown (all GAs recorded as listen) — correct it as you
    observe which object transmits.
  • run `bussard validate --dir fresh` — W011 (no DPT) warnings are expected and honest.
```

The synthesized model is a scaffold, not ground truth. Every file carries a loud banner
saying so: GA and com-object names are placeholders, DPTs are unknown (so `validate` warns
W011), directions are recorded as `listen:`, and com-object flags are placeholder `CW`
stubs so the model validates. Non-System-B devices are recorded as stubs (mask noted,
tables skipped). Watch the bus with `monitor` and annotate as you learn.

## Power users: the virtual device harness

To exercise the management stack against an independent, foreign KNX implementation rather
than bussard's own mocks, the repo ships a test harness that builds
[thelsing/knx](https://github.com/thelsing/knx) and runs it as a separate process over
KNXnet/IP routing. See
[`tests-support/virtual-device/README.md`](../tests-support/virtual-device/README.md).

It documents an interop wall worth knowing about: the only thelsing binary that speaks IP
multicast reports mask `57B0` (KNXnet/IP System B), so it clears `assign` and `scan` but
hits the `07B0` gate on the table-level rungs (`reconstruct`, `apply`). KNX Virtual
(Windows) works for discovery and assign, but management reads need a loaded application.
The upshot: `assign`/`scan` are validated against a foreign peer today; the full table
cycle needs a `07B0`-reporting device (a spare TP actuator, or a TP-UART variant).
