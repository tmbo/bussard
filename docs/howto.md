# How do I ...

Recipes for everyday bussard work. Each assumes a model directory (default `knx/`; every command takes `--dir`). Flags and fields are in the [reference](reference.md); install and first steps are in the [README](../README.md).

Three KNX terms the recipes rely on:

- A group address (GA, `3/2/0`) is the bus's pub/sub topic: a telegram sent to a GA carries one value, and every device listening on it reacts. `groups.yaml` names each GA and records its datapoint type (DPT), which tells bussard how to decode the value.
- An individual address (IA, `1.1.4`, area.line.device) is a device's unique bus address, used for commissioning and diagnosis.
- A com object is one input or output slot of a device, such as "channel A: move up/down" on a blind actuator. Linking it to a GA in `links.yaml` makes the device send on or listen to that address. In the compact `CRWTUI` flag string, W means the object accepts writes (a command input) and T means it transmits (a status output).

A word on safety before the writing recipes: every bus-writing command reads the live state first, shows a plan, confirms on a terminal (`y/N`), writes, then verifies by reading back. `apply` also backs up first. `plan`, `apply`, `reconstruct` and `flash` support the System B (`07B0`, `27B0`, `57B0`) and System 7 (`0705`, `0701`, `0700`) masks and refuse anything else before writing; [SAFETY.md](SAFETY.md#supported-device-masks) has the table, and `bussard audit` shows it per device. A write to a non-loopback gateway is refused unless you opt in with `--allow-remote-gateway`. Do the first real writes against a spare device or the simulator, not a live installation. Read [SAFETY.md](SAFETY.md) once before you start writing.

## ... watch and decode the bus?

```console
$ bussard monitor
12:03:41.221  1.1.7 Weather Station    → 3/0/0 Wind Alarm           = Alarm (1.005, obj "Wind Alarm")
12:03:44.809  1.1.1 Push Button Hallway → 0/0/0 Hallway Light Switch = On (1.001, obj "Rocker 1")
12:03:44.981  1.1.3 Switch Actuator     → 0/0/1 Hallway Light Status = On (1.001)
```

Every telegram resolves to its GA name, the sending device, and a typed value. Flip a switch and watch it name itself. Narrow the stream with `--filter 3/2/0,1/0/` (GAs, GA prefixes, or sender IAs); `--json` emits one JSON object per line for tooling. GAs missing from the model show as raw hex; add them to `groups.yaml` with a `dpt:` and re-run.

## ... see the whole network in a browser?

```console
$ bussard viz
bussard viz serving on http://127.0.0.1:8080 (Ctrl-C to stop)
read-only: group writes return 403 (pass --allow-writes to enable them)
```

Open the address to get a bus-spine diagram of every device by floor and room, the group-address tree, and live telegrams pulsing along the spine as they happen. Select a device or GA to see its links, senders, and listeners. With no reachable gateway the page still shows the model, just without live traffic. See [the viz server](reference.md#the-viz-server) for the endpoints.

A bare `bussard viz` is a viewer: it never transmits, so it is safe to point at the live installation. Add `--allow-writes` to arm the per-DPT test-write widgets, and then the same real-gateway gate as `bussard write` applies — against a non-loopback gateway the server refuses to start without `--allow-remote-gateway`. Every armed write asks for an explicit confirmation naming the GA and the gateway, and a `protected` GA needs the force checkbox on top of that.

## ... find out what I have?

```console
$ bussard audit
== Model ==
project: my-house   imported from: my-house.knxproj
38 device(s), 214 group address(es), 402 link(s)
  line 1.1: 38 device(s)
...
== Devices per mask ==
  07B0 System B (29 device(s)): bussard can: plan/apply, flash, reconstruct, describe
  0705 System 7 (7 device(s)): bussard can: plan/apply, flash, reconstruct, describe
  0012 System 1 (2 device(s)): bussard can: describe only
```

`audit` reads the model and reports what an owner or integrator needs next: devices without a name or a location, GAs without a DPT, links to com-objects the device file does not declare, one-sided links (a GA with senders but no listener, or the reverse), what bussard can do with each device's mask, protected GAs, and the KNX Secure devices. Pass `--keyring <file.knxkeys>` (password in `BUSSARD_KEYRING_PASSWORD`) to see which Secure devices the keyring covers.

Add `--live` to also ask the gateway for its tunnel budget, sample the bus for `--window` seconds (default 30) and probe every modelled device. The live part only reads: it never sends a group telegram. `--json` emits the same report as one object, which is also what Claude gets from the `knx_audit` MCP tool.

Unlinked com-objects and unused GAs are counted, not flagged. Actuators ship far more objects than a project links, and a GA with no link at all is a reserve address.

## ... get past "no free tunnelling connection"?

A KNXnet/IP interface has a fixed number of tunnel slots, often one to five, and every connected client holds one: Home Assistant's KNX integration, an open ETS project, `bussard viz`, `bussard mcp`, or another bussard command still running. When all are taken the interface answers a connect with `E_NO_MORE_CONNECTIONS`, and bussard says so and exits with code `4` instead of timing out. `bussard init --gateway <ip>` and `bussard audit --live` print `N tunnels, M in use` when the interface reports it. Stop one of the other clients, or switch a long-running one to routing (`--routing`) if your interface supports multicast. More in [SAFETY.md](SAFETY.md#the-tunnel-budget).

## ... find out what devices are on my line?

```console
$ bussard scan 1.1
IA         MASK    SYSTEM     MANUFACTURER    ORDER             MODEL
1.1.1      07B0    System B   MDT             BE-06001.02       known
1.1.4      07B0    System B   Albrecht Jung   23024 1S R        known
1.1.47     07B0    System B   MDT             JAL-0810.03       NOT in model

3 device(s) responded
1 not in model
all model devices on this line responded
```

The delta is the point: which devices are known, which are unexpected, and which model devices did not answer. The scan probes addresses one at a time (most gateways cannot multiplex connection-oriented sessions), so a full line takes a while; narrow it with `--from`/`--to`.

## ... add a brand-new device?

Get the device's `.knxprod` first. If you know the order number (the scan shows it), the pointer index can fetch and verify it:

```console
$ bussard import-product --order-number "AKK-0216.03"
Found in the product-data index:
  MDT — MDT Switch Actuator AKK (compact, REG)
  ...
Download this file? [y/N] y
Downloaded and verified 334088 bytes.
Cached vendor file (downloaded): knx/vendor/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
Generated 1 model file in knx/models:
  models/M-0083_A-000D-23-5BFD.yaml
```

Then run the wizard and press the device's programming button when it asks:

```console
$ bussard adopt --product knx/vendor/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
bussard adopt — the guided new-device flow
  step 1/5  product data
  step 2/5  assign an address
device in programming mode: 15.15.255 (its current address)
adopt 15.15.255 → 1.1.5? [y/N] y
wrote 1.1.5; verifying…
  step 3/5  write the device file
  wrote knx/devices/1.1.5-mdt-switch-actuator-akk.yaml
  step 4/5  wire the group objects
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
  step 5/5  summary

adopted 15.15.255 → 1.1.5
```

`adopt` picks the next free address on the model's dominant line (confirming first), verifies the write, cross-checks the device's order number against the product data (a mismatch prints a loud warning), and lists the most useful com objects. What remains manual: paste and edit the snippets, then `bussard plan 1.1.5` and `bussard apply 1.1.5`. A factory-fresh device also needs [a first flash](#-flash-a-factory-fresh-device) before links take effect.

## ... change what a button does?

Edit `links.yaml`: point the button's com object at the new GA (and define the GA in `groups.yaml` if it is new). Then validate, preview, and write:

```console
$ bussard validate
0 errors, 2 warnings
$ bussard plan 1.1.5
plan for 1.1.5 — mask 07B0 (System B)

2 addition(s), 1 removal(s), 3 unchanged:
  + add:    object    0 → 0/0/1
  + add:    object    4 → 0/1/1
  - remove: object    7 → 2/4/9

run `bussard apply 1.1.5` to write these changes (with confirmation).
$ bussard apply 1.1.5
...
apply 3 change(s) to 1.1.5? [y/N] y
backup written to knx/captures/backups/1.1.5-1758042000.json

apply verified: address table Loaded (5 entries), association table Loaded (5 entries)
```

`plan` is read-only on the bus. `apply` backs up the pre-state tables before any write; the tables are rewritten wholesale, so re-running `apply` after a failure is safe and idempotent. If the model already matches the device, `plan` prints `nothing to do` and `apply` exits 0.

## ... undo a change?

bussard keeps its own history, so undo does not need git. Every command that writes the model or the bus saves a full copy of the model files first.

```console
$ bussard status
2 pending change(s) since snapshot 20260922T101112Z-001 (2026-09-22T10:11:12Z):

Rocker 1 on Hallway push button now switches Porch light (0/0/4).
Porch light (0/0/4) changes type from 1.001 to 1.002.

Nothing has reached any device yet. Run `bussard plan <ia>` to check a device,
`bussard apply <ia>` to write it, or `bussard undo` to put the files back.
$ bussard history
  1  20260922T100000Z-001  import home.knxproj (before writing the imported model)
     the first snapshot of the model
  2  20260922T101112Z-001  apply 1.1.5 → 192.0.2.10:3671 (before writing the device tables)
     Rocker 1 on Hallway push button now switches Porch light (0/0/4) and 1 more
$ bussard undo
Restored the model files to snapshot 20260922T100000Z-001 (2026-09-22T10:00:00Z).
The state before this undo is kept as snapshot 20260922T103000Z-001.

Rocker 1 on Hallway push button no longer switches Porch light (0/0/4).

Run `bussard plan 1.1.5` and `bussard apply 1.1.5` to push this to devices.
```

`undo` changes files only: the devices keep working exactly as before until you run `plan` and `apply`. The state before the undo is snapshotted too, so an undo can be undone. `bussard show 2` renders what one snapshot changed; `bussard status --raw` prints the file-level diff for anyone who does want to read YAML.

An edit you make in an editor is not lost either: the next command records it as an `external edit` snapshot before doing anything else.

## ... see what my assistant changed?

Model edits made over MCP go through the same history, and every edit tool returns the change as sentences so the assistant can read them back to you before you agree. Afterwards:

```console
$ bussard status
1 pending change(s) since snapshot 20260922T104500Z-001 (2026-09-22T10:45:00Z):

Living room blind actuator, channel B, now listens to Central down (3/0/1).
$ bussard history --json | jq '.[-1]'
{
  "index": 7,
  "id": "20260922T104500Z-001",
  "command": "mcp knx_add_link",
  "args": ["1.1.4", "12", "3/0/1", "listen"],
  "summary": "Living room blind actuator, channel B, now listens to Central down (3/0/1)"
}
```

Nothing an assistant does over MCP reaches the bus: the model-edit tools write YAML files, and `plan`/`apply`/`flash` are CLI-only. A change touching a `protected: true` group address ends with "This group address is protected." and is sorted first, and the MCP tools refuse such a change outright. If you dislike what you see, `bussard undo`. To run the server without the edit tools at all, start it with `bussard mcp --no-model-edits`.

## ... send my configuration to an integrator?

Export the model as one file and send that:

```console
$ bussard export house.bussard
exported 4 device(s), 11 group address(es), 6 history snapshot(s) → house.bussard
model sha256 3f1c…
never included: models/ (cached vendor product models), vendor/ (vendor product data), captures/ (bus recordings), keyrings (*.knxkeys and tool keys), *.knxproj (ETS projects), *.knxprod (vendor product files), .env (passwords and local settings)
```

The `.bussard` file is a zip holding `bussard.yaml`, `groups.yaml`, `links.yaml`, `devices/`, the history snapshots and a manifest with counts and a SHA-256 of the model. Passwords, keyrings, vendor data and ETS files stay on your machine. Leave out the history with `--no-history`. Without a file name, `export` writes `<dir>-<date>.bussard` next to the model directory.

The integrator runs `bussard import house.bussard --dir knx` into an empty directory and gets your model back byte for byte, history included. Keep a copy as your backup too: export at the end of the first working weekend and after every change you want to keep. `apply` reminds you on stderr when the last export is older than the model you just pushed.

Over MCP, the assistant does the same with `knx_export_bundle`.

## ... see what an integrator's new export would change?

Before importing, ask for the difference:

```console
$ bussard diff knx integrator-2026-10-01.bussard
2 change(s) from knx to integrator-2026-10-01.bussard:
  Group address 1/0/1 is now called "Kitchen ceiling" (was "Light Kitchen").
  Night setback on Living room thermostat (1.0.4): 2 to 3.
```

Each side can be a model directory, a `.bussard` bundle or a `.knxproj` (`--password`, `--password-b`, or `BUSSARD_PROJECT_PASSWORD`). A renamed group address is one rename. `--json` gives the structured changes, `--raw` a file-level YAML diff. With an assistant, `knx_diff_project` returns the same sentences, and the assistant reads them to you before you import.

Then import:

```console
$ bussard import integrator-2026-10-01.bussard --dir knx
```

Generated data (com-object tables, links, parameters) follows the bundle. Names, rooms and descriptions you edited stay yours; each disagreement is printed as a sentence and the command exits 3. Re-run with `--theirs` to take the integrator's values, `--mine` to keep yours, or `--interactive` to choose each one. The import snapshots first, so `bussard undo` reverts it.

## ... clean stale links off a device?

Same pair. A link left on the device by an earlier ETS download but absent from `links.yaml` shows up in the plan as a removal:

```console
$ bussard plan 1.1.5
  - remove: object    7 → 2/4/9
```

So `plan` shows what `apply` will prune, not just what it adds; `apply` removes it. To first see what a device actually carries, `bussard reconstruct 1.1.4` reads its tables back and diffs them against the model (the diff compares GA sets per object; the send/listen direction lives in a table many devices do not expose).

## ... back up every device?

Before the first write to an installation, take a snapshot of all of it:

```console
$ bussard backup
backing up 12 device(s) via 192.0.2.10:3671 into knx/captures/backups/20260922T101500Z
...
  1.1.4      07B0  backed up
      parameters: 1840 octet(s)
  1.1.12     0010  skipped
      unsupported mask 0010 (System 1): ...

10 backed up, 1 skipped, 1 unreachable, 0 failed
```

`backup` only reads, so it is safe on a live bus. Each device gets one JSON file with its tables (and, on System B, its parameter segment); `manifest.json` lists every device and what happened to it. Use `--line 1.1` or a list of addresses to back up part of the installation, and `--out <dir>` to write elsewhere.

To put one device's tables back:

```console
$ bussard restore knx/captures/backups/20260922T101500Z 1.1.4
```

`restore` shows the plan and asks before writing, exactly like `apply`. If the device has not changed since the snapshot, the plan is empty and nothing is written.

## ... replace a dead device?

Mount a new device of the same product, connect it to the bus, and run:

```console
$ bussard replace 1.1.4 --product MDT_JAL_0410_02.knxprod
Press the programming button on the replacement device for 1.1.4.
device in programming mode: 15.15.255
  mask: 07B0 (System B)
  order number: MDT-JAL-0410.02
replace 1.1.4: address 15.15.255 → 1.1.4, flash the application and apply the model's tables, via 192.0.2.10:3671? [y/N] y
...
replaced 1.1.4 via 192.0.2.10:3671
```

`replace` refuses when the old device still answers or when the new one reports a different order number or mask than `devices/1.1.4-*.yaml`; `--force` overrides both, for when the model is out of date. It assigns the address, flashes the application with the model's parameters, applies the model's links, and writes `replaced: <date>` into the device file. Pass `--no-flash` for a spare that already carries the right application.

## ... generate the Home Assistant config?

```console
$ bussard ha-config --out ha-knx.yaml
```

The output is a complete `knx:` document; `!include` it or paste it into your Home Assistant configuration. Read the footer: it counts the derived entities and lists every unmapped GA by DPT, so nothing is silently dropped. Tune the result with an `ha.yaml` next to the model (rename entities, promote a switch to a light, exclude GAs, merge extra state addresses). Derivation rules and `ha.yaml` fields are in [ha-config.md](ha-config.md).

## ... generate the handover documentation?

```console
$ bussard doc --out docs/installation
$ bussard doc --format html --out handover/
```

`doc` writes the folder the KNX guidelines ask for: a device list, a group-address list with senders and listeners, one sheet per room in plain language, the connection details (never credentials), and a change log from git. Give devices a `location:` (floor and room) to get room sheets. The output is deterministic, so commit it and regenerate after every change; the diff then shows what moved. `--json` prints the same content as one structured document. Details in the [reference](reference.md#bussard-doc).

## ... bootstrap without any ETS project?

`init` discovers the gateway and writes an empty model; if discovery finds nothing (multicast does not cross subnets), pass `--gateway <ip>` directly:

```console
$ bussard init
Searching for KNXnet/IP gateways on the local network...
Found gateway: KNX IP Interface (192.0.2.10:3671, IA 1.1.250)

Created a fresh KNX model in knx.
```

Then synthesize a model from what the devices already carry:

```console
$ bussard reconstruct --line 1.1 --out fresh
sweeping line 1.1.0–255 sequentially — estimated up to 13m38s on TP1
sweep complete: 3 device(s) found
reconstructed line 1.1 into fresh

3 device(s) responded: 2 read (System B), 1 recorded as stubs
synthesized 9 group address(es) and 5 link(s)
```

The synthesized model is a scaffold, not ground truth, and every file carries a banner saying so: names and DPTs are placeholders (`validate` warns W011, honestly), directions are recorded as `listen:`, and non-System-B devices become stubs. Watch the bus with `monitor --dir fresh` and annotate `groups.yaml` as you identify traffic; decoding fills in as the model grows.

## ... commission a whole line?

Preview the line first. `plan --line` reads every device the model has on the line and prints one table:

```console
$ bussard plan --line 1.1

plan line 1.1 via 192.0.2.10:3671 — 3 device(s)

address   name              mask   status
1.1.4     Jalousie Wohnen   07B0   changes: 2
1.1.5     Alter Dimmer      0012   skipped: unsupported mask 0012 (System 1)
1.1.6     Schaltaktor       07B0   unchanged
```

Then write it. `apply --line` asks once for the whole line, backs up and verifies each device, and keeps going when one fails:

```console
$ bussard apply --line 1.1
apply the model's links to 3 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
```

If the tunnel drops or you stop the run, re-run with `--resume`. It reads `knx/captures/apply-line-1.1.json` and skips the devices already done, touching only the rest. Add `--json` to either command for a summary an assistant can report.

## ... label devices on the bench?

Put the model's devices for a line on the bench, factory-fresh, and run:

```console
$ bussard commission --line 1.1 --labels labels.csv
commission 2 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
  press the programming button on Blind actuator (JAL-0810.03)
  assigned 15.15.255 → 1.1.7
1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room
```

For each device that does not answer yet, `commission` asks for its programming button, checks the pressed device's order number against the model, and only then writes the address. Pressing the wrong module stops that device with both order numbers named; the run carries on with the next one. Each commissioned device prints a label line and appends `address;name;order_number;floor;room` to `labels.csv` for the label printer. Add `--flash` and `--apply` to program each device in the same pass.

## ... flash a factory-fresh device?

A factory-fresh device needs its application program downloaded once before links take effect. `flash` does that first download straight from the `.knxprod`:

```console
$ bussard flash 1.1.5 --product MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
Flash plan for 1.1.5
  application : M-0083_A-000D-23-5BFD MDT Switch Actuator AKK
  mask        : app 07B0 vs device 07B0 — compatible
  writes      : 512 byte(s) across 8 step(s), est. 2.4s on TP1
flash M-0083_A-000D-23-5BFD (2 memory write(s)) to 1.1.5? [y/N] y
...
flash verified: application program M-0083_A-000D-23-5BFD is Loaded on 1.1.5
```

The safety story is the pre-flight plan: `flash` refuses before any write when the device is not System B, the application's mask does not match, or the load procedure contains an operation it cannot execute (see [the supported-operations list](reference.md#bussard-flash---product-file-address)). Unlike `apply` there is no backup, because a fresh device has no prior application to save; recovery from a failed flash is re-running it, or falling back to ETS. For the same reason the pre-flight also checks the device really is fresh: a device already carrying a different application is refused unless you pass `--force`, while re-flashing the same application (the recovery path above) needs no flag. [SAFETY.md](SAFETY.md) has the full table. After writing, `flash` verifies the application reads back as `Loaded` and spot-checks the written segments byte-for-byte.

One special case: a device with a BCU access key set needs `--bcu-key <HEX>`; without it bussard presents the free-access key, which is correct for an unkeyed device. The download runs over a single management connection for its whole duration, exactly as ETS does; if that connection genuinely dies mid-flash, re-run `flash` — the download is idempotent (it re-unloads and rewrites the application wholesale).

## ... change a device parameter?

Device parameters (channel modes, run times, alarm behaviour) live in the device file's `parameters:` block, imported from the ETS project. Only values that differ from the vendor default are stored, keyed `<name-slug>@<ref-id>`:

```yaml
parameters:
  "windalarm-1@MD-1_M-3_MI-1_P-3_R-45": "1"
```

Edit the value, then validate: with the device's product model generated (`import-product`), `validate` checks that the key exists and the value is in range (E016/E017). The new value reaches the device via `flash`, which recomputes the full parameter memory image from the vendor defaults plus your overrides. Objects whose resident image is unchanged (typically the code segment) are skipped, so a parameter change streams only what differs; pass `--full` to re-stream everything. Its pre-flight names each change in the vendor's words, with the value the device holds now:

```console
$ bussard flash 1.1.12 --product heating.knxprod --gateway 127.0.0.1:3671
Flash plan for 1.1.12
  ...
  parameters  : 1 change(s):
      Night setback: 18 °C to 17 °C
  writes      : 312 byte(s) across 9 step(s), ~24 memory frame(s), est. 1.0s on TP1
  procedure   : 9 step(s); re-run with -v for the memory-level plan
```

On a factory-fresh device there is nothing to read back, so the line reads `Night setback: unknown current value, will be 17 °C`. `--json` puts the same lines in a `parameters` array. One caveat: a `.knxproj` re-import replaces the whole `parameters:` block with ETS truth, so make the change in ETS too if you still re-import.

For a device that already runs the application, `--parameters-only` does what ETS's partial download does: it rewrites only the parameter memory, octet by octet where it differs, and restarts. No unload, no tables, no factory reset:

```console
$ bussard flash 1.1.12 --product heating.knxprod --parameters-only --gateway 127.0.0.1:3671
Parameter-only download for 1.1.12
  application : M-0083_A-0042-10-1234 Heating actuator
  parameters  : 1 change(s):
      Night setback: 18 °C to 17 °C
  memory      :
      M-0083_A-0042-10-1234_RS-04-00000 at 0x004400: 1 of 312 octet(s) change
  procedure   : open for loading (obj 4); write parameters image (312 bytes) at 0x00004400; complete load (obj 4); restart device (no unload, no table write)
download the parameters (1 octet(s)) to 1.1.12 via 127.0.0.1:3671? [y/N] y
parameter backup written to knx/captures/backups/parameters/1.1.12-1790182579.json
parameters verified: 1 changed octet(s) read back from 1.1.12; the application is Loaded
```

It refuses when the device runs another application or is not `Loaded`, and when a changed parameter shows or hides a com-object: that changes the group-object table, which needs the full `flash`. [SAFETY.md](SAFETY.md#what-each-write-command-does-and-its-rails) has the table.

To see what a device holds before you change anything, give `plan` or `reconstruct` the product file. Both read the parameter memory back (read-only), decode it, and list the values that differ from the vendor default and from the model:

```console
$ bussard reconstruct 1.1.12 --product heating.knxprod
...
parameters (application M-0083_A-0042-10-1234):
  1 parameter(s) differ from the vendor default:
      Night setback: 17 °C (default 18 °C)
  the device matches the model's parameters: block
```

Without `--product` they use the archive `import-product` cached in `<dir>/vendor/` for the model's order number, when there is one.

## ... name the group addresses of a house without a project file?

Let the assistant run the loop with you. Start the MCP server (`--passive` is enough, nothing here transmits) and say "help me name the group addresses". The assistant asks you to press a button, waits for the telegram with `knx_wait_for_telegram`, then calls `knx_infer_group`, which returns DPT candidates, the sending device, its channel and com object, and a proposed name such as "Kitchen ceiling light, switch". It tells you what it thinks the button is; you confirm or correct it in chat, and only then does it write the answer into the model with `knx_set_group` and `knx_add_link`. Press the same button again when the candidates are uncertain: every extra telegram narrows them.

At a terminal, `bussard learn` runs the same loop:

```console
$ bussard learn --untyped --gateway 192.0.2.10

[1/12] 1/0/1: trigger the object you want to name (waiting up to 30s)
  1/0/1  sender 1.1.30 Schaltaktor (Kitchen)
  com object 3 Kanal A - Schalten, channel Ceiling light, declares 1.001
  payload 01 (1 byte(s))
    1. 1.001 [high] the sending com object declares DPT 1.001 in the model
  proposed name: Kitchen ceiling light, schalten
  accept as "Kitchen ceiling light, schalten" / 1.001? [a]ccept, [e]dit name, [d]pt, [s]kip, [q]uit:
```

`--unnamed` picks placeholder names instead of missing DPTs, `--ga` names specific addresses, and a bare `bussard learn` takes whatever appears on the bus. Accepted answers land in `groups.yaml` and, when the com object is clear, `links.yaml`; review the diff and run `validate`, which stops reporting W011 for every GA you typed.

## ... write an acceptance test?

Put a `tests.yaml` next to `groups.yaml`. Each test is a stimulus and the telegram that proves the installation reacted:

```yaml
tests:
  - name: Kitchen ceiling light switches and reports
    write: { ga: "1/0/10", value: "on" }
    expect: { ga: "1/0/12", value: "on", within: 2s }
  - name: Wind alarm raises the blinds
    manual: "Press the test button on the weather station"
    expect: { ga: "3/1/0", value: "up", within: 5s }
```

The assistant can draft the file from the model (switch objects with a status GA are the obvious first tests) and run it over MCP with `knx_run_tests` when the server has `--allow-writes`. At a terminal:

```console
$ bussard test --gateway 192.0.2.10
PASS Kitchen ceiling light switches and reports
     1/0/12 arrived = on within 2s
FAIL Wind alarm raises the blinds
     expected 3/1/0 = up within 5s after the manual step "Press the test button on the weather station", but it did not arrive

2 test(s): 1 passed, 1 failed, 0 skipped, 0 refused
```

The report has no timestamps, so rerunning it at the three-month visit gives a diffable protocol; `--json` feeds other tooling. The run exits non-zero on any failure. A test that writes a protected GA needs `allow_protected: true` in the file and `--force`, and the MCP tool never runs it.

## ... let Claude debug the bus?

Register the MCP server once:

```console
$ claude mcp add knx -- bussard mcp --dir knx
```

Then ask in plain language: "What devices are on my bus?", "Watch for telegrams while I press the kitchen switch", "Read the wind speed". The server exposes the model, live telegrams, a "press the button now" wait tool, and rate-limited bus reads ([the full tool list](reference.md#the-mcp-server)). Add `--passive` for a server that never transmits, or `--allow-writes` to let Claude write group values. `--allow-writes` goes through the same real-gateway gate as `bussard write`: against a non-loopback gateway the server refuses to start without `--allow-remote-gateway`. Protected GAs are refused over MCP with no override either way, and a `dpt` that contradicts the model is refused too.

The payoff is closing the loop between an intent and a reviewed change. "I added a presence detector in the hall, it should switch the hall light": Claude finds the detector's GA from recent telegrams, reads the light state, checks the model, and proposes the `links.yaml` edit. You review the diff, then run `plan` and `apply` yourself.

## ... plan the group addresses for a new house?

Write the room book as a plan file and let bussard do the numbering:

```yaml
# plan.yaml
rooms:
  - floor: Ground floor
    room: Kitchen
    functions: [light, light-dim, blind, heating]
  - floor: Ground floor
    room: Living room
    functions: [light-dim, blind, heating, socket]
  - floor: First floor
    room: Bedroom
    functions: [light, blind, heating]
```

```console
$ bussard scaffold plan.yaml --dir knx
Scaffolded 62 group address(es) into knx/groups.yaml using the floor-trade-block scheme.
  1/1/0     1.001    Ground floor Kitchen Light Switch
  1/1/3     1.001    Ground floor Kitchen Light Switch status
  1/1/5     1.001    Ground floor Kitchen Dimmer Switch
  ...
Wrote a matching lint: block to knx/bussard.yaml - `bussard validate` now checks the convention.
Validation: 0 error(s), 0 warning(s).
```

Each function reserves a fixed block (five addresses for a light, ten for a blind or heating zone) and fills only the roles it needs, so the unused slots are there when the plain light later becomes a dimmer. Pick the other scheme with `--scheme function-floor` (trade on the main group, floor on the middle). Add rooms to `plan.yaml` and re-run: existing addresses and names are kept verbatim, only the new rooms are numbered.

The written `lint:` block makes `bussard validate` check the convention from then on: a GA outside its block, a switch with no feedback address, a DPT that contradicts its role ([codes L005-L008](reference.md#validation-diagnostics)).

An assistant driving `bussard mcp` can do the same over the `knx_scaffold_groups` tool, drafting the room list from a conversation. Confirm the floors, rooms and functions before it writes.

## ... get my names into ETS?

Import is otherwise one-way. `export-groups` writes the plan in the two formats ETS's *Group Addresses -> Import* accepts:

```console
$ bussard export-groups --format ets-csv --out groups.csv
Wrote 62 group address(es) to groups.csv (ETS CSV).
Import it in ETS: Group Addresses -> Import, then pick this file.
```

In ETS, open the project, select *Group Addresses* in the project tree, and use *Import* on the toolbar. The CSV is the three-level form ETS itself exports (UTF-8 with a BOM, semicolon separated); `--format ets-xml` writes the `GroupAddress-Export` XML instead, which keeps the main and middle range names as a tree.

Names, descriptions and DPTs cross over as they are. ETS has no equivalent of bussard's `protected:` flag, so a guarded address carries a leading `[protected]` marker in its description and stays recognisable on the other side.

## ... capture history and query it?

```console
$ bussard capture --to knx/captures/bus.db --filter 3/
```

Capture stores raw cEMI bytes plus a decoded snapshot in SQLite, so telegrams can be re-decoded after model fixes. Query it directly ([schema](reference.md#the-capture-database)):

```console
$ sqlite3 knx/captures/bus.db \
    "SELECT ts_utc, source, destination, apci FROM telegrams
     WHERE destination = '3/2/0' ORDER BY ts_utc DESC LIMIT 10"
```

Or hand it to the MCP server, where it extends `knx_recent_telegrams` beyond the in-memory window:

```console
$ claude mcp add knx -- bussard mcp --dir knx --capture-db knx/captures/bus.db
```

## What goes in git?

Git is optional: `bussard history` and `bussard undo` work without it. If you do use git, `bussard.yaml`, `groups.yaml`, `links.yaml`, and `devices/` are the source of truth and belong in the repo. Keep out: `.bussard/` (bussard's own history, local to the machine; `init` git-ignores it), `vendor/` and `models/` (derived from copyrighted `.knxprod` files; `import-product` plants a `.gitignore`), `captures/` (`init` git-ignores it), and `.env` (secrets like `BUSSARD_PROJECT_PASSWORD`).

### ETS with git

If ETS stays the tool of record, keep git as the review log: after every ETS session, export the `.knxproj`, run `bussard import project.knxproj --dir knx`, and commit. Before committing, `bussard diff <last-export>.knxproj project.knxproj` explains the session in sentences; that is the review. The commit then holds the YAML diff for anyone who reads it.
