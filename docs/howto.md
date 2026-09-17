# How do I ...

Recipes for everyday bussard work. Each assumes a model directory (default `knx/`; every command takes `--dir`). Flags and fields are in the [reference](reference.md); install and first steps are in the [README](../README.md).

Three KNX terms the recipes rely on:

- A group address (GA, `3/2/0`) is the bus's pub/sub topic: a telegram sent to a GA carries one value, and every device listening on it reacts. `groups.yaml` names each GA and records its datapoint type (DPT), which tells bussard how to decode the value.
- An individual address (IA, `1.1.4`, area.line.device) is a device's unique bus address, used for commissioning and diagnosis.
- A com object is one input or output slot of a device, such as "channel A: move up/down" on a blind actuator. Linking it to a GA in `links.yaml` makes the device send on or listen to that address. In the compact `CRWTUI` flag string, W means the object accepts writes (a command input) and T means it transmits (a status output).

A word on safety before the writing recipes: every bus-writing command reads the live state first, shows a plan, confirms on a terminal (`y/N`), writes, then verifies by reading back. `apply` also backs up first. `plan`, `apply`, `reconstruct` and `flash` support System B (mask `07B0`) devices for now and refuse anything else before writing. Do the first real writes against a spare device, not a live installation.

## ... watch and decode the bus?

```console
$ bussard monitor
12:03:41.221  1.1.30 Meteodata          → 3/2/0 Windalarm            = Alarm (1.005, obj "Windalarm 1")
12:03:44.809  1.1.12 Taster Flur EG     → 1/0/1 Licht Flur           = On (1.001, obj "Taste 1")
12:03:44.981  1.1.7 Schaltaktor UV      → 1/0/2 Licht Flur Status    = On (1.001)
```

Every telegram resolves to its GA name, the sending device, and a typed value. Flip a switch and watch it name itself. Narrow the stream with `--filter 3/2/0,1/0/` (GAs, GA prefixes, or sender IAs); `--json` emits one JSON object per line for tooling. GAs missing from the model show as raw hex; add them to `groups.yaml` with a `dpt:` and re-run.

## ... see the whole network in a browser?

```console
$ bussard viz
bussard viz serving on http://127.0.0.1:8080 (Ctrl-C to stop)
```

Open the address to get a bus-spine diagram of every device by floor and room, the group-address tree, and live telegrams pulsing along the spine as they happen. Select a device or GA to see its links, senders, and listeners. Per-DPT widgets send a test write (protected GAs need an explicit force); the confirmation is the echoed telegram on the live stream. With no reachable gateway the page still shows the model, just without live traffic. See [the viz server](reference.md#the-viz-server) for the endpoints.

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

## ... clean stale links off a device?

Same pair. A link left on the device by an earlier ETS download but absent from `links.yaml` shows up in the plan as a removal:

```console
$ bussard plan 1.1.5
  - remove: object    7 → 2/4/9
```

So `plan` shows what `apply` will prune, not just what it adds; `apply` removes it. To first see what a device actually carries, `bussard reconstruct 1.1.4` reads its tables back and diffs them against the model (the diff compares GA sets per object; the send/listen direction lives in a table many devices do not expose).

## ... generate the Home Assistant config?

```console
$ bussard ha-config --out ha-knx.yaml
```

The output is a complete `knx:` document; `!include` it or paste it into your Home Assistant configuration. Read the footer: it counts the derived entities and lists every unmapped GA by DPT, so nothing is silently dropped. Tune the result with an `ha.yaml` next to the model (rename entities, promote a switch to a light, exclude GAs, merge extra state addresses). Derivation rules and `ha.yaml` fields are in [ha-config.md](ha-config.md).

## ... bootstrap without any ETS project?

`init` discovers the gateway and writes an empty model; if discovery finds nothing (multicast does not cross subnets), pass `--gateway <ip>` directly:

```console
$ bussard init
Searching for KNXnet/IP gateways on the local network...
Found gateway: KNX IP Interface (192.168.1.74:3671, IA 1.1.250)

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

The safety story is the pre-flight plan: `flash` refuses before any write when the device is not System B, the application's mask does not match, or the load procedure contains an operation it cannot execute (see [the supported-operations list](reference.md#bussard-flash---product-file-address)). Unlike `apply` there is no backup, because a fresh device has no prior application to save; recovery from a failed flash is re-running it, or falling back to ETS. After writing, `flash` verifies the application reads back as `Loaded` and spot-checks the written segments byte-for-byte.

One special case: a device with a BCU access key set needs `--bcu-key <HEX>`; without it bussard presents the free-access key, which is correct for an unkeyed device. The download runs over a single management connection for its whole duration, exactly as ETS does; if that connection genuinely dies mid-flash, re-run `flash` — the download is idempotent (it re-unloads and rewrites the application wholesale).

## ... change a device parameter?

Device parameters (channel modes, run times, alarm behaviour) live in the device file's `parameters:` block, imported from the ETS project. Only values that differ from the vendor default are stored, keyed `<name-slug>@<ref-id>`:

```yaml
parameters:
  "windalarm-1@MD-1_M-3_MI-1_P-3_R-45": "1"
```

Edit the value, then validate: with the device's product model generated (`import-product`), `validate` checks that the key exists and the value is in range (E016/E017). The new value reaches the device via `flash`, which recomputes the full parameter memory image from the vendor defaults plus your overrides. One caveat: a `.knxproj` re-import replaces the whole `parameters:` block with ETS truth, so make the change in ETS too if you still re-import.

## ... let Claude debug the bus?

Register the MCP server once:

```console
$ claude mcp add knx -- bussard mcp --dir knx
```

Then ask in plain language: "What devices are on my bus?", "Watch for telegrams while I press the kitchen switch", "Read the wind speed". The server exposes the model, live telegrams, a "press the button now" wait tool, and rate-limited bus reads ([the full tool list](reference.md#the-mcp-server)). Add `--passive` for a server that never transmits, or `--allow-writes` to let Claude write group values; protected GAs are refused over MCP with no override either way.

The payoff is closing the loop between an intent and a reviewed change. "I added a presence detector in the hall, it should switch the hall light": Claude finds the detector's GA from recent telegrams, reads the light state, checks the model, and proposes the `links.yaml` edit. You review the diff, then run `plan` and `apply` yourself.

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

`bussard.yaml`, `groups.yaml`, `links.yaml`, and `devices/` are the source of truth and belong in the repo. Keep out: `vendor/` and `models/` (derived from copyrighted `.knxprod` files; `import-product` plants a `.gitignore`), `captures/` (`init` git-ignores it), and `.env` (secrets like `BUSSARD_PROJECT_PASSWORD`).
