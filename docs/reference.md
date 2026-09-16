# Reference

The complete surface of `bussard`: every command and flag, the environment variables, the model directory and its YAML fields, the validation diagnostics, the JSON contracts, and the MCP tools. Verified against the code; `bussard <command> --help` is always authoritative for the build you run.

## Conventions

- Addresses: group addresses (GAs) are 3-level strings like `3/2/0`; individual addresses (IAs) are `area.line.device` like `1.1.4`; DPTs are `"1.001"`.
- `--dir <DIR>` (default `knx`): the model directory. Every command that touches the model takes it.
- `--gateway <HOST>`: override the gateway `host[:port]` for tunneling (port defaults to 3671).
- `--routing`: force KNXnet/IP routing (multicast) instead of tunneling.
- Filters (`monitor --filter`, `capture --filter`): a comma-separated list of GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`), or IAs (`1.1.30`).
- Confirmation: commands that write to devices confirm on a terminal (`y/N`). Without a TTY they refuse unless `--yes` is passed (`--yes-download` for `import-product`).

### Exit codes

`0` on success, non-zero on any error. Meaningful cases:

- `validate` exits non-zero when there are errors (warnings and infos alone exit 0).
- `read` exits non-zero when no response arrives within the timeout, so scripts can detect a dead group object.
- `plan` and `apply` exit 0 when there is nothing to do.
- Refusals (protected GA without `--force`, non-TTY without `--yes`, unsupported device mask, unsupported load procedure) exit non-zero before anything is written.

## Commands

### `bussard init`

Create a fresh model directory: discover the gateway, write the skeleton.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The directory to create the model in. |
| `--gateway <HOST>` | discover | Use this gateway `host[:port]` instead of discovering one. |
| `--routing` | off | Configure KNXnet/IP routing (multicast) instead of tunneling. |

Gateway discovery is multicast and does not cross subnets. If it finds nothing, `init` still writes a valid skeleton with a placeholder gateway.

### `bussard import [PROJECT]`

Import an existing `.knxproj` (or xknxproject JSON dump) into the model. Re-import is idempotent: hand edits to names, DPTs, descriptions and `protected:` flags survive where the address is unchanged; device files whose address left the project are pruned.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[PROJECT]` | | The `.knxproj` file to import (omit when using `--from-json`). |
| `--from-json <FILE>` | | Import from an xknxproject JSON dump instead of a `.knxproj`. |
| `--password <PASSWORD>` | | Project password. Falls back to `BUSSARD_PROJECT_PASSWORD`, then an interactive prompt. |
| `--dir <DIR>` | `knx` | The model directory to write. |

### `bussard scan [LINE]`

Scan a line for devices: mask version, manufacturer, order number, and the delta against the model (known, unexpected, missing). Sweeps addresses sequentially, so a full line takes a while.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[LINE]` | `1.1` | The line to scan. |
| `--from <N>` | `0` | The first device number to probe (0-255). |
| `--to <N>` | `255` | The last device number to probe (0-255). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON instead of the table format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard assign [ADDRESS]`

Assign an individual address to the device in programming mode. Refuses when more than one device is in programming mode.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | next free on the line | The address to assign, e.g. `1.1.47`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard reconstruct [ADDRESS]`

Read a device's tables back over the bus and diff them against the model, or (with `--line`) sweep a whole line and synthesize a fresh model. System B (mask `07B0`) only; other masks are recorded as stubs in line mode and refused in single-device mode. The diff compares GA sets per object; send/listen direction is not recoverable from the address and association tables alone.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | | The single device to read, e.g. `1.1.4` (mutually exclusive with `--line`). |
| `--line <LINE>` | | Sweep a whole line, e.g. `1.1`, and synthesize a fresh model (requires `--out`). |
| `--from <N>` | `0` | First device number to probe in line mode (0-255). |
| `--to <N>` | `255` | Last device number to probe in line mode (0-255). |
| `--out <DIR>` | | Line mode only: the fresh model directory. Must be absent or empty; reconstruction never merges into an existing model. |
| `--dir <DIR>` | `knx` | The model directory (line mode: connection defaults only). |
| `--json` | off | Emit JSON instead of the report format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

A hidden diagnostic, `--l4-soak <N>`, connects once to ADDRESS and issues N harmless descriptor reads on that single connection, reporting the exact exchange count reached when the peer drops it. It measures a peer's per-connection exchange budget so `flash --reconnect-every` can be set below it. Read-only on the bus.

### `bussard import-product [FILE]`

Import vendor product data (`.knxprod`): cache it under `<dir>/vendor/` and generate one model file per application program under `<dir>/models/`. Three modes: a local file (positional), `--order-number` to look the file up in the pointer index and download it, or `--list` to show the index. Details in [product-data.md](product-data.md).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | | The `.knxprod` file to import (positional mode). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--order-number <ORDER>` | | Look the `.knxprod` up in the pointer index by order number and download it from the vendor (with confirmation). |
| `--yes-download` | off | Skip the download confirmation prompt. Only meaningful with `--order-number`; required on a non-TTY. |
| `--list` | | List the product-data pointer index and exit. |

Downloads are verified against the index by byte size and SHA-256; a mismatch is a hard error. Order-number matching is case- and whitespace-insensitive but keeps interior separators (`AKK-0216.03` matches `akk-0216.03`, not `AKK021603`).

### `bussard adopt`

Guide a new device from programming mode into the model: product data, address assignment with order-number cross-check, a rich device file, and ready-to-paste `groups.yaml` / `links.yaml` snippets. Interactive; needs a terminal (or `BUSSARD_ADOPT_ADDRESS` plus `--product` for scripted runs).

| Flag | Default | Meaning |
|---|---|---|
| `--product <FILE>` | cached model | The vendor `.knxprod` for the new device. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard flash --product <FILE> <ADDRESS>`

Flash an application program from vendor product data into a device (the ETS-free application download). Pre-flight plan first; refuses before any write on a non-`07B0` mask, a mask mismatch, or an unsupported load-procedure operation. The parameter memory image is computed from the vendor defaults plus the device file's `parameters:` overrides, so a flash also carries parameter changes. No backup exists for a flash; recovery is re-running `flash`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.0.10`. |
| `--product <FILE>` | required | The vendor `.knxprod` containing the application program. |
| `--application <REF>` | sole/matching application | The application program id. Mutually exclusive with `--order-number`. |
| `--order-number <ORDER>` | | Select the application by hardware order number (e.g. `AKK-0216.03`), resolved through the product's hardware catalogue. Exactly one match is required. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--verify <MODE>` | `per-chunk` | How memory writes are verified. `per-chunk` reads each 12-byte chunk back right after writing it (conservative; matches real devices). `batched` writes a whole segment first and reads it back once, roughly halving the memory round-trips, at the cost of catching a corrupt write only at the end-of-segment verify. |
| `--pace <MS>` | none | Sleep N milliseconds between memory frames. Real gateways throttle to TP1 speed themselves; simulators (KNX Virtual) ACK at loopback speed and can wedge under the burst. 25-50 is a TP1-like rate. |
| `--reconnect-every <N>` | off | Window the download: after ~N numbered exchanges, gracefully disconnect, reconnect, and resume where the procedure left off, including inside a long memory write. Robust against a peer that drops the L4 connection at a shallow depth (KNX Virtual drops as early as 7 exchanges; use 4-5 there). Probe a peer's budget with the hidden `reconstruct <ia> --l4-soak <N>`. |
| `--max-window-retries <N>` | `8` | Consecutive window retries without forward progress to allow on an unexpected mid-write drop before giving up. Any newly confirmed byte resets the count. Only meaningful with `--reconnect-every`. |
| `--bcu-key <HEX>` | free access | The device's BCU access key, in hex (`FFFFFFFF` or `0x11223344`), presented with A_Authorize on every management connect. Unset presents the free-access key (`FFFFFFFF`), correct for an unkeyed device; a keyed device needs its project key here or it denies access. |
| `--tolerate-nonconformant-load-states` | off | Accept a device that reports Loaded (instead of the conformant Loading) right after StartLoading. Needed for KNX Virtual; off by default so real-device behaviour stays strict. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

Supported load-procedure operations: `Unload`, `Load`, `LoadCompleted`, `RelSegment`, `WriteRelMem`, `WriteMem`, `WriteProp`, `CompareProp`, `LoadImageProp`, `Restart` on a single-LSM System B device. Procedures containing `LdCtrlAbsSegment`, `LdCtrlTaskSegment`, `LdCtrlTaskCtrl1`, or unrecognized ops (e.g. `LdCtrlCompareRelMem`) are refused whole, before any write. After writing, `flash` verifies the application reads back as `Loaded` and spot-checks written segments byte-for-byte.

Only `flash` takes `--bcu-key`; `plan`, `apply` and `reconstruct` always authorize with the free-access key, so a device with a BCU key set denies them.

### `bussard plan <ADDRESS>`

Read a device's live tables and show what `apply` would change. Read-only on the bus. Refuses to compute an empty table set for a device with no links in the model (that would wipe it). System B only.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to plan for, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON instead of the report format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard apply <ADDRESS>`

Apply the model's link tables to a device: plan, confirm, back up, write, verify. The pre-state tables are written to `<dir>/captures/backups/<ia>-<timestamp>.json` before any write; tables are rewritten wholesale, so re-running `apply` is idempotent. System B only.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard validate`

Validate the YAML model and report diagnostics (see [the diagnostics table](#validation-diagnostics)). Exits non-zero on errors.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--format <FORMAT>` | `text` | `text` (rustc-style diagnostics) or `json` (a JSON array). |

### `bussard monitor`

Live-monitor the bus, decoding telegrams against the model. Unknown GAs and DPTs degrade to raw hex, never a failure.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON Lines (see [the telegram JSON contract](#telegram-json-contract)) instead of the pretty text format. |
| `--filter <EXPR>` | all | Only show matching telegrams (GAs, GA prefixes, IAs). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard capture --to <DB>`

Capture telegrams to a SQLite database (see [the capture database](#the-capture-database)).

| Flag | Default | Meaning |
|---|---|---|
| `--to <DB>` | required | The database file to write (created if absent). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--filter <EXPR>` | all | Only capture matching telegrams. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard read <GA>`

Read a group value from the bus: send a GroupValueRead, print the typed response. Exits non-zero when no response arrives within 3 seconds.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to read, e.g. `3/2/0`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard write <GA> <VALUE>`

Write a group value to the bus. The value is human-typed (`on`/`off`, `up`/`down`, a number, a percentage like `75%`) and encoded against the GA's DPT from `groups.yaml`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to write, e.g. `3/0/4`. |
| `<VALUE>` | | The value to encode. |
| `--dpt <DPT>` | the GA's DPT | The DPT to encode as. |
| `--force` | off | Write even if the GA is marked `protected: true` in the model. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard ha-config`

Generate the Home Assistant KNX integration YAML from the model. Derivation rules and the `ha.yaml` override file are documented in [ha-config.md](ha-config.md).

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--out <FILE>` | stdout | Output file. |

### `bussard mcp`

Run the MCP server over stdio (see [the MCP server](#the-mcp-server)).

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory (required for the server). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--passive` | off | Never transmit on the bus; omits the `knx_read_group` tool. |
| `--allow-writes` | off | Register the `knx_write_group` tool. Mutually exclusive with `--passive`. |
| `--capture-db <PATH>` | | A `bussard capture` database to extend `knx_recent_telegrams` history beyond the in-memory ring. |

## Environment variables

| Variable | Meaning |
|---|---|
| `BUSSARD_PROJECT_PASSWORD` | Password for a protected `.knxproj` when `--password` is not given. Keep it in an untracked `.env`, never in the repo. |
| `BUSSARD_ADOPT_ADDRESS` | The target address for `adopt`, for driving the wizard from a script or test (together with `--product`). |
| `BUSSARD_ASSIGN_WAIT_MS` | Test knob: shrinks the programming-mode wait budget of `assign` and `adopt`. Unset in normal use. |
| `BUSSARD_SCAN_DISCOVERY_MS` | Test knob: shrinks the per-address probe timeout of `scan` and `reconstruct --line`. Unset in normal use. |

Test-harness variables (`BUSSARD_VIRTUAL_DEVICE*`, `BUSSARD_TEST_MULTICAST`, `BUSSARD_PRODUCT_CORPUS`) gate the integration test suites, never the CLI; they are documented in the `tests-support/` READMEs.

## The model directory

```
knx/
  bussard.yaml      # connection config
  groups.yaml       # the group-address plan
  links.yaml        # com-object → GA assignments
  devices/          # one file per device, e.g. 1.1.4-jalousieaktor-wohnen.yaml
  ha.yaml           # optional ha-config overrides (see ha-config.md)
  models/           # generated from .knxprod; git-ignored
  vendor/           # cached .knxprod originals; git-ignored
  captures/         # local captures and apply backups; git-ignored
```

`bussard.yaml`, `groups.yaml`, `links.yaml` and `devices/` are the source of truth and belong in git. `models/`, `vendor/` and `captures/` are local-only; `init` and `import-product` plant the `.gitignore` entries. All YAML is parsed strictly: unknown fields and duplicate keys are errors. Emission is deterministic and sorted, so re-imports and hand edits produce minimal diffs. Every generated file carries a banner naming what generated it and what is hand-editable.

### `bussard.yaml`

```yaml
connection:
  transport: tunnel          # tunnel | routing
  gateway: "192.168.1.74:3671"   # host:port for tunneling (optional)
  multicast: "224.0.23.12:3671"  # addr:port for routing (optional; this is the default)
```

| Field | Type | Meaning |
|---|---|---|
| `connection.transport` | `tunnel` \| `routing` | The transport used to reach the bus. |
| `connection.gateway` | string, optional | Gateway `host:port` for tunneling. |
| `connection.multicast` | string, optional | Multicast `addr:port` for routing; defaults to `224.0.23.12:3671`. |

### `groups.yaml`

```yaml
project: "Home"                 # optional metadata
imported_from: "home.knxproj"   # optional provenance
ranges:
  "3": { name: "Beschattung" }        # a main group
  "3/2": { name: "Sicherheit" }       # a middle group
groups:
  "3/0/4":
    name: "Jalousie Wohnen Süd — Auf/Ab"
    dpt: "1.008"
  "3/2/0":
    name: "Windalarm"
    dpt: "1.005"
    description: "Wetterstation → alle Raffstore-Kanäle"
    protected: true
```

| Field | Type | Meaning |
|---|---|---|
| `project` | string, optional | Project name metadata. |
| `imported_from` | string, optional | Provenance (the source `.knxproj`). |
| `ranges` | map, optional | Named main/middle ranges, keyed by `"3"` (main) or `"3/2"` (middle); each has a `name`. |
| `groups.<ga>.name` | string | Display name. Hand-editable; survives re-import. |
| `groups.<ga>.dpt` | string, optional | Datapoint type, e.g. `"1.008"`. Without it, `monitor` cannot decode the value (W011). |
| `groups.<ga>.description` | string, optional | Free text. |
| `groups.<ga>.protected` | bool, default `false` | Safety-critical GA: the CLI refuses writes without `--force`, MCP refuses outright. Serialized only when `true`. |

### `links.yaml`

```yaml
links:
  "1.1.4":
    - object: 12
      name: "A: Behang Auf/Ab"      # informational; refreshed on import
      listen: ["3/0/4"]
  "1.1.30":
    - object: 3
      name: "Windalarm 1"
      send: "3/2/0"
```

| Field | Type | Meaning |
|---|---|---|
| `links.<ia>` | list | The device's links, keyed by individual address. |
| `object` | number | The ETS com-object number, the stable handle. |
| `name` | string, optional | The informational com-object name. This file is its single home; it appears nowhere else. |
| `send` | GA, optional | The single sending GA (at most one, mirroring KNX association semantics). |
| `listen` | list of GAs | The listening GAs (any number). |

### `devices/*.yaml`

`address:` is the device identity; the filename slug is cosmetic (but must start with the address, E002). Everything above the `GENERATED` marker is hand-editable; `module_bases:` and `com_objects:` below it are regenerated on re-import.

```yaml
address: "1.1.4"
name: "Jalousieaktor Wohnen"
location: { floor: "EG", room: "Wohnzimmer" }
product:
  manufacturer: "Albrecht Jung"
  order_number: "23024 1S R"
  application_ref: "M-0004_A-20D6-25-D965"
  mask: "07B0"
channels:
  A: { name: "Raffstore Wohnen Süd 1" }
parameters:
  "windalarm-1@MD-1_M-3_MI-1_P-3_R-45": "1"
# --- GENERATED: regenerated on re-import; hand edits here are lost. ---
module_bases:
  MD-1_M-3_MI-1: 1797
com_objects:
  12: { dpt: "1.008", flags: "CW", channel: "A" }
```

| Field | Type | Meaning |
|---|---|---|
| `address` | IA | The device identity. |
| `name` | string | Display name. |
| `description` | string, optional | Free text. |
| `location.floor`, `location.room` | strings, optional | Physical location. |
| `product.manufacturer` | string, optional | Manufacturer name. |
| `product.manufacturer_ref` | string, optional | Manufacturer reference id. |
| `product.order_number` | string, optional | Catalogue order number; the join key into product-data models. |
| `product.hardware_ref` | string, optional | Hardware reference id. |
| `product.application_ref` | string, optional | Application-program id; matches a `models/*.yaml` identity. |
| `product.mask` | string, optional | Mask version, e.g. `"07B0"`; decides property- vs memory-based links. |
| `channels.<key>.name` | string | Human channel label. The block is emitted only when real labels are known. |
| `parameters.<key>` | map string → string, optional | Parameter values that differ from the vendor default, keyed `<name-slug>@<ref-id>` (the ref id disambiguates repeated module-instance parameters). Imported from the ETS project and replaced wholesale on re-import; hand-editable between imports. Validated against the product model in `models/` (E016/E017); `flash` writes them into parameter memory. |
| `module_bases.<ref>` | map string → number, generated | Per-module-instance memory base offsets from the ETS project. A module parameter's effective offset is its declared offset plus the instance base; `flash` needs this to place per-channel parameters. Do not edit. |
| `com_objects.<n>.dpt` | string, optional | Datapoint type. |
| `com_objects.<n>.size` | string, optional | Declared size like `"1 bit"`; serialized only when there is no DPT (otherwise the size follows from the DPT). |
| `com_objects.<n>.flags` | string | Compact `CRWTUI` flag string. W = accepts writes (a command input), T = transmits (a status output). |
| `com_objects.<n>.ref` | string, optional | Cross-reference id from the product data. |
| `com_objects.<n>.channel` | string, optional | Owning channel key. |

Com-object entries carry no `name` (it lives in `links.yaml`).

### Generated model files (`models/*.yaml`)

One file per application program, generated by `import-product` and never hand-edited. The field-by-field description lives in [product-data.md](product-data.md#the-model-file-format).

## Validation diagnostics

`validate` (and the `knx_validate` MCP tool) run strict parsing, then these rule passes:

| Code | Rule | Severity |
|---|---|---|
| E001 | link references a GA not defined in `groups.yaml` | error |
| E002 | device file name does not start with its `address:` | error |
| E003 | link references a com object the device doesn't have | error |
| E004 | conflicting object/DPT sizes on one GA | error |
| W005 | same size but different DPT subtypes on one GA | warning |
| W006 | more than one sending object on a GA | warning |
| E007 | impossible flags (no C flag; `send` without T) | error |
| W008 | listening object with neither W nor U | warning |
| I009 | orphaned com object (T or W, never linked) | info |
| I010 | GA defined but never linked | info |
| W011 | GA without a DPT (monitor can't decode it) | warning |
| E012 | reserved GA `0/0/0` defined in `groups.yaml` | error |
| E013 | link for a device that has no device file | error |
| E014 | the same object linked more than once on one device | error |
| I015 | GA marked `protected: true` (listed so a reviewer sees the guarded set) | info |
| E016 | parameter key malformed (no `@`) or not in the product model | error |
| E017 | parameter value invalid (unparseable, out of range, not an enum member) | error |
| I017 | parameter value equals the vendor default (redundant) | info |
| I018 | device has `parameters:` but no product model in `models/` to validate against | info |

## Telegram JSON contract

`monitor --json` emits one object per line; the MCP telegram tools mirror the same fields. Absent fields are `null`, so the schema is uniform.

| Field | Meaning |
|---|---|
| `ts_utc` | RFC3339 UTC timestamp (same name as the SQLite capture column). |
| `source` | Sender IA. |
| `source_name` | The sending device's name from the model. |
| `destination` | Destination GA. |
| `destination_name` | The GA's name from `groups.yaml`. |
| `dest_type` | Destination address type. |
| `apci` | The APCI (e.g. GroupValueWrite). |
| `payload` | Raw payload, hex. |
| `value` | The decoded, typed value. |
| `dpt` | The DPT used to decode. |
| `object_name` | The sending com-object's informational name from `links.yaml`. |
| `note` | Decode diagnostics, e.g. a size mismatch. |

## The capture database

`capture --to <DB>` writes SQLite. The `telegrams` table stores the raw cEMI bytes plus a decoded snapshot, so telegrams can be re-decoded after model fixes:

```sql
CREATE TABLE telegrams (
  id          INTEGER PRIMARY KEY,
  ts_utc      TEXT NOT NULL,     -- RFC3339 UTC
  source      TEXT NOT NULL,     -- IA
  destination TEXT NOT NULL,     -- GA
  apci        TEXT NOT NULL,
  raw_cemi    BLOB NOT NULL,
  decoded     TEXT               -- JSON snapshot at capture time
);
CREATE INDEX idx_telegrams_dest_ts ON telegrams (destination, ts_utc);
```

## The MCP server

`bussard mcp` serves the Model Context Protocol over stdio. Three tiers:

| Tier | Flag | On the bus |
|---|---|---|
| Passive | `--passive` | Never transmits. `knx_read_group` is not registered. |
| Read (default) | none | May send GroupValueReads, rate-limited. |
| Write | `--allow-writes` | Adds `knx_write_group`. |

Bus operations share one rate limiter (minimum 250 ms between operations, at most two in flight). A GA marked `protected: true` is hard-refused by `knx_write_group` with no MCP override; the LLM must ask a human, who can run `bussard write ... --force` from the CLI. Programming and download (`plan`, `apply`, `flash`) are CLI-only and not exposed over MCP.

### Tools

| Tool | Parameters | Returns |
|---|---|---|
| `knx_project_summary` | none | Project name, device/GA/link counts, floors and rooms, GA main-range names, bus connection status, validation counts. Call first. |
| `knx_model_lookup` | `query` (substring), `limit` (default 50, max 500) | Case-insensitive matches across GA names/addresses, device names/IAs, room names, com-object names, grouped by kind. |
| `knx_get_group` | `ga` | The GA's definition, every link sending to or listening on it, and the last telegram seen on it. |
| `knx_get_device` | `address` | One device's identity, product, location, channels, com-object table, and links. |
| `knx_recent_telegrams` | `limit` (default 50, max 1000), `ga` (GA or prefix), `source` (IA), `since` (RFC3339), all optional | Recent decoded telegrams, oldest first. With `--capture-db`, windows that predate the in-memory ring are topped up from the capture database. |
| `knx_wait_for_telegram` | `timeout_seconds` (max 300), `ga`, `source` (optional) | Blocks until a matching telegram arrives or the timeout elapses. A timeout is a normal result, not an error. Enables "press the button now" debugging. |
| `knx_validate` | none | Every diagnostic (code, severity, message, location) plus counts. |
| `knx_read_group` | `ga` | Transmits a GroupValueRead and returns the decoded response. Omitted in `--passive` mode. |
| `knx_write_group` | `ga`, `value` (human-typed), `dpt` (optional override) | A GroupValueWrite. Registered only with `--allow-writes`; refuses protected GAs outright. |
