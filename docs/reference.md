# Reference

The complete surface of `bussard`: every command and flag, the environment variables, the model directory and its YAML fields, the validation diagnostics, the JSON contracts, and the MCP tools. Verified against the code; `bussard <command> --help` is always authoritative for the build you run.

## Conventions

- Addresses: group addresses (GAs) are 3-level strings like `3/2/0`; individual addresses (IAs) are `area.line.device` like `1.1.4`; DPTs are `"1.001"`.
- `--dir <DIR>` (default `knx`): the model directory. Every command that touches the model takes it.
- `--gateway <HOST>`: override the gateway `host[:port]` for tunneling (port defaults to 3671).
- `--routing`: force KNXnet/IP routing (multicast) instead of tunneling.
- Filters (`monitor --filter`, `capture --filter`): a comma-separated list of GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`), or IAs (`1.1.30`).
- Confirmation: commands that write to devices confirm on a terminal (`y/N`), naming the resolved gateway (`host:port`). Without a TTY they refuse unless `--yes` is passed (`--yes-download` for `import-product`). This covers `write`, `flash`, `apply`, `assign` and `adopt`.
- Real-gateway safety: a write command whose resolved gateway is **not** loopback (not `127.0.0.0/8` or `::1`) refuses to run unless you opt in with `--allow-remote-gateway` or `BUSSARD_ALLOW_REAL_GATEWAY=1`. Loopback gateways (the local simulator, the test suite) are always allowed. Reads (`monitor`, `read`, `scan`, `plan`, `reconstruct`) are never gated. The two long-running servers pass the same gate once, at startup, when they are able to transmit: `mcp --allow-writes`, `viz --allow-writes`, and `viz --watch-prog`. Without those flags neither server can write, so neither is gated. [SAFETY.md](SAFETY.md) is the read-before-your-first-write guide to all of this.

### Global flags

These apply to every subcommand:

- `-v` / `--verbose` (repeatable): raise log verbosity. `-v` = `info`, `-vv` = `debug`, `-vvv` = `trace`. The default (no flag) is `warn`. An explicit `RUST_LOG` overrides this entirely, so `RUST_LOG=bussard_transport=trace` still works for targeted tracing.
- `--timing`: print the invocation's wall-clock time to stderr on exit (e.g. `took 1.23s`). Off by default.

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

A re-import always takes the generated sections (com-object tables, link wiring, parameters) from the project and always preserves hand-authored fields, reporting every difference instead of overwriting it. There is no flag for that: it is the only behaviour the merge implements.

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

Assign an individual address to the device in programming mode. Refuses when more than one device is in programming mode. Confirms on a terminal (naming the gateway); a non-TTY needs `--yes` (an explicit address is not itself consent).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | next free on the line | The address to assign, e.g. `1.1.47`. |
| `--yes` | off | Skip the confirmation prompt (required for a non-TTY assign). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |

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

### `bussard describe <ADDRESS>`

Introspect a device over the bus: discover its interface objects and, for each, enumerate every property's description (PID with a name when known, data type, element count, and read/write access levels) as a table. Read-only on the bus — it sends `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` (object discovery) and `A_PropertyDescription_Read`, never a write. Unlike `reconstruct` it does not resolve group tables; it describes the device's raw property set, which is useful for commissioning and diagnostics on an unknown device.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to introspect, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory (connection defaults). |
| `--json` | off | Emit JSON instead of the table format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

When the model marks the device secure-capable, the output carries a `KNX Secure:` line (and a `secure` object in `--json`, with `secure_capable` and the Data Secure state). That is inspection only: `bussard` cannot program a Secure device — see [SAFETY.md](SAFETY.md#known-limitations).

### `bussard keyring <FILE>`

Inspect an ETS KNX Secure keyring export (`.knxkeys`): print what it carries — the device individual addresses, the tunnel/management interface addresses, whether a backbone key is present, and how many group keys there are. **No key material is ever printed**, in text or JSON.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<FILE>` | | The `.knxkeys` file to inspect. |
| `--json` | off | Emit JSON instead of the text summary. |

The keyring password comes from `BUSSARD_KEYRING_PASSWORD` and is deliberately **not** a flag, so it never lands in shell history or a process listing. Reading a keyring does not enable Secure writes; see [SAFETY.md](SAFETY.md#known-limitations).

### `bussard import-product [FILE]`

Import vendor product data (`.knxprod`): cache it under `<dir>/vendor/` and generate one model file per application program under `<dir>/models/`. Three modes: a local file (positional), `--order-number` to look the file up in the pointer index and download it, or `--list` to show the index. Details in [product-data.md](product-data.md).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | | The `.knxprod` file to import (positional mode). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--order-number <ORDER>` | | Look the `.knxprod` up in the pointer index by order number and download it from the vendor (with confirmation). |
| `--yes-download` | off | Skip the download confirmation prompt. Only meaningful with `--order-number`; required on a non-TTY. |
| `--inner <NAME>` | | Import one named inner archive from a multi-product `.knxprod` instead of every one it contains. |
| `--list` | | List the product-data pointer index and exit. |

Downloads are verified against the index by byte size and SHA-256; a mismatch is a hard error. Order-number matching is case- and whitespace-insensitive but keeps interior separators (`AKK-0216.03` matches `akk-0216.03`, not `AKK021603`).

### `bussard adopt`

Guide a new device from programming mode into the model: product data, address assignment with order-number cross-check, a rich device file, and ready-to-paste `groups.yaml` / `links.yaml` snippets. Interactive; needs a terminal (or `BUSSARD_ADOPT_ADDRESS` plus `--product` for scripted runs).

| Flag | Default | Meaning |
|---|---|---|
| `--product <FILE>` | cached model | The vendor `.knxprod` for the new device. |
| `--yes` | off | Skip the confirmation prompt (required for a non-TTY, scripted adopt). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |

### `bussard flash --product <FILE> <ADDRESS>`

Flash an application program from vendor product data into a device (the ETS-free application download). Supports System B (`07B0` and the `57B0`/`27B0` variants) and System 7 (`0705`/`0701`/`0700`). Pre-flight plan first; refuses before any write on an unsupported mask family, a mask mismatch, or an unsupported load-procedure operation. The parameter memory image is computed from the vendor defaults plus the device file's `parameters:` overrides, so a flash also carries parameter changes. No backup exists for a flash; recovery is re-running `flash`.

The same pre-flight also checks the device is factory-fresh (issue #79), read-only, before anything is written: it reads each object's load state and, on System B, the resident application id (`PID_PROGRAM_VERSION`). A device carrying a **different** application, one it cannot identify, or a load state it cannot read at all is **refused**; `--force` overrides. Re-flashing the **same** application is allowed without `--force` (it is the documented recovery path after an interrupted flash) and prints a notice, because it still resets the parameters to the vendor defaults plus the model's overrides and rewrites the tables from the model's links. See [the flash section in SAFETY.md](SAFETY.md#what-each-write-command-does-and-its-rails) for the full table.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.0.10`. |
| `--product <FILE>` | required | The vendor `.knxprod` containing the application program. |
| `--application <REF>` | sole/matching application | The application program id. Mutually exclusive with `--order-number`. |
| `--order-number <ORDER>` | | Select the application by hardware order number (e.g. `AKK-0216.03`), resolved through the product's hardware catalogue. Exactly one match is required. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--force` | off | Flash a device that is **not** factory-fresh: it already carries a different (or unidentifiable) application, or its load state could not be read. Destructive: the resident application, its parameters and its links are overwritten with no backup. Not needed to re-flash the same application. |
| `--bcu-key <HEX>` | free access | The device's BCU access key, in hex (`FFFFFFFF` or `0x11223344`), presented with A_Authorize on every management connect. Unset presents the free-access key (`FFFFFFFF`), correct for an unkeyed device; a keyed device needs its project key here or it denies access. |
| `--allow-remote-gateway` | off | Permit a flash to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

The confirmation names the resolved gateway (`flash <app> to <target> via <host:port>?`).

Supported load-procedure operations: `Unload`, `Load`, `LoadCompleted`, `RelSegment`, `WriteRelMem`, `WriteMem`, `WriteProp`, `CompareProp`, `LoadImageProp`, `Restart` on a single-LSM System B device. Procedures containing `LdCtrlAbsSegment`, `LdCtrlTaskSegment`, `LdCtrlTaskCtrl1`, or unrecognized ops (e.g. `LdCtrlCompareRelMem`) are refused whole, before any write. After writing, `flash` verifies the application reads back as `Loaded` and spot-checks written segments byte-for-byte.

Only `flash` takes `--bcu-key`; `plan`, `apply` and `reconstruct` always authorize with the free-access key, so a device with a BCU key set denies them.

### `bussard plan <ADDRESS>`

Read a device's live tables and show what `apply` would change. Read-only on the bus. Refuses to compute an empty table set for a device with no links in the model (that would wipe it). System B (`x7B0`) and System 7 (`0705` / `0701`); on System 7 the tables are read straight out of the `0x4000` / `0x4201` memory regions, bounded by the region size.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to plan for, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON instead of the report format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard apply <ADDRESS>`

Apply the model's link tables to a device: plan, confirm, back up, write, verify. The pre-state tables are written to `<dir>/captures/backups/<ia>-<timestamp>.json` before any write; tables are rewritten wholesale, so re-running `apply` is idempotent. System B (`x7B0`) and System 7 (`0705` / `0701`). On System 7 only the two table load-state machines are driven (Unload, StartLoading, allocate, 12-octet writes with read-back verify, TaskSegment, LoadCompleted) — parameters are untouched and the device is not restarted, so a link change costs no downtime.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard validate`

Validate the YAML model and report diagnostics (see [the diagnostics table](#validation-diagnostics)). Exits non-zero on errors.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--format <FORMAT>` | `text` | `text` (rustc-style diagnostics) or `json` (a JSON array). |

### `bussard scaffold <PLAN>`

Draft a group-address plan from a room and function list. Reserves the conventional block per function (five addresses for a light, ten for a blind or a heating zone), names every address `<Floor> <Room> <Function> <Role>`, fills the DPTs, and leaves the unused slots in each block free for growth. Re-running on an extended plan adds addresses and never renumbers or renames the ones already there.

The plan file is device-free:

```yaml
rooms:
  - floor: Ground floor
    room: Kitchen
    functions: [light, light-dim, blind, heating]
```

Functions: `light` (switch + feedback), `light-dim` (switch, dim, value, both feedbacks), `blind`, `heating`, `socket`.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--scheme <SCHEME>` | `lint.groups.scheme`, else `floor-trade-block` | `floor-trade-block` (main = floor, middle = trade) or `function-floor` (main = trade, middle = floor). |
| `--out <FILE>` | `<dir>/groups.yaml` | Write (and extend) this file instead. |
| `--json` | off | Emit JSON instead of the table. |
| `--no-lint-config` | off | Do not append a matching `lint:` block to `bussard.yaml`. |

Addressing under the two schemes:

| Scheme | main | middle | sub |
|---|---|---|---|
| `floor-trade-block` | floor | trade | block start + role offset |
| `function-floor` | trade | floor | block start + role offset |

Floors and trades count from 1 (index 0 stays free for central functions, which also keeps the reserved `0/0/0` out of reach). Trades are `light` 1, `blind` 2, `heating` 3, `socket` 4. The middle level is three bits, so `function-floor` supports at most seven floors. Role offsets inside a block are fixed: a light block is switch (0), dim (1), value (2), switch status (3), value status (4); a blind block is move, step, position, slat, position status, slat status, moving status (0-6); a heating block is setpoint, operating mode, actual temperature, control value, setpoint status, operating mode status (0-5).

### `bussard export-groups`

Write the group-address plan in a format ETS's *Group Addresses -> Import* accepts. Names, descriptions and DPTs cross over; the `protected:` flag, which ETS has no field for, is carried into the description as a leading `[protected]` marker.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--format <FORMAT>` | required | `ets-csv` or `ets-xml`. |
| `--out <FILE>` | required | The file to write. |

`ets-csv` is the three-level CSV ETS itself exports: UTF-8 with a BOM, semicolon separated, CRLF line endings, every field quoted, with the columns `Main`, `Middle`, `Sub`, `Address`, `Central`, `Unfiltered`, `Description`, `DatapointType`, `Security`. Main groups, middle groups and addresses each get their own row, and the DPT is in ETS notation (`DPST-1-1`, or `DPT-1` when the model has no sub number).

`ets-xml` is the `GroupAddress-Export` document in the namespace `http://knx.org/xml/ga-export/01`: nested `GroupRange` elements carrying `Name`, `RangeStart` and `RangeEnd`, with `GroupAddress` leaves carrying `Name`, `Address`, `Description`, `DPTs` and `Security`.

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

Write a group value to the bus. The value is human-typed (`on`/`off`, `up`/`down`, a number, a percentage like `75%`) and encoded against the GA's DPT from `groups.yaml`. Confirms on a terminal, naming the GA, value and resolved gateway; a non-TTY needs `--yes`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to write, e.g. `3/0/4`. |
| `<VALUE>` | | The value to encode. |
| `--dpt <DPT>` | the GA's DPT | The DPT to encode as. |
| `--force` | off | Write even if the GA is marked `protected: true` in the model. |
| `--yes` | off | Skip the confirmation prompt (required for a non-TTY write). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |

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
| `--allow-remote-gateway` | off | Permit `--allow-writes` against a non-loopback (real) gateway. The same gate as `bussard write`; without it a write-enabled server pointed at a real gateway refuses to start. |
| `--capture-db <PATH>` | | A `bussard capture` database to extend `knx_recent_telegrams` history beyond the in-memory ring. |

### `bussard viz`

Serve the network-visualization website: an HTTP server that renders the model as a bus-spine diagram and streams live traffic (see [the viz server](#the-viz-server)).

| Flag | Default | Meaning |
|---|---|---|
| `--listen <ADDR>` | `127.0.0.1:8080` | The address to bind the HTTP server to. A non-loopback bind is allowed but warns: the port is unauthenticated. |
| `--dir <DIR>` | `knx` | The model directory (required; a bad model is a hard error so the protected-GA gate never fails open). |
| `--gateway <HOST>` | | Gateway override. On connect failure the server degrades to model-only mode. |
| `--routing` | off | Force routing transport. |
| `--watch-prog` | off | Watch for devices in KNX programming mode and highlight them in the UI. Periodically broadcasts `A_IndividualAddress_Read` on the bus and surfaces the responders in `/api/state`'s `prog` field and the `prog` SSE event. This is active bus traffic, so it is off by default and must be enabled explicitly; never point it at a real installation unattended. Takes effect only when a bus is connected. |
| `--allow-writes` | off | Arm `POST /api/group-write`. Off by default: a bare `bussard viz` is a viewer and the endpoint answers `403 writes_disabled`. |
| `--allow-remote-gateway` | off | Permit `--allow-writes` or `--watch-prog` against a non-loopback (real) gateway. The same gate as `bussard write`; without it such a server refuses to start. |
| `--allow-host <HOST>` | | Also answer requests whose `Host` header is this name (repeatable). Loopback names and bare IP literals are always accepted; any other name is refused, because that is how DNS rebinding reaches this port. |

## Environment variables

| Variable | Meaning |
|---|---|
| `BUSSARD_PROJECT_PASSWORD` | Password for a protected `.knxproj` when `--password` is not given. Keep it in an untracked `.env`, never in the repo. |
| `BUSSARD_KEYRING_PASSWORD` | Password for a `.knxkeys` keyring read by `bussard keyring`. There is deliberately no flag for it, so it never lands in shell history or a process listing. |
| `BUSSARD_ALLOW_REAL_GATEWAY` | Set to `1` to permit a write command against a non-loopback (real) gateway, equivalent to `--allow-remote-gateway`. Loopback gateways never need it. |
| `RUST_LOG` | Log filter (e.g. `debug`, `bussard_transport=trace`). Overrides `-v`/`--verbose` when set. |
| `BUSSARD_ADOPT_ADDRESS` | The target address for `adopt`, for driving the wizard from a script or test (together with `--product`). |
| `BUSSARD_ASSIGN_WAIT_MS` | Test knob: shrinks the programming-mode wait budget of `assign` and `adopt`. Unset in normal use. |
| `BUSSARD_SCAN_DISCOVERY_MS` | Test knob: shrinks the per-address probe timeout of `scan` and `reconstruct --line`. Unset in normal use. |
| `BUSSARD_WIRE_TRACE` | Set to `1` to log every KNXnet/IP datagram as hex on stderr. The diagnostic of last resort when a gateway behaves unexpectedly; very noisy. |
| `BUSSARD_FLASH_L4_TIMEOUT_MS` | Flash knob: the per-exchange Layer 4 timeout. Raise it for a slow device or a lossy link. |
| `BUSSARD_FLASH_REBOOT_WAIT_MS` | Flash knob: how long to wait for a device to come back after a restart. |
| `BUSSARD_FLASH_RECONNECT_EXCHANGES` | Flash knob: how many exchanges to attempt while reconnecting after a restart. |

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
  gateway: "192.0.2.10:3671"   # host:port for tunneling (optional)
  multicast: "224.0.23.12:3671"  # addr:port for routing (optional; this is the default)
```

| Field | Type | Meaning |
|---|---|---|
| `connection.transport` | `tunnel` \| `routing` | The transport used to reach the bus. |
| `connection.gateway` | string, optional | Gateway `host:port` for tunneling. |
| `connection.multicast` | string, optional | Multicast `addr:port` for routing; defaults to `224.0.23.12:3671`. |

An optional `lint:` block turns on the topology and convention rules (`L001`-`L008` in [the diagnostics table](#validation-diagnostics)). Without it nothing extra is reported, so adding the feature cannot change an existing project. `bussard scaffold` writes the block for you.

```yaml
lint:
  topology:
    max_devices_per_line: 64
    supply_ma: { "1.1": 640 }
  groups:
    scheme: floor-trade-block    # or function-floor
    blocks: { light: 5, blind: 10, heating: 10 }
    feedback_pairing: true
    name_pattern: "* * *"
```

| Field | Type | Meaning |
|---|---|---|
| `lint.topology.max_devices_per_line` | integer, optional | The most devices one line may carry (the KNX TP limit is 64). Drives `L001`. |
| `lint.topology.supply_ma` | map line -> mA, optional | Each line's power-supply budget. Drives `L002`, and declaring a line here also declares that it exists, which drives `L003`. |
| `lint.groups.scheme` | `floor-trade-block` \| `function-floor`, optional | Which address level carries the floor and which the trade. The convention lints need it. |
| `lint.groups.blocks` | map trade -> size, optional | How many consecutive sub addresses each trade reserves per room. A trade that is absent is not part of the plan. |
| `lint.groups.feedback_pairing` | bool, default false | Require the feedback address the block layout reserves for each command address. |
| `lint.groups.name_pattern` | string, optional | A glob every GA name must match: `*` is any run of characters (including none), `?` exactly one, everything else literal. |

Bus current for `L002` comes from the cached product data (`models/*.yaml`, written by `import-product` from the `.knxprod` `Hardware.xml` `BusCurrent`). Devices with no cached product contribute nothing and are counted in the warning.

### `groups.yaml`

```yaml
project: "Demo House"                 # optional metadata
imported_from: "demo-house.knxproj"   # optional provenance
ranges:
  "3": { name: "Central" }            # a main group
  "3/2": { name: "Alarms" }           # a middle group
groups:
  "3/0/4":
    name: "Living Room Blind Move"
    dpt: "1.008"
  "3/2/0":
    name: "Wind Alarm"
    dpt: "1.005"
    description: "weather station -> every blind channel"
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
      name: "A: Blind Up/Down"      # informational; refreshed on import
      listen: ["3/0/4"]
  "1.1.30":
    - object: 3
      name: "Wind Alarm 1"
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
name: "Blind Actuator 4-fold"
location: { floor: "Ground Floor", room: "Utility Room" }
product:
  manufacturer: "Northwind Controls"
  order_number: "BA-4"
  application_ref: "M-0004_A-20D6-25-D965"
  mask: "07B0"
channels:
  A: { name: "Blind 1 - Living Room" }
parameters:
  "wind-alarm-1@MD-1_M-3_MI-1_P-3_R-45": "1"
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

These rules are opt-in and run only when `bussard.yaml` carries a [`lint:` block](#bussardyaml):

| Code | Rule | Severity |
|---|---|---|
| L001 | more devices on a line than `topology.max_devices_per_line` | warning |
| L002 | a line's summed device bus current exceeds its `topology.supply_ma` budget | warning |
| L003 | a device sits on a line `topology.supply_ma` does not declare | warning |
| L004 | a KNX Secure device sits behind a line coupler that is not Secure-capable | warning |
| L005 | a GA falls outside every block declared in `groups.blocks` | warning |
| L006 | a command GA has no feedback GA on the offset its block reserves | warning |
| L007 | a GA name does not match `groups.name_pattern` | warning |
| L008 | a GA's DPT contradicts the role its block offset stands for | warning |

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
| Passive | `--passive` | Never transmits. The bus-touching read tools (`knx_read_group`, `knx_describe_device`) are not registered. |
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
| `knx_scaffold_groups` | `plan` (JSON `{rooms: [{floor, room, functions}]}`), `scheme` (optional) | Writes `groups.yaml` from a room and function list, returns the addresses added and the model's validation counts. Confirm the room list with the human first. |
| `knx_read_group` | `ga` | Transmits a GroupValueRead and returns the decoded response. Omitted in `--passive` mode. |
| `knx_describe_device` | `address` | Introspects a device: enumerates its interface objects and each property's description (PID, type, element count, access levels). Read-only on the bus. Omitted in `--passive` mode. |
| `knx_write_group` | `ga`, `value` (human-typed), `dpt` (optional override) | A GroupValueWrite. Registered only with `--allow-writes`; refuses protected GAs outright, and refuses a `dpt` that contradicts the GA's DPT in the model (the override is for GAs the model does not type). |

The model is not frozen at startup: the server re-reads the model directory when its files change, so a `protected: true` or a corrected `dpt:` added to `groups.yaml` mid-session is in force on the next tool call. A model that fails to parse is not swapped in; the server keeps the last good one and warns on stderr.

## The viz server

`bussard viz` serves a single self-contained website (no CDN, no build step, works offline) that turns the model into a live picture of the installation. Open the listen address in a browser.

The page shows:

- **Topology.** A bus-spine diagram grouped by floor and room: every device as a card with its name, address, and type; the group-address plan as a tree on the right. Selecting a device or GA draws its links and lists its senders and listeners.
- **Live traffic.** Telegrams pulse along the spine from sender to listeners and flash the affected cards and tree rows. A bottom log shows time, source, GA, decoded value, and DPT, with a filter grammar and pause.
- **State.** The last value seen on each GA, decoded against its DPT.
- **Problems.** Com objects with no link and GAs with no sender or no listener are surfaced for the P5 review.
- **Test writes.** Per-DPT widgets send a GroupValueWrite from the page. A `protected` GA is disabled until you arm a force checkbox. The confirmation is the echoed telegram on the live stream.

Structure is read-only: devices, groups, and links are edited in the YAML model. An edit does not need a restart — `POST /api/reload` (the ⟳ button next to the bus status) re-reads the directory and swaps the model in place; see [reloading the model](#reloading-the-model).

Writes are off by default. Without `--allow-writes` the send widgets are there but `POST /api/group-write` answers `403 writes_disabled`, so a bare `bussard viz` cannot put anything on the bus. With writes armed, every send asks for an explicit confirmation naming the GA and the resolved gateway before it goes out, and a `protected` GA additionally needs the force checkbox.

### API

The website is driven by a small JSON/SSE API on the same listen address.

| Endpoint | Returns |
|---|---|
| `GET /` | The website shell. `GET /assets/{file}` serves the embedded JS/CSS modules. |
| `GET /api/model` | The precomputed model projection (devices, groups, ranges, links, senders/listeners). Rebuilt in place by `POST /api/reload`. |
| `GET /api/state` | `{bus: {state, transport, connected, gateway, loopback}, seq, values, prog}`, where `gateway` is the resolved endpoint (`192.0.2.10:3671`, or `multicast 224.0.23.12:3671`; `null` in model-only mode) and `loopback` says whether it is a loopback address, where `values` is the last value, payload, DPT, and source per GA, and `prog` is an array of the individual addresses currently observed in programming mode (empty when none, or when `--watch-prog` is off). |
| `GET /api/traffic` | Server-Sent Events. `event: bus` (connection state, always sent first), `event: telegram` (`id:` is the seq, `data:` is the [telegram JSON](#telegram-json-contract) plus `seq`), `event: model` (the model was reloaded, `data:` is `{model_version, stats}`, so the page refetches `/api/model`), `event: prog` (the programming-mode set changed, `data:` is `{devices: [ia, ...]}`; only emitted with `--watch-prog`), `event: gap` (the subscriber fell behind and should re-snapshot). `?backlog=N` (default 50) replays recent telegrams; a reconnect with `Last-Event-ID` resumes with no duplicates and no gaps. |
| `POST /api/group-write` | `{address, value?, payload?, dpt?, force?}`. Encodes and sends a GroupValueWrite; returns `200` with an echo of what was written. |
| `POST /api/reload` | Reloads the model from disk and swaps it in atomically. Returns `200` with `{model_version, stats}` on success, or `422` `model_invalid` (keeping the old model) when the model on disk is broken. |

`POST /api/group-write` takes exactly one of `value` or `payload`. `value` is a human string encoded through the same `parse_value` + `encode` stack as `bussard write` (`dpt` overrides the GA's modelled DPT). `payload` is raw bytes as hex (even length, upper- or lowercase, for example `"0b64"`) sent verbatim, for exotic DPTs with no string grammar. When a DPT is known for a `payload` write (from the model or `dpt`), the decoded byte length is checked against the DPT's expected size: a sub-byte (packable) DPT takes exactly one byte with value `<= 0x3f` and is sent packed into the 6-bit APDU exactly as the `value` path would; a byte-sized DPT takes that many whole octets. When no DPT is known anywhere, the raw write is still allowed but sent unpacked as a full data octet, because a lone 1-byte payload `<= 0x3f` is ambiguous between the packed 1-bit form and a byte-sized value and the full octet is the form every device reads correctly.

The write policy matches `bussard write`: `403` `writes_disabled` for every write when the server was started without `--allow-writes`; `400` for a bad address, an un-encodable value, bad hex, both or neither of `value`/`payload`, or a payload whose length does not match a known DPT; `403` for a `protected` GA without `force` (which applies to raw writes identically); `422` when no DPT can be resolved for a `value` write (supply `dpt`); and `503` when the bus is unavailable. The success echo carries `payload` (the hex bytes sent) and sets `value` to `null` for raw writes. Errors are `{"error": {"code", "message"}}`.

### Reloading the model

The `knx/` YAML is meant to be edited by hand and by LLMs; `POST /api/reload` picks up those edits without restarting the server. It re-runs `Model::load` on the model directory and swaps the shared model plus its precomputed `/api/model` projection in one atomic move, bumping a `model_version` counter (the initial model is version 1). The reload button in the page header (next to the bus status dot) calls it and surfaces any error inline.

The load-failure semantics are the point: a broken model never replaces a good one. On success the endpoint returns `200` with `{ok, model_version, stats}` (`stats` is `{devices, groups, links}`) and emits a `model` event on the SSE stream carrying `{model_version, stats}`, so every connected page refetches `/api/model` and rebuilds its views. On a load error it returns `422` `{"error": {"code": "model_invalid", "message": <the LoadError, naming the offending file>}}` and keeps serving the previous model unchanged, with no swap and no SSE event. The protected-GA write gate and the live decoder both read the current model, so a reload's newly protected GAs are enforced and its renamed addresses resolve on the very next write and telegram.

### Watching programming mode

With `--watch-prog` the server runs a background probe that puts a broadcast `A_IndividualAddress_Read` on the bus every few seconds and collects the responders for about a second, exactly as `bussard assign` does. Every device in KNX programming mode answers with its own individual address (the software equivalent of the red programming LED on real hardware). The responding set is reported in `/api/state`'s `prog` array and, whenever it changes, on the SSE stream as a `prog` event carrying `{devices: [ia, ...]}`, so the UI can highlight a device the moment its programming button is pressed and drop the highlight when it is released.

This is opt-in because the probe generates active bus traffic: it must never run unnoticed against a real installation. It is off by default, takes effect only when the bus is connected, and reuses the server's single tunnel (it never opens a second connection). While the bus is disconnected the set is cleared and probing pauses; it resumes on reconnect.

### Who may reach the server

The listen port is unauthenticated: anything that can open a TCP connection to it can read the whole model, and, with `--allow-writes`, write to the bus. Keep the default `127.0.0.1` bind unless you have a reason not to.

Two browser-specific holes are closed regardless of the bind address:

- **`Host` allow-list.** A request is served only when its `Host` header is a bare IP literal, `localhost` (or a `*.localhost` name), or a name passed with `--allow-host`. Anything else gets `403 forbidden`. Without this, an attacker page on `evil.example` can repoint its own DNS name at `127.0.0.1` and make the browser treat `http://evil.example:8080/api/...` as same-origin with the attacker's page, giving it full read (and write) access. The attacker cannot forge the `Host` header, and rebinding needs a *name*, which is why an IP literal is safe.
- **`Origin` check.** Any state-changing request (`POST`) whose `Origin` is not itself an allowed host is refused with `403 forbidden`. This is what stops a plain cross-site form post at `POST /api/reload`, which takes no body and so is reachable without any preflight. A request with no `Origin` at all is allowed, because no browser omits it here; that is `curl`, not an attack.

### Degraded and offline modes

If the gateway cannot be reached at startup, the server runs in **model-only mode**: the topology, tree, inspector, and problems panels all work, but there is no live traffic and `POST /api/group-write` returns `503`. If the gateway drops mid-session, the bus actor reconnects in the background: `/api/state` flips to `reconnecting`, the SSE stream emits a `bus` event, and writes fail with `503` until the tunnel recovers. No restart is needed.

The server takes one tunnel connection for the whole session. Whether a second tool (a concurrent `bussard write`, `flash`, or `scan`) can share the gateway depends on the gateway: `knx-sim` currently accepts more than one tunnel, but real gateways vary, and traffic on one tunnel is not necessarily mirrored to another. To drive test traffic that the page will always see, use `POST /api/group-write` on the viz server itself.
