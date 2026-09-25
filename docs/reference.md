# Reference

The complete surface of `bussard`: every command and flag, the environment variables, the model directory and its YAML fields, the validation diagnostics, the JSON contracts, and the MCP tools. Verified against the code; `bussard <command> --help` is always authoritative for the build you run.

## Conventions

- Addresses: group addresses (GAs) are 3-level strings like `3/2/0`; individual addresses (IAs) are `area.line.device` like `1.1.4`; DPTs are `"1.001"`.
- `--dir <DIR>` (default `knx`): the model directory. Every command that touches the model takes it.
- `--gateway <HOST>`: override the gateway `host[:port]` for tunneling (port defaults to 3671).
- `--routing`: force KNXnet/IP routing (multicast) instead of tunneling.
- `--skip-address-check`: on the commands that open a connection to a device, skip the pre-flight probe that no bus device answers at bussard's own source individual address. See [SAFETY.md](SAFETY.md#source-address-check).
- Filters (`monitor --filter`, `capture --filter`): a comma-separated list of GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`), or IAs (`1.1.30`).
- Confirmation: commands that write to devices confirm on a terminal (`y/N`), naming the resolved gateway (`host:port`). Without a TTY they refuse unless `--yes` is passed (`--yes-download` for `import-product`). This covers `write`, `flash`, `apply`, `assign` and `adopt`.
- Real-gateway safety: a write command whose resolved gateway is **not** loopback (not `127.0.0.0/8` or `::1`) refuses to run unless you opt in with `--allow-remote-gateway` or `BUSSARD_ALLOW_REAL_GATEWAY=1`. Loopback gateways (the local simulator, the test suite) are always allowed. Reads (`monitor`, `read`, `scan`, `plan`, `reconstruct`) are never gated. The two long-running servers pass the same gate once, at startup, when they are able to transmit: `mcp --allow-writes`, `mcp --allow-programming`, `viz --allow-writes`, and `viz --watch-prog`. The MCP programming tools check it again on every call. Without those flags neither server can write, so neither is gated. [SAFETY.md](SAFETY.md) is the read-before-your-first-write guide to all of this.

### Global flags

These apply to every subcommand:

- `-v` / `--verbose` (repeatable): raise log verbosity. `-v` = `info`, `-vv` = `debug`, `-vvv` = `trace`. The default (no flag) is `warn`. An explicit `RUST_LOG` overrides this entirely, so `RUST_LOG=bussard_transport=trace` still works for targeted tracing.
- `--timing`: print the invocation's wall-clock time to stderr on exit (e.g. `took 1.23s`). Off by default.
- `--no-progress`: never draw the live progress display; print the plain progress lines instead, as a piped run does.
- `--secure-user <ID>` with `--secure-password-env <VAR>`: open a [KNXnet/IP Secure](#knxnetip-secure-tunnelling) tunnel as tunnelling user `ID`, with its password read from the environment variable `VAR` (never from the command line). Both flags go together.
- `--secure-transport auto|tcp|udp`: the carrier of the KNXnet/IP Secure session (default `auto`: TCP, and UDP when the interface refuses TCP but advertises Secure). Needs tunnelling credentials.

#### KNXnet/IP Secure tunnelling

An interface with KNXnet/IP Secure enabled and no plain tunnel refuses an ordinary connection. bussard then needs a tunnelling user's credentials and opens an authenticated, encrypted session (issue #71 Phase B): X25519 key agreement, the interface proves its device authentication code, bussard proves the user password, and every frame after that travels in a SECURE_WRAPPER.

- **From a keyring (automatic).** A command that takes `--keyring <file.knxkeys>` also uses the keyring's tunnelling users (`Interface Type="Tunneling"` entries, see [`bussard keyring`](#bussard-keyring-file)). bussard asks the gateway for its extended description; when a keyring interface names the gateway's individual address as its host and the gateway advertises KNXnet/IP Secure, the tunnel goes secure as the user whose tunnel address is free. The keyring also carries the interface's device authentication code, so bussard checks the interface's identity before it authenticates. A plain gateway stays on the plain tunnel.
- **One keyring, two jobs (issue #189).** The keyring opens the tunnel, and its `Device` entries carry the tool keys. A device the keyring lists is managed over KNX Data Secure with its tool key. A device it does not list is managed in the clear through the secure tunnel, so the plain devices behind a secure-only interface stay reachable. The exception: a device whose model file says `security.activated: true` but that the keyring does not list is refused with `the keyring ... has no tool key for <IA>`, because plain access cannot reach it. This holds for `describe`, `reconstruct`, `plan`, `flash`, `apply`, `commission`, `replace`, `backup`, `restore`, the `--line` walks, and the MCP device tools. `scan`, `assign` and `audit --live` identify devices with the same rule but never refuse: a Data Secure-activated device that answers a plain descriptor read with mask `FFFF` and has no tool key is labelled "Data Secure activated (mask hidden), no tool key in the keyring" (issue #203).
- **The config default.** `connection.keyring` in [`bussard.yaml`](#bussardyaml) names the keyring every bus command uses when `--keyring` is not given (`adopt` and `test` use it for the tunnel only). The flag overrides it. The password still comes from `BUSSARD_KEYRING_PASSWORD`.
- **Explicit.** `--secure-user <ID> --secure-password-env <VAR>` on any command always opens a secure session as that user. Without a keyring the interface's identity is not verified (a warning says so).
- **TCP or UDP (issue #197).** bussard opens the session over TCP first, as ETS does with the Jung interface. When the TCP connect is refused and the interface's extended search advertises KNXnet/IP Secure, it opens the session over UDP instead: one UDP socket for the session and the tunnel, TUNNELING_ACKs inside the wrappers, the real local endpoint in every HPAI. `--secure-transport tcp` or `udp` forces one carrier. The UDP path follows the KNX specification and is verified against knx-sim only; no UDP-only interface has been tested.
- **Neither.** Against a secure-only interface the command fails at once, with no retries: `interface <gateway> requires KNXnet/IP Secure (secure tunnelling only) and no tunnelling credentials were given ...`. `bussard init --gateway <ip>` prints `KNXnet/IP Secure: tunnelling is secure-only` for such an interface.

The tunnel address is assigned by the interface to the authenticated user (in an ETS keyring, each user has its own, e.g. 1.1.22 to 1.1.29), and management traffic uses it as its source. A refused password (`refused tunnelling user N`) and an interface that fails its own authentication are fatal. A lost link re-establishes a new secure session within the [`BUSSARD_TUNNEL_RECONNECT_SECS`](#environment-variables) budget. TCP carries no ACK, so after 5 s without any frame from the interface the tunnel sends a CONNECTIONSTATE_REQUEST and treats 2 s of further silence as a lost link: a pulled cable is noticed after about 7 s ([`BUSSARD_TCP_READ_DEADLINE_MS`](#environment-variables)). A UDP session detects a loss through its ACK timeout, as a plain tunnel does. The session sends a wrapped keepalive every 30 s ([`BUSSARD_SECURE_KEEPALIVE_SECS`](#environment-variables)); `bussard test --secure-idle <secs>` measures how long the interface keeps an idle session. Secure routing (multicast) is not implemented.

#### Progress display

`flash` (including `--parameters-only`), `apply`, `reconstruct --line` and `scan` show a live progress view on stderr when both stdout and stderr are terminals. It shows the current step `k/n` and its label, a byte bar for the segment being streamed, the elapsed time, an ETA and the last bus event (a reboot wait, a reconnect, a connect retry). The flash ETA starts from the plan's TP1 frame estimate and switches to the measured rate once 5% of the bytes are written. A successful run clears the view and ends with the same final lines as before; a failed run leaves it on screen so the step it stopped at stays visible.

The view is off, and the output is the plain line-oriented text byte for byte, whenever stdout or stderr is not a terminal, `TERM=dumb`, `BUSSARD_WIRE_TRACE=1` is set, the command runs with `--json`, or `--no-progress` is given. The plain lines never contain cursor-control codes beyond the `\r` the byte and address counters have always used, so logs, the campaign wrapper's `step.log`, the MCP server and scripts see the same text as before. Progress never goes to stdout.

### Exit codes

`0` on success, non-zero on any error. Meaningful cases:

- `validate` exits non-zero when there are errors (warnings and infos alone exit 0).
- `read` exits non-zero when no response arrives within the timeout, so scripts can detect a dead group object.
- `plan` and `apply` exit 0 when there is nothing to do.
- `import` exits `3` when a re-import kept hand-edited values that differ from the incoming side and no `--mine`, `--theirs` or `--interactive` settled them. The write still happened.
- Refusals (protected GA without `--force`, non-TTY without `--yes`, unsupported device mask, unsupported load procedure) exit non-zero before anything is written.
- `audit` exits 0 on a completed audit, whatever it found; findings are data, not failures.

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Any other error or refusal. |
| `3` | `import` re-imported the project but left hand-authored conflicts un-applied. The files were written with your edits intact; reconcile the reported fields. |
| `4` | The gateway has no free tunnelling connection (`E_NO_MORE_CONNECTIONS`, status `0x24`). Every tunnel slot is taken, usually by Home Assistant, an open ETS project or another bussard process. Distinct from a network timeout, which exits `1`. See [the tunnel budget](SAFETY.md#the-tunnel-budget). |

## Commands

### `bussard init`

Create a fresh model directory: discover the gateway, write the skeleton.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The directory to create the model in. |
| `--gateway <HOST>` | discover | Use this gateway `host[:port]` instead of discovering one. |
| `--routing` | off | Configure KNXnet/IP routing (multicast) instead of tunneling. |

Gateway discovery is multicast and does not cross subnets. If it finds nothing, `init` still writes a valid skeleton with a placeholder gateway.

With a resolved tunnelling gateway, `init` asks the interface to describe itself (a unicast DESCRIPTION_REQUEST, no tunnel slot used) and prints its tunnel budget:

```
Gateway: Jung IP Interface (192.0.2.10:3671, IA 1.1.0)
Tunnelling: 4 tunnels, 1 in use.
```

The count comes from the tunnelling-info DIB (KNXnet/IP Core v2). An interface that sends only its additional individual addresses prints `N tunnels (usage not reported)`; an older interface that reports neither says so. If the reachability check finds every slot taken, `init` prints the no-free-tunnel message (see [exit codes](#exit-codes)) and still writes the skeleton.

`init` asks with an extended search (SEARCH_REQUEST_EXTENDED), which also reports KNXnet/IP Secure: `KNXnet/IP Secure: tunnelling is secure-only (needs tunnelling credentials)`, `supported, plain tunnelling allowed` or `not advertised`. A secure-only interface skips the plain reachability check and names the credentials a command needs ([KNXnet/IP Secure tunnelling](#knxnetip-secure-tunnelling)). Discovery lists such interfaces as `KNXnet/IP Secure only`.

### `bussard import [PROJECT]`

Import an existing `.knxproj`, a `.bussard` bundle (see [`export`](#bussard-export-file)) or an xknxproject JSON dump into the model. Re-import is idempotent: hand edits to names, DPTs, descriptions and `protected:` flags survive where the address is unchanged; device files whose address left the project are pruned.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[PROJECT]` | | The `.knxproj` or `.bussard` file to import (omit when using `--from-json`). |
| `--from-json <FILE>` | | Import from an xknxproject JSON dump instead of a `.knxproj`. |
| `--password <PASSWORD>` | | Project password. Falls back to `BUSSARD_PROJECT_PASSWORD`, then an interactive prompt. |
| `--dir <DIR>` | `knx` | The model directory to write. |
| `--mine` | off | On a re-import, keep this model's value for every hand-edited conflict and exit 0. |
| `--theirs` | off | On a re-import, take the incoming value for every hand-edited conflict. |
| `--interactive` | off | On a re-import, ask per conflict (`m` keeps mine, `t` takes theirs). Needs a terminal. |

A re-import always takes the generated sections (com-object tables, link wiring, parameters) from the incoming side. Hand-authored fields (names, rooms, descriptions, DPTs, `protected:`, channel names) that differ are conflicts: each is printed as a sentence, e.g. `Group address Light Kitchen (1/0/1): the name is "Light Kitchen" here and "Kitchen ceiling" in the bundle. Kept this model's value.` Without a flag the local value is kept and the command exits `3` so a script notices; `--mine`, `--theirs` and `--interactive` settle the conflicts and exit 0. After the write, `import` prints what it changed in the model as the same sentences `bussard status` uses, then validates the written model and prints `validation: N error(s), M warning(s)` with each error (an error does not undo the import; it is what to fix next). A group address a device uses but the project does not define is added to `groups.toml` (see [`groups reserve`](#bussard-groups-reserve-floor-room-function)). Every import into an existing model snapshots it first, so `bussard undo` reverts it.

A bundle imported into a directory without a model (no `groups.yaml`, no device file) is extracted byte for byte, history included: the copy is identical to the exported model. An existing `bussard.yaml`, for example from `bussard init`, is kept. A bundle imported into an existing model runs the merge above; the local history stays and the bundle's snapshots are not merged into it.

### `bussard export [FILE]`

Write the model and its history as one `.bussard` file: the handover file for an integrator and the owner's backup. See [The bundle format](#the-bundle-format).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | `<parent>/<dir name>-<YYYY-MM-DD>.bussard` | The bundle to write, next to the model directory by default. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--no-history` | off | Leave the `.bussard/history` snapshots out. |
| `--json` | off | Print `{"path", "manifest"}` as JSON. |

The model must load; `export` refuses a broken model. It records the bundle's path, time and model digest in `<dir>/.bussard/last_export.json`. After a verified `apply`, bussard prints a one-line hint on stderr when that record is older than the newest `apply` snapshot and the model files have changed since the export, or when the model was never exported. An apply of an unchanged model stays quiet.

### `bussard diff <A> <B>`

Explain what changes from `A` to `B`, as the plain sentences `bussard status` prints. Each side is a `.knxproj`, a `.bussard` bundle, an xknxproject `.json` dump or a model directory. Both sides are loaded in memory; nothing is written. Exits 0 whether or not there are differences.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<A>`, `<B>` | | The two sides. |
| `--json` | off | Emit `{"a", "b", "summary", "touches_protected", "changes": [...]}`, the same change objects as `status --json`. |
| `--raw` | off | Print a file-level YAML diff instead of the sentences. |
| `--password <PASSWORD>` | | Password for both `.knxproj` sides. Falls back to `BUSSARD_PROJECT_PASSWORD`. |
| `--password-b <PASSWORD>` | | Password for the second side, when it differs. |

Group addresses are matched by address and devices by individual address, so a GA renamed in a newer export is one rename, not a removal and an addition. Two exports of the same project give an empty diff. A parameter change is named by the parameter's text from the cached product model (`models/*.yaml`) when a model-directory side has one, and by its key otherwise.

### `bussard scan [LINE]`

Scan a line for devices: mask version, manufacturer, order number, and the delta against the model (known, unexpected, missing). Sweeps addresses sequentially, one management connection at a time.

**How an absent address is ruled out (issue #45).** Most IP interfaces confirm every frame bussard sends with an `L_Data.con`. When no device acknowledges a frame on TP1, the interface sends a *negative* con (error bit set) within 22 to 45 ms. `scan` takes the negative con of the `T_Connect` or the descriptor read as proof that the address is absent and moves on at once. A gateway that sends no negative confirmation falls back to the ACK timeout and one repetition (2 × 1.5 s per absent address), as before. A present device is read with exactly the same frames either way. On a line of 256 addresses with 5 devices the mock sweep takes 8 s with negative confirmations and about 12.5 minutes without them. The same rule applies to the other presence probes built on the discovery budget (`audit --live`, `reconstruct --line`, `backup`, `replace`, `commission`). Programming sessions and the readiness probe after a device restart never use it: to them a negative con only means "not up yet", and they wait out their timeouts.

When the sweep ends, stderr shows a summary such as `256 addresses in 8.4 s (absent by negative confirmation: 251, by timeout: 0)`. `--json` adds a `timing` object: `addresses`, `total_ms`, `absent_negative_confirmation`, `absent_timeout`, `refused`, and `per_address`, one `{address, ms, outcome}` row per probed address, where `outcome` is `present`, `absent_negative_confirmation`, `absent_timeout` or `refused`. The other keys of the JSON output are unchanged.

A Data Secure-activated device answers a plain descriptor read with mask `FFFF` (issue #203). When the keyring lists the address, `scan` reads the descriptor and the properties over `A_SecureData` (after the S-A_Sync handshake) and shows the real mask; the row is marked `Data Secure activated` and `--json` adds `"secure": "activated"`. Without a tool key the row keeps mask `FFFF` with the label `Data Secure activated (mask hidden), no tool key in the keyring` and `"secure": "activated_no_key"`; a key that the device does not accept gives `"secure": "key_refused"`. A plain device's row and frames are unchanged (no `secure` field).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[LINE]` | `1.1` | The line to scan. |
| `--from <N>` | `0` | The first device number to probe (0-255). |
| `--to <N>` | `255` | The last device number to probe (0-255). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON instead of the table format. |
| `--keyring <FILE>` | `connection.keyring` | An ETS `.knxkeys` keyring: its tunnelling users open the [KNXnet/IP Secure tunnel](#knxnetip-secure-tunnelling), and a device it lists is identified over KNX Data Secure with its tool key (real mask, `secure: activated`). Unlisted devices are read in the clear. Password from `BUSSARD_KEYRING_PASSWORD`. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

### `bussard assign [ADDRESS]`

Assign an individual address to the device in programming mode. Refuses when more than one device is in programming mode. Confirms on a terminal (naming the gateway); a non-TTY needs `--yes` (an explicit address is not itself consent).

The verification after the write reads the device at its new address. For a Data Secure-activated device it runs over `A_SecureData` with the tool key (issue #203): `--tool-key` if given, else the keyring entry of the new address, else the entry of the old address. In the last case `assign` prints a note to re-export the keyring from ETS: the keyring lists devices by individual address, so later commands only find the key under the new address once the keyring does (see [SAFETY.md](SAFETY.md#what-each-write-command-does-and-its-rails)). Without any key an activated device answers mask `FFFF`: the address is verified, the output says `Data Secure activated (mask hidden), no tool key in the keyring`, and the stub device file records no mask.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | next free on the line | The address to assign, e.g. `1.1.47`. |
| `--yes` | off | Skip the confirmation prompt (required for a non-TTY assign). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--keyring <FILE>` | `connection.keyring` | An ETS `.knxkeys` keyring: its tunnelling users open the [KNXnet/IP Secure tunnel](#knxnetip-secure-tunnelling), and its tool key for the new (else the old) address verifies a Data Secure-activated device. Password from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | A raw 16-byte tool key (32 hex characters) for the verification of a Data Secure-activated device; overrides the keyring's device entries (the keyring still opens the tunnel). For test or bench devices: process arguments are visible to other users. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
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
| `--product <FILE>` | cached archive | Single-device mode: the device's `.knxprod`, to read back and decode its parameter memory too (see [parameter read-back](#parameter-read-back)). Without it the archive in `<dir>/vendor/` whose catalogue carries the model's order number is used, when cached. |
| `--application <REF>` | model's application | The application program id to decode with (default: the model's `application_ref`, else the order number, else the sole application). |
| `--keyring <FILE>` | | Single-device mode: the ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key. Required for a security-activated device; the password comes from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | Single-device mode: the raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--json` | off | Emit JSON instead of the report format. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
| `--refresh-facts` | off | Ignore the stored [device facts](#bussardfacts) and read them from the device again. |

A KNX Data Secure-activated device answers the plain descriptor read with mask `FFFF`, so without its tool key `reconstruct` stops with "mask FFFF (System ?) ... can: describe only" plus the `--keyring` hint. With `--keyring` (or `--tool-key`) every read, the descriptor included, runs over KNX Data Secure: the device reports its real mask and the table reads and the parameter read-back run unchanged on the secured session. `plan` takes the same two flags.

On System B each table's entry count comes from its `PID_TABLE` property. The entries are read from memory (the table's `PID_TABLE_REFERENCE` address, `A_MemoryExtended_Read` or `A_Memory_Read` at the negotiated chunk, up to 228 octets, 215 under Data Secure) when that takes fewer requests than `PID_TABLE` reads of 15 elements, otherwise through `PID_TABLE`. A table of 1,333 associations takes 25 memory reads instead of 89 property reads; a table of a few entries stays on one property read. The memory read falls back to `PID_TABLE` when the reference is missing, the device refuses or does not answer the read, or the memory count word disagrees with the property count. `--json` reports the path per table in `table_source` (`property (PID_TABLE)` or `memory (PID_TABLE_REFERENCE)`). `plan`, `apply`, `backup`, `line` and the MCP plan tool read the tables the same way.

### `bussard describe <ADDRESS>`

Introspect a device over the bus: discover its interface objects and, for each, enumerate every property's description (PID with a name when known, data type, element count, and read/write access levels) as a table. Read-only on the bus — it sends `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` (object discovery) and `A_PropertyDescription_Read`, never a write. Unlike `reconstruct` it does not resolve group tables; it describes the device's raw property set, which is useful for commissioning and diagnostics on an unknown device.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to introspect, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory (connection defaults). |
| `--json` | off | Emit JSON instead of the table format. |
| `--full` | off | Walk every object's property descriptions again, even when the [device facts](#bussardfacts) hold them. |
| `--refresh-facts` | off | Ignore the stored device facts and read everything from the device again. |
| `--keyring <FILE>` | `connection.keyring` | The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key. Required for a security-activated device. A keyring that does not list the target only opens the [secure tunnel](#knxnetip-secure-tunnelling) and the device is read in the clear. The keyring password comes from `BUSSARD_KEYRING_PASSWORD`, never a flag. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device with a synthetic key. Conflicts with `--keyring`. A process argument is visible to other users on the machine, so do not use it for a real installation. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

The first `describe` of a device stores its interface objects and property descriptions as [device facts](#bussardfacts). A later `describe` checks the device's mask and application id (the descriptor read plus one property read) and, when both still match, prints the stored objects and descriptions instead of sending one `A_PropertyDescription_Read` per property: on a KNX Data Secure device about 4 requests instead of about 110. The report is the same either way; in text mode a note on stderr says the facts were reused. `--full` walks the descriptions again, `--refresh-facts` re-reads everything, and a changed mask or application id re-reads on its own.

A security-activated device refuses plain management access; pass its tool key with `--keyring` (or `--tool-key` for a test device) and `describe` runs over KNX Data Secure. The same two flags work on `flash`, `apply`, `plan` and `reconstruct`. See [SAFETY.md](SAFETY.md#known-limitations) for what is verified.

An activated device still answers the plain `A_DeviceDescriptor_Read` and the PID 56 read, then refuses the interface-object walk. `describe` treats a walk that finds no interface object after a successful descriptor read as a failure, not an empty device: it exits 1 with the `--keyring` hint on stderr. System 1 (BCU1) devices have no interface objects and are exempt.

The `--json` output has these fields:

| Field | Present | Meaning |
|---|---|---|
| `address`, `mask`, `system_type` | always | The device and its mask version. |
| `objects` | on success | The interface objects and their properties. Absent on a refused walk. |
| `unsecured_management` | refused walk, no key | `"refused"`: the device answered the descriptor read but not the plain walk. |
| `secured_management` | refused walk, with a key | `"unanswered"`: the secured walk returned no interface object. |
| `error` | refused walk | The error message, with the KNX Secure hint. |
| `secure.model` | the model has a security block | What the knxproj import recorded: `secure_capable`, `activated`, `has_fdsk_certificate`. An export made before ETS activated the device says `activated: false`. |
| `secure.device` | model security, a tool key, or a refused walk | What the device did in this run: `plain_management` (`answered`, `refused`, or `not_attempted` when a key was given) and `secured_management` (`used`, `not_attempted` without a key, or `unanswered`). |

The text output prints the same split as `KNX Secure (model):` and `KNX Secure (this run):` lines. No key material appears in either form.

### `bussard keyring <FILE>`

Inspect an ETS KNX Secure keyring export (`.knxkeys`): print what it carries — the device individual addresses, the tunnel/management interface addresses, whether a backbone key is present, how many group keys there are, the KNXnet/IP Secure tunnelling users (user id, tunnel address, interface, and whether the password and the device authentication code are present) and the devices with KNXnet/IP Secure device credentials. **No key material or password is ever printed**, in text or JSON (`tunnelling_users`, `ip_secure_devices`).

```
  KNXnet/IP Secure tunnelling users (2):
    user 2 -> 1.1.22 (host 1.1.200)
    user 3 -> 1.1.23 (host 1.1.200)
```

A user line notes a missing password or device authentication code; a keyring without tunnelling users prints `KNXnet/IP Secure tunnelling users: none`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<FILE>` | | The `.knxkeys` file to inspect. |
| `--json` | off | Emit JSON instead of the text summary. |

The keyring password comes from `BUSSARD_KEYRING_PASSWORD` and is deliberately **not** a flag, so it never lands in shell history or a process listing. Reading a keyring changes nothing on the bus; to program or read back a Data Secure device, pass the same file to `flash`, `apply`, `describe`, `plan` or `reconstruct` with `--keyring`. See [SAFETY.md](SAFETY.md#known-limitations).

### `bussard import-product [FILE]`

Import vendor product data (`.knxprod`): cache it under `<dir>/vendor/` and generate one model file per application program under `<dir>/models/`. An ETS project export (`.knxproj`) works as a source too; it is read in place and not copied under `vendor/`, since it is your project, not vendor data. Three modes: a local file (positional), `--order-number` to look the file up in the pointer index and download it, or `--list` to show the index. Details in [product-data.md](product-data.md).

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | | The `.knxprod` or `.knxproj` file to import (positional mode). |
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
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |

### `bussard flash <ADDRESS>`

Download the full application program from vendor product data into a device (the ETS-free application download): for a fresh device, or one whose application changes. Everyday changes to links and parameters go through [`apply`](#bussard-apply-address), which writes only what differs. The product data is the archive in `<dir>/vendor/` whose catalogue carries the device's order number (`import` and `adopt` fetch it), and the application is the one the lock pins; `--product` and `--application` override both. Supports System B (`07B0` and the `57B0`/`27B0` variants) and System 7 (`0705`/`0701`/`0700`). Pre-flight plan first; refuses before any write on an unsupported mask family, a mask mismatch, or an unsupported load-procedure operation. The parameter memory image is computed from the vendor defaults plus the device file's `parameters:` overrides, so a flash also carries parameter changes. No backup exists for a flash; recovery is re-running `flash`.

The same pre-flight also checks the device is factory-fresh (issue #79), read-only, before anything is written: it reads each object's load state and, on System B, the resident application id (`PID_PROGRAM_VERSION`). A device carrying a **different** application, one it cannot identify, or a load state it cannot read at all is **refused**; `--force` overrides. Re-flashing the **same** application is allowed without `--force` (it is the documented recovery path after an interrupted flash) and prints a notice, because it still resets the parameters to the vendor defaults plus the model's overrides and rewrites the tables from the model's links. See [the flash section in SAFETY.md](SAFETY.md#what-each-write-command-does-and-its-rails) for the full table.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.0.10`. |
| `--product <FILE>` | cached archive | The vendor `.knxprod` containing the application program. Default: the archive in `<dir>/vendor/` whose catalogue carries the device's order number. |
| `--application <REF>` | the lock's program | The application program id (default: the program the lock pins, else the order number's, else the sole one). Mutually exclusive with `--order-number`. |
| `--order-number <ORDER>` | | Select the application by hardware order number (e.g. `AKK-0216.03`), resolved through the product's hardware catalogue. Exactly one match is required. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--force` | off | Flash a device that is **not** factory-fresh: it already carries a different (or unidentifiable) application, or its load state could not be read. Destructive: the resident application, its parameters and its links are overwritten with no backup. Not needed to re-flash the same application. |
| `--full` | off | Re-stream every object. By default, when the device already carries the same application (or none), an object whose resident image matches what would be written (MCB size and CRC) and which reports `Loaded` is skipped; the flash output lists each skipped step. A parameter-only change then re-downloads the parameter segment but not the code segment. Never skipped when `--force` replaces a different or unidentified application, or when the plan starts with a factory reset. |
| `--parameters-only` | off | Rewrite only the parameter memory of a device that already runs this application (see [parameter-only download](#parameter-only-download)). Conflicts with `--full`, `--force` and `--no-factory-reset`; with `--dry-run` it prints the op sequence offline. |
| `--no-factory-reset` | off | Leave out the factory reset (System B). By default a download that writes filled segments sparsely, or that replaces an application with `--force`, starts with a confirmed master reset, erase code 7: the device erases its application, parameters and links, keeps its individual address, and reboots. Use this only when you know the device holds no stale image. |
| `--bcu-key <HEX>` | free access | The device's BCU access key, in hex (`FFFFFFFF` or `0x11223344`), presented with A_Authorize on every management connect. Unset presents the free-access key (`FFFFFFFF`), correct for an unkeyed device; a keyed device needs its project key here or it denies access. |
| `--keyring <FILE>` | | The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key. Required for a security-activated device; the password comes from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`; unsuitable for a real key (process arguments are visible). |
| `--secure-sender <IA>` | off | Data Secure: also list this address (bussard's tunnel address) with sequence 0 in the security individual address table (PID 54) the flash writes, so the device accepts `write --keyring` from bussard. Without it the table holds only the devices that send on a secured GA the device listens to (with their keyring sequence), as ETS writes it, and the device drops bussard's secured group telegrams. See [SAFETY.md](SAFETY.md). |
| `--allow-remote-gateway` | off | Permit a flash to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
| `--refresh-facts` | off | Ignore the stored [device facts](#bussardfacts) and read them from the device again. |
| `--json` | off | Print the pre-flight plan as JSON instead of the report. It carries a `parameters` array (`key`, `name`, `old`, `new`, `unit`; `old` is `null` when unreadable), the application identity, the write summary and the step trace. The confirmation and the flash itself are unchanged. |
| `--dry-run` | off | Build and print the pre-flight plan against the application's own mask, then stop. No gateway is resolved and no connection is opened, so it works with no gateway configured. |
| `--dump-images <DIR>` | | With `--dry-run`: write `plan.json` and the exact memory images the flash would stream (one `.bin` each, plus the table images) into `DIR`. See [the offline oracle](testing-campaign.md#before-a-flash-the-offline-oracle). |
| `-v` | off | Show the memory-level plan (the step trace) and the raw override keys under the parameter-level plan, and end with the wall-clock time per phase: pre-flight, download, restart + verification, followed by the reboot readiness per restart the device confirmed, for example `; readiness M-0004_A-20D6-26-FAEB-O000A: factory reset 8.5 s (process time 8 s), restart 2.1 s (process time 0 s)`: the time from the device's `A_Restart_Response` to the first answered readiness probe (after a factory reset the probes start at +3 s and only measure; the reported process time is always waited out). |

The pre-flight report leads with the **parameter-level plan** (issue #109): one line per parameter the flash changes, named with the parameter text from the `.knxprod`, with old value, new value and unit (`Night setback: 18 °C to 17 °C`). Enumerations show the vendor's member text. The current values are read back, read-only, from the device's parameter segment when it already carries an application, on the pre-flight connection and in chunks sized to the device's maximum APDU; on a factory-fresh device, or when a segment cannot be read, the line reads `unknown current value, will be <new>`. With `--force` the read-back is skipped (the whole application is rewritten anyway) and the plan says so. A parameter left at its vendor default is listed only when the device is known to hold something else. On System 7 the parameter diff is replaced by a note, and the memory-level plan is the authoritative one. The memory-level plan is always available with `-v`.

The confirmation names the resolved gateway (`flash <app> to <target> via <host:port>?`).

**Factory reset and final restart (System B).** When the download allocates a segment with a fill byte, bussard writes only the octets that differ from the fill, and the device does not erase the rest. A re-flash would then inherit the previous image's octets wherever the new one writes nothing. So the plan starts with a factory reset, as ETS starts an initial download: `A_Restart` master reset with erase code 7 and channel 0, sent numbered (`4f 81 07 00` in the ETS capture), answered by `A_Restart_Response` with an error code and a process time in seconds (`4f a1 00 00 08`). bussard waits the process time (at most 60 s), reconnects and continues. It erases the application program, the parameters and the group addresses and links; the individual address stays. The step sits before the first `Unload`, after any read-only `CompareProp`/`CompareRelMem` preconditions. `--force` on a device that is not factory-fresh adds the same step to any System B plan. A refused or unanswered reset fails the flash before anything is written; only when the gateway link dropped meanwhile is it sent again once the tunnel is back, and a link loss during the reconnect after it is ridden out (see [resume on connection loss](SAFETY.md)). Such a plan also ends like ETS: the terminal `LdCtrlRestart` goes out as the confirmed master reset with erase code 1, and bussard waits its process time before verifying. Plans without filled segments (KNX Virtual DA.tp, thelsing) keep the bare `A_Restart`, and an `LdCtrlMasterReset` op in a load procedure is still sent as the bare `A_Restart` KNX Virtual expects.

Supported load-procedure operations on System B: `Unload`, `Load`, `LoadCompleted`, `RelSegment`, `WriteRelMem`, `WriteMem`, `WriteProp`, `CompareProp`, `LoadImageProp`, `Restart`. On System 7 the procedure runs on its own absolute-addressed lowering: `Unload`, `Load`, `AbsSegment` (allocate and stream), `TaskSegment`, `TaskCtrl1`, `LoadCompleted`, the obj0/PID78 `CompareProp`, `CompareMem`, `LoadImageProp` and `Restart`. Procedures with unrecognized ops (e.g. `LdCtrlCompareRelMem`) are refused whole, before any write. After writing, `flash` verifies the application reads back as `Loaded` and spot-checks written segments byte-for-byte. On a System 7 mask whose product data declares no `VerifyMode` (Theben `0700`/`0701`), `flash` streams each segment the way ETS does: it reads every chunk first, writes only the chunks that differ from the image, and reads written chunks back, so a re-flash of an unchanged device writes nothing but the load-state records. The plan shows these segments as `stream segment (read-compare, N octets)`, and `plan.json` from `--dump-images` marks them `"write_mode": "read-compare"` (a `VerifyMode` mask such as Jung `0705` stays `"blind"`).

Only `flash` takes `--bcu-key`; `plan`, `apply` and `reconstruct` always authorize with the free-access key, so a device with a BCU key set denies them.

#### Parameter-only download

`flash --parameters-only <ADDRESS>` rewrites only the parameter memory of a device that already runs the application (issue #119). It builds the same plan a full flash would, then keeps only what touches the parameter memory:

- **System B**: `StartLoading` on the object that holds the parameter segment, the procedure's property writes on that object (the `PID_MCB_TABLE` seed and `PID_PROGRAM_VERSION`), the parameter image written at the base the object reports through `PID_TABLE_REFERENCE`, `LoadCompleted`, the procedure's MCB checks on that object, and the terminal restart. No `Unload`, no segment allocation, no factory reset, no table object.
- **System 7** (issue #146): `StartLoading` on the load-state machine that holds the parameter segments (LSM 3), the differing octets written in place into each parameter segment, `LoadCompleted`, the procedure's MCB reads of objects 1 to 3, and the restart. No `AbsSegment` record, no task segment, no task control: re-sending the `0x0700` allocation put a Jung 3361-1MWW into load state Error, and ETS's partial download of the same device sends none of them. The executor reads LSM 3 first and writes nothing unless it is `Loaded`. LSM 1 and 2 (the tables) are not touched and nothing is unloaded.

Before planning it reads the parameter memory back, and every write goes out as the octets that differ from what the device holds, the way ETS rewrote a single octet in its partial downloads of `1.1.47` (System B) and `1.1.202` (System 7). The plan names each parameter that changes (`Threshold: 7 to 12`), the memory regions and how many of their octets change. When nothing differs it prints `nothing to do` and exits 0 without touching a load state.

It refuses, before any write, when:

- the device runs another application: on System B its `PID_PROGRAM_VERSION` differs from the product's, or cannot be read; System 7 has no readable application id, so every load-state machine must be `Loaded` and the first octets of each application code segment must read back as the product's bytes;
- the application is not `Loaded`, or the load state cannot be read;
- a parameter segment cannot be read back (its base or content is unknown);
- on System 7, the model's links differ from the device's group-address or association table: the table load-state machines are not reloaded, so run `apply` first;
- the new values change the group-object table: the Dynamic section is evaluated with the values the device holds and with the model's values, and a com-object shown or hidden (or an object whose size or flags change) needs a full `flash`. The refusal names the objects.

The confirmation, `--yes` and the gateway gate are the same as for `apply`. The parameter memory is backed up to `<dir>/captures/backups/parameters/<ia>-<unix time>.json` before the first write (kept apart from the table backups, so `restore` never picks it up). After the restart the memory is read back and every changed octet compared; a mismatch exits 1 with the backup path and the recovery: re-run the download while the application still reads `Loaded`, otherwise a full `flash --force`. Segments the application rewrites at run time (System 7 `checksum_ctrl` 0, the Jung `0x4916` region) are written but not compared. `--json` prints the plan as JSON (`parameters`, `regions`, `procedure`).

#### Parameter read-back

`plan <ADDRESS>` and `reconstruct <ADDRESS>` read the parameter memory too when they have the device's product file (`--product`, or the cached archive for the model's order number). The memory is located through the application's load procedure (System B: `PID_TABLE_REFERENCE` of the object plus the write offset; System 7: the `AbsSegment` addresses) and decoded as the exact inverse of the image `flash` writes: the same offsets, union members, module instances and parameter refs, so a device holding the model's image reports no difference. Only the parameters the configuration shows are decoded; a hidden parameter the application downloads at its default is never reported. The report lists the parameters whose value differs from the vendor default and those that differ from the model's `parameters:` block (`Threshold: device 9, model 12`), keyed like the model (`P-5_R-5`, `MD-1_M-2_MI-1_P-2_R-5` for a module instance); `--json` adds a `parameters` object with `non_default` and `differences`. Parameters the application owns at runtime (`Access="None"`, such as a download flag ETS writes and the application resets after the restart) are listed separately as device-managed, with no verdict (`device_managed` in `--json`). The memory is decoded only when the device runs the product's program, by the same rule `flash --parameters-only` applies: on System B the same manufacturer, application number and version (a product build with another hash counts as the same program); on System 7, which has no readable id, every load-state machine the procedure loads is `Loaded` and the code segments read back as the product's. Otherwise the section carries a note instead of decoded values. Both commands stay read-only.

### `bussard plan <ADDRESS>`

Show what `apply` would write, without writing anything: the same plan `apply` prints before it asks. With `--line`, plan every device the model has on that line instead. Read-only on the bus. Refuses to compute an empty table set for a device with no links in the model (that would wipe it). System B (`x7B0`) and System 7 (`0705` / `0701`); on System 7 the tables are read straight out of the `0x4000` / `0x4201` memory regions, bounded by the region size.

The plan speaks the device file's words, grouped by channel:

```
1.1.47 Jalousieaktor Kind 2
  channel a-1 (Fenster Süd)
    + langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)
    ~ status-position sends 0/1/4, was 0/1/9
    ~ betriebsart = Jalousie, was Rollladen
  unchanged: 3 objects, 41 parameters
  writes: address table (4 entries), association table (5 entries), 1 parameter octet
  backup: knx/captures/backups (tables) and knx/captures/backups/parameters (parameter memory)
```

`+` is a link the device gains (`now listens on`, or `now sends` for the object's sending address), `~` a sending address or a parameter that takes another value, `-` an address only the device has (`no longer uses`). Parameters are compared when product data is at hand: the `.knxprod` in `<dir>/vendor/` for the device's order number (fetched by `import` and `adopt`), or `--product`; without it a `note:` says so. A device that already matches prints `<ia> matches the model; nothing to write`. `-v` adds the table-level detail (every object and address, the load operations, the full parameter read-back).

`--json` prints the same plan as data: `address`, `name`, `gateway`, `changes` (`mark`, `subject`, `channel`, `key`, `object`, `sentence`), `unchanged_objects`, `unchanged_parameters`, `writes` (`address_table`, `association_table`, `parameter_octets`), `backup_dir`, `notes`, `question`, and `state_hash`, the SHA-256 of the device state read (the raw tables, plus the parameter memory when it was read). `apply --plan <hash>` refuses when the device no longer hashes to it. The table detail (`additions`, `removals`, `unchanged`, the table counts, `load_steps`, `noop`) and the parameter read-back (`parameters`) are there too.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to plan for, e.g. `1.1.4`. Omit with `--line`. |
| `--line <LINE>` | | Plan every model device on this line, e.g. `1.1`, in address order (see [whole-line runs](#whole-line-runs)). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--product <FILE>` | cached archive | The product data to compare the parameter memory with (see [parameter read-back](#parameter-read-back)). Without it the archive in `<dir>/vendor/` whose catalogue carries the model's order number is used, when cached. |
| `--application <REF>` | the lock's program | The application program id to decode with. |
| `--keyring <FILE>` | | The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key, as for [`reconstruct`](#bussard-reconstruct-address). With `--line`, each device's key is looked up in it. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--json` | off | Emit the plan as JSON (above), with `state_hash`. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
| `--refresh-facts` | off | Ignore the stored [device facts](#bussardfacts) and read them from the device again. |

### `bussard apply <ADDRESS>`

Write the model to one device. `apply` is the one verb for everyday changes, links and parameters alike:

1. Validate the model. An error stops here with the diagnostics and nothing is written (warnings do not block). A group address the device files use but `groups.toml` does not define is declared there first.
2. Read the device's live tables and, when product data is at hand, its parameter memory, over one management session.
3. Print the [plan](#bussard-plan-address) and ask once: `apply these 3 changes to 1.1.47 through 192.168.1.74:3671? [y/N]`. An empty plan prints `1.1.47 matches the model; nothing to write` and asks nothing. `--yes` answers for a script; without a terminal and without `--yes` the write is refused. With `--plan <hash>` (the `state_hash` from `plan --json`), a device whose state no longer hashes to it is refused before the question.
4. Back up the pre-state tables to `<dir>/captures/backups/<ia>-<timestamp>.json` (the format `backup` and `restore` share) and, when parameters change, the parameter memory to `<dir>/captures/backups/parameters/`.
5. Write the minimum: the tables when a link changes, and only the parameter octets that differ (the [parameter-only download](#parameter-only-download): no unload, no segment allocation, then the load completes and the device restarts). Each is verified by reading it back.

A parameter change that shows or hides a com-object changes the group-object table, which a parameter download does not rewrite: `apply` refuses that device and names the full [`flash`](#bussard-flash-address) it needs. A device that runs another application than the product data describes gets its links written and its parameters left alone, with a note that a full `flash` is the way to change the application. `apply` prints a hint when no installation-wide `backup` run exists yet. Tables are rewritten wholesale, so re-running `apply` is idempotent.

On the wire: System B (`x7B0`) and System 7 (`0705` / `0701`). On System B each table is written into a segment the device allocates for it: StartLoading, `LdCtrlRelSegment`, read the placement from `PID_TABLE_REFERENCE`, memory-write the count word plus the elements, LoadCompleted. The `PID_TABLE` property array is never written, because real devices refuse it (see the finding in [testing-campaign.md](testing-campaign.md#findings)). On System 7 a link change drives only the two table load-state machines (Unload, StartLoading, allocate, 12-octet writes with read-back verify, TaskSegment, LoadCompleted): parameters are untouched and the device is not restarted, so a link change costs no downtime.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to program, e.g. `1.1.4`. Omit with `--line`. |
| `--line <LINE>` | | Apply to every model device on this line, e.g. `1.1`, in address order (see [whole-line runs](#whole-line-runs)). |
| `--resume` | off | Line mode only: continue the run recorded in `<dir>/captures/apply-line-<line>.json`, skipping the devices it finished. |
| `--json` | off | Line mode only: emit the summary as JSON. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the interactive confirmation (dangerous; for scripts). |
| `--plan <HASH>` | | Single-device mode: refuse unless the device state still hashes to this `state_hash` from `bussard plan --json`. |
| `--product <FILE>` | cached archive | Single-device mode: the product data to compare and write the parameter memory with. Default: the archive in `<dir>/vendor/` whose catalogue carries the device's order number. |
| `--application <REF>` | the lock's program | Single-device mode: the application program id to decode the parameters with. |
| `--keyring <FILE>` | | The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool key. Required for a security-activated device; the password comes from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--secure-sender <IA>` | off | Single-device mode, Data Secure: add this address (bussard's tunnel address) with sequence 0 to the security individual address table (PID 54) the security object is reprogrammed with, as for `flash`. Conflicts with `--line`. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |
| `--refresh-facts` | off | Ignore the stored [device facts](#bussardfacts) and read them from the device again. |

#### Whole-line runs

`plan --line` and `apply --line` visit the model's devices on one line in address order and end with one summary table: address, name, mask and status. The status is one of `changes: N` (plan), `applied: N` (apply), `unchanged`, `skipped: <reason>` or `failed: <reason>`. A device with an unsupported mask or no links in the model is skipped; a device that cannot be read or written fails. Neither stops the run.

`apply --line` asks one confirmation for the whole run, naming the resolved gateway and the device count, then does per device what `apply <ADDRESS>` does: plan, back up, write, verify. Each outcome is written to `<dir>/captures/apply-line-<line>.json` as it happens. After a tunnel drop, a killed process or Ctrl-C, `--resume` reads that file and skips the finished devices without any bus traffic; failed devices are retried. A run with no failures deletes the file. The exit code is non-zero if any device failed.

`--json` prints `{line, mode, gateway, devices: [{address, name, mask, system_type, status, changes, detail}], total, changed, unchanged, skipped, failed, state_file}`; `state_file` is set when the run left one behind.

### `bussard commission --line <LINE>`

Bench mode: commission the devices the model has on a line. It first checks which of them already answer at their address; those are reported as `present` and left alone. After one confirmation naming the gateway, it walks the rest in address order:

1. Prompts `press the programming button on <name> (<order number>)` and waits for exactly one device in programming mode, as `assign` does.
2. Reads that device's order number and compares it with the model's `product.order_number` (case and surrounding space ignored). A mismatch, or an unreadable order number while the model names one, is a hard stop for that device: nothing is written and the run moves on to the next device. A model device without an order number is assigned with a warning.
3. Writes the address, verifies it with a descriptor read, and clears programming mode.
4. With `--flash`, runs `flash` on the new address, selecting the application by the model's order number from `--product`, or from the first archive in `<dir>/vendor/` that carries it. With `--apply`, runs `apply`.
5. Prints a label line, e.g. `1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room`, and with `--labels` appends a row to the CSV.

The summary table lists each device as `commissioned`, `present` or `failed: <reason>`. The exit code is non-zero if any device failed.

| Flag | Default | Meaning |
|---|---|---|
| `--line <LINE>` | | The line to commission, e.g. `1.1`. |
| `--flash` | off | Also flash each device's application program. |
| `--apply` | off | Also apply the model's link tables. |
| `--labels <FILE>` | | Append one row per commissioned device, columns `address;name;order_number;floor;room` (header written when the file is new). |
| `--product <FILE>` | | The `.knxprod` to flash from (with `--flash`). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the confirmation (required without a TTY). |
| `--json` | off | Emit the summary as JSON; label lines then go to stderr and into each device's `label` field. |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool key for `--flash` and `--apply`. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

### `bussard status`

Show what has changed in the model since the last history snapshot, as plain sentences ("Rocker 1 on Hallway push button now switches Porch light (0/0/4)."). Nothing here has reached a device: `status` reads files only. Always exits 0. With no snapshot yet it says so and stops.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit the change set as JSON (`{"base": <snapshot id>, "changes": [...]}`). |
| `--raw` | off | Print the file-level diff instead of the sentences. |

### `bussard history`

List the snapshots under `<dir>/.bussard/history`, oldest first: number, id, the command and arguments that caused it, the gateway a bus write went to, and a one-line summary of what it changed. Deterministic apart from the timestamps.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit the list as JSON. |

### `bussard show <SNAPSHOT> [SNAPSHOT]`

Render what one snapshot changed (against the one before it), or the change between two snapshots. A snapshot is named by its id or by its number from `bussard history`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<SNAPSHOT>` | | The snapshot to show (id or number). |
| `[SNAPSHOT]` | | A second snapshot: show the change from the first to this one. |
| `--dir <DIR>` | `knx` | The model directory. |

### `bussard undo [SNAPSHOT]`

Restore the model files to a snapshot, print what that reverts, and point at `plan`/`apply`. **Files only**: devices keep their tables until a human pushes the restored model to them. Without an argument it restores the newest snapshot that differs from the working files. Snapshots are taken before each write, so that reverts exactly the last change, whether it was a model edit or a bus-only command like `apply`. The state before the undo is itself snapshotted, so a second `undo` reverts the first.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[SNAPSHOT]` | the newest one that differs from the working files | The snapshot to restore (id or number). |
| `--dir <DIR>` | `knx` | The model directory. |

### `bussard backup [ADDRESS...]`

Snapshot the installation before you change it. For every device in the model (or every model device on `--line`, or the addresses given), `backup` reads the address and association tables and writes one JSON file per device, in the same format `apply` uses for its pre-write backup. On System B it also reads the application segment, which holds the parameters: the base comes from `PID_TABLE_REFERENCE` and the length from `PID_MCB_TABLE`, so no product data is needed. System 7 reports no length for its parameter image, so its parameters are marked as not captured.

`manifest.json` lists every device the run considered, with its mask, system type, resident application id, order number, read time, parameter status and one of four statuses:

| Status | Meaning |
|---|---|
| `backed_up` | Tables (and, where possible, parameters) were written to a file. |
| `skipped` | The mask is outside System B / System 7; the reason is in `detail`. |
| `unreachable` | Nothing answered at the address. |
| `failed` | The device answered, but a read failed; the reason is in `detail`. |

`backup` sends only descriptor, authorize, property-read and memory-read APDUs, so it is safe on a live installation. It uses one bus connection, leased per device. Exit code 0 when no device failed, 1 otherwise.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS...]` | every model device | Back up only these devices. |
| `--line <LINE>` | | Back up only the model devices on this line, e.g. `1.1`. |
| `--out <DIR>` | `<dir>/captures/backups/<UTC timestamp>/` | Where to write the snapshot. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Print the manifest as JSON. |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool keys, as for `apply`. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

### `bussard restore <BACKUP_DIR> <ADDRESS>`

Write one device's backed-up link tables back. `restore` picks the newest `<ia>-<timestamp>.json` in `BACKUP_DIR` (a `backup` run, or `<dir>/captures/backups` for the files `apply` leaves) and runs the `apply` path with the backup as the desired state: plan, confirm, pre-write backup, write, verify. A backup restored onto a device that has not changed plans empty and writes nothing. Parameter memory in the backup is reported but not written; put parameters back with `flash`. The model is optional here: the tables come from the backup.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<BACKUP_DIR>` | | The backup directory. |
| `<ADDRESS>` | | The device to restore, e.g. `1.1.4`. |
| `--dir <DIR>` | `knx` | The model directory (connection defaults, backup location). |
| `--yes` | off | Skip the interactive confirmation. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool key. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

### `bussard replace <ADDRESS> --product <FILE>`

Put a new device of the same product in place of a dead one. The steps:

1. Check that nothing answers at `ADDRESS`. A device that still answers is refused unless `--force`.
2. Wait for the programming button and read the pressed device's order number, mask and application id. A mismatch with the model's device file (`product.order_number`, `product.mask`) is refused unless `--force`. A field the model states but the device does not report counts as a mismatch.
3. Ask once for confirmation, naming the gateway. Then assign the address (as `assign` does), flash the application with the model's parameters (as `flash` does; skipped with `--no-flash`), and apply the model's tables (as `apply` does).
4. Record `replaced: <RFC3339>` in the device file with a one-line edit; the rest of the file is kept as it is.

`replace` adds no write primitive of its own. If the flash or apply step fails, the address is already assigned; the error names the command to re-run.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The address of the device being replaced. |
| `--product <FILE>` | | The vendor `.knxprod` for the new device. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--yes` | off | Skip the confirmation (required without a TTY). |
| `--force` | off | Proceed although the old device answers or the identity does not match. |
| `--no-flash` | off | Leave the application image alone (a spare that already carries it). |
| `--bcu-key <HEX>` | free access | BCU key for the flash step. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--keyring <FILE>` / `--tool-key <HEX>` | | KNX Data Secure tool key. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | Skip the pre-flight check that no bus device answers at bussard's own source address. See [SAFETY.md](SAFETY.md#source-address-check). |

### `bussard validate`

Validate the YAML model and report diagnostics (see [the diagnostics table](#validation-diagnostics)). Exits non-zero on errors.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--format <FORMAT>` | `text` | `text` (rustc-style diagnostics) or `json` (a JSON array). |

### `bussard groups reserve "<FLOOR> <ROOM>" <FUNCTION>...`

Reserve the conventional group addresses for one room and append them to `groups.toml`, then print them. Each function gets the block of its trade (five addresses for a light, ten for a blind or a heating zone); every address is named `<Floor> <Room> <Function> <Role>` with its DPT, and the unused slots in the block stay free for growth. Running it again for a room and function that already have their block adds nothing, and existing addresses are never renumbered or renamed.

```
$ bussard groups reserve "EG Küche" light blind
reserved 9 group address(es) for EG Küche in knx/groups.toml (floor-trade-block scheme):
  1/1/0     1.001    EG Küche Light Switch
  1/1/3     1.001    EG Küche Light Switch status
  1/2/0     1.008    EG Küche Blind Move
  ...
```

The room is one argument, floor first: the first word is the floor, the rest the room. Functions: `light` (switch + feedback), `light-dim` (switch, dim, value, both feedbacks), `blind`, `heating`, `socket`.

The scheme is `[lint.groups] scheme` in `bussard.toml`. The first reservation in a project without one writes a `[lint]` table with the scheme, so every later reservation and `bussard validate` follow the same convention. There is no plan file; for several rooms at once, run the command once per room, or have an assistant call `knx_scaffold_groups` with the room list as JSON.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--scheme <SCHEME>` | `[lint.groups] scheme`, else `floor-trade-block` | `floor-trade-block` (main = floor, middle = trade) or `function-floor` (main = trade, middle = floor), for a project that has no scheme yet. Refused when it contradicts `bussard.toml`. |
| `--json` | off | Emit JSON (`room`, `scheme`, `file`, `added`, `lint_config_written`, `validation`) instead of the list. |

A group address that a device file uses but `groups.toml` does not define is declared there by `import`, `apply` and the MCP edit tools, named `<channel name or device name> <object function or key>` with the object's DPT, and reported (`added 0/1/3 "Fenster Süd Langzeitbetrieb" (DPT 1.008) to groups.toml, first used by 1.1.47 object 144`). `bussard validate` alone only warns (E001).

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

### `bussard doc`

Render the handover documentation folder the KNX guidelines prescribe, straight from the model (issue #97). Offline: it reads the model and, when present, the cached product models in `models/`, and never touches the bus.

| File | Contents |
|---|---|
| `index.md` | Links to everything below, including one entry per room sheet. |
| `devices.md` | Individual address, name, location, manufacturer, order number, application, mask, Secure status. |
| `groups.md` | Address, name, DPT, description, protected flag, senders and listeners (device and com-object names). |
| `rooms/<floor>-<room>.md` | Every device in the room with its channels, and one plain-language line per com object: `Rocker 1 switches Kitchen ceiling light (1/0/10); status from 1/0/12.` Unnamed items fall back to their addresses. Devices without a `location:` get no room sheet. |
| `connection.md` | Transport and gateway or multicast endpoint from `bussard.yaml`. Never credentials. |
| `changelog.md` | The last 50 commits touching the model directory, from `git log`. Empty when the directory is not a git repository or `git` is missing. |

The output is deterministic: two runs on the same model write identical bytes (no timestamps), so the folder can be committed and its diff reviewed after every change.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--out <DIR>` | `docs/installation` | Where to write the files. Existing files with the same names are overwritten; others are left alone. |
| `--format <FORMAT>` | `md` | `md` (Markdown) or `html` (one self-contained page per file, inline styles, no scripts). |
| `--json` | off | Print the structured document model to stdout instead of writing files. |

### `bussard monitor`

Live-monitor the bus, decoding telegrams against the model. Unknown GAs and DPTs degrade to raw hex, never a failure.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit JSON Lines (see [the telegram JSON contract](#telegram-json-contract)) instead of the pretty text format. |
| `--filter <EXPR>` | all | Only show matching telegrams (GAs, GA prefixes, IAs). |
| `--keyring <FILE>` | | An ETS `.knxkeys` export (password in `BUSSARD_KEYRING_PASSWORD`). Secured group telegrams (KNX Data Secure, `A_SecureData` with the tool-access bit clear) are verified and decrypted with the group key of their destination GA and decoded like plain ones, marked `[secured]`. A MAC failure shows `[secured (MAC failed) seq=… raw=…]`, a GA without a key `[secured (no group key) …]`. A sequence number that does not increase per sender adds a warning; nothing is dropped. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard capture --to <DB>`

Capture telegrams to a SQLite database (see [the capture database](#the-capture-database)).

| Flag | Default | Meaning |
|---|---|---|
| `--to <DB>` | required | The database file to write (created if absent). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--filter <EXPR>` | all | Only capture matching telegrams. |
| `--keyring <FILE>` | | As for `monitor`: secured group telegrams are decrypted into the decoded snapshot, which carries the `secured` fields. The raw cEMI keeps the secured bytes. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

### `bussard read <GA>`

Read a group value from the bus: send a GroupValueRead, print the typed response. Exits non-zero when no response arrives within 3 seconds.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to read, e.g. `3/2/0`. |
| `--dir <DIR>` | `knx` | The model directory. |
| `--keyring <FILE>` | | Group keys for secured GAs (password in `BUSSARD_KEYRING_PASSWORD`). A GA with a key, or `secure: true` in `groups.yaml`, is read with a secured GroupValueRead, and only a response whose MAC verifies under the group key is accepted; stderr says `secured: …`. A secured GA without a key is refused before anything is sent. |
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
| `--keyring <FILE>` | | Group keys for secured GAs. A GA with a key, or `secure: true` in `groups.yaml`, is written as a secured group telegram (SCF `0x10`, the group key, a sequence above the last one sent); a secured GA without a key is refused. A plain GA is sent byte for byte as without a keyring. A receiver accepts it only if bussard's tunnel address is in its security individual address table (PID 54): program the device with `flash`/`apply --keyring --secure-sender <tunnel IA>`, otherwise it drops the telegram silently. After a secured write bussard prints a note naming its tunnel address and the receivers the model links to the GA, because it does not record which devices got `--secure-sender`. See [SAFETY.md](SAFETY.md#secured-group-writes-from-bussard). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--allow-remote-gateway` | off | Permit a write to a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |

### `bussard learn`

Name and type group addresses from live traffic. Learn mode prompts you to trigger an object, waits for the telegram, and shows the sender, its channel and com object, the payload, ranked DPT candidates with a reason for each, and a proposed name built from the device's room, channel and com-object function. Accept, edit the name, change the DPT, skip, or quit. Accepted answers go into `groups.yaml`; when the sending com object can be pinned down (an existing link, or exactly one free transmit-capable object on the sending device), `links.yaml` gets the `send:` entry too.

Learn mode never transmits. It listens on the same connection `monitor` uses and never calls a send path. A DPT candidate is ranked `high` only when the sending com object declares that DPT in the model; payload shape alone gives `medium` at most, because most payload lengths fit several DPTs. Repeated telegrams on one GA narrow the candidates.

| Flag | Default | Meaning |
|---|---|---|
| `--ga <GA>` | | Learn this group address. Repeatable; learned in the order given. |
| `--unnamed` | off | Learn every GA in the model whose name is a placeholder (empty, the address itself, `GA <address>`, `Unnamed`, `Unknown...`). |
| `--untyped` | off | Learn every GA in the model with no DPT (the ones `validate` reports as W011). |
| `--yes` | off | Accept the top candidate and the proposed name without prompting. Required without a terminal. |
| `--timeout <SECS>` | `30` | How long to wait for each telegram. |
| `--dir <DIR>` | `knx` | The model directory. A model that fails to parse is a hard error. |
| `--keyring <FILE>` | `connection.keyring` | ETS `.knxkeys` keyring whose group keys decrypt secured group telegrams. The password comes from `BUSSARD_KEYRING_PASSWORD`. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |

With neither `--ga` nor `--unnamed`/`--untyped`, learn takes whatever appears on the bus next, one GA at a time, until a wait times out or you quit.

Secured group telegrams (KNX Data Secure, issue #204) go through the same decode path as `monitor --keyring`. With a keyring, learn verifies the MAC under the GA's group key and decrypts the inner APDU, and the inference runs on that value. The observation says `secured`, the stdout line ends in `, secured)`, and the learned group gets `secure = true` in `groups.toml`, so `read`, `write`, `flash` and `apply` treat it as secured. A sequence number that does not increase over the sender's last one prints the same advisory warning `monitor` shows. A secured telegram that cannot be verified (no keyring, no group key for the GA, a MAC failure) is reported and skipped; learn never guesses a DPT from ciphertext. Decryption is local, so learn still never transmits.

### `bussard test`

Run the acceptance tests in [`tests.yaml`](#testsyaml) against the bus and print a pass/fail report. Each test writes a group value (or prints a `manual:` instruction and waits for Enter), then waits for the expected telegram. A failing expectation reports the value that did arrive on the expected GA. The text report contains no timestamps, so two runs over a healthy installation are byte-identical; the JSON report adds only `started_at`. Exits non-zero when any test fails; skipped and refused tests do not fail the run.

A test run writes to the bus, so it goes through the same rails as `bussard write`: the non-loopback gateway gate and a confirmation naming the gateway. A test that writes to a `protected: true` GA needs both `allow_protected: true` in the file and `--force`; with either missing it is reported as refused and nothing is sent to that GA.

| Flag | Default | Meaning |
|---|---|---|
| `--file <FILE>` | `<dir>/tests.yaml` | The test file to run. |
| `--json` | off | Print the report as JSON: `started_at`, `tests[]` (`name`, `status` of `pass`/`fail`/`skipped`/`refused`, `detail`, `observed`), and `summary` counts. |
| `--force` | off | Together with `allow_protected: true` in the file, permit tests that write to protected GAs. |
| `--skip-manual` | off | Report `manual:` tests as skipped instead of prompting. Without a terminal they are skipped anyway. |
| `--only <NAME>` | all | Run only the named test (case-insensitive). Repeatable. |
| `--yes` | off | Skip the confirmation prompt (required for a non-TTY run). |
| `--dir <DIR>` | `knx` | The model directory. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--allow-remote-gateway` | off | Permit a run against a non-loopback gateway (or set `BUSSARD_ALLOW_REAL_GATEWAY=1`). |
| `--secure-idle <SECS>` | | Instead of running `tests.yaml`: measure the KNXnet/IP Secure session idle timeout (issue #197). See below. |

**`--secure-idle <SECS>`** opens a KNXnet/IP Secure session with the interface (credentials from `connection.keyring`, or `--secure-user`/`--secure-password-env`), sends nothing for `SECS` seconds (no keepalive, no heartbeat, no tunnel), then sends one wrapped CONNECTIONSTATE_REQUEST for a channel it does not hold and prints one line: `ALIVE` (the interface answered), `DROPPED after <t> s (<reason>)` (it sent a SESSION_STATUS or closed the TCP connection) or `SILENT` (no answer). `--json` prints the same as an object (`outcome`, `after_ms`, `reason`, `answered_ms`, `transport`, `user_id`). It is read-only: no CONNECT, so no tunnel slot, and nothing reaches the bus, which is why it needs neither `--yes` nor `--allow-remote-gateway`. Run it with growing `SECS` (say 45, 65, 90, 125) to bracket the interface's timeout; `--secure-transport` picks the carrier.

### `bussard ha-config`

Generate the Home Assistant KNX integration YAML from the model. Derivation rules and the `ha.yaml` override file are documented in [ha-config.md](ha-config.md).

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--out <FILE>` | stdout | Output file. |

### `bussard audit`

Report what the installation holds and what bussard can do with it. Read-only. The static part reads only the model; `--live` adds a read-tier look at the gateway and the bus. Exits 0 on a completed audit.

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory. |
| `--json` | off | Emit one JSON object instead of the sectioned text report. The same object the `knx_audit` MCP tool returns. |
| `--live` | off | Add the live part: gateway description, traffic sample, scan of the modelled devices. |
| `--window <SECS>` | `30` | Traffic-sample window for `--live`. |
| `--keyring <FILE>` | `connection.keyring` | An ETS `.knxkeys` keyring; each Secure device is reported with or without a tool-key entry, and with `--live` probed over KNX Data Secure with its tool key. Password from `BUSSARD_KEYRING_PASSWORD`. No key material is printed. |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--skip-address-check` | off | With `--live`, skip the check that no bus device answers at bussard's own source address before the scan. See [SAFETY.md](SAFETY.md#source-address-check). |

Static sections (JSON keys in brackets):

- **Model** (`model`): device count per line, devices without a name or a location, GAs without a DPT or a name (including GAs that exist only in `links.yaml`), links to com-objects the device file does not declare, links for addresses with no device file, protected GAs, project name and import source.
- **Findings** (`model.findings`): one-sided links only, a GA with senders but no listener or listeners but no sender. Unlinked com-objects and unused GAs are counted in `model.info` as neutral information. The viz Problems panel renders this same analysis.
- **Devices per mask** (`masks`): devices grouped by the `product.mask` their file records, with what bussard can do (`plan_apply`, `flash`, `reconstruct`, `describe`). The column comes from the same table the `plan`, `apply`, `flash` and `reconstruct` refusals use ([SAFETY.md](SAFETY.md#supported-device-masks)).
- **KNX Secure** (`secure`): Secure-capable and activated devices, and with `--keyring` whether the keyring holds each one's tool key.

Live sections (`live`, with `--live`):

- **Gateway** (`live.gateway`): name, individual address and `N tunnels, M in use` from the interface's description. A full interface stops the audit with exit code `4`.
- **Traffic sample** (`live.traffic`): group telegrams seen during `--window`, per GA with its repetition rate (frames marked repeated in the cEMI control field, or identical telegrams from the same source within 500 ms), GAs sent on the bus that have no listener in the model, and source addresses the model does not know.
- **Scan delta** (`live.scan`): every modelled device probed with the `scan` machinery, one at a time and at most one probe per 250 ms, per line: which answered (with a mask mismatch against the model flagged) and which did not. Only modelled addresses are probed; unexpected devices show up as unknown traffic sources, or run `bussard scan`. A Data Secure device's row carries `secure` (its `live.secure` status) and the real mask when the secured probe read it; a hidden `FFFF` mask is never flagged as a mismatch.
- **KNX Secure (live)** (`live.secure`, issue #203): every Data Secure device (one that answers the plain probe with mask `FFFF`, has a `security:` block in the model, or is in the keyring) with `activated`, `reachable_secured` (the secured probe with the keyring's tool key answered; `null` when none ran), `plain_reads_refused` (the plain descriptor read returned `FFFF`), `in_keyring` (`null` without `--keyring`), the real `mask`, and one `status`: `reachable_secured`, `key_refused`, `not_in_keyring`, `plain_reads_refused` (no keyring given), `plain`, or `not_answering`. The secured probe runs like `describe --keyring`: S-A_Sync, then the descriptor and device-object property reads inside `A_SecureData`.

The live part sends only management reads (device descriptor, authorize, device-object properties) to individual addresses and never a group telegram.

### `bussard mcp`

Run the MCP server over stdio (see [the MCP server](#the-mcp-server)).

| Flag | Default | Meaning |
|---|---|---|
| `--dir <DIR>` | `knx` | The model directory (required for the server). |
| `--gateway <HOST>` | | Gateway override. |
| `--routing` | off | Force routing transport. |
| `--passive` | off | Never transmit on the bus; omits the `knx_read_group` tool. |
| `--allow-writes` | off | Register the `knx_write_group` tool. Mutually exclusive with `--passive`. |
| `--allow-programming` | off | Register the programming tier, `knx_plan_device` and `knx_apply_device` (see [the programming tier](#the-programming-tier)). Mutually exclusive with `--passive`. |
| `--plan-ttl-minutes <MINUTES>` | `10` | How long a `knx_plan_device` digest stays valid for `knx_apply_device`. Needs `--allow-programming`. |
| `--allow-remote-gateway` | off | Permit `--allow-writes` or `--allow-programming` against a non-loopback (real) gateway. The same gate as `bussard write`; without it (or `BUSSARD_ALLOW_REAL_GATEWAY=1`) such a server pointed at a real gateway refuses to start. |
| `--no-model-edits` | off | Withhold the model-edit tools (`knx_set_group`, `knx_add_link`, `knx_remove_link`, `knx_set_device`, `knx_set_parameter`, `knx_undo`, `knx_scaffold_groups`, `knx_reserve_groups`). They write the model's TOML files behind a history snapshot and never touch the bus, so they are registered by default. |
| `--capture-db <PATH>` | | A `bussard capture` database to extend `knx_recent_telegrams` history beyond the in-memory ring. |
| `--keyring <FILE>` | `connection.keyring` | ETS keyring export (`.knxkeys`) for KNX Data Secure management: `knx_describe_device` and `knx_plan_device` wrap their session with the target's tool key, as `bussard describe --keyring` and `bussard plan --keyring` do. Both read a device the keyring does not list in the clear, through the secure tunnel the keyring opens, unless the model marks it `security.activated` (then they refuse, issue #189); `knx_apply_device` refuses a device the keyring lists, since that write also reprograms the security object (use `bussard apply --keyring`). Its group keys also secure `knx_read_group` and `knx_write_group` on a secured GA (issue #172; the results carry `secured`), and decrypt secured telegrams re-decoded from `--capture`; a secured GA without a key is refused. The password comes from `BUSSARD_KEYRING_PASSWORD`. |

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
| `--keyring <FILE>` | | Group keys (password in `BUSSARD_KEYRING_PASSWORD`): `POST /api/group-write` to a secured GA is sent as a secured group telegram (a secured GA without a key answers 400), and secured telegrams in the live traffic are decrypted and carry the `secured` fields. |
| `--allow-host <HOST>` | | Also answer requests whose `Host` header is this name (repeatable). Loopback names and bare IP literals are always accepted; any other name is refused, because that is how DNS rebinding reaches this port. |

## Environment variables

| Variable | Meaning |
|---|---|
| `BUSSARD_PROJECT_PASSWORD` | Password for a protected `.knxproj` when `--password` is not given. Keep it in an untracked `.env`, never in the repo. |
| `BUSSARD_KEYRING_PASSWORD` | Password for a `.knxkeys` keyring read by `bussard keyring`, passed with `--keyring`, or named by `connection.keyring` in `bussard.yaml`. There is deliberately no flag for it, so it never lands in shell history or a process listing. |
| *(the `--secure-password-env` variable)* | The KNXnet/IP Secure tunnelling user's password for `--secure-user`. You choose the variable's name; bussard reads only that variable. |
| `BUSSARD_ALLOW_REAL_GATEWAY` | Set to `1` to permit a write command against a non-loopback (real) gateway, equivalent to `--allow-remote-gateway`. Loopback gateways never need it. |
| `RUST_LOG` | Log filter (e.g. `debug`, `bussard_transport=trace`). Overrides `-v`/`--verbose` when set. |
| `BUSSARD_ADOPT_ADDRESS` | The target address for `adopt`, for driving the wizard from a script or test (together with `--product`). |
| `BUSSARD_ASSIGN_WAIT_MS` | Test knob: shrinks the programming-mode wait budget of `assign` and `adopt`. Unset in normal use. |
| `BUSSARD_SCAN_DISCOVERY_MS` | Test knob: shrinks the per-address probe timeout of `scan` and `reconstruct --line`. Unset in normal use. |
| `BUSSARD_ADDRESS_PROBE_MS` | Test knob: shrinks the per-attempt timeout of the source-address check (default 600 ms). Unset in normal use. |
| `BUSSARD_WIRE_TRACE` | Set to `1` to log every cEMI frame as hex on stderr, one `[wire] <UTC time, ms> TX >>`/`RX <<` line each, so per-frame timing can be read off the log. The diagnostic of last resort when a gateway behaves unexpectedly; very noisy. |
| `BUSSARD_SECURE_KEEPALIVE_SECS` | The KNXnet/IP Secure session keepalive interval in seconds (default `30`; `0` sends none). A wrapped SESSION_STATUS `STATUS_KEEPALIVE` goes out this often. The default is inferred from the KNX specification's 60 s session timeout; `bussard test --secure-idle` measures the real one. |
| `BUSSARD_TCP_READ_DEADLINE_MS` | The read deadline of a KNXnet/IP Secure (TCP) tunnel in milliseconds (default `5000`; `0` turns it off). After this long without any frame from the interface the tunnel sends a CONNECTIONSTATE_REQUEST; no answer within the shorter of the deadline and 2 s counts as a lost link and starts the re-establish. The plain UDP tunnel ignores it: its ACK timeout detects a loss within about 2 s. |
| `BUSSARD_TUNNEL_RECONNECT_SECS` | How long, in seconds, a lost gateway tunnel is re-established before the pending bus operation fails (default `60`; `0` turns it off). While it runs, the log says `gateway connection lost` and later `gateway connection re-established`, and the progress display shows it as the last event. See [SAFETY.md](SAFETY.md). |
| `BUSSARD_FLASH_L4_TIMEOUT_MS` | Flash knob: the per-exchange Layer 4 timeout. Raise it for a slow device or a lossy link. |
| `BUSSARD_FLASH_REBOOT_WAIT_MS` | Flash knob: the upper bound on the readiness poll after a restart (default 10 s, 30 s for a Data Secure device). The poll probes every 500 ms: from 0.5 s after the process time of a restart the device confirmed, from 1.5 s after a bare `A_Restart`. |
| `BUSSARD_SPARSE_MERGE_GAP` | Flash knob: the largest gap, in octets, the sparse writer writes through to join two runs of a System B image (default `100`; `0` joins nothing). A gap is only joined when the joined run needs fewer memory-write requests than the two runs apart, and the octets written into it are the ones the device already holds (the segment's fill, or the read-back memory on a parameters-only download), so the device image is the same either way. The default sits under the ~115-octet break-even of a 200 ms request at 1.7 ms per octet (issue #210). System 7 parameter downloads keep a 4-octet gap. |
| `BUSSARD_FLASH_RECONNECT_EXCHANGES` | Flash knob: cycle the L4 connection (disconnect, reconnect, re-authorize) once this many numbered exchanges have run on it, checked between steps. Unset: 10 for a KNX Virtual device (manufacturer `0x00FA`), off for every other device, which keeps one connection like ETS. `0` turns cycling off everywhere. |

Test-harness variables (`BUSSARD_VIRTUAL_DEVICE*`, `BUSSARD_TEST_MULTICAST`, `BUSSARD_PRODUCT_CORPUS`) gate the integration test suites, never the CLI; they are documented in the `tests-support/` READMEs.

## The model directory

```
knx/
  bussard.yaml      # connection config
  groups.yaml       # the group-address plan
  links.yaml        # com-object → GA assignments
  devices/          # one file per device, e.g. 1.1.4-jalousieaktor-wohnen.yaml
  ha.yaml           # optional ha-config overrides (see ha-config.md)
  tests.yaml        # optional acceptance tests for `bussard test`
  models/           # generated from .knxprod; git-ignored
  vendor/           # cached .knxprod originals; git-ignored
  captures/         # local captures, apply backups and apply-line-<line>.json resume state; git-ignored
  .bussard/         # bussard's own history, device facts and last_export.json; git-ignored
```

#### `.bussard/history`

bussard keeps its own history so undo works without git:

```
knx/.bussard/history/20260922T101112Z-001/
  manifest.json     # {"reason": {"command", "args"}, "gateway", "result", "bussard_version", "created_at"}
  bussard.yaml
  groups.yaml
  links.yaml
  devices/*.yaml
```

One directory per snapshot, named by a UTC timestamp plus a sequence number, so a listing is already a timeline. A snapshot is a full copy of the four model inputs, since a house model is well under a megabyte. Nothing else is ever copied: `models/`, `vendor/`, `captures/`, keyrings, `.knxproj` and `.knxprod` files stay out (see [product-data.md](product-data.md)).

`import`, `apply`, `flash`, `adopt`, `reconstruct` and every MCP model edit snapshot before they write. `plan` and those commands also record an `external edit` snapshot first when the working files differ from the last one, so an edit made in an editor or by an assistant writing YAML is never lost. `bussard status`, `history`, `show` and `undo` read this directory; `bussard init` git-ignores it.

#### `.bussard/facts`

What bussard reads off a device that does not change while the device keeps its application: the mask, `PID_MAX_APDU_LENGTH`, the interface-object table, the property descriptions (once `describe` has walked them) and how the device answered `A_Authorize`. One generated file per device, written by the first `describe`, `reconstruct`, `plan`, `apply` or `flash` that reads it:

```toml
# This file is @generated by bussard from reads of the device (issue #209). Do not edit it by hand.
[device_facts]
address = "1.1.12"
read_at = "2026-09-25T10:11:12Z"
mask = "07B0"
application_object = 3
application_id = "0004D14221"
max_apdu = 233
authorize = "granted"
object_table_source = "io_list"

[[device_facts.objects]]
index = 0
object_type = 0

[[device_facts.objects.properties]]
index = 1
pid = 1
pdt = 4
writable = false
max_elements = 1
read_level = 3
write_level = 0

[[device_facts.objects]]
index = 1
object_type = 1
```

Every bus command that uses the facts first reads the device descriptor and the application id (`PID_PROGRAM_VERSION` of `application_object`). When both equal the stored `mask` and `application_id`, the command skips the `PID_OBJECT_TYPE` walk (one read per object) and the `PID_MAX_APDU_LENGTH` read; otherwise it reads the facts again and replaces the file. `--refresh-facts` forces the re-read, and deleting the file has the same effect. A file that does not parse is ignored with a warning and rewritten. The object table is read from `PID_IO_LIST` (device object, PID 71) in one or a few multi-element reads when a System B device offers it and the list agrees with `PID_OBJECT_TYPE` at the last object, the first application object and the index after the last; any refusal, short answer, timeout or disagreement falls back to the walk (`object_table_source = "walk"`).

`authorize = "unsupported"` lets the read-only commands (`describe`, `plan`, `reconstruct`) skip `A_Authorize_Request`, which such a device leaves unanswered for the full response timeout. `apply` and `flash` always present it. The written frames of `apply` and `flash` do not change; only reads are skipped.

The facts live here, not in `devices/*.toml` or `bussard.lock`, because an ETS re-import rewrites those and never touches `.bussard/`, because the device files hold intent to review while the facts are observations, and because the lock is written by `import` and `adopt` only and is covered by snapshots and the model fingerprint, which a read-only bus command must not change. They are not part of a [bundle](#the-bundle-format). Without a model directory no facts are stored and every command reads the device as before.

`bussard.yaml`, `groups.yaml`, `links.yaml`, `devices/` and `tests.yaml` belong in git; the first four are the source of truth. `models/`, `vendor/` and `captures/` are local-only; `init` and `import-product` plant the `.gitignore` entries. All YAML is parsed strictly: unknown fields and duplicate keys are errors. Emission is deterministic and sorted, so re-imports and hand edits produce minimal diffs. Every generated file carries a banner naming what generated it and what is hand-editable.

### The bundle format

A `.bussard` file is a zip archive:

```
manifest.json                      # always the first entry
bussard.yaml
groups.yaml
links.yaml
devices/*.yaml
.bussard/history/<id>/...          # unless exported with --no-history
```

Entries are sorted, with a fixed timestamp and permissions, so two exports of the same files differ only in the manifest's `exported_at`. The manifest:

| Field | Meaning |
|---|---|
| `format`, `format_version` | `"bussard-bundle"`, `1`. |
| `model_version` | The YAML model schema version, `1`. A reader refuses a newer one. |
| `bussard_version` | The bussard that wrote the bundle. |
| `exported_at` | RFC3339 in UTC. |
| `project` | The project name from `groups.yaml`, when set. |
| `devices`, `group_addresses`, `links`, `history_snapshots` | Counts. |
| `files` | The SHA-256 of each model file, by path. |
| `model_sha256` | SHA-256 over the lines `<file sha256>  <path>\n`, sorted by path (the `sha256sum` output format). |
| `excluded` | What a bundle never contains (below). |

A bundle never contains `models/`, `vendor/`, `captures/`, keyrings, `.knxproj` or `.knxprod` files, or `.env`: the export copies an allow-list of model files and nothing else. A reader rejects any entry outside the layout above, any model file whose hash does not match, and any entry larger than 64 MiB.

### `bussard.yaml`

```yaml
connection:
  transport: tunnel          # tunnel | routing
  gateway: "192.0.2.10:3671"   # host:port for tunneling (optional)
  multicast: "224.0.23.12:3671"  # addr:port for routing (optional; this is the default)
  keyring: ../secrets/site.knxkeys  # default for --keyring (optional; relative to this directory)
```

| Field | Type | Meaning |
|---|---|---|
| `connection.transport` | `tunnel` \| `routing` | The transport used to reach the bus. |
| `connection.gateway` | string, optional | Gateway `host:port` for tunneling. |
| `connection.multicast` | string, optional | Multicast `addr:port` for routing; defaults to `224.0.23.12:3671`. |
| `connection.keyring` | path, optional | The ETS `.knxkeys` keyring every bus command uses when `--keyring` is not given: for the [KNXnet/IP Secure tunnel](#knxnetip-secure-tunnelling), the tool keys of the devices it lists, and the group keys. A relative path is resolved against the model directory. `--keyring` overrides it. The password comes from `BUSSARD_KEYRING_PASSWORD`. Keep the keyring file itself out of git. |

An optional `lint:` block turns on the topology and convention rules (`L001`-`L008` in [the diagnostics table](#validation-diagnostics)). Without it nothing extra is reported, so adding the feature cannot change an existing project. `bussard groups reserve` writes the block for you.

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
| `groups.<ga>.secure` | bool, default `false` | ETS runs the GA with KNX Data Secure: the project stores a group key for it (the `Key` attribute of its `GroupAddress`, or `Security="On"`). Imported from the project and replaced on re-import; the key itself lives only in the `.knxkeys` keyring. A secured `flash`/`apply` refuses when the keyring has no key for a linked `secure` GA. Serialized only when `true`. |

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
replaced: 2026-09-22T10:15:00Z   # written by `bussard replace`; absent otherwise
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
  14: { dpt: "9.001", flags: "CRT", secure: true }   # Data Secure group object
security:                    # only for a Data-Secure-capable device
  secure_capable: true
  activated: true
  secure_commissioning: true
  sequence_number: 275080325586
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
| `com_objects.<n>.secure` | bool, generated, default `false` | The group object communicates with KNX Data Secure: its ETS `Security` setting is `On`, or `Auto` (the default, also when the attribute is absent) with a `secure` GA linked. A secured download writes flag `0x03` for it into the security object's `PID_GO_SECURITY_FLAGS`; a linked GA with a keyring key flags the object too. Serialized only when `true`. |
| `security.secure_capable` | bool, generated | The application can run KNX Data Secure (`IsSecureEnabled`). Capability, not activation. |
| `security.activated` | bool, generated | ETS has loaded the device's tool key (`LoadedToolKey` in the device's `<Security>` element): all management access must use `--keyring`. A sequence number alone is not this signal. |
| `security.secure_commissioning` | bool, generated | Secure commissioning is enabled in the project (`ToolKey` present), whether or not ETS has downloaded it yet. |
| `security.has_fdsk_certificate` | bool, generated | The project holds the device's factory certificate (FDSK). Presence only. |
| `security.sequence_number` | number, generated | The Data Secure sequence number ETS last recorded for the device. |

The `security:` block never carries key material: tool keys, group keys and the FDSK stay in the keyring.

Com-object entries carry no `name` (it lives in `links.yaml`).

### `tests.yaml`

The acceptance tests `bussard test` and the `knx_run_tests` MCP tool run. Optional; parsed as strictly as the rest of the model.

```yaml
allow_protected: false      # opt-in for tests that write protected GAs (also needs --force)
tests:
  - name: Kitchen ceiling light switches and reports
    write: { ga: "1/0/10", value: "on" }
    expect: { ga: "1/0/12", value: "on", within: 2s }
  - name: Wind alarm raises the blinds
    manual: "Trigger the wind alarm on the weather station"
    expect: { ga: "3/1/0", value: "up", within: 5s }
```

| Field | Type | Meaning |
|---|---|---|
| `allow_protected` | bool, default `false` | Half of the opt-in for writing a `protected: true` GA. The CLI also needs `--force`; the MCP tool ignores this flag and always refuses. |
| `tests[].name` | string | Reported name, and the key for `--only`. |
| `tests[].write` | `{ga, value, dpt?}` | The stimulus: a group write. `value` is human-typed and encoded against the GA's DPT, or `dpt` when given. |
| `tests[].manual` | string | The stimulus instead of a write: an instruction for a human. Exactly one of `write` or `manual`. |
| `tests[].expect.ga` | GA | The group address the proof must appear on. |
| `tests[].expect.value` | scalar, optional | The value it must carry, encoded against the GA's DPT and compared byte for byte. Omit to accept any value. On a GA without a DPT, give the payload as hex (`"0x01"`). |
| `tests[].expect.within` | duration, default `3s` | How long to wait: `2s`, `500ms`, `1m`, or a bare number of seconds. |

A manual test must have an `expect`. The runner ignores the gateway's echo of its own write and anything sent from its own address, so a test may write and expect the same GA.

### Generated model files (`models/*.yaml`)

One file per application program, generated by `import-product` and never hand-edited. The field-by-field description lives in [product-data.md](product-data.md#the-model-file-format).

## Validation diagnostics

`validate` (and the `knx_validate` MCP tool) run strict parsing, then these rule passes:

| Code | Rule | Severity |
|---|---|---|
| E001 | link references a GA not defined in `groups.yaml` | error |
| E002 | device file name does not start with its `address:` | error |
| E003 | link references a com object the device doesn't have (a warning when the device has no com-object table at all, because nothing can be checked without product data) | error |
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

With `--keyring`, a KNX Data Secure group telegram adds five fields (plain telegrams carry none of them, so their records are unchanged):

| Field | Meaning |
|---|---|
| `secured` | `true` when the MAC verified under the GA's group key (the other fields then describe the decrypted inner telegram), `false` otherwise. |
| `secure_status` | `ok`, `mac_failed` or `no_key` (the keyring has no key for the GA). |
| `secure_seq` | The sender's sequence number. |
| `secure_raw` | The raw `A_SecureData` ASDU, hex, when it did not verify; else `null`. |
| `secure_warning` | An advisory freshness warning (the sequence did not increase over the last one from this sender), else `null`. |

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

`bussard mcp` serves the Model Context Protocol over stdio. Four tiers:

| Tier | Flag | On the bus |
|---|---|---|
| Passive | `--passive` | Never transmits. The bus-touching read tools (`knx_read_group`, `knx_describe_device`) are not registered, and `knx_audit` refuses `live: true`. |
| Read (default) | none | May send GroupValueReads, rate-limited. |
| Write | `--allow-writes` | Adds `knx_write_group` and `knx_run_tests`. |
| Programming | `--allow-programming` | Adds `knx_plan_device` and `knx_apply_device`, which write one device's link tables after a plan the human approved. Needs a loopback gateway or the real-gateway opt-in. Independent of `--allow-writes`; not available with `--passive`. |
| No model edits | `--no-model-edits` | Withholds the six model-edit tools, `knx_scaffold_groups` and `knx_reserve_groups`. Orthogonal to the tiers above: they write the model's TOML files, never the bus, so they are registered in every tier by default. |

The model tools (`knx_describe_change`, `knx_history`, the six that edit, `knx_scaffold_groups` and `knx_reserve_groups`) touch files under the model directory and nothing else. `knx_export_bundle` and `knx_diff_project` only read the model (the export writes one bundle file) and are registered in every tier, `--no-model-edits` included. Every edit snapshots the model first, validates after, and returns the change as sentences for the caller to quote to the human. Nothing reaches a device until a human runs `bussard plan` and `bussard apply`, or approves a plan in the conversation on a server started with `--allow-programming`.

Tool counts: 20 in `--passive`, 22 by default, 24 with `--allow-writes`. `--no-model-edits` takes seven away from each (13, 15 and 17). `--allow-programming` adds two to any non-passive tier.

Bus operations share one rate limiter (minimum 250 ms between operations, at most two in flight). A GA marked `protected: true` is hard-refused by `knx_write_group` and `knx_run_tests` with no MCP override; the LLM must ask a human, who can run `bussard write ... --force` from the CLI. Download (`flash`) and batch programming (`apply --line`) are CLI-only. Single-device table programming is exposed only through the programming tier below.

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
| `knx_audit` | `live` (default false), `window_seconds` (default 30, max 3600) | The `bussard audit --json` object. The server's `--keyring` (password in `BUSSARD_KEYRING_PASSWORD` of the server's environment) fills the static keyring check. With `live: true` it adds the gateway description with tunnel slots, a traffic sample taken from the server's telegram buffer, and `live.secure`: the model's Data Secure devices probed as `bussard audit --live` probes them, with the same fields. `live.scan` is `null` (line scans are CLI-only). `live: true` is refused in `--passive` mode; the static audit is always available. |
| `knx_scaffold_groups` | `plan` (JSON `{rooms: [{floor, room, functions}]}`), `scheme` (optional) | Writes `groups.toml` from a room and function list, returns the addresses added and the model's validation counts. Confirm the room list with the human first. |
| `knx_reserve_groups` | `room` (`"<Floor> <Room>"`), `functions` | The same for one room, as `bussard groups reserve` does it, under the project's scheme. |
| `knx_read_group` | `ga` | Transmits a GroupValueRead and returns the decoded response. Omitted in `--passive` mode. |
| `knx_describe_device` | `address` | Introspects a device: enumerates its interface objects and each property's description (PID, type, element count, access levels). Read-only on the bus. With `--keyring`, a KNX Data Secure device is addressed with its tool key. Omitted in `--passive` mode. |
| `knx_infer_group` | `ga`, `payload_hex` (optional) | What the traffic on a GA says it is: ranked DPT candidates (`dpt`, `confidence` of `low`/`medium`/`high`, `reason`), the sender (address, name, location), its channel and com object (index, name, declared DPT, flags), the GA's current model entry, a proposed name, and a `next_step` telling the assistant to confirm with the human before calling `knx_set_group` and `knx_add_link`. Uses every telegram seen on the GA, or `payload_hex` when given. Reads only; also registered in `--passive`. |
| `knx_write_group` | `ga`, `value` (human-typed), `dpt` (optional override) | A GroupValueWrite. Registered only with `--allow-writes`; refuses protected GAs outright, and refuses a `dpt` that contradicts the GA's DPT in the model (the override is for GAs the model does not type). |
| `knx_run_tests` | `only` (list of test names, optional) | Runs `tests.yaml` and returns the same report as `bussard test --json`, plus `refused_protected`. Registered only with `--allow-writes`. A test that writes a protected GA is refused whatever the file says; `manual:` tests are skipped. |
| `knx_describe_change` | `from`, `to` (snapshot ids, optional) | The change as plain sentences. With no arguments: the pending changes, i.e. the working model against the last snapshot. Files only. |
| `knx_history` | `limit` (default 50, max 500) | The history snapshots with id, time, command, gateway and a one-line summary each. |
| `knx_set_group` | `ga`, `name`, `dpt`, `description` (all but `ga` optional) | Creates or updates a group address. Creating one needs `name`. Refuses to rename or retype a `protected: true` GA; there is no parameter that sets or clears `protected`. |
| `knx_add_link` | `device`, `com_object`, `ga`, `role` (`send`\|`listen`) | Binds a com object to a GA. A com object has at most one sending GA, so an existing one is replaced. Refuses protected GAs. |
| `knx_remove_link` | `device`, `com_object`, `ga`, `role` | Unbinds a com object from a GA. Refuses protected GAs. |
| `knx_set_device` | `address`, `name`, `floor`, `room` (all but `address` optional) | Renames a device or changes where it lives. |
| `knx_set_parameter` | `address`, `parameter`, `value` | Sets one value in the device file's `parameters:` block, checked against the product model. Refuses when the device has no `parameters:` block or no product model to check against. |
| `knx_undo` | `snapshot_id` (optional) | Restores the model files to a snapshot (default: the newest one that differs from the working files, i.e. undo the last change). Files only. |
| `knx_export_bundle` | `path`, `include_history` (default true), both optional | Writes the model and its history as one `.bussard` file (default: next to the model directory) and returns the path and manifest. Available in every tier. |
| `knx_diff_project` | `path` (a `.knxproj` or `.bussard`) | What that file would change compared with the working model: `{count, summary, touches_protected, sentences, changes, source}`. The assistant quotes the sentences before the human imports. A password-protected `.knxproj` needs `BUSSARD_PROJECT_PASSWORD` in the server's environment. Read-only; available in every tier. |
| `knx_plan_device` | `address` | Reads the device's live tables (read-only on the bus) and returns the plan `bussard plan --json` has for the tables: `sentences` (the text rendering in the device file's words), `changes`, `unchanged_objects`, `writes`, `question`, `state_hash`, plus `plan` (the table-level detail: additions, removals, unchanged count, table sizes, load operations), `pending_model_changes` (sentences), the same lists as JSON, `backup_dir`, `plan_digest`, `planned_at` and `expires_at`. Parameters are not compared over MCP. A plan with nothing to do has no digest. Refuses a change that touches a protected GA. With the server's `--keyring`, a Data Secure device the keyring lists is read over KNX Data Secure (`secured: true`). Registered only with `--allow-programming`. |
| `knx_apply_device` | `address`, `plan_digest`, `plan_hash` (optional) | Writes the planned tables: backup first, then the `bussard apply` write, then a read-back verify. Returns `verified`, the final load states, `backup`, `gateway` and the history `snapshot`. Refused unless the digest is fresh and a new read still reproduces it (see below), when `plan_hash` is given and a fresh read no longer hashes to it, and for a device the server's `--keyring` holds a Data Secure tool key for (use `bussard apply --keyring`). Registered only with `--allow-programming`. |

### The programming tier

`--allow-programming` (issue #118) lets the assistant finish a change instead of ending with "now type `bussard apply`". It is the same plan and write as the CLI, with gates in front:

- **Write gate.** A non-loopback gateway needs `BUSSARD_ALLOW_REAL_GATEWAY=1` or `--allow-remote-gateway`. The server refuses to start without it, and both tools check it again on every call.
- **Source-address probe.** Both tools refuse when a device already answers at the tunnel's own individual address, as the CLI device commands do.
- **Plan digest.** `knx_plan_device` returns `plan_digest`, a SHA-256 over the device address, the model's links for it, the desired tables and the live tables it read. `knx_apply_device` refuses unless the digest came from this server session within `--plan-ttl-minutes` (default 10) and a fresh read of the device, with the current model, reproduces it. A digest is single use: a write, or a refusal because the device or the model moved, retires it.
- **Human approval.** The tool descriptions tell the assistant to show the plan to the human and to call `knx_apply_device` only after an explicit yes in the conversation.
- **Protected GAs.** A plan whose additions or removals touch a `protected: true` GA is refused, with no override.

An apply writes the pre-state backup to `captures/backups/` before anything else, records a history snapshot `mcp knx_apply_device <address> <digest>` naming the gateway (the audit line `bussard history` shows), writes, and verifies by reading back. One device per call. `flash` stays CLI-only.

The model is not frozen at startup: the server re-reads the model directory when its files change (and immediately after one of its own model edits), so a `protected: true` or a corrected `dpt:` added to `groups.yaml` mid-session is in force on the next tool call. A model that fails to parse is not swapped in; the server keeps the last good one and warns on stderr.

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
