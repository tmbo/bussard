# Safety

`bussard` writes to physical building infrastructure. A bad write can move a
blind onto a plant, trip a wind alarm, or leave a device half-programmed. This
page is the one thing to read before your first write. The write path is built
to make the dangerous cases loud, but the guard-rails only help if you know
which bus you are pointed at.

Read commands (`monitor`, `read`, `scan`, `plan`, `reconstruct`) never transmit
device programming and are never gated. Everything below is about the write
commands: `write`, `apply`, `flash`, `assign`, `adopt`.

Two long-running servers can also write, and they pass the same gate at
startup rather than per command:

- `bussard mcp --allow-writes`, which registers the `knx_write_group` tool and
  hands an LLM the bus for the session.
- `bussard viz --allow-writes` (arms `POST /api/group-write`) and
  `bussard viz --watch-prog` (puts broadcast reads on the bus on a timer).

Both default to off. A bare `bussard viz` is a viewer whose write endpoint
answers `403`, and a bare `bussard mcp` has no write tool, so neither can
transmit and neither is gated.

## The one rule: know which bus you are hitting

The single most dangerous mistake is running a write against your live house
when you meant a test bus. `bussard.yaml` can carry a `connection.gateway`
pointing at the real gateway, and that value is used by default, so a bare
`bussard write ...` can reach the real bus without you naming it.

Two things protect you:

1. **Every write names its gateway.** The confirmation prompt echoes the
   resolved gateway as `host:port` (for example
   `write 3/0/4 <- down (1.008) via 192.0.2.10:3671? [y/N]`). Read it before
   you type `y`. If the address is not the one you expect, abort.

2. **Non-loopback gateways are refused by default.** A write whose resolved
   gateway is *not* loopback (not `127.0.0.0/8`, not `::1`) refuses to run.
   For the five write commands the check happens per invocation; for the two
   servers it happens once, at startup, so a write-enabled server pointed at a
   real gateway refuses to start at all:

   ```
   refusing to write to non-loopback gateway 192.0.2.10:3671: this looks
   like a real KNX bus. If you really mean to write to it, re-run with
   --allow-remote-gateway or set BUSSARD_ALLOW_REAL_GATEWAY=1.
   ```

   Loopback gateways (the simulator, the test suite) are always allowed. To
   write to a real gateway you opt in explicitly, per command with
   `--allow-remote-gateway` or for a session with `BUSSARD_ALLOW_REAL_GATEWAY=1`.
   Treat setting the env var as arming the tool: unset it when you are done.

Point at a test bus by giving a loopback gateway explicitly, either
`--gateway 127.0.0.1` on the command or `connection.gateway: 127.0.0.1:3671`
in `bussard.yaml`. The [`knx-sim`](../knx-sim/README.md) simulator is the
easiest safe target: from the `knx-sim/` directory run
`cargo run -- examples/da_tp.yaml`, which listens on `127.0.0.1:3671`, then
point `bussard` at it. Because it is loopback, no opt-in flag is needed.

## Your first writes

Do your first real writes against a spare device or the simulator, never a
live installation. Two safe practice targets:

- **The simulator.** `knx-sim` is a strict, independent device model. It
  accepts the same programming a real System B or System 7 device does and
  rejects out-of-order or out-of-bounds operations, so a mistake fails on the
  sim instead of on your wall. See the [flash walk-through](howto.md#-flash-a-factory-fresh-device)
  and the [`bussard flash` reference](reference.md#bussard-flash---product-file-address).
- **A spare device on the bench**, powered and reachable but not wired into
  anything that moves.

Once a command behaves the way you expect against the sim, the only change for
the real bus is the gateway and the `--allow-remote-gateway` opt-in.

## What each write command does, and its rails

Every device write is plan-before-apply: `bussard` reads the live state, shows
a diff, asks for confirmation on the terminal (`y/N`), writes, then verifies by
reading back. Without a TTY the write is refused unless you pass `--yes`
(`--yes-download` for `import-product`). A refusal exits non-zero *before*
anything is written.

**`write <GA> <VALUE>`** sends a single group value (`on`/`off`, `up`/`down`, a
number, a percentage). It is a runtime command, not device programming: nothing
is stored on a device, but actuators move. The confirmation names the GA, the
decoded value, and the gateway.

**`apply <ADDRESS>`** writes the model's link tables (group address and
association tables) to a device. It backs up first: the device's pre-apply
tables are written to `<dir>/captures/backups/<ia>-<timestamp>.json` before any
write, and the apply refuses if the backup cannot be written. Tables are
rewritten wholesale, so re-running `apply` is idempotent. To go back, re-apply
from the model, or `bussard restore <dir>/captures/backups <ADDRESS>` to write
the backed-up tables through the same path.

**Installation-wide backup (`backup`, `restore`).** The per-device backup above
covers only the device `apply` is about to touch. Take a snapshot of the whole
installation before the first write: `bussard backup` reads every model device
into `<dir>/captures/backups/<UTC timestamp>/`, one JSON file per device plus a
`manifest.json`. It is read-only on the bus: it sends descriptor, authorize,
property-read and memory-read APDUs and nothing else, and a mock-gateway test
fails if a single write reaches a device. The manifest lists every device,
including the ones it could not cover: `skipped` for a mask bussard cannot read,
`unreachable` for a device that did not answer, `failed` for a read that broke
(which makes the run exit 1). On System B the snapshot includes the
application segment, where the parameters live; on System 7 it does not,
because the device does not report that segment's length. `apply` prints a
hint while no such snapshot exists.

`bussard restore <backup-dir> <ADDRESS>` writes one device's tables back. It is
the `apply` command with the backup as the desired state: same plan, same
confirmation naming the gateway, same pre-write backup, same verify, same
non-loopback gate. Restoring a fresh backup onto an unchanged device plans empty
and writes nothing. `restore` writes link tables only; parameters come back with
`flash`.

**`replace <ADDRESS> --product <FILE>`** swaps a dead device for a new one of
the same product. It refuses when the old device still answers, and when the
pressed device's order number or mask differs from the model's device file,
unless `--force`. After one confirmation naming the gateway it runs the
`assign`, `flash` and `apply` write paths in turn (no write of its own), then
records `replaced: <date>` in the device file.

**`flash --product <FILE> <ADDRESS>`** downloads an application program from
vendor product data (the ETS-free application download). It runs a pre-flight
plan, then writes, then verifies the application reads back as `Loaded` and
spot-checks written segments. A flash takes **no backup**, because a
factory-fresh device has no prior application to save. The command states this
plainly before it writes:

```
NOTE: a first flash assumes the device is factory-fresh; no backup is
possible (there is no prior application to save). Recovery from a failed
flash is re-running `bussard flash`.
```

**The factory-freshness check.** Because there is no backup, `flash` verifies
that assumption before it writes anything. In its read-only pre-flight it reads
the load state of every object the download would rewrite: on System B each
interface object's `PID_LOAD_STATE_CONTROL` plus the resident application id in
`PID_PROGRAM_VERSION`, on System 7 each load-state machine. Then:

| What the device reports | What `flash` does |
| --- | --- |
| No application loaded | Proceeds (the device is factory-fresh). |
| An object left `Loading` or in `Error` by an interrupted flash | Proceeds; re-flashing is the recovery path. |
| The **same** application already loaded | Proceeds without `--force`, with a notice. |
| A **different** application loaded | **Refuses**; `--force` overrides. |
| An application loaded that it cannot identify | **Refuses**; `--force` overrides. |
| A load state it cannot read at all | **Refuses** as unknown; `--force` overrides. |

A refusal names the device, the resident application and the two ways forward:
capture what is on the device first (`reconstruct` reads its links into the
model, and `apply` backs the tables up to `captures/backups/` before writing),
or re-run with `--force` to overwrite it anyway. `--force` prints a single loud
line naming the device, the gateway and what is being destroyed, and the
confirmation prompt repeats it, so a `y` is typed against the real consequence.

Two details worth knowing. **Unreadable is not fresh**: if the device refuses
the state reads, `flash` refuses too, and says the state was unreadable rather
than `Loaded`, because a write with no backup must not be what finds out. And
**re-flashing the same application is deliberately allowed**, because the
failure messages tell you to re-run `flash` after an interrupted one. It is
still a full rewrite: the parameters are reset to the vendor defaults plus the
device file's `parameters:` overrides, and the address, association and
group-object tables are rewritten from the model's links. On System 7 there is
no application-id property, so a loaded device can never be recognised as "the
same application": any loaded System 7 device needs `--force`.

**Recovery from a failed or interrupted flash.** The download is idempotent: it
re-unloads and rewrites the whole application, so the fix for a partial flash is
to re-run `bussard flash <ADDRESS>`. The bus lease resumes on drop, so an
interrupted session reconnects promptly rather than waiting out the full ACK
timeout. If re-flashing does not recover the device, fall back to downloading it
with ETS. Do not assume a device is functional until a flash reports the
application `Loaded` and verified.

**`assign`** sets a device's individual address; **`adopt`** is the interactive
wizard that assigns and flashes a new device. Both are gated the same way: they
confirm on a terminal, and non-interactively they need `--yes`. An explicit
target address is not itself consent, so a scripted `assign` still needs
`--yes`; `adopt` additionally needs a product file and an explicit target
address to run without a TTY.

**Whole-line runs** (`apply --line`, `commission --line`) ask one confirmation
for the run instead of one per device. The prompt names the resolved gateway
and the number of devices it will touch, and the same `--yes` and non-loopback
gates apply. Each device still gets the full single-device rails: `apply
--line` backs up and verifies every device, and `commission` refuses to address
a device whose order number does not match the model. A device that fails is
reported and the run moves on. `apply --line` records every outcome in
`<dir>/captures/apply-line-<line>.json` as it goes, so after an interruption
`--resume` continues without rewriting finished devices; a clean run deletes
the file.

## Protected group addresses

A GA marked `protected: true` in `groups.yaml` (wind alarms, central functions,
anything safety-critical) is refused by default. The three entry points do not
treat the override the same way:

| Interface | Protected-GA write |
| --------- | ------------------ |
| CLI (`bussard write`) | refused; overridable with `--force` |
| viz test-write widget | refused; overridable with an explicit `force` |
| MCP (LLM over the server) | hard-refused; **no override exists** |

The asymmetry is deliberate: a human at the CLI or the viz page can force a
protected write when they mean to, but an LLM driving `bussard` over MCP can
never write a protected GA, with or without `--allow-writes`. Keep genuinely
dangerous GAs marked `protected: true` so the MCP path can never touch them.

The same refusal covers the MCP model-edit tools: a protected GA cannot be
renamed or retyped, and no link to it can be added or removed, over MCP. There is
also no tool parameter that sets or clears `protected:`; only a human editing
`groups.yaml` can. Any change that touches a protected GA is rendered with the
sentence "This group address is protected." and sorted to the top of
`bussard status`, so it is the first thing anyone reads.

`bussard test` runs scripted writes, so it takes the same rails as `bussard
write` (the non-loopback gateway gate and a confirmation naming the gateway),
and a protected GA needs two opt-ins instead of one: `allow_protected: true` in
`tests.yaml` and `--force` on the command line. With either missing, the test
is reported as refused and nothing is written to that GA. The `knx_run_tests`
MCP tool refuses such a test whatever the file says. `bussard learn` never
transmits at all.

## History and undo

bussard keeps a full copy of the model files under `<dir>/.bussard/history`
before every command that writes the model or the bus, and before every model
edit made over MCP. `bussard status` says what has changed since the last one,
`bussard history` lists them, and `bussard undo` puts the files back.

`undo` touches **files only**. It sends nothing on the bus and changes no
device: after an undo the installation behaves exactly as it did a second
before. The restored model reaches a device only when a human runs
`bussard plan <ia>` and then `bussard apply <ia>`, behind the usual
confirmation. An undo is itself snapshotted first, so it can be undone.

Snapshots carry the four model inputs (`bussard.yaml`, `groups.yaml`,
`links.yaml`, `devices/*.yaml`) and nothing else. Product data, captures,
keyrings and project files are never copied into them, so a snapshot cannot
leak a key, a password or vendor data.

A `.bussard` bundle from `bussard export` (or `knx_export_bundle`) holds those
same model files, the history snapshots and a manifest, and nothing else. It
never contains `models/`, `vendor/`, `captures/`, keyrings, `.knxproj` or
`.knxprod` files, or `.env`, because the export copies an allow-list rather
than skipping a deny-list. The manifest names these exclusions. `bussard.yaml`
does travel with it, so the recipient sees your gateway address; an import into
an existing model keeps the recipient's own `bussard.yaml`. Importing a bundle
writes files only and snapshots first; nothing reaches a device until someone
runs `plan` and `apply`.

## Source address check

Every command that opens a connection to a device (`scan`, `assign`, `adopt`,
`describe`, `plan`, `apply`, `flash`, `reconstruct`, `backup`, `restore`,
`replace`, `commission`, `audit --live`, and `plan --line` / `apply --line`)
first checks that no device on the bus answers at the individual address
bussard itself will use as its source: the address the gateway assigned to the
tunnel, or `0.0.255` on routing. If a device answers, the command refuses before
touching anything:

```
refusing to continue: a device on the bus (mask 07B0) already answers at
1.1.255, the individual address this connection would use as its source.
```

This matters because a KNX device tells its management clients apart by source
individual address and nothing else. If a real device sits at our address, both
parties' numbered telegrams land inside one layer-4 session at the target: a
memory write can be applied on behalf of the wrong session while both sides
still see an acknowledgement. That is silent configuration corruption rather
than a loud failure. ETS runs the same check before it uses an interface.

The check runs once per tunnel. `flash`, `apply` and `restore` hold one tunnel
for their read-only pre-flight and their write phase, so they check once. A
command that opens several tunnels in turn (`commission`, `replace`) checks on
each. Group-only commands (`read`, `write`, `monitor`, `capture`, `learn`,
`test`) never open a device connection and skip it.

The check costs one telegram and about 0.6 seconds on a free address. The fix is
almost always on the gateway: give the tunnel an individual address no device
owns (many gateways ship with a default that collides on a busy line).

`--skip-address-check` turns it off, for a gateway that misbehaves on the probe
itself. Nothing else disables it.

**What it does not catch.** The check proves that no *device* answers at our
address. It cannot see a second passive tool that shares the address without
answering, for example another bussard in routing mode also sourcing from
`0.0.255`, or an ETS session on a second tunnel. It also reports free when a
device replies with something other than a device descriptor, since only a real
`A_DeviceDescriptor_Response` is treated as proof.

## Supported device masks

Write commands refuse an unsupported device mask during the pre-flight, before
any write. Support differs by command. This table is the single source: it is
rendered from `MaskProfile::capabilities` in `bussard-mgmt`, the same table the
refusals and `bussard audit` use, and a test
(`crates/bussard-cli/tests/docs_consistency.rs`) fails when it drifts.

<!-- mask-table:start -->
| Mask | Family | Medium | `plan` / `apply` | `flash` | `reconstruct` | `describe` | Notes |
|---|---|---|---|---|---|---|---|
| `0010` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0011` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0012` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0013` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0020` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0021` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0025` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0300` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0310` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0311` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0700` | System 7 | TP1 | yes | yes | yes | yes | memory-mapped tables (default 0x4000 / 0x4201), A_Authorize required; line-mode `reconstruct --line` records a stub instead of tables |
| `0701` | System 7 | TP1 | yes | yes | yes | yes | memory-mapped tables (default 0x4000 / 0x4201), A_Authorize required; line-mode `reconstruct --line` records a stub instead of tables |
| `0705` | System 7 | TP1 | yes | yes | yes | yes | memory-mapped tables (default 0x4000 / 0x4201), A_Authorize required; line-mode `reconstruct --line` records a stub instead of tables |
| `07B0` | System B | TP1 | yes | yes | yes | yes | tables live in device-allocated segments found via PID_TABLE_REFERENCE; full read and write support |
| `27B0` | System B | RF | yes | yes | yes | yes | tables live in device-allocated segments found via PID_TABLE_REFERENCE; full read and write support |
| `57B0` | System B | KNX-IP | yes | yes | yes | yes | tables live in device-allocated segments found via PID_TABLE_REFERENCE; full read and write support |
<!-- mask-table:end -->

The details per command:

- **`flash`** supports **System B** (`07B0`, and the `57B0` / `27B0` KNX-IP and
  RF variants) and **System 7** (`0705` / `0701` / `0700`). A mask outside
  those families, a mask mismatch between the application and the device, or a
  load procedure containing an operation `bussard` cannot execute all refuse the
  procedure rather than leaving a device half-flashed.
- **`apply`, `plan`, and single-device `reconstruct`** support **System B**
  (`x7B0`) and **System 7** (`0705` / `0701`). On System B each table lives in a
  segment the device allocates for it: `apply` opens the table object, asks for a
  segment with `LdCtrlRelSegment`, reads the placement from
  `PID_TABLE_REFERENCE`, and writes the image there. It never writes the
  `PID_TABLE` property array, which real devices refuse (a Jung F50 rejected it
  outright). On System 7 the tables are the absolute memory
  regions at `0x4000` (address table + group-object descriptors) and `0x4201`
  (association table), and `apply` rewrites only those two table load-state
  machines — the parameter LSM and the application image are never touched, and
  the device is not restarted. Another mask is refused (in line-mode
  `reconstruct` it is recorded as a stub instead). The refusal names the mask,
  for example:

  ```
  1.1.5 reports mask 0012 (System 1) — `bussard apply` supports the
  System B (x7B0) and System 7 (0705 / 0701) families
  ```

  Every System 7 table read is bounded by its memory region: a count octet
  claiming more entries than the region holds (virgin EEPROM reads `0xFF`) is
  refused rather than followed into neighbouring memory, and an image that would
  not fit its region is refused before anything is written.

  These three commands run without a `.knxprod`, so the System 7 table bases are
  the corpus-wide defaults `0x4000` / `0x4201` rather than product-resolved
  addresses. A device that keeps its tables elsewhere reads back as an empty
  table set — never as mis-decoded links — and must be programmed with
  `bussard flash`, which does resolve the addresses from product data.

Everything not on these lists is refused before a write, not attempted and
rolled back.

## The tunnel budget

A KNXnet/IP tunnelling interface has a fixed number of connection slots, often
one to five, set by the hardware. Each client holds one slot for as long as it is
connected: Home Assistant's KNX integration holds one permanently, ETS holds one
while a project is online, and so does every running `bussard` command, including
a long-running `bussard viz` or `bussard mcp`. A second bussard command started
while the first is running needs a second slot.

When every slot is taken, the interface refuses a new connection with
`E_NO_MORE_CONNECTIONS`. bussard reports that as its own condition, not a
timeout, and exits with code `4`:

```
error: 192.0.2.10:3671 has no free tunnelling connection (E_NO_MORE_CONNECTIONS).
A KNXnet/IP interface has a fixed number of tunnel slots, ...
```

It is a capacity problem, not a fault: retrying does not help until a slot is
freed. Close one of the other clients (or wait for a crashed one's slot to time
out, about two minutes), or run a long-lived observer over routing if the
interface supports it. `bussard init --gateway <ip>` and `bussard audit --live`
print `N tunnels, M in use` when the interface reports its slots. A bussard write
never retries into a full interface, so the refusal happens before anything is
sent to a device.

## Known limitations

- **KNX Secure: Data Secure tool-access only, simulator-verified.** `bussard`
  can program a KNX Data Secure device through its tool key (`--keyring
  <file.knxkeys>` with `BUSSARD_KEYRING_PASSWORD`, or `--tool-key` for tests) on
  `flash`, `describe` and `apply`; `bussard keyring` inspects an ETS export. This
  path is verified only against the knx-sim activated device, not yet against a
  security-activated physical device. KNXnet/IP Secure (encrypted tunnel
  sessions to a Secure-only interface) is not implemented; a Secure-only
  interface refuses `bussard`. Phase B of
  [issue #71](https://github.com/tmbo/bussard/issues/71) tracks it.

## See also

- [How do I ...](howto.md) — the writing recipes, with the safety note up front.
- [Reference](reference.md) — every command, flag, and the exact refusal
  conditions.

## Private data (the maintainer's installation, and yours)

The repository must never describe a real installation. Raw installation data
(`knx/`, `*.knxproj`, `*.knxkeys`, captures, `shared-with-windows/`, the product
corpus cache) is gitignored. Fixtures, examples and tests use invented names
and TEST-NET addresses; review a diff for room names, device names and LAN
addresses before you commit it.
If you flash your own house, keep your `knx/` out of any fork you publish.

## For professionals

The rails above are tuned for an owner doing a first write. An integrator writes to real gateways every day, and the settings below keep the rails without the friction.

### Arm the service laptop, not the project

Set the real-gateway opt-in once, in the shell profile of the machine that commissions:

```sh
export BUSSARD_ALLOW_REAL_GATEWAY=1
```

It has the same effect as passing `--allow-remote-gateway` to every write command, and to `mcp --allow-writes` and `viz --allow-writes` at startup. It removes nothing else: every confirmation still names the gateway, protected group addresses still need `--force`, and the MCP server still has no path to `plan`, `apply` or `flash`.

The opt-in is per machine on purpose. The question it answers is "is this computer meant to write to real buses?", and only the machine knows that. A setting in `bussard.yaml` would travel with the model: into every bundle handed to a customer, every repository clone, and every assistant session started on that model. The owner who imports the handover bundle would receive an armed tool without choosing it. Keep the variable out of `.env` files that live next to a model for the same reason.

### Share the interface with ETS

An integrator often has ETS and bussard open against the same interface. The [tunnel budget](#the-tunnel-budget) section explains the slot count and exit code `4`. On top of that:

- Check the budget before the session. `bussard init --gateway <ip>` or `bussard audit --live` prints `N tunnels, M in use`. Home Assistant or a visualisation server usually holds one slot permanently.
- Close the ETS bus connection before a long bussard run such as `apply --line` or `commission`, and close bussard before an ETS download. Each running bussard command holds a slot, and so do `bussard mcp` and `bussard viz` for as long as they run.
- Never program one device from both tools at once. A device accepts one management connection at a time, so a second tool's download fails or interleaves with the first. Finish in one tool, then plan in the other: `bussard plan <ia>` after an ETS download shows exactly what ETS left on the device.
- After a crash, a tunnel slot stays taken until the interface times it out, about two minutes. Wait instead of retrying in a loop.
