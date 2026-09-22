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
rewritten wholesale, so re-running `apply` is idempotent. To restore, re-apply
from the model, or reconstruct the earlier state from the backup JSON.

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

## Supported device masks

Write commands refuse an unsupported device mask during the pre-flight, before
any write. Support differs by command:

- **`flash`** supports **System B** (`07B0`, and the `57B0` / `27B0` KNX-IP and
  RF variants) and **System 7** (`0705` / `0701` / `0700`). A mask outside
  those families, a mask mismatch between the application and the device, or a
  load procedure containing an operation `bussard` cannot execute all refuse the
  procedure rather than leaving a device half-flashed.
- **`apply`, `plan`, and single-device `reconstruct`** support **System B**
  (`x7B0`) and **System 7** (`0705` / `0701`). On System B the tables are
  interface-object property arrays; on System 7 they are the absolute memory
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
corpus cache) is gitignored, and `scripts/check-no-house-data.sh` refuses any
commit or tracked file that carries private markers: those paths, a private
LAN address, or a room, floor, location or custom device name from the
maintainer's model. The names themselves are not in the repo; only their
sha256 hashes are (`.house-markers.sha256`, regenerated by
`scripts/gen-house-markers.sh` from the gitignored `knx/`). CI runs the check
over every tracked file; `scripts/install-hooks.sh` installs it as a pre-commit
hook. Fixtures, examples and tests use invented names and TEST-NET addresses.
If you flash your own house, keep your `knx/` out of any fork you publish.
