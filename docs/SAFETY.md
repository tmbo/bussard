# Safety

`bussard` writes to physical building infrastructure. A bad write can move a
blind onto a plant, trip a wind alarm, or leave a device half-programmed. This
page is the one thing to read before your first write. The write path is built
to make the dangerous cases loud, but the guard-rails only help if you know
which bus you are pointed at.

Read commands (`monitor`, `read`, `scan`, `plan`, `reconstruct`) never transmit
device programming and are never gated. Everything below is about the write
commands: `write`, `apply`, `flash`, `assign`, `adopt`.

## The one rule: know which bus you are hitting

The single most dangerous mistake is running a write against your live house
when you meant a test bus. `bussard.yaml` can carry a `connection.gateway`
pointing at the real gateway, and that value is used by default, so a bare
`bussard write ...` can reach the real bus without you naming it.

Two things protect you:

1. **Every write names its gateway.** The confirmation prompt echoes the
   resolved gateway as `host:port` (for example
   `write 3/0/4 <- down (1.008) via 192.168.1.74:3671? [y/N]`). Read it before
   you type `y`. If the address is not the one you expect, abort.

2. **Non-loopback gateways are refused by default.** A write whose resolved
   gateway is *not* loopback (not `127.0.0.0/8`, not `::1`) refuses to run:

   ```
   refusing to write to non-loopback gateway 192.168.1.74:3671: this looks
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
spot-checks written segments. A flash assumes the device is **factory-fresh**
and takes **no backup**, because a fresh device has no prior application to
save. The command states this plainly before it writes:

```
NOTE: a first flash assumes the device is factory-fresh; no backup is
possible (there is no prior application to save). Recovery from a failed
flash is re-running `bussard flash`.
```

Note that today `flash` does not check whether the device is actually
factory-fresh; flashing a device that already carries an application overwrites
it with no backup. Refusing (or requiring `--force`) in that case is tracked in
[issue #79](https://github.com/tmbo/bussard/issues/79). Until then, be sure the
target is fresh, or accept that you are overwriting it.

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
- **`apply`, `plan`, and single-device `reconstruct`** support **System B only**
  for now. Another mask is refused (in line-mode `reconstruct` it is recorded as
  a stub instead). The refusal names the mask, for example:

  ```
  1.1.5 reports mask 0705 (System 7) — `bussard apply` supports
  System B (mask 07B0) only for now
  ```

Everything not on these lists is refused before a write, not attempted and
rolled back.

## Known limitations

- **KNX Secure is not supported.** `bussard` speaks unencrypted management
  sessions. It cannot program a device that requires KNXnet/IP Secure or KNX
  Data Secure. The roadmap decision is tracked in
  [issue #71](https://github.com/tmbo/bussard/issues/71). Do not point `bussard`
  at a Secure installation expecting it to write.
- **`flash` does not yet verify factory-freshness**
  ([issue #79](https://github.com/tmbo/bussard/issues/79)); see the flash
  section above.

## See also

- [How do I ...](howto.md) — the writing recipes, with the safety note up front.
- [Reference](reference.md) — every command, flag, and the exact refusal
  conditions.
