# Safety

bussard writes to physical building infrastructure, and the guard-rails only
help if you know which bus you are pointed at. Read this page before your
first write; it takes five minutes.

A bad write can move a blind onto a plant, trip a wind alarm, or leave a
device half-programmed. The write path is built to make those cases loud.

## Only a few commands write

Read commands (`monitor`, `read`, `scan`, `plan`, `reconstruct`) never
transmit device programming and are never gated. These commands write:
`write`, `apply`, `flash`, `assign`, `adopt`, `commission`, `restore`,
`replace`, `restart`, `test`, `interface secure` and `secure diag --clear`. [What each write command does](write-commands.md)
covers each one.

Two long-running servers can also write. They pass the same gate once, at
startup, rather than per command:

- `bussard mcp --allow-writes` hands an LLM the bus for group writes for the
  session, and `bussard mcp --allow-programming` lets it write one device's
  tables and parameters after you approve the plan.
- `bussard viz --allow-writes` arms the page's group-write endpoint, and
  `bussard viz --watch-prog` puts broadcast reads on the bus on a timer.

Both default to off. A bare `bussard viz` is a viewer whose write endpoint
answers `403`, and a bare `bussard mcp` has no write tool, so neither can
transmit and neither is gated.

## Every write asks once

- `--yes` means one thing on every command: skip the confirmation prompt. It
  never consents to anything else.
- Without a terminal and without `--yes`, a write command is refused with
  `refusing to <action> without a terminal to confirm on; pass --yes to
  confirm non-interactively`. `learn` follows the same rule.
- An explicit address or value is not consent. `bussard assign 1.1.47` in a
  script still needs `--yes`.
- Downloading vendor product data is a separate consent, `--yes-download`
  (`init`, `import`, `import-product`, `adopt`). Without a terminal and
  without it, nothing is downloaded, and `import-product` refuses.
- `--yes` never lifts the real-gateway gate below. The gate is checked before
  the prompt.

## The one rule: know which bus you are hitting

The most dangerous mistake is running a write against your live house when you
meant a test bus. `bussard.toml` can carry a `connection.gateway` pointing at
the real gateway, and that value is the default, so a bare `bussard write`
can reach the real bus without you naming it. Two things protect you.

**Every write names its gateway.** The confirmation prompt shows the resolved
gateway as `host:port`, for example:

```console
write 3/0/4 <- down (1.008) via 192.0.2.10:3671? [y/N]
```

Read it before you type `y`. If the address is not the one you expect, abort.

**Real gateways are refused by default.** A write whose gateway is not
loopback (not `127.0.0.0/8`, not `::1`) refuses to run. A write command checks
on every invocation; a write-enabled server checks at startup and refuses to
start:

```console
refusing to write to non-loopback gateway 192.0.2.10:3671: this looks
like a real KNX bus. If you really mean to write to it, re-run with
--allow-remote-gateway or set BUSSARD_ALLOW_REAL_GATEWAY=1.
```

You opt in per command with `--allow-remote-gateway`, or for a shell session
with an exported `BUSSARD_ALLOW_REAL_GATEWAY=1`. Treat setting the variable as
arming the tool and unset it when you are done. `BUSSARD_GATEWAY` and
`BUSSARD_DIR` only choose which bus and model a command uses; no other
variable can permit a write.

**The simulator is the safe target.** Loopback gateways are always allowed.
Give one explicitly, with `--gateway 127.0.0.1` on the command or
`gateway = "127.0.0.1:3671"` under `[connection]` in `bussard.toml`. The
`knx-sim` simulator in the repository listens on `127.0.0.1:3671`: from the
`knx-sim/` directory run `cargo run -- examples/da_tp.yaml`, then point
bussard at it. No opt-in flag is needed.

## Your first writes

Do your first real writes against the simulator or a spare device, never a
live installation:

- **The simulator** accepts the same programming a real System B or System 7
  device does, and rejects out-of-order or out-of-bounds operations, so a
  mistake fails on the simulator instead of on your wall.
- **A spare device on the bench**, powered and reachable but not wired into
  anything that moves.

Once a command behaves as you expect on the simulator, the only change for
the real bus is the gateway and the `--allow-remote-gateway` opt-in. Before
the first write to the real bus, take a `bussard backup` of the whole
installation.

## Protected group addresses

Mark a group address `protected = true` in `groups.toml` for wind alarms,
central functions and anything else safety-critical. A write to it is refused
by default:

| Interface | Protected write |
|---|---|
| CLI (`bussard write`) | refused; overridable with `--force` |
| viz test-write widget | refused; overridable with an explicit `force` |
| MCP (an LLM over the server) | refused; no override exists |

A human at the CLI or the viz page can force a protected write when they mean
to. An LLM over MCP never can, with or without `--allow-writes`, and it cannot
rename, retype or relink a protected address or clear the flag. Only a human
editing `groups.toml` changes `protected`. [The assistant](assistant.md)
explains why.

`bussard test` needs two opt-ins for a protected address: `allow_protected =
true` in `tests.toml` and `--force` on the command line. With either missing,
the test is reported as refused and nothing is sent to that address.

## Secrets stay out of git

bussard reads `BUSSARD_*` variables from one `.env` file, which may hold
`BUSSARD_KEYRING_PASSWORD`, `BUSSARD_PROJECT_PASSWORD` and `BUSSARD_HA_TOKEN`.
Keep those there only while `.env` is in `.gitignore`. bussard never prints a
value and never copies a `.env` into a bundle.

A `.env` never opens the write gate. `BUSSARD_ALLOW_REAL_GATEWAY` in the file
is ignored with a warning, so a write to a real gateway still needs the flag
or an exported variable. The key store `bussard.keys` is committed on purpose
and is only as private as its password. [KNX Secure](knx-secure.md) has the
full rules.

## For professionals

The rails are tuned for an owner doing a first write. An integrator writes to
real gateways every day, and these settings keep the rails without the
friction.

### Arm the service laptop, not the project

Set the real-gateway opt-in once, in the shell profile of the machine that
commissions:

```sh
export BUSSARD_ALLOW_REAL_GATEWAY=1
```

It has the effect of `--allow-remote-gateway` on every write command, and on
`mcp --allow-writes` and `viz --allow-writes` at startup. It removes nothing
else: every confirmation still names the gateway, protected addresses still
need `--force`, and the MCP server reaches a device's tables only through the
programming tier, one approved plan at a time.

The opt-in is per machine on purpose: only the machine knows whether it is
meant to write to real buses. A setting in `bussard.toml` would travel with
the model into every bundle handed to a customer, every clone and every
assistant session. A `.env` next to a model travels the same way, which is
why bussard ignores the variable there.

### Share the interface with ETS

ETS and bussard often run against the same interface, and each holds a
tunnelling slot (one of the interface's few connections).

- Check the budget before the session. `bussard init --gateway <ip>` or
  `bussard audit --live` prints `N tunnels, M in use`. Home Assistant or a
  visualisation usually holds one slot permanently.
- Close the ETS bus connection before a long run such as `apply --line` or
  `commission`, and close bussard before an ETS download. `bussard mcp` and
  `bussard viz` hold a slot for as long as they run.
- Never program one device from both tools at once. A device accepts one
  management connection at a time, so a second download fails or interleaves
  with the first. Finish in one tool, then run `bussard plan <ia>` to see
  exactly what ETS left on the device.
- After a crash, a slot stays taken until the interface times it out, about
  two minutes. Wait instead of retrying in a loop.

[Device support](device-support.md) explains the slot count and exit code `4`.

## Next steps

- [What each write command does](write-commands.md): what every write refuses, backs up and verifies.
- [KNX Secure](knx-secure.md): keys, the key store and the `.env` rules.
- [The assistant](assistant.md): the MCP tiers, history and undo.
- [Back up and replace](../how-to/back-up-and-replace.md): take the snapshot before your first write.
