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
- `bussard mcp --allow-programming`, which registers `knx_plan_device` and
  `knx_apply_device` so an LLM can write one device's link tables after the
  human approves the plan (see [MCP programming tier](#mcp-programming-tier)).
- `bussard viz --allow-writes` (arms `POST /api/group-write`) and
  `bussard viz --watch-prog` (puts broadcast reads on the bus on a timer).

Both default to off. A bare `bussard viz` is a viewer whose write endpoint
answers `403`, and a bare `bussard mcp` has no write tool, so neither can
transmit and neither is gated.

## The one rule: know which bus you are hitting

The single most dangerous mistake is running a write against your live house
when you meant a test bus. `bussard.toml` can carry a `connection.gateway`
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
in `bussard.toml`. The [`knx-sim`](../knx-sim/README.md) simulator is the
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
  and the [`bussard flash` reference](reference.md#bussard-flash-address).
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

**Secured group addresses (KNX Data Secure, issue #172).** A device with a
secured group object ignores a plain telegram on its GA. `write`, `read` (and
MCP `knx_write_group` / `knx_read_group`, and viz) send such a GA as an
`A_SecureData` group telegram when it has a group key in `--keyring` or is
marked `secure = true` in `groups.toml`; a secured GA without a key is refused
before anything is sent, and a plain GA goes out byte for byte as before. A
secured `read` accepts only a response whose MAC verifies under the group key.
The sequence number is milliseconds since 2018-01-05, and never below the last
one the same process sent. A receiver accepts a secured group telegram only
from a sender it knows: ETS lists the senders of each secured GA in the
device's security individual address table (PID 54), so the tunnel address
bussard sends from must be in it, or the device drops the telegram without a
word (`write` then reports success, `read` times out). `flash --keyring` and
`apply --keyring` write that table like ETS (the devices that send on a secured
GA the device listens to) and leave bussard out of it unless you pass
`--secure-sender <tunnel IA>`: that adds bussard's own address with sequence 0,
so the device accepts `write --keyring` from it. It is off by default because
it widens who the device trusts; the next ETS download of the device removes
it again. `monitor --keyring` is read-only on the bus. See [Secured group
writes from bussard](#secured-group-writes-from-bussard) for the workflow.

**`apply <ADDRESS>`** writes the model to a device: its link tables (group
address and association tables) and, when the product data is cached (or
`--product` is given), the parameter octets that differ. It validates the model
first and refuses on an error, before the bus is touched. It shows the plan in
the device file's words and asks once (`apply these N changes to <ia> through
<gateway>? [y/N]`); a device that already matches is not asked about and not
written. With `--plan <hash>` it refuses when the device state no longer
hashes to the `state_hash` of the plan a human approved (`plan --json`). It
backs up first: the device's pre-apply tables are written to
`<dir>/captures/backups/<ia>-<timestamp>.json`, and the parameter memory to
`<dir>/captures/backups/parameters/` when parameters change, before any write;
the apply refuses if a backup cannot be written. The parameter half is the
parameter-only download below, with its rails; a parameter change that shows or
hides a com-object is refused and needs a full `flash`. Tables are rewritten
wholesale, so re-running `apply` is idempotent. To go back, re-apply from the
model, or `bussard restore <dir>/captures/backups <ADDRESS>` to write the
backed-up tables through the same path.

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

**`flash <ADDRESS>`** downloads an application program from vendor product
data (the archive cached under `vendor/` for the device's order number, or
`--product`; the ETS-free application download). It runs a pre-flight
plan, then writes, then verifies the application reads back as `Loaded` and
spot-checks written segments. After the terminal restart it re-reads the
application object's type and load state; the other objects' `Loaded` comes
from their own `LoadCompleted` before the restart, and a segment whose MCB CRC
check already passed before the restart is not sampled again. If the
application is not `Loaded` after the reboot, every object's state and every
sample is read, as before (issue #215). Each load-state change (unload, open, segment
allocation, completion) is confirmed by the state the device returns in its
answer to the write, as ETS does; when that answer carries no state octet or
not the expected state, `flash` reads the state back instead (issue #211). A flash takes **no backup**, because a
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

**The factory reset before the download (System B).** Many System B
applications allocate their segment with a fill byte and bussard, like ETS,
then writes only the octets that differ from it. The device's fill is
bookkeeping, not an erase: on a re-flash, every octet the new image leaves out
keeps whatever the previous image put there. On the #89 campaign a Jung F50
re-flashed this way kept a blinking status LED until ETS ran "reset device" and
a full download. So `flash` opens such a download the way ETS opens an initial
one: a confirmed master reset with erase code 7 ("factory reset without
individual address"). The device erases its application program, its
parameters and its group addresses and links, keeps its individual address,
answers with the time it needs to reboot, and reboots. `flash` waits that long
(at most a minute), reconnects and runs the download on the blank device. The
same reset is added when `--force` replaces an application `flash` did not
recognise or could not read. A device that refuses the reset, or does not
answer it, fails the flash before anything is written.

The reset erases everything the download rewrites, so the plan shows it as its
first step and the differential download (skipping objects whose resident image
already matches) does not apply: every object is streamed in full. Pass
`--no-factory-reset` to leave it out, but only when you know the device holds no
stale image, for example a device fresh from the box. System 7 downloads write
every region in full and never reset.

**Data Secure devices: the security object is part of the download.** A
security-activated device keeps its group keys and the per-group-object
security flags in its security interface object, not in the link tables. With
`--keyring` (or `--tool-key`), `flash` programs that object the way the ETS
secured download does (issue #156): it unloads it right after the other
objects, and after the tables and parameters it reloads it with the security
individual address table (cleared, then one `[IA][sequence]` entry per device
that sends on a secured group address this device listens to, with the
sender's keyring `SequenceNumber` when the model marks the sender `activated`,
else 0; issue #181), the group key table (one
entry per keyed group address the device links, from the keyring) and the
group-object security flags, then completes it. `apply --keyring` (and
`restore`, and `apply --line` with a keyring) rewrites the security object next
to the tables, because the key table indexes the address table. The dry run lists each of
these steps; key bytes are never printed. Use the project's current keyring: a
group address the model marks `secure` without a key in the keyring refuses
the plan before anything is written. `--tool-key` carries no group keys, so it
only suits a device without secured group addresses.

The factory reset stays in secured downloads. ETS does not send one in its
secured download, but it does send one (erase code 7) while activating Data
Secure, and the decrypted capture shows the device keeps its tool key across
it: every frame before and after verifies under the same key. The reset clears
what the download rewrites anyway, the security object included, and the
download then programs the object again. Nothing in the capture or the
specification shows harm, so the rule above applies unchanged: the reset runs
when the device carries an image `flash` did not recognise or when the
download is sparse. `--no-factory-reset` still leaves it out.

After any restart `flash` itself triggers on a Data Secure device (the
factory reset, a load procedure's master reset, the terminal restart before the
post-restart check), the device can answer at the transport layer before its
security layer is ready, and then drops the first S-A_Sync_Req without an
answer (issue #166, seen on 1.1.12). `flash` waits like ETS instead: it probes
the rebooted device with a plain `A_DeviceDescriptor_Read` every 500 ms for up
to 30 s (ETS's capture shows the device back about 14 s after the reset; a
probe that answers earlier ends the wait), keeps that connection and sends the
Sync_Req on it. A Sync_Req the device
acknowledges but does not answer is repeated on the same connection, up to
five attempts with a 1, 2, 4, 8 s backoff after a restart and three attempts
(1, 2 s) on any other secured connection, before the flash stops with "did not
answer the Data Secure sync request". Plain devices keep the shorter reboot
poll and see no extra frames.

How long `flash` waits after a restart (issue #212): after a restart the
device confirmed (the factory reset, the terminal confirmed restart) it waits
the process time the device reported, never less, and probes from 0.5 s after
that; after a bare `A_Restart` it stays quiet for 1.5 s first. A probe waits
500 ms for the device's acknowledgement and then up to 2 s for its answer,
because 1.1.5 answered 1.3 to 1.9 s late while it sent its power-up
telegrams. A probe the interface confirms negatively (`L_Data.con` with the
error bit) counts as "not up yet", never as absent: the same device answered
such a probe 1.3 s later. After the factory reset `flash` also probes from
+3 s, only to measure when the device answers; `flash -v` prints that
readiness per restart on its timing line. If the flash still stops right after the factory
reset, the device is left unloaded: re-run the same `flash`.

Activation itself (turning Data Secure on, writing the tool key and the
sending sequence number) is ETS's job: bussard operates devices ETS has
activated and never activates or deactivates one.

**Resume on connection loss.** A flash survives two kinds of connection loss
without starting over:

- *Device connection death.* The device drops its Layer-4 connection (an idle
  timeout, a per-connection exchange budget, a reboot). The flash reconnects,
  re-authorizes (including the Data Secure sync, and after a restart bussard
  triggered, the readiness probe), and resumes the current step. A chunked
  memory write continues from the last confirmed chunk; a chunk is never split
  across the reconnect.
- *Gateway tunnel loss, up to 60 s.* The KNXnet/IP link to the IP interface
  drops (a pulled LAN cable, a switch or Wi-Fi outage). When a frame stays
  unacknowledged after its retransmit, or the heartbeat fails, bussard logs
  `gateway connection lost`, sends a best-effort DISCONNECT for the old tunnel,
  and opens a new one, retrying after 1, 2, 4, 8, 8 ... s. Once the tunnel is
  back it logs `gateway connection re-established`, re-sends the pending frame,
  and the flash resumes as after a device connection death. The read-only
  pre-flight simply runs again. `BUSSARD_TUNNEL_RECONNECT_SECS` changes the
  60 s budget (`0` turns the re-establish off).

A KNXnet/IP Secure tunnel over TCP has no ACK to time out: a pulled
cable used to go unnoticed until the kernel gave up on the connection, about
37 s later. The tunnel now probes the link with a CONNECTIONSTATE_REQUEST once
it has received nothing for 5 s and treats an answer missing for 2 more seconds
as a lost link, so a loss is noticed after about 7 s.
`BUSSARD_TCP_READ_DEADLINE_MS` changes the 5 s (`0` turns the probe off). A
secure session over UDP keeps its TUNNELING_ACKs, so its ACK timeout detects a
loss as on a plain tunnel.

Both kinds of loss are also covered while bussard waits for a device it
restarted: the factory reset that opens a System B download, an
`LdCtrlMasterReset`, the final restart and its verify, and the System 7
pre-download and final restarts. The reconnect after the restart (readiness
probe, Data Secure sync, authorize) starts again once the tunnel is back, and
the flash continues with the same step. The restart itself is not sent again
unless the link dropped before the device could have received it. An
authorize that went unanswered because the link was down is not taken to mean
"this device has no authorize", so later connections still present the key.
The retries stop 90 s after the first failure (the 60 s tunnel budget plus the
30 s readiness poll); the error then is the same as without the retry.

What is not covered: a gateway that stays unreachable longer than the budget.
If that happens during the wait after the factory reset, the device is left
reset and unloaded; a plain re-run of the same `flash` recovers it.
The flash then stops with the original error plus a hint naming the gateway
(`timed out waiting for TUNNELING_ACK; the tunnel to gateway … could not be
re-established within 60 s`), leaving the device partially written. The same
re-establish protects every other command (`apply`, `describe`, `reconstruct`,
`plan`, `write`), but only `flash` resumes its own steps: another command whose
device connection dropped during the outage fails with a connection error and
can simply be run again. A group write that was pending when the link dropped
is sent once the tunnel is back, up to a minute late.

**Recovery from a failed or interrupted flash.** The download is idempotent: it
re-unloads and rewrites the whole application, so the fix for a partial flash is
to re-run `bussard flash <ADDRESS>`. If re-flashing does not recover the device,
fall back to downloading it with ETS. Do not assume a device is functional until
a flash reports the application `Loaded` and verified.

**`flash --parameters-only <ADDRESS>`** rewrites only the parameter memory of
a device that already runs the application (issue #119); `apply` runs the same
download for the parameters that differ, after the tables. Unlike a full flash
it has something to lose, the parameters the device holds, so it works like
`apply`: it reads the parameter memory first, shows the parameters that change,
confirms (or needs `--yes`), backs the memory up to
`<dir>/captures/backups/parameters/<ia>-<unix time>.json`, writes only the
octets that differ, completes the load, restarts the device and verifies by
reading the memory back. It never unloads, never allocates a segment, never
factory-resets and never touches the link tables. It refuses before any write
when:

| What the device reports | What `--parameters-only` does |
|---|---|
| Another application (System B `PID_PROGRAM_VERSION` differs or cannot be read; System 7 code that does not match the product) | Refuses: its memory has another layout. Use a full `flash`. |
| No loaded application, or an object/LSM not `Loaded` | Refuses: there is nothing to patch. Use a full `flash`. |
| An unreadable load state or parameter segment | Refuses: the base address or the current content is unknown. |
| New values that show or hide a com-object | Refuses: the group-object table would change, and only a full `flash` rewrites it. The message names the objects. |
| System 7 links that differ from the device's tables | Refuses: the table load-state machines are not reloaded. Run `apply` first. |
| Values that already match | Prints `nothing to do`, exits 0, touches no load state. |

System 7 exposes no application id, so there the identity check is every
load-state machine `Loaded` plus the first octets of each code segment matching
the product. On System 7 the download opens LSM 3 and writes the parameter octets in
place, with no allocation record, and the executor re-reads LSM 3 right before
and writes nothing unless it is `Loaded` (issue #146). If a parameter download
fails midway and the application still reads `Loaded`, re-run it (it writes
only the octets that still differ); if it does not, recover with a full
`flash --force`. The backup file holds the memory as it was.

**`assign`** sets a device's individual address; **`adopt`** is the interactive
wizard that assigns and flashes a new device. Both are gated the same way: they
confirm on a terminal, and non-interactively they need `--yes`. An explicit
target address is not itself consent, so a scripted `assign` still needs
`--yes`; `adopt` additionally needs a product file and an explicit target
address to run without a TTY.

**Changing the address of a Data Secure device.** After the address write,
`assign` verifies by reading the device at its new address. A Data
Secure-activated device answers a plain descriptor read with mask `FFFF`, so
`assign` verifies it over `A_SecureData` with its tool key (issue #203). The
keyring lists tool keys by individual address, so it finds the key under the
new address only after ETS re-exports it. Until then `assign` takes the key
from the old address's entry and prints a note to re-export the keyring;
`--tool-key` overrides the keyring for this one verification. Re-export the
keyring from ETS after every address change of a Secure device: every later
command (`describe`, `flash`, `apply`, `scan`, `audit --live`) looks the key up
under the new address and treats the device as having none until the keyring
lists it there. Without any key, `assign` still verifies that the device
answers at the new address, reports "Data Secure activated (mask hidden), no
tool key in the keyring", and records no mask in the stub device file.

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

### Secured group writes from bussard

A secured group write from bussard reaches a receiver only if the receiver
admits bussard's tunnel address as a sender. ETS never does that on its own:
the S3 captures of issue #90 show ETS lists only device senders in the
security individual address table (PID 54), never a tunnel address. The
recommended ways, in order:

1. **Admit the tunnel address on the receivers.** Find bussard's tunnel
   address (the keyring's tunnelling user, or the address `write` names in its
   note). Program each receiver of the secured GA once with
   `bussard flash <device> --keyring <file> --secure-sender <tunnel IA>`, or
   `bussard apply <device> --keyring <file> --secure-sender <tunnel IA>` for a
   link-table-only update. The device then accepts that address with sequence
   0 and tracks its sequence from the first write on. Use the same tunnelling
   user (and so the same tunnel address) for later writes.
2. **Send through a secured device.** Write to a plain GA that a secured
   device (a logic module, a push button with a logic function) forwards to the
   secured GA. The receivers keep their ETS sender list and bussard sends in
   the clear.

Either way the next ETS download of a receiver rewrites PID 54 without
bussard's address, and `write --keyring` goes back to being dropped. The
receiver gives no error: `write` reports success and nothing moves. bussard
does not record which devices were programmed with `--secure-sender`, so after
every secured write it prints a note with its tunnel address, the receivers
the model links to the GA, and the command above.

## Protected group addresses

A GA marked `protected = true` in `groups.toml` (wind alarms, central functions,
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
also no tool parameter that sets or clears `protected`; only a human editing
`groups.toml` can. Any change that touches a protected GA is rendered with the
sentence "This group address is protected." and sorted to the top of
`bussard status`, so it is the first thing anyone reads.

`bussard test` runs scripted writes, so it takes the same rails as `bussard
write` (the non-loopback gateway gate and a confirmation naming the gateway),
and a protected GA needs two opt-ins instead of one: `allow_protected = true` in
`tests.toml` and `--force` on the command line. With either missing, the test
is reported as refused and nothing is written to that GA. The `knx_run_tests`
MCP tool refuses such a test whatever the file says. `bussard learn` never
transmits at all.

## MCP programming tier

`bussard mcp --allow-programming` exposes the single-device table write of
`bussard apply` to an assistant. It is off by default and never available with
`--passive`. Every gate the CLI has applies, plus one the CLI does not need:

1. **Write gate.** A non-loopback gateway needs `BUSSARD_ALLOW_REAL_GATEWAY=1`
   or `--allow-remote-gateway`. The server refuses to start without it, and
   both tools check it again on every call. The policy is the same code the CLI
   runs.
2. **Source-address check.** Both tools run the probe described in
   [Source address check](#source-address-check) before they open a connection.
3. **Plan digest.** `knx_plan_device` reads the device and returns the plan the
   CLI prints plus a `plan_digest`: a SHA-256 over the device address, the
   model's links for it, the desired tables and the live tables it read.
   `knx_apply_device` writes only when that digest was produced by the same
   server session within `--plan-ttl-minutes` (default 10), and a fresh read of
   the device, with the current model, reproduces it. If the device was changed
   by ETS or another tool, or the model was edited, the apply is refused and the
   digest is retired. A digest is single use. The plan also carries a
   `state_hash` of the device state read (the same fingerprint `bussard plan
   --json` prints); `knx_apply_device` with `plan_hash` refuses when a fresh
   read no longer produces it. The digest stays required either way.
4. **Human approval.** Both tool descriptions tell the assistant to show the
   plan to the human and to call `knx_apply_device` only after an explicit yes
   in the conversation. The digest makes this checkable: an apply can only
   write what a plan showed.
5. **Protected GAs.** A plan whose additions or removals touch a
   `protected = true` GA is refused. There is no override over MCP.

An apply then runs exactly the CLI rails: the pre-apply backup to
`captures/backups/` (no backup, no write), a history snapshot
`mcp knx_apply_device <address> <digest>` that names the gateway (the audit
line in `bussard history`), the write, and a read-back verify. The result
carries the verify outcome and the backup path. One device per call, tables
only: the parameter half of `apply`, `flash` and `apply --line` stay CLI-only.

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

Snapshots carry the model files (`bussard.toml`, `groups.toml`, `bussard.lock`,
`devices/*.toml`, and `tests.toml` and `ha.toml` when present) and nothing else. Product data, captures,
keyrings and project files are never copied into them, so a snapshot cannot
leak a key, a password or vendor data.

A `.bussard` bundle from `bussard export` (or `knx_export_bundle`) holds those
same model files, the history snapshots and a manifest, and nothing else. It
never contains `models/`, `vendor/`, `captures/`, keyrings, `.knxproj` or
`.knxprod` files, or `.env`, because the export copies an allow-list rather
than skipping a deny-list. The manifest names these exclusions. `bussard.toml`
does travel with it, so the recipient sees your gateway address; an import into
an existing model keeps the recipient's own `bussard.toml`. Importing a bundle
writes files only and snapshots first; nothing reaches a device until someone
runs `plan` and `apply`.

## Source address check

Every command that opens a connection to a device (`scan`, `assign`, `adopt`,
`describe`, `plan`, `apply`, `flash`, `reconstruct`, `backup`, `restore`,
`replace`, `commission`, `audit --live`, `plan --line` / `apply --line`, and the
MCP tools `knx_plan_device` / `knx_apply_device`)
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

On a KNXnet/IP Secure interface each slot is bound to a tunnelling user. With
`--keyring` bussard picks a user whose slot is free; with `--secure-user` the
slot is fixed by the user you name, so pick one Home Assistant does not hold.

**Keyring without a device entry (issue #189).** On a secure-only interface
every command needs the keyring, if only to open the tunnel. A device the
keyring lists is managed over KNX Data Secure with its tool key. A device the
keyring does not list is managed in the clear through the encrypted tunnel,
exactly as through a plain interface. A device whose model file says
`security.activated: true` is never tried in the clear: without a keyring
entry the command refuses before anything is sent to it. A device the model
does not mark activated but that is activated on the bus refuses the plain
access; the command fails with the hint to export a current keyring from ETS.
`connection.keyring` in `bussard.toml` sets the keyring once for every
command; the password stays in `BUSSARD_KEYRING_PASSWORD` and the keyring file
stays out of git.

## Known limitations

- **KNX Secure: Data Secure tool access, verified on a physical device;
  KNXnet/IP Secure tunnelling implemented, not yet run against real
  hardware.** `bussard` can program a KNX Data Secure
  device through its tool key (`--keyring <file.knxkeys>` with
  `BUSSARD_KEYRING_PASSWORD`, or `--tool-key` for tests) on `flash` and
  `apply`, and read one back with `describe`, `plan` and `reconstruct`;
  `bussard keyring` inspects an ETS export. Each secured
  connection starts with the same S-A_Sync handshake ETS uses, and a secured
  `flash` or `apply` also programs the security object (group key table,
  group-object security flags). The crypto, the handshake and the
  security-object bytes are calibrated against an ETS 6.4.1 capture of a
  physical device (every frame verifies; the group key table and flags
  bussard builds equal the ones ETS wrote), the full path runs against the
  knx-sim activated device, and on 2026-09-24 a secured `describe`, a no-op
  `apply` and a full `flash` with factory reset and security object completed
  on a physical activated push-button module. After a restart it triggers,
  bussard probes the device with a plain descriptor read and retries the Sync
  request before giving up, because the security layer comes up later than the
  transport layer. Still inferred (one device, one group key): the packing of
  several group-key entries and the meaning of the security-flag bits beyond
  `0x03`. Secured group communication (`monitor`, `capture`, `read`, `write`
  with `--keyring`, [#172](https://github.com/tmbo/bussard/issues/172)) runs
  against the knx-sim secured group object; the group-address CCM nonce is
  confirmed by the capture's broadcast S-A_Sync frames, but no secured group
  telegram of a real device has been verified yet.
- **KNXnet/IP Secure tunnelling** ([#71](https://github.com/tmbo/bussard/issues/71)
  Phase B). A secure-only interface needs a tunnelling user: `--keyring`
  (automatic, see the [reference](reference.md#knxnetip-secure-tunnelling)) or
  `--secure-user <id> --secure-password-env <VAR>`. Without either, bussard
  refuses at once and names the cause instead of retrying
  ([#182](https://github.com/tmbo/bussard/issues/182)). The frame layouts, the
  DIBs and the interface's authentication MAC are checked against an ETS
  capture of the Jung interface, and the whole path (flash of a Data Secure
  device inside a secure tunnel, wrong password, reconnect) runs against the
  knx-sim secure interface; the first session against real hardware is still
  to come. Start with a read-only `monitor --keyring` against the interface
  before any write. What the wire cannot yet confirm: the MAC input of the
  wrapped frames (a mismatch shows as a refused authentication, never as a
  wrong write) and the interface's idle timeout (bussard sends a keepalive
  every 30 s, `BUSSARD_SECURE_KEEPALIVE_SECS` changes it; `bussard test
  --secure-idle <secs>` measures the timeout read-only). An interface without
  a TCP endpoint gets a UDP session ([#197](https://github.com/tmbo/bussard/issues/197)),
  implemented from the KNX specification and verified against knx-sim only.
  Secure routing (multicast) is not implemented. The tunnel
  slots on a secure interface belong to users: each ETS tunnelling user has
  its own tunnel address, and bussard picks a free one from the keyring.

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

The opt-in is per machine on purpose. The question it answers is "is this computer meant to write to real buses?", and only the machine knows that. A setting in `bussard.toml` would travel with the model: into every bundle handed to a customer, every repository clone, and every assistant session started on that model. The owner who imports the handover bundle would receive an armed tool without choosing it. Keep the variable out of `.env` files that live next to a model for the same reason.

### Share the interface with ETS

An integrator often has ETS and bussard open against the same interface. The [tunnel budget](#the-tunnel-budget) section explains the slot count and exit code `4`. On top of that:

- Check the budget before the session. `bussard init --gateway <ip>` or `bussard audit --live` prints `N tunnels, M in use`. Home Assistant or a visualisation server usually holds one slot permanently.
- Close the ETS bus connection before a long bussard run such as `apply --line` or `commission`, and close bussard before an ETS download. Each running bussard command holds a slot, and so do `bussard mcp` and `bussard viz` for as long as they run.
- Never program one device from both tools at once. A device accepts one management connection at a time, so a second tool's download fails or interleaves with the first. Finish in one tool, then plan in the other: `bussard plan <ia>` after an ETS download shows exactly what ETS left on the device.
- After a crash, a tunnel slot stays taken until the interface times it out, about two minutes. Wait instead of retrying in a loop.
