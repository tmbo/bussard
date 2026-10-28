# What each write command does

Every write command refuses on any doubt before it writes, and reports
"verified" only after a read-back matches the model. This page lists, per
command, what it writes, refuses, backs up and verifies. A refusal exits
non-zero before anything is written; the confirmation and real-gateway rules
are on [Safety](safety.md).

!!! warning
    Every command on this page transmits on the bus. Point it at the
    simulator or a bench device until you trust it.

Without a terminal or `--yes`, `assign`, `adopt`, `replace` and `commission`
refuse before opening a connection, because their first bus step acts on the
device in programming mode. The other write commands first show what they
would change, then refuse at the prompt.

## `write` sends one group value

- **Writes** a single group value (`on`/`off`, `up`/`down`, a number, a
  percentage). Nothing is stored on a device, but actuators move.
- **Refuses** a protected group address without `--force`, and a secured
  group address it holds no key for.
- **Confirms** with the address, the decoded value and the gateway, and
  **verifies** only that the interface acknowledged the telegram. A group write has no reply from the device, so neither bussard nor
  an assistant may report that the device executed it.

## `apply` writes links and parameters

- **Writes** the device's link tables (the group address and association
  tables) and, when `bussard.lock` pins the product data or `--product` is
  given, the parameter octets that differ. Tables are rewritten wholesale, so
  re-running `apply` is idempotent. A device that already matches is not asked
  about and not written.
- **Refuses**, before the bus is touched, a model that fails validation, a
  pinned archive that is missing or changed, and a `--product` or
  `--application` that contradicts the lock without `--force`. It refuses a
  device whose application id or mask differs from the lock, naming the
  `bussard flash` it needs, and a parameter change that shows or hides a
  com-object. With `--plan <hash>` it refuses a device that no longer matches
  the `state_hash` of the approved plan (`plan --json`).
- **Backs up** the pre-apply tables to
  `<dir>/captures/backups/<ia>-<timestamp>.json`, and the parameter memory to
  `<dir>/captures/backups/parameters/` when parameters change. If a backup
  cannot be written, the apply refuses.
- **Verifies** by reading the tables and parameters back. A System 7 table
  write ends with a basic restart, as in ETS, and the read-back waits for the
  device to answer again.

The prompt reads `apply these N changes to <ia> through <gateway>? [y/N]`. To
go back, re-apply from the model or `restore` the backup. The parameter half is
[the parameter-only download](../reference/commands/programming.md#parameter-only-download).

**Device-managed parameters** (`Access="None"`, owned by the application at
runtime) always differ from the model. A plan with only those differences is
"nothing to write"; alongside another write they are written at the model's
value, as ETS does.

## `backup` and `restore`

`bussard backup` is read-only on the bus. It reads every model device into
`<dir>/captures/backups/<UTC timestamp>/`, one JSON file per device plus a
`manifest.json` that lists every device, including `skipped` (a mask bussard
cannot read), `unreachable` and `failed` (exit 1). On System B it includes the
parameters; on System 7 it cannot. `apply` hints while no snapshot exists.

`bussard restore <backup-dir> <ADDRESS>` is `apply` with the backup as the
desired state: the same plan, confirmation, pre-write backup, verify and gate.
It writes link tables only. A fresh backup restored onto an unchanged device
plans empty and writes nothing.

`bussard restore --parameters <backup.json> <ADDRESS>` replays a parameter
backup with the parameter-only download. It refuses a backup of another
device, application or mask, and a device that does not run the application.
It writes only placed octets, keeps device-managed octets as the device holds
them, backs up what it overwrites and verifies by read-back.

## `restart` restarts one device

`bussard restart <ADDRESS>` restarts the device the way ETS's *Restart device*
does: the device re-runs its application, as a power cycle of that one device
would. Parameters, tables and the address stay. It is what a device needs when
it should take up a change at startup.

- **Asks** once, naming the device and the gateway, behind the real-gateway
  gate.
- **Picks the form ETS picks** from the product data: a secure-capable
  System B application gets the confirmed restart (master reset, erase code
  1), which the device answers; every other device gets a bare `A_Restart`,
  which it does not answer.
- **Verifies** a confirmed restart by its answer: only error code 0 counts,
  and no answer or another code exits 1. A basic restart cannot be verified,
  so it is reported as sent, not as restarted.
- **Checks the device comes back** by reconnecting until it answers its
  descriptor read again with the mask it reported before the restart. A
  device that stays silent past `--timeout` (30 s), or comes back as another
  mask, exits 1.
- **Acts on the bus**: a device may transmit its status objects as it starts,
  as it does when bus voltage returns. Anything that listens to those
  addresses sees them.

## `flash` downloads an application

- **Writes** a whole application program: parameters at the vendor defaults
  plus the device file's values, and the address, association and
  group-object tables from the model's links. The image comes from the archive
  `bussard.lock` pins under `products/`, checked by its SHA-256, or from
  `--product`.
- **Refuses** before any bus access a pinned archive that is missing or
  changed, and a `--product` or `--application` that contradicts the lock
  unless `--force` (which then pins it). Identity drift against the lock is
  printed, not refused: a flash is how it is fixed.
- **Backs up nothing.** A factory-fresh device has no prior application to
  save, and the command says so before it writes:

  ```console
  NOTE: a first flash assumes the device is factory-fresh; no backup is
  possible (there is no prior application to save). Recovery from a failed
  flash is re-running `bussard flash`.
  ```

- **Verifies** that the application reads back as `Loaded` after the restart
  and spot-checks the written segments.

**The freshness check.** Because there is no backup, the read-only pre-flight
reads the device's load state (whether an application is loaded) first:

| What the device reports | What `flash` does |
|---|---|
| No application loaded | Proceeds: the device is factory-fresh. |
| An object left `Loading` or in `Error` by an interrupted flash | Proceeds: re-flashing is the recovery. |
| The same application already loaded | Proceeds without `--force`, with a notice. |
| A different application loaded | Refuses; `--force` overrides. |
| An application it cannot identify | Refuses; `--force` overrides. |
| A load state it cannot read | Refuses as unknown; `--force` overrides. |

A refusal names the resident application and the ways forward: capture the
device first (`reconstruct`, or `apply`, which backs up), or `--force`, which
prints one loud line naming device, gateway and what is destroyed. Unreadable
is never fresh. System 7 has no application id, so a loaded System 7 device
always needs `--force`.

**The factory reset (System B).** Many applications write only the octets
that differ from a fill byte, so on a re-flash the octets the new image leaves
out keep the old image's values. `flash` therefore opens such a download of a
secure-capable application, and any `--force` over an unknown one, with a
confirmed factory reset, as ETS does: it
keeps the individual address, erases application, parameters and links, waits
for the reboot (at most a minute) and streams every object in full. A device
that refuses or ignores the reset fails the flash before anything is written.
Pass `--no-factory-reset` only for a device you know holds no stale image.
System 7 downloads write every region in full and never reset. An
application that is not secure-capable is never reset either: ETS sends it no
master reset, only the download's own unloads, and ends its download with a
bare `A_Restart`.

**Recovery.** The download is idempotent: re-run the same `bussard flash
<ADDRESS>`, and fall back to ETS if that fails. A device is not functional
until a flash reports the application `Loaded` and verified.

**Connection loss.** A flash survives a dropped device connection and a lost
tunnel of up to 60 seconds, and resumes the current step. Longer, it stops
with a hint naming the gateway and the device partly written: re-run it.
`apply`, `describe`, `reconstruct`, `plan` and `write` reconnect too but do not
resume; run them again. A pending group write goes out up to a minute late.

??? note "Details"
    - **Load-state reads.** System B: `PID_LOAD_STATE_CONTROL` of the
      application objects (types 3 and 4) and the application id in
      `PID_PROGRAM_VERSION`; other objects only when no application object
      reports a state. System 7: each load-state machine.
    - **Reset.** Master reset, erase code 7. `flash` waits the reboot time the
      device reports, reconnects and streams every object; the differential
      download that skips matching objects does not apply after a reset.
    - **Load-state changes** are confirmed by the state in the device's
      answer, as ETS does, else read back. After the restart `flash` re-reads
      the application object's state; a segment whose MCB CRC check passed is
      not sampled again. If the application is not `Loaded`, everything is read.
    - **Restart timing.** It waits the reported process time, then probes from
      0.5 s after it (1.5 s of quiet after a bare `A_Restart`). A probe waits
      500 ms for the acknowledgement and up to 2 s for the answer; a negative
      `L_Data.con` means "not up yet". `flash -v` prints readiness per restart.
    - **Reconnect.** An unacknowledged frame or a failed heartbeat logs
      `gateway connection lost`; bussard sends a DISCONNECT, retries after 1,
      2, 4, 8, 8 ... s, logs `gateway connection re-established` and re-sends
      the frame. A chunked write resumes from the last confirmed chunk.
      `BUSSARD_TUNNEL_RECONNECT_SECS` changes the 60 s (`0` turns it off).
      Waits on a restart are covered too; the restart is not re-sent unless the
      link dropped before the device could receive it. Retries stop 90 s after
      the first failure.
    - **Secure tunnel over TCP.** After 5 s of silence it sends a
      CONNECTIONSTATE_REQUEST and treats 2 more silent seconds as a lost link.
      `BUSSARD_TCP_READ_DEADLINE_MS` changes the 5 s (`0` turns it off).

## `flash --parameters-only` patches parameters

- **Writes** only the parameter octets that differ, on a device that already
  runs the application, then completes the load and restarts the device. It
  never unloads, allocates, factory-resets or touches the link tables. `apply`
  runs the same download after the tables.
- **Backs up** the parameter memory to
  `<dir>/captures/backups/parameters/<ia>-<unix time>.json` after showing the
  changes and confirming.
- **Verifies** by reading the memory back.

It refuses before any write when:

| What the device reports | What it does |
|---|---|
| Another application, or an id it cannot read | Refuses: the memory has another layout. Use a full `flash`. |
| No loaded application, or an object not `Loaded` | Refuses: nothing to patch. Use a full `flash`. |
| An unreadable load state or parameter segment | Refuses: the base address or content is unknown. |
| New values that show or hide a com-object | Refuses and names the objects: only a full `flash` rewrites the group-object table. |
| System 7 links that differ from the device | Refuses: run `apply` first. |
| Values that already match | Prints `nothing to do` and exits 0. |

**What a partial write touches.** As in an ETS download, only the octets a
parameter is placed in under the current configuration; any other octet keeps
the device's value, listed as "ETS does not write this octet in a download". A
full `flash` writes every octet. If a download fails midway and the
application still reads `Loaded`, re-run it; if not, use `flash --force`.

??? note "Details"
    On System 7 the identity check is every load-state machine `Loaded` plus
    each code segment's first octets matching the product (without a code
    segment, the load-state machines alone, which the pre-flight says). The
    download writes in place after re-reading LSM 3 as `Loaded`.

## `assign` and `adopt` set an address

- **Writes** the individual address: the optional `ADDRESS`, else the next
  free one on the line. `adopt` also writes the device file and prints the
  `flash` command; it does not flash.
- **Verifies** by reading the device at its new address.

**A Data Secure device** answers a plain read with mask `FFFF`, so `assign`
verifies over Data Secure, with the tool key of the old address's keyring
entry or `--tool-key`, and asks you to re-export the keyring from ETS: later
commands look the key up under the new address. Without a key it only checks
that the device answers, and records no mask.

**Adopting a Data Secure device only reads.** When the keyring lists it,
`adopt` refuses any target address but the device's own, writes nothing, and
reads the identity, tables, parameters, security flags and sender table, kept
in the lock (`secure_senders`) so a later secured download keeps those
senders. Press the button to leave programming mode. An activated device the
keyring does not list fails before any file is written.

## `replace` swaps a dead device

- **Writes** through the `assign`, `flash` and `apply` paths in turn, after
  one confirmation naming the gateway, flashing from the pinned archive or
  `--product`. It records `replaced: <date>` in the device file.
- **Refuses** when the old device still answers, when the new device's order
  number or mask differs from the device file, and with `--no-flash` when it
  runs another application than the lock pins, unless `--force`. A missing
  pinned archive refuses before the bus is touched.

## `commission` and whole-line runs

`commission --line` and `apply --line` ask one confirmation for the run,
naming the gateway and the number of devices. Each device still gets every
single-device rail: `apply --line` backs up and verifies each one, and
`commission` refuses to address a device whose order number does not match
the model. A failed device is reported and the run moves on. `apply --line`
records each outcome in `<dir>/captures/apply-line-<line>.json`, so `--resume`
skips finished devices after an interruption; a clean run deletes the file.

## `test` runs scripted writes

`bussard test` takes the rails of `write`: the real-gateway gate and a
confirmation naming the gateway. A protected address needs both
`allow_protected = true` in `tests.toml` and `--force`; otherwise the test is
reported as refused. `bussard learn` never transmits.

## Secure downloads program the security object

A Data Secure device keeps its group keys and per-object security flags in
its security object, not in the link tables. With `--keyring` (or
`--tool-key`), `flash` reloads that object after the tables and parameters,
the way the ETS secured download does. `apply --keyring`, `restore` and
`apply --line` with a keyring rewrite it next to the tables, because the key
table indexes the address table.

- **Refuses** the plan when a group address the model marks `secure` has no
  key in the keyring. Use the project's current keyring. `--tool-key` carries
  no group keys, so it suits only a device without secured addresses.
- **Prints** each step in the dry run, never key bytes, and **keeps** the
  factory reset: the device keeps its tool key across it.

??? note "Details"
    The object is unloaded after the other objects, then reloaded with the
    security individual address table (PID 54: cleared, then one
    `[IA][sequence]` per device that sends on a secured address this device
    listens to, with the keyring sequence number when the sender is
    `activated`, else 0), the group key table (PID 53) and the group-object
    security flags (PID 61), then completed. After a restart `flash` probes
    with a plain `A_DeviceDescriptor_Read` every 500 ms for up to 30 s, then
    sends the S-A_Sync_Req on that connection. An unanswered Sync_Req is
    repeated up to five times (1, 2, 4, 8 s backoff) after a restart and three
    times (1, 2 s) otherwise, then the flash stops with "did not answer the
    Data Secure sync request".

## Secured group addresses need an admitted sender

A device with a secured group object ignores a plain telegram on its address.
`write`, `read`, viz and the assistant send to a secured address over Data
Secure when the keyring holds its group key or `groups.toml` marks it
`secure = true`. A secured address without a key is refused before anything is
sent; a secured `read` accepts only a response that verifies under the key.

A receiver accepts a secured telegram only from a sender in its sender table.
If bussard's tunnel address is missing, the device drops the telegram
silently: `write` reports success and `read` times out. bussard checks each
linked device's sender table recorded in the lock, else an ETS assignment of
the address to the tunnelling address in the key store. When every linked
device has a table and none lists the tunnel address, the write is refused;
when the evidence is unknown, it is sent and the result says delivery is not
confirmed. To admit the tunnel addresses, in order of preference:

1. Set `admit_tunnel_senders = true` under `[connection]`. `plan` lists a
   change on each device that lacks one, and `apply` adds every tunnelling
   address of the key store at sequence 0, recording the table in the lock.
2. Pass `--secure-sender <tunnel IA>` on `flash` or `apply` for one run.
3. Assign the addresses to the tunnelling addresses in ETS, download the
   receivers from ETS and re-import the keyring.
4. Write to a plain address a secured device forwards to the secured one.

Options 1 and 2 widen who the device trusts, so both are off by default and
the next ETS download of a receiver removes the tunnel addresses again.

## Switching Data Secure off for one group address

`bussard groups secure <GA> off` lets a Secure device run one address plain,
for example for a non-Secure sender:

1. The key store, `groups.toml` and the lock drop the key and the `secure`
   flags, in one snapshot `bussard undo` restores, key included. It needs
   `BUSSARD_KEYRING_PASSWORD`, and is refused while a linked object also
   links another secured address.
2. `bussard plan <ia>` on each linked device lists the change; `apply`
   rewrites the tables and the whole security object.
3. Every other keyring user (Home Assistant, ETS) keeps sending secured, which
   the device drops. Run `bussard keys export` and load the export there.

`on` keeps the store's key or generates one, and is refused while a linked
device cannot run Data Secure. An ETS re-import or old keyring brings `secure`
back, with a warning naming the devices: change it in ETS too.

## Switching KNXnet/IP Secure of an IP interface

`bussard interface secure on|off <ia>` switches a KNX IP interface between
plain and secure tunnelling the way ETS does. Its sequence matches ETS
offline but has not yet run against a live interface.

- **Credentials** live in the key store, never the model. `on` needs the
  FDSK there and takes the tool key, authentication code, management password
  and a tunnelling user per `[knxnet] tunnels` address, generating and saving
  any missing one before the first write.
- **Refuses** `on` when the interface already reports secure-only tunnelling;
  `on` runs over a plain tunnel to a device in factory state. `off` needs the
  tool key, and through a secure session with the interface itself it needs
  `--allow-self-reconfigure`. The store drops the tool key only after the
  device verified on its FDSK.
- **Verifies** on a fresh connection under the key the device should now hold:
  the security mode, the tunnelling users after `on`, and through the
  interface itself its secured service families.

If a switch stops half way, the device holds every step before the one the
error names and the store keeps its credentials (the previous store is
`bussard.keys.bak`): retry. If no stored credential reaches it, press its
reset button to return it to its FDSK and plain tunnelling, then run
`interface secure on` again, or `bussard keys import` an ETS export.

## Next steps

- [Programming commands](../reference/commands/programming.md): every flag of `apply`, `flash`, `restore`, `replace` and `restart`.
- [Back up and replace](../how-to/back-up-and-replace.md): backups, restores and a dead device, step by step.
- [KNX Secure](knx-secure.md): keys, the key store and what activated means.
- [Device support](device-support.md): which masks each command supports.
