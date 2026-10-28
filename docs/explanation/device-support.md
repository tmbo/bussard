# Device support

bussard refuses a device it cannot program safely before it writes anything,
rather than attempting and rolling back. This page lists which devices each
command supports, the checks that protect a management session, and what is
not supported yet.

## Supported device masks

A device's mask is the code it reports for its system family, such as `07B0`
for System B on twisted pair. Write commands refuse an unsupported mask in the
pre-flight, before any write. Support differs by command, and `bussard audit`
uses the same table.

<!-- mask-table:start -->
| Mask | Family | Medium | `plan` / `apply` | `flash` | `reconstruct` | `describe` | Notes |
|---|---|---|---|---|---|---|---|
| `0010` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0011` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0012` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0013` | System 1 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0020` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0021` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
| `0025` | System 2 | TP1 | no | no | no | yes | classified but unsupported; program it with ETS |
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

One exception to the `flash` column: on mask `0021` (the Jung IPS 300 SREG
KNX IP interface) `flash` runs an application whose load procedure holds only
property compares and writes. It loads no object, never factory-resets the
interface, and ends with a read-back of every property it wrote.

- **`flash`** supports System B (`07B0`, and the `57B0` / `27B0` KNX-IP and
  RF variants) and System 7 (`0705` / `0701` / `0700`). Another family, a mask
  that differs between application and device, or a load procedure with an
  operation bussard cannot execute refuses the procedure rather than leaving a
  device half-flashed.
- **`apply`, `plan` and single-device `reconstruct`** support System B
  (`x7B0`) and System 7 (`0705` / `0701`). Another mask is refused with a
  message naming the mask and the supported families; line-mode `reconstruct`
  records it as a stub instead.
- **System 7 tables without product data.** These three commands run without
  a `.knxprod`, so they assume the usual table addresses. A device that keeps
  its tables elsewhere reads back as an empty table set, never as wrong links,
  and must be programmed with `bussard flash`, which takes the addresses from
  the product data.
- **System 7 `apply` needs product data.** Each table write ends with a
  record naming the application it belongs to (PEI type, manufacturer,
  application number and version), taken from the product data. Without it,
  `apply` refuses before it connects; `plan` still runs.
- **System 7 communication flags.** A System 7 device ignores every telegram
  for an object whose communication flag is off, and ETS switches it off on
  every object without a link. So a new link on such an object only works once
  its flag is on. With the device's product data, `apply` switches the flag on
  for each newly linked object and off for an object that loses its last link,
  and `plan` lists each switch. `apply --line` does the same with each
  device's pinned product data. Without product data bussard does not know
  where the group-object table is: `plan` names each newly linked object whose
  flag it could not check. A device that refuses the read of its group-object
  table is handled the same way; its tables are still read.
- **System 7 restart.** Like ETS, `apply` restarts a System 7 device after
  writing its tables (a basic restart). It waits for the device to answer
  again, then reads the tables back, so the read-back also shows that the
  write survived the restart.

??? note "Details"
    On System B each table lives in a segment the device allocates: `apply`
    opens the table object, requests a segment with `LdCtrlRelSegment`, reads
    the placement from `PID_TABLE_REFERENCE` and writes the image there. It
    never writes the `PID_TABLE` property array, which real devices refuse.
    On System 7 the tables are the memory regions at `0x4000` (address table)
    and `0x4201` (association table), or wherever the product's load
    procedure puts them. `apply` follows the order of ETS 6.4.1's table-only
    downloads: `Unload` on LSM 1 and 2, then each table loaded to completion
    in turn, then, when a flag changes, the group-object table inside a
    `StartLoading`/`LoadCompleted` bracket on LSM 3 (no `Unload`), then a
    basic restart. It never rewrites the parameters or the application. The
    address table is written alone and may fill its segment and no more: the
    product's segment size, else up to the association table the device
    reports or the product places. With none of these known (no product data,
    and a device that does not answer `PID_TABLE_REFERENCE`), the table may
    be rewritten at its current length but not grown, and `plan` says so.
    Every System 7 table read is bounded the same way: a
    count octet claiming more entries than the region holds (virgin EEPROM
    reads `0xFF`) is refused, and an image that would not fit is refused
    before anything is written.

    The group-object table is not behind the address table: the program
    declares it in a segment of its own (`<ComObjectTable>`), on the Ekinex
    EK-E72 at `0x41D8`. `apply` reads it there. When a flag changes it
    rewrites the whole table from the image it read, with only those flag
    octets changed, as ETS does, and reads the table back. It refuses to do
    so on a device whose application (LSM 3) is not `Loaded`.

## Source address check

Every command that opens a connection to a device first checks that no device
answers at the individual address bussard itself sends from: the address the
gateway assigned to the tunnel, or `0.0.255` on routing. If one answers, the
command refuses before touching anything:

```console
refusing to continue: a device on the bus (mask 07B0) already answers at
1.1.255, the individual address this connection would use as its source.
```

A device tells its management clients apart by source address and nothing
else. With a real device at bussard's address, both parties' telegrams land
in one session at the target, and a memory write can be applied for the wrong
one while both sides see an acknowledgement. That is silent corruption, so
bussard checks first, as ETS does.

The check costs one telegram and about 0.6 seconds. The fix is almost always
on the gateway: give the tunnel an individual address no device owns, since
many gateways ship with a default that collides on a busy line.
`--skip-address-check` turns it off for a gateway that misbehaves on the
probe; nothing else disables it.

It runs once per tunnel. `flash`, `apply` and `restore` hold one tunnel for
the pre-flight and the write, so they check once; `commission` and `replace`
open several and check on each. Group-only commands (`read`, `write`,
`monitor`, `capture`, `learn`, `test`) open no device connection and skip it.

The check proves only that no device answers. It cannot see a second passive
tool on the same address, such as another bussard on routing or an ETS session
on a second tunnel, and it reports free when the reply is not a device
descriptor.

??? note "Details"
    The commands that check are `scan`, `assign`, `adopt`, `describe`, `plan`,
    `apply`, `flash`, `reconstruct`, `backup`, `restore`, `replace`,
    `commission`, `audit --live`, `plan --line` / `apply --line`, and the MCP
    tools `knx_plan_device` and `knx_apply_device`. Only an
    `A_DeviceDescriptor_Response` counts as proof. Under `--yes`, `flash` also
    keeps the pre-flight's device connection for the write phase.

## The tunnel budget

A KNXnet/IP tunnelling interface has a fixed number of connection slots,
often one to five. Each client holds one while connected: Home Assistant's KNX
integration permanently, ETS while a project is online, and every running
bussard command, including `bussard viz` and `bussard mcp`. A second bussard
command started while the first runs needs a second slot.

When every slot is taken, bussard reports it as its own condition, not a
timeout, and exits with code `4` (illustrative output):

```console
error: 192.0.2.10:3671 has no free tunnelling connection (E_NO_MORE_CONNECTIONS).
A KNXnet/IP interface has a fixed number of tunnel slots, ...
```

Retrying does not help until a slot is free. Close another client, wait about
two minutes for a crashed one's slot to time out, or run a long-lived observer
over routing if the interface supports it. `bussard init --gateway <ip>` and
`bussard audit --live` print `N tunnels, M in use`. A write never retries into
a full interface, so the refusal comes before anything reaches a device.

On a KNXnet/IP Secure interface each slot belongs to a tunnelling user. With
`--keyring`, bussard picks a user whose slot is free and that no other bussard
process on this host holds, and moves on when the interface refuses one. With
`--secure-user` you fix the slot, so pick one Home Assistant does not hold.

**Reconnecting is not a write.** `knx_bus_reconnect` drops the MCP server's
connection to the interface and opens a new one. Nothing is sent onto the KNX
bus, so it needs only the read tier; in `--passive` mode the server
reconnects on its own. A tool that writes while the bus is down is refused
with the last connection error, never queued: a waiting frame is dropped
after 2 seconds.

## Known limitations

- **KNX Data Secure.** bussard programs a Data Secure device with its tool key
  on `flash` and `apply`, and reads one back with `describe`, `plan` and
  `reconstruct`. The handshake and security-object bytes match ETS, and a full
  flash has completed on a real activated device. Two parts are inferred from
  one device with one group key: the packing of several group keys, and the
  security-flag bits beyond `0x03`. Secured group communication (`monitor`,
  `capture`, `read`, `write` with `--keyring`) is verified against the
  simulator only.
- **KNXnet/IP Secure tunnelling.** A secure-only interface needs a tunnelling
  user, from `--keyring` or `--secure-user <id> --secure-password-env <VAR>`;
  without either, bussard refuses at once and names the cause. The frames
  match an ETS capture and the whole path runs against the simulator, but no
  session against real hardware has run yet, so start with a read-only
  `monitor --keyring`. A mismatch would show as a refused authentication,
  never as a wrong write.
- **Secure session keepalive.** Some interfaces drop a session idle for 60
  seconds, so bussard sends a keepalive every 30 seconds
  (`BUSSARD_SECURE_KEEPALIVE_SECS` changes it; `bussard test --secure-idle
  <secs>` measures an interface read-only). An interface without a TCP
  endpoint gets a UDP session only with `--secure-transport udp`.
- **Not implemented:** secure routing (multicast), activating or deactivating
  Data Secure on a device, and activation from the FDSK certificate. Use ETS.

## Next steps

- [Find what you have](../how-to/find-what-you-have.md): scan, audit and free tunnel slots.
- [Device commands](../reference/commands/devices.md): `scan`, `describe`, `reconstruct` and their flags.
- [What each write command does](write-commands.md): the rails of each write.
- [KNX Secure](knx-secure.md): keys and what activated means.
