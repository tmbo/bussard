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
| `0021` | System 2 | TP1 | no | property-only | no | yes | classified but unsupported; program it with ETS |
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

The `flash` column reads `property-only` on mask `0021` (System 2, such as
the Jung IPS 300 SREG KNX IP interface): `flash` runs an application there
only when its load procedure holds property compares and writes alone. It loads no object, never
factory-resets the interface, and ends with a read-back of every property it
wrote. Every other System 1 and System 2 download (BCU1, BCU2: memory
allocation and table writes) is refused before anything is written; program
those devices with ETS.

- **`flash`** supports System B (`07B0`, and the `57B0` / `27B0` KNX-IP and
  RF variants), System 7 (`0705` / `0701` / `0700`) and the property-only
  procedures on `0021`. Another family, a mask
  that differs between application and device, a System B device whose
  manufacturer is not the application's, or a load procedure with an
  operation bussard cannot execute refuses the procedure rather than leaving
  a device half-flashed. A System B device with no links in your project gets
  empty address and association tables, as ETS writes them, and then reacts
  to no group telegram.
- **`apply`, `plan` and single-device `reconstruct`** support System B
  (`x7B0`) and System 7 (`0705` / `0701` / `0700`). Another mask is refused
  with a message naming the mask and the supported families; line-mode
  `reconstruct` records it as a stub instead.
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
- **System B communication flags.** The same holds on System B: a full flash
  clears the flag of every object your project does not link. With the device's
  product data, `plan` reads the group-object table and compares it with the
  table a full flash would write; when they differ, `apply` reloads the table
  before the link tables and reads it back, and `plan` names each object whose
  descriptor changes. `apply --line` does the same. Without product data `plan`
  names each newly linked object whose flag it could not check. No ETS capture
  of such a partial download exists yet, so the order follows the KNX
  standard's partial download of the group-object table.
- **System 7 restart.** Like ETS, `apply` restarts a System 7 device after
  writing its tables (a basic restart). It waits for the device to answer
  again, then reads the tables back, so the read-back also shows that the
  write survived the restart.
- **System 7 load-state machines.** A System 7 device has four load-state
  machines (address table, association table, application, PEI program).
  Some products name a fifth in their load procedure; `flash` sends no record
  for it, as ETS sends none.

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

## Supported devices

The mask says whether bussard can talk to a device at all. The list of
supported devices says whether bussard has checked what it writes to that
product: it names each application program whose download bussard has
compared with ETS, by the application id `bussard.lock` pins and the device
reports. `bussard device --supported` prints it.

- **`capture`**: the offline oracle is identical against an ETS download of a
  real device.
- **`synthetic`**: a fabricated test product, identical against its ETS
  capture.
- **`live`**: flashed by bussard on a real device and read back.

`flash`, `apply` (also `--line`), `restore`, `replace` and the download half
of `commission`, and their MCP tools, refuse a device whose application is not
on the list before anything is written. Reads are never affected: `plan`,
`describe`, `device`, `backup` and `reconstruct` work on every device, and
`plan`, `describe` and `device` print the verdict. A group `write`, `assign`
and `restart` are not gated.

The refusal applies on a gateway that is not loopback, the same rule as the
real-gateway opt-in. A simulator cannot be damaged, so the knx-sim loop and
the product sweep keep running for products that are not on the list yet,
which is how a product gets onto it. To write an unsupported device anyway,
back it up first and pass `--allow-unsupported`; over MCP the human has to say
yes to it (see [Safety](safety.md)). The result and the history record then
say `support: forced`.

<!-- supported-table:start -->
| Application | Id | Product | Evidence |
|---|---|---|---|
| `M-0002_A-A0ED-10` | `0002A0ED10` | ABB BE/S16.230.3.2 binary input | capture |
| `M-0004_A-20D7-26` | `000420D726` | Jung 230241SR switch actuator | capture |
| `M-0004_A-20DE-22` | `000420DE22` | Jung 230021SU switch actuator | capture |
| `M-0004_A-20E0-21` | `000420E021` | Jung 360061SR heating actuator v2.1 | capture |
| `M-0004_A-3030-23` | `0004303023` | Jung 390041SR LED universal dimmer | capture |
| `M-0004_A-7066-11` | `0004706611` | Jung 2116REG | capture |
| `M-0004_A-A011-13` | `0004A01113` | Jung 3361-1MWW presence detector | capture |
| `M-0004_A-D142-21` | `0004D14221` | Jung 52921ST F50 push-button module | capture |
| `M-0048_A-140C-14` | `0048140C14` | Theben Meteodata 140 S | capture |
| `M-00FA_A-2700-10` | `00FA270010` | bussard synthetic syn-minimal (NEST-LIGHT) | synthetic |
| `M-00FA_A-2704-10` | `00FA270410` | bussard synthetic syn-le-order (NEST-ALTI) | synthetic |
| `M-00FA_A-2705-10` | `00FA270510` | bussard synthetic syn-union-default-range (NEST-STRAY) | synthetic |
| `M-00FA_A-2706-10` | `00FA270610` | bussard synthetic syn-text-undeclared (NEST-SQUAWK) | synthetic |
| `M-00FA_A-2707-10` | `00FA270710` | bussard synthetic syn-relseg-fill (NEST-FILL) | synthetic |
| `M-00FA_A-2708-10` | `00FA270810` | bussard synthetic syn-choose-partial-segment (NEST-HALF) | synthetic |
| `M-00FA_A-270A-10` | `00FA270A10` | bussard synthetic syn-master-reset (NEST-RESET) | synthetic |
| `M-00FA_A-270B-10` | `00FA270B10` | bussard synthetic syn-param-calculation (NEST-CALC) | synthetic |
| `M-00FA_A-270C-10` | `00FA270C10` | bussard synthetic syn-hidden-default (NEST-EGGHEAT) | synthetic |
| `M-00FA_A-270E-10` | `00FA270E10` | bussard synthetic syn-choose-never-shown (NEST-GHOST) | synthetic |
| `M-00FA_A-2713-13` | `00FA271313` | bussard synthetic syn-module-repeat (NEST-TRIFEED) | synthetic |
| `M-00FA_A-2714-10` | `00FA271410` | bussard synthetic syn-legacy-patch-always (NEST-PATCH) | synthetic |
| `M-00FA_A-2715-10` | `00FA271510` | bussard synthetic syn-ip-address-param (NEST-HOMING) | synthetic |
| `M-00FA_A-2716-10` | `00FA271610` | bussard synthetic syn-user-memory (NEST-LARDER) | synthetic |
| `M-00FA_A-2717-10` | `00FA271710` | bussard synthetic syn-writerelmem-size (NEST-QUILL) | synthetic |
| `M-00FA_A-2718-10` | `00FA271810` | bussard synthetic syn-text-initialvalue (NEST-NAME) | synthetic |
| `M-00FA_A-2719-10` | `00FA271910` | bussard synthetic syn-choose-per-ref (NEST-TWIN) | synthetic |
| `M-00FA_A-271B-10` | `00FA271B10` | bussard synthetic syn-com-objects (NEST-CHIRP) | synthetic |
| `M-00FA_A-271C-10` | `00FA271C10` | bussard synthetic syn-dynamic-tests (NEST-WORM) | synthetic |
| `M-00FA_A-271D-10` | `00FA271D10` | bussard synthetic syn-union-bitfields (NEST-BITS) | synthetic |
| `M-00FA_A-271E-10` | `00FA271E10` | bussard synthetic syn-property-param (NEST-TERR) | synthetic |
| `M-00FA_A-271F-10` | `00FA271F10` | bussard synthetic syn-assign (NEST-CHORE) | synthetic |
| `M-00FA_A-2725-10` | `00FA272510` | bussard synthetic syn-product-07b0 (NEST-PLAN) | synthetic |
| `M-00FA_A-2726-10` | `00FA272610` | bussard synthetic syn-map-error (NEST-FALSE) | synthetic |
| `M-00FA_A-2728-10` | `00FA272810` | bussard synthetic syn-color-param (NEST-COLOUR) | synthetic |
| `M-00FA_A-278A-10` | `00FA278A10` | bussard synthetic syn-master-reset-code4 (NEST-RESET4) | synthetic |
| `M-00FA_A-2796-10` | `00FA279610` | bussard synthetic syn-user-memory-extmem (NEST-LARDERX) | synthetic |
| `M-00FA_A-27A8-10` | `00FA27A810` | bussard synthetic syn-color-param-hsv (NEST-COLHSV) | synthetic |
| `M-00FA_A-27A9-10` | `00FA27A910` | bussard synthetic syn-color-param-hsv2 (NEST-COLHSV2) | synthetic |
| `M-00FA_A-2800-10` | `00FA280010` | bussard synthetic syn-s7-0705 (NEST-DOOR) | synthetic |
| `M-00FA_A-2801-10` | `00FA280110` | bussard synthetic syn-s7-0701 (NEST-BKDOOR) | synthetic |
| `M-00FA_A-2809-10` | `00FA280910` | bussard synthetic syn-s7-choose-split (NEST-SPLIT) | synthetic |
| `M-00FA_A-280D-10` | `00FA280D10` | bussard synthetic syn-s7-hidden-default (NEST-EGGBAK) | synthetic |
| `M-00FA_A-280F-11` | `00FA280F11` | bussard synthetic syn-s7-lsm5 (NEST-TWIG5) | synthetic |
| `M-00FA_A-2810-10` | `00FA281010` | bussard synthetic syn-s7-pei80 (NEST-CLAW) | synthetic |
| `M-00FA_A-2811-10` | `00FA281110` | bussard synthetic syn-s7-taskptr (NEST-HUNT) | synthetic |
| `M-00FA_A-281A-10` | `00FA281A10` | bussard synthetic syn-s7-no-comobjects (NEST-SILENT) | synthetic |
| `M-00FA_A-2820-10` | `00FA282010` | bussard synthetic syn-s7-lsm5-0705 (NEST-TWIG5G) | synthetic |
| `M-00FA_A-2821-11` | `00FA282111` | bussard synthetic syn-s7-pid204 (NEST-PLUME) | synthetic |
| `M-00FA_A-2827-10` | `00FA282710` | bussard synthetic syn-s7-delay (NEST-HATCH) | synthetic |
| `M-00FA_A-2889-10` | `00FA288910` | bussard synthetic syn-s7-static-split (NEST-FORK) | synthetic |
| `M-00FA_A-288D-10` | `00FA288D10` | bussard synthetic syn-s7-hidden-default-p11 (NEST-EGGOLD) | synthetic |
| `M-00FA_A-288E-10` | `00FA288E10` | bussard synthetic syn-s7-hidden-default-ets4 (NEST-EGGV4) | synthetic |
| `M-00FA_A-2900-10` | `00FA290010` | bussard synthetic syn-secure (NEST-GUARD) | synthetic |
| `M-00FA_A-2A22-10` | `00FA2A2210` | bussard synthetic syn-ip-enabled-tp (NEST-UPLINK) | synthetic |
| `M-0112_A-0003-10` | `0112000310` | Helios KWL KNX connect | capture |
<!-- supported-table:end -->

## Source address check

Every command that opens a connection to a device first checks that no device
answers at the address bussard itself sends from: the address the
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
on the gateway: give the tunnel an address no device owns, since
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
    The commands that check are `scan`, `assign`, `adopt`, `describe`,
    `status <ADDRESS>`, `plan`, `apply`, `flash`, `restart`, `reconstruct`,
    `backup`, `restore`, `replace`, `commission`, `audit --live`,
    `plan --line` / `apply --line`, `interface secure`, `secure diag`, and the
    MCP tools `knx_plan_device`, `knx_apply_device` and
    `knx_interface_secure`. Only an
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

## Managing the IP interface itself

The commands that manage a KNX IP interface (`plan` and `apply` of a device
file with a `[knxnet]` table, `describe` of the interface, `interface secure
on|off`) reach it over a tunnel to its own address. When no tunnel
can do that, bussard opens a KNXnet/IP device management connection to the
interface instead, as ETS does. It needs no tunnel slot and no tunnel
address:

- `--device-management` asks for it. This is the way to reach a
  factory-fresh interface, which still calls itself 15.15.255.
- Without the flag, `plan`, `apply` and `describe` switch to it when the
  interface is the gateway and either has no free slot or another device
  answers at the tunnel's address. `interface secure` switches when the
  interface is the gateway and reports no free slot. Each prints a `note:`
  line with the reason.

The tunnel stays the default. bussard opens a device management connection
only to a gateway that names the target (or 15.15.255) as its own address,
because such a connection reaches the interface whatever address is asked
for. On a KNXnet/IP Secure interface it signs in as the management user,
with the `ManagementPassword` the keyring or key store holds for the
interface. The writes and the read-back are the same as over a tunnel. Only
the carrier differs.

**Reconnecting is not a write.** `knx_bus_reconnect` drops the MCP server's
connection to the interface and opens a new one. Nothing is sent onto the KNX
bus, so it needs only the read tier; in `--passive` mode the server
reconnects on its own. A tool that writes while the bus is down is refused
with the last connection error, never queued: a waiting frame is dropped
after 2 seconds.

## Known limitations

- **KNX Data Secure.** bussard programs a Data Secure device with its tool key
  on `flash` and `apply`, and reads one back with `describe`, `plan` and
  `reconstruct`. The handshake and security-object bytes match ETS, full
  flashes have completed on real secured devices, and secured group
  telegrams decrypt on a live bus. One part is inferred: the layout of a
  sender table (the devices a receiver accepts secured telegrams from) with
  more than one entry, since every download observed so far writes at most
  one.
- **Securing a device.** bussard operates devices ETS has secured. It does
  not secure a factory-fresh device from its certificate, re-key one or
  switch Data Secure off; use ETS. A device that answers only under its
  factory key, because it was reset or never commissioned, is recognised by
  `describe` with the factory key from the key store and named as such. bussard writes nothing under the factory key.
- **KNXnet/IP Secure tunnelling.** A secure-only interface needs a tunnelling
  user, from the key store, `--keyring`, or `--secure-user <id>
  --secure-password-env <VAR>`; without one, bussard refuses at once and
  names the cause. Secure tunnelling runs against real secure-only
  interfaces. `bussard interface secure on|off`, which switches an
  interface's security, matches an ETS capture step for step but has not yet
  run against a real interface.
- **Secure session keepalive.** Some interfaces drop a session idle for 60
  seconds, so bussard sends a keepalive every 30 seconds
  (`BUSSARD_SECURE_KEEPALIVE_SECS` changes it; `bussard test --secure-idle
  <secs>` measures an interface read-only). The session runs over TCP only,
  as the KNX standard requires.
- **Calculated parameters.** Some programs compute parameter values with a
  small script instead of storing what you set, such as a thermostat's fan
  settings or a dimmer's dimming curve. bussard runs these scripts (the
  VBScript and JavaScript that product data uses). Like ETS, it runs a
  script only once a value the script reads differs from the product's
  default; at the defaults the computed values keep their defaults (shown
  by the ETS captures `syn-param-calculation` `defaults` and `calc-input`).
  A script it cannot run
  makes `plan`, `apply` and `flash` refuse that device and name the
  calculation, rather than write a value the script did not compute. So do
  calculations that keep changing each other's results, and a value in the
  device file for a parameter a calculation computes differently: remove it,
  or change the parameters the calculation reads. `bussard device`,
  `bussard doc`, `bussard diff`, `viz` and the MCP project tools show a
  computed parameter with the value the download writes, marked as computed
  by its calculation.
  Verified byte for byte against ETS downloads of Ekinex EK-E72 thermostats
  (VBScript), a Jung LED dimmer (JavaScript) and the synthetic product that
  changes a calculation's input.
- **Text parameters.** A text parameter is written in the code page its
  program declares. A program that declares none is written in ISO 8859-1, as
  ETS does; a character whose octet differs between ISO 8859-1,
  Windows-1252 and ISO 8859-15 (the euro sign, for example) or lies beyond
  U+00FF is refused there. A declared code page bussard does not know takes
  ASCII only.
- **System 1 and System 2.** BCU1 and BCU2 devices are identified and
  described, but not programmed, except the property-only applications on
  `0021` above.
- **Not implemented:** secure routing (multicast).

## Next steps

- [Find what you have](../how-to/find-what-you-have.md): scan, audit and free tunnel slots.
- [Device commands](../reference/commands/devices.md): `scan`, `describe`, `reconstruct` and their flags.
- [What each write command does](write-commands.md): the rails of each write.
- [KNX Secure](knx-secure.md): keys and what secured means.
