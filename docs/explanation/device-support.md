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
  table a full flash would write, and names each object whose descriptor
  changes. `apply` and `apply --line` write it with the link tables. Without
  product data `plan` names each newly linked object whose flag it could not
  check.
- **System B link change.** With product data, every link change unloads the
  group-object, association and address tables, reloads all three and
  restarts the device, as ETS does (KNX 03_05_03 §3.9.3.5, ETS capture
  `syn-minimal/apply`). `apply --line` restarts each device it writes.
  `apply` waits for the device to answer again, then reads it back. When
  links and parameters change together, the parameter download sends the one
  restart; no ETS capture of that combination exists yet. A restart that
  could not be sent stays pending: the next `plan` offers it.
- **Unfinished table download.** A write of the link tables alone (no
  product data, `restore`) first checks the group-object table's load
  state. When a failed download left it unloaded, the write is refused
  before anything is sent: `apply` from your project (with product data) or
  `flash` reloads it.
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

The mask says whether bussard can talk to a device at all. The device-support
list says whether bussard has checked what it writes to that product. It
names application programs by the application id `bussard.lock` pins and the
device reports, and puts each in one of three categories:

- **proven**: bussard wrote a real device with this application and the
  read-back matched. Kept by hand; every entry cites the issue or the dated
  owner statement that records the run.
- **likely**: the evidence says bussard's download matches ETS, but bussard
  has not written a real device with this application. A plan for it says
  "not confirmed on a real device", and so does the assistant over MCP.
- **unsupported or unknown**: a known problem (the entry names its issue and,
  where the issue gives one, its cause), or an application the list does not
  name.

`proven` and `likely` pass the write gate. `bussard device --supported` prints
the whole list (`--json` too) with the evidence for each entry: `live`,
`house-capture` (the offline oracle is identical against an ETS download of a
house device), `sweep` (the ETS sweep over the product catalogue) or `issue`.

### How `likely` is computed

`tools/supported-devices/generate.py` computes the `likely` entries from
committed files only, and CI fails when the list is stale. The gate looks an
application up by its id (manufacturer, number and version), and the sweep can
hold several builds of one id, so rule `sweep-1` holds for every build. It
takes an application into `likely` when:

1. the ETS sweep (`tools/ets-sweep/evidence/manifest.json`) captured at least
   one build, and found bussard's image identical to ETS's for every captured
   build;
2. the load-control records are identical too;
3. each comparison covers at least 95 % of the octets bussard places;
4. no build differs; and
5. every mask a build has belongs to a family with a proven device.

A build the sweep skipped (ETS's catalogue held another build of the order
number) counts neither for nor against an entry; the entry records how many
builds were not compared (`uncompared`). An application with builds on two
masks lists both and counts in both rows of the table.

The hand-kept entries are checked against the sweep too: a hand entry's mask
must be the sweep's mask for its id, and a `proven` or `likely` entry with a
differing sweep row stops the generator unless the entry says why.

The family key is the mask. The shape of the load procedure would separate
families further, but no committed file records it per application yet. A
summary of each application's load-control operations, written by
`tools/ets-sweep/catalog_apps.py` next to its order numbers, would let the key
include it.

What `likely` does not rest on yet: the constructs an application uses are not
checked against the synthetic products that isolate them, and a defaults sweep
reaches the default branches of a product only. Both are open in issue #1097.
Firmware behaviour (timing, load states, restarts) is shown by a proven device
alone. An application the sweep reports as differing is listed as unsupported
with its issue.

The synthetic products (#596) are not on the list: no real device runs them,
and the knx-sim loop runs on loopback, where nothing is refused. The table
counts them per family.

### What is gated

`flash`, `apply` (also `--line`), `restore`, `replace` and the download half
of `commission`, and their MCP tools, refuse an unsupported device before
anything is written. Reads are never affected: `plan`, `describe`, `device`,
`backup` and `reconstruct` work on every device, and `plan`, `describe`,
`device`, `status` and `audit` print the verdict with its category. The
KNXnet/IP settings of an IP interface (its `[knxnet]` table) are not gated:
they are standard properties, not built from the application program. A group
`write`, `assign` and `restart` are not gated.

The refusal applies on a gateway that is not loopback, the same rule as the
real-gateway opt-in. A simulator cannot be damaged, so the knx-sim loop and
the product sweep keep running for products that are not on the list yet,
which is how a product gets onto it. To write an unsupported device anyway,
back it up first and pass `--allow-unsupported`; over MCP the human has to say
yes to it (see [Safety](safety.md)). The result and the history record then
say `support: forced`.

Mask `0701` has no proven device yet, so its applications stay unknown
however their sweep reads.

<!-- supported-table:start -->
Sweep manifest of 2026-11-10, coverage floor 95.0 %.

| Family (mask) | Proven | Likely | Identical, no proven device | Known problems | Synthetic products |
|---|---|---|---|---|---|
| `0701` | 0 | 0 | 364 | 29 | 5 |
| `0705` | 1 | 275 | 0 | 9 | 8 |
| `07B0` | 3 | 766 | 0 | 45 | 37 |
| all | 4 | 1040 | 364 | 83 | 50 |

| Manufacturer | Proven | Likely | Known problems |
|---|---|---|---|
| `M-0001` | 0 | 37 | 0 |
| `M-0002` | 1 | 63 | 1 |
| `M-0004` | 2 | 69 | 8 |
| `M-0006` | 0 | 6 | 0 |
| `M-0007` | 0 | 34 | 0 |
| `M-0008` | 0 | 52 | 3 |
| `M-0009` | 0 | 35 | 31 |
| `M-000C` | 0 | 3 | 0 |
| `M-0048` | 0 | 82 | 2 |
| `M-0064` | 0 | 11 | 0 |
| `M-0071` | 0 | 238 | 8 |
| `M-0072` | 0 | 1 | 0 |
| `M-0076` | 0 | 2 | 1 |
| `M-0077` | 0 | 2 | 0 |
| `M-007C` | 0 | 0 | 6 |
| `M-0080` | 0 | 5 | 0 |
| `M-0083` | 0 | 145 | 1 |
| `M-0085` | 0 | 22 | 0 |
| `M-0087` | 0 | 1 | 0 |
| `M-008B` | 0 | 1 | 0 |
| `M-008E` | 0 | 12 | 0 |
| `M-009A` | 0 | 15 | 0 |
| `M-00A6` | 0 | 6 | 1 |
| `M-00B0` | 0 | 1 | 0 |
| `M-00B6` | 0 | 49 | 1 |
| `M-00C5` | 0 | 28 | 0 |
| `M-00C8` | 0 | 16 | 7 |
| `M-00C9` | 0 | 32 | 0 |
| `M-00E1` | 0 | 0 | 1 |
| `M-00E8` | 0 | 5 | 0 |
| `M-00EF` | 0 | 10 | 11 |
| `M-00FC` | 0 | 12 | 0 |
| `M-00FD` | 0 | 11 | 0 |
| `M-0112` | 1 | 0 | 0 |
| `M-011E` | 0 | 15 | 1 |
| `M-011F` | 0 | 6 | 0 |
| `M-0151` | 0 | 2 | 0 |
| `M-0159` | 0 | 1 | 0 |
| `M-0162` | 0 | 3 | 0 |
| `M-017D` | 0 | 3 | 0 |
| `M-0182` | 0 | 1 | 0 |
| `M-0191` | 0 | 1 | 0 |
| `M-020D` | 0 | 1 | 0 |
| `M-020F` | 0 | 1 | 0 |

Kept by hand:

| Application | Id | Product | Mask | Category | Evidence |
|---|---|---|---|---|---|
| `M-0002_A-A0ED-10` | `0002A0ED10` | ABB BE/S16.230.3.2 binary input | `07B0` | proven | live |
| `M-0004_A-20D7-26` | `000420D726` | Jung 230241SR switch actuator | `07B0` | likely | house-capture |
| `M-0004_A-20DE-22` | `000420DE22` | Jung 230021SU switch actuator | `07B0` | likely | house-capture |
| `M-0004_A-20E0-21` | `000420E021` | Jung 360061SR heating actuator v2.1 | `07B0` | likely | house-capture |
| `M-0004_A-3030-23` | `0004303023` | Jung 390041SR LED universal dimmer | `07B0` | likely | house-capture |
| `M-0004_A-7066-11` | `0004706611` | Jung 2116REG | `0705` | likely | house-capture |
| `M-0004_A-A011-13` | `0004A01113` | Jung 3361-1MWW presence detector | `0705` | proven | live |
| `M-0004_A-D142-21` | `0004D14221` | Jung 52921ST F50 push-button module | `07B0` | proven | live |
| `M-0009_A-E0EE-10` | `0009E0EE10` | Hager STXF121 (TXF121) | `07B0` | unsupported | issue |
| `M-0009_A-E0F1-10` | `0009E0F110` | Hager STXC51x (TXC513, TXC515) | `07B0` | unsupported | issue |
| `M-0009_A-E0F2-10` | `0009E0F210` | Hager STXD50x (TXD501, TXD503) | `07B0` | unsupported | issue |
| `M-0009_A-E802-13` | `0009E80213` | Hager STYMS646R (TYMS646R) | `07B0` | unsupported | issue |
| `M-0112_A-0003-10` | `0112000310` | Helios KWL KNX connect | `07B0` | proven | live |
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
