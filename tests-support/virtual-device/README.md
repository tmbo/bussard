# Virtual-device test harness

Runs [thelsing/knx](https://github.com/thelsing/knx)'s Linux KNXnet/IP demo as an
**external test peer** so bussard's management stack can be exercised against an
independent, foreign device implementation instead of our own in-process mocks.

## Licence framing

thelsing/knx is GPL-3.0. bussard is MIT. We keep them at arm's length: this
harness **clones and builds** thelsing/knx at test time into a standalone
executable and **runs it as a separate process** that bussard talks to over a
network socket (KNXnet/IP routing multicast). Nothing from thelsing/knx is
linked into, vendored into, or ported to bussard. The build script and the test
code here are bussard's own. This is ordinary "two independent programs talking
over the wire" interop, the same relationship bussard has with any real KNX
device on a bus.

## CI shakedown findings (2026-09, `ci/virtual-device-shakedown`)

The first live run of the `virtual-device` CI job failed at rung (a): assign
found no device in programming mode. Two independent root causes were found;
both are fixed harness-side. The job stays `continue-on-error` (advisory).

### 1. Same-host multicast delivery (FIXED)

thelsing's `src/linux_platform.cpp` hard-codes `IP_MULTICAST_LOOP = 0` on its one
multicast socket (`loop = 0; setsockopt(..., IP_MULTICAST_LOOP, ...)`). On Linux
that flag is a property of the *sending* socket and governs whether a multicast
datagram is delivered to group members **on the same host**. With it off, the
device's routing replies never reach a bussard process sharing the host, so
prog-mode discovery times out.

Fix (harness-side, unmodified pinned binary): run the device in its own network
namespace joined to the root namespace by a veth pair (`netns-setup.sh`). Its
multicast now egresses a real link and arrives at bussard as ordinary *inbound*
traffic, where `IP_MULTICAST_LOOP` no longer applies. bussard stays in the root
namespace on `10.213.0.1` (veth-host), reached via a `224.0.23.12/32` route; the
device runs under `ip netns exec knxdev`. A bidirectional multicast probe and the
in-namespace packet capture confirm the group crosses the veth both ways. This
fix is correct and necessary and should be kept.

### 2. The device is not in programming mode at boot (FIXED, harness-side)

With the multicast path fixed, bussard's broadcast `A_IndividualAddress_Read`
physically reaches the device (confirmed in the in-namespace pcap) but the device
never replies. Root cause, from the pinned source:

- `src/knx/device_object.h` defaults `_ownAddress = 0xFFFF` (15.15.255), **not
  0**. So the demo's `main.cpp` guard `if (knx.individualAddress() == 0)
  knx.progMode(true)` never fires: a factory-fresh device does **not** enter
  programming mode. thelsing's `individualAddressReadIndication` only answers in
  programming mode, so the read is silently ignored. This is correct behaviour
  for a device booted at 15.15.255.

Fix: the ladder presses the programming button before `assign`, the way an
installer does on real hardware. `VirtualDevice::press_programming_button` in
`virtual_device.rs` opens a transport connection to 15.15.255 over routing,
writes `PID_PROG_MODE` (device object 0, property 54) = 1 and disconnects, then
waits for the device to log `progmode on`. It uses raw frames on a plain UDP
socket, not bussard's stack, so rung (a) still tests bussard's discovery.

An earlier version of this README called the broadcast read an "interop wall":
`knx_probe.py` set prog mode, yet the device still did not answer. That finding
was a probe bug. The probe sent the TPCI/APCI octets as `00 01` instead of
`01 00`, which the device decodes as `A_GroupValue_Read` (its log shows
`Broadcast-indication: unhandled APDU-Type: 0`). With the octets fixed, the
device answers the broadcast read once prog mode is on.

## Platform: Linux only

thelsing's `src/linux_platform.cpp` is wrapped top to bottom in `#ifdef __linux__`
with no macOS branch, and depends on Linux-only facilities (`linux/*` headers,
sysfs GPIO, `/dev/spidev`, `/dev/ttyUSB`). **It does not compile on macOS.**

A container does not rescue local macOS use. KNXnet/IP routing is multicast, and
Docker Desktop for Mac runs its engine in a Linux VM whose host-network multicast
does not bridge to the macOS host, so bussard on the Mac could not exchange
multicast with a containerised device. The honest verdict: this harness runs on
**native Linux** (a Linux developer box or CI). On macOS `build.sh` stops early
with an explanation and a non-zero exit, and the integration test self-skips.

## Files

- `build.sh`: clones thelsing/knx at a pinned commit and builds the
  `knx-linux-ip` CMake target. Prints the built binary path as its last stdout
  line and to `target/virtual-device/binary-path.txt`.
- `run-device.sh`: boots the demo. Factory-fresh by default (an empty working
  directory, so no `flash.bin`; the device boots at 15.15.255, not in programming mode); can
  pre-seed a saved `flash.bin` with `--seed` for table tests. The Rust test
  spawns the binary directly and does not need this wrapper, but it documents the
  boot contract and is handy for manual runs.
- The management-ladder integration test lives at
  `crates/bussard-cli/tests/virtual_device.rs`.
- The **flash oracle** integration test lives at
  `crates/bussard-cli/tests/virtual_device_flash.rs`, with its synthetic
  `.knxprod` source under `knxprod/` (see "The flash oracle" below).

## The flash oracle (`bussard flash` end-to-end)

A factory-fresh thelsing device boots at 15.15.255 and does not enter
programming mode by itself (the ladder presses its button first, see finding 2).
`bussard flash` does not need programming mode at all: it needs no programming-mode discovery, only a connection-oriented management
session to a **known** address — and `knx_probe.py` already proved the device is
reachable connection-oriented at its default 15.15.255. So the flash oracle
flashes the device **at 15.15.255 directly** and drives its ApplicationProgram
object Unloaded -> Loading -> Loaded.

Run it (Linux):

```sh
BIN=$(tests-support/virtual-device/build.sh)
BUSSARD_VIRTUAL_DEVICE=1 BUSSARD_TEST_MULTICAST=1 BUSSARD_VIRTUAL_DEVICE_BIN=$BIN \
  cargo test -p bussard-cli --test virtual_device_flash -- --ignored --nocapture
```

The exact command the test runs (plain flags — no windowing, pacing, or
tolerate-flags):

```sh
bussard flash 15.15.255 --product <built.knxprod> --dir <empty> --yes \
  --bcu-key FFFFFFFF --routing
```

### The synthetic `.knxprod`

`knxprod/M-00FA/M-00FA_A-0001.xml` is bussard's OWN hand-authored product XML
(MIT), not vendor data and not derived from any thelsing source. It declares:

- `MaskVersion="MV-57B0"` — bussard's flash pre-flight gates on `is_system_b`
  (true for the whole `x7B0` family, so 57B0 passes) **and** an exact
  app-mask == device-mask compare, so the app must declare 57B0 to be accepted
  against this device.
- a 6-byte relative code segment and a single `ProductDefault` load procedure
  that lowers to exactly: Unload / StartLoading / **relative** segment allocation
  (`LdCtrlRelSegment`) / WriteRelMem / LoadCompleted / Restart.

The harness zips this XML into a `.knxprod` at run time with the `zip` CLI, so
git carries readable XML rather than a binary blob.

### Why this reaches Loaded (device-side facts)

From the pinned thelsing source (public headers/behaviour only, nothing linked
or vendored): the `Bau57B0` stack exposes the **ApplicationProgram interface
object at index 4** (object type 3), so bussard's dynamic
`PID_OBJECT_TYPE`-probe discovery finds it. That object is a dynamic
`TableObject`, whose load-state machine takes `Unloaded --StartLoading-->
Loading --LoadCompleted--> Loaded` **unconditionally** — no prior segment
allocation is required to reach Loaded, and `LoadCompleted` has no path to
`Error`. Memory writes are accepted and read back for any in-range address with
no access-control gate, and `A_Authorize` always grants level 0 (so
`--bcu-key FFFFFFFF` is harmless). One caveat the fixture respects: the device
accepts only the **relative** `AdditionalLoadControls` sub-command (`0x0B`,
which `bussard-mgmt`'s `allocate_segment` uses) and pushes the object to `Error`
on an **absolute** segment (`0x0A`) — so the procedure uses `LdCtrlRelSegment`,
never `LdCtrlAbsSegment`.

## Which binary, and the mask consequence

thelsing's `examples/knx-linux` builds three binaries, medium and mask coupled at
compile time:

| binary          | `MASK_VERSION` | data link layer            | reachable how          |
| --------------- | -------------- | -------------------------- | ---------------------- |
| `knx-linux-tp`  | `0x07B0`       | TP-UART (`TpUartDataLinkLayer`) | serial `/dev/ttyUSB0`  |
| `knx-linux-rf`  | `0x27B0`       | CC1101 radio               | SPI GPIO               |
| `knx-linux-ip`  | `0x57B0`       | KNXnet/IP (`IpDataLinkLayer`)   | multicast 224.0.23.12  |

Only `knx-linux-ip` speaks KNXnet/IP routing multicast, so it is the only one a
`bussard --routing` client can reach without serial/radio hardware. But it
reports mask **`0x57B0`** (KNXnet/IP System B), not `0x07B0` (TP System B). All
three inherit the same `BauSystemBDevice` management stack (device object,
address/association/group-object tables, load-state machine, the full
application-layer service set), so the difference bussard sees is purely the mask
and the medium.

## The test ladder

Enable and run (Linux):

```sh
BIN=$(tests-support/virtual-device/build.sh)
BUSSARD_VIRTUAL_DEVICE=1 BUSSARD_TEST_MULTICAST=1 \
BUSSARD_VIRTUAL_DEVICE_BIN=$BIN \
  cargo test -p bussard-cli --test virtual_device -- --ignored --nocapture
```

The test is `#[ignore]` and additionally guarded by `BUSSARD_VIRTUAL_DEVICE=1`
and `BUSSARD_TEST_MULTICAST=1`, so it never runs in the normal suite.

| rung | step                              | result | why                                                         |
| ---- | --------------------------------- | ------ | ----------------------------------------------------------- |
| a    | programming-mode discovery        | works  | after the harness writes `PID_PROG_MODE = 1` (the "button") |
| b    | `assign` writes + verifies address | works  | `A_IndividualAddress_Write` lands; descriptor read returns `57B0` |
| c    | `scan` finds it with its mask      | works  | reports `57B0`, classified `System B (IP)` by bussard       |
| d    | `reconstruct` reads its tables     | works  | 57B0 is System B in the mask profile; tables read (empty)  |
| e    | `apply` writes a tiny links set    | n/a    | not attempted: the fresh device has no application program  |

## Interop findings

- **The foreign device is reachable and answers the management protocol.** Prog-mode
  broadcast discovery, individual-address assignment, the post-write descriptor
  read, and a line scan all work against thelsing's stack over multicast. This is
  the first validation of bussard's management layer against a non-bussard peer.
- **57B0 is read like 07B0.** The mask profile treats every System B mask
  (07B0 TP, 27B0 RF, 57B0 IP) the same, so `reconstruct` reads the
  routing-reachable demo's tables. Before that change this rung stopped at a
  07B0-only gate.
- **bussard's table-layout assumptions match thelsing's.** bussard's
  `bussard-mgmt::tables` read side was written with thelsing's table objects as a
  behavioural reference (address table word 0 = entry count, 1-based TSAPs,
  association entries TSAP-then-ASAP, table content served through memory with
  `PID_TABLE_REFERENCE` giving the address). The memory-fallback read path is the
  one that would exercise here, because thelsing's group-object table registers no
  `PID_TABLE` property. Rung (d) exercises that path against the foreign stack.

## Pinned upstream

- Repo: `https://github.com/thelsing/knx`
- Commit: `980c047ad7fc5e27bf2fae95e48acde5d5e0b4fd` (master, 2025-11-04)

Override with `KNX_REPO` / `KNX_COMMIT` env vars for `build.sh`. Bump both
deliberately; the pin keeps CI reproducible and stops an upstream force-push from
silently changing what the interop tests run against.
