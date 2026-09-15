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
  directory, so no `flash.bin`, so the device enters programming mode); can
  pre-seed a saved `flash.bin` with `--seed` for table tests. The Rust test
  spawns the binary directly and does not need this wrapper, but it documents the
  boot contract and is handy for manual runs.
- The integration test lives at
  `crates/bussard-cli/tests/virtual_device.rs`.

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

## The test ladder and where it stops

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
| a    | programming-mode discovery        | works  | fresh device (no `flash.bin`) auto-enters prog mode         |
| b    | `assign` writes + verifies address | works  | `A_IndividualAddress_Write` lands; descriptor read returns `57B0` |
| c    | `scan` finds it with its mask      | works  | reports `57B0`, classified `System ?` by bussard            |
| d    | `reconstruct` reads its tables     | stops  | `reconstruct` gates on `07B0`; refuses `57B0` cleanly       |
| e    | `apply` writes a tiny links set    | n/a    | same `07B0` gate as (d), not reachable over routing         |

## Interop findings

- **The foreign device is reachable and answers the management protocol.** Prog-mode
  broadcast discovery, individual-address assignment, the post-write descriptor
  read, and a line scan all work against thelsing's stack over multicast. This is
  the first validation of bussard's management layer against a non-bussard peer.
- **The mask gate is the wall.** `reconstruct`/`apply` accept `07B0` only, and the
  routing-reachable demo is `57B0`. There is no stock thelsing binary that both
  speaks IP multicast and reports `07B0`, so the table-level rungs cannot be
  reached over routing without either (1) relaxing bussard's mask gate to also
  accept `57B0` (they share the `BauSystemBDevice` table stack, so it is
  plausibly safe), or (2) building a modified thelsing variant that pairs
  `IpDataLinkLayer` with a `07B0` `maskVersion`, or (3) driving `knx-linux-tp`
  over a real/virtual TP-UART. Option (1) is the cleanest next step to reach the
  full apply cycle against a foreign device.
- **bussard's table-layout assumptions match thelsing's.** bussard's
  `bussard-mgmt::tables` read side was written with thelsing's table objects as a
  behavioural reference (address table word 0 = entry count, 1-based TSAPs,
  association entries TSAP-then-ASAP, table content served through memory with
  `PID_TABLE_REFERENCE` giving the address). The memory-fallback read path is the
  one that would exercise here, because thelsing's group-object table registers no
  `PID_TABLE` property. This alignment is why rung (d) is a mask-gate refusal
  rather than a decode failure.

## Pinned upstream

- Repo: `https://github.com/thelsing/knx`
- Commit: `980c047ad7fc5e27bf2fae95e48acde5d5e0b4fd` (master, 2025-11-04)

Override with `KNX_REPO` / `KNX_COMMIT` env vars for `build.sh`. Bump both
deliberately; the pin keeps CI reproducible and stops an upstream force-push from
silently changing what the interop tests run against.
