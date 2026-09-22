# knxtrace

Reads a KNXnet/IP capture, decodes it down to the application layer, and diffs
two downloads of the same device. It exists for the physical-device campaign
([#89](https://github.com/tmbo/bussard/issues/89)) and the Secure test plan
([#90](https://github.com/tmbo/bussard/issues/90)), where the central question is
*did `bussard` write the same thing ETS did?*

Nothing here talks to a bus. It is an offline reader for `.pcap` / `.pcapng`
files and for the `<src> <dst> <tpdu>` fixture streams `knx-sim` already ships.

## Running it

```
uv run tools/knxtrace/knxtrace.py devices <capture>
uv run tools/knxtrace/knxtrace.py trace   <capture> [--device 1.1.5] [--service TUNNELING_REQUEST]
uv run tools/knxtrace/knxtrace.py ops     <capture> [--device 1.1.5] [--json]
uv run tools/knxtrace/knxtrace.py diff    <a> <b> --device 1.1.5 [--json] [--only-real]
```

Tests:

```
uv run tools/knxtrace/test_knxtrace.py
```

Python 3.10 or newer, no third-party packages. The PEP 723 header declares an
empty dependency list, so `uv run` needs no network.

**No scapy.** This repository refuses copyleft dependencies (`CLAUDE.md`,
"License Policy") and scapy is GPLv2. The capture reader is about 350 lines of
stdlib `struct`, which also keeps every failure mode ours: a malformed record is
skipped, never fatal.

## The two views

`trace` is chronological and shows everything: one line per KNXnet/IP frame with
the service, the cEMI message code, the transport-layer PDU and the decoded
APDU. This is what you read when a step behaved strangely.

`ops` is the normalized view: one operation sequence per target device, with
everything that legitimately varies between two runs removed:

- the KNXnet/IP layer (tunnel channel ids, sequence counters, `TUNNELING_ACK`)
- Layer 4 sequence numbers and `T_ACK` / `T_NAK`
- `L_Data.con` echoes of an `L_Data.req`
- link-layer repeats of an identical TPDU
- timing, and interleaving with other devices

and everything that is real programming kept: load events per interface object,
allocation records, memory writes as address / length / content hash, verify
reads, restarts, address writes, secure envelopes. It closes with the **memory
image**: every memory write coalesced into contiguous regions, so the same image
looks the same however it was chunked.

```
$ uv run tools/knxtrace/knxtrace.py ops knx-sim/tests/fixtures/ets_da_tp_flash_requests.txt
normalized operation sequence for 1.1.2 (...)
dropped: 0 L_Data.con echo(es), 0 repeat(s), 57 L4 ack(s)

   1  connect T_Connect
   2  descriptor type0 type=0
   4  authorize Authorize_Request key=FFFFFFFF(free-access)
   5  load-event obj1/PID_LOAD_STATE_CONTROL event=Unload index=1
  ...
  72  restart Restart type=basic

memory image (4 region(s), chunking removed):
    0x006000..0x006100 len=256 sha=5a7b563e
    0x008000..0x008094 len=148 sha=2bc40596
```

## The diff and how it classifies

`diff` compares two normalized sequences for one device and gives every
difference a verdict.

| Verdict | Reason | What it means |
| --- | --- | --- |
| `IDENTICAL` | | The sequences match exactly, byte for byte. |
| `BENIGN` | `ordering` | The same operations, reshuffled: reads, or writes to different interface objects. |
| `BENIGN` | `cycling` | One side opened or closed the Layer 4 connection more often. |
| `BENIGN` | `chunking` | The same memory image split into different write sizes. |
| `BENIGN` | `retry` | One side repeated an operation the other also performed. |
| `DIFFERENT` | `payload` | The same operation on the same object, different bytes. |
| `DIFFERENT` | `ordering` | Reordered operations **on the same object**, where order is meaningful. |
| `DIFFERENT` | `missing` / `extra` | An operation only one side performed. |
| `DIFFERENT` | `coverage` | Memory octets one side wrote and the other never did. |
| `DIFFERENT` | `content` | Memory octets both sides wrote, with different values. |

`chunking` does the heavy lifting: ETS and `bussard` pick different APDU sizes,
and `bussard` uses `A_MemoryExtended_Write` above 64 KB where ETS may not, so the
write records disagree constantly while the resulting image is identical. The
differ therefore compares the coalesced image as its own, chunking-independent
check. `coverage` and `content` come from that comparison, so a real memory
difference is reported with exact address ranges no matter how the writes lined
up.

`diff` exits `1` when the verdict is `DIFFERENT` and `0` otherwise, so a campaign
script can gate on it. `--only-real` hides the benign findings.

## Coverage

**Capture formats.** `pcap` (both endiannesses, microsecond and nanosecond),
`pcapng` (section and interface blocks, `if_tsresol`, enhanced and simple packet
blocks). Link types: Ethernet with VLAN tags, `NULL`/`LOOP` loopback, Linux
`SLL` and `SLL2`, raw IPv4/IPv6. IPv4 (fragments skipped) and IPv6 (extension
headers walked).

**Transports.** UDP datagrams are walked by the KNXnet/IP header length field, so
several frames in one datagram all decode. TCP is reassembled per directional
4-tuple, tolerating out-of-order segments and overlapping retransmits, and framed
the same way; a gap that never fills resyncs by scanning for the next `06 10`.

**KNXnet/IP.** Search, description, the connection lifecycle (`CONNECT`,
`CONNECTIONSTATE`, `DISCONNECT`, with status names), `TUNNELING_REQUEST` /
`TUNNELING_ACK` with channel, sequence and status, device configuration, routing,
tunnelling features, and the Secure frames `0x0950`-`0x0955` named by type.

**cEMI.** `L_Data.req` / `.ind` / `.con`, source and destination addresses,
priority, hop count, repeat and confirm-error flags, plus the management message
codes by name.

**Transport layer.** `T_Connect`, `T_Disconnect`, `T_ACK` / `T_NAK` with their
sequence numbers, and numbered and unnumbered data PDUs.

**Application layer, by name and decoded fields.** `A_DeviceDescriptor_Read` /
`_Response` (with the mask version); `A_PropertyValue_Read` / `_Write` /
`_Response` with object index and name, PID and name, element count and start
index, and for `PID_LOAD_STATE_CONTROL` the load event, the load state and the
allocation records (`LdCtrlAbsSegment`, `LdCtrlRelSegment`, `LdCtrlTaskPtr`,
`LdCtrlTaskCtrl1` / `2`, segment address, size, access and memory type);
`A_PropertyDescription_Read` / `_Response` with data type, element count and
access levels; `A_Memory_Read` / `_Write` / `_Response` with address, count and
data; `A_MemoryExtended_*` with the 3-octet address; `A_Authorize` and `A_Key`
with the level; `A_Restart` including the master-reset variant with erase code
and channel; `A_IndividualAddress_Read` / `_Write` / `_Response` and the
serial-number-addressed forms; `A_GroupValue_Read` / `_Write` / `_Response`
including the 6-bit small-value form; and `A_SecureData` with its security
control field and sequence number.

## Privacy

The campaign's captures come from a private installation, so the decoder is built
not to print anything that should not leave it:

- `A_Authorize` / `A_Key_Write` keys are reported as `redacted:<hash>`, except
  the well-known free-access key `FFFFFFFF`, which is named.
- `A_SecureData` payloads are reported as a length and a content hash. The
  protected APDU and its MAC are never printed.
- KNXnet/IP Secure frames are named, sized and hashed. Nothing is decrypted, and
  there is no code path that could decrypt.

Captures themselves live under the gitignored `captures/`, and `.pcap` /
`.pcapng` files are gitignored everywhere. The tests here build their own
captures in-process from RFC 5737 TEST-NET-1 addresses.

## Layout

| File | What it holds |
| --- | --- |
| `knxtrace.py` | The CLI: `devices`, `trace`, `ops`, `diff`. |
| `capture.py` | pcap / pcapng reading, link and IP layers, TCP reassembly. |
| `knxip.py` | KNXnet/IP, cEMI, transport layer and APCI decoding. |
| `normalize.py` | Frame stream to per-device operation sequence. |
| `opsdiff.py` | The differ and its classification rules. |
| `test_knxtrace.py` | Tests, on synthetic captures and the `knx-sim` fixtures. |

See [`docs/testing-campaign.md`](../../docs/testing-campaign.md) for how this
fits into the campaign runbook.
