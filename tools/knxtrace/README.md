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
uv run tools/knxtrace/knxtrace.py image   <capture> --device 1.1.5 --out <dir>
uv run tools/knxtrace/knxtrace.py imgdiff <bussard-dump-dir> <image-dir> [--json]
```

`devices`, `trace`, `ops`, `diff` and `image` also take `--keyring
<file.knxkeys>` to decrypt KNX Data Secure frames (see [Data Secure](#data-secure)),
and `trace` takes `--seq-check`.

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
`LdCtrlTaskCtrl1` / `2`, segment address, size, access and memory type); the
extended services `A_PropertyExtValue_*`, `A_PropertyExtDescription_*` and
`A_FunctionPropertyExt_*` with object type, instance and PID (ETS uses them on
the security object during Data Secure activation);
`A_PropertyDescription_Read` / `_Response` with data type, element count and
access levels; `A_Memory_Read` / `_Write` / `_Response` with address, count and
data; `A_MemoryExtended_*` with the 3-octet address; `A_Authorize` and `A_Key`
with the level; `A_Restart` including the master-reset variant with erase code
and channel; `A_IndividualAddress_Read` / `_Write` / `_Response` and the
serial-number-addressed forms; `A_GroupValue_Read` / `_Write` / `_Response`
including the 6-bit small-value form; and `A_SecureData` with its security
control field and sequence number, plus, with a keyring, the decrypted inner
APDU.

## Data Secure

```
export BUSSARD_KEYRING_PASSWORD=...   # the password the .knxkeys was exported with
uv run tools/knxtrace/knxtrace.py devices secure.pcapng --keyring project.knxkeys
uv run tools/knxtrace/knxtrace.py trace   secure.pcapng --device 1.1.12 \
    --keyring project.knxkeys --seq-check
```

`datasecure.py` reads the ETS keyring and verifies `A_SecureData` (APCI
`0x3F1`) frames. It is a port of bussard's Rust implementation, which stays the
reference: `crates/bussard-project/src/keyring.rs` for the keyring and
`crates/bussard-secure/src/{crypto,asdu}.rs` for the frame. The tests pin it to
the Rust known-answer vectors.

- **Keyring.** PBKDF2-HMAC-SHA256 of the password, salt `1.keyring.ets.knx.org`,
  65536 iterations, 16 bytes. The root `Signature` must verify, so a wrong
  password is an error rather than a screen of `MAC FAIL`. `ToolKey`, `FDSK`
  and group `Key` attributes are one AES-128-CBC block each, IV
  `sha256(Created)[:16]`.
- **Key choice.** Tool-access frames (SCF bit 7) try the device's tool key, then
  its FDSK (ETS talks under the FDSK until activation installs the tool key).
  The device is whichever end of the frame the keyring knows. Group frames use
  the group address's key.
- **S-A_Data.** `SCF(1) || seq(6) || APDU || MAC(4)`, AES-128-CCM with the TP
  `block_0` / `counter_0` nonce over source, destination, frame flags and the
  carrier's TPCI octet. The CBC-MAC is cut to 4 bytes before the CTR stage and
  the keystream runs on over the payload, so the payload starts at byte 4 of
  AES(counter_0). This was calibrated against a real ETS capture (bussard
  PR #153). A tunnelled `L_Data.req` from `0.0.0` is also tried with the source
  the interface reported in its `L_Data.con`.
- **S-A_Sync_Req** (SCF `0x92`). `seq(6) || serial(6, clear) || enc(challenge(6))
  || MAC(4)`. The nonce is the frame's own sequence; the additional data is
  `SCF || serial`. The serial is zeros on the per-connection form and names the
  target on the broadcast to `0/0/0`, which is how the key is found then.
- **S-A_Sync_Res** (SCF `0x93`). `masked(6) || enc(responder_seq(6) ||
  requester_seq(6)) || MAC(4)`, where `masked` is the CCM nonce XOR the
  request's challenge. It verifies only against the challenge of the request it
  answers.

Per frame, `trace` prints `A_SecureData{scf=0x90 seq=N tool MAC ok} ->
A_PropertyValue_Read ...`, `... -> S-A_Sync_Req serial=none challenge_len=6`,
`... -> S-A_Sync_Res responder_seq=N requester_seq=M`, or `MAC FAIL` when keys
were tried and none verified. The challenge itself is never printed.
A frame with no key in the keyring prints as without `--keyring`. `devices` and
`ops` count a verified frame as the operation it carries; both commands end
with a summary by outcome, service and inner APDU, and the `S-A_Data` sequence
range per sender.

`--seq-check` reports every `S-A_Data` sequence number that did not increase per
(sender, key). Sync frames are left out: the sequence field of an
`S-A_Sync_Res` is not a counter, and ETS reuses a `Sync_Req`'s sequence for the
next data frame.

`image --keyring` composes a Secure download like a plain one, and also writes
the property writes of the download to `properties.json` (see
[the offline oracle](../../docs/testing-campaign.md#before-a-flash-the-offline-oracle)):
object, PID, count, index, length and value, with security-object key material
reduced to `redacted:<sha256[:8]>` by the same rule as the trace.

AES is pure Python so the tool keeps its empty dependency list. That is slow
per block and fine for a capture's few hundred secure frames.

## Privacy

The campaign's captures come from a private installation, so the decoder is built
not to print anything that should not leave it:

- `A_Authorize` / `A_Key_Write` keys are reported as `redacted:<hash>`, except
  the well-known free-access key `FFFFFFFF`, which is named.
- `A_SecureData` payloads are reported as a length and a content hash. Without
  a keyring the protected APDU and its MAC are never printed. With `--keyring`,
  a frame whose MAC verifies shows its inner APDU, decoded like plain traffic,
  except that key material inside it is reported as `redacted:<hash>`: the
  key PIDs (P2P, group and zone key tables, tool key), anything key-sized (16 bytes
  or more) addressed to the security object (type 17) by the extended
  services, and any undecoded service with a key-sized payload. Keyring keys are never printed: output names them only as
  `tool`, `fdsk` or `group`, and the keyring password is read from
  `$BUSSARD_KEYRING_PASSWORD`, never the command line.
- KNXnet/IP Secure frames are named, sized and hashed. Nothing is decrypted, and
  there is no code path that could decrypt.

Captures themselves live under the gitignored `captures/`, and `.pcap` /
`.pcapng` files are gitignored everywhere. The tests here build their own
captures in-process from RFC 5737 TEST-NET-1 addresses.

## Layout

| File | What it holds |
| --- | --- |
| `knxtrace.py` | The CLI: `devices`, `trace`, `ops`, `diff`, `image`, `imgdiff`. |
| `capture.py` | pcap / pcapng reading, link and IP layers, TCP reassembly. |
| `knxip.py` | KNXnet/IP, cEMI, transport layer and APCI decoding. |
| `datasecure.py` | ETS keyring, AES-128, and `A_SecureData` verification and decryption. |
| `normalize.py` | Frame stream to per-device operation sequence. |
| `opsdiff.py` | The differ and its classification rules. |
| `image.py` | Composes the memory and the property writes (`properties.json`) a download wrote and diffs both against a `bussard flash --dry-run --dump-images` directory (see [the offline oracle](../../docs/testing-campaign.md#before-a-flash-the-offline-oracle)). |
| `test_knxtrace.py` | Tests, on synthetic captures and the `knx-sim` fixtures. |

See [`docs/testing-campaign.md`](../../docs/testing-campaign.md) for how this
fits into the campaign runbook.
