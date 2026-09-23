# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Tests for knxtrace. Run with: uv run tools/knxtrace/test_knxtrace.py

Every capture used here is generated in-process from TEST-NET-1 addresses
(192.0.2.0/24, RFC 5737) and invented device addresses. No real capture, no real
installation data and no key material appears in this file or in what it writes.

The only committed data the tests read is `knx-sim/tests/fixtures/*.txt`: the
request-direction TPDU streams from the ETS oracle captures, which the simulator
already replays. They make the normalizer's fixtures because they are exactly
what a live capture must reduce to.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture as cap  # noqa: E402
import image as memimage  # noqa: E402
import knxip  # noqa: E402
import normalize as norm  # noqa: E402
import opsdiff  # noqa: E402
from knxtrace import main  # noqa: E402

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
)
FIXTURES = os.path.join(REPO_ROOT, "knx-sim", "tests", "fixtures")

# TEST-NET-1 (RFC 5737). Never a real address.
TOOL_IP = "192.0.2.10"
GATEWAY_IP = "192.0.2.20"
TOOL_PORT = 55123
KNX_PORT = 3671


# --------------------------------------------------------------------------
# Synthetic capture construction
# --------------------------------------------------------------------------


def ia(text: str) -> int:
    a, l, d = (int(p) for p in text.split("."))
    return (a << 12) | (l << 8) | d


def cemi_ldata(src: str, dst: str, npdu: bytes, mc: int = 0x11) -> bytes:
    """One cEMI L_Data frame addressed to an individual address."""
    return (
        bytes([mc, 0x00, 0xBC, 0x60])
        + struct.pack("!HH", ia(src), ia(dst))
        + bytes([len(npdu) - 1])
        + npdu
    )


def tunneling_request(cemi: bytes, channel: int = 1, seq: int = 0) -> bytes:
    body = bytes([0x04, channel, seq, 0x00]) + cemi
    return b"\x06\x10\x04\x20" + struct.pack("!H", 6 + len(body)) + body


def tunneling_ack(channel: int = 1, seq: int = 0) -> bytes:
    body = bytes([0x04, channel, seq, 0x00])
    return b"\x06\x10\x04\x21" + struct.pack("!H", 6 + len(body)) + body


def _eth_ipv4_udp(src_ip, sport, dst_ip, dport, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 20 + len(udp))
        + b"\x00\x00\x40\x00\x40\x11\x00\x00"
        + bytes(int(o) for o in src_ip.split("."))
        + bytes(int(o) for o in dst_ip.split("."))
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + udp


def _eth_ipv4_tcp(src_ip, sport, dst_ip, dport, seq, payload: bytes, flags=0x18) -> bytes:
    tcp = (
        struct.pack("!HHII", sport, dport, seq, 0)
        + bytes([0x50, flags])
        + b"\xff\xff\x00\x00\x00\x00"
        + payload
    )
    ip = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 20 + len(tcp))
        + b"\x00\x00\x40\x00\x40\x06\x00\x00"
        + bytes(int(o) for o in src_ip.split("."))
        + bytes(int(o) for o in dst_ip.split("."))
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + tcp


def write_pcapng(path: str, frames: list, linktype: int = 1) -> None:
    """Writes a minimal but valid pcapng: SHB, IDB, one EPB per frame."""
    out = bytearray()

    def block(btype: int, body: bytes) -> bytes:
        total = len(body) + 12  # type + length + body + trailing length
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    out += block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", linktype, 0, 0xFFFF))
    for n, frame in enumerate(frames):
        ts = 1_700_000_000_000_000 + n * 1000
        pad = (-len(frame)) % 4
        out += block(
            0x00000006,
            struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFF_FFFF, len(frame), len(frame))
            + frame
            + b"\x00" * pad,
        )
    with open(path, "wb") as fh:
        fh.write(bytes(out))


def udp_capture(path: str, knx_frames: list) -> None:
    """Every frame as one UDP datagram, alternating tool -> gateway direction."""
    eth = []
    for frame, to_gateway in knx_frames:
        if to_gateway:
            eth.append(_eth_ipv4_udp(TOOL_IP, TOOL_PORT, GATEWAY_IP, KNX_PORT, frame))
        else:
            eth.append(_eth_ipv4_udp(GATEWAY_IP, KNX_PORT, TOOL_IP, TOOL_PORT, frame))
    write_pcapng(path, eth)


# TPDU builders: [tpci, apci_low, payload...]


def t_connect() -> bytes:
    return b"\x80"


def t_disconnect() -> bytes:
    return b"\x81"


def numbered(seq: int, apci: int, payload: bytes = b"") -> bytes:
    tpci = 0x40 | ((seq & 0x0F) << 2) | ((apci >> 8) & 0x03)
    return bytes([tpci, apci & 0xFF]) + payload


def mem_write(addr: int, data: bytes, seq: int = 0) -> bytes:
    return numbered(seq, 0x280 | len(data), struct.pack("!H", addr) + data)


def prop_write(obj: int, pid: int, count: int, index: int, data: bytes, seq: int = 0) -> bytes:
    return numbered(
        seq, 0x3D7, bytes([obj, pid, (count << 4) | (index >> 8), index & 0xFF]) + data
    )


# --------------------------------------------------------------------------


class TestCaptureReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name: str) -> str:
        return os.path.join(self.tmp.name, name)

    def test_packets_reads_pcapng_udp(self):
        path = self.path("udp.pcapng")
        udp_capture(
            path,
            [
                (tunneling_request(cemi_ldata("0.0.0", "1.1.5", t_connect())), True),
                (tunneling_ack(), False),
            ],
        )
        pkts = list(cap.packets(path))
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[0].dst_port, KNX_PORT)
        self.assertEqual(pkts[0].src_ip, TOOL_IP)

    def test_packets_reads_pcap_classic(self):
        path = self.path("classic.pcap")
        frame = _eth_ipv4_udp(
            TOOL_IP,
            TOOL_PORT,
            GATEWAY_IP,
            KNX_PORT,
            tunneling_request(cemi_ldata("0.0.0", "1.1.5", t_connect())),
        )
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1))
            fh.write(struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)))
            fh.write(frame)
        frames = knxip.frames_from_file(path)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].service_name, "TUNNELING_REQUEST")

    def test_frames_reassembles_tcp_out_of_order(self):
        """A frame split across two segments that arrive reversed still decodes."""
        knx = tunneling_request(cemi_ldata("0.0.0", "1.1.5", mem_write(0x4000, b"\xaa" * 8)))
        first, second = knx[:5], knx[5:]
        path = self.path("tcp.pcapng")
        write_pcapng(
            path,
            [
                _eth_ipv4_tcp(TOOL_IP, TOOL_PORT, GATEWAY_IP, KNX_PORT, 1000, b"", 0x02),
                # the tail arrives before the head
                _eth_ipv4_tcp(
                    TOOL_IP, TOOL_PORT, GATEWAY_IP, KNX_PORT, 1001 + len(first), second
                ),
                _eth_ipv4_tcp(TOOL_IP, TOOL_PORT, GATEWAY_IP, KNX_PORT, 1001, first),
            ],
        )
        frames = knxip.frames_from_file(path)
        decoded = [f for f in frames if f.service_name == "TUNNELING_REQUEST"]
        self.assertEqual(len(decoded), 1)
        self.assertEqual(decoded[0].cemi.l4.apdu.name, "A_Memory_Write")

    def test_frames_survives_garbage(self):
        """Random bytes and a truncated record never raise; they just yield less."""
        path = self.path("garbage.pcapng")
        write_pcapng(path, [b"\x00" * 3, os.urandom(60), b"\xff" * 200])
        self.assertEqual(knxip.frames_from_file(path), [])

        short = self.path("short.pcapng")
        with open(short, "wb") as fh:
            fh.write(b"\x0a\x0d\x0d\x0a\x00")
        self.assertEqual(knxip.frames_from_file(short), [])

        bad = self.path("bad.bin")
        with open(bad, "wb") as fh:
            fh.write(b"not a capture at all")
        with self.assertRaises(cap.CaptureError):
            knxip.frames_from_file(bad)

    def test_walk_datagram_handles_multiple_frames(self):
        """Several KNXnet/IP frames in one datagram are walked by header length."""
        blob = tunneling_ack(seq=0) + tunneling_ack(seq=1)
        path = self.path("multi.pcapng")
        write_pcapng(path, [_eth_ipv4_udp(GATEWAY_IP, KNX_PORT, TOOL_IP, TOOL_PORT, blob)])
        frames = knxip.frames_from_file(path)
        self.assertEqual([f.service_name for f in frames], ["TUNNELING_ACK"] * 2)
        self.assertEqual([f.fields["seq"] for f in frames], [0, 1])

    def test_walk_datagram_flags_truncated_frame(self):
        """A header claiming more octets than are present is reported, not raised."""
        knx = tunneling_request(cemi_ldata("0.0.0", "1.1.5", t_connect()))
        path = self.path("trunc.pcapng")
        write_pcapng(path, [_eth_ipv4_udp(TOOL_IP, TOOL_PORT, GATEWAY_IP, KNX_PORT, knx[:-3])])
        frames = knxip.frames_from_file(path)
        self.assertTrue(frames[0].is_malformed)
        self.assertIn("truncated", frames[0].note)


class TestApciDecoding(unittest.TestCase):
    def apdu(self, npdu: bytes):
        l4 = knxip.decode_npdu(npdu)
        self.assertIsNotNone(l4)
        return l4

    def test_decode_npdu_control_pdus(self):
        self.assertEqual(self.apdu(b"\x80").kind, "T_Connect")
        self.assertEqual(self.apdu(b"\x81").kind, "T_Disconnect")
        ack = self.apdu(b"\xc2")
        self.assertEqual((ack.kind, ack.seq), ("T_ACK", 0))
        nak = self.apdu(bytes([0xC3 | (5 << 2)]))
        self.assertEqual((nak.kind, nak.seq), ("T_NAK", 5))
        ack7 = self.apdu(bytes([0xC2 | (7 << 2)]))
        self.assertEqual(ack7.seq, 7)

    def test_decode_apdu_device_descriptor(self):
        req = self.apdu(numbered(0, 0x300)).apdu
        self.assertEqual(req.name, "A_DeviceDescriptor_Read")
        res = self.apdu(numbered(0, 0x340, b"\x07\xb0")).apdu
        self.assertEqual(res.fields["mask"], "07B0")

    def test_decode_apdu_property_value(self):
        apdu = self.apdu(prop_write(3, 5, 1, 1, b"\x02")).apdu
        self.assertEqual(apdu.name, "A_PropertyValue_Write")
        self.assertEqual(apdu.fields["obj"], 3)
        self.assertEqual(apdu.fields["pid_name"], "PID_LOAD_STATE_CONTROL")
        self.assertEqual(apdu.fields["count"], 1)
        self.assertEqual(apdu.fields["index"], 1)
        # Written to the device, this octet is a load EVENT ...
        self.assertEqual(apdu.fields["load_event"], "LoadCompleted")
        # ... and read back from it, the same octet is a load STATE.
        response = self.apdu(numbered(0, 0x3D6, bytes([3, 5, 0x10, 0x01, 0x02]))).apdu
        self.assertEqual(response.name, "A_PropertyValue_Response")
        self.assertEqual(response.fields["load_state"], "Loading")

    def test_decode_apdu_property_description(self):
        payload = bytes([3, 5, 0, 0x80 | 0x0A]) + struct.pack("!H", 1) + bytes([0x31])
        apdu = self.apdu(numbered(0, 0x3D9, payload)).apdu
        self.assertEqual(apdu.name, "A_PropertyDescription_Response")
        self.assertEqual(apdu.fields["pdt"], 0x0A)
        self.assertTrue(apdu.fields["write_enabled"])
        self.assertEqual(apdu.fields["read_level"], 3)
        self.assertEqual(apdu.fields["write_level"], 1)

    def test_decode_apdu_alloc_record(self):
        """AdditionalLoadControls / LdCtrlAbsSegment decodes to address and size."""
        data = bytes([0x03, 0x01]) + struct.pack("!I", 0x4B00) + struct.pack("!H", 0x0130) + b"\x30\x00"
        apdu = self.apdu(prop_write(3, 5, 1, 1, data)).apdu
        self.assertEqual(apdu.fields["load_event"], "AdditionalLoadControls")
        self.assertEqual(apdu.fields["ld_ctrl"], "LdCtrlAbsSegment")
        self.assertEqual(apdu.fields["seg_addr"], "0x00004b00")
        self.assertEqual(apdu.fields["seg_size"], 0x0130)

    def test_decode_apdu_memory(self):
        apdu = self.apdu(mem_write(0x4000, b"\x01\x02\x03")).apdu
        self.assertEqual(apdu.name, "A_Memory_Write")
        self.assertEqual(apdu.fields["addr"], "0x4000")
        self.assertEqual(apdu.fields["count"], 3)
        self.assertEqual(apdu.fields["data"], "010203")

        read = self.apdu(numbered(0, 0x200 | 4, struct.pack("!H", 0x4010))).apdu
        self.assertEqual((read.name, read.fields["count"]), ("A_Memory_Read", 4))

    def test_decode_apdu_memory_extended(self):
        """The 3-octet address form used above 64 KB."""
        payload = bytes([4, 0x01, 0x23, 0x45]) + b"\xde\xad\xbe\xef"
        apdu = self.apdu(numbered(0, 0x1FB, payload)).apdu
        self.assertEqual(apdu.name, "A_MemoryExtended_Write")
        self.assertEqual(apdu.fields["addr"], "0x012345")
        self.assertEqual(apdu.fields["count"], 4)

    def test_decode_apdu_restart_variants(self):
        basic = self.apdu(numbered(0, 0x380)).apdu
        self.assertEqual(basic.fields["type"], "basic")
        master = self.apdu(numbered(0, 0x381, b"\x01\x00")).apdu
        self.assertEqual(master.fields["type"], "master-reset")
        self.assertEqual(master.fields["erase_code"], 1)

    def test_decode_apdu_individual_address(self):
        apdu = self.apdu(numbered(0, 0x0C0, struct.pack("!H", ia("1.1.47")))).apdu
        self.assertEqual(apdu.name, "A_IndividualAddress_Write")
        self.assertEqual(apdu.fields["address"], "1.1.47")

    def test_decode_apdu_group_value(self):
        small = knxip.decode_npdu(bytes([0x00, 0x80 | 0x01])).apdu
        self.assertEqual(small.name, "A_GroupValue_Write")
        self.assertTrue(small.fields["small"])
        wide = knxip.decode_npdu(bytes([0x00, 0x80, 0x0C])).apdu
        self.assertEqual(wide.fields["value"], "0c")

    def test_decode_apdu_authorize_redacts_key(self):
        """A project BCU key must never be printed, only hashed."""
        secret = b"\x00" + b"\xde\xad\xbe\xef"
        apdu = self.apdu(numbered(0, 0x3D1, secret)).apdu
        self.assertEqual(apdu.name, "A_Authorize_Request")
        self.assertTrue(str(apdu.fields["key"]).startswith("redacted:"))
        self.assertNotIn("deadbeef", apdu.summary())

        free = self.apdu(numbered(0, 0x3D1, b"\x00\xff\xff\xff\xff")).apdu
        self.assertEqual(free.fields["key"], "FFFFFFFF(free-access)")

    def test_decode_apdu_secure_data_hides_payload(self):
        """A_SecureData reports SCF and sequence, never the protected APDU."""
        protected = b"\xca\xfe" * 8
        payload = b"\x90" + b"\x00\x00\x00\x00\x00\x07" + protected
        apdu = self.apdu(numbered(0, 0x3F1, payload)).apdu
        self.assertEqual(apdu.name, "A_SecureData")
        self.assertEqual(apdu.fields["scf"], "0x90")
        self.assertTrue(apdu.fields["tool_access"])
        self.assertEqual(apdu.fields["seq"], 7)
        self.assertEqual(apdu.fields["protected_len"], len(protected))
        self.assertNotIn(protected.hex(), apdu.summary())

    def test_decode_knxip_secure_services_named_not_decrypted(self):
        body = struct.pack("!H", 0x0001) + b"\x00" * 6 + b"\x11" * 6 + b"\x22\x33" + b"\xaa" * 40
        frame = b"\x06\x10\x09\x50" + struct.pack("!H", 6 + len(body)) + body
        decoded = knxip.decode_knxip(0.0, "a", "b", "udp", frame)
        self.assertEqual(decoded.service_name, "SECURE_WRAPPER")
        self.assertEqual(decoded.fields["session"], "0x0001")
        self.assertIn("encrypted_sha", decoded.fields)
        self.assertNotIn("decrypted", decoded.fields)

        for svc, name in (
            (0x0951, "SESSION_REQUEST"),
            (0x0952, "SESSION_RESPONSE"),
            (0x0953, "SESSION_AUTHENTICATE"),
            (0x0954, "SESSION_STATUS"),
            (0x0955, "TIMER_NOTIFY"),
        ):
            body = b"\x00" * 32
            frame = b"\x06\x10" + struct.pack("!HH", svc, 6 + len(body)) + body
            self.assertEqual(
                knxip.decode_knxip(0.0, "a", "b", "udp", frame).service_name, name
            )

    def test_decode_knxip_connection_lifecycle(self):
        for svc, name in (
            (0x0205, "CONNECT_REQUEST"),
            (0x0206, "CONNECT_RESPONSE"),
            (0x0207, "CONNECTIONSTATE_REQUEST"),
            (0x0209, "DISCONNECT_REQUEST"),
        ):
            body = b"\x01\x00" + b"\x08\x01" + b"\x00" * 10
            frame = b"\x06\x10" + struct.pack("!HH", svc, 6 + len(body)) + body
            decoded = knxip.decode_knxip(0.0, "a", "b", "udp", frame)
            self.assertEqual(decoded.service_name, name)
        body = b"\x07\x24"
        frame = b"\x06\x10" + struct.pack("!HH", 0x0206, 6 + len(body)) + body
        decoded = knxip.decode_knxip(0.0, "a", "b", "udp", frame)
        self.assertEqual(decoded.fields["status"], "NO_MORE_CONNECTIONS")

    def test_decode_cemi_message_codes(self):
        for mc, name in ((0x11, "L_Data.req"), (0x29, "L_Data.ind"), (0x2E, "L_Data.con")):
            cemi = knxip.decode_cemi(cemi_ldata("1.1.1", "1.1.5", t_connect(), mc=mc))
            self.assertEqual(cemi.mc_name, name)
            self.assertEqual(cemi.src, "1.1.1")
            self.assertEqual(cemi.dst, "1.1.5")
            self.assertFalse(cemi.dst_is_group)


class TestNormalize(unittest.TestCase):
    def test_normalize_tpdu_file_ets_da_tp(self):
        """The committed ETS oracle stream normalizes to a System B download."""
        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        buckets = norm.normalize_tpdu_file(path)
        ops = norm.resolve_device(buckets, None)
        self.assertEqual(ops.device, "1.1.2")
        counts = ops.counts()
        for kind in (
            norm.KIND_CONNECT,
            norm.KIND_AUTHORIZE,
            norm.KIND_LOAD_EVENT,
            norm.KIND_ALLOC,
            norm.KIND_MEM_WRITE,
            norm.KIND_RESTART,
        ):
            self.assertIn(kind, counts, "%s missing from %s" % (kind, counts))
        # ETS cycles the L4 connection several times during one download.
        self.assertGreaterEqual(counts[norm.KIND_CONNECT], 1)
        self.assertEqual(counts[norm.KIND_CONNECT], counts.get(norm.KIND_DISCONNECT, 0))
        # L4 acknowledgements are plumbing and must not reach the sequence.
        self.assertGreater(ops.dropped_acks, 20)
        self.assertNotIn("T_ACK", [op.key for op in ops.requests()])

    def test_normalize_tpdu_file_system7_property_lsm(self):
        """A System 7 download shows the property load-state machine."""
        path = os.path.join(FIXTURES, "sys7_jung_flash_requests.txt")
        ops = norm.resolve_device(norm.normalize_tpdu_file(path), None)
        counts = ops.counts()
        self.assertIn(norm.KIND_LOAD_EVENT, counts)
        self.assertIn(norm.KIND_MEM_WRITE, counts)
        image = ops.memory_image()
        self.assertTrue(image)
        self.assertTrue(all(r.end > r.start for r in image))

    def test_normalize_tpdu_file_system7_0701_memory_mapped(self):
        path = os.path.join(FIXTURES, "sys7_theben_0701_flash_requests.txt")
        ops = norm.resolve_device(norm.normalize_tpdu_file(path), None)
        self.assertGreater(len(ops.requests()), 10)

    def test_normalize_drops_confirms_and_acks(self):
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        cemi = cemi_ldata("0.0.0", "1.1.5", mem_write(0x4000, b"\x01\x02"))
        con = cemi_ldata("0.0.0", "1.1.5", mem_write(0x4000, b"\x01\x02"), mc=0x2E)
        udp_capture(
            path,
            [
                (tunneling_request(cemi), True),
                (tunneling_ack(), False),
                (tunneling_request(con, seq=1), False),
                (tunneling_request(cemi_ldata("1.1.5", "0.0.0", b"\xc2", mc=0x29), seq=2), False),
            ],
        )
        ops = norm.resolve_device(norm.normalize(knxip.frames_from_file(path), "1.1.5"), "1.1.5")
        self.assertEqual(len(ops.requests()), 1)
        self.assertEqual(ops.dropped_confirms, 1)
        self.assertEqual(ops.dropped_acks, 1)

    def test_memory_image_coalesces_chunks(self):
        ops = norm.DeviceOps("1.1.5")
        for addr, data in ((0x1000, b"\xaa" * 4), (0x1004, b"\xbb" * 4), (0x2000, b"\xcc")):
            ops.ops.append(
                norm.Op(
                    norm.KIND_MEM_WRITE,
                    "0x%04x" % addr,
                    {"addr_int": addr},
                    "req",
                    data=data,
                )
            )
        image = ops.memory_image()
        self.assertEqual(len(image), 2)
        self.assertEqual((image[0].start, len(image[0].data)), (0x1000, 8))
        self.assertEqual(bytes(image[0].data), b"\xaa" * 4 + b"\xbb" * 4)
        self.assertEqual((image[1].start, len(image[1].data)), (0x2000, 1))


def _ops_from(pairs) -> norm.DeviceOps:
    """Builds a DeviceOps from (kind, key, data) triples, for differ tests."""
    ops = norm.DeviceOps("1.1.5")
    for kind, key, detail, data in pairs:
        ops.ops.append(norm.Op(kind, key, dict(detail), "req", data=data))
    return ops


def _mem(addr: int, data: bytes):
    return (norm.KIND_MEM_WRITE, "0x%04x" % addr, {"addr_int": addr}, data)


class TestDiff(unittest.TestCase):
    def test_diff_identical_sequences(self):
        a = _ops_from([_mem(0x4000, b"\x01\x02\x03\x04")])
        b = _ops_from([_mem(0x4000, b"\x01\x02\x03\x04")])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.IDENTICAL)
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.matched_ops, 1)

    def test_diff_chunking_is_benign(self):
        """The same image written as one chunk or four is not a difference."""
        a = _ops_from([_mem(0x4000, bytes(range(16)))])
        b = _ops_from([_mem(0x4000 + i * 4, bytes(range(i * 4, i * 4 + 4))) for i in range(4)])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.BENIGN)
        self.assertTrue(any(f.reason == "chunking" for f in report.findings))
        self.assertEqual(report.exit_code, 0)

    def test_diff_ordering_of_reads_is_benign(self):
        a = _ops_from(
            [
                (norm.KIND_PROP_READ, "obj3/PID_TABLE_REFERENCE", {}, b""),
                (norm.KIND_PROP_READ, "obj1/PID_LOAD_STATE_CONTROL", {}, b""),
            ]
        )
        b = _ops_from(
            [
                (norm.KIND_PROP_READ, "obj1/PID_LOAD_STATE_CONTROL", {}, b""),
                (norm.KIND_PROP_READ, "obj3/PID_TABLE_REFERENCE", {}, b""),
            ]
        )
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.BENIGN)
        self.assertTrue(any(f.reason == "ordering" for f in report.findings))

    def test_diff_connection_cycling_is_benign(self):
        common = [_mem(0x4000, b"\x01")]
        a = _ops_from(
            [(norm.KIND_CONNECT, "T_Connect", {}, b"")] + common
        )
        b = _ops_from(
            [(norm.KIND_CONNECT, "T_Connect", {}, b"")]
            + common
            + [
                (norm.KIND_DISCONNECT, "T_Disconnect", {}, b""),
                (norm.KIND_CONNECT, "T_Connect", {}, b""),
            ]
        )
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.BENIGN)
        self.assertTrue(any(f.reason == "cycling" for f in report.findings))

    def test_diff_payload_difference_is_real(self):
        a = _ops_from([_mem(0x4000, b"\x01\x02\x03\x04")])
        b = _ops_from([_mem(0x4000, b"\x01\x02\xff\x04")])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.DIFFERENT)
        self.assertEqual(report.exit_code, 1)
        content = [f for f in report.image_findings if f.reason == "content"]
        self.assertTrue(content)
        self.assertIn("0x004002", content[0].detail)
        self.assertIn("03", content[0].detail)
        self.assertIn("ff", content[0].detail)

    def test_diff_missing_operation_is_real(self):
        a = _ops_from(
            [
                (norm.KIND_LOAD_EVENT, "obj3/PID_LOAD_STATE_CONTROL", {"event": "Unload"}, b"\x04"),
                _mem(0x4000, b"\x01"),
            ]
        )
        b = _ops_from([_mem(0x4000, b"\x01")])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.DIFFERENT)
        self.assertTrue(
            any(f.reason in ("missing", "extra") for f in report.findings), report.findings
        )

    def test_diff_coverage_difference_is_real(self):
        """One side writing octets the other never wrote is always reported."""
        a = _ops_from([_mem(0x4000, b"\x01\x02\x03\x04")])
        b = _ops_from([_mem(0x4000, b"\x01\x02")])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.DIFFERENT)
        self.assertTrue(any(f.reason == "coverage" for f in report.image_findings))

    def test_diff_retry_is_benign(self):
        common = [_mem(0x4000, b"\x01")]
        a = _ops_from(common)
        b = _ops_from(common + [_mem(0x4000, b"\x01")])
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.BENIGN)

    def test_diff_secure_sequence_advance_is_benign(self):
        """A fresh secure sequence number must not look like a payload change."""
        a = _ops_from(
            [(norm.KIND_SECURE, "S-A_Data", {"scf": "0x90", "protected_len": 20, "seq": 4}, b"")]
        )
        b = _ops_from(
            [(norm.KIND_SECURE, "S-A_Data", {"scf": "0x90", "protected_len": 20, "seq": 99}, b"")]
        )
        report = opsdiff.diff(a, b)
        self.assertEqual(report.verdict, opsdiff.IDENTICAL)

    def test_diff_of_a_fixture_against_itself_is_identical(self):
        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        ops = norm.resolve_device(norm.normalize_tpdu_file(path), None)
        report = opsdiff.diff(ops, ops, "fixture", "fixture")
        self.assertEqual(report.verdict, opsdiff.IDENTICAL)
        self.assertIn("verdict: IDENTICAL", "\n".join(report.summary_lines()))


def prop_response(obj: int, pid: int, count: int, index: int, data: bytes, seq: int = 0) -> bytes:
    return numbered(
        seq, 0x3D6, bytes([obj, pid, (count << 4) | (index >> 8), index & 0xFF]) + data
    )


class TestImage(unittest.TestCase):
    """`knxtrace image` / `imgdiff`: compose what a download wrote, diff it."""

    def download_capture(self) -> str:
        """A System B download of 1.1.5: a fill-flagged app segment on obj4 whose
        base (0x4000) is read back, sparse parameter writes into it, and a
        non-filled address table on obj1 at 0x1000."""
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        tool, dev = "0.0.0", "1.1.5"

        def rel_seg(size: int, fill: int) -> bytes:
            return bytes([3, 0x0B]) + struct.pack("!I", size) + bytes([fill, 0xAA])

        frames = [
            cemi_ldata(tool, dev, t_connect()),
            cemi_ldata(tool, dev, prop_write(4, 5, 1, 1, rel_seg(16, 1), seq=0)),
            cemi_ldata(dev, tool, prop_response(4, 7, 1, 1, struct.pack("!I", 0x4000)), mc=0x29),
            cemi_ldata(tool, dev, mem_write(0x4002, b"\x01\x02", seq=1)),
            cemi_ldata(tool, dev, mem_write(0x4004, b"\x03", seq=2)),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, rel_seg(4, 0), seq=3)),
            cemi_ldata(dev, tool, prop_response(1, 7, 1, 1, struct.pack("!I", 0x1000)), mc=0x29),
            cemi_ldata(tool, dev, mem_write(0x1000, b"\x00\x01\x08\x01", seq=4)),
            cemi_ldata(tool, dev, t_disconnect()),
        ]
        udp_capture(
            path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)]
        )
        return path

    def tmpdir(self) -> str:
        path = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path

    def test_compose_regions_allocations_and_fill(self):
        out = self.tmpdir()
        code = main(["image", self.download_capture(), "--device", "1.1.5", "--out", out])
        self.assertEqual(code, 0)
        with open(os.path.join(out, "regions.json")) as fh:
            index = json.load(fh)
        self.assertEqual(
            [(r["start"], r["length"]) for r in index["regions"]], [(0x1000, 4), (0x4002, 3)]
        )
        with open(os.path.join(out, "0x004002.bin"), "rb") as fh:
            self.assertEqual(fh.read(), b"\x01\x02\x03")
        allocs = index["allocations"]
        self.assertEqual(len(allocs), 2)
        self.assertEqual((allocs[0]["object"], allocs[0]["base"]), (4, 0x4000))
        self.assertTrue(allocs[0]["fill"])
        self.assertEqual(allocs[0]["written_octets"], 3)
        self.assertEqual((allocs[1]["object"], allocs[1]["base"]), (1, 0x1000))
        self.assertNotIn("composed_file", allocs[1])
        # The fill-flagged allocation composes as fill + sparse writes.
        with open(os.path.join(out, allocs[0]["composed_file"]), "rb") as fh:
            self.assertEqual(fh.read(), b"\xaa\xaa\x01\x02\x03" + b"\xaa" * 11)

    def write_plan(self, steps: list, files: dict) -> str:
        plan_dir = self.tmpdir()
        for name, data in files.items():
            with open(os.path.join(plan_dir, name), "wb") as fh:
                fh.write(data)
        plan = {"device": "1.1.5", "system": "B", "application": {"id": "M-00FA_A-1"},
                "steps": steps, "tables": []}
        with open(os.path.join(plan_dir, "plan.json"), "w") as fh:
            json.dump(plan, fh)
        return plan_dir

    @staticmethod
    def step(n, kind, obj, name, length, address=None):
        return {"index": n, "label": "", "image": {
            "image_kind": kind, "object": obj, "offset": 0, "address": address,
            "file": name, "length": length, "mask_file": None}}

    def test_compare_identical_differs_and_not_comparable(self):
        ets = self.tmpdir()
        main(["image", self.download_capture(), "--device", "1.1.5", "--out", ets])
        plan_dir = self.write_plan(
            [
                # Matches the fill + writes exactly.
                self.step(1, "parameters", 4, "p.bin", 16),
                # One octet differs in the address table.
                self.step(2, "table", 1, "t.bin", 4),
                # An object ETS never allocated.
                self.step(3, "table", 3, "g.bin", 2),
            ],
            {
                "p.bin": b"\xaa\xaa\x01\x02\x03" + b"\xaa" * 11,
                "t.bin": b"\x00\x01\x08\x02",
                "g.bin": b"\x00\x00",
            },
        )
        report = memimage.compare(plan_dir, ets)
        verdicts = [(r["region"], r["verdict"]) for r in report["regions"]]
        self.assertEqual(
            verdicts,
            [
                ("parameters", memimage.IDENTICAL),
                ("address table", memimage.DIFFERS),
                ("group-object table", memimage.NOT_COMPARABLE),
            ],
        )
        table = report["regions"][1]
        self.assertEqual((table["diff_octets"], table["first_offset"]), (1, 3))
        self.assertEqual((table["bussard_hex"], table["ets_hex"]), ("00010802", "00010801"))
        self.assertEqual(report["verdict"], memimage.DIFFERS)
        self.assertEqual(report["ets_only_octets"], 0)
        self.assertEqual(main(["imgdiff", plan_dir, ets]), 1)


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_main_ops_on_fixture(self):
        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        code, out = self.run_cli(["ops", path, "--device", "1.1.2"])
        self.assertEqual(code, 0)
        self.assertIn("normalized operation sequence for 1.1.2", out)
        self.assertIn("memory image", out)

    def test_main_ops_json(self):
        import json

        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        code, out = self.run_cli(["ops", path, "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["device"], "1.1.2")
        self.assertTrue(parsed["ops"])

    def test_main_diff_identical_fixture(self):
        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        code, out = self.run_cli(["diff", path, path, "--device", "1.1.2"])
        self.assertEqual(code, 0)
        self.assertIn("IDENTICAL", out)

    def test_main_devices_and_trace_on_capture(self):
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        udp_capture(
            path,
            [
                (tunneling_request(cemi_ldata("0.0.0", "1.1.5", t_connect())), True),
                (tunneling_ack(), False),
                (tunneling_request(cemi_ldata("0.0.0", "1.1.5", mem_write(0x4000, b"\xaa" * 8)), seq=1), True),
                (tunneling_request(cemi_ldata("0.0.0", "1.1.5", t_disconnect()), seq=2), True),
            ],
        )
        code, out = self.run_cli(["devices", path])
        self.assertEqual(code, 0)
        self.assertIn("1.1.5", out)

        code, out = self.run_cli(["trace", path])
        self.assertEqual(code, 0)
        self.assertIn("TUNNELING_REQUEST", out)
        self.assertIn("A_Memory_Write", out)

    def test_main_ops_unknown_device_explains(self):
        path = os.path.join(FIXTURES, "ets_da_tp_flash_requests.txt")
        with self.assertRaises(SystemExit) as ctx:
            main(["ops", path, "--device", "9.9.9"])
        self.assertIn("no operations for 9.9.9", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
