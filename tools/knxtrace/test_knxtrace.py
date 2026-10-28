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
import datasecure as ds  # noqa: E402
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
        """AdditionalLoadControls / LdCtrlAbsSegment decodes to address and size;
        subtype 01 is a stack segment with the data segment's layout."""
        data = bytes.fromhex("030107f6000100020000")  # MDT A-0222 stack segment
        apdu = self.apdu(prop_write(3, 5, 1, 1, data)).apdu
        self.assertEqual(apdu.fields["load_event"], "AdditionalLoadControls")
        self.assertEqual(apdu.fields["ld_ctrl"], "LdCtrlAbsSegment(stack)")
        self.assertEqual(apdu.fields["seg_addr"], "0x07f6")
        self.assertEqual(apdu.fields["seg_size"], 1)
        self.assertEqual(apdu.fields["mem_type"], "0x02")
        task = self.apdu(prop_write(1, 5, 1, 1, bytes.fromhex("030240000100b6454801"))).apdu
        self.assertEqual((task.fields["pei_type"], task.fields["app_id"]), (1, "00b6454801"))

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

    def test_decode_knxip_secure_dibs_and_srp(self):
        # The Jung interface's extended answer with Secure enabled (issue #90
        # S4): families incl. security, the secured-families DIB, two slots.
        dev = bytearray(54)
        dev[0], dev[1], dev[2] = 54, 0x01, 0x02
        dev[4:6] = struct.pack("!H", 0x11C8)
        dev[24:30] = b"IP-IF1"
        dibs = (
            bytes(dev)
            + bytes([0x0A, 0x02, 0x02, 0x02, 0x03, 0x02, 0x04, 0x02, 0x09, 0x01])
            + bytes([0x06, 0x06, 0x03, 0x01, 0x04, 0x01])
            + bytes([0x0C, 0x07, 0x00, 0xF8, 0x11, 0x16, 0x00, 0x05, 0x11, 0x17, 0x00, 0x04])
        )
        body = bytes([0x08, 0x02, 0, 0, 0, 0, 0, 0]) + dibs
        frame = b"\x06\x10\x02\x0c" + struct.pack("!H", 6 + len(body)) + body
        decoded = knxip.decode_knxip(0.0, "a", "b", "tcp", frame)
        self.assertEqual(decoded.service_name, "SEARCH_RESPONSE_EXTENDED")
        self.assertEqual(decoded.fields["hpai"], "tcp route-back")
        self.assertEqual(decoded.fields["ia"], "1.1.200")
        self.assertIn("security v1", decoded.fields["families"])
        self.assertEqual(
            decoded.fields["secured_families"], ["device_management v1", "tunnelling v1"]
        )
        self.assertEqual(decoded.fields["secure"], "tunnelling secure-only")
        self.assertEqual(decoded.fields["tunnel_slots"], ["1.1.22[u-f]", "1.1.23[u--]"])

        srp = bytes([0x08, 0x04, 0x01, 0x08, 0x02, 0x06, 0x07, 0x00])
        body = bytes([0x08, 0x02, 0, 0, 0, 0, 0, 0]) + srp
        frame = b"\x06\x10\x02\x0b" + struct.pack("!H", 6 + len(body)) + body
        decoded = knxip.decode_knxip(0.0, "a", "b", "tcp", frame)
        self.assertEqual(
            decoded.fields["srp"],
            ["request_dibs:DEVICE_INFO,EXTENDED_DEVICE_INFO,SUPP_SVC_FAMILIES,"
             "SECURED_SERVICE_FAMILIES,TUNNELING_INFO"],
        )

        req = bytes([0x08, 0x02, 0, 0, 0, 0, 0, 0]) + b"\x5a" * 32
        frame = b"\x06\x10\x09\x51" + struct.pack("!H", 6 + len(req)) + req
        decoded = knxip.decode_knxip(0.0, "a", "b", "tcp", frame)
        self.assertEqual(decoded.fields["hpai"], "tcp route-back")
        self.assertEqual(decoded.fields["public_key_len"], 32)

    def test_decode_knxip_tunnelling_feature_codes(self):
        frame = b"\x06\x10\x04\x22\x00\x0c" + b"\x04\x92\x00\x00\x03\x00"
        self.assertEqual(
            knxip.decode_knxip(0.0, "a", "b", "tcp", frame).service_name,
            "TUNNELING_FEATURE_GET",
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


    def test_compare_fill_diff_counts_octets_ets_never_wrote(self):
        ets = self.tmpdir()
        main(["image", self.download_capture(), "--device", "1.1.5", "--out", ets])
        # Offset 0 is fill (ETS never wrote it), offset 2 was written by ETS.
        plan_dir = self.write_plan(
            [self.step(1, "parameters", 4, "p.bin", 16)],
            {"p.bin": b"\x00\xaa\x09\x02\x03" + b"\xaa" * 11},
        )
        report = memimage.compare(plan_dir, ets)
        par = report["regions"][0]
        self.assertEqual(par["verdict"], memimage.DIFFERS)
        self.assertEqual(par["diff_octets"], 2)
        self.assertEqual((par["fill_diff_octets"], par["fill_diff_offsets"]), (1, [0]))
        self.assertIn("1 of them ETS never wrote", "\n".join(memimage.render(report)))

    def test_compare_full_coverage_stays_identical(self):
        ets = self.tmpdir()
        main(["image", self.download_capture(), "--device", "1.1.5", "--out", ets])
        plan_dir = self.write_plan(
            [self.step(1, "parameters", 4, "p.bin", 16), self.step(2, "table", 1, "t.bin", 4)],
            {"p.bin": b"\xaa\xaa\x01\x02\x03" + b"\xaa" * 11, "t.bin": b"\x00\x01\x08\x01"},
        )
        report = memimage.compare(plan_dir, ets)
        self.assertEqual(report["verdict"], memimage.IDENTICAL)
        cov = report["coverage"]
        self.assertEqual((cov["placed"], cov["compared"], cov["percent"]), (20, 20, 100.0))
        self.assertFalse(cov["thin"])
        self.assertIn("coverage 100.0 %", "\n".join(memimage.render(report)))

    def test_compare_thin_row_is_not_comparable(self):
        """Issue #347: one matching octet out of many placed is no evidence."""
        ets = self.tmpdir()
        main(["image", self.download_capture(), "--device", "1.1.5", "--out", ets])
        # An absolute parameter segment at 0x4000 (the capture's filled
        # 16-octet allocation with 3 written octets) with placed octets on two
        # pages; only the first page is in the capture.
        data = bytearray(0x200)
        data[0:16] = b"\xaa\xaa\x01\x02\x03" + b"\xaa" * 11
        step = self.step(1, "parameters", None, "p.bin", len(data), address=0x4000)
        step["image"]["placed"] = {"octets": 12, "ranges": [[2, 4], [0x100, 0x10A]]}
        plan_dir = self.write_plan([step], {"p.bin": bytes(data)})
        report = memimage.compare(plan_dir, ets)
        par = report["regions"][0]
        self.assertEqual(par["verdict"], memimage.IDENTICAL)
        self.assertEqual((par["placed"], par["placed_compared"]), (12, 2))
        self.assertEqual(report["verdict"], memimage.NOT_COMPARABLE)
        cov = report["coverage"]
        self.assertTrue(cov["thin"])
        self.assertEqual(cov["blind_pages"], ["0x4100"])
        self.assertIn("thin", report["reason"])
        # A lower threshold still flags the uncompared page.
        relaxed = memimage.compare(plan_dir, ets, min_coverage=10.0)
        self.assertEqual(relaxed["verdict"], memimage.NOT_COMPARABLE)
        self.assertNotIn("<", relaxed["coverage"]["reason"])
        # The CLI exit code stays 0 for not comparable (only differs fails).
        self.assertEqual(main(["imgdiff", plan_dir, ets]), 0)

    def test_compare_scope_judges_only_named_regions(self):
        """A tables-only capture (a security change) is judged on its tables."""
        ets = self.tmpdir()
        main(["image", self.download_capture(), "--device", "1.1.5", "--out", ets])
        par = self.step(1, "parameters", None, "p.bin", 0x200, address=0x4000)
        par["image"]["placed"] = {"octets": 10, "ranges": [[0x100, 0x10A]]}
        plan_dir = self.write_plan(
            [par, self.step(2, "table", 1, "t.bin", 4)],
            {"p.bin": bytes(0x200), "t.bin": b"\x00\x01\x08\x01"},
        )
        whole = memimage.compare(plan_dir, ets)
        self.assertEqual(whole["verdict"], memimage.DIFFERS)
        scoped = memimage.compare(plan_dir, ets, scope=["addr"])
        self.assertEqual(scoped["verdict"], memimage.IDENTICAL)
        self.assertEqual(scoped["coverage"]["percent"], 100.0)
        self.assertEqual([r["in_scope"] for r in scoped["regions"]], [False, True])
        self.assertIn("(out of scope)", "\n".join(memimage.render(scoped)))
        self.assertEqual(memimage.region_short("app segment 0x4800"), "seg0x4800")


def mem_read(addr: int, count: int, seq: int = 0) -> bytes:
    return numbered(seq, 0x200 | count, struct.pack("!H", addr))


def mem_response(addr: int, data: bytes, seq: int = 0) -> bytes:
    return numbered(seq, 0x240 | len(data), struct.pack("!H", addr) + data)


class TestReadConfirmed(unittest.TestCase):
    """Issue #384: octets ETS read and did not write are read-confirmed."""

    def capture(self) -> str:
        """A read-compare download (mask 0701 style) of 1.1.5: ETS reads
        0x4000..0x4003, writes the one octet that differs (0x4001) and an
        octet it never read (0x4010), then reads 0x4001 back and gets a value
        other than the one it wrote (the Meteodata marker case)."""
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        tool, dev = "0.0.0", "1.1.5"
        frames = [
            cemi_ldata(tool, dev, t_connect()),
            cemi_ldata(tool, dev, mem_read(0x4000, 4, seq=0)),
            cemi_ldata(dev, tool, mem_response(0x4000, b"\xaa\xbb\xcc\xdd", seq=0), mc=0x29),
            cemi_ldata(tool, dev, mem_write(0x4001, b"\x11", seq=1)),
            cemi_ldata(tool, dev, mem_write(0x4010, b"\x22", seq=2)),
            cemi_ldata(tool, dev, mem_read(0x4001, 1, seq=3)),
            cemi_ldata(dev, tool, mem_response(0x4001, b"\x00", seq=1), mc=0x29),
            cemi_ldata(tool, dev, t_disconnect()),
        ]
        udp_capture(path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)])
        return path

    def tmpdir(self) -> str:
        path = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path

    def image(self) -> str:
        out = self.tmpdir()
        self.assertEqual(main(["image", self.capture(), "--device", "1.1.5", "--out", out]), 0)
        return out

    def plan(self, data: bytes) -> str:
        plan_dir = self.tmpdir()
        with open(os.path.join(plan_dir, "p.bin"), "wb") as fh:
            fh.write(data)
        step = {"index": 1, "label": "", "image": {
            "image_kind": "parameters", "object": None, "offset": 0, "address": 0x4000,
            "file": "p.bin", "length": len(data), "mask_file": None}}
        with open(os.path.join(plan_dir, "plan.json"), "w") as fh:
            json.dump({"device": "1.1.5", "system": "7", "application": {"id": "M-00FA_A-1"},
                       "steps": [step], "tables": []}, fh)
        return plan_dir

    def test_compose_confirmed_read_not_written_read_then_written_written_only(self):
        out = self.image()
        with open(os.path.join(out, "regions.json")) as fh:
            index = json.load(fh)
        # Written: 0x4001 (read first, then written) and 0x4010 (written only).
        self.assertEqual([(r["start"], r["length"]) for r in index["regions"]],
                         [(0x4001, 1), (0x4010, 1)])
        # Confirmed: read and never written. 0x4001 is not, though ETS read
        # it before and after its write; 0x4010 is not, never read.
        self.assertEqual([(r["start"], r["file"]) for r in index["confirmed"]],
                         [(0x4000, "confirmed/0x004000.bin"), (0x4002, "confirmed/0x004002.bin")])
        with open(os.path.join(out, "confirmed", "0x004002.bin"), "rb") as fh:
            self.assertEqual(fh.read(), b"\xcc\xdd")
        ets = memimage.EtsMemory(out)
        self.assertEqual(ets.confirmed, {0x4000: 0xAA, 0x4002: 0xCC, 0x4003: 0xDD})
        self.assertEqual(ets.get(0x4001), 0x11)

    def test_compare_confirmed_identical_while_written_is_thin(self):
        report = memimage.compare(self.plan(b"\xaa\x11\xcc\xdd"), self.image())
        self.assertEqual(report["verdict"], memimage.NOT_COMPARABLE)  # 1 of 4 written
        conf = report["confirmed"]
        self.assertEqual((conf["verdict"], conf["octets"], conf["compared"], conf["placed"]),
                         (memimage.IDENTICAL, 3, 3, 4))
        self.assertEqual(conf["percent"], 75.0)
        text = "\n".join(memimage.render(report))
        self.assertIn("written: not-comparable, confirmed: identical (3 octets)", text)
        self.assertIn("confirmed coverage 75.0 %", text)

    def test_compare_confirmed_mismatch_is_reported_separately(self):
        report = memimage.compare(self.plan(b"\xaa\x11\xcc\x00"), self.image())
        par = report["regions"][0]
        # The written octet matches; the confirmed side names the mismatch.
        self.assertEqual(par["verdict"], memimage.IDENTICAL)
        conf = report["confirmed"]
        self.assertEqual(conf["verdict"], memimage.DIFFERS)
        self.assertEqual(conf["mismatches"], [{"address": 0x4003, "offset": 3, "bussard": "00",
                                               "ets": "dd", "region": "parameters"}])
        self.assertEqual(memimage.confirmed_text(report),
                         "written: not-comparable, confirmed: 1 of 3 octets differ at 0x4000+3")
        self.assertIn("confirmed mismatch 0x004003 (par+0x3): bussard 00, device/ETS dd",
                      "\n".join(memimage.render(report)))

    def test_compare_without_confirmed_index_still_works(self):
        out = self.image()
        with open(os.path.join(out, "regions.json")) as fh:
            index = json.load(fh)
        del index["confirmed"]
        with open(os.path.join(out, "regions.json"), "w") as fh:
            json.dump(index, fh)
        conf = memimage.compare(self.plan(b"\xaa\x11\xcc\xdd"), out)["confirmed"]
        self.assertEqual((conf["verdict"], conf["octets"]), (memimage.NOT_COMPARABLE, 0))


def ext_write(obj_type: int, pid: int, count: int, index: int, data: bytes, seq: int = 0) -> bytes:
    """A_PropertyExtValue_WriteCon on instance 1 of an object type."""
    head = struct.pack("!H", obj_type) + ((1 << 12) | pid).to_bytes(3, "big")
    return numbered(seq, 0x1CE, head + bytes([count]) + struct.pack("!H", index) + data)


def func_command(obj_type: int, pid: int, data: bytes, seq: int = 0) -> bytes:
    """A_FunctionPropertyExt_Command on instance 1 of an object type."""
    head = struct.pack("!H", obj_type) + ((1 << 12) | pid).to_bytes(3, "big")
    return numbered(seq, 0x1D4, head + data)


class TestPropertyWrites(unittest.TestCase):
    """`properties.json` and its parity check against bussard's plan."""

    GROUP_KEYS = bytes(range(0x40, 0x52))  # 18 octets, like a PID 53 write
    GO_FLAGS = bytes([0x03] * 20)

    def capture(self) -> str:
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        tool, dev = "0.0.0", "1.1.5"
        mcb = bytes.fromhex("0000180400330000")
        frames = [
            cemi_ldata(tool, dev, t_connect()),
            cemi_ldata(tool, dev, prop_write(4, 5, 1, 1, bytes([4]) + bytes(9), seq=0)),
            cemi_ldata(tool, dev, prop_write(4, 27, 1, 1, mcb, seq=1)),
            cemi_ldata(tool, dev, func_command(17, 5, bytes([1]) + bytes(9), seq=2)),
            cemi_ldata(tool, dev, ext_write(17, 54, 1, 0, b"\x00\x00", seq=3)),
            cemi_ldata(tool, dev, ext_write(17, 53, 1, 1, self.GROUP_KEYS, seq=4)),
            cemi_ldata(tool, dev, ext_write(17, 61, 20, 1, self.GO_FLAGS, seq=5)),
            cemi_ldata(tool, dev, prop_write(4, 13, 1, 1, bytes.fromhex("00fa000112"), seq=6)),
            cemi_ldata(tool, dev, t_disconnect()),
        ]
        udp_capture(path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)])
        return path

    def image_dir(self) -> str:
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        self.assertEqual(main(["image", self.capture(), "--device", "1.1.5", "--out", out]), 0)
        return out

    @staticmethod
    def redacted(data: bytes) -> str:
        import hashlib

        return "redacted:" + hashlib.sha256(data).hexdigest()[:8]

    def test_compose_writes_properties_json_with_redaction(self):
        out = self.image_dir()
        with open(os.path.join(out, "properties.json")) as fh:
            text = fh.read()
        props = json.loads(text)
        self.assertEqual(
            [(p["service"], p["object"], p["pid"], p["length"]) for p in props],
            [
                ("A_PropertyValue_Write", {"index": 4}, 5, 10),
                ("A_PropertyValue_Write", {"index": 4}, 27, 8),
                ("A_FunctionPropertyExt_Command", {"type": 17, "instance": 1}, 5, 10),
                ("A_PropertyExtValue_WriteCon", {"type": 17, "instance": 1}, 54, 2),
                ("A_PropertyExtValue_WriteCon", {"type": 17, "instance": 1}, 53, 18),
                ("A_PropertyExtValue_WriteCon", {"type": 17, "instance": 1}, 61, 20),
                ("A_PropertyValue_Write", {"index": 4}, 13, 5),
            ],
        )
        self.assertEqual(props[1]["data"], "0000180400330000")
        self.assertEqual((props[3]["count"], props[3]["index"], props[3]["data"]), (1, 0, "0000"))
        self.assertIsNone(props[2]["count"])
        # The group key table and the key-sized GO flags are hashed, never hex.
        self.assertEqual(props[4]["data"], self.redacted(self.GROUP_KEYS))
        self.assertEqual(props[5]["data"], self.redacted(self.GO_FLAGS))
        self.assertNotIn(self.GROUP_KEYS.hex(), text)
        with open(os.path.join(out, "regions.json")) as fh:
            self.assertEqual(json.load(fh)["property_writes"], 7)

    def test_is_key_material_rules(self):
        self.assertTrue(ds.is_key_material(17, None, 60, 16))  # zone key table
        self.assertTrue(ds.is_key_material(17, None, 53, 2))
        self.assertTrue(ds.is_key_material(17, None, 61, 16))  # key-sized
        self.assertFalse(ds.is_key_material(17, None, 61, 15))
        self.assertFalse(ds.is_key_material(17, None, 59, 6))
        self.assertFalse(ds.is_key_material(4, None, 56, 32))  # not the security object
        self.assertTrue(ds.is_key_material(None, 4, 56, 16))
        self.assertFalse(ds.is_key_material(None, 0, 56, 2))  # PID_MAX_APDU_LENGTH
        # PID 54 (sender table) is never a key, however long (#384); PID 53
        # and the tool key stay hashed.
        self.assertFalse(ds.is_key_material(17, None, 54, 16))
        self.assertFalse(ds.is_key_material(17, None, 54, 64))
        self.assertTrue(ds.is_key_material(17, None, 53, 18))
        self.assertTrue(ds.is_key_material(17, None, 56, 16))

    def test_compose_shows_a_key_sized_pid54_write(self):
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        senders = bytes.fromhex("1105" + "0040ab845d7b" + "1107" + "004000000002")
        frames = [
            cemi_ldata("0.0.0", "1.1.5", t_connect()),
            cemi_ldata("0.0.0", "1.1.5", ext_write(17, 54, 2, 1, senders, seq=0)),
            cemi_ldata("0.0.0", "1.1.5", ext_write(17, 56, 1, 1, bytes(range(16)), seq=1)),
            cemi_ldata("0.0.0", "1.1.5", t_disconnect()),
        ]
        udp_capture(path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)])
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        self.assertEqual(main(["image", path, "--device", "1.1.5", "--out", out]), 0)
        with open(os.path.join(out, "properties.json")) as fh:
            props = json.load(fh)
        self.assertEqual(props[0]["data"], senders.hex())
        self.assertEqual(props[1]["data"], self.redacted(bytes(range(16))))
        # The decrypted-APDU path (trace, ops) applies the same rule.
        from knxip import decode_apdu
        payload = (struct.pack("!H", 17) + ((1 << 12) | 54).to_bytes(3, "big") + bytes([2])
                   + struct.pack("!H", 1) + senders)
        apdu = ds.redact_keys(decode_apdu(0x1CE, payload, 0x0E))
        self.assertEqual(apdu.fields.get("data"), senders.hex())

    def test_sender_table_names_both_lists_across_lengths(self):
        """bussard admits 1.1.5 and 1.1.7, ETS only 1.1.5: the writes differ in
        length, so the per-write alignment shows them one-sided; the sender
        table line names both lists with their sequence numbers."""
        ours = [self.sec(54, "1105" + "000000000010" + "1107" + "000000000020", length=16,
                         step=24)]
        ets = [self.sec(54, "1105" + "000000000011", length=8, seq=5,
                        service="A_PropertyExtValue_WriteCon")]
        table = memimage._sender_table(ours, ets)
        self.assertEqual(table, {"value": "differs",
                                 "bussard": "1.1.5 (seq 16), 1.1.7 (seq 32)",
                                 "ets": "1.1.5 (seq 17)"})
        props = {"verdict": memimage.DIFFERS, "bussard_writes": 1, "ets_writes": 1,
                 "value_counts": {}, "matched": [], "sender_table": table,
                 "bussard_only": [{"step": 24, "key": ["type17.1", 54, 16]}],
                 "ets_only": [{"ets_seq": 5, "service": "A_PropertyExtValue_WriteCon",
                               "key": ["type17.1", 54, 8], "data": ""}]}
        lines = memimage.render_properties(props)
        self.assertIn("      sender table (PID 54): ETS 1.1.5 (seq 17)", lines)
        self.assertIn("      sender table (PID 54): bussard 1.1.5 (seq 16), 1.1.7 (seq 32)", lines)
        # Equal sets: no sender table line; a redacted side: no table at all.
        self.assertEqual(memimage._sender_table(ours, ours)["value"], "equal")
        self.assertIsNone(memimage._sender_table(ours, [self.sec(54, "redacted:00", length=8)]))

    def test_compare_properties_aligns_plan_steps(self):
        ets = self.image_dir()
        plan_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, plan_dir, ignore_errors=True)
        label = "%d. write property (object %d, type 0, PID %d, %d byte(s) from element 1)"
        plan = {
            "device": "1.1.5", "system": "B", "application": {"id": "M-00FA_A-1"}, "tables": [],
            "steps": [
                # The vendor pads the MCB entry to 10; it goes out as one 8-octet write.
                {"index": 1, "label": label % (1, 4, 27, 10)},
                {"index": 2, "label": "2. load"},
                # A structured record: the key table's hash matches the redacted ETS value.
                {"index": 3, "label": "3.", "property": {
                    "object_type": 17, "instance": 1, "pid": 53, "start_element": 1,
                    "length": 18, "data": self.redacted(self.GROUP_KEYS)}},
                {"index": 4, "label": label % (4, 5, 13, 5)},
                {"index": 5, "label": "5.", "property": {
                    "object": 4, "pid": 13, "start_element": 1, "length": 5, "data": "00fa000113"}},
            ],
        }
        with open(os.path.join(plan_dir, "plan.json"), "w") as fh:
            json.dump(plan, fh)
        props = memimage.compare(plan_dir, ets)["properties"]
        self.assertEqual(props["verdict"], memimage.DIFFERS)
        self.assertEqual(props["ets_load_controls_skipped"], 1)
        self.assertEqual(
            [(m["key"], m["value"]) for m in props["matched"]],
            [
                (["obj4", 27, 8], "no-value"),
                (["type17.1", 53, 18], "hash-equal"),
                (["obj4", 13, 5], "differs"),
            ],
        )
        self.assertEqual([b["key"] for b in props["bussard_only"]], [["obj5", 13, 5]])
        self.assertEqual(
            [e["key"] for e in props["ets_only"]],
            [["type17.1", 5, 10], ["type17.1", 54, 2], ["type17.1", 61, 20]],
        )
        # The image verdict stays its own: no images here, so not comparable.
        self.assertEqual(memimage.compare(plan_dir, ets)["verdict"], memimage.NOT_COMPARABLE)
        lines = "\n".join(memimage.render(memimage.compare(plan_dir, ets)))
        self.assertIn("bussard only: step   4 obj5 PID 13 (5 octets)", lines)
        self.assertNotIn(self.GROUP_KEYS.hex(), lines)

    def ip_capture(self, procedure: bool) -> str:
        """An IP interface download (issue #390): commissioning on objects 17
        and 11, with or without the load procedure's PID 204 write."""
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        tool, dev = "0.0.0", "1.1.200"
        frames = [
            cemi_ldata(tool, dev, t_connect()),
            cemi_ldata(tool, dev, func_command(17, 51, bytes([0, 0, 1]), seq=0)),
            cemi_ldata(tool, dev, ext_write(11, 76, 30, 1, b"IP".ljust(30, b"\0"), seq=1)),
            cemi_ldata(tool, dev, ext_write(11, 92, 1, 1, bytes([0x77] * 16), seq=2)),
        ]
        if procedure:
            frames.append(cemi_ldata(tool, dev, ext_write(11, 204, 1, 1, bytes([10]), seq=3)))
        frames.append(cemi_ldata(tool, dev, t_disconnect()))
        udp_capture(path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)])
        return path

    def ip_plan(self) -> str:
        plan_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, plan_dir, ignore_errors=True)
        plan = {
            "device": "1.1.200", "system": "properties", "application": {"id": "M-0004_A-1"},
            "tables": [],
            "steps": [
                {"index": 1, "label": "1.", "property": {
                    "object_type": 11, "instance": 1, "pid": 204, "start_element": 1,
                    "count": 1, "length": 1, "data": "0a"}},
            ],
        }
        with open(os.path.join(plan_dir, "plan.json"), "w") as fh:
            json.dump(plan, fh)
        return plan_dir

    def test_compare_properties_lists_ip_commissioning_without_counting_it(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        self.assertEqual(main(["image", self.ip_capture(True), "--device", "1.1.200", "--out", out]), 0)
        props = memimage.compare(self.ip_plan(), out)["properties"]
        self.assertEqual(props["verdict"], memimage.IDENTICAL)
        self.assertEqual(
            [e["key"] for e in props["commissioning"]],
            [["type17.1", 51, 3], ["type11.1", 76, 30], ["type11.1", 92, 16]],
        )
        self.assertEqual(props["ets_only"], [])
        # The device authentication code is never written out as hex.
        with open(os.path.join(out, "properties.json")) as fh:
            self.assertNotIn("77" * 16, fh.read())
        lines = "\n".join(memimage.render_properties(props))
        self.assertIn("ETS commissioning (not counted): #3   A_PropertyExtValue_WriteCon type11.1 PID 92", lines)

    def test_compare_properties_names_a_capture_without_the_procedure(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        self.assertEqual(main(["image", self.ip_capture(False), "--device", "1.1.200", "--out", out]), 0)
        props = memimage.compare(self.ip_plan(), out)["properties"]
        self.assertEqual(props["verdict"], memimage.NOT_COMPARABLE)
        self.assertIn("ETS did not run the load procedure", props["reason"])
        self.assertEqual(len(props["commissioning"]), 3)
        lines = "\n".join(memimage.render_properties(props))
        self.assertIn("bussard only: step   1 type11.1 PID 204 (1 octets)", lines)

    def test_normalize_names_the_extended_property_services(self):
        buckets = norm.normalize(knxip.frames_from_file(self.ip_capture(True)), "1.1.200")
        ops = buckets["1.1.200"].requests()
        kinds = [(op.kind, op.key) for op in ops if op.kind not in (norm.KIND_CONNECT, norm.KIND_DISCONNECT)]
        self.assertEqual(
            kinds,
            [
                (norm.KIND_FUNC_PROP, "type17.1/PID51"),
                (norm.KIND_PROP_WRITE, "type11.1/PID76"),
                (norm.KIND_PROP_WRITE, "type11.1/PID92"),
                (norm.KIND_PROP_WRITE, "type11.1/PID204"),
            ],
        )
        secret = [op for op in ops if op.key == "type11.1/PID92"][0]
        self.assertTrue(secret.detail.get("key_material"))
        self.assertNotIn("sha", secret.detail)
        self.assertEqual(secret.data, b"")
        self.assertTrue(ds.is_key_material(11, None, 93, 32))
        self.assertFalse(ds.is_key_material(11, None, 205, 32))

    def test_compare_properties_accepts_a_list_of_records(self):
        # One plan step that goes out as several writes lists them under
        # `properties` (the security object's chunked writes, issue #156).
        ets = self.image_dir()
        plan_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, plan_dir, ignore_errors=True)
        plan = {
            "device": "1.1.5", "system": "B", "application": {"id": "M-00FA_A-1"}, "tables": [],
            "steps": [
                {"index": 1, "label": "1.", "properties": [
                    {"object_type": 17, "instance": 1, "pid": 5, "length": 10},
                    {"object_type": 17, "instance": 1, "pid": 54, "start_element": 0,
                     "length": 2},
                ]},
            ],
        }
        with open(os.path.join(plan_dir, "plan.json"), "w") as fh:
            json.dump(plan, fh)
        entries = memimage.plan_property_writes(plan)
        self.assertEqual(
            [(e["step"], memimage._prop_key(e)) for e in entries],
            [(1, ("type17.1", 5, 10)), (1, ("type17.1", 54, 2))],
        )

    @staticmethod
    def sec(pid: int, data: str, **extra) -> dict:
        entry = {"object": {"type": 17, "instance": 1}, "pid": pid, "data": data}
        entry.update(extra)
        return entry

    def test_value_check_pid54_compares_by_sender_address(self):
        ours = self.sec(54, "1105" + "0040102ea9ce")
        ets = self.sec(54, "1105" + "0040ab845d77")
        self.assertEqual(
            memimage._value_check(ours, ets),
            ("equal", "sequence numbers differ: ETS 1.1.5 (seq %d); bussard 1.1.5 (seq %d)"
             % (0x0040AB845D77, 0x0040102EA9CE)),
        )
        self.assertEqual(memimage._value_check(ours, dict(ets, data=ours["data"])), ("equal", ""))
        outcome, why = memimage._value_check(ours, self.sec(54, "1106" + "0040ab845d77"))
        self.assertEqual((outcome, why), (
            "differs", "senders differ: ETS 1.1.6 (seq %d); bussard 1.1.5 (seq %d)"
            % (0x0040AB845D77, 0x0040102EA9CE)))
        two = "1105" + "000000000001" + "1106" + "000000000001"
        swapped = "1106" + "000000000001" + "1105" + "000000000001"
        outcome, why = memimage._value_check(self.sec(54, two), self.sec(54, swapped))
        self.assertEqual(outcome, "differs")
        self.assertIn("sender order differs", why)
        # Not a whole entry list (the clearing write): plain byte compare.
        self.assertEqual(memimage._value_check(self.sec(54, "0000"), self.sec(54, "0000")),
                         ("equal", ""))
        # Not the security object: plain byte compare.
        plain = {"object": {"index": 4}, "pid": 54, "data": ours["data"]}
        self.assertEqual(memimage._value_check(plain, dict(plain, data=ets["data"])),
                         ("differs", "bytes differ"))

    @staticmethod
    def key_table(*indexes: int) -> bytes:
        """A group key table value: per entry the address table index and a
        16-octet key derived from it."""
        return b"".join(struct.pack(">H", i) + bytes([0x10 + i] * 16) for i in indexes)

    def key_write(self, table: bytes, salt: str = "run-salt", groups=None) -> dict:
        """A PID 53 write as either side lists it; `groups` (index to group
        address) names the entries, as bussard's dump does."""
        entries = memimage.group_key_entries(table, salt)
        for e in entries:
            if groups and e["index"] in groups:
                e["ga"] = groups[e["index"]]
        return self.sec(53, self.redacted(table), length=len(table), entries=entries)

    def test_value_check_pid53_names_the_group_per_entry(self):
        groups = {1: "0/0/6", 2: "1/2/3"}
        ours_table = self.key_table(1, 2)
        ets_table = struct.pack(">H", 1) + bytes([0x33] * 16) + self.key_table(2)
        ours = self.key_write(ours_table, groups=groups)
        self.assertEqual([(e["index"], e["ga"]) for e in ours["entries"]],
                         [(1, "0/0/6"), (2, "1/2/3")])
        # ETS's entries carry the index only: named by bussard's group.
        ets = self.key_write(ets_table)
        self.assertEqual(memimage._value_check(ours, ets), ("differs", "0/0/6: key differs"))
        self.assertEqual(memimage._value_check(ours, dict(ours)), ("hash-equal", ""))
        ets_one = self.key_write(self.key_table(2))
        self.assertEqual(memimage._value_check(ours, ets_one),
                         ("differs", "0/0/6: missing in ETS"))
        self.assertEqual(memimage._value_check(ets_one, ours),
                         ("differs", "0/0/6: missing in bussard"))
        # With ETS's own address table resolved, entries match by group even
        # when the indexes moved (ETS's table has an extra group first).
        ets_shifted = self.key_write(self.key_table(2, 3), groups={2: "0/0/6", 3: "1/2/3"})
        for e, idx in zip(ets_shifted["entries"], (1, 2)):
            # Same keys as ours under a different index.
            e["key"] = ours["entries"][idx - 1]["key"]
        self.assertEqual(memimage._value_check(ours, ets_shifted), ("hash-equal", ""))
        # The entry hash is salted: never the hash or hex of a bare key.
        text = json.dumps(ours)
        for i in (1, 2):
            key = bytes([0x10 + i] * 16)
            self.assertNotIn(self.redacted(key)[len("redacted:"):], text)
            self.assertNotIn(key.hex(), text)
        other = memimage.group_key_entries(ours_table, "other-salt")
        self.assertNotEqual(other[0]["key"], ours["entries"][0]["key"])
        # Without entries on one side (no salt): the whole-value hash, as before.
        self.assertEqual(memimage._value_check(dict(ours, entries=None), ets),
                         ("differs", "hash differs"))

    def test_group_key_table_compares_across_chunks(self):
        groups = {i: "0/0/%d" % i for i in range(1, 6)}
        # bussard writes 3 + 1 entries, ETS 2 + 3: index 4 is extra on the ETS side.
        ours = [self.key_write(self.key_table(1, 2, 3), groups=groups),
                self.key_write(self.key_table(5), groups=groups)]
        ets = [self.key_write(self.key_table(1, 2)), self.key_write(self.key_table(3, 4, 5))]
        gk = memimage._group_key_table(ours, ets)
        self.assertEqual((gk["value"], gk["why"]), ("differs", "index 4: missing in bussard"))
        self.assertEqual((gk["bussard_entries"], gk["ets_entries"]), (4, 5))
        same = memimage._group_key_table(
            [self.key_write(self.key_table(1, 2, 3), groups=groups)],
            [self.key_write(self.key_table(1)), self.key_write(self.key_table(2, 3))],
        )
        self.assertEqual(same["value"], "hash-equal")
        # One side without salted entries: no table verdict.
        self.assertIsNone(memimage._group_key_table([dict(ours[0], entries=None)], ets))
        props = {
            "verdict": memimage.DIFFERS, "bussard_writes": 2, "ets_writes": 2,
            "value_counts": {}, "bussard_only": [], "ets_only": [], "matched": [],
            "group_key_table": gk,
        }
        self.assertIn("      group key table (PID 53, bussard 4, ETS 5 entries): "
                      "index 4: missing in bussard", memimage.render_properties(props))

    def test_ets_groups_reads_the_address_table_ets_wrote(self):
        class Mem:
            def __init__(self, base: int, data: bytes):
                self.base, self.data = base, data

            def get(self, at: int):
                i = at - self.base
                return self.data[i] if 0 <= i < len(self.data) else None

        table = struct.pack(">HHH", 2, 0x0006, 0x0A03)  # count 2: 0/0/6, 1/2/3
        results = [{"region": "address table", "address": 0x4000}]
        self.assertEqual(
            memimage._ets_groups({"system": "B"}, results, Mem(0x4000, table)),
            {1: "0/0/6", 2: "1/2/3"},
        )
        self.assertEqual(memimage._ets_groups({"system": "7"}, results, Mem(0x4000, table)), {})
        self.assertEqual(memimage._ets_groups({"system": "B"}, results, Mem(0x5000, table)), {})

    def test_compose_lists_group_key_entries_under_the_salt(self):
        from unittest import mock

        with mock.patch.dict(os.environ, {memimage.ORACLE_SALT_ENV: "run-salt"}):
            out = self.image_dir()
        with open(os.path.join(out, "properties.json")) as fh:
            text = fh.read()
        props = json.loads(text)
        self.assertEqual(props[4]["pid"], 53)
        self.assertEqual(props[4]["entries"],
                         memimage.group_key_entries(self.GROUP_KEYS, "run-salt"))
        self.assertNotIn(self.GROUP_KEYS.hex(), text)
        self.assertNotIn(self.GROUP_KEYS[2:].hex(), text)
        self.assertNotIn("run-salt", text)
        with mock.patch.dict(os.environ, {memimage.ORACLE_SALT_ENV: ""}):
            out = self.image_dir()
        with open(os.path.join(out, "properties.json")) as fh:
            self.assertNotIn("entries", json.load(fh)[4])

    def test_render_properties_prints_the_pid54_note(self):
        props = {
            "verdict": memimage.IDENTICAL, "bussard_writes": 1, "ets_writes": 1,
            "value_counts": {"equal": 1}, "bussard_only": [], "ets_only": [],
            "matched": [{"step": 25, "key": ["type17.1", 54, 8], "value": "equal",
                         "why": "sequence numbers differ: ETS 0040ab845d77, bussard 0040102ea9ce"}],
        }
        props["matched"].append({"step": 26, "key": ["obj4", 13, 5], "value": "no-value",
                                 "why": "plan.json carries no value for this step"})
        lines = memimage.render_properties(props)
        self.assertFalse(any("obj4 PID 13" in line for line in lines))
        self.assertIn(
            "      step  25 type17.1 PID 54 (8 octets): equal "
            "(sequence numbers differ: ETS 0040ab845d77, bussard 0040102ea9ce)",
            lines,
        )

    def test_compare_properties_without_properties_json(self):
        ets = self.image_dir()
        os.unlink(os.path.join(ets, "properties.json"))
        props = memimage.compare_properties({"steps": []}, ets)
        self.assertEqual(props["verdict"], memimage.NOT_COMPARABLE)


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


# --------------------------------------------------------------------------
# Data Secure
# --------------------------------------------------------------------------

# Synthetic keys only. The known-answer vectors come from the Rust reference
# (`crates/bussard-secure/src/{crypto,asdu}.rs`, `crates/bussard-project/src/
# keyring.rs`) so a divergence from bussard's own implementation fails here.
SYN_TOOL_KEY = bytes([0x42] * 16)
SYN_FDSK = bytes([0x24] * 16)
SYN_GROUP_KEY = bytes([0x77] * 16)
SYN_PASSWORD = "synthetic-keyring-pw"

# keyring.rs `FULL`: generated by an independent implementation of the
# documented algorithm with a made-up password.
RUST_FULL_KEYRING = """<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-02-03T04:05:06" Signature="BwFnB3x3sq9qwzQsIIYDHQ==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="1000" Key="XXLSoIYX1PClHpjLLr06xw==" />
  <Interface Type="Tunneling" Host="1.1.0" IndividualAddress="1.1.200" UserID="2" Password="CEuTO5HdZ/da1DOMrSJhAQZ94w6kq3rM2I2EFv/3fWw=" Authentication="fj0EBnFwaOJuRN85Aovn5Z8UU1ndm0p0F5tkraeg72Y=">
    <Group Address="2563" Senders="1.1.10" />
  </Interface>
  <GroupAddresses>
    <Group Address="2563" Key="9gsADI4+cx1p65cAhr5GDA==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="1.1.10" ToolKey="4KejWFAOVLtfuK2uo4tiyA==" ManagementPassword="v66sERBaqXzGcl6zuAsdsA==" Authentication="Qoy1wZsb3MhAe+PdJd6p4uHl3mt02IukjeAPcy2BWrE=" SequenceNumber="42" />
  </Devices>
</Keyring>"""


def synthetic_keyring(devices: dict, groups: dict = None, password: str = SYN_PASSWORD) -> str:
    """A signed .knxkeys document. `devices` maps IA -> {"ToolKey": k, "FDSK": k}."""
    import base64
    import hashlib
    import xml.etree.ElementTree as ET

    created = "2026-03-04T05:06:07"
    kk = hashlib.pbkdf2_hmac("sha256", password.encode(), ds.KEYRING_SALT, 65536, 16)
    iv = hashlib.sha256(created.encode()).digest()[:16]
    aes = ds.Aes128(kk)

    def enc(key: bytes) -> str:
        return base64.b64encode(aes.encrypt_block(bytes(a ^ b for a, b in zip(key, iv)))).decode()

    root = ET.Element("Keyring", {"Project": "Synthetic", "CreatedBy": "knxtrace-test", "Created": created})
    if groups:
        ga = ET.SubElement(root, "GroupAddresses")
        for addr, key in groups.items():
            ET.SubElement(ga, "Group", {"Address": str(addr), "Key": enc(key)})
    devs = ET.SubElement(root, "Devices")
    for addr, keys in devices.items():
        ET.SubElement(devs, "Device", {"IndividualAddress": addr, **{k: enc(v) for k, v in keys.items()}})
    sig = base64.b64encode(hashlib.sha256(ds._canonical(root, kk)).digest()[:16]).decode()
    root.set("Signature", sig)
    return ET.tostring(root, encoding="unicode")


def secure_npdu(key: bytes, seq_l4: int, src: str, dst: str, seq: int, inner: bytes, scf: int = 0x90) -> bytes:
    """A numbered A_SecureData TPDU wrapping `inner` (APCI octets + data)."""
    tpci = 0x40 | ((seq_l4 & 0x0F) << 2) | 0x03
    asdu = ds.encode(key, scf, seq, ds.Addressing(ia(src), ia(dst), False, 0, tpci), inner)
    return bytes([tpci, 0xF1]) + asdu


SYN_CHALLENGE = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6])


def sync_req_npdu(seq_l4: int, seq: int) -> bytes:
    tpci = 0x40 | ((seq_l4 & 0x0F) << 2) | 0x03
    addr = ds.Addressing(ia("1.1.25"), ia("1.1.12"), False, 0, tpci)
    return bytes([tpci, 0xF1]) + ds.encode_sync_req(SYN_TOOL_KEY, seq, bytes(6), SYN_CHALLENGE, addr)


def sync_res_npdu(seq_l4: int) -> bytes:
    tpci = 0x40 | ((seq_l4 & 0x0F) << 2) | 0x03
    addr = ds.Addressing(ia("1.1.12"), ia("1.1.25"), False, 0, tpci)
    return bytes([tpci, 0xF1]) + ds.encode_sync_res(SYN_TOOL_KEY, 501, 1001, SYN_CHALLENGE, 0x777777, addr)


class TestDataSecure(unittest.TestCase):
    def test_aes128_fips197_vector(self):
        aes = ds.Aes128(bytes(range(16)))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = aes.encrypt_block(pt)
        self.assertEqual(ct.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes.decrypt_block(ct), pt)
        self.assertNotIn("00010203", repr(aes))

    def test_cbc_mac_rust_zero_key_vector(self):
        mac = ds.cbc_mac(ds.Aes128(bytes(16)), b"\x11", b"", bytes(16))
        self.assertEqual(mac.hex(), "7b4e7efe4a9b4662fd0371aa9f1a2f5f")

    def test_tp_block_0_tpci_octet_is_not_shifted_twice(self):
        for octet, expected in ((0x42, 0x43), (0x46, 0x47), (0x00, 0x03)):
            self.assertEqual(ds.tp_block_0(1, 0x1101, 0x1102, False, 0, octet, 7)[12], expected)
        self.assertEqual(ds.tp_counter_0(42, 0x1101, 0x110A)[6:].hex(), "1101110a000000000100")

    def test_encode_decode_rust_known_answer_vector(self):
        key = bytes(range(16))
        addr = ds.Addressing(0x1101, 0x1102, False, 0, 0x42)
        inner = bytes([0x03, 0xD1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
        vectors = {
            # The corrected (bussard PR #153) vector: one keystream over
            # mac(4) || payload.
            0x90: "9000000000002afbb8725d145fbe98a53da2",
            0x80: "8000000000002a03d100ffffffffb5a46c9f",
        }
        for scf, expected in vectors.items():
            asdu = ds.encode(key, scf, 42, addr, inner)
            self.assertEqual(asdu.hex(), expected)
            plain, ok = ds.decode(key, asdu, addr)
            self.assertTrue(ok)
            self.assertEqual(plain, inner)

    def test_payload_keystream_continues_after_the_mac(self):
        """The payload is XORed with AES(counter_0)[4:], not AES(counter_0 + 1)."""
        key = bytes(range(16))
        addr = ds.Addressing(0x1101, 0x1102, False, 0, 0x42)
        apdu = bytes([0x03, 0x00])
        asdu = ds.encode(key, 0x90, 42, addr, apdu)
        ks = ds.Aes128(key).encrypt_block(ds.tp_counter_0(42, 0x1101, 0x1102))
        self.assertEqual(asdu[7:9], bytes(a ^ b for a, b in zip(apdu, ks[4:6])))

    def test_sync_req_round_trip(self):
        key = bytes(range(16))
        addr = ds.Addressing(0x1101, 0x1102, False, 0, 0x42)
        serial = bytes([0x00, 0xFA, 0x12, 0x34, 0x56, 0x78])
        challenge = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        asdu = ds.encode_sync_req(key, 0x0012_3456_789A, serial, challenge, addr)
        self.assertEqual(len(asdu), 23)
        self.assertEqual(asdu[7:13], serial)  # in the clear
        self.assertNotEqual(asdu[13:19], challenge)  # encrypted
        self.assertEqual(ds.decode_sync_req(key, asdu, addr), (0x0012_3456_789A, serial, challenge, True))
        forged = bytearray(asdu)
        forged[8] ^= 0x01  # the serial is authenticated
        self.assertFalse(ds.decode_sync_req(key, bytes(forged), addr)[3])

    def test_sync_res_round_trip(self):
        key = bytes(range(16))
        addr = ds.Addressing(0x1101, 0x1102, False, 0, 0x42)
        challenge = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        asdu = ds.encode_sync_res(key, 0x0012_3456_0001, 0x0012_3456_789A, challenge, 0x0102_0304_0506, addr)
        self.assertEqual(len(asdu), 23)
        self.assertEqual(asdu[1:7].hex(), "112233445566")  # nonce XOR challenge
        self.assertEqual(ds.decode_sync_res(key, asdu, addr, challenge), (0x0012_3456_0001, 0x0012_3456_789A, True))
        self.assertFalse(ds.decode_sync_res(key, asdu, addr, bytes(6))[2])

    def test_decode_reports_mac_failure(self):
        addr = ds.Addressing(0x1101, 0x110A, False, 0, 0x42)
        asdu = bytearray(ds.encode(bytes(16), 0x90, 7, addr, b"\x02\x80\x00\x10\x01"))
        self.assertFalse(ds.decode(bytes([0x99] * 16), bytes(asdu), addr)[1])
        asdu[-1] ^= 0xFF
        self.assertFalse(ds.decode(bytes(16), bytes(asdu), addr)[1])
        # The addressing is authenticated too.
        other = ds.Addressing(0x1102, 0x110A, False, 0, 0x42)
        good = ds.encode(bytes(16), 0x90, 7, addr, b"\x03\x00")
        self.assertFalse(ds.decode(bytes(16), good, other)[1])

    def test_parse_keyring_rust_fixture(self):
        ring = ds.parse_keyring(RUST_FULL_KEYRING, SYN_PASSWORD)
        self.assertEqual(ring.tool_keys, {ia("1.1.10"): SYN_TOOL_KEY})
        self.assertEqual(ring.group_keys, {2563: SYN_GROUP_KEY})
        self.assertNotIn("42424242", repr(ring))

    def test_parse_keyring_wrong_password(self):
        with self.assertRaises(ds.KeyringError) as ctx:
            ds.parse_keyring(RUST_FULL_KEYRING, "not-the-password")
        self.assertIn("wrong keyring password", str(ctx.exception))

    def test_parse_keyring_reads_fdsk_and_three_level_groups(self):
        text = synthetic_keyring(
            {"1.1.12": {"ToolKey": SYN_TOOL_KEY, "FDSK": SYN_FDSK}}, {"1/2/3": SYN_GROUP_KEY}
        )
        ring = ds.parse_keyring(text, SYN_PASSWORD)
        self.assertEqual(ring.tool_keys[ia("1.1.12")], SYN_TOOL_KEY)
        self.assertEqual(ring.fdsks[ia("1.1.12")], SYN_FDSK)
        self.assertEqual(ring.group_keys[(1 << 11) | (2 << 8) | 3], SYN_GROUP_KEY)

    def secure_capture(self) -> str:
        """ETS-shaped: FDSK exchange, then tool-key traffic, one unknown device."""
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        read_desc = bytes([0x03, 0x00])
        prop_read = bytes([0x03, 0xD5, 0x11, 0x36, 0x10, 0x01])  # obj 17, PID 54
        desc_resp = bytes([0x03, 0x40, 0x07, 0xB0])
        frames = [
            (tunneling_request(cemi_ldata("1.1.25", "1.1.12", secure_npdu(SYN_FDSK, 0, "1.1.25", "1.1.12", 1000, read_desc))), True),
            (tunneling_request(cemi_ldata("1.1.12", "1.1.25", secure_npdu(SYN_FDSK, 0, "1.1.12", "1.1.25", 500, desc_resp), mc=0x29), seq=1), False),
            (tunneling_request(cemi_ldata("1.1.25", "1.1.12", sync_req_npdu(1, 999)), seq=6), True),
            (tunneling_request(cemi_ldata("1.1.12", "1.1.25", sync_res_npdu(1), mc=0x29), seq=7), False),
            (tunneling_request(cemi_ldata("1.1.25", "1.1.12", secure_npdu(SYN_TOOL_KEY, 1, "1.1.25", "1.1.12", 1001, prop_read)), seq=2), True),
            # A replayed (non-increasing) sequence from the tool.
            (tunneling_request(cemi_ldata("1.1.25", "1.1.12", secure_npdu(SYN_TOOL_KEY, 2, "1.1.25", "1.1.12", 1001, prop_read)), seq=3), True),
            # Wrong key: the keyring has keys for 1.1.12, none verifies.
            (tunneling_request(cemi_ldata("1.1.25", "1.1.12", secure_npdu(bytes([0x99] * 16), 3, "1.1.25", "1.1.12", 1002, prop_read)), seq=4), True),
            # No key for 1.1.40 at all.
            (tunneling_request(cemi_ldata("1.1.25", "1.1.40", secure_npdu(bytes([0x55] * 16), 0, "1.1.25", "1.1.40", 1003, read_desc)), seq=5), True),
        ]
        udp_capture(path, frames)
        return path

    def keyring_file(self) -> str:
        path = tempfile.mkstemp(suffix=".knxkeys")[1]
        self.addCleanup(os.unlink, path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(synthetic_keyring({"1.1.12": {"ToolKey": SYN_TOOL_KEY, "FDSK": SYN_FDSK}}))
        return path

    def test_unwrap_frames_decodes_inner_apdus(self):
        frames = knxip.frames_from_file(self.secure_capture())
        ring = ds.load_keyring(self.keyring_file(), SYN_PASSWORD)
        ds.unwrap_frames(frames, ring)
        apdus = [f.cemi.l4.apdu for f in frames if f.cemi is not None]
        self.assertEqual([a.fields.get("mac") for a in apdus], ["ok", "ok", "ok", "ok", "ok", "ok", "FAIL", None])
        self.assertEqual([a.fields.get("key") for a in apdus[:6]], ["fdsk", "fdsk", "tool", "tool", "tool", "tool"])
        self.assertEqual(apdus[0].inner.name, "A_DeviceDescriptor_Read")
        self.assertEqual(apdus[1].inner.fields["mask"], "07B0")
        self.assertIn("seq=999 tool MAC ok} -> S-A_Sync_Req serial=none challenge_len=6", apdus[2].summary())
        self.assertIn("MAC ok} -> S-A_Sync_Res responder_seq=501 requester_seq=1001", apdus[3].summary())
        self.assertNotIn(SYN_CHALLENGE.hex(), apdus[2].summary())
        self.assertEqual(apdus[4].inner.fields["pid"], 54)
        self.assertIn("A_SecureData{scf=0x90 seq=1001 tool MAC ok} -> A_PropertyValue_Read", apdus[4].summary())
        self.assertIsNone(apdus[6].inner)
        self.assertNotIn("mac", apdus[7].fields)

    def test_unwrap_frames_learns_tunnel_source(self):
        """A 0.0.0 source is retried with the address the L_Data.con showed."""
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        npdu = secure_npdu(SYN_TOOL_KEY, 0, "1.1.25", "1.1.12", 7, bytes([0x03, 0x00]))
        udp_capture(
            path,
            [
                (tunneling_request(cemi_ldata("1.1.25", "1.1.12", t_connect(), mc=0x2E)), False),
                (tunneling_request(cemi_ldata("0.0.0", "1.1.12", npdu), seq=1), True),
            ],
        )
        frames = knxip.frames_from_file(path)
        ds.unwrap_frames(frames, ds.parse_keyring(synthetic_keyring({"1.1.12": {"ToolKey": SYN_TOOL_KEY}}), SYN_PASSWORD))
        self.assertEqual(frames[1].cemi.l4.apdu.fields.get("mac"), "ok")

    def test_unwrap_frames_redacts_a_written_tool_key(self):
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        new_key = bytes([0x5A] * 16)
        write = bytes([0x03, 0xD7, 0x04, 56, 0x10, 0x01]) + new_key  # obj 4, PID_TOOL_KEY
        npdu = secure_npdu(SYN_FDSK, 0, "1.1.25", "1.1.12", 9, write)
        udp_capture(path, [(tunneling_request(cemi_ldata("1.1.25", "1.1.12", npdu)), True)])
        frames = knxip.frames_from_file(path)
        ds.unwrap_frames(frames, ds.parse_keyring(synthetic_keyring({"1.1.12": {"FDSK": SYN_FDSK}}), SYN_PASSWORD))
        summary = frames[0].cemi.l4.apdu.summary()
        self.assertIn("fdsk MAC ok} -> A_PropertyValue_Write", summary)
        self.assertIn("data=redacted:", summary)
        self.assertNotIn(new_key.hex(), summary)
        # Normalizing a redacted write keeps the real octets for hashing, and
        # the property dump shows only the hash.
        ops = norm.normalize(frames)["1.1.12"]
        self.assertEqual(ops.ops[0].kind, norm.KIND_PROP_WRITE)
        self.assertEqual(ops.ops[0].data, new_key)
        props = memimage.property_writes(ops)
        self.assertEqual((props[0]["object"], props[0]["pid"], props[0]["length"]), ({"index": 4}, 56, 16))
        self.assertEqual(props[0]["data"], "redacted:" + knxip.sha8(new_key))
        self.assertEqual(props[0]["secured"], "fdsk")

    def test_decode_apdu_property_ext_and_redaction(self):
        """Extended property services decode; a key written to object type 17 is hidden."""
        key = bytes([0x5A] * 16)
        payload = bytes([0x00, 17, 0x00, 0x10, 56, 1, 0x00, 0x01]) + key
        apdu = knxip.decode_apdu(0x1CE, payload, 0)
        self.assertEqual(apdu.name, "A_PropertyExtValue_WriteCon")
        self.assertEqual((apdu.fields["obj_type"], apdu.fields["instance"], apdu.fields["pid"]), (17, 1, 56))
        self.assertEqual((apdu.fields["count"], apdu.fields["index"]), (1, 1))
        ds.redact_keys(apdu)
        self.assertTrue(apdu.fields["data"].startswith("redacted:"))
        resp = knxip.decode_apdu(0x1CF, bytes([0x00, 17, 0x00, 0x10, 56, 1, 0x00, 0x01, 0x00]), 0)
        self.assertEqual(resp.fields["rc"], "0x00")

    def test_sequence_problems_flags_replay(self):
        frames = knxip.frames_from_file(self.secure_capture())
        problems = ds.sequence_problems(frames)
        self.assertEqual(len(problems), 1)
        self.assertIn("1.1.25", problems[0])
        self.assertIn("seq 1001 <= previous 1001", problems[0])

    def test_normalize_uses_inner_apdu(self):
        frames = knxip.frames_from_file(self.secure_capture())
        ds.unwrap_frames(frames, ds.load_keyring(self.keyring_file(), SYN_PASSWORD))
        counts = norm.normalize(frames)["1.1.12"].counts()
        self.assertEqual(counts.get("prop-read"), 2)
        self.assertEqual(counts.get("descriptor"), 1)  # requests only
        self.assertEqual(counts.get("secure-data"), 2)  # the Sync_Req and the frame whose MAC failed

    def test_main_trace_and_devices_with_keyring(self):
        import contextlib
        import io

        capture_path, keyring_path = self.secure_capture(), self.keyring_file()
        old = os.environ.get("BUSSARD_KEYRING_PASSWORD")
        os.environ["BUSSARD_KEYRING_PASSWORD"] = SYN_PASSWORD
        self.addCleanup(
            lambda: os.environ.pop("BUSSARD_KEYRING_PASSWORD", None)
            if old is None
            else os.environ.__setitem__("BUSSARD_KEYRING_PASSWORD", old)
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["trace", capture_path, "--keyring", keyring_path, "--seq-check"]), 0)
        out = buf.getvalue()
        self.assertIn("seq=1000 fdsk MAC ok} -> A_DeviceDescriptor_Read", out)
        self.assertIn("MAC FAIL", out)
        self.assertIn("sequence check: 1 non-increasing", out)
        self.assertNotIn(SYN_TOOL_KEY.hex(), out)
        self.assertNotIn(SYN_FDSK.hex(), out)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["devices", capture_path, "--keyring", keyring_path]), 0)
        out = buf.getvalue()
        self.assertIn("prop-read x2", out)
        self.assertIn("MAC ok (tool key)", out)

    def test_main_keyring_needs_password_env(self):
        old = os.environ.pop("BUSSARD_KEYRING_PASSWORD", None)
        if old is not None:
            self.addCleanup(os.environ.__setitem__, "BUSSARD_KEYRING_PASSWORD", old)
        with self.assertRaises(SystemExit) as ctx:
            main(["trace", self.secure_capture(), "--keyring", self.keyring_file()])
        self.assertIn("BUSSARD_KEYRING_PASSWORD", str(ctx.exception))



# --------------------------------------------------------------------------
# Device management connections and KNXnet/IP Secure sessions (issue #398)
# --------------------------------------------------------------------------


def device_info_dib(device: str, name: str = "Synthetic IP") -> bytes:
    """A DEVICE_INFO DIB (54 octets) naming the server's individual address."""
    body = (
        bytes([0x02, 0x00])
        + struct.pack("!H", ia(device))
        + b"\x00\x00"
        + bytes(6)  # serial
        + bytes([224, 0, 23, 12])
        + bytes(6)  # MAC
        + name.encode().ljust(30, b"\x00")
    )
    return bytes([2 + len(body), 0x01]) + body


def knxip_frame(service: int, body: bytes) -> bytes:
    return b"\x06\x10" + struct.pack("!HH", service, 6 + len(body)) + body


def device_configuration(cemi: bytes, channel: int = 3, seq: int = 0) -> bytes:
    return knxip_frame(0x0310, bytes([0x04, channel, seq, 0x00]) + cemi)


def t_data_connected(npdu: bytes, mc: int = 0x41) -> bytes:
    """A cEMI T_Data_Connected frame: reserved addressing, then the TPDU."""
    return bytes([mc, 0x00]) + bytes(6) + bytes([len(npdu) - 1]) + npdu


def unnumbered(tpdu: bytes) -> bytes:
    """The same TPDU as an unnumbered data PDU (what a T_Data_Connected carries)."""
    return bytes([tpdu[0] & 0x03]) + tpdu[1:]


def m_prop_write(obj_type: int, pid: int, count: int, index: int, data: bytes) -> bytes:
    return (
        bytes([0xF6])
        + struct.pack("!H", obj_type)
        + bytes([1, pid, (count << 4) | (index >> 8), index & 0xFF])
        + data
    )


def enc_password(kk: bytes, iv: bytes, password: str) -> str:
    """An ETS-style encrypted password: 8-octet prefix, password, PKCS#7, AES-CBC."""
    import base64

    blob = bytes(range(8)) + password.encode()
    pad = 16 - len(blob) % 16
    blob += bytes([pad]) * pad
    aes = ds.Aes128(kk)
    out, prev = b"", iv
    for i in range(0, len(blob), 16):
        prev = aes.encrypt_block(bytes(a ^ b for a, b in zip(blob[i:i + 16], prev)))
        out += prev
    return base64.b64encode(out).decode()


def ip_secure_keyring(device: str, auth: str, management: str, users: dict, password: str = SYN_PASSWORD) -> str:
    """A signed keyring with KNXnet/IP Secure passwords for one interface."""
    import base64
    import hashlib
    import xml.etree.ElementTree as ET

    created = "2026-03-04T05:06:07"
    kk = hashlib.pbkdf2_hmac("sha256", password.encode(), ds.KEYRING_SALT, 65536, 16)
    iv = hashlib.sha256(created.encode()).digest()[:16]
    root = ET.Element("Keyring", {"Project": "Synthetic", "CreatedBy": "knxtrace-test", "Created": created})
    for n, (user, pw) in enumerate(sorted(users.items())):
        ET.SubElement(root, "Interface", {
            "Type": "Tunneling", "Host": device, "IndividualAddress": "1.1.%d" % (100 + n),
            "UserID": str(user), "Password": enc_password(kk, iv, pw),
            "Authentication": enc_password(kk, iv, auth),
        })
    devs = ET.SubElement(root, "Devices")
    ET.SubElement(devs, "Device", {
        "IndividualAddress": device,
        "ManagementPassword": enc_password(kk, iv, management),
        "Authentication": enc_password(kk, iv, auth),
    })
    sig = base64.b64encode(hashlib.sha256(ds._canonical(root, kk)).digest()[:16]).decode()
    root.set("Signature", sig)
    return ET.tostring(root, encoding="unicode")


def tcp_capture(path: str, knx_frames: list, client_port: int = TOOL_PORT) -> None:
    """Every frame as one TCP segment of one connection, client <-> gateway."""
    eth = []
    seq = {True: 1000, False: 5000}
    for frame, to_gateway in knx_frames:
        if to_gateway:
            eth.append(_eth_ipv4_tcp(TOOL_IP, client_port, GATEWAY_IP, KNX_PORT, seq[True], frame))
        else:
            eth.append(_eth_ipv4_tcp(GATEWAY_IP, KNX_PORT, TOOL_IP, client_port, seq[False], frame))
        seq[to_gateway] += len(frame)
    write_pcapng(path, eth)


SYN_AUTH_CODE = "synthetic-device-auth"
SYN_MGMT_PW = "synthetic-management"
SYN_USERS = {2: "synthetic-user-2", 3: "synthetic-user-3"}
TCP_ROUTE_BACK = bytes([0x08, 0x02]) + bytes(6)


class TestDeviceManagement(unittest.TestCase):
    def test_decode_cemi_t_data_connected(self):
        cemi = knxip.decode_cemi(t_data_connected(bytes([0x03, 0x00])))
        self.assertEqual(cemi.mc_name, "T_Data_Connected.req")
        self.assertEqual(cemi.l4.apdu.name, "A_DeviceDescriptor_Read")
        resp = knxip.decode_cemi(t_data_connected(bytes([0x03, 0x40, 0x00, 0x21]), mc=0x89))
        self.assertEqual(resp.mc_name, "T_Data_Connected.ind")
        self.assertEqual(resp.l4.apdu.fields["mask"], "0021")

    def test_decode_cemi_management_property_services(self):
        cemi = knxip.decode_cemi(m_prop_write(11, 76, 3, 1, b"abc"))
        apdu = cemi.l4.apdu
        self.assertEqual(apdu.name, "M_PropWrite.req")
        self.assertEqual(
            (apdu.fields["obj_type"], apdu.fields["instance"], apdu.fields["pid"],
             apdu.fields["count"], apdu.fields["index"], apdu.fields["data"]),
            (11, 1, 76, 3, 1, b"abc".hex()),
        )
        self.assertEqual(apdu.fields["pid_name"], "PID_FRIENDLY_NAME")
        con = knxip.decode_cemi(bytes([0xF5, 0x00, 0x0B, 0x01, 76, 0x00, 0x01, 0x07]))
        self.assertEqual(con.l4.apdu.fields["error"], "0x07")
        func = knxip.decode_cemi(bytes([0xF8, 0x00, 0x0B, 0x01, 94, 0x00, 0x00, 0x03, 0x01]))
        self.assertEqual(func.l4.apdu.fields["family"], "device_management")
        self.assertEqual(func.l4.apdu.fields["secured"], "on")
        self.assertEqual(knxip.decode_cemi(bytes([0xF1])).l4.apdu.name, "M_Reset.req")

    def test_decode_cemi_management_redacts_a_device_authentication_code(self):
        code = bytes([0x3C] * 16)
        apdu = knxip.decode_cemi(m_prop_write(11, 92, 1, 1, code)).l4.apdu
        self.assertTrue(apdu.fields["data"].startswith("redacted:"))
        self.assertNotIn(code.hex(), apdu.summary())

    def test_decode_function_command_security_mode(self):
        head = struct.pack("!H", 17) + ((1 << 12) | 51).to_bytes(3, "big")
        apdu = knxip.decode_apdu(0x1D4, head + bytes([0x00, 0x00, 0x01]), 0)
        self.assertEqual((apdu.fields["pid_name"], apdu.fields["mode"]), ("PID_SECURITY_MODE", "on"))

    def test_decode_knxip_connect_request_names_the_connection(self):
        mgmt = knxip.decode_knxip(0.0, "a", "b", "tcp", knxip_frame(0x0205, TCP_ROUTE_BACK * 2 + b"\x02\x03"))
        self.assertEqual(mgmt.fields["connection"], "device_management")
        tunnel = knxip.decode_knxip(
            0.0, "a", "b", "tcp", knxip_frame(0x0205, TCP_ROUTE_BACK * 2 + b"\x04\x04\x02\x00")
        )
        self.assertEqual((tunnel.fields["connection"], tunnel.fields["layer"]), ("tunnel", "0x02"))

    def device_management_capture(self) -> str:
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        friendly = b"Synthetic".ljust(10, b"\x00")
        frames = [
            (knxip_frame(0x0203, TCP_ROUTE_BACK), True),
            (knxip_frame(0x0204, device_info_dib("1.1.250")), False),
            (knxip_frame(0x0205, TCP_ROUTE_BACK * 2 + b"\x02\x03"), True),
            (device_configuration(t_data_connected(bytes([0x03, 0x00]))), True),
            (device_configuration(t_data_connected(bytes([0x03, 0x40, 0x00, 0x21]), mc=0x89)), False),
            (device_configuration(t_data_connected(unnumbered(ext_write(11, 204, 1, 1, b"\x0a")))), True),
            (device_configuration(m_prop_write(11, 76, 10, 1, friendly)), True),
        ]
        tcp_capture(path, frames)
        return path

    def test_device_management_frames_are_filed_under_the_server(self):
        frames = knxip.frames_from_file(self.device_management_capture())
        config = [f for f in frames if f.service == 0x0310]
        self.assertEqual([f.fields["device"] for f in config], ["1.1.250"] * 4)
        ops = norm.normalize(frames)["1.1.250"]
        self.assertEqual(ops.counts(), {"descriptor": 1, "prop-write": 2})
        props = memimage.property_writes(ops)
        self.assertEqual(
            [(p["service"], p["object"], p["pid"], p["length"]) for p in props],
            [
                ("A_PropertyExtValue_WriteCon", {"type": 11, "instance": 1}, 204, 1),
                ("M_PropWrite.req", {"type": 11, "instance": 1}, 76, 10),
            ],
        )
        self.assertEqual(props[1]["data"], b"Synthetic".ljust(10, b"\x00").hex())


class TestIpSecureSessions(unittest.TestCase):
    def keyring(self, auth: str = SYN_AUTH_CODE) -> "ds.Keyring":
        return ds.parse_keyring(ip_secure_keyring("1.1.250", auth, SYN_MGMT_PW, SYN_USERS), SYN_PASSWORD)

    def test_session_response_mac_matches_the_rust_vector(self):
        import ipsecure

        mac = ipsecure.session_response_mac(bytes([0x01] * 16), 1, bytes([0x11] * 32), bytes([0x22] * 32))
        self.assertEqual(mac.hex(), "3651034f87ba7fdad9675c2db8a9e52c")

    def test_parse_keyring_decrypts_ip_secure_passwords(self):
        ring = ds.parse_keyring(RUST_FULL_KEYRING, SYN_PASSWORD)
        self.assertEqual(ring.user_passwords[(ia("1.1.0"), 2)], b"tunnel-user-pw")
        self.assertEqual(ring.auth_codes[ia("1.1.0")], b"device-auth-pw")
        self.assertIn(ia("1.1.10"), ring.management_passwords)
        self.assertNotIn("tunnel-user-pw", repr(ring))

    def session_capture(self, code: str) -> str:
        import ipsecure

        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        client, server = bytes([0x11] * 32), bytes([0x22] * 32)
        key = ds.derive_ip_secure_key(code.encode(), ds.DEVICE_AUTH_SALT)
        mac = ipsecure.session_response_mac(key, 1, client, server)

        def wrapper(plain_len: int, seq: int) -> bytes:
            return knxip_frame(0x0950, struct.pack("!H", 1) + seq.to_bytes(6, "big") + bytes(8)
                               + bytes(plain_len) + bytes(16))

        frames = [
            (knxip_frame(0x0203, TCP_ROUTE_BACK), True),
            (knxip_frame(0x0204, device_info_dib("1.1.250")), False),
            (knxip_frame(0x0951, TCP_ROUTE_BACK + client), True),
            (knxip_frame(0x0952, struct.pack("!H", 1) + server + mac), False),
            (wrapper(24, 0), True),
            (wrapper(8, 0), False),
            (wrapper(24, 1), True),
            (wrapper(18, 1), False),
        ]
        tcp_capture(path, frames)
        return path

    def test_sessions_verify_the_device_authentication_code(self):
        import ipsecure

        frames = knxip.frames_from_file(self.session_capture(SYN_AUTH_CODE))
        found = ipsecure.sessions(frames, self.keyring())
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].device, "1.1.250")
        self.assertEqual(found[0].connection, "device_management")
        self.assertIn("device authentication verified: device authentication code of 1.1.250",
                      found[0].authenticated_by)
        self.assertEqual(found[0].shape(), ">24 <8 >24 <18")
        other = ipsecure.sessions(frames, self.keyring(auth="another-code"))
        self.assertEqual(other[0].authenticated_by, "device authentication matches no code in the keyring")

    def test_main_image_names_secure_sessions_for_a_missing_device(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["image", self.session_capture(SYN_AUTH_CODE), "--device", "1.1.250",
                  "--out", tempfile.mkdtemp()])
        self.assertIn("1 KNXnet/IP Secure session(s) (device_management x1)", str(ctx.exception))

    def test_credential_check_names_the_keyring_entry_never_the_value(self):
        ring = self.keyring()
        auth_key = ds.derive_ip_secure_key(SYN_AUTH_CODE.encode(), ds.DEVICE_AUTH_SALT)
        mgmt = ds.derive_ip_secure_key(SYN_MGMT_PW.encode(), ds.USER_PASSWORD_SALT)
        user2 = ds.derive_ip_secure_key(SYN_USERS[2].encode(), ds.USER_PASSWORD_SALT)
        head = struct.pack("!H", 11)
        write92 = knxip.decode_apdu(0x1CE, head + ((1 << 12) | 92).to_bytes(3, "big") + b"\x01\x00\x01" + auth_key, 0)
        label = ds.credential_check(ring, ia("1.1.250"), write92)
        self.assertIn("equals the device authentication code of 1.1.250", label)
        hashes = mgmt + user2 + bytes(16)
        write93 = knxip.decode_apdu(0x1CE, head + ((1 << 12) | 93).to_bytes(3, "big") + b"\x03\x00\x01" + hashes, 0)
        label = ds.credential_check(ring, ia("1.1.250"), write93)
        self.assertTrue(label.startswith("user 1 = "), label)
        self.assertIn("user 3 matches nothing", label)
        self.assertNotIn(mgmt.hex(), label + write93.summary())
        self.assertTrue(write93.fields["data"].startswith("redacted:"))

    def test_keyring_extra_rings_add_candidates(self):
        first = ds.parse_keyring(synthetic_keyring({"1.1.12": {"FDSK": SYN_FDSK}}), SYN_PASSWORD)
        second = ds.parse_keyring(synthetic_keyring({"1.1.12": {"ToolKey": SYN_TOOL_KEY}}), SYN_PASSWORD)
        first.extra = [second]
        cands = first.candidates(ia("1.1.25"), ia("1.1.12"), False, True)
        self.assertEqual([label for label, _ in cands], ["tool", "fdsk"])


class TestIpSecureCompare(unittest.TestCase):
    """`imgdiff` of a `bussard interface secure --dry-run` plan (issue #398)."""

    def ets_dir(self, records) -> str:
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        with open(os.path.join(out, "properties.json"), "w") as fh:
            json.dump(records, fh)
        return out

    @staticmethod
    def ets(seq, obj_type, pid, data_hex, index=1, redact=False, service="A_PropertyExtValue_WriteCon"):
        import hashlib

        data = bytes.fromhex(data_hex)
        value = "redacted:" + hashlib.sha256(data).hexdigest()[:8] if redact else data_hex
        return {"seq": seq, "service": service, "object": {"type": obj_type, "instance": 1},
                "pid": pid, "count": 1, "index": index, "length": len(data), "data": value,
                "secured": "tool"}

    @staticmethod
    def ours(step, obj_type, pid, data_hex, start=1, secret=False, phase="tool"):
        import hashlib

        data = bytes.fromhex(data_hex)
        rec = {"object_type": obj_type, "instance": 1, "pid": pid, "start_element": start,
               "length": len(data), "phase": phase}
        if secret:
            rec["sha256"] = hashlib.sha256(data).hexdigest()
        else:
            rec["data"] = data_hex
        return {"index": step, "label": "step %d" % step, "phase": phase, "properties": [rec]}

    def test_compare_properties_ip_secure_filters_and_hashes(self):
        key = "42" * 16
        ets = [
            self.ets(1, 11, 76, "4142"),  # the [knxnet] table: not an IP Secure property
            self.ets(2, 17, 56, key, redact=True),
            self.ets(3, 11, 94, "00000401", index=None, service="A_FunctionPropertyExt_Command"),
        ]
        plan = {"system": "ip-secure", "steps": [
            self.ours(1, 17, 56, key, secret=True, phase="fdsk"),
            self.ours(2, 11, 94, "00000401", start=None),
        ]}
        props = memimage.compare_properties(plan, self.ets_dir(ets))
        self.assertEqual(props["verdict"], memimage.IDENTICAL, props)
        self.assertEqual(props["value_counts"], {"hash-equal": 1, "equal": 1})
        only_tool = memimage.compare_properties(plan, self.ets_dir(ets), phase="tool")
        self.assertEqual(only_tool["verdict"], memimage.DIFFERS)
        self.assertEqual([e["key"][1] for e in only_tool["ets_only"]], [56])

    def test_compare_properties_ip_secure_sequence_is_not_a_value(self):
        plan = {"system": "ip-secure", "steps": [{"index": 1, "label": "seq", "properties": [
            {"object_type": 17, "instance": 1, "pid": 59, "start_element": 1, "length": 6,
             "phase": "tool"}]}]}
        props = memimage.compare_properties(plan, self.ets_dir([self.ets(1, 17, 59, "0040b605ae0c")]))
        self.assertEqual(props["verdict"], memimage.IDENTICAL)
        self.assertIn("clock", props["matched"][0]["why"])


class TestLoadControls(unittest.TestCase):
    """`load_controls.json` and the load-control parity (issue #419)."""

    UNLOAD = bytes([4]) + bytes(9)
    START = bytes([1]) + bytes(9)
    DONE = bytes([2]) + bytes(9)
    ALLOC = bytes.fromhex("0300400001d5ff038000")
    TASK = bytes.fromhex("030240000100b6454801")
    LSM_RECORD = bytes.fromhex("33040046eb010000000000")

    def capture(self) -> str:
        path = tempfile.mkstemp(suffix=".pcapng")[1]
        self.addCleanup(os.unlink, path)
        tool, dev = "0.0.0", "1.1.5"
        frames = [
            cemi_ldata(tool, dev, t_connect()),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, self.UNLOAD, seq=0)),
            cemi_ldata(tool, dev, prop_write(2, 5, 1, 1, self.UNLOAD, seq=1)),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, self.START, seq=2)),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, self.ALLOC, seq=3)),
            cemi_ldata(tool, dev, mem_write(0x4000, b"\x01\x02", seq=4)),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, self.TASK, seq=5)),
            cemi_ldata(tool, dev, prop_write(1, 5, 1, 1, self.DONE, seq=6)),
            cemi_ldata(tool, dev, mem_write(0x0104, self.LSM_RECORD, seq=7)),
            cemi_ldata(tool, dev, t_disconnect()),
        ]
        udp_capture(path, [(tunneling_request(f, seq=n), True) for n, f in enumerate(frames)])
        return path

    def image_dir(self) -> str:
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        self.assertEqual(main(["image", self.capture(), "--device", "1.1.5", "--out", out]), 0)
        return out

    @staticmethod
    def plan(records) -> dict:
        steps = [{"index": n + 1, "label": "", "load_controls": [r]} for n, r in enumerate(records)]
        return {"device": "1.1.5", "system": "7", "steps": steps, "tables": [],
                "load_control_records": len(records)}

    @staticmethod
    def prop(obj, data: bytes) -> dict:
        return {"form": "property", "object": obj, "data": data.hex()}

    def ours(self, task: bytes = TASK) -> list:
        return [
            # The pre-download pass and the procedure both unload LSM 1.
            self.prop(1, self.UNLOAD), self.prop(2, self.UNLOAD), self.prop(1, self.UNLOAD),
            self.prop(1, self.START), self.prop(1, self.ALLOC), self.prop(1, task),
            self.prop(1, self.DONE),
            {"form": "memory", "lsm": 3, "address": 0x0104, "data": self.LSM_RECORD.hex()},
        ]

    def test_compose_writes_load_controls_in_order(self):
        with open(os.path.join(self.image_dir(), memimage.LOAD_CONTROLS_FILE)) as fh:
            records = json.load(fh)
        self.assertEqual(
            [(r["form"], r.get("object"), r.get("lsm")) for r in records],
            [("property", 1, None), ("property", 2, None)] + [("property", 1, None)] * 4
            + [("memory", None, 3)],
        )
        self.assertEqual(records[3]["data"], self.ALLOC.hex())
        self.assertEqual(records[-1]["data"], self.LSM_RECORD.hex())

    def test_compare_load_controls_identical_collapses_an_immediate_repeat(self):
        lc = memimage.compare_load_controls(self.plan(self.ours()), self.image_dir())
        self.assertEqual(lc["verdict"], memimage.IDENTICAL, lc)
        self.assertEqual(lc["objects"][0], {"object": 1, "bussard": 5, "ets": 5,
                                            "verdict": memimage.IDENTICAL})

    def test_compare_load_controls_differs_names_the_record(self):
        other = bytes.fromhex("03024000000004454801")
        lc = memimage.compare_load_controls(self.plan(self.ours(task=other)), self.image_dir())
        self.assertEqual(lc["verdict"], memimage.DIFFERS)
        first = lc["first"]
        self.assertEqual((first["object"], first["position"], first["kind"], first["event"]),
                         (1, 4, "value", "task-segment"))
        self.assertEqual((first["bussard_hex"], first["ets_hex"]), (other.hex(), self.TASK.hex()))
        lines = "\n".join(memimage.render_load_controls(lc))
        self.assertIn(other.hex(), lines)

    def test_compare_load_controls_form_and_missing_record_differ(self):
        ours = self.ours()[:-1] + [self.prop(3, bytes.fromhex("030446eb010000000000"))]
        ours.append(self.prop(4, self.UNLOAD))
        lc = memimage.compare_load_controls(self.plan(ours), self.image_dir())
        self.assertEqual(lc["verdict"], memimage.DIFFERS)
        kinds = {(d["object"], d["kind"]) for d in lc["differences"]}
        self.assertEqual(kinds, {(3, "value"), (4, "bussard-only")})

    def test_compare_load_controls_not_comparable_without_plan_field(self):
        plan = self.plan(self.ours())
        del plan["load_control_records"]
        lc = memimage.compare_load_controls(plan, self.image_dir())
        self.assertEqual(lc["verdict"], memimage.NOT_COMPARABLE)
        self.assertIn("rebuild bussard", lc["reason"])

    def test_compare_load_controls_pairs_an_unresolved_object(self):
        ets = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, ets, ignore_errors=True)
        with open(os.path.join(ets, memimage.LOAD_CONTROLS_FILE), "w") as fh:
            json.dump([{"seq": 1, "form": "property", "object": 3, "data": self.UNLOAD.hex()}], fh)
        plan = self.plan([self.prop(None, self.UNLOAD)])
        plan["system"] = "B"
        lc = memimage.compare_load_controls(plan, ets)
        self.assertEqual(lc["verdict"], memimage.IDENTICAL, lc)
        self.assertTrue(lc["notes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
