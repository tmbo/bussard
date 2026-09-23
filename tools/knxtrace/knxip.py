"""KNXnet/IP, cEMI, transport layer (L4) and application layer (APCI) decoding.

The layering mirrors the wire:

    KNXnet/IP frame  ->  cEMI L_Data  ->  TPCI (L4)  ->  APCI (application)

Everything here is pure: bytes in, dataclasses out. No file or socket I/O, so
the whole decoder is unit-testable against raw TPDU fixtures.

Sources: the published KNX standard (3/3/7 Application Layer, 3/5/2 Management
Procedures, 3/8/2 KNXnet/IP Core, 3/8/4 Tunnelling), the Wireshark dissector's
public field definitions, and bussard's own clean-room constants in
`crates/bussard-mgmt/src/apci.rs` and `crates/bussard-secure/src/asdu.rs`.

Privacy: this decoder never prints key material. `A_Authorize` keys other than
the well-known free-access key are redacted to a hash, and KNXnet/IP Secure
session frames are named and sized but never decrypted. `A_SecureData` (Data
Secure) payloads are reported as a length and a hash here; with an ETS keyring,
`datasecure.unwrap_frames` verifies the MAC afterwards and attaches the
decrypted inner APDU as `Apdu.inner`, decoded by this module like any other.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from capture import Packet, TcpStream, packets as read_packets

KNXIP_HEADER = b"\x06\x10"
HEADER_LEN = 6

SERVICE_NAMES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST",
    0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST",
    0x020A: "DISCONNECT_RESPONSE",
    0x020B: "SEARCH_REQUEST_EXTENDED",
    0x020C: "SEARCH_RESPONSE_EXTENDED",
    0x0310: "DEVICE_CONFIGURATION_REQUEST",
    0x0311: "DEVICE_CONFIGURATION_ACK",
    0x0420: "TUNNELING_REQUEST",
    0x0421: "TUNNELING_ACK",
    0x0430: "TUNNELING_FEATURE_GET",
    0x0431: "TUNNELING_FEATURE_RESPONSE",
    0x0432: "TUNNELING_FEATURE_SET",
    0x0433: "TUNNELING_FEATURE_INFO",
    0x0530: "ROUTING_INDICATION",
    0x0531: "ROUTING_LOST_MESSAGE",
    0x0532: "ROUTING_BUSY",
    0x0950: "SECURE_WRAPPER",
    0x0951: "SESSION_REQUEST",
    0x0952: "SESSION_RESPONSE",
    0x0953: "SESSION_AUTHENTICATE",
    0x0954: "SESSION_STATUS",
    0x0955: "TIMER_NOTIFY",
}

SECURE_SERVICES = (0x0950, 0x0951, 0x0952, 0x0953, 0x0954, 0x0955)

SESSION_STATUS_NAMES = {
    0x00: "AUTHENTICATION_SUCCESS",
    0x01: "AUTHENTICATION_FAILED",
    0x02: "UNAUTHENTICATED",
    0x03: "TIMEOUT",
    0x04: "KEEPALIVE",
    0x05: "CLOSE",
}

CONNECT_STATUS = {
    0x00: "NO_ERROR",
    0x21: "CONNECTION_ID",
    0x22: "CONNECTION_TYPE",
    0x23: "CONNECTION_OPTION",
    0x24: "NO_MORE_CONNECTIONS",
    0x25: "NO_MORE_UNIQUE_CONNECTIONS",
    0x26: "DATA_CONNECTION",
    0x27: "KNX_CONNECTION",
    0x29: "TUNNELLING_LAYER",
}

CEMI_MESSAGE_CODES = {
    0x11: "L_Data.req",
    0x2E: "L_Data.con",
    0x29: "L_Data.ind",
    0x10: "L_Raw.req",
    0x2D: "L_Raw.con",
    0x2F: "L_Raw.ind",
    0x13: "L_Poll_Data.req",
    0x25: "L_Poll_Data.con",
    0xFC: "M_PropRead.req",
    0xFB: "M_PropRead.con",
    0xF6: "M_PropWrite.req",
    0xF5: "M_PropWrite.con",
    0xF7: "M_PropInfo.ind",
    0xF8: "M_FuncPropCommand.req",
    0xF9: "M_FuncPropStateRead.req",
    0xFA: "M_FuncProp.con",
    0xF1: "M_Reset.req",
    0xF0: "M_Reset.ind",
}

PRIORITY_NAMES = {0: "system", 1: "normal", 2: "urgent", 3: "low"}

# --- Application layer -----------------------------------------------------

A_SECURE_DATA = 0x03F1
FREE_ACCESS_KEY = bytes.fromhex("ffffffff")

# APCIs whose full 10 bits are the service selector.
APCI_EXACT = {
    0x000: "A_GroupValue_Read",
    0x0C0: "A_IndividualAddress_Write",
    0x100: "A_IndividualAddress_Read",
    0x140: "A_IndividualAddress_Response",
    0x1CC: "A_PropertyExtValue_Read",
    0x1CD: "A_PropertyExtValue_Response",
    0x1CE: "A_PropertyExtValue_WriteCon",
    0x1CF: "A_PropertyExtValue_WriteConResponse",
    0x1D0: "A_PropertyExtValue_WriteUnCon",
    0x1D2: "A_PropertyExtDescription_Read",
    0x1D3: "A_PropertyExtDescription_Response",
    0x1D4: "A_FunctionPropertyExt_Command",
    0x1D5: "A_FunctionPropertyExt_State_Read",
    0x1D6: "A_FunctionPropertyExt_State_Response",
    0x1FB: "A_MemoryExtended_Write",
    0x1FC: "A_MemoryExtended_Write_Response",
    0x1FD: "A_MemoryExtended_Read",
    0x1FE: "A_MemoryExtended_Read_Response",
    0x2C0: "A_UserMemory_Read",
    0x2C1: "A_UserMemory_Response",
    0x2C2: "A_UserMemory_Write",
    0x2C5: "A_UserManufacturerInfo_Read",
    0x2C6: "A_UserManufacturerInfo_Response",
    0x3A1: "A_Restart_Response",
    0x3D0: "A_ADC_Read",
    0x3D1: "A_Authorize_Request",
    0x3D2: "A_Authorize_Response",
    0x3D3: "A_Key_Write",
    0x3D4: "A_Key_Response",
    0x3D5: "A_PropertyValue_Read",
    0x3D6: "A_PropertyValue_Response",
    0x3D7: "A_PropertyValue_Write",
    0x3D8: "A_PropertyDescription_Read",
    0x3D9: "A_PropertyDescription_Response",
    0x3DA: "A_NetworkParameter_Read",
    0x3DB: "A_NetworkParameter_Response",
    0x3DC: "A_IndividualAddressSerialNumber_Read",
    0x3DD: "A_IndividualAddressSerialNumber_Response",
    0x3DE: "A_IndividualAddressSerialNumber_Write",
    0x3E0: "A_DomainAddress_Write",
    0x3E1: "A_DomainAddress_Read",
    0x3E2: "A_DomainAddress_Response",
    A_SECURE_DATA: "A_SecureData",
}
# APCIs whose low 6 bits carry a parameter (count, descriptor type, restart type).
APCI_MASKED = {
    0x040: "A_GroupValue_Response",
    0x080: "A_GroupValue_Write",
    0x200: "A_Memory_Read",
    0x240: "A_Memory_Response",
    0x280: "A_Memory_Write",
    0x300: "A_DeviceDescriptor_Read",
    0x340: "A_DeviceDescriptor_Response",
    0x380: "A_Restart",
}
APCI_SELECTOR_MASK = 0x3C0

# Interface objects, by index, as every System B / System 7 device lays them out.
OBJECT_NAMES = {
    0: "device",
    1: "address-table",
    2: "association-table",
    3: "application-program",
    4: "interface-program",
    5: "eib-object-associationtable",
    6: "router",
    7: "lte-address-routing-table",
    8: "cemi-server",
    9: "group-object-table",
    10: "polling-master",
    11: "knxnet-ip-parameter",
    17: "file-server",
    19: "security",
}

PID_NAMES = {
    5: "PID_LOAD_STATE_CONTROL",
    7: "PID_TABLE_REFERENCE",
    9: "PID_PEI_TYPE",
    11: "PID_SERIAL_NUMBER",
    12: "PID_MANUFACTURER_ID",
    13: "PID_PROGRAM_VERSION",
    14: "PID_DEVICE_CONTROL",
    15: "PID_ORDER_INFO",
    19: "PID_MCB_TABLE",
    25: "PID_TABLE",
    51: "PID_ROUTING_COUNT",
    52: "PID_MAX_RETRY_COUNT",
    54: "PID_PROGMODE",
    56: "PID_MAX_APDU_LENGTH",
    59: "PID_DEVICE_DESCRIPTOR",
    78: "PID_HARDWARE_TYPE",
    83: "PID_RF_DOMAIN_ADDRESS",
}

LOAD_EVENTS = {
    0: "NoOperation",
    1: "StartLoading",
    2: "LoadCompleted",
    3: "AdditionalLoadControls",
    4: "Unload",
}

LOAD_STATES = {0: "Unloaded", 1: "Loaded", 2: "Loading", 3: "Error"}

LD_CTRL_ABS_SEGMENT = 0x01
LD_CTRL_TASK_SEGMENT = 0x02
LD_CTRL_TASK_PTR = 0x03
LD_CTRL_TASK_CTRL1 = 0x04
LD_CTRL_TASK_CTRL2 = 0x05
LD_CTRL_REL_SEGMENT = 0x0B
LD_CTRL_DATA_SEGMENT = 0x0C

LD_CTRL_NAMES = {
    LD_CTRL_ABS_SEGMENT: "LdCtrlAbsSegment",
    LD_CTRL_TASK_SEGMENT: "LdCtrlTaskSegment",
    LD_CTRL_TASK_PTR: "LdCtrlTaskPtr",
    LD_CTRL_TASK_CTRL1: "LdCtrlTaskCtrl1",
    LD_CTRL_TASK_CTRL2: "LdCtrlTaskCtrl2",
    LD_CTRL_REL_SEGMENT: "LdCtrlRelSegment",
    LD_CTRL_DATA_SEGMENT: "LdCtrlDataSegment",
}

SECURE_ALGORITHMS = {0b000: "CCM-auth-only", 0b001: "CCM-auth-enc"}
SECURE_SAL_SERVICES = {0: "S-A_Data", 2: "S-A_Sync_Req", 3: "S-A_Sync_Res"}


def sha8(data: bytes) -> str:
    """The short content hash used everywhere a payload is summarised."""
    return hashlib.sha256(data).hexdigest()[:8]


def ia_str(raw: int) -> str:
    """Formats a 16-bit individual address as `area.line.device`."""
    return "%d.%d.%d" % (raw >> 12, (raw >> 8) & 0x0F, raw & 0xFF)


def ga_str(raw: int) -> str:
    """Formats a 16-bit group address as `main/middle/sub`."""
    return "%d/%d/%d" % ((raw >> 11) & 0x1F, (raw >> 8) & 0x07, raw & 0xFF)


def parse_ia(text: str) -> Optional[int]:
    """Parses `1.1.5` into its 16-bit form; returns None if it is not an IA."""
    parts = text.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        a, l, d = (int(p) for p in parts)
    except ValueError:
        return None
    if not (0 <= a <= 15 and 0 <= l <= 15 and 0 <= d <= 255):
        return None
    return (a << 12) | (l << 8) | d


# --------------------------------------------------------------------------
# Decoded structures
# --------------------------------------------------------------------------


@dataclass
class Apdu:
    """One application-layer service: its APCI, decoded fields and payload."""

    apci: int
    name: str
    fields: Dict[str, object] = field(default_factory=dict)
    payload: bytes = b""
    # A_SecureData only: the decrypted inner APDU, set by
    # `datasecure.unwrap_frames` when a keyring key verified the MAC.
    inner: Optional["Apdu"] = None

    def summary(self) -> str:
        if self.name == "A_SecureData" and "mac" in self.fields:
            return self._secure_summary()
        if not self.fields:
            return self.name
        parts = []
        for key, value in self.fields.items():
            parts.append("%s=%s" % (key, value))
        return "%s %s" % (self.name, " ".join(parts))

    def _secure_summary(self) -> str:
        f = self.fields
        head = ["scf=%s" % f.get("scf", "?")]
        if "seq" in f:
            head.append("seq=%s" % f["seq"])
        if "key" in f:
            head.append(str(f["key"]))
        head.append("MAC %s" % f["mac"])
        text = "A_SecureData{%s}" % " ".join(head)
        if self.inner is not None:
            return "%s -> %s" % (text, self.inner.summary())
        if "sync_detail" in f:
            return "%s -> %s" % (text, f["sync_detail"])
        return text


@dataclass
class L4:
    """The transport layer: control PDUs and the numbered/unnumbered data PDUs."""

    kind: str
    seq: Optional[int] = None
    apdu: Optional[Apdu] = None
    tpci: int = 0

    def summary(self) -> str:
        if self.kind in ("T_ACK", "T_NAK"):
            return "%s(seq=%d)" % (self.kind, self.seq if self.seq is not None else -1)
        if self.kind == "NDT":
            return "NDT(seq=%d)" % (self.seq if self.seq is not None else -1)
        return self.kind


@dataclass
class Cemi:
    """A cEMI L_Data frame (or a management message code we only name)."""

    mc: int
    mc_name: str
    src: str = ""
    dst: str = ""
    dst_is_group: bool = False
    hops: int = 0
    priority: str = ""
    repeated: bool = False
    confirm_error: bool = False
    npdu: bytes = b""
    l4: Optional[L4] = None
    # Raw wire values the Data Secure nonce covers (see datasecure.py).
    src_raw: int = 0
    dst_raw: int = 0
    ext_ff: int = 0


@dataclass
class KnxFrame:
    """One KNXnet/IP frame, with whatever the layers below it decoded to."""

    ts: float
    src: str
    dst: str
    transport: str  # "udp" or "tcp"
    service: int
    service_name: str
    body: bytes
    fields: Dict[str, object] = field(default_factory=dict)
    cemi: Optional[Cemi] = None
    note: str = ""

    @property
    def is_malformed(self) -> bool:
        return self.service_name == "MALFORMED"


# --------------------------------------------------------------------------
# Application layer
# --------------------------------------------------------------------------


def decode_apdu(apci: int, payload: bytes, small_data: int) -> Apdu:
    """Decodes one APDU.

    `small_data` is the low 6 bits of the APCI, which several services use as an
    inline parameter (memory octet count, descriptor type, 6-bit group value).
    """
    name = APCI_EXACT.get(apci)
    if name is not None:
        return _decode_exact(apci, name, payload)

    selector = apci & APCI_SELECTOR_MASK
    name = APCI_MASKED.get(selector)
    if name is None:
        return Apdu(apci, "APCI_0x%03X" % apci, {"len": len(payload)}, payload)

    if selector == 0x080 or selector == 0x040:  # A_GroupValue_Write / _Response
        fields: Dict[str, object] = {}
        if payload:
            fields["value"] = payload.hex()
            fields["len"] = len(payload)
        else:
            fields["value"] = "%02x" % small_data
            fields["small"] = True
        return Apdu(apci, name, fields, payload)

    if selector in (0x200, 0x240, 0x280):  # A_Memory_Read/_Response/_Write
        count = small_data
        if len(payload) < 2:
            return Apdu(apci, name, {"truncated": True}, payload)
        addr = struct.unpack("!H", payload[0:2])[0]
        data = payload[2:]
        fields = {"addr": "0x%04x" % addr, "count": count}
        if selector != 0x200:
            fields["len"] = len(data)
            fields["sha"] = sha8(data)
            fields["data"] = data.hex()
        return Apdu(apci, name, fields, payload)

    if selector in (0x300, 0x340):  # A_DeviceDescriptor_Read/_Response
        fields = {"type": small_data}
        if selector == 0x340 and len(payload) >= 2:
            fields["descriptor"] = payload.hex()
            fields["mask"] = "%04X" % struct.unpack("!H", payload[0:2])[0]
        return Apdu(apci, name, fields, payload)

    if selector == 0x380:  # A_Restart
        master = bool(apci & 0x01)
        fields = {"type": "master-reset" if master else "basic"}
        if master and len(payload) >= 2:
            fields["erase_code"] = payload[0]
            fields["channel"] = payload[1]
        return Apdu(apci, "A_Restart", fields, payload)

    return Apdu(apci, name, {"len": len(payload)}, payload)


def _decode_exact(apci: int, name: str, payload: bytes) -> Apdu:
    fields: Dict[str, object] = {}

    if apci in (0x3D5, 0x3D6, 0x3D7):  # A_PropertyValue_Read/_Response/_Write
        if len(payload) < 4:
            return Apdu(apci, name, {"truncated": True}, payload)
        obj, pid = payload[0], payload[1]
        count = payload[2] >> 4
        index = ((payload[2] & 0x0F) << 8) | payload[3]
        data = payload[4:]
        fields = {
            "obj": obj,
            "obj_name": OBJECT_NAMES.get(obj, "obj%d" % obj),
            "pid": pid,
            "pid_name": PID_NAMES.get(pid, "PID_%d" % pid),
            "count": count,
            "index": index,
        }
        if data:
            fields["data"] = data.hex()
            fields["len"] = len(data)
            decoded = _decode_property_value(obj, pid, data, apci == 0x3D7)
            if decoded:
                fields.update(decoded)
        return Apdu(apci, name, fields, payload)

    if apci == 0x3D8:  # A_PropertyDescription_Read
        if len(payload) < 3:
            return Apdu(apci, name, {"truncated": True}, payload)
        fields = {
            "obj": payload[0],
            "pid": payload[1],
            "pid_name": PID_NAMES.get(payload[1], "PID_%d" % payload[1]),
            "prop_index": payload[2],
        }
        return Apdu(apci, name, fields, payload)

    if apci == 0x3D9:  # A_PropertyDescription_Response
        if len(payload) < 7:
            return Apdu(apci, name, {"truncated": True}, payload)
        type_byte = payload[3]
        max_elems = struct.unpack("!H", payload[4:6])[0] & 0x0FFF
        access = payload[6]
        fields = {
            "obj": payload[0],
            "pid": payload[1],
            "pid_name": PID_NAMES.get(payload[1], "PID_%d" % payload[1]),
            "prop_index": payload[2],
            "pdt": type_byte & 0x3F,
            "write_enabled": bool(type_byte & 0x80),
            "max_elements": max_elems,
            "read_level": access >> 4,
            "write_level": access & 0x0F,
        }
        return Apdu(apci, name, fields, payload)

    if apci in (0x3D1, 0x3D3):  # A_Authorize_Request / A_Key_Write
        key = payload[1:5] if len(payload) >= 5 else b""
        if key == FREE_ACCESS_KEY:
            fields["key"] = "FFFFFFFF(free-access)"
        elif key:
            # A project BCU key is a secret: name it by hash, never by value.
            fields["key"] = "redacted:%s" % sha8(key)
        if apci == 0x3D3 and payload:
            fields["level"] = payload[0]
        return Apdu(apci, name, fields, payload)

    if apci in (0x3D2, 0x3D4):  # A_Authorize_Response / A_Key_Response
        if payload:
            fields["level"] = payload[0]
        return Apdu(apci, name, fields, payload)

    if apci == 0x3A1:  # A_Restart_Response
        if len(payload) >= 3:
            fields["error"] = payload[0]
            fields["process_time"] = struct.unpack("!H", payload[1:3])[0]
        return Apdu(apci, name, fields, payload)

    if apci in (0x1FB, 0x1FD):  # A_MemoryExtended_Write / _Read
        if len(payload) < 4:
            return Apdu(apci, name, {"truncated": True}, payload)
        count = payload[0]
        addr = (payload[1] << 16) | (payload[2] << 8) | payload[3]
        data = payload[4:]
        fields = {"addr": "0x%06x" % addr, "count": count}
        if apci == 0x1FB:
            fields["len"] = len(data)
            fields["sha"] = sha8(data)
            fields["data"] = data.hex()
        return Apdu(apci, name, fields, payload)

    if apci in (0x1FC, 0x1FE):  # A_MemoryExtended_*_Response
        if len(payload) < 4:
            return Apdu(apci, name, {"truncated": True}, payload)
        addr = (payload[1] << 16) | (payload[2] << 8) | payload[3]
        data = payload[4:]
        fields = {"rc": "0x%02x" % payload[0], "addr": "0x%06x" % addr}
        if data:
            fields["len"] = len(data)
            fields["sha"] = sha8(data)
            fields["data"] = data.hex()
        return Apdu(apci, name, fields, payload)

    if apci in (0x0C0, 0x140):  # A_IndividualAddress_Write / _Response
        if len(payload) >= 2:
            fields["address"] = ia_str(struct.unpack("!H", payload[0:2])[0])
        return Apdu(apci, name, fields, payload)

    if apci in (0x3DC, 0x3DD, 0x3DE):  # serial-number addressed services
        if len(payload) >= 6:
            fields["serial"] = payload[0:6].hex()
        if apci == 0x3DE and len(payload) >= 8:
            fields["address"] = ia_str(struct.unpack("!H", payload[6:8])[0])
        return Apdu(apci, name, fields, payload)

    if apci == A_SECURE_DATA:
        return _decode_secure(apci, name, payload)

    if 0x1CC <= apci <= 0x1D6:  # extended property / function property services
        return _decode_property_ext(apci, name, payload)

    if payload:
        fields["len"] = len(payload)
        fields["data"] = payload.hex()
    return Apdu(apci, name, fields, payload)


def _decode_property_ext(apci: int, name: str, payload: bytes) -> Apdu:
    """The extended (interface object type addressed) property services.

    Header: object type (2), object instance (12 bits) and PID (12 bits)
    packed in 3 octets. The value services then carry element count (1) and
    start index (2); the write-con response and function-property responses
    carry a return code (1).
    """
    if len(payload) < 5:
        return Apdu(apci, name, {"truncated": True, "len": len(payload)}, payload)
    obj_type = struct.unpack("!H", payload[0:2])[0]
    packed = int.from_bytes(payload[2:5], "big")
    fields: Dict[str, object] = {
        "obj_type": obj_type,
        "instance": packed >> 12,
        "pid": packed & 0x0FFF,
    }
    rest = payload[5:]
    if apci in (0x1CC, 0x1CD, 0x1CE, 0x1CF, 0x1D0):
        if len(rest) >= 3:
            fields["count"] = rest[0]
            fields["index"] = struct.unpack("!H", rest[1:3])[0]
            rest = rest[3:]
        if apci == 0x1CF and rest:
            fields["rc"] = "0x%02x" % rest[0]
            rest = rest[1:]
    elif apci == 0x1D2 and len(rest) >= 2:  # description read: prop index
        fields["prop_index"] = struct.unpack("!H", rest[0:2])[0] & 0x0FFF
        rest = rest[2:]
    elif apci == 0x1D6 and rest:
        fields["rc"] = "0x%02x" % rest[0]
        rest = rest[1:]
    if rest:
        fields["len"] = len(rest)
        fields["data"] = rest.hex()
    return Apdu(apci, name, fields, payload)


def _decode_secure(apci: int, name: str, payload: bytes) -> Apdu:
    """Decodes the A_SecureData ASDU header only — never the protected APDU.

    Decryption is a separate pass (`datasecure.unwrap_frames`) that needs the
    frame's addressing and a keyring, neither of which this function sees.

    The SCF and the 6-octet sequence number travel in the clear and are what a
    parity diff needs. The wrapped APDU and its MAC are summarised by length and
    hash: they are ciphertext under the tool key, and printing them invites
    someone to paste key-adjacent material into an issue.
    """
    if not payload:
        return Apdu(apci, name, {"truncated": True}, payload)
    scf = payload[0]
    fields: Dict[str, object] = {
        "scf": "0x%02x" % scf,
        "tool_access": bool(scf & 0x80),
        "algorithm": SECURE_ALGORITHMS.get((scf >> 4) & 0x07, "unknown-%d" % ((scf >> 4) & 0x07)),
        "system_broadcast": bool(scf & 0x08),
        "service": SECURE_SAL_SERVICES.get(scf & 0x07, "unknown-%d" % (scf & 0x07)),
    }
    if len(payload) >= 7:
        seq = int.from_bytes(payload[1:7], "big")
        fields["seq"] = seq
        rest = payload[7:]
        fields["protected_len"] = len(rest)
        fields["protected_sha"] = sha8(rest)
    else:
        fields["truncated"] = True
    return Apdu(apci, name, fields, payload)


def _decode_property_value(
    obj: int, pid: int, data: bytes, is_write: bool = False
) -> Dict[str, object]:
    """Decodes the property values that matter for a download diff.

    Direction matters for PID_LOAD_STATE_CONTROL: the same octet is a load
    *event* when written to the device and a load *state* when read back, and a
    normalized sequence that confused the two would diff nonsense.
    """
    out: Dict[str, object] = {}
    if pid != 5 or not data:  # PID_LOAD_STATE_CONTROL
        if pid == 7 and len(data) in (2, 4):  # PID_TABLE_REFERENCE
            out["table_ref"] = "0x%0*x" % (len(data) * 2, int.from_bytes(data, "big"))
        return out
    if not is_write:
        out["load_state"] = LOAD_STATES.get(data[0], "state%d" % data[0])
        return out
    event = data[0]
    out["load_event"] = LOAD_EVENTS.get(event, "event%d" % event)
    if event == 3 and len(data) >= 2:
        sub = data[1]
        out["ld_ctrl"] = LD_CTRL_NAMES.get(sub, "sub0x%02x" % sub)
        if sub == LD_CTRL_REL_SEGMENT and len(data) >= 8:
            out["seg_size"] = struct.unpack("!I", data[2:6])[0]
            out["fill"] = bool(data[6])
            out["fill_byte"] = "0x%02x" % data[7]
        elif sub == LD_CTRL_ABS_SEGMENT and len(data) >= 10:
            out["seg_addr"] = "0x%08x" % struct.unpack("!I", data[2:6])[0]
            out["seg_size"] = struct.unpack("!H", data[6:8])[0]
            out["access"] = "0x%02x" % data[8]
            out["mem_type"] = "0x%02x" % data[9]
        elif sub in (LD_CTRL_TASK_PTR, LD_CTRL_TASK_CTRL1, LD_CTRL_TASK_CTRL2):
            out["ld_ctrl_data"] = data[2:].hex()
    return out


# --------------------------------------------------------------------------
# Transport layer (TPCI)
# --------------------------------------------------------------------------


def decode_npdu(npdu: bytes) -> Optional[L4]:
    """Decodes a TPDU: the TPCI octet and, for data PDUs, the APDU behind it.

    `npdu` is the octets after the cEMI length field, i.e. `[tpci, apci_low,
    payload...]` — the same shape as the committed `*_flash_requests.txt`
    fixtures.
    """
    if not npdu:
        return None
    tpci = npdu[0]
    if tpci == 0x80:
        return L4("T_Connect", tpci=tpci)
    if tpci == 0x81:
        return L4("T_Disconnect", tpci=tpci)
    if (tpci & 0xC3) == 0xC2:
        return L4("T_ACK", seq=(tpci >> 2) & 0x0F, tpci=tpci)
    if (tpci & 0xC3) == 0xC3:
        return L4("T_NAK", seq=(tpci >> 2) & 0x0F, tpci=tpci)
    if len(npdu) < 2:
        return L4("DATA_TRUNCATED", tpci=tpci)
    numbered = (tpci & 0x40) != 0
    seq = (tpci >> 2) & 0x0F if numbered else None
    apci = ((tpci & 0x03) << 8) | npdu[1]
    small = npdu[1] & 0x3F
    apdu = decode_apdu(apci, npdu[2:], small)
    return L4("NDT" if numbered else "UDT", seq=seq, apdu=apdu, tpci=tpci)


# --------------------------------------------------------------------------
# cEMI
# --------------------------------------------------------------------------


def decode_cemi(data: bytes) -> Optional[Cemi]:
    """Decodes a cEMI frame; returns None if it is too short to be one."""
    if len(data) < 2:
        return None
    mc = data[0]
    name = CEMI_MESSAGE_CODES.get(mc, "cEMI_0x%02X" % mc)
    if mc not in (0x11, 0x2E, 0x29):
        return Cemi(mc, name, npdu=data[1:])
    add_len = data[1]
    off = 2 + add_len
    if len(data) < off + 8:
        return Cemi(mc, name, npdu=data[off:])
    ctrl1, ctrl2 = data[off], data[off + 1]
    src_raw = struct.unpack("!H", data[off + 2 : off + 4])[0]
    dst_raw = struct.unpack("!H", data[off + 4 : off + 6])[0]
    npdu_len = data[off + 6]
    npdu = data[off + 7 : off + 8 + npdu_len]
    is_group = bool(ctrl2 & 0x80)
    return Cemi(
        mc=mc,
        mc_name=name,
        src=ia_str(src_raw),
        dst=ga_str(dst_raw) if is_group else ia_str(dst_raw),
        dst_is_group=is_group,
        hops=(ctrl2 >> 4) & 0x07,
        priority=PRIORITY_NAMES.get((ctrl1 >> 2) & 0x03, "?"),
        repeated=not bool(ctrl1 & 0x20),
        confirm_error=bool(ctrl1 & 0x01),
        npdu=npdu,
        l4=decode_npdu(npdu),
        src_raw=src_raw,
        dst_raw=dst_raw,
        ext_ff=ctrl2 & 0x0F,
    )


# --------------------------------------------------------------------------
# KNXnet/IP
# --------------------------------------------------------------------------


def decode_knxip(ts: float, src: str, dst: str, transport: str, frame: bytes) -> KnxFrame:
    """Decodes one complete KNXnet/IP frame (header included)."""
    if len(frame) < HEADER_LEN or frame[0] != 0x06 or frame[1] != 0x10:
        return KnxFrame(
            ts, src, dst, transport, 0, "MALFORMED", frame, {"len": len(frame)},
            note="not a KNXnet/IP header",
        )
    service = struct.unpack("!H", frame[2:4])[0]
    name = SERVICE_NAMES.get(service, "SERVICE_0x%04X" % service)
    body = frame[HEADER_LEN:]
    out = KnxFrame(ts, src, dst, transport, service, name, body)

    try:
        if service in (0x0420, 0x0310):  # TUNNELING_REQUEST / DEVICE_CONFIGURATION
            if len(body) >= 4:
                out.fields["channel"] = body[1]
                out.fields["seq"] = body[2]
                out.cemi = decode_cemi(body[body[0] :])
        elif service in (0x0421, 0x0311):  # TUNNELING_ACK / DEVICE_CONFIGURATION_ACK
            if len(body) >= 4:
                out.fields["channel"] = body[1]
                out.fields["seq"] = body[2]
                out.fields["status"] = "0x%02x" % body[3]
        elif service == 0x0530:  # ROUTING_INDICATION
            out.cemi = decode_cemi(body)
        elif service == 0x0205:  # CONNECT_REQUEST
            if body:
                cri = body[-4:] if len(body) >= 4 else b""
                if len(cri) >= 2:
                    out.fields["conn_type"] = "0x%02x" % cri[1]
                if len(cri) >= 3:
                    out.fields["layer"] = "0x%02x" % cri[2]
        elif service == 0x0206:  # CONNECT_RESPONSE
            if len(body) >= 2:
                out.fields["channel"] = body[0]
                out.fields["status"] = CONNECT_STATUS.get(body[1], "0x%02x" % body[1])
            # CRD: [len, type, individual address] for a tunnel connection.
            if len(body) >= 12 and body[10] == 0x04:
                out.fields["assigned"] = ia_str(struct.unpack("!H", body[12:14])[0]) if len(body) >= 14 else "?"
        elif service in (0x0207, 0x0208, 0x0209, 0x020A):
            if len(body) >= 2:
                out.fields["channel"] = body[0]
                if service in (0x0208, 0x020A):
                    out.fields["status"] = CONNECT_STATUS.get(body[1], "0x%02x" % body[1])
        elif service in SECURE_SERVICES:
            out.fields.update(_decode_secure_service(service, body))
    except (struct.error, IndexError, ValueError):
        out.note = "body decode failed"
    return out


def _decode_secure_service(service: int, body: bytes) -> Dict[str, object]:
    """Names and sizes a KNXnet/IP Secure frame. Nothing here is decrypted.

    Phase B is not implemented in bussard, so the point of this branch is to
    make a secure capture legible for calibration (issue #90 S4): which frames
    appeared, in what order, carrying how many bytes. Public keys, MACs and
    ciphertext are reported as lengths and hashes only.
    """
    out: Dict[str, object] = {"len": len(body)}
    if service == 0x0950 and len(body) >= 16:  # SECURE_WRAPPER
        out["session"] = "0x%04x" % struct.unpack("!H", body[0:2])[0]
        out["seq"] = int.from_bytes(body[2:8], "big")
        out["serial"] = body[8:14].hex()
        out["tag"] = body[14:16].hex()
        out["encrypted_len"] = max(0, len(body) - 16 - 16)
        out["encrypted_sha"] = sha8(body[16:])
    elif service == 0x0951:  # SESSION_REQUEST
        out["public_key_len"] = max(0, len(body) - 8)
    elif service == 0x0952 and len(body) >= 2:  # SESSION_RESPONSE
        out["session"] = "0x%04x" % struct.unpack("!H", body[0:2])[0]
        out["public_key_len"] = max(0, len(body) - 2 - 16)
        out["mac_len"] = 16 if len(body) >= 18 else 0
    elif service == 0x0953 and len(body) >= 2:  # SESSION_AUTHENTICATE
        out["user"] = body[1]
        out["mac_len"] = max(0, len(body) - 2)
    elif service == 0x0954 and len(body) >= 1:  # SESSION_STATUS
        out["status"] = SESSION_STATUS_NAMES.get(body[0], "0x%02x" % body[0])
    elif service == 0x0955 and len(body) >= 14:  # TIMER_NOTIFY
        out["timer"] = int.from_bytes(body[0:6], "big")
        out["serial"] = body[6:12].hex()
        out["tag"] = body[12:14].hex()
    return out


# --------------------------------------------------------------------------
# Framing: UDP datagrams and TCP streams
# --------------------------------------------------------------------------


def _walk_datagram(ts, src, dst, data: bytes) -> Iterator[KnxFrame]:
    """Walks the KNXnet/IP frames inside one UDP datagram."""
    off = 0
    while off + HEADER_LEN <= len(data):
        if data[off] != 0x06 or data[off + 1] != 0x10:
            yield KnxFrame(
                ts, src, dst, "udp", 0, "MALFORMED", data[off:],
                {"len": len(data) - off}, note="no KNXnet/IP header at offset %d" % off,
            )
            return
        total = struct.unpack("!H", data[off + 4 : off + 6])[0]
        if total < HEADER_LEN or off + total > len(data):
            yield KnxFrame(
                ts, src, dst, "udp", 0, "MALFORMED", data[off:],
                {"len": len(data) - off, "claimed": total}, note="truncated frame",
            )
            return
        yield decode_knxip(ts, src, dst, "udp", data[off : off + total])
        off += total


def _walk_stream(ts, src, dst, buf: bytearray) -> Iterator[KnxFrame]:
    """Consumes complete KNXnet/IP frames from a TCP byte stream buffer.

    Bytes that are not a valid header are dropped one at a time until the next
    `06 10` — the resync that keeps a capture with a missing segment usable.
    """
    while len(buf) >= HEADER_LEN:
        if buf[0] != 0x06 or buf[1] != 0x10:
            idx = bytes(buf).find(KNXIP_HEADER, 1)
            if idx < 0:
                skipped = len(buf)
                del buf[:]
                yield KnxFrame(
                    ts, src, dst, "tcp", 0, "MALFORMED", b"",
                    {"skipped": skipped}, note="resync: no KNXnet/IP header found",
                )
                return
            yield KnxFrame(
                ts, src, dst, "tcp", 0, "MALFORMED", bytes(buf[:idx]),
                {"skipped": idx}, note="resync to next KNXnet/IP header",
            )
            del buf[:idx]
            continue
        total = struct.unpack("!H", bytes(buf[4:6]))[0]
        if total < HEADER_LEN or total > 0xFFFF:
            del buf[:1]
            continue
        if len(buf) < total:
            return  # wait for more segments
        frame = bytes(buf[:total])
        del buf[:total]
        yield decode_knxip(ts, src, dst, "tcp", frame)


def frames(packets_iter) -> Iterator[KnxFrame]:
    """Turns a stream of `capture.Packet`s into decoded KNXnet/IP frames.

    UDP datagrams are walked directly. TCP is reassembled per directional
    4-tuple and framed by the KNXnet/IP header length field, which is what
    makes a `knxip_tunnel` (TCP) capture readable at all.
    """
    streams: Dict[tuple, TcpStream] = {}
    buffers: Dict[tuple, bytearray] = {}
    for pkt in packets_iter:
        if pkt.proto == 17:
            for frame in _walk_datagram(pkt.ts, pkt.src, pkt.dst, pkt.payload):
                yield frame
            continue
        key = pkt.flow
        stream = streams.get(key)
        if stream is None:
            stream = streams[key] = TcpStream()
            buffers[key] = bytearray()
        if pkt.tcp_syn:
            stream.next_seq = (pkt.tcp_seq + 1) & 0xFFFF_FFFF
        chunk = stream.add(pkt.tcp_seq, pkt.payload)
        if not chunk and pkt.payload and stream.pending:
            chunk = b""  # still waiting on a gap; hold the segment
        buf = buffers[key]
        buf += chunk
        for frame in _walk_stream(pkt.ts, pkt.src, pkt.dst, buf):
            yield frame
        if pkt.tcp_fin:
            buf += stream.flush_gap()
            for frame in _walk_stream(pkt.ts, pkt.src, pkt.dst, buf):
                yield frame


def frames_from_file(path: str) -> List[KnxFrame]:
    """Reads a capture file and returns every decoded KNXnet/IP frame."""
    return list(frames(read_packets(path)))
