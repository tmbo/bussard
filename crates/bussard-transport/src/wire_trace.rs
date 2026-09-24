//! Optional hex wire trace of every cEMI frame the [`Tunnel`](crate::Tunnel)
//! sends and receives.
//!
//! This is a keepable diagnostic, **off by default**. It is enabled only when the
//! environment variable named by [`WIRE_TRACE_ENV`] is set to `1` (checked once,
//! cached). When on, [`trace_frame`] logs one line per outbound and inbound cEMI
//! frame to **stderr**: the direction, the source→destination addresses, and the
//! raw transport/application octets (the TPCI/APCI + data), plus the full raw
//! cEMI hex.
//!
//! It exists so a bussard flash can be captured frame-by-frame without an admin
//! packet sniffer: run `BUSSARD_WIRE_TRACE=1 bussard flash …` and diff the stderr
//! trace against a reference (e.g. an ETS capture). The output goes to stderr,
//! not the `tracing` log, so it is legible without a subscriber and never mixes
//! into structured logs.

use std::sync::OnceLock;

use crate::cemi::{Apdu, CemiFrame, Destination, Tpci};

/// Environment variable that enables the wire trace when set to `1`.
///
/// Any other value (or unset) leaves the trace off. Read once and cached, so
/// toggling it mid-process has no effect — set it before launching bussard.
pub const WIRE_TRACE_ENV: &str = "BUSSARD_WIRE_TRACE";

/// Direction of a traced frame, relative to bussard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A frame bussard is transmitting to the bus (`L_Data.req`).
    Outbound,
    /// A frame bussard received from the bus (`L_Data.ind`).
    Inbound,
}

impl Direction {
    /// A fixed-width arrow marker for the trace line.
    fn marker(self) -> &'static str {
        match self {
            Direction::Outbound => "TX >>",
            Direction::Inbound => "RX <<",
        }
    }
}

/// Whether the wire trace is enabled, evaluated once from [`WIRE_TRACE_ENV`].
fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(WIRE_TRACE_ENV)
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Logs one cEMI `frame` in `direction` to stderr, if the wire trace is enabled.
///
/// A no-op (a single cached env lookup) when the trace is off, so it is cheap to
/// call on every send/receive. The line is:
///
/// ```text
/// [wire] TX >> 1.0.255 -> 1.0.30  A_PropertyValue_Read  APCI=0x3D5  apdu=[4b d5 00 0c 10 01]  cemi=11 00 …
/// ```
///
/// where `apdu` is the transport/application octets (the TPCI/APCI byte and any
/// following data) and `cemi` is the full raw frame as it appears on the wire.
pub fn trace_frame(direction: Direction, frame: &CemiFrame) {
    if !enabled() {
        return;
    }
    let raw = frame.encode();
    let dst = match &frame.destination {
        Destination::Individual(ia) => ia.to_string(),
        Destination::Group(ga) => ga.to_string(),
    };
    eprintln!(
        "[wire] {} {} -> {}  {}  apdu=[{}]  cemi={}",
        direction.marker(),
        frame.source,
        dst,
        summarize(frame),
        hex(&transport_octets(frame)),
        hex(&raw),
    );
}

/// The transport/application octets of a frame: the raw TPCI byte for a
/// control-only telegram, or the TPCI/APCI octets plus any data for an APDU.
///
/// This is exactly what appears after the NPDU length byte on the wire, i.e. the
/// TPDU the KNX transport + application layers exchange — the octets a reference
/// capture shows as the frame's payload.
fn transport_octets(frame: &CemiFrame) -> Vec<u8> {
    let raw = frame.encode();
    // The cEMI layout up to and including the NPDU length byte is:
    //   msgcode(1) ai_len(1) ai(ai_len) ctl1(1) ctl2(1) src(2) dst(2) npdu_len(1)
    // so the TPDU begins at that fixed offset once the additional-info length is
    // known. Slicing the encoded frame keeps this in lockstep with the codec.
    let tpdu_start = 1 + 1 + frame.additional_info.len() + 1 + 1 + 2 + 2 + 1;
    raw.get(tpdu_start..).unwrap_or(&[]).to_vec()
}

/// A short human summary of the transport/application service the frame carries,
/// for the trace line: the transport-control kind, the group service, or the raw
/// 10-bit APCI of a management service.
fn summarize(frame: &CemiFrame) -> String {
    match (&frame.tpci, &frame.apdu) {
        (Tpci::Control(b), _) | (Tpci::Other(b), Apdu::Empty) => control_name(*b),
        (_, Apdu::GroupValueRead) => "GroupValueRead".to_string(),
        (_, Apdu::GroupValueWrite(_)) => "GroupValueWrite".to_string(),
        (_, Apdu::GroupValueResponse(_)) => "GroupValueResponse".to_string(),
        (_, Apdu::Other { apci, .. }) => format!("{}  APCI={apci:#05X}", apci_name(*apci)),
        (_, Apdu::Empty) => "T_control".to_string(),
    }
}

/// Names the connection-control TPCI octet of a control-only telegram.
fn control_name(tpci: u8) -> String {
    if tpci == 0x80 {
        "T_Connect".to_string()
    } else if tpci == 0x81 {
        "T_Disconnect".to_string()
    } else if tpci & 0xC3 == 0xC2 {
        format!("T_ACK(seq={})", (tpci >> 2) & 0x0F)
    } else if tpci & 0xC3 == 0xC3 {
        format!("T_NAK(seq={})", (tpci >> 2) & 0x0F)
    } else {
        format!("T_control({tpci:#04X})")
    }
}

/// Names a management APCI service for the trace line. Covers the services a
/// bussard flash uses; unknown values print as their raw APCI.
fn apci_name(apci: u16) -> &'static str {
    // Memory services encode a length in the low 6 bits, so mask before matching.
    match apci & 0x03C0 {
        0x0200 => return "A_Memory_Read",
        0x0240 => return "A_Memory_Response",
        0x0280 => return "A_Memory_Write",
        _ => {}
    }
    match apci {
        0x0300 => "A_DeviceDescriptor_Read",
        0x0340 => "A_DeviceDescriptor_Response",
        0x0380 => "A_Restart",
        0x0381 => "A_Restart_Response/MasterReset",
        0x03D1 => "A_Authorize_Request",
        0x03D2 => "A_Authorize_Response",
        0x03D5 => "A_PropertyValue_Read",
        0x03D6 => "A_PropertyValue_Response",
        0x03D7 => "A_PropertyValue_Write",
        0x03D8 => "A_PropertyDescription_Read",
        0x03D9 => "A_PropertyDescription_Response",
        0x01FB => "A_MemoryExtended_Write",
        0x01FC => "A_MemoryExtended_Write_Response",
        0x01FD => "A_MemoryExtended_Read",
        0x01FE => "A_MemoryExtended_Read_Response",
        _ => "A_service",
    }
}

/// Renders bytes as lowercase space-separated hex (empty string for no bytes).
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cemi::{Control1, Control2, MessageCode};
    use bussard_model::IndividualAddress;

    fn mgmt_frame(apci: u16, data: Vec<u8>) -> CemiFrame {
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2::default(),
            source: "1.0.255"
                .parse::<IndividualAddress>()
                .expect("valid fixture address"),
            destination: Destination::Individual("1.0.30".parse().expect("valid fixture address")),
            tpci: Tpci::Other(0x4b),
            apdu: Apdu::Other { apci, data },
        }
    }

    #[test]
    fn transport_octets_match_the_tpdu_tail() {
        // A_PropertyValue_Read for obj 0 PID 0x0c: the transport octets are the
        // raw TPDU (the tail of the encoded frame after the NPDU length byte).
        let frame = mgmt_frame(0x03D5, vec![0x00, 0x0c, 0x10, 0x01]);
        let octets = transport_octets(&frame);
        let raw = frame.encode();
        assert_eq!(octets.as_slice(), &raw[raw.len() - octets.len()..]);
        // The APDU tail carries the property-read operands.
        assert!(octets.ends_with(&[0x00, 0x0c, 0x10, 0x01]));
    }

    #[test]
    fn test_apci_name_memory_extended_services() {
        assert_eq!(apci_name(0x01FB), "A_MemoryExtended_Write");
        assert_eq!(apci_name(0x01FC), "A_MemoryExtended_Write_Response");
        assert_eq!(apci_name(0x01FD), "A_MemoryExtended_Read");
        assert_eq!(apci_name(0x01FE), "A_MemoryExtended_Read_Response");
        // Neighbouring unknown APCIs still fall back to the generic label.
        assert_eq!(apci_name(0x01FA), "A_service");
        assert_eq!(apci_name(0x01FF), "A_service");
    }

    #[test]
    fn summarize_names_the_apci_service() {
        let frame = mgmt_frame(0x0380, Vec::new());
        assert!(summarize(&frame).contains("A_Restart"));
        let frame = mgmt_frame(0x0281, vec![0x60, 0x00]); // A_Memory_Write len 1
        assert!(summarize(&frame).contains("A_Memory_Write"));
    }

    #[test]
    fn control_names_cover_the_connection_primitives() {
        assert_eq!(control_name(0x80), "T_Connect");
        assert_eq!(control_name(0x81), "T_Disconnect");
        assert_eq!(control_name(0xC2), "T_ACK(seq=0)");
        assert!(control_name(0xC6).starts_with("T_ACK(seq=1)"));
    }

    #[test]
    fn hex_is_lowercase_space_separated() {
        assert_eq!(hex(&[0x00, 0xff, 0x1e]), "00 ff 1e");
        assert_eq!(hex(&[]), "");
    }
}
