//! Transport-layer (layer-4) TPCI control-octet constants and bit-packing.
//!
//! The KNX transport layer multiplexes four connection-oriented control
//! telegrams and one numbered-data telegram into the single TPCI octet that
//! precedes the APCI. This module encodes/decodes that octet. It is pure (no
//! I/O) so it can be unit-tested exhaustively; the connection-oriented state
//! machine lives in `bussard-mgmt`.
//!
//! # Octet layout
//!
//! ```text
//!  bit  7 6 5 4 3 2 1 0
//!       │ │ └─────┼─┴── numbered-data: sequence number (bits 5-2), rest fixed
//!       │ └────────── data/control select
//!       └──────────── numbered/unnumbered select
//! ```
//!
//! - `T_Data_Group` / `T_Data_Broadcast` (unnumbered data): `0x00`.
//! - `T_Data_Connected` (**NDT**, numbered data): `0x40 | (seq << 2)`.
//! - `T_Connect` (UDT control): `0x80`.
//! - `T_Disconnect` (UDT control): `0x81`.
//! - `T_ACK` (numbered control): `0xC2 | (seq << 2)`.
//! - `T_NAK` (numbered control): `0xC3 | (seq << 2)`.
//!
//! Sequence numbers are 4-bit (0–15) with wraparound and live in bits 5-2.
//!
//! Written from scratch from the published KNX transport-layer structure
//! (EN 50090 / the KNX standard); no GPL sources were consulted.

/// `T_Connect` — open a connection-oriented transport connection (UDT control).
pub const T_CONNECT: u8 = 0x80;

/// `T_Disconnect` — tear down the connection (UDT control).
pub const T_DISCONNECT: u8 = 0x81;

/// Base value of a `T_Data_Connected` (NDT, numbered data) TPCI, before the
/// sequence number is packed in.
pub const NDT_BASE: u8 = 0x40;

/// Base value of a `T_ACK` TPCI, before the sequence number is packed in.
pub const T_ACK_BASE: u8 = 0xC2;

/// Base value of a `T_NAK` TPCI, before the sequence number is packed in.
pub const T_NAK_BASE: u8 = 0xC3;

/// The classified kind of a decoded TPCI control/data octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpciKind {
    /// Unnumbered data (`T_Data_Group` / `T_Data_Broadcast`), octet `0x00`.
    UnnumberedData,
    /// Numbered connected data (`T_Data_Connected`) with its sequence number.
    NumberedData(u8),
    /// `T_Connect`.
    Connect,
    /// `T_Disconnect`.
    Disconnect,
    /// `T_ACK` with the acknowledged sequence number.
    Ack(u8),
    /// `T_NAK` with the negatively-acknowledged sequence number.
    Nak(u8),
    /// An octet that does not match any known transport control/data pattern.
    Unknown(u8),
}

/// Extracts the 4-bit sequence number (bits 5-2) from a TPCI octet.
#[inline]
pub fn sequence(octet: u8) -> u8 {
    (octet >> 2) & 0x0f
}

/// Builds a `T_Data_Connected` (NDT) TPCI octet for `seq` (0–15).
///
/// Only the low nibble of `seq` is used, matching the 4-bit on-wire field.
#[inline]
pub fn ndt(seq: u8) -> u8 {
    NDT_BASE | ((seq & 0x0f) << 2)
}

/// Builds a `T_ACK` TPCI octet for `seq` (0–15).
#[inline]
pub fn t_ack(seq: u8) -> u8 {
    T_ACK_BASE | ((seq & 0x0f) << 2)
}

/// Builds a `T_NAK` TPCI octet for `seq` (0–15).
#[inline]
pub fn t_nak(seq: u8) -> u8 {
    T_NAK_BASE | ((seq & 0x0f) << 2)
}

/// Classifies a raw TPCI octet.
///
/// The two high bits select the family; for the numbered families the low two
/// bits distinguish data (`00`) from `T_ACK` (`10`) / `T_NAK` (`11`).
pub fn classify(octet: u8) -> TpciKind {
    match octet & 0xc0 {
        // 00xxxxxx — unnumbered. Only 0x00 (data) and 0x80/0x81 (control) are
        // defined; 0x00 here is unnumbered data.
        0x00 => TpciKind::UnnumberedData,
        // 01xxxxxx — numbered data (NDT). The low two bits are the top two bits
        // of the APCI when application data follows, so they are NOT part of the
        // TPCI and must be ignored here: only the family (bits 7-6) and the
        // sequence (bits 5-2) matter.
        0x40 => TpciKind::NumberedData(sequence(octet)),
        // 10xxxxxx — unnumbered control: T_Connect / T_Disconnect.
        0x80 => match octet {
            T_CONNECT => TpciKind::Connect,
            T_DISCONNECT => TpciKind::Disconnect,
            other => TpciKind::Unknown(other),
        },
        // 11xxxxxx — numbered control: T_ACK (…10) / T_NAK (…11).
        0xc0 => match octet & 0x03 {
            0x02 => TpciKind::Ack(sequence(octet)),
            0x03 => TpciKind::Nak(sequence(octet)),
            _ => TpciKind::Unknown(octet),
        },
        _ => TpciKind::Unknown(octet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_disconnect_roundtrip() {
        assert_eq!(classify(T_CONNECT), TpciKind::Connect);
        assert_eq!(classify(T_DISCONNECT), TpciKind::Disconnect);
    }

    #[test]
    fn ndt_packs_and_classifies_all_sequences() {
        for seq in 0..16u8 {
            let octet = ndt(seq);
            assert_eq!(sequence(octet), seq);
            assert_eq!(classify(octet), TpciKind::NumberedData(seq));
            // Bit pattern: 01 <seq:4> 00.
            assert_eq!(octet & 0xc3, 0x40);
        }
    }

    #[test]
    fn ack_nak_pack_and_classify_all_sequences() {
        for seq in 0..16u8 {
            assert_eq!(classify(t_ack(seq)), TpciKind::Ack(seq));
            assert_eq!(classify(t_nak(seq)), TpciKind::Nak(seq));
        }
        // The canonical seq-0 values from the spec.
        assert_eq!(t_ack(0), 0xC2);
        assert_eq!(t_nak(0), 0xC3);
        assert_eq!(ndt(0), 0x40);
    }

    #[test]
    fn sequence_wraparound_uses_low_nibble_only() {
        // seq 16 wraps to 0; seq 17 wraps to 1.
        assert_eq!(ndt(16), ndt(0));
        assert_eq!(t_ack(17), t_ack(1));
    }

    #[test]
    fn unnumbered_data_is_zero() {
        assert_eq!(classify(0x00), TpciKind::UnnumberedData);
    }

    #[test]
    fn unknown_octets_surface_as_unknown() {
        // 0x82 is 10-family but neither connect nor disconnect.
        assert_eq!(classify(0x82), TpciKind::Unknown(0x82));
    }

    #[test]
    fn ndt_low_bits_are_apci_and_ignored() {
        // 0x43 = NDT seq 0 with the APCI's top two bits (0x03) folded into the
        // octet. The low two bits are APCI, not TPCI, so this classifies as
        // NumberedData(0), not Unknown.
        assert_eq!(classify(0x43), TpciKind::NumberedData(0));
        // 0x46 = NDT seq 1 with APCI high bits 0x02.
        assert_eq!(classify(0x46), TpciKind::NumberedData(1));
    }
}
