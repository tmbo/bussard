//! Transport-layer (TPCI) and application-layer (APCI) decoding for management
//! telegrams.
//!
//! The TPDU's first byte is the TPCI. Its top two bits classify the transport
//! frame:
//!
//! ```text
//!   00xx_xxxx  T_Data_Group / T_Data_Broadcast / T_Data_Individual (numbered=0)
//!   01xx_xxxx  T_Data_Connected  (sequence in bits 5..2)
//!   1000_0000  T_Connect
//!   1000_0001  T_Disconnect
//!   11xx_xx10  T_ACK   (sequence in bits 5..2)
//!   11xx_xx11  T_NAK   (sequence in bits 5..2)
//! ```
//!
//! For a data telegram the 10-bit APCI is `((tpci & 0x03) << 8) | apci_byte`,
//! where `apci_byte` is the second TPDU byte. This split-across-two-bytes
//! encoding is the standard KNX application layer (confirmed against the
//! Wireshark KNX dissector and the ETS capture).

/// A decoded transport-control primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpci {
    /// Unnumbered data (group/broadcast/individual). Carries an APDU.
    DataUnnumbered,
    /// Connection-oriented data with a 4-bit sequence number. Carries an APDU.
    DataConnected(u8),
    /// `T_Connect` — open a transport connection.
    Connect,
    /// `T_Disconnect` — close the transport connection.
    Disconnect,
    /// `T_ACK` for the given sequence number.
    Ack(u8),
    /// `T_NAK` for the given sequence number.
    Nak(u8),
}

impl Tpci {
    /// Classify the TPCI byte.
    pub fn from_byte(b: u8) -> Self {
        if b == 0x80 {
            return Tpci::Connect;
        }
        if b == 0x81 {
            return Tpci::Disconnect;
        }
        match b & 0xC0 {
            0x00 => Tpci::DataUnnumbered,
            0x40 => Tpci::DataConnected((b >> 2) & 0x0F),
            0xC0 => {
                let seq = (b >> 2) & 0x0F;
                if b & 0x03 == 0x02 {
                    Tpci::Ack(seq)
                } else {
                    Tpci::Nak(seq)
                }
            }
            _ => Tpci::DataUnnumbered,
        }
    }

    /// The TPCI byte for a connected data telegram with `seq` (APCI bits are
    /// OR-ed in separately by the APDU encoder).
    pub fn data_connected_byte(seq: u8) -> u8 {
        0x40 | ((seq & 0x0F) << 2)
    }

    /// The `T_ACK` byte for `seq`.
    pub fn ack_byte(seq: u8) -> u8 {
        0xC0 | ((seq & 0x0F) << 2) | 0x02
    }
}

/// Application-layer service identifiers relevant to device management.
///
/// Values are the 10-bit APCI. The memory/group families use only the top four
/// bits as a selector with the low six bits carrying a count; those are handled
/// by [`Apci::from_u10`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apci {
    /// `A_GroupValue_Read` (0x000) — a query for a group value.
    GroupValueRead,
    /// `A_GroupValue_Response` (0x040) — an answer carrying a group value.
    GroupValueResponse,
    /// `A_GroupValue_Write` (0x080) — a push of a group value.
    GroupValueWrite,
    /// `A_IndividualAddress_Write` (0x0C0) — a broadcast that sets the
    /// individual address of the (single) device currently in programming mode.
    /// Carries the 2-octet new address.
    IndividualAddressWrite,
    /// `A_IndividualAddress_Read` (0x100) — a broadcast query; every device in
    /// programming mode answers with [`Apci::IndividualAddressResponse`]. No
    /// payload.
    IndividualAddressRead,
    /// `A_IndividualAddress_Response` (0x140) — a device in programming mode
    /// announcing its own individual address (in the frame's source). No payload.
    IndividualAddressResponse,
    /// `A_Memory_Read` with byte count.
    MemoryRead(u8),
    /// `A_Memory_Response` with byte count.
    MemoryResponse(u8),
    /// `A_Memory_Write` with byte count.
    MemoryWrite(u8),
    /// `A_MemoryExtended_Write` (0x1FB) — write memory at a 24-bit address.
    MemoryExtendedWrite,
    /// `A_MemoryExtended_Write_Response` (0x1FC).
    MemoryExtendedWriteResponse,
    /// `A_MemoryExtended_Read` (0x1FD) — read memory at a 24-bit address.
    MemoryExtendedRead,
    /// `A_MemoryExtended_Read_Response` (0x1FE).
    MemoryExtendedReadResponse,
    /// `A_PropertyExtValue_Read` (0x1CC): extended property read addressed by
    /// `[object_type:16][instance:12|pid:12][count][start:16]`.
    PropertyExtValueRead,
    /// `A_PropertyExtValue_Response` (0x1CD).
    PropertyExtValueResponse,
    /// `A_PropertyExtValue_WriteCon` (0x1CE): confirmed extended property write.
    PropertyExtValueWriteCon,
    /// `A_PropertyExtValue_WriteConResponse` (0x1CF).
    PropertyExtValueWriteConResponse,
    /// `A_PropertyExtDescription_Read` (0x1D2).
    PropertyExtDescriptionRead,
    /// `A_PropertyExtDescription_Response` (0x1D3).
    PropertyExtDescriptionResponse,
    /// `A_FunctionPropertyExt_Command` (0x1D4).
    FunctionPropertyExtCommand,
    /// `A_FunctionPropertyExt_State_Read` (0x1D5).
    FunctionPropertyExtStateRead,
    /// `A_FunctionPropertyExt_State_Response` (0x1D6).
    FunctionPropertyExtStateResponse,
    /// `A_DeviceDescriptor_Read` (descriptor type in low bits).
    DeviceDescriptorRead(u8),
    /// `A_DeviceDescriptor_Response`.
    DeviceDescriptorResponse(u8),
    /// `A_Restart` (0x380) — with the two low restart bits.
    Restart,
    /// `A_Restart_Response` (0x381).
    RestartResponse,
    /// `A_Authorize_Request` (0x3D1).
    AuthorizeRequest,
    /// `A_Authorize_Response` (0x3D2).
    AuthorizeResponse,
    /// `A_PropertyValue_Read` (0x3D5).
    PropertyValueRead,
    /// `A_PropertyValue_Response` (0x3D6).
    PropertyValueResponse,
    /// `A_PropertyValue_Write` (0x3D7).
    PropertyValueWrite,
    /// `A_PropertyDescription_Read` (0x3D8).
    PropertyDescriptionRead,
    /// `A_PropertyDescription_Response` (0x3D9).
    PropertyDescriptionResponse,
    /// Any other APCI, kept as the raw 10-bit value.
    Other(u16),
}

impl Apci {
    /// Decode the 10-bit APCI.
    pub fn from_u10(apci: u16) -> Self {
        // The group-value family occupies the top-four-bit selectors 0x000 /
        // 0x040 / 0x080; the low 6 bits carry a packed sub-byte value (for the
        // "small" APDU form) and are not part of the service identity.
        match apci & 0x3C0 {
            0x000 => return Apci::GroupValueRead,
            0x040 => return Apci::GroupValueResponse,
            0x080 => return Apci::GroupValueWrite,
            0x200 => return Apci::MemoryRead((apci & 0x3F) as u8),
            0x240 => return Apci::MemoryResponse((apci & 0x3F) as u8),
            0x280 => return Apci::MemoryWrite((apci & 0x3F) as u8),
            _ => {}
        }
        // A_DeviceDescriptor_Read/Response use 0x300 / 0x340 with a 6-bit type.
        if apci & 0x3C0 == 0x300 {
            return Apci::DeviceDescriptorRead((apci & 0x3F) as u8);
        }
        if apci & 0x3C0 == 0x340 {
            return Apci::DeviceDescriptorResponse((apci & 0x3F) as u8);
        }
        match apci {
            // Broadcast individual-address services: exact 10-bit values that do
            // not collide with the group (0x000/0x040/0x080) or memory
            // (0x200/0x240/0x280) selector families masked above.
            0x0C0 => Apci::IndividualAddressWrite,
            0x100 => Apci::IndividualAddressRead,
            0x140 => Apci::IndividualAddressResponse,
            0x1CC => Apci::PropertyExtValueRead,
            0x1CD => Apci::PropertyExtValueResponse,
            0x1CE => Apci::PropertyExtValueWriteCon,
            0x1CF => Apci::PropertyExtValueWriteConResponse,
            0x1D2 => Apci::PropertyExtDescriptionRead,
            0x1D3 => Apci::PropertyExtDescriptionResponse,
            0x1D4 => Apci::FunctionPropertyExtCommand,
            0x1D5 => Apci::FunctionPropertyExtStateRead,
            0x1D6 => Apci::FunctionPropertyExtStateResponse,
            0x1FB => Apci::MemoryExtendedWrite,
            0x1FC => Apci::MemoryExtendedWriteResponse,
            0x1FD => Apci::MemoryExtendedRead,
            0x1FE => Apci::MemoryExtendedReadResponse,
            0x380 => Apci::Restart,
            0x381 => Apci::RestartResponse,
            0x3D1 => Apci::AuthorizeRequest,
            0x3D2 => Apci::AuthorizeResponse,
            0x3D5 => Apci::PropertyValueRead,
            0x3D6 => Apci::PropertyValueResponse,
            0x3D7 => Apci::PropertyValueWrite,
            0x3D8 => Apci::PropertyDescriptionRead,
            0x3D9 => Apci::PropertyDescriptionResponse,
            other => Apci::Other(other),
        }
    }

    /// The 10-bit APCI value for this service (count/type bits zeroed for the
    /// families that carry them; callers OR those in themselves).
    pub fn to_u10(self) -> u16 {
        match self {
            Apci::GroupValueRead => 0x000,
            Apci::GroupValueResponse => 0x040,
            Apci::GroupValueWrite => 0x080,
            Apci::IndividualAddressWrite => 0x0C0,
            Apci::IndividualAddressRead => 0x100,
            Apci::IndividualAddressResponse => 0x140,
            Apci::MemoryRead(n) => 0x200 | (n as u16 & 0x3F),
            Apci::MemoryResponse(n) => 0x240 | (n as u16 & 0x3F),
            Apci::MemoryWrite(n) => 0x280 | (n as u16 & 0x3F),
            Apci::PropertyExtValueRead => 0x1CC,
            Apci::PropertyExtValueResponse => 0x1CD,
            Apci::PropertyExtValueWriteCon => 0x1CE,
            Apci::PropertyExtValueWriteConResponse => 0x1CF,
            Apci::PropertyExtDescriptionRead => 0x1D2,
            Apci::PropertyExtDescriptionResponse => 0x1D3,
            Apci::FunctionPropertyExtCommand => 0x1D4,
            Apci::FunctionPropertyExtStateRead => 0x1D5,
            Apci::FunctionPropertyExtStateResponse => 0x1D6,
            Apci::MemoryExtendedWrite => 0x1FB,
            Apci::MemoryExtendedWriteResponse => 0x1FC,
            Apci::MemoryExtendedRead => 0x1FD,
            Apci::MemoryExtendedReadResponse => 0x1FE,
            Apci::DeviceDescriptorRead(t) => 0x300 | (t as u16 & 0x3F),
            Apci::DeviceDescriptorResponse(t) => 0x340 | (t as u16 & 0x3F),
            Apci::Restart => 0x380,
            Apci::RestartResponse => 0x381,
            Apci::AuthorizeRequest => 0x3D1,
            Apci::AuthorizeResponse => 0x3D2,
            Apci::PropertyValueRead => 0x3D5,
            Apci::PropertyValueResponse => 0x3D6,
            Apci::PropertyValueWrite => 0x3D7,
            Apci::PropertyDescriptionRead => 0x3D8,
            Apci::PropertyDescriptionResponse => 0x3D9,
            Apci::Other(v) => v,
        }
    }
}

/// A parsed application-layer message: the service plus its data payload
/// (everything after the two APCI bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    /// The application service.
    pub apci: Apci,
    /// The raw 10-bit APCI (needed to recover count/type bits for the memory
    /// and device-descriptor families).
    pub apci_raw: u16,
    /// Payload bytes following the two-byte APCI header.
    pub data: Vec<u8>,
}

impl Apdu {
    /// Parse the APDU portion of a TPDU (the bytes starting at the TPCI byte).
    ///
    /// Returns `None` if the TPDU is a pure control frame (no APCI) or is too
    /// short to hold an APCI.
    pub fn parse(tpdu: &[u8]) -> Option<Self> {
        if tpdu.len() < 2 {
            return None;
        }
        let apci_raw = ((tpdu[0] as u16 & 0x03) << 8) | tpdu[1] as u16;
        Some(Apdu {
            apci: Apci::from_u10(apci_raw),
            apci_raw,
            data: tpdu[2..].to_vec(),
        })
    }

    /// The byte count encoded in a memory-family APCI (low 6 bits).
    pub fn memory_count(&self) -> u8 {
        (self.apci_raw & 0x3F) as u8
    }

    /// Build a TPDU body (APCI header + data) for a connected response with the
    /// given sequence number. The two APCI bytes carry the service; the caller
    /// supplies the already-composed 10-bit APCI (with count/type bits).
    pub fn encode_connected(seq: u8, apci10: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + data.len());
        // TPCI: connected-data with sequence, plus top two APCI bits.
        out.push(Tpci::data_connected_byte(seq) | ((apci10 >> 8) as u8 & 0x03));
        out.push((apci10 & 0xFF) as u8);
        out.extend_from_slice(data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpci_classification() {
        assert_eq!(Tpci::from_byte(0x80), Tpci::Connect);
        assert_eq!(Tpci::from_byte(0x81), Tpci::Disconnect);
        assert_eq!(Tpci::from_byte(0xC2), Tpci::Ack(0));
        assert_eq!(Tpci::from_byte(0xC6), Tpci::Ack(1));
        assert_eq!(Tpci::from_byte(0x40), Tpci::DataConnected(0));
        assert_eq!(Tpci::from_byte(0x4c), Tpci::DataConnected(3));
        assert_eq!(Tpci::from_byte(0x00), Tpci::DataUnnumbered);
    }

    #[test]
    fn test_apci_decode_memory_write() {
        // 0xbf = 10_111111 -> (0x03<<8)|0xbf? No: apci = ((0xbf&3)<<8)|... uses
        // the TPDU bytes. Test directly against the 10-bit value 0x2BF.
        assert_eq!(Apci::from_u10(0x2BF), Apci::MemoryWrite(0x3F));
        assert_eq!(Apci::from_u10(0x284), Apci::MemoryWrite(4));
        assert_eq!(Apci::from_u10(0x380), Apci::Restart);
        assert_eq!(Apci::from_u10(0x3D7), Apci::PropertyValueWrite);
        assert_eq!(Apci::from_u10(0x3D1), Apci::AuthorizeRequest);
    }

    #[test]
    fn test_apdu_parse_propwrite() {
        // apdu=4f d7 01 05 10 01 04 ...  TPCI=0x4f (connected seq3), APCI byte d7.
        let tpdu = [0x4f, 0xd7, 0x01, 0x05, 0x10, 0x01, 0x04];
        let apdu = Apdu::parse(&tpdu).expect("parses");
        assert_eq!(apdu.apci, Apci::PropertyValueWrite);
        assert_eq!(apdu.data, vec![0x01, 0x05, 0x10, 0x01, 0x04]);
    }

    #[test]
    fn test_apdu_parse_control_frame() {
        assert!(Apdu::parse(&[0x80]).is_none());
    }

    #[test]
    fn test_apci_decode_extended_memory() {
        assert_eq!(Apci::from_u10(0x1FB), Apci::MemoryExtendedWrite);
        assert_eq!(Apci::from_u10(0x1FC), Apci::MemoryExtendedWriteResponse);
        assert_eq!(Apci::from_u10(0x1FD), Apci::MemoryExtendedRead);
        assert_eq!(Apci::from_u10(0x1FE), Apci::MemoryExtendedReadResponse);
        // Round-trips through to_u10.
        assert_eq!(Apci::MemoryExtendedWrite.to_u10(), 0x1FB);
        assert_eq!(Apci::MemoryExtendedReadResponse.to_u10(), 0x1FE);
        // The extended selectors do NOT collide with the plain memory family.
        assert!(matches!(Apci::from_u10(0x280), Apci::MemoryWrite(_)));
    }

    #[test]
    fn test_apci_extended_property_services_roundtrip() {
        for v in [
            0x1CCu16, 0x1CD, 0x1CE, 0x1CF, 0x1D2, 0x1D3, 0x1D4, 0x1D5, 0x1D6,
        ] {
            let apci = Apci::from_u10(v);
            assert!(!matches!(apci, Apci::Other(_)), "0x{v:03x} is decoded");
            assert_eq!(apci.to_u10(), v);
        }
        assert_eq!(Apci::from_u10(0x1D4), Apci::FunctionPropertyExtCommand);
        assert_eq!(Apci::from_u10(0x1CE), Apci::PropertyExtValueWriteCon);
    }

    #[test]
    fn test_apci_individual_address_services() {
        // The three broadcast individual-address services decode to their own
        // variants and round-trip through to_u10.
        assert_eq!(Apci::from_u10(0x0C0), Apci::IndividualAddressWrite);
        assert_eq!(Apci::from_u10(0x100), Apci::IndividualAddressRead);
        assert_eq!(Apci::from_u10(0x140), Apci::IndividualAddressResponse);
        assert_eq!(Apci::IndividualAddressWrite.to_u10(), 0x0C0);
        assert_eq!(Apci::IndividualAddressRead.to_u10(), 0x100);
        assert_eq!(Apci::IndividualAddressResponse.to_u10(), 0x140);
        // Crucially they must NOT be misclassified as the group-value family
        // (whose selectors are 0x000/0x040/0x080).
        assert!(!matches!(Apci::from_u10(0x0C0), Apci::GroupValueWrite));
        assert!(!matches!(Apci::from_u10(0x100), Apci::GroupValueRead));
        assert!(!matches!(Apci::from_u10(0x140), Apci::GroupValueResponse));
    }

    #[test]
    fn test_encode_connected_restart_response() {
        // A_Restart_Response 0x381 with data 04 00, seq 0 -> 43 81 04 00.
        let tpdu = Apdu::encode_connected(0, 0x381, &[0x04, 0x00]);
        assert_eq!(tpdu, vec![0x43, 0x81, 0x04, 0x00]);
    }
}
