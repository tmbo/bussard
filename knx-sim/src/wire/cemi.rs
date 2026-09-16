//! cEMI `L_Data` frame codec.
//!
//! cEMI (common External Message Interface) is the medium-independent framing
//! that rides inside a KNXnet/IP tunnelling body. Only the `L_Data` service is
//! implemented, which is all a management/flash flow uses.
//!
//! Layout of an `L_Data` cEMI frame (no additional info):
//!
//! ```text
//! +----+------+------+------+-----+-----+-----+-----+----------- ... -----+
//! | MC | AILn | Ctl1 | Ctl2 | SrcH| SrcL| DstH| DstL| NPDULen | TPDU ...   |
//! +----+------+------+------+-----+-----+-----+-----+----------- ... -----+
//! ```
//!
//! - `MC`   message code: `0x11` = `L_Data.req`, `0x29` = `L_Data.ind`,
//!   `0x2E` = `L_Data.con`.
//! - `AILn` additional-info length (bytes of optional additional info; 0 here).
//! - `Ctl1` frame/priority/ack/confirm flags; bit 0 (`0x01`) is the
//!   don't-repeat/standard-vs-extended nibble handling (we keep the observed
//!   value).
//! - `Ctl2` bit 7 = destination-address-type (1 = group), bits 6..4 = hop count.
//! - `NPDULen` number of TPDU bytes *after* the length byte, i.e. the APDU
//!   length field; the TPDU itself is `NPDULen + 1` bytes.
//!
//! The message-code values match KNX cEMI (see the Wireshark KNX/IP dissector,
//! `packet-knxnetip.c`, and the captured ETS↔KNX-Virtual flash).

use crate::wire::address::{GroupAddress, IndividualAddress};

/// cEMI message code for the `L_Data` service primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageCode {
    /// `L_Data.req` (0x11) — request from the tool toward the bus.
    LDataReq,
    /// `L_Data.ind` (0x29) — indication from a device toward the tool.
    LDataInd,
    /// `L_Data.con` (0x2E) — local confirmation of a request.
    LDataCon,
}

impl MessageCode {
    /// Decode a cEMI message-code byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x11 => Some(Self::LDataReq),
            0x29 => Some(Self::LDataInd),
            0x2E => Some(Self::LDataCon),
            _ => None,
        }
    }

    /// The wire byte for this message code.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::LDataReq => 0x11,
            Self::LDataInd => 0x29,
            Self::LDataCon => 0x2E,
        }
    }
}

/// A decoded cEMI `L_Data` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CemiLData {
    /// Message code (req/ind/con).
    pub message_code: MessageCode,
    /// Control field 1 (frame format / priority / repeat / ack / confirm).
    pub ctrl1: u8,
    /// Control field 2 (address type, hop count, extended frame format).
    pub ctrl2: u8,
    /// Source individual address.
    pub source: IndividualAddress,
    /// Raw 16-bit destination (interpret as group or individual per `ctrl2`).
    pub dest: u16,
    /// The Transport Protocol Data Unit (TPCI/APCI + data). The first byte holds
    /// TPCI; for a data telegram the low two bits plus the next byte hold APCI.
    pub tpdu: Vec<u8>,
}

/// Errors from decoding a cEMI `L_Data` frame.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CemiError {
    /// Frame ended before a required field.
    #[error("cEMI frame truncated: need {need} bytes, have {have}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// Message code was not a recognised `L_Data` primitive.
    #[error("unsupported cEMI message code 0x{0:02x}")]
    UnsupportedMessageCode(u8),
    /// The NPDU length field disagreed with the actual TPDU byte count.
    #[error("cEMI NPDU length {declared} disagrees with {actual} available TPDU bytes")]
    NpduLengthMismatch {
        /// Length declared in the NPDU length byte.
        declared: usize,
        /// Actual bytes available for the TPDU.
        actual: usize,
    },
}

impl CemiLData {
    /// True if the destination is a group address (`ctrl2` bit 7 set).
    pub fn is_group(&self) -> bool {
        self.ctrl2 & 0x80 != 0
    }

    /// The destination as an individual address (meaningful when not group).
    pub fn dest_individual(&self) -> IndividualAddress {
        IndividualAddress(self.dest)
    }

    /// The destination as a group address (meaningful when group).
    pub fn dest_group(&self) -> GroupAddress {
        GroupAddress(self.dest)
    }

    /// Decode a cEMI `L_Data` frame from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, CemiError> {
        if buf.len() < 2 {
            return Err(CemiError::Truncated {
                need: 2,
                have: buf.len(),
            });
        }
        let message_code =
            MessageCode::from_byte(buf[0]).ok_or(CemiError::UnsupportedMessageCode(buf[0]))?;
        let addl_len = buf[1] as usize;
        // MC + AILn + addl + ctrl1 + ctrl2 + src(2) + dst(2) + npdulen
        let header_end = 2 + addl_len;
        let fixed_need = header_end + 7;
        if buf.len() < fixed_need {
            return Err(CemiError::Truncated {
                need: fixed_need,
                have: buf.len(),
            });
        }
        let ctrl1 = buf[header_end];
        let ctrl2 = buf[header_end + 1];
        let source = IndividualAddress(u16::from_be_bytes([
            buf[header_end + 2],
            buf[header_end + 3],
        ]));
        let dest = u16::from_be_bytes([buf[header_end + 4], buf[header_end + 5]]);
        let npdu_len = buf[header_end + 6] as usize;
        // TPDU is npdu_len + 1 bytes (TPCI byte is not counted by npdu_len).
        let tpdu_start = header_end + 7;
        let tpdu_len = npdu_len + 1;
        let available = buf.len() - tpdu_start;
        if available < tpdu_len {
            return Err(CemiError::NpduLengthMismatch {
                declared: tpdu_len,
                actual: available,
            });
        }
        let tpdu = buf[tpdu_start..tpdu_start + tpdu_len].to_vec();
        Ok(Self {
            message_code,
            ctrl1,
            ctrl2,
            source,
            dest,
            tpdu,
        })
    }

    /// Encode this frame to cEMI bytes (no additional info).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.tpdu.len());
        out.push(self.message_code.to_byte());
        out.push(0); // additional info length
        out.push(self.ctrl1);
        out.push(self.ctrl2);
        out.extend_from_slice(&self.source.raw().to_be_bytes());
        out.extend_from_slice(&self.dest.to_be_bytes());
        // NPDU length = TPDU bytes - 1 (TPCI byte not counted).
        let npdu_len = self.tpdu.len().saturating_sub(1) as u8;
        out.push(npdu_len);
        out.extend_from_slice(&self.tpdu);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_l_data_ind_prop_response() -> Result<(), CemiError> {
        // From the ETS capture: 1.1.2 -> 1.0.255 PropResp apdu=47 d6 00 38 10 01 00 42
        // cEMI: 29 00 <ctrl1> <ctrl2> 11 02 10 ff <npdu=7> 47 d6 00 38 10 01 00 42
        let frame = [
            0x29, 0x00, 0x00, 0x60, 0x11, 0x02, 0x10, 0xff, 0x07, 0x47, 0xd6, 0x00, 0x38, 0x10,
            0x01, 0x00, 0x42,
        ];
        let c = CemiLData::decode(&frame)?;
        assert_eq!(c.message_code, MessageCode::LDataInd);
        assert_eq!(c.source, IndividualAddress::new(1, 1, 2));
        assert_eq!(c.dest, 0x10ff);
        assert_eq!(c.tpdu, vec![0x47, 0xd6, 0x00, 0x38, 0x10, 0x01, 0x00, 0x42]);
        Ok(())
    }

    #[test]
    fn test_cemi_roundtrip() -> Result<(), CemiError> {
        let frame = CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress::new(0, 0, 0),
            dest: 0x1102,
            tpdu: vec![0x4f, 0x80], // A_Restart bare
        };
        let bytes = frame.encode();
        let back = CemiLData::decode(&bytes)?;
        assert_eq!(frame, back);
        Ok(())
    }

    #[test]
    fn test_decode_truncated() {
        assert!(matches!(
            CemiLData::decode(&[0x11]),
            Err(CemiError::Truncated { .. })
        ));
    }

    #[test]
    fn test_decode_bad_message_code() {
        let frame = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            CemiLData::decode(&frame),
            Err(CemiError::UnsupportedMessageCode(0xFF))
        ));
    }
}
