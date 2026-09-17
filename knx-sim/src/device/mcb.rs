//! `PID_MCB_TABLE` (memory control block) — the device-computed integrity block
//! a modern download's `LdCtrlLoadImageProp` step reads back to verify a segment.
//!
//! After a loadable object reaches `Loaded`, a System B device exposes an
//! 8-octet memory-control-block entry via `PID_MCB_TABLE` (PID 27) describing the
//! segment it stored, including a CRC the device computed over the segment bytes.
//! A tool validates its written image by reading this entry and comparing the
//! device's CRC to one it computed independently over the bytes it streamed; a
//! mismatch means the image did not land intact. Many real System B products
//! (the MDT actuators in the example) use this step, so a device that cannot
//! answer PID 27 fails the flash at the verify stage.
//!
//! This is an **independent** implementation written from the KNX spec (3/5/2
//! Management Procedures `LdCtrlLoadImageProp`; 3/5/1 property definitions), not
//! shared with the tool. The entry layout is:
//!
//! ```text
//!   | 0..4 | segment size  | u32 big-endian                    |
//!   | 4    | CRC control   | 0x00 ("always valid")             |
//!   | 5    | access        | 0xFF                              |
//!   | 6..8 | CRC           | CRC-16/AUG-CCITT over the bytes BE |
//! ```
//!
//! The CRC is **CRC-16/AUG-CCITT**: width 16, polynomial `0x1021`, init `0xFFFF`,
//! no reflection, no final XOR, message augmented with 16 zero bits before
//! reduction. Its catalogued check value for `"123456789"` is `0xE5CC`.

/// One `PID_MCB_TABLE` entry width (`PDT_GENERIC_08`).
pub const MCB_ENTRY_LEN: usize = 8;

/// Compute CRC-16/AUG-CCITT over `data`.
///
/// Bit-at-a-time with the message augmented by 16 zero bits (the two extra
/// octets in the loop), polynomial `0x1021`, initial value `0xFFFF`. This is the
/// AUG-CCITT variant the KNX MCB uses, independently derived from its parameters
/// (not copied from the tool).
pub fn crc16_aug_ccitt(data: &[u8]) -> u16 {
    let mut acc: u32 = 0xFFFF;
    let total_bits = 8 * (data.len() + 2);
    for i in 0..total_bits {
        acc <<= 1;
        let bit = if (i / 8) < data.len() {
            ((data[i / 8] >> (7 - (i % 8))) & 1) as u32
        } else {
            0
        };
        acc |= bit;
        if acc & 0x1_0000 != 0 {
            acc ^= 0x1021;
        }
    }
    (acc & 0xFFFF) as u16
}

/// Build the 8-octet MCB entry a device reports for a segment holding exactly
/// `segment_data`: `[size:u32 BE][0x00][0xFF][crc16:u16 BE]`.
pub fn mcb_entry(segment_data: &[u8]) -> [u8; MCB_ENTRY_LEN] {
    let size = segment_data.len() as u32;
    let crc = crc16_aug_ccitt(segment_data);
    let mut v = [0u8; MCB_ENTRY_LEN];
    v[0..4].copy_from_slice(&size.to_be_bytes());
    v[4] = 0x00;
    v[5] = 0xFF;
    v[6..8].copy_from_slice(&crc.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_aug_ccitt_check_value() {
        // The catalogued CRC-16/AUG-CCITT check for "123456789" is 0xE5CC.
        assert_eq!(crc16_aug_ccitt(b"123456789"), 0xE5CC);
    }

    #[test]
    fn test_mcb_entry_layout() {
        let entry = mcb_entry(&[0xAA; 4]);
        // size = 4, control 0x00, access 0xFF, then the CRC.
        assert_eq!(&entry[0..4], &[0, 0, 0, 4]);
        assert_eq!(entry[4], 0x00);
        assert_eq!(entry[5], 0xFF);
        let crc = crc16_aug_ccitt(&[0xAA; 4]);
        assert_eq!(&entry[6..8], &crc.to_be_bytes());
    }
}
