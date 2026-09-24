//! KNX Data Secure **group communication** (issue #172, spec §5).
//!
//! A secured group telegram is an ordinary `T_Data_Group` frame to a group
//! address whose APDU is `A_SecureData` (`0x03F1`). It differs from the
//! tool-access management path of [`crate::session`] in three places only:
//!
//! - the SCF has the tool-access and system-broadcast bits clear
//!   ([`Scf::group_data`], `0x10` for authentication + encryption);
//! - the CCM `block_0` / `counter_0` carry the group destination and the
//!   address-type bit ([`TpAddressing::group`]);
//! - the key is the **group key** of the destination GA (the keyring's
//!   `GroupAddresses/Group@Key`), not a device's tool key.
//!
//! The inner APDU is the plain group APDU with its TPCI bits zero, e.g.
//! `[0x00, 0x00]` for a `GroupValueRead` or `[0x00, 0x81]` for a small
//! `GroupValueWrite` of 1.
//!
//! Receivers track the last sequence accepted per sender individual address.
//! [`Freshness`] is that table for a *passive* observer (a bus monitor): it
//! reports a non-increasing sequence as advisory, it never decides to drop.

use std::collections::HashMap;

use crate::asdu::{self, AsduError, SEQ_LEN, Scf, SecureAsdu, SecureService, TP_MAC_LEN};
use crate::key::Key16;
use crate::sequence::Sequence;
use crate::{SecurityAlgorithm, TpAddressing};

/// A verified, decrypted secured group telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPlain {
    /// The SCF that was authenticated.
    pub scf: Scf,
    /// The sender's sequence number carried in the frame.
    pub sequence: Sequence,
    /// The plain inner group APDU (TPCI bits zero), ready for the ordinary
    /// group decoder.
    pub apdu: Vec<u8>,
}

/// Seals the plain group APDU `apdu` for the group address `group` (raw) as
/// sent by `source` (raw), returning the `A_SecureData` ASDU (the data octets
/// after the `0x03F1` APCI).
///
/// # Errors
///
/// [`AsduError::GroupApduTooShort`] if `apdu` is shorter than the two APCI
/// octets, or a CCM error from [`asdu::encode`].
pub fn encode_group(
    key: &Key16,
    algorithm: SecurityAlgorithm,
    seq: Sequence,
    source: u16,
    group: u16,
    apdu: &[u8],
) -> Result<SecureAsdu, AsduError> {
    let [hi, lo, data @ ..] = apdu else {
        return Err(AsduError::GroupApduTooShort(apdu.len()));
    };
    let apci = (u16::from(hi & 0x03) << 8) | u16::from(*lo);
    asdu::encode(
        key,
        Scf::group_data(algorithm),
        seq,
        &TpAddressing::group(source, group),
        apci,
        data,
    )
}

/// Verifies and decrypts a secured group ASDU sent by `source` to `group`
/// (both raw) under the GA's group key.
///
/// # Errors
///
/// - [`AsduError::NotGroupTraffic`] if the SCF has the tool-access or
///   system-broadcast bit set (that frame is keyed by a tool key).
/// - [`AsduError::MacMismatch`] on a wrong key, a forged or corrupted frame.
/// - [`AsduError::TooShort`], [`AsduError::UnknownScf`],
///   [`AsduError::UnexpectedService`] for malformed input.
pub fn decode_group(
    key: &Key16,
    asdu: &[u8],
    source: u16,
    group: u16,
) -> Result<GroupPlain, AsduError> {
    let (scf, _) = peek_header(asdu)?;
    if scf.tool_access || scf.system_broadcast {
        return Err(AsduError::NotGroupTraffic(scf.to_byte()));
    }
    let inner = asdu::decode(key, asdu, &TpAddressing::group(source, group))?;
    Ok(GroupPlain {
        scf: inner.scf,
        sequence: inner.sequence,
        apdu: asdu::inner_apdu_bytes(inner.apci, &inner.data),
    })
}

/// Parses the SCF and the sequence field of an `A_SecureData` ASDU without a
/// key, for display when the frame cannot (or did not) verify.
///
/// For an S-A_Sync_Res the six bytes are not a sequence (they are masked with
/// the challenge); callers that care check [`Scf::service`].
///
/// # Errors
///
/// [`AsduError::TooShort`] below `SCF + seq + MAC`, [`AsduError::UnknownScf`]
/// for an unrecognised SCF.
pub fn peek_header(asdu: &[u8]) -> Result<(Scf, Sequence), AsduError> {
    if asdu.len() < 1 + SEQ_LEN + TP_MAC_LEN {
        return Err(AsduError::TooShort(asdu.len()));
    }
    let scf = Scf::from_byte(asdu[0])?;
    let mut seq = [0u8; SEQ_LEN];
    seq.copy_from_slice(&asdu[1..1 + SEQ_LEN]);
    Ok((scf, Sequence::from_bytes(seq)))
}

/// Whether an ASDU's SCF names secured group data (S-A_Data, tool-access and
/// system-broadcast clear). `false` for anything malformed.
pub fn is_group_data(asdu: &[u8]) -> bool {
    peek_header(asdu).is_ok_and(|(scf, _)| {
        !scf.tool_access && !scf.system_broadcast && scf.service == SecureService::Data
    })
}

/// The last sequence seen per sender, for an observer that reports a
/// non-increasing sequence (a replay, a sender that restarted without its
/// counter, or a duplicate) as an **advisory** warning (spec §5.9, receive
/// side). Nothing is ever dropped on its verdict.
#[derive(Debug, Clone, Default)]
pub struct Freshness {
    last: HashMap<u16, u64>,
}

impl Freshness {
    /// An empty table.
    pub fn new() -> Self {
        Freshness::default()
    }

    /// Records `seq` from `source` (raw individual address). Returns the last
    /// accepted sequence when `seq` does not exceed it (stale), else `None`.
    /// A stale value does not lower the recorded high-water mark.
    pub fn observe(&mut self, source: u16, seq: Sequence) -> Option<u64> {
        let value = seq.value();
        match self.last.get(&source) {
            Some(&last) if value <= last => Some(last),
            _ => {
                self.last.insert(source, value);
                None
            }
        }
    }

    /// The last sequence accepted from `source`, if any.
    pub fn last(&self, source: u16) -> Option<u64> {
        self.last.get(&source).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), AsduError>;

    /// The shared known-answer inputs (synthetic): key `000102…0F`, sequence
    /// 42, source 1.1.1 (`0x1101`) to GA 1/2/3 (`0x0A03`), a small
    /// `GroupValueWrite` of 1.
    const KAT_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const KAT_SOURCE: u16 = 0x1101;
    const KAT_GROUP: u16 = 0x0A03;
    const KAT_APDU: [u8; 2] = [0x00, 0x81];

    /// SCF 0x10 (group, auth + encryption). Derived from the calibrated CCM
    /// (tool-access vectors confirmed against ETS) and cross-checked with the
    /// independent Python implementation in `tools/knxtrace/datasecure.py`.
    const KAT_GROUP_AUTH_ENC: [u8; 13] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0xDF, 0x59, 0x49, 0x89, 0x9F, 0xD3,
    ];
    /// SCF 0x00 (group, authentication only): the APDU rides in the clear.
    const KAT_GROUP_AUTH_ONLY: [u8; 13] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x81, 0x2E, 0x51, 0xCA, 0x4A,
    ];

    #[test]
    fn test_scf_group_data_bytes() {
        assert_eq!(
            Scf::group_data(SecurityAlgorithm::AuthenticationEncryption).to_byte(),
            0x10
        );
        assert_eq!(
            Scf::group_data(SecurityAlgorithm::AuthenticationOnly).to_byte(),
            0x00
        );
    }

    #[test]
    fn test_group_addressing_block_0_and_counter_0() {
        let seq = Sequence::new(42);
        let a = TpAddressing::group(KAT_SOURCE, KAT_GROUP);
        let b0 = asdu::tp_block_0(seq, &a, 2);
        assert_eq!(&b0[6..10], &[0x11, 0x01, 0x0A, 0x03]);
        assert_eq!(b0[11], 0x80, "address-type bit set, standard frame");
        assert_eq!(b0[12], 0x03, "T_Data_Group TPCI 0x00 -> 0x03");
        assert_eq!(b0[13], 0xF1);
        assert_eq!(b0[15], 2);
        let c0 = asdu::tp_counter_0(seq, &a);
        assert_eq!(&c0[6..10], &[0x11, 0x01, 0x0A, 0x03]);
        assert_eq!(&c0[10..16], &[0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn test_encode_group_known_answer_vectors() -> TestResult {
        let key = Key16::new(KAT_KEY);
        let seq = Sequence::new(42);
        for (alg, expected) in [
            (
                SecurityAlgorithm::AuthenticationEncryption,
                KAT_GROUP_AUTH_ENC,
            ),
            (SecurityAlgorithm::AuthenticationOnly, KAT_GROUP_AUTH_ONLY),
        ] {
            let got = encode_group(&key, alg, seq, KAT_SOURCE, KAT_GROUP, &KAT_APDU)?;
            assert_eq!(got, expected, "{alg:?} group vector diverged");
            let plain = decode_group(&key, &expected, KAT_SOURCE, KAT_GROUP)?;
            assert_eq!(plain.apdu, KAT_APDU);
            assert_eq!(plain.sequence, seq);
        }
        Ok(())
    }

    #[test]
    fn test_group_round_trip_large_response() -> TestResult {
        let key = Key16::new([0x5A; 16]);
        let seq = Sequence::new(0x0040_0000_1234);
        // GroupValueResponse with a 2-byte DPT 9 payload.
        let apdu = [0x00, 0x40, 0x0C, 0x1A];
        let asdu = encode_group(
            &key,
            SecurityAlgorithm::AuthenticationEncryption,
            seq,
            0x110C,
            0x0A03,
            &apdu,
        )?;
        assert_eq!(asdu.len(), 1 + 6 + apdu.len() + 4);
        assert_ne!(&asdu[7..11], &apdu, "encrypted");
        assert!(is_group_data(&asdu));
        let plain = decode_group(&key, &asdu, 0x110C, 0x0A03)?;
        assert_eq!(plain.apdu, apdu);
        assert_eq!(plain.sequence, seq);
        Ok(())
    }

    #[test]
    fn test_group_read_round_trip() -> TestResult {
        let key = Key16::new(KAT_KEY);
        let asdu = encode_group(
            &key,
            SecurityAlgorithm::AuthenticationEncryption,
            Sequence::new(7),
            KAT_SOURCE,
            KAT_GROUP,
            &[0x00, 0x00],
        )?;
        assert_eq!(
            decode_group(&key, &asdu, KAT_SOURCE, KAT_GROUP)?.apdu,
            vec![0x00, 0x00]
        );
        Ok(())
    }

    #[test]
    fn test_decode_group_rejects_wrong_key_group_and_source() -> TestResult {
        let key = Key16::new(KAT_KEY);
        let asdu = encode_group(
            &key,
            SecurityAlgorithm::AuthenticationEncryption,
            Sequence::new(9),
            KAT_SOURCE,
            KAT_GROUP,
            &KAT_APDU,
        )?;
        let wrong = Key16::new([0xEE; 16]);
        assert_eq!(
            decode_group(&wrong, &asdu, KAT_SOURCE, KAT_GROUP),
            Err(AsduError::MacMismatch)
        );
        // The GA and the source are authenticated through B0/Ctr0.
        assert_eq!(
            decode_group(&key, &asdu, KAT_SOURCE, 0x0A04),
            Err(AsduError::MacMismatch)
        );
        assert_eq!(
            decode_group(&key, &asdu, 0x1102, KAT_GROUP),
            Err(AsduError::MacMismatch)
        );
        Ok(())
    }

    #[test]
    fn test_decode_group_rejects_tool_access_scf() -> TestResult {
        let key = Key16::new(KAT_KEY);
        let asdu = asdu::encode(
            &key,
            Scf::tool_data(SecurityAlgorithm::AuthenticationEncryption),
            Sequence::new(1),
            &TpAddressing::group(KAT_SOURCE, KAT_GROUP),
            0x081,
            &[],
        )?;
        assert!(!is_group_data(&asdu));
        assert_eq!(
            decode_group(&key, &asdu, KAT_SOURCE, KAT_GROUP),
            Err(AsduError::NotGroupTraffic(0x90))
        );
        Ok(())
    }

    #[test]
    fn test_encode_group_rejects_short_apdu() {
        let key = Key16::new(KAT_KEY);
        assert_eq!(
            encode_group(
                &key,
                SecurityAlgorithm::AuthenticationEncryption,
                Sequence::new(1),
                KAT_SOURCE,
                KAT_GROUP,
                &[0x00],
            ),
            Err(AsduError::GroupApduTooShort(1))
        );
    }

    #[test]
    fn test_peek_header_reads_scf_and_sequence() -> TestResult {
        let (scf, seq) = peek_header(&KAT_GROUP_AUTH_ENC)?;
        assert_eq!(scf.to_byte(), 0x10);
        assert_eq!(seq, Sequence::new(42));
        assert_eq!(peek_header(&[0x10, 0x00]), Err(AsduError::TooShort(2)));
        Ok(())
    }

    #[test]
    fn test_freshness_flags_non_increasing_per_sender() {
        let mut f = Freshness::new();
        assert_eq!(f.observe(0x1101, Sequence::new(10)), None);
        assert_eq!(f.observe(0x1101, Sequence::new(11)), None);
        assert_eq!(f.observe(0x1101, Sequence::new(11)), Some(11));
        assert_eq!(f.observe(0x1101, Sequence::new(5)), Some(11));
        // Another sender has its own counter.
        assert_eq!(f.observe(0x1102, Sequence::new(5)), None);
        assert_eq!(f.last(0x1101), Some(11));
    }
}
