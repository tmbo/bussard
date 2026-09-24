//! KNX Data Secure group telegrams in the monitor (issue #172).
//!
//! A secured group telegram arrives as an `A_SecureData` (`0x03F1`) APDU on a
//! group address. With the keyring's group keys a [`GroupKeyring`] verifies the
//! MAC, decrypts the inner APDU and hands a frame carrying the plain APDU to
//! the ordinary decode pipeline, so the value, DPT and names resolve exactly as
//! for a plain telegram. The outcome travels on the telegram as a
//! [`SecureInfo`]:
//!
//! - [`SecureStatus::Verified`]: the MAC verified under the GA's group key.
//! - [`SecureStatus::MacFailed`]: it did not; the raw ASDU stays visible.
//! - [`SecureStatus::NoKey`]: the keyring has no key for the GA.
//!
//! A sender's sequence number must increase from one telegram to the next. A
//! non-increasing one (a replay, a sender that restarted without keeping its
//! counter, a duplicate) is reported as an advisory
//! [`SecureInfo::warning`]; the monitor never drops a telegram for it.
//!
//! Tool-access frames (management, the broadcast `S-A_Sync` to `0/0/0`) are
//! keyed by a device's tool key, not a group key, and pass through unchanged.
//! Nothing here prints or stores key material.

use std::collections::HashMap;

use bussard_model::GroupAddress;
use bussard_secure::{Freshness, Key16, SecurityAlgorithm, decode_group, peek_header};
use bussard_transport::TimestampedFrame;
use bussard_transport::cemi::{Apdu, Destination, MessageCode};

/// The verdict on one secured group telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureStatus {
    /// The MAC verified under the GA's group key; the telegram shows the
    /// decrypted inner APDU.
    Verified,
    /// The MAC did not verify (a wrong or stale key, corruption, a forgery).
    MacFailed,
    /// The keyring holds no group key for the destination GA.
    NoKey,
}

impl SecureStatus {
    /// The stable tag used in JSON output: `ok`, `mac_failed`, `no_key`.
    pub fn tag(self) -> &'static str {
        match self {
            SecureStatus::Verified => "ok",
            SecureStatus::MacFailed => "mac_failed",
            SecureStatus::NoKey => "no_key",
        }
    }
}

/// What the monitor learned about a secured group telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureInfo {
    /// Whether the telegram verified.
    pub status: SecureStatus,
    /// The SCF byte (`0x10` authentication + encryption, `0x00`
    /// authentication only).
    pub scf: u8,
    /// The sender's sequence number as carried in the frame (only
    /// authenticated when `status` is [`SecureStatus::Verified`]).
    pub sequence: u64,
    /// The raw ASDU (SCF, sequence, secured APDU, MAC) when the telegram did
    /// not verify, for debugging. `None` once verified.
    pub raw_asdu: Option<Vec<u8>>,
    /// An advisory freshness warning: the sequence did not increase over the
    /// last one seen from this sender.
    pub warning: Option<String>,
}

impl SecureInfo {
    /// Whether the telegram verified (`secured: true` in JSON).
    pub fn verified(&self) -> bool {
        self.status == SecureStatus::Verified
    }
}

/// The keyring's group keys plus the per-sender freshness table, for a
/// monitor or capture run.
///
/// `Debug` lists how many keys it holds, never the keys.
pub struct GroupKeyring {
    keys: HashMap<GroupAddress, Key16>,
    freshness: Freshness,
}

impl std::fmt::Debug for GroupKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKeyring")
            .field("group_keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl GroupKeyring {
    /// A keyring over the given group keys (the keyring's
    /// `GroupAddresses/Group@Key` entries).
    pub fn new(keys: HashMap<GroupAddress, Key16>) -> Self {
        GroupKeyring {
            keys,
            freshness: Freshness::new(),
        }
    }

    /// How many group keys it holds.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether it holds no group key at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether it holds a key for `ga`.
    pub fn has_key(&self, ga: GroupAddress) -> bool {
        self.keys.contains_key(&ga)
    }

    /// Unwraps a secured group telegram.
    ///
    /// Returns `None` for anything that is not secured group data (a plain
    /// telegram, a tool-access frame, a malformed ASDU): decode it as is.
    /// Otherwise returns the [`SecureInfo`] and, when the MAC verified, a copy
    /// of `frame` whose APDU is the decrypted inner group APDU.
    pub fn unwrap(
        &mut self,
        frame: &TimestampedFrame,
    ) -> Option<(Option<TimestampedFrame>, SecureInfo)> {
        let cemi = &frame.frame;
        let Destination::Group(ga) = cemi.destination else {
            return None;
        };
        let asdu = cemi.secure_asdu()?;
        let (scf, sequence) = peek_header(asdu).ok()?;
        if scf.tool_access || scf.system_broadcast {
            return None;
        }
        let failed = |status| SecureInfo {
            status,
            scf: scf.to_byte(),
            sequence: sequence.value(),
            raw_asdu: Some(asdu.to_vec()),
            warning: None,
        };
        let Some(key) = self.keys.get(&ga) else {
            return Some((None, failed(SecureStatus::NoKey)));
        };
        let Ok(plain) = decode_group(key, asdu, cemi.source.raw(), ga.raw()) else {
            return Some((None, failed(SecureStatus::MacFailed)));
        };
        let Ok(inner) = Apdu::from_group_tpdu(&plain.apdu) else {
            return Some((None, failed(SecureStatus::MacFailed)));
        };
        // The gateway's L_Data.con echo and a link-layer repeat carry the same
        // sequence again by design; only first copies count for freshness.
        let first_copy = cemi.message_code != MessageCode::LDataCon && !cemi.control1.repeated;
        let warning = if first_copy {
            self.freshness
                .observe(cemi.source.raw(), plain.sequence)
                .map(|last| {
                    format!(
                        "sequence {} from {} is not above the last seen {last} (replay or \
                         sender restart?)",
                        plain.sequence.value(),
                        cemi.source
                    )
                })
        } else {
            None
        };
        let mut unwrapped = frame.clone();
        unwrapped.frame.apdu = inner;
        Some((
            Some(unwrapped),
            SecureInfo {
                status: SecureStatus::Verified,
                scf: plain.scf.to_byte(),
                sequence: plain.sequence.value(),
                raw_asdu: None,
                warning,
            },
        ))
    }
}

/// The short human label of an SCF's algorithm, for the pretty line.
pub(crate) fn algorithm_label(scf: u8) -> &'static str {
    match SecurityAlgorithm::from_code((scf >> 4) & 0b111) {
        Some(SecurityAlgorithm::AuthenticationOnly) => "auth",
        _ => "auth+conf",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_secure::{Sequence, encode_group};
    use bussard_testkit::{TestResult, ga, ia};
    use bussard_transport::cemi::{CemiFrame, GroupData};
    use std::time::SystemTime;

    fn key() -> Key16 {
        Key16::new([0x42; 16])
    }

    fn secured(
        src: &str,
        dest: &str,
        seq: u64,
        apdu: &[u8],
        k: &Key16,
    ) -> TestResult<TimestampedFrame> {
        let source = ia(src)?;
        let group = ga(dest)?;
        let asdu = encode_group(
            k,
            SecurityAlgorithm::AuthenticationEncryption,
            Sequence::new(seq),
            source.raw(),
            group.raw(),
            apdu,
        )?;
        let mut frame = CemiFrame::group_secure(group, source, asdu);
        frame.message_code = MessageCode::LDataInd;
        Ok(TimestampedFrame {
            received_at: SystemTime::UNIX_EPOCH,
            frame,
        })
    }

    fn keyring() -> TestResult<GroupKeyring> {
        let mut keys = HashMap::new();
        keys.insert(ga("1/2/3")?, key());
        Ok(GroupKeyring::new(keys))
    }

    #[test]
    fn test_unwrap_verifies_and_exposes_the_inner_apdu() -> TestResult {
        let mut ring = keyring()?;
        let f = secured("1.1.10", "1/2/3", 100, &[0x00, 0x81], &key())?;
        let (inner, info) = ring.unwrap(&f).ok_or("not recognised as secured")?;
        assert_eq!(info.status, SecureStatus::Verified);
        assert_eq!(info.scf, 0x10);
        assert_eq!(info.sequence, 100);
        assert!(info.warning.is_none());
        let inner = inner.ok_or("no inner frame")?;
        assert_eq!(inner.frame.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        Ok(())
    }

    #[test]
    fn test_unwrap_reports_mac_failure_with_raw_bytes() -> TestResult {
        let mut ring = keyring()?;
        let f = secured("1.1.10", "1/2/3", 100, &[0x00, 0x81], &Key16::new([1; 16]))?;
        let (inner, info) = ring.unwrap(&f).ok_or("not recognised")?;
        assert!(inner.is_none());
        assert_eq!(info.status, SecureStatus::MacFailed);
        assert_eq!(info.raw_asdu.as_deref(), f.frame.secure_asdu());
        Ok(())
    }

    #[test]
    fn test_unwrap_without_a_key_for_the_ga() -> TestResult {
        let mut ring = keyring()?;
        let f = secured("1.1.10", "1/2/4", 100, &[0x00, 0x81], &key())?;
        let (_, info) = ring.unwrap(&f).ok_or("not recognised")?;
        assert_eq!(info.status, SecureStatus::NoKey);
        Ok(())
    }

    #[test]
    fn test_unwrap_warns_on_a_non_increasing_sequence_but_still_decodes() -> TestResult {
        let mut ring = keyring()?;
        ring.unwrap(&secured("1.1.10", "1/2/3", 100, &[0x00, 0x81], &key())?);
        let (inner, info) = ring
            .unwrap(&secured("1.1.10", "1/2/3", 100, &[0x00, 0x80], &key())?)
            .ok_or("not recognised")?;
        assert!(inner.is_some(), "a stale telegram is still decoded");
        let warning = info.warning.ok_or("expected a freshness warning")?;
        assert!(warning.contains("not above the last seen 100"), "{warning}");
        // The L_Data.con echo of our own send is not a replay.
        let mut echo = secured("1.1.10", "1/2/3", 100, &[0x00, 0x81], &key())?;
        echo.frame.message_code = MessageCode::LDataCon;
        let (_, info) = ring.unwrap(&echo).ok_or("not recognised")?;
        assert!(info.warning.is_none());
        Ok(())
    }

    #[test]
    fn test_unwrap_ignores_plain_and_tool_access_frames() -> TestResult {
        let mut ring = keyring()?;
        let plain = TimestampedFrame {
            received_at: SystemTime::UNIX_EPOCH,
            frame: CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.10")?, &[1]),
        };
        assert!(ring.unwrap(&plain).is_none());
        let mut tool = secured("1.1.10", "1/2/3", 1, &[0x00, 0x81], &key())?;
        if let Apdu::Other { data, .. } = &mut tool.frame.apdu {
            data[0] = 0x90;
        }
        assert!(ring.unwrap(&tool).is_none());
        Ok(())
    }
}
