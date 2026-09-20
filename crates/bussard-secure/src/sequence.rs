//! The 6-byte KNX Data Secure sequence number (spec §5.8).
//!
//! The sequence is the number of milliseconds since the KNX Secure epoch
//! `2018-01-05T00:00:00Z`, held as a 48-bit value, incremented by at least one
//! per send. A device rejects a frame whose sequence is not strictly greater
//! than the last it accepted from that source, so a sender must never replay a
//! lower value (spec §5.9).

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds between the Unix epoch and the KNX Secure epoch
/// `2018-01-05T00:00:00Z` (`1_515_110_400` seconds × 1000).
pub const KNX_SECURE_EPOCH_MS: u64 = 1_515_110_400_000;

/// The maximum representable 48-bit sequence value (`0xFFFF_FFFFFFFF`).
pub const MAX_SEQUENCE: u64 = 0xFFFF_FFFF_FFFF;

/// A 6-byte (48-bit) KNX Data Secure sequence number.
///
/// Stored as a `u64` masked to 48 bits; serialized big-endian to 6 wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sequence(u64);

impl Sequence {
    /// Wraps a raw 48-bit value (masked to 48 bits).
    pub fn new(value: u64) -> Self {
        Sequence(value & MAX_SEQUENCE)
    }

    /// The sequence seeded from the current wall clock: milliseconds since the
    /// KNX Secure epoch (spec §5.8).
    ///
    /// Falls back to `0` if the clock is somehow before the KNX Secure epoch (a
    /// misconfigured system), which a Sync exchange or a persisted higher value
    /// then corrects.
    pub fn now() -> Self {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(KNX_SECURE_EPOCH_MS);
        let since_epoch = unix_ms.saturating_sub(KNX_SECURE_EPOCH_MS);
        Sequence::new(since_epoch)
    }

    /// The raw 48-bit value.
    pub fn value(self) -> u64 {
        self.0
    }

    /// The 6 big-endian wire bytes.
    pub fn to_bytes(self) -> [u8; 6] {
        let b = self.0.to_be_bytes();
        // `to_be_bytes` on a u64 yields 8 bytes; take the low 6.
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }

    /// Parses a sequence from 6 big-endian wire bytes.
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        let mut wide = [0u8; 8];
        wide[2..].copy_from_slice(&bytes);
        Sequence::new(u64::from_be_bytes(wide))
    }

    /// The next sequence to send: one greater, saturating at [`MAX_SEQUENCE`].
    ///
    /// The KNX rule is "any strictly higher value is acceptable"; incrementing by
    /// one is the minimal legal step.
    pub fn next(self) -> Self {
        Sequence::new(self.0.saturating_add(1).min(MAX_SEQUENCE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_constant() {
        // 2018-01-05T00:00:00Z is 1_515_110_400 Unix seconds.
        assert_eq!(KNX_SECURE_EPOCH_MS, 1_515_110_400 * 1000);
    }

    #[test]
    fn test_to_from_bytes_round_trip() {
        let seq = Sequence::new(0x0102_0304_0506);
        assert_eq!(seq.to_bytes(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(Sequence::from_bytes(seq.to_bytes()), seq);
    }

    #[test]
    fn test_masks_to_48_bits() {
        let seq = Sequence::new(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(seq.value(), MAX_SEQUENCE);
        assert_eq!(seq.to_bytes(), [0xFF; 6]);
    }

    #[test]
    fn test_next_increments() {
        assert_eq!(Sequence::new(41).next(), Sequence::new(42));
        // Saturates at the 48-bit ceiling.
        assert_eq!(
            Sequence::new(MAX_SEQUENCE).next(),
            Sequence::new(MAX_SEQUENCE)
        );
    }

    #[test]
    fn test_now_is_after_epoch() {
        // Any run of this test happens well after 2018-01-05, so `now` is a
        // large positive millisecond count.
        assert!(Sequence::now().value() > 0);
    }
}
