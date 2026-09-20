//! The zeroizing 16-byte key wrapper used everywhere KNX Secure key material is
//! held in memory (spec §2.3).
//!
//! # Key hygiene (mandatory, spec §2.3)
//!
//! - [`Key16`] does NOT derive `Debug`: the hand-written impl redacts the bytes
//!   so a key can never be printed, logged, or `{:?}`-formatted by accident.
//! - It does NOT implement `Serialize`/`Deserialize`: key bytes must never reach
//!   the committed YAML model or any other file (the model carries flags, not
//!   bytes).
//! - It zeroizes its buffer on drop (via the `zeroize` crate) so freed key
//!   material does not linger in memory.
//! - It is deliberately not `Copy` and equality is constant-time, so keys are
//!   passed by reference rather than casually copied around.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A raw 128-bit KNX Secure key (FDSK, tool key, group key, backbone key, or a
/// derived password/authentication key).
///
/// See the module docs for the hygiene guarantees. Construct with [`Key16::new`]
/// and read the raw bytes only at the crypto boundary via [`Key16::bytes`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key16([u8; 16]);

impl Key16 {
    /// Wraps 16 raw key bytes.
    pub fn new(bytes: [u8; 16]) -> Self {
        Key16(bytes)
    }

    /// Borrows the raw key bytes.
    ///
    /// This is the single controlled read point; callers must only use it to
    /// feed a cipher and must never print, log, or persist the result.
    pub fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for Key16 {
    /// Redacts the key bytes so they can never leak through a debug format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key16(<redacted>)")
    }
}

impl PartialEq for Key16 {
    /// Constant-time equality so a key comparison does not leak bytes via timing.
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for Key16 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacts_key_bytes() {
        let key = Key16::new([0xAB; 16]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "Key16(<redacted>)");
        // The raw byte value must not appear in any debug rendering.
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn test_eq_is_value_equality() {
        assert_eq!(Key16::new([1; 16]), Key16::new([1; 16]));
        assert_ne!(Key16::new([1; 16]), Key16::new([2; 16]));
    }

    #[test]
    fn test_bytes_round_trips() {
        let raw = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let key = Key16::new(raw);
        assert_eq!(key.bytes(), &raw);
    }
}
