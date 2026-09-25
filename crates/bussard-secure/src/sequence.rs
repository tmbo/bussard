//! The 6-byte KNX Data Secure sequence number (spec §5.8).
//!
//! The sequence is the number of milliseconds since the KNX Secure epoch
//! `2018-01-05T00:00:00Z`, held as a 48-bit value, incremented by at least one
//! per send. A device rejects a frame whose sequence is not strictly greater
//! than the last it accepted from that source, so a sender must never replay a
//! lower value (spec §5.9).
//!
//! bussard never persists its own send sequence (issue #241): every seed comes
//! from the clock through [`SequenceClock`], whose process-wide instance
//! ([`process_clock`]) never issues a value at or below one it already issued
//! or saw sent. A later run starts from a later millisecond count, and the
//! S-A_Sync handshake (spec §6.3) reconciles the rare case where an earlier run
//! sent more than one APDU per millisecond and so ran ahead of the clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds between the Unix epoch and the KNX Secure epoch
/// `2018-01-05T00:00:00Z` (`1_515_110_400` seconds × 1000).
pub const KNX_SECURE_EPOCH_MS: u64 = 1_515_110_400_000;

/// The maximum representable 48-bit sequence value (`0xFFFF_FFFFFFFF`).
pub const MAX_SEQUENCE: u64 = 0xFFFF_FFFF_FFFF;

/// The wall clock as milliseconds since the KNX Secure epoch, `0` for a clock
/// set before 2018-01-05 (masked to 48 bits by the caller).
fn system_clock_ms() -> u64 {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(KNX_SECURE_EPOCH_MS);
    unix_ms.saturating_sub(KNX_SECURE_EPOCH_MS)
}

/// A clock-seeded, monotonic issuer of Data Secure send sequences (issue #241).
///
/// [`issue`](Self::issue) returns `max(clock, last + 1)` and records it, so no
/// two calls ever return the same value and none returns a value at or below
/// one already issued or [`observe`](Self::observe)d, even when two calls fall
/// in the same millisecond or the system clock steps backwards. bussard's
/// sessions use the process-wide instance, [`process_clock`]; tests build their
/// own with [`with_clock`](Self::with_clock).
#[derive(Debug)]
pub struct SequenceClock {
    /// The highest value issued or observed so far (`0` before the first).
    last: AtomicU64,
    /// Milliseconds since the KNX Secure epoch.
    clock: fn() -> u64,
}

/// The process-wide [`SequenceClock`] on the system clock.
static PROCESS_CLOCK: SequenceClock = SequenceClock::system();

/// The process-wide sequence issuer every bussard session seeds from.
pub fn process_clock() -> &'static SequenceClock {
    &PROCESS_CLOCK
}

impl SequenceClock {
    /// An issuer on the system clock (milliseconds since the KNX Secure epoch).
    pub const fn system() -> Self {
        Self::with_clock(system_clock_ms)
    }

    /// An issuer on a caller-supplied clock, for deterministic tests.
    pub const fn with_clock(clock: fn() -> u64) -> Self {
        SequenceClock {
            last: AtomicU64::new(0),
            clock,
        }
    }

    /// Issues the next seed: `max(clock, last + 1)`, saturating at
    /// [`MAX_SEQUENCE`], and records it as the new floor.
    pub fn issue(&self) -> Sequence {
        let clock = (self.clock)() & MAX_SEQUENCE;
        let mut current = self.last.load(Ordering::SeqCst);
        loop {
            let next = clock.max(current.saturating_add(1)).min(MAX_SEQUENCE);
            match self
                .last
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Sequence::new(next),
                Err(actual) => current = actual,
            }
        }
    }

    /// Records a sequence that went on the wire, so later seeds stay above it.
    /// Never moves backwards.
    pub fn observe(&self, seq: Sequence) {
        self.last.fetch_max(seq.value(), Ordering::SeqCst);
    }

    /// The highest value issued or observed so far (`0` before the first).
    pub fn last(&self) -> u64 {
        self.last.load(Ordering::SeqCst)
    }
}

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

    /// The raw wall clock as a sequence: milliseconds since the KNX Secure
    /// epoch (spec §5.8). Not monotonic; a sender seeds from [`Sequence::seed`].
    ///
    /// Falls back to `0` if the clock is somehow before the KNX Secure epoch (a
    /// misconfigured system), which a Sync exchange then corrects.
    pub fn now() -> Self {
        Sequence::new(system_clock_ms())
    }

    /// A fresh send-sequence seed from the process-wide [`SequenceClock`]:
    /// the clock, but strictly above every value this process already issued
    /// or sent (issue #241).
    pub fn seed() -> Self {
        PROCESS_CLOCK.issue()
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

/// A shared, monotonic high-water mark of the last sequence sent to one device
/// (spec §5.9, send side).
///
/// A device refuses any sequence that is not strictly greater than the last it
/// accepted, and the send counter runs ahead of the clock as soon as more than
/// one APDU is sent per millisecond. So a *new* session — after a reconnect, a
/// device restart, or simply a second management command in the same run —
/// must NOT reseed from the clock alone: that replays values the device has
/// already accepted and it refuses every one of them.
///
/// [`SequenceHighWater`] is the small piece of state that survives a connection:
/// clone it into every [`DataSecureSession`](crate::session::DataSecureSession)
/// for the same device and each new session seeds from
/// `max(clock, last_sent + 1)`.
///
/// Cross-*process* monotonicity rests on the clock (a later run starts with a
/// later millisecond count; nothing is persisted, issue #241) and, on a
/// security-activated device, on the S-A_Sync
/// handshake of spec §6.3: the device's Sync_Res names the sequence it accepts
/// next, and the session jumps to it when the clock seed is behind.
#[derive(Debug, Clone, Default)]
pub struct SequenceHighWater(Arc<AtomicU64>);

impl SequenceHighWater {
    /// A fresh high-water mark that has seen nothing yet.
    pub fn new() -> Self {
        SequenceHighWater(Arc::new(AtomicU64::new(0)))
    }

    /// The seed a new session should start from: `max(clock seed, last_sent +
    /// 1)`, where the clock seed comes from the process-wide
    /// [`SequenceClock`] and so is itself strictly monotonic.
    pub fn next_seed(&self) -> Sequence {
        let last = self.0.load(Ordering::SeqCst);
        let seed = Sequence::seed().value();
        let next = Sequence::new(seed.max(last.saturating_add(1)));
        PROCESS_CLOCK.observe(next);
        next
    }

    /// Records a sequence that has been put on the wire. Never moves backwards.
    /// The process-wide [`SequenceClock`] records it too.
    pub fn observe(&self, seq: Sequence) {
        self.0.fetch_max(seq.value(), Ordering::SeqCst);
        PROCESS_CLOCK.observe(seq);
    }

    /// The highest sequence recorded so far (`0` if none).
    pub fn last_sent(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second session must never reuse a sequence the first one already sent:
    /// the clock alone is not monotonic enough once the counter runs ahead of it.
    #[test]
    fn test_high_water_seeds_above_the_last_sent() {
        let hw = SequenceHighWater::new();
        // A first session that ran far ahead of the clock.
        let ahead = Sequence::new(Sequence::now().value() + 5_000);
        hw.observe(ahead);
        assert!(
            hw.next_seed() > ahead,
            "a new session must seed strictly above the last sent sequence"
        );
    }

    #[test]
    fn test_high_water_falls_back_to_the_clock() {
        let hw = SequenceHighWater::new();
        // Nothing sent yet: the seed is the clock (spec §5.8).
        assert!(hw.next_seed().value() >= Sequence::now().value().saturating_sub(1_000));
        assert_eq!(hw.last_sent(), 0);
    }

    #[test]
    fn test_high_water_never_moves_backwards() {
        let hw = SequenceHighWater::new();
        hw.observe(Sequence::new(500));
        hw.observe(Sequence::new(100));
        assert_eq!(hw.last_sent(), 500);
    }

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

    /// A fake clock pinned to one millisecond.
    fn frozen() -> u64 {
        1_000
    }

    #[test]
    fn test_sequence_clock_issue_same_millisecond_never_repeats() {
        let clock = SequenceClock::with_clock(frozen);
        let a = clock.issue();
        let b = clock.issue();
        assert_eq!(a.value(), 1_000);
        assert_eq!(b.value(), 1_001, "the same millisecond yields last + 1");
    }

    /// Two seeds a millisecond apart never collide, even when the first run
    /// sent a few APDUs past its seed within that millisecond.
    #[test]
    fn test_sequence_clock_issue_a_millisecond_apart_never_collide() {
        use std::sync::atomic::AtomicU64 as Tick;
        static NOW: Tick = Tick::new(5_000);
        fn ticking() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let clock = SequenceClock::with_clock(ticking);
        let first = clock.issue();
        // The first session sends three APDUs: first, first + 1, first + 2.
        clock.observe(Sequence::new(first.value() + 2));
        NOW.store(5_001, Ordering::SeqCst);
        let second = clock.issue();
        assert!(
            second.value() > first.value() + 2,
            "{second:?} after {first:?}"
        );
        NOW.store(5_002, Ordering::SeqCst);
        let third = clock.issue();
        assert!(third > second);
    }

    #[test]
    fn test_sequence_clock_issue_survives_a_clock_step_backwards() {
        use std::sync::atomic::AtomicU64 as Tick;
        static NOW: Tick = Tick::new(9_000);
        fn stepping() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let clock = SequenceClock::with_clock(stepping);
        let before = clock.issue();
        NOW.store(10, Ordering::SeqCst);
        let after = clock.issue();
        assert!(after > before, "a clock step back must not lower the seed");
        assert_eq!(clock.last(), after.value());
    }

    #[test]
    fn test_sequence_clock_issue_saturates_at_max() {
        fn at_max() -> u64 {
            MAX_SEQUENCE
        }
        let clock = SequenceClock::with_clock(at_max);
        assert_eq!(clock.issue().value(), MAX_SEQUENCE);
        assert_eq!(clock.issue().value(), MAX_SEQUENCE);
    }

    #[test]
    fn test_seed_is_strictly_monotonic_and_near_the_clock() {
        let a = Sequence::seed();
        let b = Sequence::seed();
        assert!(b > a);
        assert!(a.value() >= Sequence::now().value().saturating_sub(60_000));
    }

    #[test]
    fn test_now_is_after_epoch() {
        // Any run of this test happens well after 2018-01-05, so `now` is a
        // large positive millisecond count.
        assert!(Sequence::now().value() > 0);
    }
}
