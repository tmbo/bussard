//! The per-device Data Secure session that owns the tool key, the send sequence,
//! and the per-source freshness table (spec §5.9, §6.1).
//!
//! [`DataSecureSession`] is the stateful counterpart of the pure [`crate::asdu`]
//! codec: it wraps an outgoing `(apci, data)` into an A_SecureData ASDU with the
//! next send sequence, and unwraps + freshness-checks an incoming ASDU. The
//! transport seam ([`SecureLayer`] over `DeviceConnection`, spec §6.1) holds one
//! of these when a device is security-activated.

use std::collections::HashMap;

use crate::asdu::{self, AsduError, Scf, SecurityAlgorithm, TpAddressing};
use crate::key::Key16;
use crate::sequence::{Sequence, SequenceHighWater};

/// A live Data Secure session against one device, keyed by its tool key.
///
/// Holds the monotonic send sequence (seeded from persisted state or the clock,
/// spec §5.9) and a per-source-IA last-seen sequence table for replay protection.
/// The [`Key16`] is moved in and never cloned or logged (spec §2.3).
pub struct DataSecureSession {
    /// The device's tool key (keyring `ToolKey`, else the FDSK — spec §2.1).
    tool_key: Key16,
    /// The algorithm used for wrapped management APDUs (default
    /// [`SecurityAlgorithm::AuthenticationEncryption`], spec §6.2).
    algorithm: SecurityAlgorithm,
    /// The next sequence to send. Incremented after every wrap.
    send_seq: Sequence,
    /// Last-seen sequence per source IA (raw 16-bit), for replay protection.
    last_seen: HashMap<u16, Sequence>,
    /// The shared per-device send high-water mark, when the caller keeps one
    /// across connections (spec §5.9). Updated on every wrap.
    high_water: Option<SequenceHighWater>,
}

impl DataSecureSession {
    /// Builds a session with `tool_key`, seeding the send sequence from the
    /// current clock (spec §5.8). Use [`with_send_sequence`](Self::with_send_sequence)
    /// to seed from persisted state or a `<Security SequenceNumber>` value.
    pub fn new(tool_key: Key16) -> Self {
        DataSecureSession {
            tool_key,
            algorithm: SecurityAlgorithm::AuthenticationEncryption,
            send_seq: Sequence::now(),
            last_seen: HashMap::new(),
            high_water: None,
        }
    }

    /// Ties this session to a shared per-device send high-water mark (spec §5.9).
    ///
    /// The send sequence is seeded from `high_water.next_seed()` — i.e.
    /// `max(clock, last_sent + 1)` — and every wrapped APDU is recorded back into
    /// it. Give every session for the same device the same clone and a reconnect
    /// can never replay a sequence the device has already accepted.
    pub fn with_high_water(mut self, high_water: SequenceHighWater) -> Self {
        self.send_seq = high_water.next_seed();
        self.high_water = Some(high_water);
        self
    }

    /// Sets the initial send sequence exactly (spec §5.9 send-side persistence).
    ///
    /// The default from [`new`](Self::new) is the clock (`Sequence::now`). A
    /// caller restoring persisted per-device state should pass
    /// `max(persisted, Sequence::now())` so a new run never replays a lower value
    /// than the device last accepted, while honouring a device already ahead of
    /// the clock. The value is used verbatim (no implicit clamping) so callers get
    /// deterministic, testable sequences.
    pub fn with_send_sequence(mut self, seed: Sequence) -> Self {
        self.send_seq = seed;
        self
    }

    /// Overrides the CCM algorithm for wrapped APDUs (default is encrypt).
    pub fn with_algorithm(mut self, algorithm: SecurityAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// The next sequence this session would send (for persistence, spec §5.9).
    pub fn send_sequence(&self) -> Sequence {
        self.send_seq
    }

    /// Wraps a plain management `(apci, data)` into an A_SecureData ASDU using the
    /// next send sequence, then advances the sequence (spec §6.1).
    ///
    /// Returns the outer `(A_SECURE_DATA apci, asdu bytes)` the transport sends.
    ///
    /// # Errors
    ///
    /// Propagates [`AsduError`] from the codec (e.g. an over-long payload).
    pub fn wrap(
        &mut self,
        addr: &TpAddressing,
        apci: u16,
        data: &[u8],
    ) -> Result<(u16, Vec<u8>), AsduError> {
        let scf = Scf::tool_data(self.algorithm);
        let seq = self.send_seq;
        let asdu = asdu::encode(&self.tool_key, scf, seq, addr, apci, data)?;
        if let Some(hw) = &self.high_water {
            hw.observe(seq);
        }
        self.send_seq = self.send_seq.next();
        Ok((asdu::A_SECURE_DATA, asdu))
    }

    /// Unwraps an inbound A_SecureData ASDU, verifies the MAC, enforces freshness,
    /// and returns the inner `(apci, data)` (spec §5.9 receive-side, §6.1).
    ///
    /// `outer_apci` must be [`asdu::A_SECURE_DATA`]; other APCIs are returned
    /// unchanged as a plain frame (a device may still answer some frames in the
    /// clear). The freshness table is updated only after a successful MAC verify.
    ///
    /// # Errors
    ///
    /// - [`AsduError::MacMismatch`] on a bad MAC.
    /// - [`AsduError::StaleSequence`] if the sequence is not strictly greater than
    ///   the last accepted from this source (a replay).
    pub fn unwrap(
        &mut self,
        addr: &TpAddressing,
        outer_apci: u16,
        asdu_bytes: &[u8],
    ) -> Result<UnwrapOutcome, AsduError> {
        if outer_apci != asdu::A_SECURE_DATA {
            // Not a secured frame: hand it back untouched. A device inside a
            // secure link may still emit a plain transport/control frame.
            return Ok(UnwrapOutcome::Plain);
        }
        let decoded = asdu::decode(&self.tool_key, asdu_bytes, addr)?;

        // Freshness: strictly-greater than the last accepted from this source.
        let source = addr.source;
        if let Some(&last) = self.last_seen.get(&source) {
            if decoded.sequence <= last {
                return Err(AsduError::StaleSequence {
                    got: decoded.sequence.value(),
                    last: last.value(),
                });
            }
        }
        self.last_seen.insert(source, decoded.sequence);

        Ok(UnwrapOutcome::Secured {
            apci: decoded.apci,
            data: decoded.data,
        })
    }
}

impl std::fmt::Debug for DataSecureSession {
    /// Redacts the tool key; shows only non-secret session state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataSecureSession")
            .field("tool_key", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("send_seq", &self.send_seq)
            .field("known_sources", &self.last_seen.len())
            .finish()
    }
}

/// The result of [`DataSecureSession::unwrap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapOutcome {
    /// The frame was a verified A_SecureData; the inner APDU is recovered.
    Secured {
        /// The inner management APCI.
        apci: u16,
        /// The inner data octets.
        data: Vec<u8>,
    },
    /// The frame was not an A_SecureData (a plain transport/control frame) and is
    /// handed back for the plain path to handle.
    Plain,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(source: u16) -> TpAddressing {
        TpAddressing {
            source,
            destination: 0x110A,
            address_type_group: false,
            extended_frame_format: 0,
            tpci: 0x42,
        }
    }

    #[test]
    fn test_wrap_advances_sequence() {
        let mut sess =
            DataSecureSession::new(Key16::new([0u8; 16])).with_send_sequence(Sequence::new(100));
        let start = sess.send_sequence();
        let (apci, _) = sess.wrap(&addr(0x1101), 0x280, &[0x00, 0x10]).unwrap();
        assert_eq!(apci, asdu::A_SECURE_DATA);
        assert_eq!(sess.send_sequence(), start.next());
    }

    #[test]
    fn test_wrap_unwrap_round_trip() {
        // A "device" session and a "tool" session sharing the tool key.
        let key_bytes = [0x24; 16];
        let mut tool =
            DataSecureSession::new(Key16::new(key_bytes)).with_send_sequence(Sequence::new(500));
        let mut device = DataSecureSession::new(Key16::new(key_bytes));

        let a = addr(0x1101);
        let (apci, asdu_bytes) = tool
            .wrap(&a, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();
        // The device sees the frame from source 1.1.1.
        match device.unwrap(&a, apci, &asdu_bytes).unwrap() {
            UnwrapOutcome::Secured { apci, data } => {
                assert_eq!(apci, 0x3D1);
                assert_eq!(data, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
            }
            other => panic!("expected Secured, got {other:?}"),
        }
    }

    #[test]
    fn test_unwrap_rejects_replay() {
        let key_bytes = [0x24; 16];
        let mut tool =
            DataSecureSession::new(Key16::new(key_bytes)).with_send_sequence(Sequence::new(500));
        let mut device = DataSecureSession::new(Key16::new(key_bytes));
        let a = addr(0x1101);

        let (apci, asdu_bytes) = tool.wrap(&a, 0x280, &[0x00, 0x10]).unwrap();
        device.unwrap(&a, apci, &asdu_bytes).unwrap();
        // Replaying the exact same frame is stale (not strictly greater).
        let err = device.unwrap(&a, apci, &asdu_bytes).unwrap_err();
        assert!(
            matches!(err, AsduError::StaleSequence { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_unwrap_passes_through_plain() {
        let mut device = DataSecureSession::new(Key16::new([0u8; 16]));
        let outcome = device.unwrap(&addr(0x1101), 0x340, &[0x07, 0xB0]).unwrap();
        assert_eq!(outcome, UnwrapOutcome::Plain);
    }

    /// Spec §5.9: a second session for the same device continues above the first
    /// one's sequences instead of reseeding from the clock (which an activated
    /// device refuses as stale).
    #[test]
    fn test_high_water_makes_reconnects_monotonic() {
        let hw = crate::sequence::SequenceHighWater::new();
        let mut first = DataSecureSession::new(Key16::new([0x24; 16])).with_high_water(hw.clone());
        let a = addr(0x1101);
        // Burn a few hundred sequences, far faster than the clock advances.
        for _ in 0..500 {
            first.wrap(&a, 0x280, &[0x00, 0x10]).expect("wrap");
        }
        let after_first = hw.last_sent();
        // A reconnect builds a fresh session from the same high-water mark.
        let second = DataSecureSession::new(Key16::new([0x24; 16])).with_high_water(hw.clone());
        assert!(
            second.send_sequence().value() > after_first,
            "a reconnect must not replay sequences the device already accepted"
        );
    }

    #[test]
    fn test_debug_redacts_key() {
        let sess = DataSecureSession::new(Key16::new([0xAB; 16]));
        let rendered = format!("{sess:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ab"));
    }
}
