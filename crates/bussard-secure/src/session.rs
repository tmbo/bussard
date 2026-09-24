//! The per-device Data Secure session that owns the tool key, the send sequence,
//! and the per-source freshness table (spec §5.9, §6.1).
//!
//! [`DataSecureSession`] is the stateful counterpart of the pure [`crate::asdu`]
//! codec: it wraps an outgoing `(apci, data)` into an A_SecureData ASDU with the
//! next send sequence, and unwraps + freshness-checks an incoming ASDU. It also
//! runs the S-A_Sync handshake (spec §6.3) that ETS performs before the first
//! S-A_Data of every connection: [`DataSecureSession::sync_request`] on the tool
//! side, [`DataSecureSession::answer_sync_request`] on the device side. The
//! transport seam ([`SecureLayer`] over `DeviceConnection`, spec §6.1) holds one
//! of these when a device is security-activated.

use std::collections::HashMap;

use crate::asdu::{
    self, AsduError, Challenge, Scf, SecureService, SecurityAlgorithm, SyncRequest, TpAddressing,
};
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
    /// Where the S-A_Sync handshake stands (spec §6.3).
    sync: SyncState,
}

/// The S-A_Sync handshake state of a [`DataSecureSession`] (spec §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncState {
    /// No Sync_Req sent yet.
    NotStarted,
    /// A Sync_Req with this challenge is outstanding.
    Pending(Challenge),
    /// A Sync_Res verified; sequences are seeded from the device.
    Done,
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
            sync: SyncState::NotStarted,
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

    /// Whether an S-A_Sync_Res has been verified on this session (spec §6.3).
    pub fn is_synced(&self) -> bool {
        self.sync == SyncState::Done
    }

    /// Builds the connection-oriented S-A_Sync_Req that opens secured tool access
    /// (spec §6.3), with a fresh random challenge.
    ///
    /// ETS sends this before the first S-A_Data of every connection (secure-1-1-12
    /// capture, 2026-09-23). The request carries the current send sequence but
    /// does **not** consume it: the device answers with the sequence it accepts
    /// next (normally this same value) and the first S-A_Data reuses it, exactly
    /// as ETS does. Returns the outer `(A_SECURE_DATA apci, asdu bytes)`.
    ///
    /// # Errors
    ///
    /// Propagates [`AsduError`] from the codec.
    pub fn sync_request(&mut self, addr: &TpAddressing) -> Result<(u16, Vec<u8>), AsduError> {
        self.sync_request_with_challenge(addr, fresh_challenge())
    }

    /// [`sync_request`](Self::sync_request) with a caller-chosen challenge, for
    /// deterministic tests. Production code uses the random one.
    ///
    /// # Errors
    ///
    /// Propagates [`AsduError`] from the codec.
    pub fn sync_request_with_challenge(
        &mut self,
        addr: &TpAddressing,
        challenge: Challenge,
    ) -> Result<(u16, Vec<u8>), AsduError> {
        let req = SyncRequest {
            sequence: self.send_seq,
            // Connection-oriented: the serial field is zero (the capture's
            // unicast Sync_Req frames all carry six zero bytes here).
            serial: [0u8; asdu::SERIAL_LEN],
            challenge,
        };
        let asdu = asdu::encode_sync_req(
            &self.tool_key,
            Scf::tool_sync(SecureService::SyncReq),
            &req,
            addr,
        )?;
        if let Some(hw) = &self.high_water {
            hw.observe(req.sequence);
        }
        self.sync = SyncState::Pending(challenge);
        Ok((asdu::A_SECURE_DATA, asdu))
    }

    /// Verifies an S-A_Sync_Res and applies it (spec §6.3).
    ///
    /// The next send sequence becomes `max(current, requester_sequence)` and the
    /// device's freshness floor becomes `responder_sequence - 1`, so its next
    /// S-A_Data (which carries `responder_sequence`) is accepted and anything
    /// older is refused. The response is bound to our challenge, so it cannot be
    /// a replay.
    fn apply_sync_response(
        &mut self,
        addr: &TpAddressing,
        asdu_bytes: &[u8],
    ) -> Result<UnwrapOutcome, AsduError> {
        let SyncState::Pending(challenge) = self.sync else {
            return Err(AsduError::UnsolicitedSyncResponse);
        };
        let res = asdu::decode_sync_res(&self.tool_key, asdu_bytes, addr, &challenge)?;
        if res.requester_sequence > self.send_seq {
            self.send_seq = res.requester_sequence;
        }
        let floor = res.responder_sequence.value().saturating_sub(1);
        self.last_seen.insert(addr.source, Sequence::new(floor));
        self.sync = SyncState::Done;
        Ok(UnwrapOutcome::Synced {
            device_sequence: res.responder_sequence,
            next_send_sequence: self.send_seq,
        })
    }

    /// The **device** role of the Sync handshake: verifies an inbound
    /// S-A_Sync_Req and builds the S-A_Sync_Res (spec §6.3).
    ///
    /// This is what an activated device does (and what bussard's mock devices use
    /// to stand in for one): the response reports this session's own next send
    /// sequence and the sequence it accepts next from the requester,
    /// `max(request sequence, last accepted + 1)`. The Sync_Req itself does not
    /// update the freshness table, so the requester's first S-A_Data may reuse
    /// the request's sequence, as ETS does. `req_addr` is the request frame's
    /// addressing, `res_addr` the response frame's.
    ///
    /// # Errors
    ///
    /// Propagates [`AsduError`] for a malformed or wrongly authenticated request.
    pub fn answer_sync_request(
        &mut self,
        req_addr: &TpAddressing,
        asdu_bytes: &[u8],
        res_addr: &TpAddressing,
    ) -> Result<(u16, Vec<u8>), AsduError> {
        let (_, req) = asdu::decode_sync_req(&self.tool_key, asdu_bytes, req_addr)?;
        let accepted_next = self
            .last_seen
            .get(&req_addr.source)
            .map(|s| s.next())
            .map_or(req.sequence, |n| n.max(req.sequence));
        let res = asdu::SyncResponse {
            responder_sequence: self.send_seq,
            requester_sequence: accepted_next,
        };
        let nonce = Sequence::from_bytes(fresh_challenge());
        let asdu = asdu::encode_sync_res(
            &self.tool_key,
            Scf::tool_sync(SecureService::SyncRes),
            &res,
            &req.challenge,
            nonce,
            res_addr,
        )?;
        Ok((asdu::A_SECURE_DATA, asdu))
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
        match asdu_bytes.first().map(|&b| Scf::from_byte(b)) {
            Some(Ok(scf)) if scf.service == SecureService::SyncRes => {
                return self.apply_sync_response(addr, asdu_bytes);
            }
            Some(Ok(scf)) if scf.service == SecureService::SyncReq => {
                // A tool never answers a device's sync request.
                return Err(AsduError::UnexpectedService(scf.to_byte()));
            }
            _ => {}
        }
        let decoded = asdu::decode(&self.tool_key, asdu_bytes, addr)?;

        // Freshness: strictly-greater than the last accepted from this source.
        let source = addr.source;
        if let Some(&last) = self.last_seen.get(&source)
            && decoded.sequence <= last
        {
            return Err(AsduError::StaleSequence {
                got: decoded.sequence.value(),
                last: last.value(),
            });
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
            .field("synced", &self.is_synced())
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
    /// The frame was a verified S-A_Sync_Res answering our S-A_Sync_Req; the
    /// session's sequences are now seeded from it (spec §6.3).
    Synced {
        /// The device's own next send sequence.
        device_sequence: Sequence,
        /// The sequence the next S-A_Data from us carries.
        next_send_sequence: Sequence,
    },
}

/// A fresh 6-byte S-A_Sync_Req challenge.
///
/// Drawn from std's randomly keyed SipHash (`RandomState` seeds its keys from
/// the operating system's randomness source) over the clock and a process-wide
/// counter, so no RNG crate is needed. The challenge only has to be
/// unpredictable enough that an attacker cannot pre-record a matching
/// S-A_Sync_Res; the Sync_Res MAC under the tool key does the rest.
fn fresh_challenge() -> Challenge {
    use std::hash::{BuildHasher, RandomState};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let value = RandomState::new().hash_one((nanos, count));
    let b = value.to_be_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5]]
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

    /// The Sync handshake as the capture shows it: the Sync_Req carries the send
    /// sequence without consuming it, the Sync_Res seeds both directions, and the
    /// first S-A_Data reuses the Sync_Req's sequence.
    #[test]
    fn test_sync_handshake_seeds_both_directions() -> Result<(), AsduError> {
        let key = [0x24u8; 16];
        let mut tool =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(5_000));
        let to_dev = addr(0x1119);
        let challenge = [1, 2, 3, 4, 5, 6];
        let (apci, req) = tool.sync_request_with_challenge(&to_dev, challenge)?;
        assert_eq!(apci, asdu::A_SECURE_DATA);
        assert_eq!(req[0], 0x92);
        assert!(!tool.is_synced());
        assert_eq!(tool.send_sequence(), Sequence::new(5_000));

        // The device side: verify the request and answer it.
        let (_, parsed) = asdu::decode_sync_req(&Key16::new(key), &req, &to_dev)?;
        assert_eq!(parsed.challenge, challenge);
        assert_eq!(parsed.serial, [0u8; 6]);
        let from_dev = TpAddressing {
            source: 0x110C,
            destination: 0x1119,
            ..addr(0x110C)
        };
        let res = asdu::encode_sync_res(
            &Key16::new(key),
            Scf::tool_sync(SecureService::SyncRes),
            &asdu::SyncResponse {
                responder_sequence: Sequence::new(900),
                // The device has seen 6_000 from us before: we must jump past it.
                requester_sequence: Sequence::new(6_001),
            },
            &challenge,
            Sequence::new(0x1234_5678_9ABC),
            &from_dev,
        )?;
        match tool.unwrap(&from_dev, asdu::A_SECURE_DATA, &res)? {
            UnwrapOutcome::Synced {
                device_sequence,
                next_send_sequence,
            } => {
                assert_eq!(device_sequence, Sequence::new(900));
                assert_eq!(next_send_sequence, Sequence::new(6_001));
            }
            other => panic!("expected Synced, got {other:?}"),
        }
        assert!(tool.is_synced());
        assert_eq!(tool.send_sequence(), Sequence::new(6_001));

        // The device's next data frame carries 900: accepted. 899 would be stale.
        let mut dev =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(899));
        let (_, stale) = dev.wrap(&from_dev, 0x3D2, &[0x00])?;
        assert!(matches!(
            tool.unwrap(&from_dev, asdu::A_SECURE_DATA, &stale),
            Err(AsduError::StaleSequence { .. })
        ));
        let (_, fresh) = dev.wrap(&from_dev, 0x3D2, &[0x00])?;
        assert!(matches!(
            tool.unwrap(&from_dev, asdu::A_SECURE_DATA, &fresh)?,
            UnwrapOutcome::Secured { apci: 0x3D2, .. }
        ));
        Ok(())
    }

    /// A Sync_Res that answers a different challenge does not verify.
    #[test]
    fn test_sync_response_to_another_challenge_is_rejected() -> Result<(), AsduError> {
        let key = [0x24u8; 16];
        let mut tool = DataSecureSession::new(Key16::new(key));
        let a = addr(0x110C);
        tool.sync_request_with_challenge(&a, [9; 6])?;
        let res = asdu::encode_sync_res(
            &Key16::new(key),
            Scf::tool_sync(SecureService::SyncRes),
            &asdu::SyncResponse {
                responder_sequence: Sequence::new(1),
                requester_sequence: Sequence::new(2),
            },
            &[8; 6],
            Sequence::new(77),
            &a,
        )?;
        assert_eq!(
            tool.unwrap(&a, asdu::A_SECURE_DATA, &res),
            Err(AsduError::MacMismatch)
        );
        assert!(!tool.is_synced());
        Ok(())
    }

    #[test]
    fn test_unsolicited_sync_response_is_rejected() -> Result<(), AsduError> {
        let key = [0x24u8; 16];
        let mut tool = DataSecureSession::new(Key16::new(key));
        let a = addr(0x110C);
        let res = asdu::encode_sync_res(
            &Key16::new(key),
            Scf::tool_sync(SecureService::SyncRes),
            &asdu::SyncResponse {
                responder_sequence: Sequence::new(1),
                requester_sequence: Sequence::new(2),
            },
            &[8; 6],
            Sequence::new(77),
            &a,
        )?;
        assert_eq!(
            tool.unwrap(&a, asdu::A_SECURE_DATA, &res),
            Err(AsduError::UnsolicitedSyncResponse)
        );
        Ok(())
    }

    /// Tool and device sessions complete the handshake end to end; the device
    /// asks the tool to move past what it has already accepted.
    #[test]
    fn test_answer_sync_request_round_trip() -> Result<(), AsduError> {
        let key = [0x31u8; 16];
        let to_dev = addr(0x1119);
        let from_dev = TpAddressing {
            source: 0x110A,
            destination: 0x1119,
            ..addr(0x110A)
        };
        let mut device =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(70));
        // The device already accepted 500 from the tool in an earlier session.
        let mut earlier =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(500));
        let (_, old) = earlier.wrap(&to_dev, 0x300, &[0x00])?;
        device.unwrap(&to_dev, asdu::A_SECURE_DATA, &old)?;

        // A new tool session whose clock seed is behind the device's table.
        let mut tool =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(100));
        let (_, req) = tool.sync_request(&to_dev)?;
        let (_, res) = device.answer_sync_request(&to_dev, &req, &from_dev)?;
        tool.unwrap(&from_dev, asdu::A_SECURE_DATA, &res)?;
        assert!(tool.is_synced());
        assert_eq!(tool.send_sequence(), Sequence::new(501));
        // And the device accepts the tool's next data frame.
        let (_, data) = tool.wrap(&to_dev, 0x300, &[0x00])?;
        assert!(matches!(
            device.unwrap(&to_dev, asdu::A_SECURE_DATA, &data)?,
            UnwrapOutcome::Secured { .. }
        ));
        Ok(())
    }

    #[test]
    fn test_fresh_challenges_differ() {
        assert_ne!(fresh_challenge(), fresh_challenge());
    }

    #[test]
    fn test_debug_redacts_key() {
        let sess = DataSecureSession::new(Key16::new([0xAB; 16]));
        let rendered = format!("{sess:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ab"));
    }
}
