//! The connection-oriented L4 transport, server side: a Style 3 transport
//! layer (03_03_04 Transport Layer §5.4.3 as amended by AN210 §2.2.1, the only
//! style the transport-layer test specification 08_03_04 §3 admits for a new
//! device).
//!
//! - **T_Connect** (E00, E01): from CLOSED the connection opens with both
//!   sequence counters at 0 (A1). A repeated `T_Connect` from the connected
//!   address is ignored and the sequences are kept (A0); one from another
//!   address is answered with `T_Disconnect` (A10).
//! - **Numbered data**: at `SeqNoRcv` it is processed and acknowledged (E04,
//!   A2); a repeat of the previous one is acknowledged again without
//!   processing (E05, A3); any other sequence draws a `T_NAK` with the received
//!   sequence (E06, A4), or is dropped silently when
//!   [`Device::with_strict_l4_drop`] asks for the old behaviour.
//! - **Responses**: a numbered response waits for its `T_ACK` (OPEN_WAIT). A
//!   `T_ACK` or `T_NAK` with another sequence is ignored (E09, E11: A0, the
//!   AN210 amendment); a matching `T_NAK` repeats it (E12, A9) up to
//!   [`MAX_REPETITIONS`] times and then closes (E13, A6). Without an answer it
//!   is repeated every [`ACKNOWLEDGE_TIMEOUT`] (E17, A9) and the connection
//!   closes after the third repetition (E18, A6).
//! - **Connection timeout**: a connection without traffic for
//!   [`CONNECTION_TIMEOUT`] closes with a `T_Disconnect` to the peer (E16, A6).
//!
//! The timers run from [`Device::tick_l4`], which the bus drives, and are
//! checked again when the next frame arrives. Control frames go out at system
//! priority (03_03_04 §5.3).

use std::time::{Duration, Instant};

use crate::bus::event::Event;
use crate::wire::apdu::Apdu;
use crate::wire::{CemiLData, IndividualAddress, MessageCode, Tpci};

use super::{Device, DeviceError, DeviceReaction};

/// The connection timeout (03_03_04 §5, `connection_timeout_timer`): 6 s.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(6);

/// The acknowledge timeout (03_03_04 §5, `acknowledgment_timeout_timer`): 3 s.
pub const ACKNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(3);

/// How often an unacknowledged response is repeated before the connection is
/// closed (03_03_04 §5, `max_rep_count`).
pub const MAX_REPETITIONS: u8 = 3;

/// Control field 1 of a device-originated transport control frame: standard
/// frame, not repeated, broadcast, system priority (03_03_04 §5.3).
const CTRL1_SYSTEM: u8 = 0xB0;

/// A numbered response waiting for its `T_ACK` (state OPEN_WAIT).
#[derive(Debug, Clone)]
struct PendingResponse {
    frame: CemiLData,
    seq: u8,
    sent_at: Instant,
    repetitions: u8,
}

/// The transport-layer connection state beyond the sequence counters.
#[derive(Debug, Clone)]
pub(super) struct L4Session {
    /// The connected partner (`connection_address`), valid while connected.
    peer: IndividualAddress,
    /// When the connection last saw traffic, for [`CONNECTION_TIMEOUT`].
    last_traffic: Instant,
    /// The response waiting for its `T_ACK`.
    pending: Option<PendingResponse>,
    /// Drop an out-of-window numbered telegram silently instead of answering
    /// it with `T_NAK` (the behaviour before Style 3, for desync tests).
    strict_drop: bool,
}

impl Default for L4Session {
    fn default() -> Self {
        L4Session {
            peer: IndividualAddress(0),
            last_traffic: Instant::now(),
            pending: None,
            strict_drop: false,
        }
    }
}

impl Device {
    /// Keeps the pre-Style 3 behaviour of dropping an out-of-window numbered
    /// telegram silently (builder-style). Off by default, where the device
    /// answers it with `T_NAK` (03_03_04 §5.4.3 E06, A4). A test that wants a
    /// desynced tool to stall turns it on.
    pub fn with_strict_l4_drop(mut self, on: bool) -> Self {
        self.l4.strict_drop = on;
        self
    }

    /// Whether a transport connection from `peer` is open.
    pub fn l4_connected_to(&self, peer: IndividualAddress) -> bool {
        self.connected && self.l4.peer == peer
    }

    /// Runs the transport timers at `now` and returns the frames the device
    /// sends: a repeated response (E17, A9) or a `T_Disconnect` (E16 or E18,
    /// A6).
    pub fn tick_l4(&mut self, now: Instant) -> Vec<CemiLData> {
        if !self.connected {
            return Vec::new();
        }
        if now.saturating_duration_since(self.l4.last_traffic) >= CONNECTION_TIMEOUT {
            return self.l4_abandon("connection timeout");
        }
        let Some(pending) = &mut self.l4.pending else {
            return Vec::new();
        };
        if now.saturating_duration_since(pending.sent_at) < ACKNOWLEDGE_TIMEOUT {
            return Vec::new();
        }
        if pending.repetitions >= MAX_REPETITIONS {
            return self.l4_abandon("response not acknowledged");
        }
        pending.repetitions += 1;
        pending.sent_at = now;
        let frame = pending.frame.clone();
        self.l4.last_traffic = now;
        vec![frame]
    }

    /// When the next transport timer of this device runs out, if one runs.
    pub fn next_l4_deadline(&self) -> Option<Instant> {
        if !self.connected {
            return None;
        }
        let idle = self.l4.last_traffic + CONNECTION_TIMEOUT;
        Some(match &self.l4.pending {
            Some(p) => idle.min(p.sent_at + ACKNOWLEDGE_TIMEOUT),
            None => idle,
        })
    }

    /// Closes the connection and returns the `T_Disconnect` to the peer (A6).
    fn l4_abandon(&mut self, why: &str) -> Vec<CemiLData> {
        let peer = self.l4.peer;
        self.l4_close();
        let frame = self.t_control(peer, Tpci::DISCONNECT_BYTE);
        self.emit(Event::Telegram {
            direction: crate::bus::event::Direction::ToTool,
            cemi: frame.encode(),
            summary: format!("{} closes the connection to {peer}: {why}", self.address),
        });
        vec![frame]
    }

    /// Leaves the connection (A5/A6): nothing pending, verify mode cleared on
    /// a System 7 device (Resources 03_05_01 §4.2.14).
    fn l4_close(&mut self) {
        self.connected = false;
        self.l4.pending = None;
        if self.sys7.is_some() {
            self.clear_verify_mode();
        }
    }

    /// Handles a transport control PDU (`T_Connect`, `T_Disconnect`, `T_ACK`,
    /// `T_NAK`) from `cemi.source`.
    pub(super) fn handle_transport_control(
        &mut self,
        cemi: &CemiLData,
        tpci: Tpci,
        now: Instant,
    ) -> DeviceReaction {
        let from = cemi.source;
        let from_peer = self.connected && from == self.l4.peer;
        let mut responses = Vec::new();
        match tpci {
            Tpci::Connect if !self.connected => self.l4_open(from, now),
            // E00: a repeated T_Connect from the partner changes nothing (A0).
            Tpci::Connect if from_peer => {}
            // E01: another client while connected is refused (A10).
            Tpci::Connect => responses.push(self.t_control(from, Tpci::DISCONNECT_BYTE)),
            // E02, A5; E03 (another address) is A0.
            Tpci::Disconnect if from_peer => self.l4_close(),
            Tpci::Ack(seq) if from_peer => {
                self.l4.last_traffic = now;
                // E08, A8: the pending response is delivered. E09 (another
                // sequence) is A0 since AN210.
                if self.l4.pending.as_ref().is_some_and(|p| p.seq == seq) {
                    self.l4.pending = None;
                }
            }
            Tpci::Nak(seq) if from_peer => {
                self.l4.last_traffic = now;
                // E12/E13; E11 (another sequence) is A0.
                if let Some(pending) = self.l4.pending.as_mut().filter(|p| p.seq == seq) {
                    if pending.repetitions >= MAX_REPETITIONS {
                        responses = self.l4_abandon("T_NAK after the last repetition");
                    } else {
                        pending.repetitions += 1;
                        pending.sent_at = now;
                        responses.push(pending.frame.clone());
                    }
                }
            }
            _ => {}
        }
        DeviceReaction {
            responses,
            did_master_reset: false,
        }
    }

    /// Opens the connection to `peer` (A1).
    fn l4_open(&mut self, peer: IndividualAddress, now: Instant) {
        self.connected = true;
        self.l4.peer = peer;
        self.l4.last_traffic = now;
        self.l4.pending = None;
        self.tx_seq = 0;
        self.rx_seq = 0;
        // A fresh connection also resets the per-connection exchange budget:
        // each L4 connection gets its own allowance, so a tool that
        // periodically reconnects (as ETS does) never exhausts it.
        self.l4_exchanges = 0;
        // Verify mode (PID_DEVICE_CONTROL bit 2) belongs to the transport
        // connection: the device clears it when the connection closes, and a
        // client sets it again on every new one (Resources 03_05_01 §4.2.14).
        // A System 7 device follows the standard here; the System B KNX
        // Virtual model keeps the `04` it reports permanently.
        if self.sys7.is_some() {
            self.clear_verify_mode();
        }
        // Authorization is NOT reset on connect. In the ETS capture the tool
        // authorizes once (Phase A) and, after the pre-flash basic restart +
        // reconnect (Phase C), issues PID5/memory writes with no
        // re-authorize. A real device with the free-access key granted stays
        // at level 0 until a key is set, so the grant persists across a basic
        // restart within the session.
    }

    /// Runs the connection timeout lazily before a frame is handled, in case
    /// the bus did not tick in time: the frames to send first.
    pub(super) fn expire_l4(&mut self, now: Instant) -> Vec<CemiLData> {
        if self.connected
            && now.saturating_duration_since(self.l4.last_traffic) >= CONNECTION_TIMEOUT
        {
            return self.l4_abandon("connection timeout");
        }
        Vec::new()
    }

    /// Handle a numbered data telegram (NDT) from the connected partner
    /// (03_03_04 §5.4.3, events E04-E07):
    ///
    /// - **Expected sequence** (`seq == rx_seq`, E04, A2): process the APDU,
    ///   advance the receive sequence, and acknowledge. Verbs that carry their
    ///   own application-layer response (property read/write, authorize,
    ///   device-descriptor, master-reset) answer; the bus puts the T_ACK a real
    ///   device sends first in front of that answer. Response-less verbs
    ///   (`A_MemoryWrite`, a bare `A_Restart`) get the `T_ACK(seq)` here.
    /// - **Repeat of the last accepted frame** (`seq == rx_seq - 1` mod 16, E05,
    ///   A3): a retransmit whose `T_ACK` the tool missed. Re-acknowledge with
    ///   `T_ACK(seq)` but do **not** reprocess it (reprocessing a memory write
    ///   or double-advancing state would corrupt the session).
    /// - **Any other sequence** (E06, A4): `T_NAK(seq)`, not processed, so a
    ///   Style 3 tool repeats and then closes. With
    ///   [`with_strict_l4_drop`](Self::with_strict_l4_drop) it is dropped
    ///   silently instead.
    /// - **Another source** (E07): ignored (A0).
    pub(super) fn handle_numbered_data(
        &mut self,
        cemi: &CemiLData,
        seq: u8,
        now: Instant,
    ) -> Result<DeviceReaction, DeviceError> {
        let tool = cemi.source;
        if self.connected && tool != self.l4.peer {
            return Ok(DeviceReaction::default());
        }
        if self.connected {
            self.l4.last_traffic = now;
        }

        // A retransmit of the frame we last accepted: re-ACK, do not reprocess.
        let last_accepted = self.rx_seq.wrapping_sub(1) & 0x0F;
        if self.connected && seq == last_accepted {
            return Ok(DeviceReaction {
                responses: vec![self.t_ack(tool, seq)],
                did_master_reset: false,
            });
        }

        // Out-of-window sequence: T_NAK with the received sequence (A4).
        if self.connected && seq != self.rx_seq {
            self.emit(Event::Telegram {
                direction: crate::bus::event::Direction::ToBus,
                cemi: cemi.encode(),
                summary: format!(
                    "{} {}: out-of-sequence NDT seq {seq} (expected {})",
                    if self.l4.strict_drop {
                        "DROPPED by"
                    } else {
                        "T_NAKed by"
                    },
                    self.address,
                    self.rx_seq
                ),
            });
            if self.l4.strict_drop {
                return Ok(DeviceReaction::default());
            }
            return Ok(DeviceReaction {
                responses: vec![self.t_control(tool, Tpci::nak_byte(seq))],
                did_master_reset: false,
            });
        }

        // Per-connection exchange budget: a real connection-oriented device drops
        // a long-held L4 connection after a bounded number of numbered exchanges
        // (KNX Virtual DA.tp drops at ~35). This expected-sequence NDT is one such
        // exchange; if accepting it would exceed the budget, the device drops the
        // connection instead — it stops answering entirely (silence), exactly as
        // the real device does, so the tool sees "device absent" unless it cycled
        // the connection in time. Reset per connection on T_Connect. `None` =
        // unlimited (the default), leaving existing behaviour unchanged.
        if let Some(budget) = self.l4_exchange_budget {
            if self.l4_exchanges >= budget {
                self.connected = false;
                self.emit(Event::Telegram {
                    direction: crate::bus::event::Direction::ToBus,
                    cemi: cemi.encode(),
                    summary: format!(
                        "DROPPED by {}: L4 exchange budget {budget} exhausted; connection dropped",
                        self.address
                    ),
                });
                return Ok(DeviceReaction::default());
            }
            self.l4_exchanges += 1;
        }

        // Expected sequence: parse, process, advance, acknowledge.
        let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
            service: "APDU".into(),
            detail: "too short".into(),
        })?;
        self.rx_seq = (self.rx_seq + 1) & 0x0F;
        // The response carries the device's own send sequence (03_03_04), not
        // the request's: it lags the tool's after T_ACK-only exchanges, which
        // bussard's L4 expects and ETS 6 accepts (it T_ACKed a lagging answer
        // and went on, ETS-against-sim capture 2026-10-27). KNX Virtual mirrors
        // the request's number instead; mirroring here broke bussard's loop.
        let mut reaction = self.handle_apdu(cemi, &apdu)?;
        if reaction.responses.is_empty() {
            reaction.responses.push(self.t_ack(tool, seq));
        }
        // A numbered response waits for its T_ACK (OPEN_WAIT); a restart that
        // dropped the connection leaves nothing to wait for.
        if self.connected
            && let Some(resp) = reaction
                .responses
                .iter()
                .rev()
                .find(|r| r.tpdu.first().is_some_and(|b| b & 0xC0 == 0x40))
        {
            self.l4.pending = Some(PendingResponse {
                frame: resp.clone(),
                seq: (resp.tpdu[0] >> 2) & 0x0F,
                sent_at: now,
                repetitions: 0,
            });
        }
        // The T_ACK that precedes an application-layer response is added by
        // the bus (`Bus::deliver_from_tool`), where the device's unit tests do
        // not look.
        Ok(reaction)
    }

    /// Build a transport-layer `T_ACK(seq)` frame back toward `to`.
    ///
    /// A real device T_ACKs every numbered data telegram at the transport layer,
    /// including an `A_Restart` — which, unlike a property/memory verb, carries no
    /// application-layer response. The management tool waits for that T_ACK before
    /// it considers the restart delivered (see bussard's
    /// `master_reset_via_basic_restart`), so the simulator must emit it before it
    /// reboots and drops the connection, or the tool retransmits into the void.
    fn t_ack(&self, to: IndividualAddress, seq: u8) -> CemiLData {
        self.t_control(to, Tpci::ack_byte(seq))
    }

    /// Build a transport control frame (`T_ACK`, `T_NAK`, `T_Disconnect`)
    /// toward `to`, at system priority (03_03_04 §5.3).
    fn t_control(&self, to: IndividualAddress, octet: u8) -> CemiLData {
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: CTRL1_SYSTEM,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu: vec![octet],
        }
    }

    /// Build a connected `L_Data.ind` response back toward `dest` (the tool).
    pub(super) fn respond(&mut self, to: IndividualAddress, apci10: u16, data: &[u8]) -> CemiLData {
        let seq = self.tx_seq;
        self.tx_seq = (self.tx_seq + 1) & 0x0F;
        let tpdu = Apdu::encode_connected(seq, apci10, data);
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ACKNOWLEDGE_TIMEOUT, CONNECTION_TIMEOUT, MAX_REPETITIONS};
    use crate::device::test_support::*;
    use crate::device::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_l4_duplicate_ndt_is_reacked_not_reprocessed() -> Result<(), Box<dyn std::error::Error>>
    {
        // A retransmit of the last-accepted NDT (its T_ACK was lost) must be
        // re-acknowledged with the SAME sequence but NOT reprocessed. We use an
        // authorize at seq 0 (auth -> level 0), then replay the identical seq-0
        // frame: the replay must produce a bare T_ACK(0), not a second authorize
        // response, and must not advance rx_seq.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        assert_eq!(dev.rx_seq, 0);
        let auth = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&auth)?;
        assert_eq!(
            r.responses.len(),
            1,
            "authorize answers with a response NDT"
        );
        assert_eq!(dev.rx_seq, 1, "rx_seq advanced past the accepted frame");

        // Replay the exact same seq-0 frame (a retransmit).
        let replay = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r2 = dev.handle_cemi(&replay)?;
        assert_eq!(r2.responses.len(), 1, "duplicate is re-acknowledged");
        // The re-ACK is a bare transport T_ACK(0), not an application response.
        assert_eq!(r2.responses[0].tpdu, vec![Tpci::ack_byte(0)]);
        assert_eq!(dev.rx_seq, 1, "duplicate must not advance rx_seq");
        Ok(())
    }

    #[test]
    fn test_l4_out_of_sequence_ndt_is_naked() -> Result<(), Box<dyn std::error::Error>> {
        // 03_03_04 §5.4.3 E06, A4: an NDT with an unexpected sequence (neither
        // the expected one nor the last-accepted repeat) is answered with
        // T_NAK carrying the received sequence and not processed.
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        let stray = data_seq(&dev, 5, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&stray)?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu, vec![Tpci::nak_byte(5)]);
        assert_eq!(r.responses[0].ctrl1, 0xB0, "system priority");
        assert_eq!(dev.rx_seq, 0, "rx_seq unchanged by a refused frame");
        assert_eq!(
            dev.access_level, 15,
            "the stray authorize was not processed"
        );
        Ok(())
    }

    #[test]
    fn test_l4_out_of_sequence_ndt_is_dropped_when_strict() -> Result<(), Box<dyn std::error::Error>>
    {
        // The pre-Style 3 behaviour stays available for desync tests: no
        // response at all, so a desynced tool stalls.
        let mut dev = system_b_device()?.with_strict_l4_drop(true);
        connect(&mut dev)?;
        let stray = data_seq(&dev, 5, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&stray)?;
        assert!(
            r.responses.is_empty(),
            "out-of-sequence NDT draws no response"
        );
        assert_eq!(dev.rx_seq, 0);
        assert_eq!(dev.access_level, 15);
        Ok(())
    }

    /// A device answering an authorize at seq 0, so a response is pending.
    fn answered(dev: &mut Device) -> Result<CemiLData, Box<dyn std::error::Error>> {
        connect(dev)?;
        let r = dev.handle_cemi(&data(dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let resp = r.responses.last().ok_or("authorize response")?.clone();
        assert_eq!(resp.tpdu[0] & 0xC0, 0x40, "a numbered response");
        Ok(resp)
    }

    fn control(dev: &Device, from: IndividualAddress, octet: u8) -> CemiLData {
        CemiLData {
            source: from,
            tpdu: vec![octet],
            ..data_seq(dev, 0, 0, &[])
        }
    }

    fn tool() -> IndividualAddress {
        IndividualAddress::new(0, 0, 0)
    }

    #[test]
    fn test_l4_repeated_t_connect_keeps_the_sequences() -> Result<(), Box<dyn std::error::Error>> {
        // E00 in OPEN_IDLE is A0: the partner's repeated T_Connect neither
        // resets the sequences nor answers.
        let mut dev = system_b_device()?;
        answered(&mut dev)?;
        assert_eq!((dev.rx_seq, dev.tx_seq), (1, 1));
        let r = dev.handle_cemi(&control(&dev, tool(), 0x80))?;
        assert!(r.responses.is_empty());
        assert_eq!((dev.rx_seq, dev.tx_seq), (1, 1), "sequences kept");
        Ok(())
    }

    #[test]
    fn test_l4_t_connect_from_another_client_is_refused() -> Result<(), Box<dyn std::error::Error>>
    {
        // E01, A10: a T_Disconnect back to the other client; the open
        // connection stays.
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        let other = IndividualAddress::new(1, 1, 250);
        let r = dev.handle_cemi(&control(&dev, other, 0x80))?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu, vec![Tpci::DISCONNECT_BYTE]);
        assert_eq!(r.responses[0].dest, other.raw());
        assert!(dev.l4_connected_to(tool()));
        Ok(())
    }

    #[test]
    fn test_l4_connection_timeout_disconnects() -> Result<(), Box<dyn std::error::Error>> {
        // E16, A6: 6 s without traffic close the connection with a
        // T_Disconnect to the partner; a numbered telegram afterwards is
        // ignored (E04 in CLOSED, A0).
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        let now = Instant::now();
        assert!(dev.tick_l4(now + Duration::from_secs(5)).is_empty());
        let out = dev.tick_l4(now + CONNECTION_TIMEOUT + Duration::from_millis(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tpdu, vec![Tpci::DISCONNECT_BYTE]);
        assert!(!dev.l4_connected_to(tool()));
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]));
        assert!(r.is_err() || r.as_ref().is_ok_and(|r| r.responses.is_empty()));
        Ok(())
    }

    #[test]
    fn test_l4_connection_timeout_runs_when_the_next_frame_arrives()
    -> Result<(), Box<dyn std::error::Error>> {
        // Without a tick in between, the next frame finds the connection
        // expired: the T_Disconnect goes out first.
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        let later = Instant::now() + CONNECTION_TIMEOUT + Duration::from_secs(1);
        let r = dev.handle_cemi_at(&control(&dev, tool(), 0x80), later)?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu, vec![Tpci::DISCONNECT_BYTE]);
        assert!(
            dev.l4_connected_to(tool()),
            "the T_Connect opened a fresh connection"
        );
        assert_eq!(dev.rx_seq, 0);
        Ok(())
    }

    #[test]
    fn test_l4_unacknowledged_response_is_repeated_then_disconnected()
    -> Result<(), Box<dyn std::error::Error>> {
        // E17, A9 three times every 3 s, then E18, A6.
        let mut dev = system_b_device()?;
        let resp = answered(&mut dev)?;
        let mut now = Instant::now();
        for _ in 0..MAX_REPETITIONS {
            now += ACKNOWLEDGE_TIMEOUT;
            let out = dev.tick_l4(now);
            assert_eq!(out, vec![resp.clone()], "the stored response again");
        }
        now += ACKNOWLEDGE_TIMEOUT;
        let out = dev.tick_l4(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tpdu, vec![Tpci::DISCONNECT_BYTE]);
        assert!(!dev.l4_connected_to(tool()));
        Ok(())
    }

    #[test]
    fn test_l4_t_ack_completes_the_response() -> Result<(), Box<dyn std::error::Error>> {
        // E09 (wrong sequence) is A0 since AN210; E08 consumes the response.
        let mut dev = system_b_device()?;
        let resp = answered(&mut dev)?;
        let seq = (resp.tpdu[0] >> 2) & 0x0F;
        let wrong = dev.handle_cemi(&control(&dev, tool(), Tpci::ack_byte(seq + 3)))?;
        assert!(wrong.responses.is_empty());
        assert!(dev.l4_connected_to(tool()), "a stray T_ACK does not close");
        let now = Instant::now() + ACKNOWLEDGE_TIMEOUT;
        assert_eq!(
            dev.tick_l4(now).len(),
            1,
            "still waiting for the right T_ACK"
        );
        dev.handle_cemi(&control(&dev, tool(), Tpci::ack_byte(seq)))?;
        assert!(
            dev.tick_l4(now + ACKNOWLEDGE_TIMEOUT).is_empty(),
            "nothing pending"
        );
        Ok(())
    }

    #[test]
    fn test_l4_t_nak_repeats_the_response() -> Result<(), Box<dyn std::error::Error>> {
        // E12, A9; E11 (wrong sequence) A0; E13 after the last repetition, A6.
        let mut dev = system_b_device()?;
        let resp = answered(&mut dev)?;
        let seq = (resp.tpdu[0] >> 2) & 0x0F;
        let wrong = dev.handle_cemi(&control(&dev, tool(), Tpci::nak_byte(seq + 1)))?;
        assert!(wrong.responses.is_empty());
        for _ in 0..MAX_REPETITIONS {
            let r = dev.handle_cemi(&control(&dev, tool(), Tpci::nak_byte(seq)))?;
            assert_eq!(r.responses, vec![resp.clone()]);
        }
        let r = dev.handle_cemi(&control(&dev, tool(), Tpci::nak_byte(seq)))?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu, vec![Tpci::DISCONNECT_BYTE]);
        assert!(!dev.l4_connected_to(tool()));
        Ok(())
    }

    #[test]
    fn test_l4_sequence_advances_across_a_wrap() -> Result<(), Box<dyn std::error::Error>> {
        // Drive 18 accepted device-descriptor reads so the receive sequence wraps
        // past 15 back through 0 and 1. Each read is at the expected sequence
        // (data() threads dev.rx_seq), so every one must be accepted and answered,
        // and rx_seq must land at 18 mod 16 = 2.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        for i in 0..18u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "descriptor read {i} must be accepted and answered"
            );
        }
        assert_eq!(dev.rx_seq, 2, "18 accepted NDTs wrap rx_seq to 2");
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_drops_connection_after_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        // A device with a per-connection exchange budget drops the connection —
        // stops answering — once that many numbered exchanges have been accepted on
        // one connection, modelling a real connection-oriented device's
        // per-connection resource limit (KNX Virtual drops at ~35). Set a low
        // budget (3) and drive descriptor reads: the first 3 are answered, the 4th
        // and beyond draw no response and the device is no longer connected.
        let Some(dev) = da_tp_device()? else {
            return Ok(());
        };
        let mut dev = dev.with_l4_exchange_budget(Some(3));
        connect(&mut dev)?;
        for i in 0..3u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "exchange {i} is within budget and must be answered"
            );
        }
        // The 4th exchange exceeds the budget: the device drops the connection.
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert!(
            r.responses.is_empty(),
            "the over-budget exchange must draw no response (connection dropped)"
        );
        assert!(
            !dev.connected,
            "exceeding the budget drops the L4 connection"
        );
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_resets_on_reconnect() -> Result<(), Box<dyn std::error::Error>> {
        // The per-connection budget is per CONNECTION: a fresh T_Connect resets it,
        // so a tool that reconnects before exhausting the budget keeps being
        // served. Drive the budget to exhaustion, then reconnect and confirm the
        // device answers again — the persistent object state is unchanged.
        let Some(dev) = da_tp_device()? else {
            return Ok(());
        };
        let mut dev = dev.with_l4_exchange_budget(Some(2));
        connect(&mut dev)?;
        for _ in 0..2u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(r.responses.len(), 1);
        }
        // Over budget: dropped.
        assert!(
            dev.handle_cemi(&data(&dev, 0x300, &[]))?
                .responses
                .is_empty()
        );
        // Reconnect: a fresh window resets the budget and the device serves again.
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(
            r.responses.len(),
            1,
            "a fresh connection resets the budget and the device answers again"
        );
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_unlimited_by_default() -> Result<(), Box<dyn std::error::Error>> {
        // The default budget is unlimited: without `with_l4_exchange_budget`, a
        // long run of exchanges on one connection is served in full (existing tests
        // and captures are unaffected).
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        for i in 0..40u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "exchange {i} must be answered under the default unlimited budget"
            );
        }
        assert!(dev.connected, "the connection stays up under no budget");
        Ok(())
    }
}
