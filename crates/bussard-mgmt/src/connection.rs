//! The connection-oriented transport (layer-4) state machine.
//!
//! This drives the KNX "style-1 rationalised" connection over any
//! [`BusConnection`]: it opens a connection to one individual address with
//! `T_Connect`, sends numbered data telegrams (NDT) and waits for the device's
//! `T_ACK`, receives the device's response NDTs and acknowledges them, and tears
//! the connection down cleanly with `T_Disconnect`.
//!
//! # State machine (style-1 rationalised)
//!
//! - **Connect**: send `T_Connect`; the connection is established optimistically
//!   (KNX `T_Connect` is unconfirmed). Sequence counters reset to 0 both ways.
//! - **Send NDT**: send `T_Data_Connected` with the current send sequence; await
//!   a `T_ACK` for that sequence within [`ACK_TIMEOUT`]; on timeout retransmit up
//!   to [`MAX_REPETITIONS`] times; then advance the send sequence (mod 16).
//! - **Receive NDT**: on an incoming NDT with the **expected** receive sequence,
//!   reply `T_ACK` and deliver it, then advance the receive sequence. On an
//!   incoming NDT with a wrong sequence, reply `T_ACK` with `expected - 1` and
//!   drop it (a benign duplicate). Any `T_Disconnect` or protocol error tears the
//!   connection down.
//! - **Disconnect**: send `T_Disconnect`. The device also disconnects itself
//!   after roughly six seconds of inactivity, so no idle heartbeat is needed —
//!   we simply reconnect per procedure.
//!
//! The wire behaviour follows the published KNX transport-layer procedure
//! (EN 50090 / the KNX standard). No GPL sources were consulted.

use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Tpci};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{BusConnection, TransportError};
use tokio::time::{Instant, timeout};

use crate::error::{MgmtError, Result};

/// How long to wait for a `T_ACK` after sending a numbered data telegram. This
/// is the KNX-standard value; `bussard scan` overrides it with a shorter value
/// to keep a full-line sweep to minutes rather than hours.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// How many times a numbered data telegram is retransmitted after an ACK
/// timeout before the connection is considered dead.
pub const MAX_REPETITIONS: u32 = 3;

/// How long to wait for a device's response telegram (an incoming NDT) after
/// our request has been acknowledged, before concluding the device will not
/// answer.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeout and retry budget for a connection-oriented session.
///
/// The defaults are the KNX-standard values ([`ACK_TIMEOUT`],
/// [`MAX_REPETITIONS`], [`RESPONSE_TIMEOUT`]). Discovery paths such as
/// `bussard scan` construct a tighter budget so probing an absent address fails
/// fast.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// How long to wait for a `T_ACK` per attempt.
    pub ack_timeout: Duration,
    /// Retransmissions after an ACK timeout before giving up.
    pub max_repetitions: u32,
    /// How long to wait for the device's response NDT.
    pub response_timeout: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            ack_timeout: ACK_TIMEOUT,
            max_repetitions: MAX_REPETITIONS,
            response_timeout: RESPONSE_TIMEOUT,
        }
    }
}

impl Timeouts {
    /// A tight budget for discovery: a short per-attempt timeout with a single
    /// retry, so an absent address is ruled out in roughly `2 × ack_timeout`.
    /// Used by `bussard scan`.
    pub fn discovery() -> Self {
        Timeouts {
            ack_timeout: Duration::from_millis(1500),
            max_repetitions: 1,
            response_timeout: Duration::from_millis(1500),
        }
    }
}

/// A live connection-oriented (layer-4) session to a single device.
///
/// Borrow-based: it drives an existing [`BusConnection`] and does not own it, so
/// several sequential connections can reuse one bus session (important on TP1,
/// where only one connection should be open at a time).
pub struct Layer4Connection<'a, C: BusConnection> {
    conn: &'a mut C,
    target: IndividualAddress,
    source: IndividualAddress,
    timeouts: Timeouts,
    send_seq: u8,
    recv_seq: u8,
    /// A response NDT the device folded in *before* its `T_ACK` (some stacks
    /// answer and acknowledge in one step). [`await_ack`](Self::await_ack)
    /// stashes its decoded `(apci, data)` here after ACKing it and advancing the
    /// receive sequence; [`recv_response`](Self::recv_response) drains this
    /// first so the folded answer is not lost.
    pending_response: Option<(u16, Vec<u8>)>,
    /// Set once the peer disconnects or a protocol error occurs, so a stale
    /// `disconnect()` is a no-op.
    closed: bool,
}

impl<'a, C: BusConnection> Layer4Connection<'a, C> {
    /// Opens a connection to `target`, sending `T_Connect`.
    ///
    /// `source` is the individual address the tool presents as. The connection
    /// is established optimistically; the first `send_data` that times out
    /// without any `T_ACK` surfaces the device as absent.
    pub async fn connect(
        conn: &'a mut C,
        target: IndividualAddress,
        source: IndividualAddress,
    ) -> Result<Layer4Connection<'a, C>> {
        Self::connect_with(conn, target, source, Timeouts::default()).await
    }

    /// Like [`connect`](Self::connect) but with an explicit timeout budget.
    pub async fn connect_with(
        conn: &'a mut C,
        target: IndividualAddress,
        source: IndividualAddress,
        timeouts: Timeouts,
    ) -> Result<Layer4Connection<'a, C>> {
        let frame = CemiFrame::t_control(target, source, tpci::T_CONNECT);
        conn.send(frame).await?;
        Ok(Layer4Connection {
            conn,
            target,
            source,
            timeouts,
            send_seq: 0,
            recv_seq: 0,
            pending_response: None,
            closed: false,
        })
    }

    /// Sends a management request (APCI + payload) as a numbered data telegram
    /// and waits for the device's `T_ACK`, retransmitting on timeout.
    ///
    /// Returns [`MgmtError::NoResponse`] if no `T_ACK` ever arrives (the device
    /// is absent), or [`MgmtError::Nak`] if the device negatively acknowledges.
    pub async fn send_data(&mut self, apci: u16, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        let seq = self.send_seq;
        let tpci_octet = tpci::ndt(seq);
        let frame = CemiFrame::t_data_connected(self.target, self.source, tpci_octet, apci, data);

        let mut attempt = 0;
        loop {
            self.conn.send(frame.clone()).await?;
            match self.await_ack(seq).await {
                AckOutcome::Acked => {
                    self.send_seq = (self.send_seq + 1) & 0x0f;
                    return Ok(());
                }
                AckOutcome::Nak => {
                    // Style-1: a NAK asks for a repeat. Retransmit up to
                    // `max_repetitions` times before giving up and tearing the
                    // connection down.
                    if attempt >= self.timeouts.max_repetitions {
                        self.mark_closed_disconnect().await;
                        return Err(MgmtError::Nak {
                            address: self.target,
                        });
                    }
                    attempt += 1;
                }
                AckOutcome::Disconnected => {
                    self.closed = true;
                    return Err(MgmtError::Disconnected {
                        address: self.target,
                    });
                }
                AckOutcome::Timeout => {
                    if attempt >= self.timeouts.max_repetitions {
                        // The very first send with no reaction at all means the
                        // device is absent; after that, treat the silence as a
                        // dead connection to a device that stopped answering.
                        self.closed = true;
                        return Err(MgmtError::NoResponse {
                            address: self.target,
                        });
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// Waits for the device's response telegram (an incoming NDT), acknowledges
    /// it, and returns its decoded APDU.
    ///
    /// Frames unrelated to this connection (group traffic, telegrams from other
    /// sources) are skipped. A wrong-sequence NDT is acknowledged with
    /// `expected - 1` and dropped. Times out as [`MgmtError::NoResponse`].
    pub async fn recv_response(&mut self) -> Result<(u16, Vec<u8>)> {
        // A folded-ACK response that arrived while we were awaiting the T_ACK has
        // already been acknowledged and sequenced; hand it back first.
        if let Some(pending) = self.pending_response.take() {
            return Ok(pending);
        }
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        let deadline = Instant::now() + self.timeouts.response_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(MgmtError::NoResponse {
                    address: self.target,
                });
            }
            let stamped = match timeout(remaining, self.conn.recv()).await {
                Ok(Ok(stamped)) => stamped,
                Ok(Err(err)) => return Err(self.map_recv_error(err)),
                Err(_elapsed) => {
                    return Err(MgmtError::NoResponse {
                        address: self.target,
                    });
                }
            };
            let frame = stamped.frame;

            // Ignore anything not from our peer addressed to us individually.
            if frame.source != self.target || frame.individual_destination() != Some(self.source) {
                continue;
            }

            match tpci::classify(frame.tpci_octet()) {
                TpciKind::Disconnect => {
                    self.closed = true;
                    return Err(MgmtError::Disconnected {
                        address: self.target,
                    });
                }
                TpciKind::NumberedData(seq) => {
                    if seq == self.recv_seq {
                        // Expected sequence: ACK and deliver.
                        self.send_control(tpci::t_ack(seq)).await?;
                        self.recv_seq = (self.recv_seq + 1) & 0x0f;
                        let (apci, data) = extract_apdu(&frame);
                        return Ok((apci, data));
                    } else {
                        // Wrong sequence (a duplicate): ACK with expected-1 and
                        // drop, per the style-1 procedure.
                        let ack_seq = self.recv_seq.wrapping_sub(1) & 0x0f;
                        self.send_control(tpci::t_ack(ack_seq)).await?;
                        continue;
                    }
                }
                // A stray ACK/NAK/connect while awaiting a response: ignore.
                _ => continue,
            }
        }
    }

    /// A request/response round-trip: send the request NDT, wait for the ACK,
    /// then wait for and acknowledge the response NDT. Returns the response APCI
    /// and payload octets.
    pub async fn request(&mut self, apci: u16, data: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.send_data(apci, data).await?;
        self.recv_response().await
    }

    /// Tears the connection down with `T_Disconnect` (best-effort).
    pub async fn disconnect(mut self) -> Result<()> {
        self.close().await
    }

    /// The target device address.
    pub fn target(&self) -> IndividualAddress {
        self.target
    }

    // --- internals ---

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let frame = CemiFrame::t_control(self.target, self.source, tpci::T_DISCONNECT);
        self.conn.send(frame).await?;
        Ok(())
    }

    /// Sends a single transport-control octet to the peer.
    async fn send_control(&mut self, octet: u8) -> Result<()> {
        let frame = CemiFrame::t_control(self.target, self.source, octet);
        self.conn.send(frame).await?;
        Ok(())
    }

    /// Best-effort `T_Disconnect` after a NAK, ignoring send errors.
    async fn mark_closed_disconnect(&mut self) {
        self.closed = true;
        let frame = CemiFrame::t_control(self.target, self.source, tpci::T_DISCONNECT);
        let _ = self.conn.send(frame).await;
    }

    /// Waits for a `T_ACK`/`T_NAK` for `seq` from the peer, skipping unrelated
    /// traffic. Incoming NDTs while waiting are acknowledged and dropped so the
    /// device is not left retransmitting.
    async fn await_ack(&mut self, seq: u8) -> AckOutcome {
        let deadline = Instant::now() + self.timeouts.ack_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return AckOutcome::Timeout;
            }
            let stamped = match timeout(remaining, self.conn.recv()).await {
                Ok(Ok(stamped)) => stamped,
                Ok(Err(_)) => return AckOutcome::Disconnected,
                Err(_elapsed) => return AckOutcome::Timeout,
            };
            let frame = stamped.frame;
            if frame.source != self.target || frame.individual_destination() != Some(self.source) {
                continue;
            }
            match tpci::classify(frame.tpci_octet()) {
                TpciKind::Ack(acked) if acked == seq => return AckOutcome::Acked,
                TpciKind::Nak(_) => return AckOutcome::Nak,
                TpciKind::Disconnect => return AckOutcome::Disconnected,
                TpciKind::NumberedData(nseq) => {
                    // The device answered before we saw its ACK (some stacks fold
                    // the ACK into the response). Acknowledge the data so it does
                    // not retransmit, stash the APDU as the pending response and
                    // advance the receive sequence, and treat our send as
                    // acknowledged. Without stashing, the folded answer would be
                    // dropped and `recv_response` would wait forever for a second
                    // NDT that never comes (permanent desync).
                    if nseq == self.recv_seq {
                        let _ = self.send_control(tpci::t_ack(nseq)).await;
                        self.recv_seq = (self.recv_seq + 1) & 0x0f;
                        self.pending_response = Some(extract_apdu(&frame));
                    } else {
                        // A duplicate/out-of-window folded NDT: ACK expected-1 and
                        // drop it, per the style-1 procedure.
                        let ack_seq = self.recv_seq.wrapping_sub(1) & 0x0f;
                        let _ = self.send_control(tpci::t_ack(ack_seq)).await;
                    }
                    return AckOutcome::Acked;
                }
                _ => continue,
            }
        }
    }

    fn map_recv_error(&mut self, err: TransportError) -> MgmtError {
        self.closed = true;
        match err {
            TransportError::Disconnected(_) => MgmtError::Disconnected {
                address: self.target,
            },
            other => MgmtError::Transport(other),
        }
    }
}

/// The outcome of waiting for an acknowledgement.
enum AckOutcome {
    /// A `T_ACK` for our sequence arrived (or the device answered directly).
    Acked,
    /// A `T_NAK` arrived.
    Nak,
    /// The peer disconnected or the connection dropped.
    Disconnected,
    /// No `T_ACK` arrived within the timeout.
    Timeout,
}

/// Extracts the (apci, data) from a management frame, tolerating any APDU shape.
fn extract_apdu(frame: &CemiFrame) -> (u16, Vec<u8>) {
    match (&frame.tpci, &frame.apdu) {
        (Tpci::Other(_) | Tpci::DataGroup, Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => (0, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::SystemTime;

    use bussard_transport::TimestampedFrame;

    /// A scripted in-memory [`BusConnection`]: it records every frame the code
    /// under test sends, and hands back a pre-queued script of frames on each
    /// `recv`. When the script is empty, `recv` blocks forever (so the ACK/
    /// response timeout fires), which lets us drive the timeout/retransmit paths
    /// deterministically with a tiny [`Timeouts`] budget.
    struct ScriptedBus {
        sent: Vec<CemiFrame>,
        inbox: VecDeque<CemiFrame>,
    }

    impl ScriptedBus {
        fn new(inbox: Vec<CemiFrame>) -> Self {
            ScriptedBus {
                sent: Vec::new(),
                inbox: inbox.into(),
            }
        }
    }

    impl BusConnection for ScriptedBus {
        async fn send(&mut self, frame: CemiFrame) -> bussard_transport::Result<()> {
            self.sent.push(frame);
            Ok(())
        }

        async fn recv(&mut self) -> bussard_transport::Result<TimestampedFrame> {
            match self.inbox.pop_front() {
                Some(frame) => Ok(TimestampedFrame {
                    received_at: SystemTime::now(),
                    frame,
                }),
                // Empty: block forever so the caller's timeout elapses.
                None => std::future::pending().await,
            }
        }

        async fn close(self) -> bussard_transport::Result<()> {
            Ok(())
        }
    }

    fn dev() -> IndividualAddress {
        "1.1.4".parse().unwrap()
    }
    fn tool() -> IndividualAddress {
        "0.0.255".parse().unwrap()
    }

    /// A device→tool control frame (T_ACK / T_NAK / T_Disconnect).
    fn control_from_dev(octet: u8) -> CemiFrame {
        CemiFrame::t_control(tool(), dev(), octet)
    }

    /// A device→tool numbered data response frame.
    fn ndt_from_dev(seq: u8, apci: u16, data: &[u8]) -> CemiFrame {
        CemiFrame::t_data_connected(tool(), dev(), tpci::ndt(seq), apci, data)
    }

    fn fast() -> Timeouts {
        Timeouts {
            ack_timeout: Duration::from_millis(50),
            max_repetitions: 1,
            response_timeout: Duration::from_millis(50),
        }
    }

    #[test]
    fn constants_are_within_spec_bounds() {
        assert_eq!(ACK_TIMEOUT, Duration::from_secs(3));
        assert_eq!(MAX_REPETITIONS, 3);
    }

    #[test]
    fn extract_apdu_reads_management_apci() {
        let frame = ndt_from_dev(0, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE, &[0x07, 0xB0]);
        let (apci, data) = extract_apdu(&frame);
        assert_eq!(apci, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE);
        assert_eq!(data, vec![0x07, 0xB0]);
    }

    #[tokio::test]
    async fn happy_path_request_response() {
        // Script: T_ACK(0) for our request, then the response NDT(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let (apci, data) = l4.request(0x300, &[0x00]).await.unwrap();
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        // We sent: T_Connect, the request NDT, and the T_ACK for the response.
        let octets: Vec<u8> = bus.sent.iter().map(|f| f.tpci_octet()).collect();
        assert_eq!(octets[0], tpci::T_CONNECT);
        // NDT seq 0 octet has APCI high bits folded in; mask them off.
        assert_eq!(octets[1] & 0xfc, tpci::ndt(0));
        assert_eq!(octets[2], tpci::t_ack(0));
    }

    #[tokio::test]
    async fn retransmit_on_ack_timeout() {
        // Script: no ACK for the first send (empty inbox forces a timeout), then
        // after the retransmit, an ACK(0) + response. We prime the inbox so the
        // ACK only appears "after" one timeout by leaving it empty first — but
        // ScriptedBus pops immediately, so instead assert the retransmit count.
        // Here we let the first attempt time out (empty inbox) and never ACK, so
        // the send fails; we assert the request was sent max_repetitions+1 times.
        let mut bus = ScriptedBus::new(vec![]);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast())
            .await
            .unwrap();
        let err = l4.send_data(0x300, &[0x00]).await.unwrap_err();
        assert!(matches!(err, MgmtError::NoResponse { .. }), "got {err:?}");
        // T_Connect + (1 initial + 1 retransmit) request sends = 3 frames.
        let ndt_sends = bus
            .sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .count();
        assert_eq!(ndt_sends, 2, "one initial send plus one retransmit");
    }

    #[tokio::test]
    async fn wrong_sequence_response_is_dropped_then_correct_delivered() {
        // Script: ACK(0), then a WRONG-seq NDT(5), then the correct NDT(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(5, 0x340, &[0xFF]),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let (_apci, data) = l4.request(0x300, &[0x00]).await.unwrap();
        // The wrong-seq frame was dropped; the correct one delivered.
        assert_eq!(data, vec![0x07, 0xB0]);
        // Among sent frames there is a T_ACK for the wrong seq's expected-1 (0-1
        // = 15) followed by the T_ACK(0) for the delivered frame.
        let acks: Vec<u8> = bus
            .sent
            .iter()
            .filter_map(|f| match tpci::classify(f.tpci_octet()) {
                TpciKind::Ack(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(acks, vec![15, 0], "wrong-seq ACKed with expected-1, then 0");
    }

    #[tokio::test]
    async fn folded_ack_response_is_delivered() {
        // The device folds the ACK: instead of a T_ACK, it answers directly with
        // the response NDT(0). await_ack must stash it, advance recv_seq and ACK
        // it; recv_response then drains the stash. Without the fix the APDU is
        // lost and recv_response times out.
        let inbox = vec![ndt_from_dev(0, 0x340, &[0x07, 0xB0])];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let (apci, data) = l4.request(0x300, &[0x00]).await.unwrap();
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        // The receive sequence advanced exactly once.
        assert_eq!(l4.recv_seq, 1);
        drop(l4);
        // We ACKed the folded response (seq 0) even though no separate T_ACK came.
        let acks: Vec<u8> = bus
            .sent
            .iter()
            .filter_map(|f| match tpci::classify(f.tpci_octet()) {
                TpciKind::Ack(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(acks, vec![0], "the folded response NDT(0) was acknowledged");
    }

    #[tokio::test]
    async fn nak_retries_before_failing() {
        // A device that NAKs every attempt should be retransmitted
        // max_repetitions times before surfacing MgmtError::Nak.
        let mut inbox = Vec::new();
        for _ in 0..4 {
            inbox.push(control_from_dev(tpci::t_nak(0)));
        }
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast())
            .await
            .unwrap();
        let err = l4.send_data(0x300, &[0x00]).await.unwrap_err();
        assert!(matches!(err, MgmtError::Nak { .. }), "got {err:?}");
        // fast() has max_repetitions = 1: one initial send + one retransmit = 2
        // NDT sends before the NAK is fatal.
        let ndt_sends = bus
            .sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .count();
        assert_eq!(ndt_sends, 2, "one initial send plus one retransmit on NAK");
    }

    #[tokio::test]
    async fn sequence_wraps_around_at_fifteen() {
        // Send 17 acknowledged requests (send_data only, no response) to focus on
        // send-sequence wraparound. await_ack matches the seq we sent, so script
        // one T_ACK per expected seq: 0..15 then wrap to 0, 1.
        let mut inbox = Vec::new();
        for i in 0..17u8 {
            inbox.push(control_from_dev(tpci::t_ack(i & 0x0f)));
        }
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        for _ in 0..17 {
            l4.send_data(0x300, &[0x00]).await.unwrap();
        }
        // After 17 sends starting at 0, the next send seq is 17 mod 16 = 1.
        assert_eq!(l4.send_seq, 1);
    }
}
