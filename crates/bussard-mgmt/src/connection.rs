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

use bussard_bus::{BusError, BusLease, FrameSubscription};
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Tpci};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{BusConnection, TimestampedFrame, TransportError};
use tokio::time::{Instant, timeout};

use crate::error::{MgmtError, Result, SilenceKind};

/// The outcome of an `A_Authorize_Request` (issue #52 finding #1).
///
/// Authorization policy is **tolerate-absence, fail-on-denied**: a device that
/// grants full access proceeds, a device that grants only limited access is a
/// hard failure, and a device that does not implement authorize at all is
/// tolerated (older/simpler devices never needed a key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// The device granted access at `level` (always `0` here — the full-access
    /// level; any non-zero grant is [`AuthorizeOutcome::Denied`]).
    Granted {
        /// The granted access level (0 = full access).
        level: u8,
    },
    /// The device answered but granted a **non-zero** access level: the presented
    /// key does not unlock the access a management session needs. A real
    /// access-denied — callers turn this into [`MgmtError::AccessDenied`].
    Denied {
        /// The non-zero level the device granted.
        level: u8,
    },
    /// The device does not implement authorize: it did not answer, or answered
    /// with a non-authorize APCI. Tolerated — the session continues unauthorized.
    /// `detail` carries the raw evidence for a debug log.
    Unsupported {
        /// A human description of why the authorize was treated as unsupported
        /// (no answer, or the raw APCI + payload of a non-authorize reply).
        detail: String,
    },
}

impl AuthorizeOutcome {
    /// Whether the device implements authorize and granted full access.
    pub fn granted(&self) -> bool {
        matches!(self, AuthorizeOutcome::Granted { .. })
    }
}

/// The two operations the layer-4 state machine needs from whatever carries its
/// frames: an ACK-completed `send` and a `recv` of the next inbound frame.
///
/// This lets [`Layer4Connection`] drive **either** a borrowed
/// [`BusConnection`](bussard_transport::BusConnection) (the standalone /
/// scripted-test path) **or** a [`BusLease`] over the bus actor (the real path,
/// where group traffic and other subscribers keep flowing) with byte-identical
/// state-machine logic. Receivers deliver *every* inbound frame; the state
/// machine filters to its peer itself.
#[allow(async_fn_in_trait)]
pub trait L4Channel: Send {
    /// Sends a frame, completing when the transport confirms it.
    async fn send(&mut self, frame: CemiFrame) -> Result<()>;

    /// Receives the next inbound frame.
    async fn recv(&mut self) -> Result<TimestampedFrame>;
}

/// A borrowed [`BusConnection`] as an [`L4Channel`] — the standalone path used by
/// the scripted unit tests and the mock-device integration tests.
impl<C: BusConnection> L4Channel for &mut C {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        BusConnection::send(*self, frame)
            .await
            .map_err(MgmtError::Transport)
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        BusConnection::recv(*self)
            .await
            .map_err(MgmtError::Transport)
    }
}

/// A [`BusLease`] over the bus actor as an [`L4Channel`].
///
/// `send` goes through the handle (ACK-completed against the tunnel); `recv`
/// drains a frame subscription taken when the channel is built, so an L4 session
/// observes the bus without stealing frames from the monitor / MCP ring / other
/// subscribers (the core single-consumer fix). The subscription is live from
/// construction, so the peer's `T_ACK` cannot slip in before the first `recv`.
pub struct LeaseChannel {
    lease: BusLease,
    sub: FrameSubscription,
}

impl LeaseChannel {
    /// Builds a channel over `lease`, subscribing to inbound frames immediately.
    pub fn new(lease: BusLease) -> Self {
        let sub = lease.subscribe();
        LeaseChannel { lease, sub }
    }

    /// Consumes the channel and returns the underlying lease (releasing it on
    /// drop).
    pub fn into_lease(self) -> BusLease {
        self.lease
    }
}

fn map_bus_error(err: BusError) -> MgmtError {
    match err {
        BusError::Transport(e) => MgmtError::Transport(e),
        // A stale drop or a gone actor both mean the connection is unusable.
        BusError::Stale | BusError::ActorGone => MgmtError::Transport(TransportError::Closed),
    }
}

impl L4Channel for LeaseChannel {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        self.lease
            .send(frame)
            .await
            .map(|_| ())
            .map_err(map_bus_error)
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        match self.sub.recv().await {
            Some(inbound) => Ok(inbound.frame),
            None => Err(MgmtError::Transport(TransportError::Closed)),
        }
    }
}

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
pub struct Layer4Connection<Ch: L4Channel> {
    conn: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    timeouts: Timeouts,
    send_seq: u8,
    recv_seq: u8,
    /// The APCI of the most-recently-sent request. Used to recognise a stray
    /// `A_Memory_Response` **verify echo** (a verify-mode device answers every
    /// `A_Memory_Write` with one) that arrives when we did NOT send a memory
    /// read: it must be drained, not mistaken for the current request's answer.
    last_send_apci: u16,
    /// How many numbered data telegrams (NDTs) this session has sent and had
    /// acknowledged. Used to fold protocol-unit progress into a mid-session
    /// silence error (#50): a stall reported "after N numbered exchanges" is
    /// measurable in messages, not just in bytes. Counts every acknowledged
    /// `send_data`, so a request/response round-trip counts as one (the response
    /// NDT the *device* sends is not a telegram we sent).
    numbered_exchanges: u32,
    /// A response NDT the device folded in *before* its `T_ACK` (some stacks
    /// answer and acknowledge in one step). [`await_ack`](Self::await_ack)
    /// stashes its decoded `(apci, data)` here after ACKing it and advancing the
    /// receive sequence; [`recv_response`](Self::recv_response) drains this
    /// first so the folded answer is not lost.
    pending_response: Option<(u16, Vec<u8>)>,
    /// The device's advertised `PID_MAX_APDU_LENGTH` (NPDU octet budget), read
    /// once and cached for the life of this connection. `None` until
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) runs; once negotiated it
    /// scales the memory-write/read and property-read chunk sizes (issue #58).
    /// A device that does not expose the property leaves this `None`, and the
    /// chunk accessors fall back to the conservative standard-frame caps.
    max_apdu: Option<u16>,
    /// Set once the peer disconnects or a protocol error occurs, so a stale
    /// `disconnect()` is a no-op.
    closed: bool,
}

impl<Ch: L4Channel> Layer4Connection<Ch> {
    /// Opens a connection to `target`, sending `T_Connect`.
    ///
    /// `conn` is the frame channel — a borrowed
    /// [`BusConnection`](bussard_transport::BusConnection) or a
    /// [`LeaseChannel`]. `source` is the individual address the tool presents as.
    /// The connection is established optimistically; the first `send_data` that
    /// times out without any `T_ACK` surfaces the device as absent.
    pub async fn connect(
        conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
    ) -> Result<Layer4Connection<Ch>> {
        Self::connect_with(conn, target, source, Timeouts::default()).await
    }

    /// Like [`connect`](Self::connect) but with an explicit timeout budget.
    pub async fn connect_with(
        mut conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
        timeouts: Timeouts,
    ) -> Result<Layer4Connection<Ch>> {
        let frame = CemiFrame::t_control(target, source, tpci::T_CONNECT);
        conn.send(frame).await?;
        Ok(Layer4Connection {
            conn,
            target,
            source,
            timeouts,
            send_seq: 0,
            recv_seq: 0,
            last_send_apci: 0,
            numbered_exchanges: 0,
            pending_response: None,
            max_apdu: None,
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
        self.last_send_apci = apci;
        let seq = self.send_seq;
        let tpci_octet = tpci::ndt(seq);
        let frame = CemiFrame::t_data_connected(self.target, self.source, tpci_octet, apci, data);

        let mut attempt = 0;
        loop {
            self.conn.send(frame.clone()).await?;
            match self.await_ack(seq).await {
                AckOutcome::Acked => {
                    self.send_seq = (self.send_seq + 1) & 0x0f;
                    self.numbered_exchanges = self.numbered_exchanges.saturating_add(1);
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
                    return Err(self.silence_error(SilenceKind::Disconnected));
                }
                AckOutcome::Timeout => {
                    if attempt >= self.timeouts.max_repetitions {
                        // The very first send with no reaction at all means the
                        // device is absent; after that, treat the silence as a
                        // dead connection to a device that stopped answering.
                        self.closed = true;
                        return Err(self.silence_error(SilenceKind::NoResponse));
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// Discards any stashed folded response.
    ///
    /// A memory write has no real application response — only the `T_ACK`, and, on
    /// a **verify-mode** device (KNX Virtual and some System B stacks), an
    /// unsolicited `A_Memory_Response` echoing the stored octets. [`await_ack`]
    /// folds that echo in as a pending response; left there, it would satisfy the
    /// NEXT request's [`recv_response`](Self::recv_response) (e.g. a following
    /// `A_PropertyValue_Read`) with the wrong APDU. A write-only caller calls this
    /// right after the write so the echo is dropped rather than mis-correlated.
    pub fn discard_pending_response(&mut self) {
        self.pending_response = None;
    }

    /// Whether `apci` is a stray `A_Memory_Response` **verify echo**: a memory
    /// response arriving when the last request we sent was NOT a memory read.
    ///
    /// A verify-mode device answers every `A_Memory_Write` with such an echo. It
    /// is not a response to any request, so it must be drained (ACKed and
    /// dropped) rather than returned as the current operation's answer — otherwise
    /// a following `A_PropertyValue_*` gets the wrong APDU ("malformed response"),
    /// or, if folded in during a later write's `T_ACK` wait, it is mistaken for
    /// that write's completion and desyncs the sequence.
    fn is_stale_memory_echo(&self, apci: u16) -> bool {
        (apci & crate::apci::APCI_SELECTOR_MASK) == crate::apci::A_MEMORY_RESPONSE
            && (self.last_send_apci & crate::apci::APCI_SELECTOR_MASK) != crate::apci::A_MEMORY_READ
    }

    /// Sends a management request as a numbered data telegram **without** waiting
    /// for the device's `T_ACK`.
    ///
    /// A device restart (`A_Restart`) is fire-and-forget: the device reboots on
    /// receipt and drops the L4 link immediately, so it never sends the `T_ACK`.
    /// [`send_data`](Self::send_data) would retransmit and eventually report the
    /// device absent; this sends the telegram once and returns. The caller waits
    /// out the reboot and re-establishes the connection.
    pub async fn send_data_unacked(&mut self, apci: u16, data: &[u8]) -> Result<()> {
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        self.last_send_apci = apci;
        let seq = self.send_seq;
        let tpci_octet = tpci::ndt(seq);
        let frame = CemiFrame::t_data_connected(self.target, self.source, tpci_octet, apci, data);
        self.conn.send(frame).await?;
        self.send_seq = (self.send_seq + 1) & 0x0f;
        self.numbered_exchanges = self.numbered_exchanges.saturating_add(1);
        Ok(())
    }

    /// Waits for the device's response telegram (an incoming NDT), acknowledges
    /// it, and returns its decoded APDU.
    ///
    /// Frames unrelated to this connection (group traffic, telegrams from other
    /// sources) are skipped. A wrong-sequence NDT is acknowledged with
    /// `expected - 1` and dropped. Times out as [`MgmtError::NoResponse`].
    pub async fn recv_response(&mut self) -> Result<(u16, Vec<u8>)> {
        // A folded-ACK response that arrived while we were awaiting the T_ACK has
        // already been acknowledged and sequenced; hand it back first — unless it
        // is a stray verify-mode memory echo, which is dropped so the real
        // response is awaited below.
        if let Some(pending) = self.pending_response.take() {
            if !self.is_stale_memory_echo(pending.0) {
                return Ok(pending);
            }
        }
        if self.closed {
            return Err(self.silence_error(SilenceKind::Disconnected));
        }
        let deadline = Instant::now() + self.timeouts.response_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.closed = true;
                return Err(self.silence_error(SilenceKind::NoResponse));
            }
            let stamped = match timeout(remaining, self.conn.recv()).await {
                Ok(Ok(stamped)) => stamped,
                Ok(Err(err)) => return Err(self.map_recv_error(err)),
                Err(_elapsed) => {
                    self.closed = true;
                    return Err(self.silence_error(SilenceKind::NoResponse));
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
                    return Err(self.silence_error(SilenceKind::Disconnected));
                }
                TpciKind::NumberedData(seq) => {
                    if seq == self.recv_seq {
                        // Expected sequence: ACK and (unless it is a stray
                        // verify-mode memory echo) deliver.
                        self.send_control(tpci::t_ack(seq)).await?;
                        self.recv_seq = (self.recv_seq + 1) & 0x0f;
                        let (apci, data) = extract_apdu(&frame);
                        if self.is_stale_memory_echo(apci) {
                            continue;
                        }
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

    /// Presents an access `key` with `A_Authorize_Request` and returns the
    /// authorization outcome (issue #52 finding #1).
    ///
    /// A connection-oriented management session on a device that expects
    /// authorization must present a key before any configuration read/write; ETS
    /// does this as the first operation after the descriptor read. This sends the
    /// request (payload `[0x00, key_be…]`, see
    /// [`encode_authorize_request`](crate::apci::encode_authorize_request)),
    /// awaits the response, validates the response APCI is
    /// [`A_AUTHORIZE_RESPONSE`](crate::apci::A_AUTHORIZE_RESPONSE), and returns
    /// the granted level.
    ///
    /// The policy is **tolerate-absence, fail-on-denied** (see
    /// [`AuthorizeOutcome`]):
    /// - a level-0 grant → [`AuthorizeOutcome::Granted`];
    /// - a non-zero level → [`AuthorizeOutcome::Denied`] (a real access problem,
    ///   surfaced by callers as [`MgmtError::AccessDenied`]);
    /// - a device that does not answer at all, or answers with a non-authorize
    ///   APCI (older/simpler devices that do not implement authorize) →
    ///   [`AuthorizeOutcome::Unsupported`], carrying the raw response detail for a
    ///   debug log. A `NoResponse` from the device (it never answered) is likewise
    ///   folded to `Unsupported` rather than failing — an unkeyed device that does
    ///   not implement authorize is expected and harmless.
    ///
    /// A **transport/connection** failure (the connection itself dropped, not the
    /// device declining to answer) still surfaces as an `Err`, since that is not
    /// an authorize outcome but a dead session.
    pub async fn authorize(&mut self, key: u32) -> Result<AuthorizeOutcome> {
        let payload = crate::apci::encode_authorize_request(key);
        let (resp_apci, data) = match self
            .request(crate::apci::A_AUTHORIZE_REQUEST, &payload)
            .await
        {
            Ok(pair) => pair,
            // The device never answered the authorize (no response NDT). This is
            // the expected shape for a device that does not implement authorize;
            // tolerate it. A genuine transport/disconnect death is surfaced.
            Err(MgmtError::NoResponse { .. })
            | Err(MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }) => {
                return Ok(AuthorizeOutcome::Unsupported {
                    detail: "device did not answer A_Authorize_Request".to_string(),
                });
            }
            Err(other) => return Err(other),
        };

        if resp_apci != crate::apci::A_AUTHORIZE_RESPONSE {
            // Answered with something that is not an authorize response: the
            // device does not implement authorize. Tolerate, capturing the raw
            // evidence for a debug log.
            return Ok(AuthorizeOutcome::Unsupported {
                detail: crate::error::raw_response_detail(resp_apci, &data),
            });
        }

        match crate::apci::decode_authorize_response(&data) {
            Some(0) => Ok(AuthorizeOutcome::Granted { level: 0 }),
            Some(level) => Ok(AuthorizeOutcome::Denied { level }),
            None => Ok(AuthorizeOutcome::Unsupported {
                detail: format!(
                    "A_Authorize_Response carried no level octet ({})",
                    crate::error::raw_response_detail(resp_apci, &data)
                ),
            }),
        }
    }

    /// Presents `key` with [`authorize`](Self::authorize) and applies the
    /// **tolerate-absence, fail-on-denied** policy directly: a granted (level-0)
    /// or unsupported authorize returns `Ok`, a non-zero level returns
    /// [`MgmtError::AccessDenied`]. The `Unsupported` case is logged at debug.
    ///
    /// This is the one-call helper the management connect paths use so every
    /// session authorizes with a uniform policy. It returns the
    /// [`AuthorizeOutcome`] on success so a caller can still log which case
    /// occurred (granted vs tolerated-absence).
    pub async fn authorize_or_fail(&mut self, key: u32) -> Result<AuthorizeOutcome> {
        let outcome = self.authorize(key).await?;
        match &outcome {
            AuthorizeOutcome::Granted { .. } => {}
            AuthorizeOutcome::Denied { level } => {
                return Err(MgmtError::AccessDenied {
                    address: self.target,
                    level: *level,
                });
            }
            AuthorizeOutcome::Unsupported { detail } => {
                tracing::debug!(
                    target = %self.target,
                    detail = %detail,
                    "device does not implement A_Authorize; continuing unauthorized (older/simpler device)"
                );
            }
        }
        Ok(outcome)
    }

    /// Tears the connection down with `T_Disconnect` (best-effort).
    pub async fn disconnect(mut self) -> Result<()> {
        self.close().await
    }

    /// The target device address.
    pub fn target(&self) -> IndividualAddress {
        self.target
    }

    /// How many numbered data telegrams (NDTs) this connection has sent and had
    /// acknowledged since it was opened.
    ///
    /// This is the per-connection exchange budget the windowed-download engine
    /// meters against: KNX Virtual drops the L4 connection after a varying number
    /// of exchanges, so a download chunked to cycle the connection before the
    /// budget is exhausted survives a fragile peer (issue #52). The counter
    /// resets to 0 on every fresh [`connect`](Self::connect) (sequence numbers
    /// reset on `T_Connect`), so each window starts a fresh count. A
    /// request/response round-trip counts as one (only the telegram *we* send is
    /// counted).
    pub fn numbered_exchanges(&self) -> u32 {
        self.numbered_exchanges
    }

    /// Reads and caches the device's `PID_MAX_APDU_LENGTH` once, returning the
    /// negotiated NPDU-octet budget used to scale memory and property chunks.
    ///
    /// The first call issues an `A_PropertyValue_Read` for
    /// [`PID_MAX_APDU_LENGTH`](crate::apci::PID_MAX_APDU_LENGTH) on the device
    /// object; later calls return the cached value without a round-trip. If the
    /// property is absent or unreadable (an older/simpler device, a short answer),
    /// the connection stays conservative: the accessors fall back to the
    /// standard-frame caps, and this returns `None`. A **connection/transport**
    /// death still propagates as `Err` (that is a dead session, not a missing
    /// property).
    ///
    /// Scaling to the reported value is a correctness matter, not just speed: a
    /// device advertising a max APDU of 15 must receive ≤12-octet memory chunks in
    /// **standard** frames, which a 63-octet chunk (an extended frame) would
    /// violate (issue #58).
    pub async fn negotiate_max_apdu(&mut self) -> Result<Option<u16>> {
        if let Some(v) = self.max_apdu {
            return Ok(Some(v));
        }
        let resp = match crate::connection::property_request(
            self,
            crate::apci::DEVICE_OBJECT_INDEX,
            crate::apci::PID_MAX_APDU_LENGTH,
            1,
            1,
        )
        .await
        {
            Ok(resp) => resp,
            // A device-level absence (no such property, a malformed/short answer,
            // or the device not answering the read) is tolerated: keep the
            // conservative defaults. A genuine transport death propagates.
            Err(MgmtError::MalformedResponse { .. })
            | Err(MgmtError::NoResponse { .. })
            | Err(MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }) => {
                tracing::debug!(
                    target = %self.target,
                    "PID_MAX_APDU_LENGTH not readable; using conservative chunk sizes"
                );
                return Ok(None);
            }
            Err(other) => return Err(other),
        };
        // The value is a big-endian octet count (1 or 2 octets on real devices).
        let value = match resp.data.as_slice() {
            [] => None,
            [b] => Some(u16::from(*b)),
            [hi, lo, ..] => Some(u16::from_be_bytes([*hi, *lo])),
        };
        match value {
            Some(v) if v != 0 => {
                self.max_apdu = Some(v);
                tracing::debug!(
                    target = %self.target,
                    max_apdu = v,
                    "negotiated PID_MAX_APDU_LENGTH; scaling chunk sizes"
                );
                Ok(Some(v))
            }
            _ => {
                tracing::debug!(
                    target = %self.target,
                    "PID_MAX_APDU_LENGTH read empty/zero; using conservative chunk sizes"
                );
                Ok(None)
            }
        }
    }

    /// The negotiated `A_Memory_Write`/`A_Memory_Read` data-octet cap for this
    /// connection: scaled from `PID_MAX_APDU_LENGTH` when
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) found it, else the
    /// conservative [`CONSERVATIVE_MEMORY_CHUNK`](crate::apci::CONSERVATIVE_MEMORY_CHUNK)
    /// standard-frame floor.
    pub fn max_memory_chunk(&self) -> u8 {
        match self.max_apdu {
            Some(v) => crate::apci::memory_chunk_for_apdu(v),
            None => crate::apci::CONSERVATIVE_MEMORY_CHUNK,
        }
    }

    /// The negotiated `A_PropertyValue_Read` value-octet cap for this connection:
    /// scaled from `PID_MAX_APDU_LENGTH` when negotiated, else the conservative
    /// [`CONSERVATIVE_PROPERTY_READ_OCTETS`](crate::apci::CONSERVATIVE_PROPERTY_READ_OCTETS).
    pub fn max_property_read_octets(&self) -> u8 {
        match self.max_apdu {
            Some(v) => crate::apci::property_read_octets_for_apdu(v),
            None => crate::apci::CONSERVATIVE_PROPERTY_READ_OCTETS,
        }
    }

    /// Seeds the cached `PID_MAX_APDU_LENGTH` without a round-trip.
    ///
    /// `PID_MAX_APDU_LENGTH` is device-stable, so a caller that negotiated it on
    /// an earlier connection to the same device (e.g. the flash session across L4
    /// cycles) can reapply it to a fresh connection with this setter instead of
    /// spending another numbered exchange re-reading it — which matters when the
    /// per-connection exchange budget is tight (issue #58). A `None`/zero value is
    /// ignored so the conservative defaults stay in effect.
    pub fn set_max_apdu(&mut self, max_apdu: Option<u16>) {
        if let Some(v) = max_apdu {
            if v != 0 {
                self.max_apdu = Some(v);
            }
        }
    }

    /// The cached `PID_MAX_APDU_LENGTH`, if it has been negotiated or seeded.
    pub fn max_apdu(&self) -> Option<u16> {
        self.max_apdu
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
                TpciKind::NumberedData(nseq) if nseq == self.recv_seq => {
                    // The device answered before we saw its ACK (some stacks fold
                    // the ACK into the response). Only a NDT at the *expected*
                    // receive sequence is causal: it is the device's fresh answer,
                    // which implicitly confirms our request landed. Acknowledge the
                    // data so it does not retransmit, stash the APDU as the pending
                    // response and advance the receive sequence, and treat our send
                    // as acknowledged. Without stashing, the folded answer would be
                    // dropped and `recv_response` would wait forever for a second
                    // NDT that never comes (permanent desync).
                    let _ = self.send_control(tpci::t_ack(nseq)).await;
                    self.recv_seq = (self.recv_seq + 1) & 0x0f;
                    let (apci, data) = extract_apdu(&frame);
                    if self.is_stale_memory_echo(apci) {
                        // A verify-mode write echo (from THIS or a prior write),
                        // not the current request's answer: drained (ACKed above),
                        // keep waiting for the real T_ACK rather than falsely
                        // treating this as the send's completion (which desyncs).
                        continue;
                    }
                    self.pending_response = Some((apci, data));
                    return AckOutcome::Acked;
                }
                TpciKind::NumberedData(_) => {
                    // A duplicate / out-of-window folded NDT: this is a
                    // *re-delivery* of a previous response (our earlier T_ACK for it
                    // was lost, so the device retransmitted), NOT confirmation that
                    // our current request landed (#58). ACK expected-1 to quiet the
                    // retransmit, then KEEP WAITING for our real T_ACK — returning
                    // `Acked` here would falsely advance our send sequence off a
                    // stale frame and desync the connection.
                    let ack_seq = self.recv_seq.wrapping_sub(1) & 0x0f;
                    let _ = self.send_control(tpci::t_ack(ack_seq)).await;
                    continue;
                }
                _ => continue,
            }
        }
    }

    fn map_recv_error(&mut self, err: MgmtError) -> MgmtError {
        self.closed = true;
        match err {
            MgmtError::Transport(TransportError::Disconnected(_))
            | MgmtError::Transport(TransportError::Closed) => {
                self.silence_error(SilenceKind::Disconnected)
            }
            other => other,
        }
    }

    /// Builds the silence error for a mid-session `NoResponse`/`Disconnected`.
    ///
    /// After at least one numbered exchange has completed on this connection, the
    /// silence carries the exchange count and sequence-wrap count as
    /// [`MgmtError::MidSessionSilence`], so a stall is measured in protocol units
    /// (#50). Before any exchange (the very first send drawing no reaction), it
    /// surfaces the bare [`MgmtError::NoResponse`]/[`MgmtError::Disconnected`] —
    /// nothing had happened yet to count, and scanning an absent address must keep
    /// seeing the plain "device absent" it matches on.
    fn silence_error(&self, kind: SilenceKind) -> MgmtError {
        if self.numbered_exchanges == 0 {
            return match kind {
                SilenceKind::NoResponse => MgmtError::NoResponse {
                    address: self.target,
                },
                SilenceKind::Disconnected => MgmtError::Disconnected {
                    address: self.target,
                },
            };
        }
        MgmtError::MidSessionSilence {
            address: self.target,
            kind,
            exchanges: self.numbered_exchanges,
            wraps: self.numbered_exchanges / 16,
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

/// Sends an `A_PropertyValue_Read` and returns the decoded
/// [`PropertyValueResponse`](crate::apci::PropertyValueResponse), validating the
/// response service and the 4-octet header.
///
/// This is the shared request/validate/decode seam every property read in the
/// crate (`device.rs`, `tables.rs`, and the five load-side reads) collapses onto:
/// it encodes the read, sends it, checks the answer is an
/// `A_PropertyValue_Response`, and decodes the header. Callers apply their own
/// `count == 0` / short-data policy to the returned struct, and map the
/// [`MgmtError`] into their own error type via `#[from]`.
pub(crate) async fn property_request<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    start: u16,
    count: u8,
) -> Result<crate::apci::PropertyValueResponse> {
    let payload = crate::apci::encode_property_value_read(object_index, property_id, count, start);
    let (resp_apci, data) = l4
        .request(crate::apci::A_PROPERTY_VALUE_READ, &payload)
        .await?;
    decode_property_response(l4.target(), resp_apci, &data)
}

/// Sends an `A_PropertyValue_Write` and returns the decoded response the device
/// echoes back, validating the response service and the 4-octet header.
///
/// The write twin of [`property_request`]: the shared encode/send/validate/decode
/// seam for every property write in the crate. Callers compare the echoed
/// [`PropertyValueResponse::data`](crate::apci::PropertyValueResponse) against
/// what they wrote (the KNX application layer echoes the *stored* value).
pub(crate) async fn property_write_request<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    count: u8,
    start: u16,
    value: &[u8],
) -> Result<crate::apci::PropertyValueResponse> {
    let payload =
        crate::apci::encode_property_value_write(object_index, property_id, count, start, value);
    let (resp_apci, data) = l4
        .request(crate::apci::A_PROPERTY_VALUE_WRITE, &payload)
        .await?;
    decode_property_response(l4.target(), resp_apci, &data)
}

/// Validates that `(resp_apci, data)` is a well-formed `A_PropertyValue_Response`
/// and decodes it, shared by [`property_request`] and [`property_write_request`].
fn decode_property_response(
    address: IndividualAddress,
    resp_apci: u16,
    data: &[u8],
) -> Result<crate::apci::PropertyValueResponse> {
    if resp_apci != crate::apci::A_PROPERTY_VALUE_RESPONSE {
        return Err(MgmtError::MalformedResponse {
            address,
            reason: format!(
                "expected A_PropertyValue_Response ({})",
                crate::error::raw_response_detail(resp_apci, data)
            ),
        });
    }
    crate::apci::decode_property_value_response(data).ok_or_else(|| MgmtError::MalformedResponse {
        address,
        reason: format!(
            "property value response too short ({})",
            crate::error::raw_response_detail(resp_apci, data)
        ),
    })
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
    async fn folded_wrong_seq_ndt_is_not_our_ack() {
        // #58: while awaiting the T_ACK for our seq-0 request, a WRONG-sequence
        // NDT arrives first — a re-delivery of a previous response (our earlier
        // T_ACK for it was lost, so the device retransmitted it). It is NOT our
        // ack: await_ack must ACK it with expected-1 and KEEP WAITING. The real
        // T_ACK(0) then arrives, followed by the fresh response NDT(0).
        let inbox = vec![
            // Stale duplicate at the wrong seq (recv_seq is 0, so 5 is off-window).
            ndt_from_dev(5, 0x340, &[0xAA]),
            // Our real T_ACK arrives only now.
            control_from_dev(tpci::t_ack(0)),
            // Then the fresh response for this request.
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast())
            .await
            .unwrap();
        let (apci, data) = l4.request(0x300, &[0x00]).await.unwrap();
        // The stale duplicate was not mistaken for the response; the real answer
        // was delivered.
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        // recv_seq advanced exactly once (only the real NDT(0) was delivered; the
        // stale wrong-seq frame did not advance it).
        assert_eq!(l4.recv_seq, 1);
        // The send sequence advanced exactly once: the request was acknowledged by
        // the real T_ACK(0), not by the stale duplicate.
        assert_eq!(l4.send_seq, 1);
        drop(l4);
        // ACKs sent: expected-1 (15) for the stale duplicate while awaiting, then 0
        // for the delivered real response.
        let acks: Vec<u8> = bus
            .sent
            .iter()
            .filter_map(|f| match tpci::classify(f.tpci_octet()) {
                TpciKind::Ack(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(
            acks,
            vec![15, 0],
            "stale duplicate ACKed with expected-1, then the real response with 0"
        );
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

    #[tokio::test]
    async fn recv_sequence_wraps_around_at_fifteen() {
        // Drive 18 request/response round-trips so the RECEIVE sequence wraps past
        // 15 back through 0 and 1. Each device response NDT carries the expected
        // receive sequence; the tool must ACK it, deliver it, and advance recv_seq
        // mod 16 correctly across the wrap. Script, per round-trip: T_ACK(send_seq)
        // then the response NDT at the matching recv_seq.
        let mut inbox = Vec::new();
        for i in 0..18u8 {
            inbox.push(control_from_dev(tpci::t_ack(i & 0x0f)));
            inbox.push(ndt_from_dev(i & 0x0f, 0x340, &[0x07, 0xB0]));
        }
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        for _ in 0..18 {
            let (apci, _data) = l4.request(0x300, &[0x00]).await.unwrap();
            assert_eq!(apci, 0x340);
        }
        // After 18 delivered responses starting at 0, recv_seq is 18 mod 16 = 2,
        // and send_seq likewise (18 sends).
        assert_eq!(l4.recv_seq, 2);
        assert_eq!(l4.send_seq, 2);
        // Every response NDT was acknowledged at its own (wrapping) sequence.
        let acks: Vec<u8> = bus
            .sent
            .iter()
            .filter_map(|f| match tpci::classify(f.tpci_octet()) {
                TpciKind::Ack(s) => Some(s),
                _ => None,
            })
            .collect();
        let expected: Vec<u8> = (0..18u8).map(|i| i & 0x0f).collect();
        assert_eq!(acks, expected, "each response ACKed at its wrapping seq");
    }

    #[tokio::test]
    async fn device_retransmit_across_wrap_is_reacked_not_redelivered() {
        // Near a wrap boundary: the device re-delivers a response whose T_ACK it
        // missed (a retransmit at the previous, off-window sequence). recv_response
        // must ACK it with expected-1 and drop it, then deliver the fresh response
        // at the expected sequence — without double-delivering. Set recv_seq to 15
        // by walking there, then script a stale NDT(14) before the real NDT(15).
        let mut inbox = Vec::new();
        // Walk recv_seq from 0 to 15 via 15 round-trips.
        for i in 0..15u8 {
            inbox.push(control_from_dev(tpci::t_ack(i)));
            inbox.push(ndt_from_dev(i, 0x340, &[i]));
        }
        // 16th round-trip: ACK(15), then a STALE retransmit at seq 14 (off-window),
        // then the fresh response at the expected seq 15.
        inbox.push(control_from_dev(tpci::t_ack(15)));
        inbox.push(ndt_from_dev(14, 0x340, &[0xAA])); // stale duplicate
        inbox.push(ndt_from_dev(15, 0x340, &[0xBB])); // the real answer
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        for _ in 0..15 {
            l4.request(0x300, &[0x00]).await.unwrap();
        }
        assert_eq!(l4.recv_seq, 15);
        // The 16th delivers the FRESH answer (0xBB), not the stale duplicate.
        let (_apci, data) = l4.request(0x300, &[0x00]).await.unwrap();
        assert_eq!(
            data,
            vec![0xBB],
            "the stale retransmit must not be delivered"
        );
        assert_eq!(
            l4.recv_seq, 0,
            "recv_seq wrapped 15 -> 0 after the real NDT"
        );
    }

    #[tokio::test]
    async fn authorize_free_access_grants_level_zero() {
        // Script: ACK(0) for our authorize request, then A_Authorize_Response(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x00]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let outcome = l4.authorize(crate::apci::FREE_ACCESS_KEY).await.unwrap();
        assert_eq!(outcome, AuthorizeOutcome::Granted { level: 0 });
        // The tool sent the exact captured wire form [00 FF FF FF FF].
        let sent_ndt = bus
            .sent
            .iter()
            .find_map(|f| match (&f.tpci, &f.apdu) {
                (Tpci::Other(_), Apdu::Other { apci, data })
                    if *apci == crate::apci::A_AUTHORIZE_REQUEST =>
                {
                    Some(data.clone())
                }
                _ => None,
            })
            .expect("an A_Authorize_Request must have been sent");
        assert_eq!(sent_ndt, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[tokio::test]
    async fn authorize_nonzero_level_is_denied() {
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x03]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let outcome = l4.authorize(0x0011_2233).await.unwrap();
        assert_eq!(outcome, AuthorizeOutcome::Denied { level: 3 });
        // authorize_or_fail turns that into an explicit AccessDenied error.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x03]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let err = l4.authorize_or_fail(0x0011_2233).await.unwrap_err();
        assert!(
            matches!(err, MgmtError::AccessDenied { level: 3, .. }),
            "got {err:?}"
        );
        assert!(
            err.device_present(),
            "access-denied means the device is present"
        );
    }

    #[tokio::test]
    async fn authorize_non_authorize_reply_is_unsupported_and_tolerated() {
        // A device that answers with a non-authorize APCI (does not implement the
        // service): the outcome is Unsupported and authorize_or_fail returns Ok
        // (tolerate-and-continue), leaving the connection usable.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool())
            .await
            .unwrap();
        let outcome = l4
            .authorize_or_fail(crate::apci::FREE_ACCESS_KEY)
            .await
            .unwrap();
        assert!(
            matches!(outcome, AuthorizeOutcome::Unsupported { .. }),
            "got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn authorize_no_response_is_unsupported() {
        // The device ACKs but never answers (empty inbox after the ACK forces the
        // response timeout): a NoResponse folds to Unsupported (tolerated), not an
        // error — an unkeyed device that does not implement authorize is expected.
        let inbox = vec![control_from_dev(tpci::t_ack(0))];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast())
            .await
            .unwrap();
        let outcome = l4.authorize(crate::apci::FREE_ACCESS_KEY).await.unwrap();
        assert!(
            matches!(outcome, AuthorizeOutcome::Unsupported { .. }),
            "got {outcome:?}"
        );
    }
}
