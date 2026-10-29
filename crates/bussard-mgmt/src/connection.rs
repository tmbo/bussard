//! The connection-oriented transport (layer-4) state machine.
//!
//! This drives the client side of a KNX transport-layer connection over any
//! [`BusConnection`]: it opens a connection to one individual address with
//! `T_Connect`, sends numbered data telegrams (NDT) and waits for the device's
//! `T_ACK`, receives the device's response NDTs and acknowledges them, and tears
//! the connection down with `T_Disconnect`.
//!
//! # State machine (Style 3)
//!
//! The events and actions follow the Style 3 table of 03_03_04 Transport Layer
//! §5.4.3 as amended by AN210 (TL Style 3 Rework, §2.2.1), the only style the
//! transport-layer test specification (08_03_04 §3) still admits:
//!
//! - **Connect** (E25, A12): send `T_Connect`, sequence counters to 0. The
//!   connection is used optimistically; a negative `L_Data.con` for the
//!   `T_Connect` closes it at once (E20, A5: [`MgmtError::NotConfirmed`]).
//! - **Send NDT** (E15, A7): send `T_Data_Connected` at `SeqNoSend` and wait
//!   for its `T_ACK` within the acknowledge timeout ([`ACK_TIMEOUT`]).
//!   - `T_ACK` at `SeqNoSend` (E08, A8): done, `SeqNoSend` advances.
//!   - `T_ACK` at another sequence (E09): ignored (A0, the AN210 amendment;
//!     the unamended table closed the connection here).
//!   - `T_NAK` at `SeqNoSend` (E12, E13): repeat while fewer than
//!     [`MAX_REPETITIONS`] repetitions went out (A9), otherwise close (A6).
//!   - `T_NAK` at another sequence (E11): ignored (A0).
//!   - acknowledge timeout (E17, E18): repeat up to [`MAX_REPETITIONS`] times
//!     (A9), then close (A6).
//! - **Receive NDT**: at `SeqNoRcv` (E04, A2) acknowledge, deliver, advance; at
//!   `SeqNoRcv - 1` (E05, A3) acknowledge it again without delivering (the
//!   peer missed our `T_ACK`); at any other sequence (E06, A4) answer `T_NAK`
//!   with the received sequence and drop it.
//! - **Peer `T_Disconnect`** (E02, A5): the connection is closed; nothing is
//!   sent back.
//! - **Close** (A6, E26/A14): every path that gives up on a connection the peer
//!   holds open (acknowledge timeout or `T_NAK` exhausted, a broken channel)
//!   sends one best-effort `T_Disconnect`, so the device does not sit in
//!   OPEN_IDLE until its connection timeout and ignore the next `T_Connect`
//!   from this address (E00, A0). Before the peer has shown itself the
//!   connection is still CONNECTING in the table's terms, where the
//!   acknowledge timeout is A0, so an absent address costs no extra frame.
//!
//! Both sides run a 6 s connection timeout ([`CONNECTION_TIMEOUT`], 03_03_04
//! §5 local variables, E16): a device closes a connection that saw no traffic
//! for 6 s. No idle heartbeat is sent. A request after a longer pause first
//! reconnects (issue #575): the device's `T_Disconnect` from the timeout is
//! drained, a `T_Disconnect` (for a device whose timer has not fired yet) and
//! a fresh `T_Connect` go out, both sequence numbers restart at 0, and an
//! `A_Authorize_Request` presented on the connection is presented again, so
//! the access level the caller established carries over. A Data Secure
//! session keeps its sync: the sequence numbers it protects are per address,
//! not per transport connection.
//!
//! The control frames go out at system priority (§5.3 A2-A4, A6); the numbered
//! data telegrams at [`Layer4Connection::data_priority`].
//!
//! The wire behaviour follows the published KNX transport-layer procedure
//! (EN 50090 / the KNX standard). No GPL sources were consulted.

use std::time::Duration;

use bussard_bus::{BusError, BusLease, FrameSubscription};
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Priority, Tpci};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{BusConnection, TimestampedFrame, TransportError};
use tokio::time::{Instant, timeout};

use crate::error::{MgmtError, Result, SilenceKind};

/// The outcome of an `A_Authorize_Request` (issue #52 finding #1).
///
/// Authorization policy is **tolerate-absence, fail-on-denied**: a device that
/// grants an access level proceeds, a device that sets the minimum level (its
/// answer to an invalid key) is a hard failure, and a device that does not
/// implement authorize at all is tolerated (older/simpler devices never needed
/// a key).
///
/// Levels run from 0 (maximum access) to 3 or 15 (minimum access), and the
/// free key `FFFFFFFFh` maps to the highest level a device leaves unprotected,
/// which can be above 0 (03_03_07 §3.5.7). A caller that needs a specific
/// level compares with [`AuthorizeOutcome::grants`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// The device granted access at `level` (0 = full access; any level below
    /// the minimum).
    Granted {
        /// The granted access level (0 = full access).
        level: u8,
    },
    /// The device answered with the minimum access level, 3 or 15, which is
    /// what it sets for an invalid key (03_03_07 §3.5.7): the presented key
    /// unlocks nothing. Callers turn this into [`MgmtError::AccessDenied`].
    Denied {
        /// The minimum level the device set.
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
    /// Whether the device implements authorize and granted an access level.
    pub fn granted(&self) -> bool {
        matches!(self, AuthorizeOutcome::Granted { .. })
    }

    /// The access level the device answered with, granted or denied.
    pub fn level(&self) -> Option<u8> {
        match self {
            AuthorizeOutcome::Granted { level } | AuthorizeOutcome::Denied { level } => {
                Some(*level)
            }
            AuthorizeOutcome::Unsupported { .. } => None,
        }
    }

    /// Whether the granted level allows an access that requires `required`
    /// (a lower number is more access, 03_03_07 §3.5.7).
    pub fn grants(&self, required: u8) -> bool {
        matches!(self, AuthorizeOutcome::Granted { level } if *level <= required)
    }
}

/// Whether `level` is a minimum access level: 3 on a device with four levels,
/// 15 on one with sixteen (03_03_07 §3.5.7). A device sets it for an invalid
/// key. A level above 15 is out of range and read the same way.
fn is_minimum_access_level(level: u8) -> bool {
    level == 3 || level >= 15
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

/// Folds a [`BusError`] into the management error type: a transport failure
/// passes through, a gone actor means the connection is unusable, and a stale
/// drop (the bus was reconnecting) is a timeout, which callers treat as a
/// recoverable link loss (issue #177).
pub(crate) fn map_bus_error(err: BusError) -> MgmtError {
    match err {
        BusError::Transport(e) => MgmtError::Transport(e),
        BusError::Stale => MgmtError::Transport(TransportError::Timeout(
            "a connected gateway (the bus is reconnecting)",
        )),
        BusError::ActorGone => MgmtError::Transport(TransportError::Closed),
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

/// The transport-layer connection timeout (03_03_04 §5, `connection_timeout_timer`):
/// a connection that sees no traffic for this long is closed by the device
/// (E16, A6). [`Layer4Connection::idle_beyond_connection_timeout`] tells a
/// caller that its peer has most likely done so.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(6);

/// How many queued frames [`Layer4Connection`] drains before an idle reconnect
/// (issue #575): the device's timeout `T_Disconnect` and whatever else the
/// line carried meanwhile. Bounded so a busy line cannot stall the reconnect.
const IDLE_DRAIN_FRAMES: usize = 64;

/// How long the drain before an idle reconnect waits for each further frame.
/// Every frame of interest was sent at least a connection timeout ago, so
/// this only has to outlast the gateway's delivery of one queued datagram.
const IDLE_DRAIN_WAIT: Duration = Duration::from_millis(20);

/// How long to wait for a device's response telegram (an incoming NDT) after
/// our request has been acknowledged, before concluding the device will not
/// answer.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// The per-attempt timeout of the pre-flight source-address probe
/// ([`Timeouts::probe`]). Short on purpose: the probe runs before every
/// connection-oriented device command, and a device sharing our address answers
/// in tens of milliseconds.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(600);

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
    /// Whether a negative `L_Data.con` for our first numbered telegram
    /// classifies the target as absent at once ([`MgmtError::NotConfirmed`])
    /// instead of waiting out `ack_timeout` and the repetitions (issue #45).
    ///
    /// Only a presence probe wants this: [`Timeouts::discovery`] sets it,
    /// every other budget leaves it `false`, so a programming session keeps
    /// its timeout-and-retry behaviour on a data telegram. It only acts before
    /// the first acknowledged exchange, and only when the interface reports
    /// confirmations at all: a gateway that never sends a negative con falls
    /// back to the ACK timeout automatically.
    ///
    /// A negative con for the `T_Connect` itself fails the connection on
    /// every budget (03_03_04 §5.4.3 E20, A5): the device never saw the
    /// connect, so it would ignore every data telegram that follows.
    pub absent_on_negative_confirmation: bool,
}

/// Environment variable that overrides [`ACK_TIMEOUT`] and [`RESPONSE_TIMEOUT`]
/// of the standard budget ([`Timeouts::default`]) and caps the S-A_Sync retry
/// backoff ([`SyncRetry`]) with a millisecond value. Set by the mock-device
/// integration tests so an unanswered request on loopback costs tens of
/// milliseconds instead of seconds; unset in normal use, where the KNX-standard
/// values apply. The repetition and attempt counts are unchanged.
pub const MGMT_TIMEOUT_MS_ENV: &str = "BUSSARD_MGMT_TIMEOUT_MS";

/// The [`MGMT_TIMEOUT_MS_ENV`] override, when set to a whole number.
fn mgmt_timeout_override() -> Option<Duration> {
    bussard_model::dotenv::var(MGMT_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
}

impl Default for Timeouts {
    /// The KNX-standard budget, or the [`MGMT_TIMEOUT_MS_ENV`] timeouts when
    /// that test knob is set.
    fn default() -> Self {
        let wait = mgmt_timeout_override();
        Timeouts {
            ack_timeout: wait.unwrap_or(ACK_TIMEOUT),
            max_repetitions: MAX_REPETITIONS,
            response_timeout: wait.unwrap_or(RESPONSE_TIMEOUT),
            absent_on_negative_confirmation: false,
        }
    }
}

impl Timeouts {
    /// A tight budget for discovery: a short per-attempt timeout with a single
    /// retry, so an absent address is ruled out in roughly `2 × ack_timeout`.
    /// Used by `bussard scan`.
    ///
    /// On an interface that reports negative `L_Data.con`s an absent address is
    /// ruled out by the first one instead, in tens of milliseconds
    /// ([`Timeouts::absent_on_negative_confirmation`], issue #45). The timeouts
    /// themselves are unchanged: they stay the fallback for gateways that send
    /// no negative confirmations and the window a present device answers in.
    pub fn discovery() -> Self {
        Timeouts {
            ack_timeout: Duration::from_millis(1500),
            max_repetitions: 1,
            response_timeout: Duration::from_millis(1500),
            absent_on_negative_confirmation: true,
        }
    }

    /// The budget for the pre-flight source-address probe
    /// ([`crate::probe::probe_own_address`]): one attempt, no repetitions, so a
    /// free address costs a single [`PROBE_TIMEOUT`] and every device command
    /// can afford to run it.
    ///
    /// A device that shares our address is on the same line and answers in tens
    /// of milliseconds, so the short budget does not weaken the check.
    pub fn probe() -> Self {
        Timeouts {
            ack_timeout: PROBE_TIMEOUT,
            max_repetitions: 0,
            response_timeout: PROBE_TIMEOUT,
            // The own-address probe must see a loop-back gateway's echoes, not
            // classify on confirmations; it keeps its single short window.
            absent_on_negative_confirmation: false,
        }
    }
}

/// How often an S-A_Sync_Req that the device T_ACKs but does not answer is
/// repeated on the same connection before the sync is declared unanswered
/// (issue #166).
///
/// A Data Secure device that has just rebooted can acknowledge frames at the
/// transport layer before its security layer is ready, so it drops the first
/// Sync_Req without an S-A_Sync_Res (live 1.1.12, 2026-09-24). Each attempt
/// waits the connection's `response_timeout` for the Sync_Res; between
/// attempts the connection sleeps a backoff that starts at `initial_backoff`
/// and doubles up to `max_backoff`. A plain connection never syncs, so this
/// policy has no effect on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRetry {
    /// Total Sync_Req attempts, including the first (at least 1).
    pub attempts: u32,
    /// The sleep before the second attempt.
    pub initial_backoff: Duration,
    /// The cap the doubling backoff never exceeds.
    pub max_backoff: Duration,
}

impl Default for SyncRetry {
    /// Three attempts, backing off 1 s then 2 s: the policy of every secured
    /// connection.
    /// [`MGMT_TIMEOUT_MS_ENV`] caps both backoff bounds when set.
    fn default() -> Self {
        SyncRetry {
            attempts: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: MAX_SYNC_BACKOFF,
        }
        .with_env_cap()
    }
}

/// The longest pause between two S-A_Sync_Req attempts (issue #575). An
/// unanswered attempt idles the connection for the response timeout (3 s)
/// and then the backoff; with at most 2 s the pause stays a second inside the
/// device's 6 s connection timeout ([`CONNECTION_TIMEOUT`], 03_03_04 §5,
/// E16), so the retry reaches the device on the connection it synced on.
/// The sync loop also bounds every backoff by the connection's own timeouts.
pub const MAX_SYNC_BACKOFF: Duration = Duration::from_secs(2);

/// The headroom the sync loop keeps below the connection timeout: the
/// response timeout plus the backoff never come closer to it than this.
const SYNC_IDLE_MARGIN: Duration = Duration::from_secs(1);

impl SyncRetry {
    /// The longer policy for the first connection after a restart bussard
    /// itself triggered: seven attempts, backing off 1 s, then 2 s
    /// ([`MAX_SYNC_BACKOFF`]) five times. With the standard 3 s response
    /// timeout the whole sync gives the device about 32 s to bring its
    /// security layer up, the window the earlier 1-2-4-8 s schedule of five
    /// attempts gave (30 s, live 1.1.12, 2026-09-24), without a pause the
    /// device's 6 s connection timeout ends (issue #575): an unanswered
    /// attempt leaves the connection idle for the response timeout plus the
    /// backoff, at most 5 s.
    ///
    /// [`MGMT_TIMEOUT_MS_ENV`] caps both backoff bounds when set; the attempt
    /// count stays seven.
    pub fn after_restart() -> Self {
        SyncRetry {
            attempts: 7,
            initial_backoff: Duration::from_secs(1),
            max_backoff: MAX_SYNC_BACKOFF,
        }
        .with_env_cap()
    }

    /// Caps the backoff with [`MGMT_TIMEOUT_MS_ENV`] when that test knob is set.
    fn with_env_cap(self) -> Self {
        match mgmt_timeout_override() {
            Some(cap) => self.with_backoff_cap(cap),
            None => self,
        }
    }

    /// The same policy with both backoff bounds capped at `cap`, so a test that
    /// shrinks the reboot wait does not sleep whole seconds between attempts.
    pub fn with_backoff_cap(self, cap: Duration) -> Self {
        SyncRetry {
            attempts: self.attempts,
            initial_backoff: self.initial_backoff.min(cap),
            max_backoff: self.max_backoff.min(cap),
        }
    }
}

/// The octets KNX Data Secure adds to a management APDU: the wrapped frame is
/// the `A_SecureData` APCI (2), the security control field (1), the sequence
/// number (6), the whole plain APDU and the truncated MAC (4), so it is 13
/// octets longer than the plain APDU. CONFIRMED from the ETS capture (issue
/// #156, see [`Layer4Connection::inner_max_apdu`]).
pub const SECURE_APDU_OVERHEAD: u16 = 13;

/// The APDU budget of a standard (short) frame, used when a device's
/// `PID_MAX_APDU_LENGTH` is unknown.
pub const STANDARD_FRAME_APDU: u16 = 15;

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
    /// Set for the duration of [`request_memory_write_echo`](Self::request_memory_write_echo):
    /// the `A_Memory_Response` that follows the `A_Memory_Write` is the verify
    /// echo the caller compares, not a stray to drain.
    expect_memory_echo: bool,
    /// The device's advertised `PID_MAX_APDU_LENGTH` (NPDU octet budget), read
    /// once and cached for the life of this connection. `None` until
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) runs; once negotiated it
    /// scales the memory-write/read and property-read chunk sizes (issue #58).
    /// A device that does not expose the property leaves this `None`, and the
    /// chunk accessors fall back to the conservative standard-frame caps.
    max_apdu: Option<u16>,
    /// What [`negotiate_max_apdu`](Self::negotiate_max_apdu) found when the
    /// device offered no usable value, so a later call on this connection does
    /// not read it again (issue #215). `None` until it ran without a value.
    max_apdu_absent: Option<MaxApduAbsence>,
    /// Set once the peer disconnects or a protocol error occurs: no further
    /// request is sent on this connection.
    closed: bool,
    /// Whether the peer may still hold this connection open: it has shown
    /// itself (any frame from it) and has not sent `T_Disconnect`. While set,
    /// closing the connection owes the peer a `T_Disconnect` (03_03_04 §5.3
    /// A6), even after a response timeout marked it `closed`.
    peer_open: bool,
    /// When a frame last went to or came from the peer, for the 6 s
    /// [`CONNECTION_TIMEOUT`].
    last_traffic: Instant,
    /// The connection timeout the peer is assumed to run:
    /// [`CONNECTION_TIMEOUT`] unless a test shortens it.
    connection_timeout: Duration,
    /// How often this connection reconnected after idling past
    /// [`Self::connection_timeout`] (issue #575).
    idle_reconnects: u32,
    /// The key the last [`authorize`](Self::authorize) presented, presented
    /// again after an idle reconnect.
    authorize_key: Option<u32>,
    /// The KNX Data Secure wrapping layer (issue #71, spec §6.1). Plain by
    /// default (`SecureLayer::plain()`), so the send/receive paths are
    /// byte-identical to the pre-Secure behaviour; when the device is
    /// security-activated this holds a `DataSecureSession` and every management
    /// APDU is transparently wrapped/unwrapped.
    secure: crate::secure::SecureLayer,
    /// How often an unanswered S-A_Sync_Req is repeated (issue #166). Unused on
    /// a plain layer.
    sync_retry: SyncRetry,
    /// Device facts a caller verified for this connection (issue #209): the
    /// object table [`probe_object_types`] returns instead of walking, and the
    /// mask the table reader uses instead of a second descriptor read. `None`
    /// on a fresh connection, so every read path is unchanged until a caller
    /// seeds it.
    seed: Option<ConnectionSeed>,
    /// The outcome of the last [`authorize`](Self::authorize) on this
    /// connection, kept so the device facts can record the verdict.
    last_authorize: Option<AuthorizeOutcome>,
    /// The priority of the numbered data telegrams. The transport layer
    /// leaves it to its user (03_03_04 §5.3 A7); [`Priority::System`] by
    /// default, as ETS sends them. The control frames are always system
    /// priority (§5.3 A2-A4, A6).
    data_priority: Priority,
    /// Whether memory above `0xFFFF` goes over the user-memory services
    /// (`A_UserMemory_*`, 20-bit address) instead of `A_MemoryExtended_*`:
    /// set for an application that does not announce
    /// `SupportsExtendedMemoryServices` (issue #472). `false` by default.
    user_memory_above_64k: bool,
}

/// Why [`Layer4Connection::negotiate_max_apdu`] found no `PID_MAX_APDU_LENGTH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxApduAbsence {
    /// The device answered without a usable value (no such property, a short
    /// answer, or zero): a device-stable fact another connection may reuse.
    Answered,
    /// The device acknowledged the read and never answered it: remembered for
    /// this connection only, so a later connection asks again.
    Unanswered,
}

/// Device facts verified for one connection (issue #209), set with
/// [`Layer4Connection::seed`].
///
/// A caller seeds a connection only after checking the cached facts against
/// the device (the descriptor read and the application id), or on the write
/// connection of a command whose read phase checked them seconds earlier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionSeed {
    /// The mask the descriptor read returned on this device.
    pub mask: Option<u16>,
    /// The interface-object table, `(index, PID_OBJECT_TYPE)` in index order.
    /// Empty means "not known": the walk runs.
    pub object_table: Vec<(u8, u16)>,
    /// `PID_MAX_APDU_LENGTH`, seeded like [`Layer4Connection::set_max_apdu`].
    pub max_apdu: Option<u16>,
    /// The device does not answer `A_Authorize_Request` (the command's read
    /// phase or its checked facts saw it stay silent), so a write session may
    /// skip the request instead of waiting out the response timeout (issue
    /// #215). Never set for a device that answered, granted or asking for a
    /// key.
    pub authorize_unanswered: bool,
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
        conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
        timeouts: Timeouts,
    ) -> Result<Layer4Connection<Ch>> {
        Self::connect_with_secure(
            conn,
            target,
            source,
            timeouts,
            crate::secure::SecureLayer::plain(),
        )
        .await
    }

    /// Like [`connect_with`](Self::connect_with) but with an explicit KNX Data
    /// Secure layer (issue #71, spec §6.1).
    ///
    /// Pass [`SecureLayer::plain`](crate::secure::SecureLayer::plain) for the
    /// unchanged plain path, or
    /// [`SecureLayer::activated`](crate::secure::SecureLayer::activated) with a
    /// `DataSecureSession` to wrap every management APDU for a security-activated
    /// device. This is the single seam that turns a plain management connection
    /// into a secure one; the state machine above it is unchanged.
    pub async fn connect_with_secure(
        mut conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
        timeouts: Timeouts,
        secure: crate::secure::SecureLayer,
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
            expect_memory_echo: false,
            max_apdu: None,
            max_apdu_absent: None,
            closed: false,
            peer_open: false,
            last_traffic: Instant::now(),
            secure,
            sync_retry: SyncRetry::default(),
            seed: None,
            last_authorize: None,
            connection_timeout: CONNECTION_TIMEOUT,
            idle_reconnects: 0,
            authorize_key: None,
            data_priority: Priority::System,
            user_memory_above_64k: false,
        })
    }

    /// Seeds verified device facts into this connection (issue #209): a
    /// non-empty object table replaces the `PID_OBJECT_TYPE` walk of
    /// [`probe_object_types`], a known max APDU is set as by
    /// [`set_max_apdu`](Self::set_max_apdu), and the mask replaces the table
    /// reader's descriptor read. Nothing is sent.
    pub fn seed(&mut self, seed: ConnectionSeed) {
        if let Some(max_apdu) = seed.max_apdu {
            self.max_apdu = Some(max_apdu);
        }
        self.seed = Some(seed);
    }

    /// The seeded object table, when a caller seeded a non-empty one.
    pub fn seeded_object_table(&self) -> Option<&[(u8, u16)]> {
        self.seed
            .as_ref()
            .map(|s| s.object_table.as_slice())
            .filter(|t| !t.is_empty())
    }

    /// The seeded mask, when a caller seeded one.
    pub fn seeded_mask(&self) -> Option<u16> {
        self.seed.as_ref().and_then(|s| s.mask)
    }

    /// Whether the seed says the device does not answer `A_Authorize_Request`
    /// (see [`ConnectionSeed::authorize_unanswered`]).
    pub fn seeded_authorize_unanswered(&self) -> bool {
        self.seed.as_ref().is_some_and(|s| s.authorize_unanswered)
    }

    /// Re-opens the connection after a request the device `T_ACK`ed but never
    /// answered, the way [`authorize`](Self::authorize) does: the peer is alive
    /// and the sequence numbers agree, so a fallback read may follow.
    pub(crate) fn reopen_after_unanswered(&mut self) {
        self.closed = false;
    }

    /// Sets the priority of the numbered data telegrams this connection sends
    /// from now on ([`Priority::System`] unless changed). The transport-layer
    /// control frames stay at system priority whatever is set here.
    pub fn set_data_priority(&mut self, priority: Priority) {
        self.data_priority = priority;
    }

    /// The priority of the numbered data telegrams this connection sends.
    pub fn data_priority(&self) -> Priority {
        self.data_priority
    }

    /// The outcome of the last [`authorize`](Self::authorize) on this
    /// connection, `None` when none was presented.
    pub fn last_authorize(&self) -> Option<&AuthorizeOutcome> {
        self.last_authorize.as_ref()
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
        if self.idle_beyond_connection_timeout() {
            self.reconnect_after_idle().await?;
        }
        self.ensure_secure_sync().await?;
        self.last_send_apci = apci;
        let seq = self.send_seq;
        let tpci_octet = tpci::ndt(seq);
        // KNX Data Secure seam (spec §6.1): on a plain layer this returns
        // `(apci, data)` untouched (byte-identical plain path); on an activated
        // layer it wraps the APDU into an A_SecureData (0x03F1) ASDU.
        let (wire_apci, wire_data) =
            self.secure
                .wrap_outgoing(self.target, self.source, tpci_octet, apci, data)?;
        self.send_numbered(tpci_octet, wire_apci, &wire_data).await
    }

    /// Sends one numbered data telegram with the already-final `(wire_apci,
    /// wire_data)` and waits for its `T_ACK`, retransmitting on timeout or NAK.
    async fn send_numbered(
        &mut self,
        tpci_octet: u8,
        wire_apci: u16,
        wire_data: &[u8],
    ) -> Result<()> {
        let seq = self.send_seq;
        let frame =
            CemiFrame::t_data_connected(self.target, self.source, tpci_octet, wire_apci, wire_data)
                .with_priority(self.data_priority);

        let mut attempt = 0;
        loop {
            self.conn.send(frame.clone()).await?;
            self.last_traffic = Instant::now();
            match self.await_ack(seq).await {
                AckOutcome::Acked => {
                    self.send_seq = (self.send_seq + 1) & 0x0f;
                    self.numbered_exchanges = self.numbered_exchanges.saturating_add(1);
                    return Ok(());
                }
                AckOutcome::Nak => {
                    // E12/E13: a T_NAK at our sequence asks for a repeat (A9)
                    // until the repetitions are spent, then the connection is
                    // closed (A6).
                    if attempt >= self.timeouts.max_repetitions {
                        // A T_NAK proves a peer, also on a connection to our
                        // own address: it is always told.
                        self.peer_open = true;
                        self.abandon().await;
                        return Err(MgmtError::Nak {
                            address: self.target,
                        });
                    }
                    attempt += 1;
                }
                AckOutcome::PeerDisconnected => {
                    // E02, A5: the peer closed; nothing to send back.
                    self.peer_closed();
                    return Err(self.silence_error(SilenceKind::Disconnected));
                }
                AckOutcome::ChannelFailed => {
                    // The frame channel failed under an open connection: tell
                    // the peer, best-effort, before giving up (A6).
                    self.abandon().await;
                    return Err(self.silence_error(SilenceKind::Disconnected));
                }
                AckOutcome::NotConfirmed => {
                    // The interface reported that the medium did not
                    // acknowledge our frame: nobody is at this address. As on
                    // a timeout, nothing is left to tear down.
                    self.peer_closed();
                    return Err(MgmtError::NotConfirmed {
                        address: self.target,
                    });
                }
                AckOutcome::ConnectRejected => {
                    // E20, A5: the T_Connect was not confirmed, so the device
                    // never opened the connection.
                    self.peer_closed();
                    return Err(MgmtError::NotConfirmed {
                        address: self.target,
                    });
                }
                AckOutcome::Timeout => {
                    if attempt >= self.timeouts.max_repetitions {
                        // E18, A6. The very first send with no reaction at all
                        // means the device is absent; after that, treat the
                        // silence as a dead connection to a device that stopped
                        // answering.
                        self.abandon().await;
                        return Err(self.silence_error(SilenceKind::NoResponse));
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// Runs the KNX Data Secure S-A_Sync handshake once per connection, before
    /// the first wrapped APDU (spec §6.3).
    ///
    /// ETS opens every secured tool-access connection this way (secure-1-1-12
    /// capture, 2026-09-23): an S-A_Sync_Req (SCF `0x92`) as a numbered data
    /// telegram, the device's S-A_Sync_Res (SCF `0x93`), then S-A_Data frames
    /// whose first sequence is the one the Sync_Res hands back. A plain layer, or
    /// one already synced, returns immediately.
    ///
    /// # Errors
    ///
    /// A device that T_ACKs the request but never answers with a verifiable
    /// Sync_Res surfaces as [`MgmtError::Secure`] with
    /// [`AsduError::SyncUnanswered`](bussard_secure::AsduError::SyncUnanswered);
    /// a device that does not even acknowledge it is reported absent as usual.
    async fn ensure_secure_sync(&mut self) -> Result<()> {
        // A session that found the device on its factory key stays refused
        // (issue #532): it is never used under the FDSK.
        if self.secure.on_factory_key() {
            return Err(MgmtError::FactoryKeyActive {
                address: self.target,
            });
        }
        if !self.secure.needs_sync() {
            return Ok(());
        }
        let unanswered = |address| MgmtError::Secure {
            address,
            source: bussard_secure::AsduError::SyncUnanswered,
        };
        let attempts = self.sync_retry.attempts.max(1);
        let mut backoff = self.sync_retry.initial_backoff;
        for attempt in 1..=attempts {
            // Each attempt carries a fresh challenge; the request does not
            // consume the Data Secure send sequence, so repeating it is safe.
            let tpci_octet = tpci::ndt(self.send_seq);
            let (wire_apci, wire_data) =
                self.secure
                    .sync_request(self.target, self.source, tpci_octet)?;
            self.last_send_apci = wire_apci;
            // No T_ACK at all still means an absent device: not retried here.
            self.send_numbered(tpci_octet, wire_apci, &wire_data)
                .await?;
            match self.recv_response().await {
                Ok(_) if self.secure.is_synced() => return Ok(()),
                Ok((apci, _)) => {
                    tracing::debug!(
                        target = %self.target,
                        apci = format_args!("{apci:#05x}"),
                        "device answered the Data Secure sync request with something else"
                    );
                    break;
                }
                // T_ACKed but no Sync_Res: the device may still be bringing its
                // security layer up after a reboot (issue #166).
                Err(MgmtError::MidSessionSilence {
                    kind: SilenceKind::NoResponse,
                    ..
                })
                | Err(MgmtError::NoResponse { .. }) => {}
                // A late Sync_Res that answers an earlier attempt's challenge
                // does not verify against this one; the next attempt can.
                Err(MgmtError::Secure { .. }) if attempt > 1 => {}
                Err(MgmtError::MidSessionSilence { .. }) => break,
                Err(other) => return Err(other),
            }
            if attempt == attempts {
                break;
            }
            // The device acknowledged the request, so the link and both
            // sequence counters are consistent: reopen the connection the
            // response timeout closed and ask again after a backoff.
            self.closed = false;
            tracing::debug!(
                target = %self.target,
                attempt,
                backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                "Data Secure sync request unanswered; retrying"
            );
            tokio::time::sleep(backoff.min(self.sync_backoff_bound())).await;
            backoff = backoff.saturating_mul(2).min(self.sync_retry.max_backoff);
            // A pause the bound could not keep inside the connection timeout
            // (a response timeout near it) reconnects before the next attempt.
            if self.idle_beyond_connection_timeout() {
                self.reconnect_after_idle().await?;
            }
        }
        // Issue #532: the tool would "typically retry" under the other key
        // (KNX 3/5/2 §4.1 NOTE 18). One fresh Sync under the FDSK finds a
        // device that was reset to default; it is reported, never used.
        if self.secure.switch_to_factory_key() {
            self.closed = false;
            let tpci_octet = tpci::ndt(self.send_seq);
            let (wire_apci, wire_data) =
                self.secure
                    .sync_request(self.target, self.source, tpci_octet)?;
            self.last_send_apci = wire_apci;
            self.send_numbered(tpci_octet, wire_apci, &wire_data)
                .await?;
            match self.recv_response().await {
                Ok(_) if self.secure.is_synced() => {
                    tracing::warn!(
                        target = %self.target,
                        "the device answered the Data Secure sync under its FDSK, not the tool key"
                    );
                    return Err(MgmtError::FactoryKeyActive {
                        address: self.target,
                    });
                }
                Ok(_)
                | Err(MgmtError::MidSessionSilence { .. })
                | Err(MgmtError::NoResponse { .. })
                | Err(MgmtError::Secure { .. }) => {}
                Err(other) => return Err(other),
            }
        }
        self.closed = true;
        Err(unanswered(self.target))
    }

    /// Sends a request **in the clear** on a security-activated connection and
    /// returns the response, without running the S-A_Sync handshake first.
    ///
    /// ETS opens every secured session with a plain `A_DeviceDescriptor_Read`
    /// before the S-A_Sync_Req (secure-1-1-12 capture): a device answers it in
    /// the clear, so it tells whether the device is up without depending on its
    /// security layer. bussard uses this as the readiness probe after a restart
    /// it triggered (issue #166). On a plain connection this is exactly
    /// [`request`](Self::request).
    pub async fn request_unsecured(&mut self, apci: u16, data: &[u8]) -> Result<(u16, Vec<u8>)> {
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        self.last_send_apci = apci;
        let tpci_octet = tpci::ndt(self.send_seq);
        self.send_numbered(tpci_octet, apci, data).await?;
        self.recv_response().await
    }

    /// Sets how often an unanswered S-A_Sync_Req is repeated (issue #166). Has
    /// no effect on a plain connection or once the handshake is done.
    pub fn set_sync_retry(&mut self, retry: SyncRetry) {
        self.sync_retry = retry;
    }

    /// The timeout budget this connection currently runs on.
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
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
        if self.expect_memory_echo {
            return false;
        }
        // The user-memory twin (issue #472): an `A_UserMemory_Response` that
        // answers no `A_UserMemory_Read` is a write's verify echo.
        if apci == crate::apci::A_USER_MEMORY_RESPONSE {
            return self.last_send_apci != crate::apci::A_USER_MEMORY_READ;
        }
        (apci & crate::apci::APCI_SELECTOR_MASK) == crate::apci::A_MEMORY_RESPONSE
            && (self.last_send_apci & crate::apci::APCI_SELECTOR_MASK) != crate::apci::A_MEMORY_READ
    }

    /// Sends an `A_Memory_Write` and returns the device's verify-mode echo,
    /// the `A_Memory_Response` a device in verify mode answers every write
    /// with (Management Procedures 03_05_02 §3.16.3, DMP_MemWrite_RCoV).
    ///
    /// The echo is delivered whether the device sends it after its `T_ACK` or
    /// folds it in before. Only the response to *this* write counts: a stray
    /// echo from an earlier write cannot be pending, because every write on a
    /// verify-mode connection goes through here and takes its own echo.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request); a device that acknowledges the write but
    /// sends no echo within the response timeout ends in
    /// [`MgmtError::NoResponse`] / [`MgmtError::MidSessionSilence`] and closes
    /// the connection.
    pub async fn request_memory_write_echo(
        &mut self,
        apci: u16,
        data: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        self.expect_memory_echo = true;
        let result = self.request(apci, data).await;
        self.expect_memory_echo = false;
        result
    }

    /// Extracts the inbound `(apci, data)` from `frame`, applying the KNX Data
    /// Secure unwrap when this connection is security-activated (spec §6.1).
    ///
    /// On a plain layer this is exactly [`extract_apdu`] — the byte-identical
    /// plain path. On an activated layer an `A_SecureData` (`0x03F1`) frame is
    /// MAC-verified, freshness-checked, and unwrapped to its inner management
    /// APDU; a non-secured frame passes through unchanged. A MAC mismatch or a
    /// stale sequence surfaces as [`MgmtError::Secure`].
    fn unwrap_apdu(&mut self, frame: &CemiFrame) -> Result<(u16, Vec<u8>)> {
        let (apci, data) = extract_apdu(frame);
        let dest = frame.individual_destination().unwrap_or(self.source);
        self.secure
            .unwrap_incoming(frame.source, dest, frame.tpci_octet(), apci, &data)
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
        self.ensure_secure_sync().await?;
        self.last_send_apci = apci;
        let seq = self.send_seq;
        let tpci_octet = tpci::ndt(seq);
        // KNX Data Secure seam (spec §6.1); plain layer is a no-op passthrough.
        let (wire_apci, wire_data) =
            self.secure
                .wrap_outgoing(self.target, self.source, tpci_octet, apci, data)?;
        let frame = CemiFrame::t_data_connected(
            self.target,
            self.source,
            tpci_octet,
            wire_apci,
            &wire_data,
        )
        .with_priority(self.data_priority);
        self.conn.send(frame).await?;
        self.send_seq = (self.send_seq + 1) & 0x0f;
        self.numbered_exchanges = self.numbered_exchanges.saturating_add(1);
        Ok(())
    }

    /// Waits for the device's response telegram (an incoming NDT), acknowledges
    /// it, and returns its decoded APDU.
    ///
    /// Frames unrelated to this connection (group traffic, telegrams from other
    /// sources) are skipped. A repeat of the previous NDT is acknowledged again
    /// and dropped (E05, A3); an NDT at any other wrong sequence draws a
    /// `T_NAK` with its sequence (E06, A4). Times out as
    /// [`MgmtError::NoResponse`]; the peer still holds the connection then, so
    /// a later [`disconnect`](Self::disconnect) sends its `T_Disconnect`.
    pub async fn recv_response(&mut self) -> Result<(u16, Vec<u8>)> {
        // A folded-ACK response that arrived while we were awaiting the T_ACK has
        // already been acknowledged and sequenced; hand it back first — unless it
        // is a stray verify-mode memory echo, which is dropped so the real
        // response is awaited below.
        if let Some(pending) = self.pending_response.take()
            && !self.is_stale_memory_echo(pending.0)
        {
            return Ok(pending);
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
                Ok(Err(err)) => {
                    let err = self.map_recv_error(err);
                    self.abandon().await;
                    return Err(err);
                }
                Err(_elapsed) => {
                    self.closed = true;
                    return Err(self.silence_error(SilenceKind::NoResponse));
                }
            };
            let frame = stamped.frame;
            if self.is_connect_rejection(&frame) {
                self.peer_closed();
                return Err(MgmtError::NotConfirmed {
                    address: self.target,
                });
            }

            // Ignore anything not from our peer addressed to us individually.
            if frame.source != self.target || frame.individual_destination() != Some(self.source) {
                continue;
            }
            self.note_peer_frame();

            match tpci::classify(frame.tpci_octet()) {
                TpciKind::Disconnect => {
                    self.peer_closed();
                    return Err(self.silence_error(SilenceKind::Disconnected));
                }
                TpciKind::NumberedData(seq) => {
                    if seq == self.recv_seq {
                        // Expected sequence: ACK and (unless it is a stray
                        // verify-mode memory echo) deliver.
                        self.send_control(tpci::t_ack(seq)).await?;
                        self.recv_seq = (self.recv_seq + 1) & 0x0f;
                        let (apci, data) = self.unwrap_apdu(&frame)?;
                        if self.is_stale_memory_echo(apci) {
                            continue;
                        }
                        return Ok((apci, data));
                    } else {
                        self.answer_wrong_sequence(seq).await?;
                        continue;
                    }
                }
                // A stray ACK/NAK/connect while awaiting a response: ignore.
                _ => continue,
            }
        }
    }

    /// A request/response round-trip whose request is wrapped under the
    /// current tool key and whose response, and everything after it, uses
    /// `next_key` (issue #398).
    ///
    /// This is the write of a new tool key (`PID_TOOL_KEY`): a Data Secure
    /// device answers it under the key it was just given, and the connection
    /// continues under that key with the sequences running on (CONFIRMED by
    /// the ETS activation capture of 1.1.200, 2026-10-26). The key is switched
    /// after the request is wrapped and before it is sent, so a response the
    /// device folds into its `T_ACK` verifies too.
    ///
    /// # Errors
    ///
    /// [`MgmtError::Secure`] on a plain connection (there is no key to
    /// replace) and as [`request`](Self::request) otherwise. When the request
    /// fails after the switch, the connection keeps the new key: the device
    /// may have taken it, and the caller decides which key to retry with.
    pub async fn request_rekeyed(
        &mut self,
        apci: u16,
        data: &[u8],
        next_key: bussard_secure::Key16,
    ) -> Result<(u16, Vec<u8>)> {
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        if !self.secure.is_active() {
            return Err(MgmtError::Secure {
                address: self.target,
                source: bussard_secure::AsduError::UnexpectedService(0x90),
            });
        }
        self.ensure_secure_sync().await?;
        self.last_send_apci = apci;
        let tpci_octet = tpci::ndt(self.send_seq);
        let (wire_apci, wire_data) =
            self.secure
                .wrap_outgoing(self.target, self.source, tpci_octet, apci, data)?;
        self.secure.set_tool_key(next_key);
        self.send_numbered(tpci_octet, wire_apci, &wire_data)
            .await?;
        self.recv_response().await
    }

    /// A request/response round-trip: send the request NDT, wait for the ACK,
    /// then wait for and acknowledge the response NDT. Returns the response APCI
    /// and payload octets.
    pub async fn request(&mut self, apci: u16, data: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.send_data(apci, data).await?;
        self.recv_response().await
    }

    /// [`request`](Self::request) for an optional service a device may
    /// acknowledge but never answer: `Ok(None)` when the device stayed silent
    /// after its `T_ACK`. The response timeout marks the connection closed;
    /// since the device acknowledged the request the peer is alive and the
    /// sequence numbers agree, so the connection is reopened, as
    /// [`authorize`](Self::authorize) does for a device without authorize.
    pub(crate) async fn request_optional(
        &mut self,
        apci: u16,
        data: &[u8],
    ) -> Result<Option<(u16, Vec<u8>)>> {
        let exchanges_before = self.numbered_exchanges;
        match self.request(apci, data).await {
            Ok(pair) => Ok(Some(pair)),
            Err(MgmtError::NoResponse { .. })
            | Err(MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }) if self.numbered_exchanges > exchanges_before => {
                self.closed = false;
                Ok(None)
            }
            Err(other) => Err(other),
        }
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
    /// - a granted level (0, or any level above it short of the minimum) →
    ///   [`AuthorizeOutcome::Granted`] carrying the level;
    /// - the minimum level 3 or 15 → [`AuthorizeOutcome::Denied`] (the device's
    ///   answer to an invalid key, surfaced by callers as
    ///   [`MgmtError::AccessDenied`]);
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
        self.authorize_key = Some(key);
        let outcome = self.authorize_exchange(key).await?;
        self.last_authorize = Some(outcome.clone());
        Ok(outcome)
    }

    /// The exchange behind [`authorize`](Self::authorize).
    async fn authorize_exchange(&mut self, key: u32) -> Result<AuthorizeOutcome> {
        let payload = crate::apci::encode_authorize_request(key);
        let exchanges_before = self.numbered_exchanges;
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
                // The response timeout marked the connection closed. If the
                // device T_ACKed the request (it counts as an exchange), the
                // peer is alive and the sequence numbers are consistent: re-open
                // the connection, or the next request fails with `Disconnected`
                // on a device that merely lacks authorize.
                if self.numbered_exchanges > exchanges_before {
                    self.closed = false;
                }
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
            Some(level) if is_minimum_access_level(level) => Ok(AuthorizeOutcome::Denied { level }),
            Some(level) => Ok(AuthorizeOutcome::Granted { level }),
            None => Ok(AuthorizeOutcome::Unsupported {
                detail: format!(
                    "A_Authorize_Response carried no level octet ({})",
                    crate::error::raw_response_detail(resp_apci, &data)
                ),
            }),
        }
    }

    /// Presents `key` with [`authorize`](Self::authorize) and applies the
    /// **tolerate-absence, fail-on-denied** policy directly: a granted or
    /// unsupported authorize returns `Ok`, the minimum level returns
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

    /// Whether this connection is known to be closed: the device sent a
    /// `T_Disconnect`, a request timed out, or it was closed locally. A closed
    /// connection refuses every further request with
    /// [`MgmtError::Disconnected`].
    pub fn is_closed(&self) -> bool {
        self.closed
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
        // Negotiated once per connection, the absence included (issue #215):
        // the table reader, the parameter read-back and the facts each ask,
        // and a device without the property answered all of them the same.
        if self.max_apdu_absent.is_some() {
            return Ok(None);
        }
        let exchanges_before = self.numbered_exchanges;
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
            Err(MgmtError::MalformedResponse { .. }) => {
                tracing::debug!(
                    target = %self.target,
                    "PID_MAX_APDU_LENGTH not readable; using conservative chunk sizes"
                );
                self.max_apdu_absent = Some(MaxApduAbsence::Answered);
                return Ok(None);
            }
            Err(MgmtError::NoResponse { .. })
            | Err(MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }) => {
                // The response timeout marked the connection closed. A device
                // that T_ACKed the read is alive and the sequence numbers
                // agree, so re-open it the way `authorize` does; otherwise the
                // next request fails with `Disconnected` on a device that only
                // lacks the property (issue #215).
                if self.numbered_exchanges > exchanges_before {
                    self.closed = false;
                }
                tracing::debug!(
                    target = %self.target,
                    "PID_MAX_APDU_LENGTH not answered; using conservative chunk sizes"
                );
                self.max_apdu_absent = Some(MaxApduAbsence::Unanswered);
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
                self.max_apdu_absent = Some(MaxApduAbsence::Answered);
                Ok(None)
            }
        }
    }

    /// Why [`negotiate_max_apdu`](Self::negotiate_max_apdu) found no value on
    /// this connection, or `None` when it found one or has not run.
    pub fn max_apdu_absence(&self) -> Option<MaxApduAbsence> {
        self.max_apdu_absent
    }

    /// Records that an earlier connection to the same device found no
    /// `PID_MAX_APDU_LENGTH` in an answer ([`MaxApduAbsence::Answered`]), so
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) keeps the conservative
    /// chunks without asking again (issue #215).
    pub fn set_max_apdu_absent(&mut self) {
        if self.max_apdu.is_none() {
            self.max_apdu_absent = Some(MaxApduAbsence::Answered);
        }
    }

    /// The negotiated `A_Memory_Write`/`A_Memory_Read` data-octet cap for this
    /// connection: scaled from `PID_MAX_APDU_LENGTH` when
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) found it, else the
    /// conservative [`CONSERVATIVE_MEMORY_CHUNK`](crate::apci::CONSERVATIVE_MEMORY_CHUNK)
    /// standard-frame floor.
    pub fn max_memory_chunk(&self) -> u8 {
        match self.inner_max_apdu() {
            Some(v) => crate::apci::memory_chunk_for_apdu(v),
            None => crate::apci::CONSERVATIVE_MEMORY_CHUNK,
        }
    }

    /// The negotiated `A_MemoryExtended_Write`/`_Read` data-octet cap for this
    /// connection: scaled from `PID_MAX_APDU_LENGTH` when
    /// [`negotiate_max_apdu`](Self::negotiate_max_apdu) found it (up to the
    /// 228-octet extended-frame ceiling ETS uses), else the conservative
    /// standard-frame floor.
    ///
    /// This is the extended-service twin of [`max_memory_chunk`](Self::max_memory_chunk):
    /// the extended service carries its count in a full payload octet (not the
    /// 6-bit APCI field), so a capable device (`PID_MAX_APDU=233`) takes 228-octet
    /// chunks instead of the plain service's 63.
    pub fn max_extended_memory_chunk(&self) -> u16 {
        match self.inner_max_apdu() {
            Some(v) => crate::apci::extended_memory_chunk_for_apdu(v),
            None => u16::from(crate::apci::CONSERVATIVE_MEMORY_CHUNK),
        }
    }

    /// The negotiated `A_PropertyValue_Read` value-octet cap for this connection:
    /// scaled from `PID_MAX_APDU_LENGTH` when negotiated, else the conservative
    /// [`CONSERVATIVE_PROPERTY_READ_OCTETS`](crate::apci::CONSERVATIVE_PROPERTY_READ_OCTETS).
    pub fn max_property_read_octets(&self) -> u8 {
        match self.inner_max_apdu() {
            Some(v) => crate::apci::property_read_octets_for_apdu(v),
            None => crate::apci::CONSERVATIVE_PROPERTY_READ_OCTETS,
        }
    }

    /// The negotiated APDU budget left for the **inner** (plain) APDU: the
    /// device's `PID_MAX_APDU_LENGTH` minus [`SECURE_APDU_OVERHEAD`] when this
    /// connection wraps every APDU in `A_SecureData`, or `None` when the
    /// property was never negotiated.
    ///
    /// CONFIRMED against the decrypted ETS capture of a secured download
    /// (issue #156): the device advertises 233, and ETS writes 215-octet
    /// `A_MemoryExtended_Write` chunks (`233 - 13 - 5`) and 211-element
    /// `A_PropertyExtValue_WriteCon` chunks (`233 - 13 - 9`) instead of the
    /// 228 it uses on a plain connection. A chunk sized to the plain budget
    /// would overflow the device's frame limit once wrapped.
    pub fn inner_max_apdu(&self) -> Option<u16> {
        let v = self.max_apdu?;
        if self.secure.is_active() {
            Some(v.saturating_sub(SECURE_APDU_OVERHEAD).max(1))
        } else {
            Some(v)
        }
    }

    /// The inner APDU budget as a number: [`inner_max_apdu`](Self::inner_max_apdu)
    /// or, when `PID_MAX_APDU_LENGTH` was never negotiated, the 15-octet
    /// standard-frame floor.
    pub fn effective_max_apdu(&self) -> u16 {
        self.inner_max_apdu().unwrap_or(STANDARD_FRAME_APDU)
    }

    /// Whether this connection wraps management APDUs in KNX Data Secure.
    pub fn is_secure(&self) -> bool {
        self.secure.is_active()
    }

    /// Runs the Data Secure S-A_Sync handshake now, if it has not run on this
    /// connection yet (spec §6.3); a no-op on a plain or synced connection.
    ///
    /// # Errors
    ///
    /// As the Sync before the first wrapped request.
    pub async fn ensure_synced(&mut self) -> Result<()> {
        if self.closed {
            return Err(MgmtError::Disconnected {
                address: self.target,
            });
        }
        self.ensure_secure_sync().await
    }

    /// The Data Secure sequence the device is expected to send next: one above
    /// the last it sent on this connection, or the one its Sync_Res reported.
    /// `None` on a plain connection or before the Sync.
    pub fn device_next_sequence(&self) -> Option<u64> {
        self.secure.device_next_sequence(self.target)
    }

    /// Makes `next` the lowest Data Secure sequence accepted from the device
    /// from now on: the step before a write of its
    /// `PID_SEQUENCE_NUMBER_SENDING`, whose confirmation already carries the
    /// value written (KNX 3/5/1 §6.3.13.3 NOTE 110, issue #535).
    pub fn expect_device_sequence(&mut self, next: u64) {
        self.secure.expect_device_sequence(self.target, next);
    }

    /// Replaces this connection's timeout/retry budget.
    ///
    /// The budget is normally fixed at connect time, but a caller that uses an
    /// already-open connection for a *liveness probe* — e.g. the flash's
    /// post-reboot poll, which asks a rebooting device for its descriptor every
    /// few hundred milliseconds — needs a much tighter budget than the KNX
    /// standard 3 s, so a device that is still down is ruled out in
    /// milliseconds rather than stalling the poll.
    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
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
        if let Some(v) = max_apdu
            && v != 0
        {
            self.max_apdu = Some(v);
        }
    }

    /// The cached `PID_MAX_APDU_LENGTH`, if it has been negotiated or seeded.
    pub fn max_apdu(&self) -> Option<u16> {
        self.max_apdu
    }

    /// Sends memory above `0xFFFF` over the user-memory services
    /// (`A_UserMemory_Read`/`_Write`, 20-bit address) instead of
    /// `A_MemoryExtended_*`, the way ETS does for an application that does not
    /// announce `SupportsExtendedMemoryServices` (issue #472). Memory up to
    /// `0xFFFF` keeps `A_Memory_*` either way.
    pub fn set_user_memory_above_64k(&mut self, user: bool) {
        self.user_memory_above_64k = user;
    }

    /// Whether memory above `0xFFFF` goes over the user-memory services (see
    /// [`set_user_memory_above_64k`](Self::set_user_memory_above_64k)).
    pub fn user_memory_above_64k(&self) -> bool {
        self.user_memory_above_64k
    }

    /// The `A_UserMemory_Write`/`_Read` data-octet cap for this connection:
    /// scaled from `PID_MAX_APDU_LENGTH` up to the 15 octets of the 4-bit
    /// count, else 10, the standard-frame floor.
    pub fn max_user_memory_chunk(&self) -> u8 {
        crate::apci::user_memory_chunk_for_apdu(
            self.inner_max_apdu().unwrap_or(STANDARD_FRAME_APDU),
        )
    }

    // --- internals ---

    /// The user's `T_Disconnect` (E26, A14): sent while the connection is in
    /// use or the peer may still hold it open; a connection the peer already
    /// closed, or that never reached it, sends nothing.
    async fn close(&mut self) -> Result<()> {
        let owed = !self.closed || self.peer_open;
        self.closed = true;
        self.peer_open = false;
        if !owed {
            return Ok(());
        }
        let frame = CemiFrame::t_control(self.target, self.source, tpci::T_DISCONNECT);
        self.conn.send(frame).await?;
        Ok(())
    }

    /// Gives up on the connection (03_03_04 §5.3 A6): one best-effort
    /// `T_Disconnect` when the peer may still hold the connection open, then
    /// closed. A send that fails or hangs is not waited for longer than the
    /// acknowledge timeout.
    async fn abandon(&mut self) {
        self.closed = true;
        if !std::mem::replace(&mut self.peer_open, false) {
            return;
        }
        let frame = CemiFrame::t_control(self.target, self.source, tpci::T_DISCONNECT);
        let _ = timeout(self.timeouts.ack_timeout, self.conn.send(frame)).await;
    }

    /// The peer closed the connection or never opened it (A5): closed, and
    /// no `T_Disconnect` is owed.
    fn peer_closed(&mut self) {
        self.closed = true;
        self.peer_open = false;
    }

    /// Records a frame from the peer: it holds the connection open, and the
    /// connection timeout restarts.
    ///
    /// A connection to our own address (the source-address probe) sees the
    /// gateway's echoes of its own frames as its peer; it never owes a
    /// `T_Disconnect` for them.
    fn note_peer_frame(&mut self) {
        self.last_traffic = Instant::now();
        if !self.is_self_addressed() {
            self.peer_open = true;
        }
    }

    /// Whether this connection goes to our own address: the source-address
    /// probe ([`crate::probe::probe_own_address`]).
    fn is_self_addressed(&self) -> bool {
        self.target == self.source
    }

    /// Whether this connection has seen no traffic for longer than the 6 s
    /// [`CONNECTION_TIMEOUT`] while the peer held it open: a device has then
    /// closed it on its side (03_03_04 §5.4.3 E16, A6) and answers the next
    /// numbered telegram with nothing or a `T_Disconnect`.
    pub fn idle_beyond_connection_timeout(&self) -> bool {
        self.peer_open && self.last_traffic.elapsed() >= self.connection_timeout
    }

    /// The longest backoff between two S-A_Sync_Req attempts that keeps the
    /// connection inside its timeout: the connection timeout less the response
    /// timeout the unanswered attempt already waited and a margin (issue #575).
    fn sync_backoff_bound(&self) -> Duration {
        self.connection_timeout
            .saturating_sub(self.timeouts.response_timeout)
            .saturating_sub(SYNC_IDLE_MARGIN)
    }

    /// Sets the connection timeout the peer is assumed to run
    /// ([`CONNECTION_TIMEOUT`] by default), so a mock-device test with a
    /// shortened device timeout does not idle for whole seconds.
    pub fn set_connection_timeout(&mut self, timeout: Duration) {
        self.connection_timeout = timeout;
    }

    /// How often this connection reconnected after idling past the connection
    /// timeout (issue #575).
    pub fn idle_reconnects(&self) -> u32 {
        self.idle_reconnects
    }

    /// Re-opens a connection that idled past the connection timeout (03_03_04
    /// §5, E16; issue #575). The device has closed it (A6) and would answer
    /// the next numbered telegram with `T_Disconnect` (CLOSED, A10), so the
    /// request that follows runs on a fresh connection instead:
    ///
    /// 1. the frames that arrived while idle are drained, the device's
    ///    timeout `T_Disconnect` among them, so it does not end the new
    ///    connection;
    /// 2. one `T_Disconnect` closes the connection on a device whose timer
    ///    has not fired yet (a repeated `T_Connect` would be ignored there,
    ///    E00 in OPEN_IDLE, and the sequence numbers would disagree), then a
    ///    `T_Connect` opens the new one; both sequence numbers restart at 0;
    /// 3. a key presented with [`authorize`](Self::authorize) is presented
    ///    again: the access level belongs to the connection. A denial fails
    ///    with [`MgmtError::AccessDenied`].
    ///
    /// The Data Secure layer keeps its sync and sequence numbers, which the
    /// device tracks per address (KNX 3/5/1 §6.3), not per connection.
    async fn reconnect_after_idle(&mut self) -> Result<()> {
        let idle = self.last_traffic.elapsed();
        tracing::info!(
            target = %self.target,
            idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
            "no traffic for longer than the transport connection timeout; the device has closed \
             the connection (03_03_04 §5, E16): reconnecting"
        );
        // A frame the device sent while we idled is already queued; waiting a
        // short while per frame also catches one still in flight.
        for _ in 0..IDLE_DRAIN_FRAMES {
            match timeout(IDLE_DRAIN_WAIT, self.conn.recv()).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
        self.conn
            .send(CemiFrame::t_control(
                self.target,
                self.source,
                tpci::T_DISCONNECT,
            ))
            .await?;
        self.conn
            .send(CemiFrame::t_control(
                self.target,
                self.source,
                tpci::T_CONNECT,
            ))
            .await?;
        self.send_seq = 0;
        self.recv_seq = 0;
        self.pending_response = None;
        self.peer_open = false;
        self.closed = false;
        self.last_traffic = Instant::now();
        self.idle_reconnects = self.idle_reconnects.saturating_add(1);
        if let Some(key) = self.authorize_key {
            // Boxed: `authorize` sends through `send_data`, which called us.
            let outcome = Box::pin(self.authorize(key)).await?;
            if let AuthorizeOutcome::Denied { level } = outcome {
                return Err(MgmtError::AccessDenied {
                    address: self.target,
                    level,
                });
            }
        }
        Ok(())
    }

    /// Answers a numbered data telegram whose sequence is not the expected
    /// `SeqNoRcv`: a repeat of the previous one is acknowledged again (E05,
    /// A3), any other sequence draws a `T_NAK` with the received sequence (E06,
    /// A4). Neither is delivered.
    async fn answer_wrong_sequence(&mut self, seq: u8) -> Result<()> {
        let previous = self.recv_seq.wrapping_sub(1) & 0x0f;
        let octet = if seq == previous {
            tpci::t_ack(seq)
        } else {
            tpci::t_nak(seq)
        };
        self.send_control(octet).await
    }

    /// Sends a single transport-control octet to the peer.
    async fn send_control(&mut self, octet: u8) -> Result<()> {
        let frame = CemiFrame::t_control(self.target, self.source, octet);
        self.conn.send(frame).await?;
        self.last_traffic = Instant::now();
        Ok(())
    }

    /// Waits for a `T_ACK`/`T_NAK` for `seq` from the peer (state OPEN_WAIT of
    /// 03_03_04 §5.4.3 with AN210), skipping unrelated traffic. A `T_ACK` or
    /// `T_NAK` at another sequence is ignored (E09, E11: A0). An NDT at the
    /// expected receive sequence is the device's answer folded in before its
    /// `T_ACK`; any other NDT is answered as in
    /// [`answer_wrong_sequence`](Self::answer_wrong_sequence) and dropped.
    async fn await_ack(&mut self, seq: u8) -> AckOutcome {
        let deadline = Instant::now() + self.timeouts.ack_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return AckOutcome::Timeout;
            }
            let stamped = match timeout(remaining, self.conn.recv()).await {
                Ok(Ok(stamped)) => stamped,
                Ok(Err(_)) => return AckOutcome::ChannelFailed,
                Err(_elapsed) => return AckOutcome::Timeout,
            };
            let frame = stamped.frame;
            if self.is_connect_rejection(&frame) {
                return AckOutcome::ConnectRejected;
            }
            if self.is_absence_confirmation(&frame) {
                return AckOutcome::NotConfirmed;
            }
            if frame.source != self.target || frame.individual_destination() != Some(self.source) {
                continue;
            }
            self.note_peer_frame();
            match tpci::classify(frame.tpci_octet()) {
                // E08, A8.
                TpciKind::Ack(acked) if acked == seq => return AckOutcome::Acked,
                // E09: AN210 §2.2.1 turns the A6 of the original table into A0,
                // since a stray T_ACK is most likely a repetition on the medium.
                TpciKind::Ack(_) => continue,
                // E12/E13: the caller repeats or closes.
                TpciKind::Nak(naked) if naked == seq => return AckOutcome::Nak,
                // E11, A0.
                TpciKind::Nak(_) => continue,
                // E02, A5.
                TpciKind::Disconnect => return AckOutcome::PeerDisconnected,
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
                    // KNX Data Secure unwrap (spec §6.1). A folded response that
                    // fails MAC verification / freshness on an activated layer is
                    // not a usable answer: drop it (it was already ACKed) and keep
                    // waiting for the real T_ACK rather than accepting a forged or
                    // replayed frame.
                    let (apci, data) = match self.unwrap_apdu(&frame) {
                        Ok(pair) => pair,
                        Err(err) => {
                            tracing::debug!(
                                target = %self.target,
                                error = %err,
                                "dropping folded response that failed Data Secure verification"
                            );
                            continue;
                        }
                    };
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
                TpciKind::NumberedData(nseq) => {
                    // A duplicate / out-of-window NDT is NOT confirmation that
                    // our current request landed (#58): a repeat of the previous
                    // response (our T_ACK for it was lost) is acknowledged again
                    // (E05, A3), any other sequence is NAKed (E06, A4). Then KEEP
                    // WAITING for our real T_ACK: returning `Acked` here would
                    // falsely advance our send sequence off a stale frame and
                    // desync the connection.
                    let _ = self.answer_wrong_sequence(nseq).await;
                    continue;
                }
                _ => continue,
            }
        }
    }

    /// Whether `frame` is a negative `L_Data.con` for one of our frames to the
    /// target that, under this session's budget, proves the target absent.
    ///
    /// Opt-in ([`Timeouts::absent_on_negative_confirmation`]) and only before
    /// the first acknowledged exchange: the con of our `T_Connect` or of the
    /// first numbered telegram. Later in a session a negative con is ignored
    /// and the ACK timeout and repetitions run as before. The con echoes our
    /// own addressing (source = us, destination = target), which is why it is
    /// checked before the peer filter.
    fn is_absence_confirmation(&self, frame: &CemiFrame) -> bool {
        self.timeouts.absent_on_negative_confirmation
            && self.numbered_exchanges == 0
            && frame.is_negative_confirmation()
            && frame.confirms(self.source, self.target)
    }

    /// Whether `frame` is a negative `L_Data.con` for our `T_Connect` (03_03_04
    /// §5.4.3 E20): the device never received the connect, so the connection
    /// is closed at once (A5) on every budget.
    ///
    /// Not for a connection to our own address: the source-address probe
    /// classifies on echoes, not on confirmations ([`Timeouts::probe`]).
    fn is_connect_rejection(&self, frame: &CemiFrame) -> bool {
        !self.is_self_addressed()
            && self.numbered_exchanges == 0
            && frame.is_negative_confirmation()
            && frame.confirms(self.source, self.target)
            && tpci::classify(frame.tpci_octet()) == TpciKind::Connect
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
    /// A `T_NAK` for our sequence arrived.
    Nak,
    /// The peer sent `T_Disconnect`.
    PeerDisconnected,
    /// The frame channel failed.
    ChannelFailed,
    /// No `T_ACK` arrived within the timeout.
    Timeout,
    /// The interface reported a negative `L_Data.con` for our frame and the
    /// budget classifies that as absent (issue #45).
    NotConfirmed,
    /// The interface reported a negative `L_Data.con` for our `T_Connect`
    /// (E20).
    ConnectRejected,
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

/// One property's description as read over the bus with
/// `A_PropertyDescription_Read` (issue #72).
///
/// This is the mgmt-layer typed struct the introspection surface returns: the
/// PID and the property index it occupies, its data-type code and writability,
/// its maximum element count, and the read/write access levels. It is a thin,
/// stable projection of [`crate::apci::PropertyDescription`] that callers (the
/// CLI `describe` table, the MCP tool) render without touching APCI types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyDesc {
    /// Interface object index the property lives on.
    pub object_index: u8,
    /// The property id (PID).
    pub property_id: u8,
    /// The property index this PID occupies within the object (1-based).
    pub property_index: u8,
    /// The property data type (PDT) code (KNX 3/5/1 property data types).
    pub pdt: u8,
    /// Whether the property is writable.
    pub writable: bool,
    /// The maximum number of elements (array length).
    pub max_elements: u16,
    /// The access level required to read the property (0 = highest access).
    pub read_level: u8,
    /// The access level required to write the property (0 = highest access).
    pub write_level: u8,
}

impl From<crate::apci::PropertyDescription> for PropertyDesc {
    fn from(d: crate::apci::PropertyDescription) -> Self {
        PropertyDesc {
            object_index: d.object_index,
            property_id: d.property_id,
            property_index: d.property_index,
            pdt: d.pdt,
            writable: d.writable,
            max_elements: d.max_elements,
            read_level: d.read_level,
            write_level: d.write_level,
        }
    }
}

/// Sends an `A_PropertyDescription_Read` and returns the decoded
/// [`PropertyDescription`](crate::apci::PropertyDescription), validating the
/// response service and the 7-octet descriptor.
///
/// Addresses either a specific PID (`property_id != 0`, `property_index` ignored
/// by the device) or a property **by index** (`property_id == 0`), the latter
/// being the enumeration path — see [`describe_object_properties`]. The shared
/// request/validate/decode seam so the mgmt method and the enumeration helper
/// agree on the wire form.
pub(crate) async fn property_description_request<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    property_index: u8,
) -> Result<crate::apci::PropertyDescription> {
    let payload =
        crate::apci::encode_property_description_read(object_index, property_id, property_index);
    let (resp_apci, data) = l4
        .request(crate::apci::A_PROPERTY_DESCRIPTION_READ, &payload)
        .await?;
    if resp_apci != crate::apci::A_PROPERTY_DESCRIPTION_RESPONSE {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "expected A_PropertyDescription_Response ({})",
                crate::error::raw_response_detail(resp_apci, &data)
            ),
        });
    }
    crate::apci::decode_property_description_response(&data).ok_or_else(|| {
        MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "property description response too short ({})",
                crate::error::raw_response_detail(resp_apci, &data)
            ),
        }
    })
}

/// The interface-object index the discovery sweep stops at (exclusive).
///
/// Interface objects are contiguously indexed from 0, so the sweep ends at the
/// first index that answers "no object here". The full `0..16` range matters: a
/// device whose application-program object sits at index 12–15 is still found,
/// where a tighter budget silently misses it.
pub const MAX_OBJECT_INDEX: u8 = 16;

/// `PID_OBJECT_TYPE` (1) — the interface-object type, the property every object
/// discovery walk reads.
pub const PID_OBJECT_TYPE: u8 = 1;

/// Probes one interface-object index for its `PID_OBJECT_TYPE`.
///
/// `Ok(Some(object_type))` is an object; `Ok(None)` means **no object at this
/// index** and ends a sweep. The `None` case is deliberately **tolerant**: an
/// index answered with a non-property service, an undecodable response, zero
/// elements or a short value all mean "no object here". Real devices do not agree
/// on how they refuse an out-of-range object index — KNX Virtual and the thelsing
/// demo each answer differently — and the flash engine's walk, the one that has
/// been run against them, tolerated all of it. Only a genuine transport failure
/// (a silence, a disconnect) propagates as `Err`.
///
/// This is the single probe behind [`probe_object_types`] and behind
/// `bussard-download`'s resumable walk, which needs one index at a time so it can
/// reconnect and continue mid-sweep.
pub async fn probe_object_type<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
) -> Result<Option<u16>> {
    match property_request(l4, index, PID_OBJECT_TYPE, 1, 1).await {
        Ok(resp) if resp.count == 0 || resp.data.len() < 2 => Ok(None),
        Ok(resp) => Ok(Some(u16::from_be_bytes([resp.data[0], resp.data[1]]))),
        // An off-service or undecodable answer is how some devices say "no object
        // at this index"; it ends the sweep rather than failing it.
        Err(MgmtError::MalformedResponse { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Walks `PID_OBJECT_TYPE` over `0..`[`MAX_OBJECT_INDEX`] and returns the
/// `(object index, object type)` pairs the device exposes, in index order.
///
/// This is *the* interface-object discovery for bussard: the table read side, the
/// incremental `apply`, the flash engine and the read-only pre-flight probe all
/// call it, so all four see the same device picture and terminate identically.
/// Each index is probed with [`probe_object_type`], whose tolerance at the end of
/// the list is the behaviour real devices need.
///
/// An empty result (nothing readable even at index 0) is not an error here;
/// callers that require at least one object say so themselves.
pub async fn probe_object_types<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<(u8, u16)>> {
    // A table the caller verified for this device (issue #209) replaces the
    // walk; nothing is sent.
    if let Some(table) = l4.seeded_object_table() {
        return Ok(table.to_vec());
    }
    let mut objects = Vec::new();
    for index in 0..MAX_OBJECT_INDEX {
        match probe_object_type(l4, index).await? {
            Some(ot) => objects.push((index, ot)),
            None => break,
        }
    }
    Ok(objects)
}

/// Reads the device descriptor type 0 — the 16-bit **mask version** that decides
/// property-based vs memory-based link writes.
///
/// Sends `A_DeviceDescriptor_Read` with the descriptor type in the low APCI bits
/// and an **empty** payload (the spec-correct framing; strict devices
/// `T_Disconnect` the over-long form), then validates the answer's service and
/// takes the mask from the leading big-endian word.
///
/// The selector check is strict — a wrong service or a shorter-than-2-octet answer
/// is rejected, with the raw APCI and payload in the message — but the response
/// **length** is not: the descriptor type rides in the response's low APCI bits, a
/// type-2 response is longer, and some interfaces (observed on the KNX Virtual
/// IP/TP interface) answer type 0 with extra trailing payload. Both are legal, so
/// any tail is ignored.
pub async fn read_device_descriptor<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<u16> {
    let (req_apci, payload) = crate::apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    decode_device_descriptor(l4.target(), resp_apci, &data)
}

/// Reads the device descriptor type 0 **in the clear**, even on a
/// security-activated connection, without the S-A_Sync handshake.
///
/// This is the readiness probe ETS sends first on every secured session and
/// bussard sends after a restart it triggered (issue #166): a device that
/// answers it is up, whether or not its security layer is ready yet. On a plain
/// connection it is identical to [`read_device_descriptor`].
pub async fn read_device_descriptor_unsecured<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<u16> {
    let (req_apci, payload) = crate::apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4.request_unsecured(req_apci, &payload).await?;
    decode_device_descriptor(l4.target(), resp_apci, &data)
}

/// The descriptor type a device echoes to say it does not support the type
/// asked for (03_03_07 §3.4.2.1).
const DESCRIPTOR_TYPE_UNSUPPORTED: u16 = 0x3F;

/// Decodes an `A_DeviceDescriptor_Response` for descriptor type 0.
///
/// The response echoes the descriptor type in its low six APCI bits (03_03_07
/// §3.4.2.1): type 3Fh is the device saying it does not support the type,
/// and a device without descriptor type 0 answers with its lowest supported
/// type, whose value is not a mask version. Both fail with what the device
/// said instead of being read as type 0.
fn decode_device_descriptor(
    address: IndividualAddress,
    resp_apci: u16,
    data: &[u8],
) -> Result<u16> {
    let is_response =
        resp_apci & crate::apci::APCI_SELECTOR_MASK == crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE;
    let echoed_type = resp_apci & !crate::apci::APCI_SELECTOR_MASK;
    if is_response && echoed_type == DESCRIPTOR_TYPE_UNSUPPORTED {
        return Err(MgmtError::DescriptorTypeUnsupported {
            address,
            requested: 0,
        });
    }
    if is_response && echoed_type != 0 {
        return Err(MgmtError::MalformedResponse {
            address,
            reason: format!(
                "answered descriptor type {echoed_type} instead of type 0 (a device without \
                 type 0 answers with its lowest supported type): {}",
                crate::error::raw_response_detail(resp_apci, data)
            ),
        });
    }
    if !is_response || data.len() < 2 {
        return Err(MgmtError::MalformedResponse {
            address,
            reason: crate::error::descriptor_response_reason(resp_apci, data),
        });
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// Enumerates the properties of one interface object by walking the property
/// index `1..` until the device reports none (issue #72).
///
/// Sends an `A_PropertyDescription_Read` by **index** (PID 0) for each index
/// from 1 upward and collects the descriptors, stopping cleanly when the device
/// answers with `max_elements == 0` (no property at that index — the end of the
/// object's property list) or with a duplicate/decreasing index (a device that
/// clamps rather than reporting absence). The value is describing an unknown
/// device's property set. Read-only on the bus.
///
/// A `NoResponse`/`MalformedResponse` from the device (it does not implement the
/// description service, or answers off-service) terminates the walk cleanly with
/// whatever was collected so far, rather than failing — an older/simpler device
/// that does not support the service still yields an empty list. A genuine
/// transport/connection death propagates as `Err`.
pub async fn describe_object_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<Vec<PropertyDesc>> {
    /// The most property indices to probe on one object before giving up. A real
    /// interface object exposes far fewer than this; the cap bounds a device that
    /// never reports absence.
    const MAX_PROPERTY_INDEX: u8 = 64;

    let mut out: Vec<PropertyDesc> = Vec::new();
    let mut index: u8 = 1;
    while index <= MAX_PROPERTY_INDEX {
        let desc = match property_description_request(l4, object_index, 0, index).await {
            Ok(desc) => desc,
            // The device does not implement the service, or answered off-service /
            // not at all: end the walk cleanly with what we have. A transport
            // death still propagates.
            Err(MgmtError::MalformedResponse { .. }) | Err(MgmtError::NoResponse { .. }) => break,
            Err(MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }) => break,
            Err(other) => return Err(other),
        };
        // max_elements == 0 is the spec's "no property here" signal: the object's
        // property list has ended.
        if desc.max_elements == 0 {
            break;
        }
        // Guard against a device that clamps the index rather than reporting
        // absence: if it keeps echoing the same/earlier property index, stop.
        if out.iter().any(|d| d.property_index == desc.property_index) {
            break;
        }
        out.push(desc.into());
        index += 1;
    }
    Ok(out)
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
        /// Fail `recv` with a closed channel once the script is empty, instead
        /// of blocking.
        fail_when_empty: bool,
    }

    impl ScriptedBus {
        fn new(inbox: Vec<CemiFrame>) -> Self {
            ScriptedBus {
                sent: Vec::new(),
                inbox: inbox.into(),
                fail_when_empty: false,
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
                None if self.fail_when_empty => Err(TransportError::Closed),
                // Empty: block forever so the caller's timeout elapses.
                None => std::future::pending().await,
            }
        }

        async fn close(self) -> bussard_transport::Result<()> {
            Ok(())
        }
    }

    /// 1.1.4.
    fn dev() -> IndividualAddress {
        IndividualAddress::from_raw(0x1104)
    }
    /// 0.0.255.
    fn tool() -> IndividualAddress {
        IndividualAddress::from_raw(0x00FF)
    }

    /// A device→tool control frame (T_ACK / T_NAK / T_Disconnect).
    fn control_from_dev(octet: u8) -> CemiFrame {
        CemiFrame::t_control(tool(), dev(), octet)
    }

    /// A device→tool numbered data response frame.
    fn ndt_from_dev(seq: u8, apci: u16, data: &[u8]) -> CemiFrame {
        CemiFrame::t_data_connected(tool(), dev(), tpci::ndt(seq), apci, data)
    }

    /// The `T_ACK`s and `T_NAK`s among `sent`, in order.
    fn acks_and_naks(sent: &[CemiFrame]) -> Vec<TpciKind> {
        sent.iter()
            .map(|f| tpci::classify(f.tpci_octet()))
            .filter(|k| matches!(k, TpciKind::Ack(_) | TpciKind::Nak(_)))
            .collect()
    }

    /// How many `T_Disconnect`s `sent` holds.
    fn disconnects(sent: &[CemiFrame]) -> usize {
        sent.iter()
            .filter(|f| f.tpci_octet() == tpci::T_DISCONNECT)
            .count()
    }

    fn fast() -> Timeouts {
        Timeouts {
            ack_timeout: Duration::from_millis(50),
            max_repetitions: 1,
            response_timeout: Duration::from_millis(50),
            absent_on_negative_confirmation: false,
        }
    }

    #[test]
    fn constants_are_within_spec_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(ACK_TIMEOUT, Duration::from_secs(3));
        assert_eq!(MAX_REPETITIONS, 3);
        Ok(())
    }

    #[test]
    fn extract_apdu_reads_management_apci() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let frame = ndt_from_dev(0, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE, &[0x07, 0xB0]);
        let (apci, data) = extract_apdu(&frame);
        assert_eq!(apci, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE);
        assert_eq!(data, vec![0x07, 0xB0]);
        Ok(())
    }

    #[tokio::test]
    async fn happy_path_request_response() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Script: T_ACK(0) for our request, then the response NDT(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let (apci, data) = l4.request(0x300, &[0x00]).await?;
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        // We sent: T_Connect, the request NDT, and the T_ACK for the response.
        let octets: Vec<u8> = bus.sent.iter().map(|f| f.tpci_octet()).collect();
        assert_eq!(octets[0], tpci::T_CONNECT);
        // NDT seq 0 octet has APCI high bits folded in; mask them off.
        assert_eq!(octets[1] & 0xfc, tpci::ndt(0));
        assert_eq!(octets[2], tpci::t_ack(0));
        Ok(())
    }

    #[tokio::test]
    async fn test_master_reset_factory_reset_reads_response_and_process_time()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The issue #117 capture: ETS sends `A_Restart` master reset, erase code
        // 7, channel 0 as a numbered request; the device T_ACKs it and answers
        // `A_Restart_Response` error 0, process time 8 s.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_RESTART_RESPONSE, &[0x00, 0x00, 0x08]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let response = crate::load::master_reset(&mut l4, 7, 0).await?;
        assert_eq!(response.error_code, 0);
        assert_eq!(response.process_time_s, 8);
        assert_eq!(
            crate::load::restart_process_wait(&response),
            Duration::from_secs(8)
        );
        // The request went out numbered, as APCI 0x381 + [07 00], and the
        // response was acknowledged.
        let (apci, data) = extract_apdu(&bus.sent[1]);
        assert_eq!(bus.sent[1].tpci_octet() & 0xfc, tpci::ndt(0));
        assert_eq!(apci, crate::apci::A_RESTART_MASTER_RESET);
        assert_eq!(data, vec![0x07, 0x00]);
        assert_eq!(bus.sent[2].tpci_octet(), tpci::t_ack(0));
        Ok(())
    }

    #[tokio::test]
    async fn test_master_reset_nonzero_error_code_is_refused()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_RESTART_RESPONSE, &[0x02, 0x00, 0x00]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let err = crate::load::master_reset(&mut l4, 7, 0)
            .await
            .err()
            .ok_or("a non-zero error code must fail")?;
        assert!(matches!(
            err,
            crate::load::WriteError::RestartRefused {
                error_code: 2,
                erase_code: 7,
                ..
            }
        ));
        assert!(err.to_string().contains("unsupported erase code"));
        Ok(())
    }

    #[test]
    fn test_restart_process_wait_is_at_least_the_process_time()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // KNX 3/5/2 §3.7.1.2.2: the process time is a minimum wait; above
        // MAX_RESTART_PROCESS_WAIT it is logged, not clamped.
        let long = crate::apci::RestartResponse {
            error_code: 0,
            process_time_s: 90,
        };
        assert_eq!(
            crate::load::restart_process_wait(&long),
            Duration::from_secs(90)
        );
        Ok(())
    }

    #[tokio::test]
    async fn retransmit_on_ack_timeout() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Script: no ACK for the first send (empty inbox forces a timeout), then
        // after the retransmit, an ACK(0) + response. We prime the inbox so the
        // ACK only appears "after" one timeout by leaving it empty first — but
        // ScriptedBus pops immediately, so instead assert the retransmit count.
        // Here we let the first attempt time out (empty inbox) and never ACK, so
        // the send fails; we assert the request was sent max_repetitions+1 times.
        let mut bus = ScriptedBus::new(vec![]);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let err = l4
            .send_data(0x300, &[0x00])
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(err, MgmtError::NoResponse { .. }), "got {err:?}");
        // The device never showed itself: the connection is CONNECTING in the
        // Style 3 table, where the acknowledge timeout is A0. No T_Disconnect.
        l4.disconnect().await?;
        assert_eq!(disconnects(&bus.sent), 0);
        // T_Connect + (1 initial + 1 retransmit) request sends = 3 frames.
        let ndt_sends = bus
            .sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .count();
        assert_eq!(ndt_sends, 2, "one initial send plus one retransmit");
        Ok(())
    }

    #[tokio::test]
    async fn wrong_sequence_response_is_dropped_then_correct_delivered()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Script: ACK(0), then a WRONG-seq NDT(5), then the correct NDT(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(5, 0x340, &[0xFF]),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let (_apci, data) = l4.request(0x300, &[0x00]).await?;
        // The wrong-seq frame was dropped; the correct one delivered.
        assert_eq!(data, vec![0x07, 0xB0]);
        // E06, A4: the out-of-window NDT(5) draws T_NAK(5); the delivered
        // frame T_ACK(0).
        assert_eq!(
            acks_and_naks(&bus.sent),
            vec![TpciKind::Nak(5), TpciKind::Ack(0)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn folded_ack_response_is_delivered()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The device folds the ACK: instead of a T_ACK, it answers directly with
        // the response NDT(0). await_ack must stash it, advance recv_seq and ACK
        // it; recv_response then drains the stash. Without the fix the APDU is
        // lost and recv_response times out.
        let inbox = vec![ndt_from_dev(0, 0x340, &[0x07, 0xB0])];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let (apci, data) = l4.request(0x300, &[0x00]).await?;
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
        Ok(())
    }

    #[tokio::test]
    async fn folded_wrong_seq_ndt_is_not_our_ack()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let (apci, data) = l4.request(0x300, &[0x00]).await?;
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
        // The out-of-window NDT(5) is NAKed with its own sequence (E06, A4)
        // while awaiting, then the real response ACKed with 0.
        assert_eq!(
            acks_and_naks(&bus.sent),
            vec![TpciKind::Nak(5), TpciKind::Ack(0)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn nak_retries_before_failing() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A device that NAKs every attempt should be retransmitted
        // max_repetitions times before surfacing MgmtError::Nak.
        let mut inbox = Vec::new();
        for _ in 0..4 {
            inbox.push(control_from_dev(tpci::t_nak(0)));
        }
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let err = l4
            .send_data(0x300, &[0x00])
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(err, MgmtError::Nak { .. }), "got {err:?}");
        l4.disconnect().await?;
        // fast() has max_repetitions = 1: one initial send + one retransmit = 2
        // NDT sends before the NAK is fatal.
        let ndt_sends = bus
            .sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .count();
        assert_eq!(ndt_sends, 2, "one initial send plus one retransmit on NAK");
        // E13, A6: one T_Disconnect, and none again on the user's disconnect.
        assert_eq!(disconnects(&bus.sent), 1);
        Ok(())
    }

    // --- Style 3 events (03_03_04 §5.4.3 with AN210 §2.2.1), issue #507 ---

    #[tokio::test]
    async fn test_await_ack_ignores_a_wrong_sequence_t_ack()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E09 in OPEN_WAIT is A0 since AN210: a stray T_ACK(9) is ignored and
        // the real T_ACK(0) completes the send.
        let inbox = vec![
            control_from_dev(tpci::t_ack(9)),
            control_from_dev(tpci::t_ack(0)),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.send_data(0x300, &[]).await?;
        assert_eq!(l4.send_seq, 1);
        assert!(!l4.is_closed());
        drop(l4);
        assert_eq!(ndt_sends(&bus), 1);
        assert_eq!(disconnects(&bus.sent), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_await_ack_ignores_a_wrong_sequence_t_nak()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E11, A0: a T_NAK for another sequence neither repeats nor closes.
        let inbox = vec![
            control_from_dev(tpci::t_nak(4)),
            control_from_dev(tpci::t_ack(0)),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.send_data(0x300, &[]).await?;
        drop(l4);
        assert_eq!(
            ndt_sends(&bus),
            1,
            "a wrong-sequence T_NAK is not a repeat request"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_await_ack_repeats_on_a_matching_t_nak()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E12, A9: T_NAK(0) repeats the stored frame, T_ACK(0) completes it.
        let inbox = vec![
            control_from_dev(tpci::t_nak(0)),
            control_from_dev(tpci::t_ack(0)),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.send_data(0x300, &[0x01]).await?;
        drop(l4);
        let ndts: Vec<&CemiFrame> = bus
            .sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(0)))
            .collect();
        assert_eq!(ndts.len(), 2);
        assert_eq!(ndts[0], ndts[1], "the repeat is the stored frame");
        Ok(())
    }

    #[tokio::test]
    async fn test_recv_response_reacks_the_previous_sequence()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E05, A3: after delivering NDT(0), a repeat of NDT(0) (our T_ACK was
        // lost) is acknowledged with its own sequence and not delivered.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
            control_from_dev(tpci::t_ack(1)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
            ndt_from_dev(1, 0x340, &[0x07, 0xB1]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.request(0x300, &[]).await?;
        let (_, data) = l4.request(0x300, &[]).await?;
        assert_eq!(data, vec![0x07, 0xB1]);
        drop(l4);
        assert_eq!(
            acks_and_naks(&bus.sent),
            vec![TpciKind::Ack(0), TpciKind::Ack(0), TpciKind::Ack(1)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_ack_timeout_on_an_open_connection_sends_t_disconnect()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E18, A6: the device answered the first request, then stops
        // acknowledging. Giving up sends one T_Disconnect so the device does
        // not sit in OPEN_IDLE and ignore our next T_Connect (E00, A0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.request(0x300, &[]).await?;
        let err = l4
            .send_data(0x300, &[])
            .await
            .err()
            .ok_or("the second send goes unacknowledged")?;
        assert!(
            matches!(
                err,
                MgmtError::MidSessionSilence {
                    kind: SilenceKind::NoResponse,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(l4.is_closed());
        l4.disconnect().await?;
        let last = bus.sent.last().ok_or("frames sent")?;
        assert_eq!(last.tpci_octet(), tpci::T_DISCONNECT);
        assert_eq!(disconnects(&bus.sent), 1, "exactly one T_Disconnect");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_disconnect_is_not_answered()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // E02, A5: the device's T_Disconnect closes the connection; nothing is
        // sent back, not even on the user's disconnect.
        let inbox = vec![control_from_dev(tpci::T_DISCONNECT)];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let err = l4.send_data(0x300, &[]).await.err().ok_or("disconnected")?;
        assert!(matches!(err, MgmtError::Disconnected { .. }), "got {err:?}");
        l4.disconnect().await?;
        assert_eq!(disconnects(&bus.sent), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_response_timeout_leaves_the_t_disconnect_to_the_user()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The device acknowledged but never answered: the connection is
        // unusable, but the device still holds it open, so the user's
        // disconnect sends the T_Disconnect it is owed.
        let inbox = vec![control_from_dev(tpci::t_ack(0))];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let err = l4.request(0x300, &[]).await.err().ok_or("no response")?;
        assert!(
            matches!(err, MgmtError::MidSessionSilence { .. }),
            "got {err:?}"
        );
        assert!(l4.is_closed());
        l4.disconnect().await?;
        assert_eq!(disconnects(&bus.sent), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_channel_failure_on_an_open_connection_sends_t_disconnect()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A broken frame channel under an open connection: one best-effort
        // T_Disconnect (A6) before the error surfaces.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        bus.fail_when_empty = true;
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        l4.request(0x300, &[]).await?;
        let err = l4
            .send_data(0x300, &[])
            .await
            .err()
            .ok_or("channel failed")?;
        assert!(
            matches!(
                err,
                MgmtError::MidSessionSilence {
                    kind: SilenceKind::Disconnected,
                    ..
                }
            ),
            "got {err:?}"
        );
        l4.disconnect().await?;
        assert_eq!(disconnects(&bus.sent), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_idle_beyond_connection_timeout()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 03_03_04 §5: the device closes a connection idle for 6 s.
        let inbox = vec![control_from_dev(tpci::t_ack(0))];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        assert!(
            !l4.idle_beyond_connection_timeout(),
            "the peer never showed itself"
        );
        l4.send_data(0x300, &[]).await?;
        assert!(!l4.idle_beyond_connection_timeout());
        let earlier = Instant::now()
            .checked_sub(CONNECTION_TIMEOUT + Duration::from_secs(1))
            .ok_or("clock too young")?;
        l4.last_traffic = earlier;
        assert!(l4.idle_beyond_connection_timeout());
        Ok(())
    }

    #[tokio::test]
    async fn sequence_wraps_around_at_fifteen()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Send 17 acknowledged requests (send_data only, no response) to focus on
        // send-sequence wraparound. await_ack matches the seq we sent, so script
        // one T_ACK per expected seq: 0..15 then wrap to 0, 1.
        let mut inbox = Vec::new();
        for i in 0..17u8 {
            inbox.push(control_from_dev(tpci::t_ack(i & 0x0f)));
        }
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        for _ in 0..17 {
            l4.send_data(0x300, &[0x00]).await?;
        }
        // After 17 sends starting at 0, the next send seq is 17 mod 16 = 1.
        assert_eq!(l4.send_seq, 1);
        Ok(())
    }

    #[tokio::test]
    async fn recv_sequence_wraps_around_at_fifteen()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        for _ in 0..18 {
            let (apci, _data) = l4.request(0x300, &[0x00]).await?;
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
        Ok(())
    }

    #[tokio::test]
    async fn device_retransmit_across_wrap_is_reacked_not_redelivered()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        for _ in 0..15 {
            l4.request(0x300, &[0x00]).await?;
        }
        assert_eq!(l4.recv_seq, 15);
        // The 16th delivers the FRESH answer (0xBB), not the stale duplicate.
        let (_apci, data) = l4.request(0x300, &[0x00]).await?;
        assert_eq!(
            data,
            vec![0xBB],
            "the stale retransmit must not be delivered"
        );
        assert_eq!(
            l4.recv_seq, 0,
            "recv_seq wrapped 15 -> 0 after the real NDT"
        );
        Ok(())
    }

    #[tokio::test]
    async fn authorize_free_access_grants_level_zero()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Script: ACK(0) for our authorize request, then A_Authorize_Response(0).
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x00]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let outcome = l4.authorize(crate::apci::FREE_ACCESS_KEY).await?;
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
            .ok_or("an A_Authorize_Request must have been sent")?;
        assert_eq!(sent_ndt, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        Ok(())
    }

    #[tokio::test]
    async fn authorize_nonzero_level_is_denied()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x03]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let outcome = l4.authorize(0x0011_2233).await?;
        assert_eq!(outcome, AuthorizeOutcome::Denied { level: 3 });
        // authorize_or_fail turns that into an explicit AccessDenied error.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x03]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let err = l4
            .authorize_or_fail(0x0011_2233)
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(
            matches!(err, MgmtError::AccessDenied { level: 3, .. }),
            "got {err:?}"
        );
        assert!(
            err.device_present(),
            "access-denied means the device is present"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_authorize_minimum_level_15_is_denied()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 03_03_07 §3.5.7: an invalid key sets the minimum level, 15 on a
        // device with sixteen levels.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_AUTHORIZE_RESPONSE, &[0x0F]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let outcome = l4.authorize(0x0011_2233).await?;
        assert_eq!(outcome, AuthorizeOutcome::Denied { level: 15 });
        assert!(!outcome.grants(15));
        Ok(())
    }

    #[test]
    fn test_decode_device_descriptor_checks_the_echoed_type()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ok = decode_device_descriptor(
            dev(),
            crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            &[0x07, 0xB0],
        )?;
        assert_eq!(ok, 0x07B0);
        let unsupported =
            decode_device_descriptor(dev(), crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE | 0x3F, &[]);
        assert!(matches!(
            unsupported,
            Err(MgmtError::DescriptorTypeUnsupported { requested: 0, .. })
        ));
        let other = decode_device_descriptor(
            dev(),
            crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE | 0x02,
            &[0x07, 0xB0],
        );
        assert!(matches!(other, Err(MgmtError::MalformedResponse { .. })));
        Ok(())
    }

    #[tokio::test]
    async fn authorize_non_authorize_reply_is_unsupported_and_tolerated()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A device that answers with a non-authorize APCI (does not implement the
        // service): the outcome is Unsupported and authorize_or_fail returns Ok
        // (tolerate-and-continue), leaving the connection usable.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, crate::apci::A_DEVICE_DESCRIPTOR_RESPONSE, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let outcome = l4.authorize_or_fail(crate::apci::FREE_ACCESS_KEY).await?;
        assert!(
            matches!(outcome, AuthorizeOutcome::Unsupported { .. }),
            "got {outcome:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn authorize_no_response_is_unsupported()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The device ACKs but never answers (empty inbox after the ACK forces the
        // response timeout): a NoResponse folds to Unsupported (tolerated), not an
        // error — an unkeyed device that does not implement authorize is expected.
        let inbox = vec![control_from_dev(tpci::t_ack(0))];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let outcome = l4.authorize(crate::apci::FREE_ACCESS_KEY).await?;
        assert!(
            matches!(outcome, AuthorizeOutcome::Unsupported { .. }),
            "got {outcome:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_authorize_silent_device_keeps_the_connection_usable() -> Result<()> {
        // The device T_ACKs the authorize request but never answers it (it does
        // not implement authorize). The outcome is Unsupported AND the connection
        // must stay open: before the fix the response timeout left it marked
        // closed, so the very next request failed with `Disconnected` without
        // ever reaching the wire.
        let inbox = vec![control_from_dev(tpci::t_ack(0))];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let outcome = l4.authorize(crate::apci::FREE_ACCESS_KEY).await?;
        assert!(
            matches!(outcome, AuthorizeOutcome::Unsupported { .. }),
            "got {outcome:?}"
        );
        // The script is exhausted, so the next request times out on the wire;
        // what matters is that it is *sent* rather than refused as Disconnected.
        let err = l4.send_data(crate::apci::A_AUTHORIZE_REQUEST, &[]).await;
        assert!(
            !matches!(err, Err(MgmtError::Disconnected { .. })),
            "a device without authorize must leave the connection usable, got {err:?}"
        );
        Ok(())
    }

    // --- KNX Data Secure seam (issue #71, spec §6) ---

    use bussard_secure::{A_SECURE_DATA, DataSecureSession, Key16, Sequence, TpAddressing, asdu};

    /// The addressing context for a device→tool response frame (source = device,
    /// dest = tool), matching what the connection reconstructs on receive.
    fn dev_to_tool_addr(tpci: u8) -> TpAddressing {
        TpAddressing {
            source: dev().raw(),
            destination: tool().raw(),
            address_type_group: false,
            extended_frame_format: 0,
            tpci,
        }
    }

    /// A scripted bus that also plays the device side of the S-A_Sync handshake:
    /// when the tool sends an S-A_Sync_Req it decodes it with `key` and queues the
    /// device's T_ACK and S-A_Sync_Res (device transport sequence 0) in front of
    /// the scripted inbox. Scripted frames therefore use tool sequence 1 and
    /// device sequence 1 onwards, exactly like the ETS capture.
    struct SyncingBus {
        inner: ScriptedBus,
        key: [u8; 16],
        /// The device's next Data Secure send sequence, reported in the Sync_Res.
        device_sequence: u64,
        /// How many Sync_Reqs the device T_ACKs without answering before it
        /// answers one (`u32::MAX`: it never answers), modelling a security
        /// layer that is not ready yet after a reboot (issue #166).
        unanswered_syncs: u32,
        /// How many Sync_Reqs the device has received.
        sync_reqs: u32,
    }

    impl SyncingBus {
        fn new(key: [u8; 16], inbox: Vec<CemiFrame>) -> Self {
            SyncingBus {
                inner: ScriptedBus::new(inbox),
                key,
                device_sequence: 1,
                unanswered_syncs: 0,
                sync_reqs: 0,
            }
        }

        fn sent(&self) -> &[CemiFrame] {
            &self.inner.sent
        }
    }

    impl BusConnection for SyncingBus {
        async fn send(&mut self, frame: CemiFrame) -> bussard_transport::Result<()> {
            if let (Tpci::Other(t), Apdu::Other { apci, data }) = (&frame.tpci, &frame.apdu)
                && *apci == A_SECURE_DATA
                && data.first() == Some(&0x92)
            {
                let req_addr = TpAddressing {
                    source: frame.source.raw(),
                    destination: dev().raw(),
                    address_type_group: false,
                    extended_frame_format: 0,
                    tpci: *t,
                };
                let key = Key16::new(self.key);
                if let Ok((_, req)) = asdu::decode_sync_req(&key, data, &req_addr) {
                    let mut front = vec![control_from_dev(tpci::t_ack((t >> 2) & 0x0F))];
                    self.sync_reqs += 1;
                    if self.unanswered_syncs > 0 {
                        self.unanswered_syncs -= 1;
                    } else {
                        let res = asdu::encode_sync_res(
                            &key,
                            bussard_secure::Scf::tool_sync(bussard_secure::SecureService::SyncRes),
                            &asdu::SyncResponse {
                                responder_sequence: Sequence::new(self.device_sequence),
                                requester_sequence: req.sequence,
                            },
                            &req.challenge,
                            Sequence::new(0x0000_1234_5678),
                            &dev_to_tool_addr(tpci::ndt(0)),
                        )
                        .map_err(|_| bussard_transport::TransportError::Closed)?;
                        front.push(ndt_from_dev(0, A_SECURE_DATA, &res));
                    }
                    for f in front.into_iter().rev() {
                        self.inner.inbox.push_front(f);
                    }
                }
            }
            self.inner.send(frame).await
        }

        async fn recv(&mut self) -> bussard_transport::Result<TimestampedFrame> {
            self.inner.recv().await
        }

        async fn close(self) -> bussard_transport::Result<()> {
            Ok(())
        }
    }

    /// PLAIN PATH BYTE-IDENTITY: a plain connection emits NO A_SecureData
    /// (`0x03F1`) anywhere on the wire — the sent APDU is exactly the caller's.
    #[tokio::test]
    async fn plain_path_emits_no_secure_data() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 = Layer4Connection::connect(&mut bus, dev(), tool()).await?;
        let (apci, data) = l4.request(0x300, &[0x00]).await?;
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        // No frame we sent carries the A_SecureData APCI, and the request NDT's
        // APCI is the plain 0x300 the caller asked for.
        for f in &bus.sent {
            if let (Tpci::Other(_), Apdu::Other { apci, .. }) = (&f.tpci, &f.apdu) {
                assert_ne!(*apci, A_SECURE_DATA, "plain path must never emit 0x03F1");
            }
        }
        Ok(())
    }

    /// ACTIVATED PATH: a secure connection wraps every management APDU in an
    /// A_SecureData (`0x03F1`) with a valid SCF, 6-byte sequence, and MAC; the
    /// device (a peer session with the same tool key) decodes it exactly.
    #[tokio::test]
    async fn activated_path_wraps_management_apdu() -> Result<()> {
        let key = [0x24u8; 16];
        // Device-side session that builds the secured response, sharing the
        // tool key. Its sequence starts above the Sync_Res's device sequence (1).
        let mut device =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1));

        // The tool's secure layer with a fixed starting sequence.
        let tool_session =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000));
        let secure = crate::secure::SecureLayer::activated(tool_session);

        // The secured RESPONSE (inner = A_DeviceDescriptor_Response 0x340, data
        // 07B0) at device transport sequence 1 (0 carried the Sync_Res).
        let resp_tpci = tpci::ndt(1);
        let (resp_apci, resp_asdu) = device
            .wrap(&dev_to_tool_addr(resp_tpci), 0x340, &[0x07, 0xB0])
            .map_err(|source| MgmtError::Secure {
                address: dev(),
                source,
            })?;
        assert_eq!(resp_apci, A_SECURE_DATA);

        let inbox = vec![
            control_from_dev(tpci::t_ack(1)),
            ndt_from_dev(1, resp_apci, &resp_asdu),
        ];
        let mut bus = SyncingBus::new(key, inbox);
        let mut l4 = Layer4Connection::connect_with_secure(
            &mut bus,
            dev(),
            tool(),
            Timeouts::default(),
            secure,
        )
        .await?;

        // Send a plain-looking request; it must go out wrapped, after the sync.
        let (apci, data) = l4.request(0x300, &[0x00]).await?;
        assert_eq!(apci, 0x340);
        assert_eq!(data, vec![0x07, 0xB0]);
        drop(l4);

        let numbered: Vec<&CemiFrame> = bus
            .sent()
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .collect();
        assert_eq!(numbered.len(), 2, "Sync_Req, then the wrapped request");
        let payload = |f: &CemiFrame| match (&f.tpci, &f.apdu) {
            (Tpci::Other(_), Apdu::Other { apci, data }) => Some((*apci, data.clone())),
            _ => None,
        };
        let (sync_apci, sync_data) =
            payload(numbered[0]).ok_or(MgmtError::Disconnected { address: dev() })?;
        assert_eq!(sync_apci, A_SECURE_DATA);
        assert_eq!(
            sync_data[0], 0x92,
            "the first numbered frame is S-A_Sync_Req"
        );
        let (wire_apci, wire_data) =
            payload(numbered[1]).ok_or(MgmtError::Disconnected { address: dev() })?;
        assert_eq!(wire_apci, A_SECURE_DATA, "activated path must emit 0x03F1");

        // Decode the wrapped request from the device side and confirm the SCF,
        // sequence and inner APDU are correct.
        let req_addr = TpAddressing {
            source: tool().raw(),
            destination: dev().raw(),
            address_type_group: false,
            extended_frame_format: 0,
            tpci: numbered[1].tpci_octet(),
        };
        let decoded = asdu::decode(&Key16::new(key), &wire_data, &req_addr).map_err(|source| {
            MgmtError::Secure {
                address: dev(),
                source,
            }
        })?;
        assert!(decoded.scf.tool_access, "tool-access SCF bit set");
        // As in the ETS capture: the first S-A_Data reuses the Sync_Req's
        // sequence, which the Sync_Res handed back.
        assert_eq!(decoded.sequence, Sequence::new(1000), "the seeded sequence");
        assert_eq!(&sync_data[1..7], &Sequence::new(1000).to_bytes());
        assert_eq!(decoded.apci, 0x300);
        assert_eq!(decoded.data, vec![0x00]);
        Ok(())
    }

    /// A device that T_ACKs the S-A_Sync_Req but never answers it surfaces as a
    /// dedicated Data Secure error, not as "device absent".
    #[tokio::test]
    async fn activated_path_reports_an_unanswered_sync() -> Result<()> {
        let key = [0x24u8; 16];
        let secure = crate::secure::SecureLayer::activated(
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000)),
        );
        let mut bus = SyncingBus::new(key, Vec::new());
        bus.unanswered_syncs = u32::MAX;
        let mut l4 =
            Layer4Connection::connect_with_secure(&mut bus, dev(), tool(), fast(), secure).await?;
        l4.set_sync_retry(SyncRetry::default().with_backoff_cap(Duration::from_millis(1)));
        let err = l4.request(0x300, &[0x00]).await.err();
        assert!(
            matches!(
                err,
                Some(MgmtError::Secure {
                    source: bussard_secure::AsduError::SyncUnanswered,
                    ..
                })
            ),
            "got {err:?}"
        );
        drop(l4);
        assert_eq!(
            bus.sync_reqs,
            SyncRetry::default().attempts,
            "an unanswered Sync_Req is repeated before the error (issue #166)"
        );
        Ok(())
    }

    /// Issue #166: a device whose security layer is not ready yet T_ACKs the
    /// first S-A_Sync_Reqs without answering; the connection repeats the request
    /// on the same link, with a fresh challenge and the next transport sequence,
    /// and syncs once the device answers.
    #[tokio::test]
    async fn test_ensure_secure_sync_retries_an_unanswered_sync_req() -> Result<()> {
        let key = [0x24u8; 16];
        let secure = crate::secure::SecureLayer::activated(
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000)),
        );
        let mut bus = SyncingBus::new(key, Vec::new());
        bus.unanswered_syncs = 2;
        let mut l4 =
            Layer4Connection::connect_with_secure(&mut bus, dev(), tool(), fast(), secure).await?;
        l4.set_sync_retry(SyncRetry::default().with_backoff_cap(Duration::from_millis(1)));
        l4.ensure_secure_sync().await?;
        assert!(l4.secure.is_synced(), "the third Sync_Req is answered");
        assert!(!l4.closed, "the retried connection stays open");
        drop(l4);
        assert_eq!(bus.sync_reqs, 3);
        let sync_tpcis: Vec<u8> = bus
            .sent()
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .map(CemiFrame::tpci_octet)
            .collect();
        assert_eq!(
            sync_tpcis,
            vec![tpci::ndt(0), tpci::ndt(1), tpci::ndt(2)],
            "each acknowledged attempt advances the transport sequence"
        );
        Ok(())
    }

    /// Issue #166: the plain readiness probe goes out in the clear on a
    /// security-activated connection and does not start the S-A_Sync handshake.
    #[tokio::test]
    async fn test_read_device_descriptor_unsecured_skips_the_sync() -> Result<()> {
        let key = [0x24u8; 16];
        let secure = crate::secure::SecureLayer::activated(
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000)),
        );
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = SyncingBus::new(key, inbox);
        let mut l4 =
            Layer4Connection::connect_with_secure(&mut bus, dev(), tool(), fast(), secure).await?;
        assert!(l4.is_secure());
        let descriptor = read_device_descriptor_unsecured(&mut l4).await?;
        assert_eq!(descriptor, 0x07B0);
        assert!(l4.secure.needs_sync(), "the probe does not sync");
        drop(l4);
        assert_eq!(bus.sync_reqs, 0);
        let numbered: Vec<u16> = bus
            .sent()
            .iter()
            .filter_map(|f| match (&f.tpci, &f.apdu) {
                (Tpci::Other(_), Apdu::Other { apci, .. }) => Some(*apci),
                _ => None,
            })
            .collect();
        assert_eq!(numbered, vec![0x300], "one plain A_DeviceDescriptor_Read");
        Ok(())
    }

    /// WIRE ROUND-TRIP: the peer must be able to rebuild the CCM nonce from the
    /// ENCODED frame alone. The wrapped request is encoded to cEMI bytes and
    /// decoded back, and the MAC is then verified using only what the decoded
    /// frame carries (source, destination, TPCI octet).
    ///
    /// This is the shape of the divergence the knx-sim conformance loop caught
    /// (issue #71): the nonce's TPCI octet was built from a value the receiver
    /// could not reproduce, so every frame failed the peer's MAC check while
    /// bussard's own constructed-frame tests passed.
    #[tokio::test]
    async fn activated_path_mac_verifies_from_a_decoded_cemi_frame()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = [0x24u8; 16];
        let tool_session =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000));
        let secure = crate::secure::SecureLayer::activated(tool_session);

        let inbox = vec![control_from_dev(tpci::t_ack(1))];
        let mut bus = SyncingBus::new(key, inbox);
        let mut l4 = Layer4Connection::connect_with_secure(
            &mut bus,
            dev(),
            tool(),
            Timeouts::default(),
            secure,
        )
        .await?;
        l4.send_data(0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]).await?;

        drop(l4);
        let request = bus
            .sent()
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .nth(1)
            .ok_or("a numbered request was sent after the Sync_Req")?;

        // Round-trip through the wire encoding: this is exactly what a device
        // (or the simulator) receives.
        let wire = request.encode();
        let decoded = CemiFrame::decode(&wire).map_err(|e| format!("the frame decodes: {e}"))?;
        let (apci, asdu_bytes) = match (&decoded.tpci, &decoded.apdu) {
            (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
            other => panic!("expected a data APDU, got {other:?}"),
        };
        assert_eq!(apci, A_SECURE_DATA);

        // Rebuild the addressing context from the DECODED frame only.
        let addr = TpAddressing {
            source: decoded.source.raw(),
            destination: decoded
                .individual_destination()
                .ok_or("individually addressed")?
                .raw(),
            address_type_group: false,
            extended_frame_format: decoded.control2.extended_frame_format,
            tpci: decoded.tpci_octet(),
        };
        let inner = asdu::decode(&Key16::new(key), &asdu_bytes, &addr)
            .map_err(|e| format!("the MAC verifies from the decoded frame: {e}"))?;
        assert_eq!(inner.apci, 0x3D1);
        assert_eq!(inner.data, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        Ok(())
    }

    /// The PID 59 write of a device whose counter is ahead of `clock` writes
    /// the device's counter, and the confirmation the device protects with
    /// the value written verifies (issue #535, KNX 3/5/1 §6.3.13.3 NOTE 110).
    async fn pid59_round_trip(device_sequence: u64, clock: u64) -> Result<u64> {
        let key = [0x24u8; 16];
        let expected = crate::ip_secure::sequence_number_to_write(clock, Some(device_sequence));
        // The device answers the write already under the new value.
        let mut device =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(expected));
        let (resp_apci, resp_asdu) = device
            .wrap(
                &dev_to_tool_addr(tpci::ndt(1)),
                0x1CF,
                &[0x00, 0x11, 0x00, 0x10, 0x3B, 0x01, 0x00, 0x01, 0x00],
            )
            .map_err(|source| MgmtError::Secure {
                address: dev(),
                source,
            })?;
        let inbox = vec![
            control_from_dev(tpci::t_ack(1)),
            ndt_from_dev(1, resp_apci, &resp_asdu),
        ];
        let mut bus = SyncingBus::new(key, inbox);
        bus.device_sequence = device_sequence;
        let tool_session =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000));
        let mut l4 = Layer4Connection::connect_with_secure(
            &mut bus,
            dev(),
            tool(),
            fast(),
            crate::secure::SecureLayer::activated(tool_session),
        )
        .await?;
        let written = crate::ip_secure::write_sequence_number(&mut l4, clock).await?;
        assert_eq!(written, expected);
        // A frame below the new value is now stale.
        assert_eq!(l4.device_next_sequence(), Some(expected + 1));
        Ok(written)
    }

    #[tokio::test]
    async fn test_write_sequence_number_device_ahead_of_clock() -> Result<()> {
        let device = 0x0000_F000_0000_0000 >> 16;
        assert_eq!(pid59_round_trip(device, 1_000).await?, device);
        Ok(())
    }

    #[tokio::test]
    async fn test_write_sequence_number_clock_ahead_of_device() -> Result<()> {
        assert_eq!(pid59_round_trip(5, 1_000_000).await?, 1_000_000);
        Ok(())
    }

    #[test]
    fn test_sequence_number_to_write_never_lowers() {
        use crate::ip_secure::sequence_number_to_write;
        assert_eq!(sequence_number_to_write(100, None), 100);
        assert_eq!(sequence_number_to_write(100, Some(7)), 100);
        assert_eq!(sequence_number_to_write(100, Some(900)), 900);
    }

    /// ACTIVATED PATH REJECTS A WRONG MAC: a secured response whose MAC does not
    /// verify (built with the wrong key) is rejected as an MgmtError::Secure, not
    /// accepted as an answer.
    #[tokio::test]
    async fn activated_path_rejects_wrong_mac_response()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = [0x24u8; 16];
        // The device builds its response with the WRONG key.
        let mut evil = DataSecureSession::new(Key16::new([0x99u8; 16]));
        let tool_session =
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(1000));
        let secure = crate::secure::SecureLayer::activated(tool_session);

        let resp_tpci = tpci::ndt(1);
        let (resp_apci, resp_asdu) = {
            let addr = dev_to_tool_addr(resp_tpci);
            evil.wrap(&addr, 0x340, &[0x07, 0xB0])?
        };

        let inbox = vec![
            control_from_dev(tpci::t_ack(1)),
            ndt_from_dev(1, resp_apci, &resp_asdu),
            // After the bad response is rejected, the connection times out waiting
            // for a real one (empty inbox), which is fine for this assertion.
        ];
        let mut bus = SyncingBus::new(key, inbox);
        let mut l4 =
            Layer4Connection::connect_with_secure(&mut bus, dev(), tool(), fast(), secure).await?;

        let err = l4
            .request(0x300, &[0x00])
            .await
            .err()
            .ok_or("expected an error")?;
        assert!(
            matches!(err, MgmtError::Secure { .. }),
            "a wrong-MAC secured response must be rejected, got {err:?}"
        );
        Ok(())
    }

    // --- negative L_Data.con (issue #45) ---

    /// The interface's `L_Data.con` of our tool→device frame with `octet`,
    /// negative (error bit set) or positive.
    fn con_for_dev(octet: u8, negative: bool) -> CemiFrame {
        let mut frame = CemiFrame::t_control(dev(), tool(), octet);
        frame.message_code = bussard_transport::cemi::MessageCode::LDataCon;
        frame.control1.error = negative;
        frame
    }

    /// [`fast`] with the discovery opt-in set.
    fn fast_discovery() -> Timeouts {
        Timeouts {
            absent_on_negative_confirmation: true,
            ..fast()
        }
    }

    fn ndt_sends(bus: &ScriptedBus) -> usize {
        bus.sent
            .iter()
            .filter(|f| matches!(tpci::classify(f.tpci_octet()), TpciKind::NumberedData(_)))
            .count()
    }

    #[tokio::test]
    async fn test_request_negative_con_classifies_absent_under_discovery()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The live shape: the T_Connect to an absent address comes back as a
        // negative con. Under the discovery budget that is "absent" at once:
        // no ACK wait, no repetition.
        let mut bus = ScriptedBus::new(vec![con_for_dev(tpci::T_CONNECT, true)]);
        let mut l4 =
            Layer4Connection::connect_with(&mut bus, dev(), tool(), fast_discovery()).await?;
        let started = std::time::Instant::now();
        let err = l4
            .request(0x300, &[])
            .await
            .err()
            .ok_or("a negative con must fail the request")?;
        assert!(
            matches!(err, MgmtError::NotConfirmed { address } if address == dev()),
            "got {err:?}"
        );
        assert!(!err.device_present(), "a negative con means absent");
        assert!(
            started.elapsed() < fast().ack_timeout,
            "classified before the ACK timeout"
        );
        drop(l4);
        assert_eq!(ndt_sends(&bus), 1, "no repetition after a negative con");
        Ok(())
    }

    #[tokio::test]
    async fn test_request_negative_con_on_t_connect_fails_on_every_budget()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 03_03_04 §5.4.3 E20, A5: the device never received the T_Connect,
        // so it ignores every data telegram that follows. A programming
        // session or a post-restart readiness probe fails at once, without
        // the ACK wait, and sends no T_Disconnect (the connection never
        // opened). The readiness probe's caller retries (#212).
        let mut bus = ScriptedBus::new(vec![con_for_dev(tpci::T_CONNECT, true)]);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let started = std::time::Instant::now();
        let err = l4
            .request(0x300, &[])
            .await
            .err()
            .ok_or("a rejected connect must fail the request")?;
        assert!(matches!(err, MgmtError::NotConfirmed { .. }), "got {err:?}");
        assert!(
            started.elapsed() < fast().ack_timeout,
            "failed before the ACK timeout"
        );
        l4.disconnect().await?;
        assert_eq!(ndt_sends(&bus), 1, "no repetition after a rejected connect");
        assert!(
            !bus.sent
                .iter()
                .any(|f| f.tpci_octet() == tpci::T_DISCONNECT),
            "nothing to disconnect"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_request_negative_con_on_ndt_ignored_without_opt_in()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A negative con for the first data telegram (not the connect) only
        // classifies under discovery; every other budget keeps the ACK timeout
        // and the repetitions, and the error is the old NoResponse.
        let mut bus = ScriptedBus::new(vec![con_for_dev(tpci::ndt(0), true)]);
        let mut l4 = Layer4Connection::connect_with(&mut bus, dev(), tool(), fast()).await?;
        let err = l4
            .request(0x300, &[])
            .await
            .err()
            .ok_or("a silent device must fail the request")?;
        assert!(matches!(err, MgmtError::NoResponse { .. }), "got {err:?}");
        drop(l4);
        assert_eq!(ndt_sends(&bus), 2, "one initial send plus one retransmit");
        Ok(())
    }

    #[tokio::test]
    async fn test_request_positive_con_keeps_the_present_path()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A present device under discovery: positive cons for both our frames,
        // then the ACK and the answer. Result and sent frames are those of the
        // no-con happy path.
        let inbox = vec![
            con_for_dev(tpci::T_CONNECT, false),
            con_for_dev(tpci::ndt(0), false),
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 =
            Layer4Connection::connect_with(&mut bus, dev(), tool(), fast_discovery()).await?;
        let (apci, data) = l4.request(0x300, &[]).await?;
        assert_eq!((apci, data), (0x340, vec![0x07, 0xB0]));
        drop(l4);

        let mut plain = ScriptedBus::new(vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
        ]);
        let mut l4 = Layer4Connection::connect_with(&mut plain, dev(), tool(), fast()).await?;
        l4.request(0x300, &[]).await?;
        drop(l4);
        assert_eq!(bus.sent, plain.sent, "byte-identical frames");
        Ok(())
    }

    #[tokio::test]
    async fn test_request_negative_con_after_first_exchange_is_ignored()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Only the connect and the first numbered telegram classify: once the
        // device has acknowledged something it is present, and a later
        // negative con (a lost frame mid-session) falls back to the ACK wait.
        let inbox = vec![
            control_from_dev(tpci::t_ack(0)),
            ndt_from_dev(0, 0x340, &[0x07, 0xB0]),
            con_for_dev(tpci::ndt(1), true),
        ];
        let mut bus = ScriptedBus::new(inbox);
        let mut l4 =
            Layer4Connection::connect_with(&mut bus, dev(), tool(), fast_discovery()).await?;
        l4.request(0x300, &[]).await?;
        let err = l4
            .request(0x300, &[])
            .await
            .err()
            .ok_or("the second request goes unanswered")?;
        assert!(
            !matches!(err, MgmtError::NotConfirmed { .. }),
            "a mid-session negative con must not classify absent: {err:?}"
        );
        Ok(())
    }
}
