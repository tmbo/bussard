//! Test-only support for bussard: one mock KNXnet/IP gateway and one mock KNX
//! device, shared by every crate's integration tests.
//!
//! Before this crate, 28 test files carried their own copy of the same mock
//! (`fn run_gateway`, `fn run_mock`, `spawn_gateway`, ...). This crate is the
//! single implementation; since issue #87 no suite keeps a copy. It is a `publish = false` dev-dependency and never
//! part of the shipped binary.
//!
//! **Safety rule:** every constructor here binds `127.0.0.1:0`. Nothing in this
//! crate can reach a real gateway, and tests must never pass a non-loopback
//! address to the code under test.
//!
//! # Three layers
//!
//! - [`wire`]: raw primitives for protocol-level tests that script every
//!   datagram themselves. [`wire::RawGateway`] binds the socket, receives and
//!   parses datagrams, accepts a CONNECT, pushes indications and ACKs. It also
//!   has frame builders such as [`wire::connect_response_body`] and
//!   [`wire::description_response_body`].
//! - [`gateway`]: [`MockGateway`], a configurable tunnelling server running as a
//!   tokio task. It handles CONNECT, CONNECTIONSTATE (heartbeat), DISCONNECT,
//!   DESCRIPTION and TUNNELLING_REQUEST/ACK. It captures every cEMI frame the
//!   client sends, runs scripted responders, pushes indications on demand or
//!   after connect, and hosts a line of [`MockDevice`]s.
//! - [`secure_gateway`]: [`MockSecureGateway`], a secure-only KNXnet/IP
//!   interface (plain CONNECT refused with `0x22`, KNXnet/IP Secure session
//!   and tunnelling over TCP), for the Phase B client (issue #71).
//! - [`device`]: [`MockDevice`], a builder-configured KNX device that speaks
//!   transport-layer connected mode, broadcast management, and the System B
//!   load-state machine.
//!
//! # Feature union of the copies this crate replaces
//!
//! The list below was taken from all 28 copies (bussard-bus, -cli, -download,
//! -mcp, -mgmt, -monitor, -transport). Items marked *(native)* are built in.
//! Items marked *(hook)* are one-off behaviours: a suite scripts them with
//! [`MockDevice::with_hook`] or a gateway responder
//! ([`GatewayBuilder::respond`]), so the core stays small.
//!
//! KNXnet/IP:
//! - CONNECT for a tunnel link-layer connection. The response hands out tunnel
//!   IA 1.1.255 and carries a data HPAI of `127.0.0.1:port` *(native)*.
//! - CONNECT refusal with a status, e.g. `0x24` E_NO_MORE_CONNECTIONS or `0x22`
//!   *(native)*.
//! - CONNECTIONSTATE answered, or deliberately left unanswered *(native)*.
//! - DISCONNECT answered. The mock then stops, or keeps serving so a second
//!   client run can connect *(native)*.
//! - DESCRIPTION answered with a device-info DIB and a tunnelling-info DIB
//!   listing slots, some in use *(native)*.
//! - TUNNELLING_ACK sent with status 0, sent with a non-zero status, or never
//!   sent (ACK exhaustion) *(native)*.
//! - A link outage after frame N for a set time: every datagram is swallowed,
//!   then the old channel is dropped and the next CONNECT gets a new channel id,
//!   so the client re-establishes the tunnel ([`GatewayBuilder::outage`],
//!   issue #177) *(native)*.
//! - Protocol probes: duplicate, out-of-window and two-behind sequence numbers;
//!   unknown message codes; bursts during an ACK wait; a server-initiated
//!   DISCONNECT; control HPAI checks. All use [`wire::RawGateway`].
//!
//! cEMI and group traffic:
//! - Every client TUNNELLING_REQUEST is captured as a [`CemiFrame`]
//!   ([`MockGateway::sent`]) *(native)*.
//! - Unsolicited indications: pushed after connect, pushed after a delay, or
//!   pushed at any time from the test ([`MockGateway::push`]) *(native)*.
//! - Scripted reactions to group reads and writes, e.g. a read answered with a
//!   GroupValueResponse, an `L_Data.con` echo before the answer, or a status GA
//!   echoing a switch *(native, via responders)*.
//!
//! Broadcast management:
//! - A_IndividualAddress_Read and _Write, answered by devices in programming
//!   mode, including a "stuck" programming button *(native)*.
//! - A_IndividualAddress_SerialNumber_Read and _Write *(native)*.
//!
//! Transport layer (connected mode):
//! - T_Connect and T_Disconnect tracking with a 4-bit per-device sequence
//!   *(native)*.
//! - T_ACK, T_NAK and silence as reactions *(native)*.
//! - Death budgets, a folded ACK, retransmitting the previous response, and
//!   reboot silence until the next T_Connect *(hook)*.
//!
//! Application services:
//! - A_DeviceDescriptor_Read type 0 *(native)*.
//! - A_Authorize with a configurable level *(native)*.
//! - A_Memory_Read and _Write. The write is answered with a Memory_Response
//!   echo (verify mode) or with a bare T_ACK *(native)*.
//! - A_MemoryExtended_Read and _Write *(native)*.
//! - A_PropertyValue_Read and _Write on a generic property store: arrays with a
//!   start=0 count and writable properties *(native)*.
//! - PID_OBJECT_TYPE, PID_PROGMODE, PID_LOAD_STATE_CONTROL (including
//!   LdCtrlRelSegment), PID_TABLE_REFERENCE and PID_TABLE served from a segment
//!   image *(native)*.
//! - A_PropertyDescription_Read, answered with "no such property" *(native)*.
//! - A_Restart, counted and acknowledged only *(native)*.
//! - Master reset with erase codes, KNX Data Secure (A_SecureData, S-A_Sync),
//!   a System 7 memory-mapped LSM, PID_MCB_TABLE CRCs, and PID_TABLE writes
//!   *(hook)*.
//!
//! Scripting hooks (for suites that keep a de-mirrored device model of their
//! own and plug it in, rather than a gateway copy):
//! - [`Reaction::Script`] with [`Step`]s: a folded ACK (answer without
//!   `T_ACK`), a replay at a stale sequence ([`Step::DataAtSeq`]), a wrong APCI,
//!   several answers, raw control frames, verbatim frames and inline pauses.
//! - [`MockDevice::with_control_hook`]: reactions to the client's `T_Connect`,
//!   `T_Disconnect`, `T_ACK` and `T_NAK` (per-connection budgets, reboot
//!   silence, a refused connect).
//! - The request context a hook reads from the device: `client_seq`, `tool`,
//!   `request_tpci` (Data Secure nonces) and [`MockDevice::send_seq`].
//! - [`GatewayBuilder::intercept`]: traffic-dependent datagram faults (drop the
//!   tunnel after the Nth memory frame until the next CONNECT, a blackout that
//!   keeps the channel id).
//! - [`GatewayBuilder::push_once_after_connect`] (a push that skips a short
//!   probe connection) and [`MockGateway::with_line`] (swap devices between
//!   client runs).
//! - The gateway's send sequence restarts at 0 on every granted CONNECT.
//!
//! Device models and recording:
//! - Several devices on one line. System B presets with preloaded tables. A
//!   persistent NAK on writes into one table object. Non-System-B masks
//!   *(native)*.
//! - Counters (telegrams, writes, restarts, T_Connects) and a request log of
//!   `(apci, data)` pairs *(native)*.
//! - Gateway statistics: connects, disconnects, heartbeats, client ACKs and the
//!   KNXnet/IP services seen *(native)*.

pub mod consts;
pub mod device;
pub mod gateway;
pub mod secure_gateway;
pub mod wire;

pub use device::{ControlHook, Hook, MemoryWritePolicy, MockDevice, Reaction, Step};
pub use gateway::{AckPolicy, GatewayBuilder, GatewayStats, Inbound, MockGateway, Outage, Verdict};
pub use secure_gateway::{MockSecureGateway, SecureGatewayBuilder, SecureGatewayStats};
pub use wire::RawGateway;

use bussard_transport::cemi::CemiFrame;
use bussard_transport::knxnet::ServiceType;

/// The boxed error type test functions return. It is `Send + Sync` so that
/// results can cross a `tokio::spawn` boundary.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The result type test functions return: `fn test_x() -> TestResult { ...; Ok(()) }`.
pub type TestResult<T = ()> = Result<T, BoxError>;

/// Why a mock operation failed.
#[derive(Debug, thiserror::Error)]
pub enum MockError {
    /// The loopback socket failed.
    #[error("mock socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A datagram did not parse as KNXnet/IP.
    #[error("malformed KNXnet/IP datagram: {0}")]
    Transport(#[from] bussard_transport::TransportError),
    /// A different KNXnet/IP service arrived than the script expected.
    #[error("expected {expected:?}, got {got:?}")]
    UnexpectedService {
        /// The service the script waited for.
        expected: ServiceType,
        /// The service that arrived.
        got: ServiceType,
    },
    /// Nothing arrived within the deadline.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// The socket bound to something other than an IPv4 address.
    #[error("the mock socket is not bound to an IPv4 address")]
    NotIpv4,
    /// The mock's shared state lock was poisoned by a panicking holder.
    #[error("the mock state lock is poisoned")]
    Poisoned,
    /// No device with this individual address is on the mock line.
    #[error("no mock device at {0}")]
    NoDevice(bussard_model::IndividualAddress),
    /// The gateway task panicked or was cancelled.
    #[error("the mock gateway task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Parses a group address, for test fixtures: `ga("1/2/3")?`.
///
/// # Errors
/// Returns the parse error for a malformed address.
pub fn ga(s: &str) -> Result<bussard_model::GroupAddress, BoxError> {
    Ok(s.parse()?)
}

/// Parses an individual address, for test fixtures: `ia("1.1.10")?`.
///
/// # Errors
/// Returns the parse error for a malformed address.
pub fn ia(s: &str) -> Result<bussard_model::IndividualAddress, BoxError> {
    Ok(s.parse()?)
}

/// Returns the group destination of a captured frame as text, or an error when
/// the frame is not group-addressed. Saves the
/// `frame.group_destination().unwrap().to_string()` chain in assertions.
///
/// # Errors
/// Returns an error when `frame` has an individual destination.
pub fn group_dest(frame: &CemiFrame) -> Result<String, BoxError> {
    frame
        .group_destination()
        .map(|g| g.to_string())
        .ok_or_else(|| "frame has no group destination".into())
}
