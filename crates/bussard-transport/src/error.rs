//! Error and result types shared across the transport crate.

use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Errors produced by the transport layer: codec, framing and connection.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A byte buffer was too short to contain the structure being decoded.
    #[error("buffer too short: needed at least {needed} bytes, had {had} (decoding {context})")]
    Truncated {
        /// Minimum number of bytes required.
        needed: usize,
        /// Number of bytes actually available.
        had: usize,
        /// Human-readable description of what was being decoded.
        context: &'static str,
    },

    /// A field held a value the decoder does not understand.
    #[error("invalid {field}: {value:#04x}")]
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
        /// The value that was rejected.
        value: u16,
    },

    /// The KNXnet/IP header magic (`0x06 0x10`) was not present.
    #[error("bad KNXnet/IP header: expected 06 10, got {0:02x} {1:02x}")]
    BadHeader(u8, u8),

    /// The gateway rejected a request with a non-zero status byte.
    #[error("gateway returned error status {status:#04x} ({context})")]
    GatewayStatus {
        /// The status byte from the response.
        status: u8,
        /// Which exchange the status applies to.
        context: &'static str,
    },

    /// The gateway refused the CONNECT because every tunnelling slot is taken
    /// (`E_NO_MORE_CONNECTIONS`, status `0x24`).
    ///
    /// This is a capacity refusal, not a network fault: the gateway answered
    /// promptly and said no. A tunnelling interface has a fixed slot count
    /// (often one to five) and Home Assistant, ETS and a second bussard each
    /// hold one while connected.
    #[error(
        "the gateway has no free tunnelling connection (E_NO_MORE_CONNECTIONS, status 0x24): \
         every tunnel slot is already in use"
    )]
    NoMoreConnections,

    /// An operation exceeded its configured timeout.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),

    /// The heartbeat failed after all retries; the connection is considered dead.
    #[error("connection state heartbeat failed after retries; gateway unreachable")]
    HeartbeatLost,

    /// The gateway link was lost and the tunnel could not be re-established
    /// within the [`TunnelReconnect`](crate::config::TunnelReconnect) budget
    /// (issue #177). `cause` is the error that first signalled the loss (an
    /// unacknowledged TUNNELING_REQUEST, a failed heartbeat, a socket error).
    #[error(
        "{cause}; the tunnel to gateway {gateway} could not be re-established within {} s \
         (is the KNX IP interface powered and its LAN cable plugged in?)",
        .budget.as_secs()
    )]
    TunnelLost {
        /// The gateway the tunnel was connected to.
        gateway: SocketAddrV4,
        /// The re-establish budget that ran out.
        budget: std::time::Duration,
        /// The error that first signalled the loss.
        cause: Box<TransportError>,
    },

    /// The remote peer initiated a disconnect.
    #[error("gateway disconnected (channel {0})")]
    Disconnected(u8),

    /// The connection has already been closed locally.
    #[error("connection is closed")]
    Closed,

    /// The interface only accepts KNXnet/IP Secure tunnelling and bussard has no
    /// credentials for it (issue #182). Fatal: retrying cannot help.
    #[error(
        "interface {gateway} requires KNXnet/IP Secure (secure tunnelling only) and {reason}. \
         Pass --keyring <file.knxkeys> (password in BUSSARD_KEYRING_PASSWORD) exported from the \
         ETS project that holds the interface's tunnelling users, or --secure-user <id> \
         --secure-password-env <VAR>"
    )]
    SecureRequired {
        /// The gateway that refused the plain tunnel.
        gateway: SocketAddrV4,
        /// Why no secure session was attempted.
        reason: String,
    },

    /// A KNXnet/IP Secure session was asked for (the idle probe of issue
    /// #197) but the credentials select none for this gateway.
    #[error("no KNXnet/IP Secure session for {gateway}: {reason}")]
    SecureNotSelected {
        /// The gateway.
        gateway: SocketAddrV4,
        /// Why no secure session was selected.
        reason: String,
    },

    /// The interface refused the tunnelling user's password (SESSION_STATUS
    /// `STATUS_AUTHENTICATION_FAILED`). Fatal: retrying cannot help.
    #[error(
        "KNXnet/IP Secure: interface {gateway} refused tunnelling user {user_id} ({status}); \
         the user id or password does not match the interface's configuration (export a \
         current keyring from ETS, or check --secure-user / --secure-password-env)"
    )]
    SecureAuthFailed {
        /// The gateway.
        gateway: SocketAddrV4,
        /// The user id presented.
        user_id: u8,
        /// The status the interface answered.
        status: bussard_secure::ipsecure::SessionStatus,
    },

    /// The interface did not prove it knows the device authentication code
    /// from the keyring (SESSION_RESPONSE MAC mismatch). Fatal: either the
    /// keyring is stale or this is not the expected interface.
    #[error(
        "KNXnet/IP Secure: interface {gateway} did not prove the device authentication code \
         from the keyring (SESSION_RESPONSE MAC mismatch); the keyring is stale or {gateway} \
         is not the interface it describes. Refusing to authenticate to it"
    )]
    SecureServerUnverified {
        /// The gateway.
        gateway: SocketAddrV4,
    },

    /// The interface ended the secure session (SESSION_STATUS close, timeout
    /// or unauthenticated). Treated as a lost link and re-established.
    #[error("KNXnet/IP Secure session ended by the gateway ({0})")]
    SecureSessionEnded(bussard_secure::ipsecure::SessionStatus),

    /// A KNXnet/IP Secure frame could not be built or checked.
    #[error("KNXnet/IP Secure: {0}")]
    Secure(#[from] bussard_secure::ipsecure::IpSecureError),

    /// An underlying socket I/O error.
    #[error("socket error{}: {source}", .peer.map(|p| format!(" ({p})")).unwrap_or_default())]
    Io {
        /// The peer address involved, if known.
        peer: Option<SocketAddr>,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// The KNXnet/IP CONNECT_RESPONSE status meaning "no more connections"
/// (every tunnelling slot is occupied).
pub const E_NO_MORE_CONNECTIONS: u8 = 0x24;

impl TransportError {
    /// Whether retrying the connect cannot succeed without the operator
    /// changing something: a secure-only interface without credentials, a
    /// refused password, or an interface that failed its own authentication.
    /// The bus actor stops reconnecting on these (issue #182).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TransportError::SecureRequired { .. }
                | TransportError::SecureAuthFailed { .. }
                | TransportError::SecureServerUnverified { .. }
        )
    }

    /// Whether this error means the gateway link dropped in a way the bus
    /// recovers from on its own: a timeout, a failed heartbeat, a gateway
    /// disconnect or a socket error.
    ///
    /// Management sessions treat such an error like a Layer-4 connection death
    /// and resume once the bus is connected again (issue #177).
    /// [`TunnelLost`](TransportError::TunnelLost) is deliberately *not* a link
    /// loss in this sense: it is the terminal error after the tunnel's own
    /// re-establish budget ran out.
    pub fn is_link_loss(&self) -> bool {
        matches!(
            self,
            TransportError::Timeout(_)
                | TransportError::HeartbeatLost
                | TransportError::Disconnected(_)
                | TransportError::Io { .. }
                | TransportError::SecureSessionEnded(_)
        )
    }
}

impl From<io::Error> for TransportError {
    fn from(source: io::Error) -> Self {
        TransportError::Io { peer: None, source }
    }
}
