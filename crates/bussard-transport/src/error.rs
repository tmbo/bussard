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

    /// The gateway rejected a request with a non-zero status byte. The
    /// message names the status code and its meaning when the KNXnet/IP
    /// specification defines it (issue #517).
    #[error(
        "gateway returned error status {status:#04x} ({context}){}",
        status_detail(.status)
    )]
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
        "interface {gateway} requires KNXnet/IP Secure (secure tunnelling only) and {reason}: \
         {hint}",
        hint = crate::guidance::tunnel_credentials_hint()
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

    /// The interface refused the TCP connect but its extended search
    /// advertises KNXnet/IP Secure. A unicast secure session runs over TCP
    /// only (KNX IP Secure 3/8/9 §2.2.3.3, §2.2.3.6.4; issue #513), so no
    /// other carrier is tried. Fatal: the interface is misconfigured, busy
    /// with its one TCP connection, or not the device the search described.
    #[error(
        "KNXnet/IP Secure: interface {gateway} advertises KNXnet/IP Secure but refused the TCP \
         connection. A KNXnet/IP Secure session runs over TCP only. Likely causes: secure \
         tunnelling is disabled or misconfigured on the interface, the interface already serves \
         as many TCP connections as it supports (often one, e.g. ETS or another client), or the \
         address belongs to a different device than the one that answered the search"
    )]
    SecureTcpRefused {
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

/// The name and meaning of a KNXnet/IP status code, or `None` for a code the
/// specification does not define.
///
/// The common codes are KNXnet/IP Core 3/8/2 §7.3; the CONNECT_RESPONSE codes
/// §7.8.2 Table 8 and Tunnelling 3/8/4 §2.2.2 and Table 11; the
/// CONNECTIONSTATE_RESPONSE codes Core §7.8.4 Table 9. No value is defined
/// twice, so one table serves every context.
pub fn status_name(status: u8) -> Option<(&'static str, &'static str)> {
    Some(match status {
        0x01 => (
            "E_HOST_PROTOCOL_TYPE",
            "the gateway does not support the requested host protocol",
        ),
        0x02 => (
            "E_VERSION_NOT_SUPPORTED",
            "the gateway does not support this KNXnet/IP protocol version",
        ),
        0x04 => (
            "E_SEQUENCE_NUMBER",
            "the gateway received a sequence number out of order",
        ),
        0x21 => (
            "E_CONNECTION_ID",
            "the gateway has no active connection with this channel id",
        ),
        0x22 => (
            "E_CONNECTION_TYPE",
            "the gateway does not support the requested connection type",
        ),
        0x23 => (
            "E_CONNECTION_OPTION",
            "the gateway does not support a requested connection option",
        ),
        E_NO_MORE_CONNECTIONS => (
            "E_NO_MORE_CONNECTIONS",
            "every tunnelling slot of the gateway is in use",
        ),
        0x25 => (
            "E_NO_MORE_UNIQUE_CONNECTIONS",
            "the gateway's free tunnelling slots share an individual address that \
             another connection already uses. Give every tunnelling address (PID 53, \
             the `[knxnet]` table of the interface's device file) a distinct value, with \
             ETS or `bussard apply` through another connection",
        ),
        0x26 => (
            "E_DATA_CONNECTION",
            "the gateway detected an error on the data connection",
        ),
        0x27 => (
            "E_KNX_CONNECTION",
            "the gateway detected an error on its KNX bus connection",
        ),
        0x28 => (
            "E_AUTHORISATION_ERROR",
            "the client is not authorised to use the requested individual address",
        ),
        0x29 => (
            "E_TUNNELLING_LAYER",
            "the gateway does not support the requested tunnelling layer",
        ),
        0x2D => (
            "E_NO_TUNNELLING_ADDRESS",
            "the requested individual address is not a tunnelling address",
        ),
        0x2E => (
            "E_CONNECTION_IN_USE",
            "the requested individual address is already in use",
        ),
        _ => return None,
    })
}

/// The `: NAME, meaning` suffix of a [`TransportError::GatewayStatus`]
/// message, empty for an undefined code.
fn status_detail(status: &u8) -> String {
    match status_name(*status) {
        Some((name, meaning)) => format!(": {name}, {meaning}"),
        None => String::new(),
    }
}

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
                | TransportError::SecureTcpRefused { .. }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_status_display_names_the_code() {
        let err = TransportError::GatewayStatus {
            status: 0x25,
            context: "CONNECT_RESPONSE",
        };
        let text = err.to_string();
        assert!(
            text.starts_with(
                "gateway returned error status 0x25 (CONNECT_RESPONSE): \
                 E_NO_MORE_UNIQUE_CONNECTIONS, "
            ),
            "{text}"
        );
        assert!(text.contains("PID 53"), "{text}");

        let err = TransportError::GatewayStatus {
            status: 0x27,
            context: "CONNECTIONSTATE_RESPONSE",
        };
        assert!(err.to_string().contains("E_KNX_CONNECTION"));
    }

    #[test]
    fn test_gateway_status_display_keeps_an_undefined_code_bare() {
        let err = TransportError::GatewayStatus {
            status: 0x7F,
            context: "TUNNELING_ACK",
        };
        assert_eq!(
            err.to_string(),
            "gateway returned error status 0x7f (TUNNELING_ACK)"
        );
    }

    #[test]
    fn test_status_name_covers_the_spec_tables() {
        for code in [
            0x01, 0x02, 0x04, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2D, 0x2E,
        ] {
            assert!(status_name(code).is_some(), "{code:#04x}");
        }
        assert_eq!(status_name(0x00), None);
    }
}
