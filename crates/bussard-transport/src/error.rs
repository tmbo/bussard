//! Error and result types shared across the transport crate.

use std::io;
use std::net::SocketAddr;

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

    /// An operation exceeded its configured timeout.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),

    /// The heartbeat failed after all retries; the connection is considered dead.
    #[error("connection state heartbeat failed after retries; gateway unreachable")]
    HeartbeatLost,

    /// The remote peer initiated a disconnect.
    #[error("gateway disconnected (channel {0})")]
    Disconnected(u8),

    /// The connection has already been closed locally.
    #[error("connection is closed")]
    Closed,

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

impl From<io::Error> for TransportError {
    fn from(source: io::Error) -> Self {
        TransportError::Io { peer: None, source }
    }
}
