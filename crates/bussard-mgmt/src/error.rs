//! Error types for the management layer.
//!
//! The central distinction, called out in the crate docs, is between a device
//! that is **absent** (no reaction at all — [`MgmtError::NoResponse`]) and a
//! device that is **present but refusing** (it disconnected, NAKed, or answered
//! with an error). Callers such as `bussard scan` treat the two very
//! differently.

use bussard_model::IndividualAddress;
use bussard_transport::TransportError;

/// Result alias for the management layer.
pub type Result<T> = std::result::Result<T, MgmtError>;

/// Errors from connection-oriented device management.
#[derive(Debug, thiserror::Error)]
pub enum MgmtError {
    /// The device did not react at all within the timeout: no `T_ACK`, no
    /// response telegram. This is the signal that the device is **absent** (the
    /// address is unused). Scanning treats this as "not present".
    #[error("no response from {address} (device absent)")]
    NoResponse {
        /// The address that did not answer.
        address: IndividualAddress,
    },

    /// The device sent a `T_NAK` for a numbered data telegram after all
    /// retransmissions. The device is **present** but rejected the telegram.
    #[error("{address} negatively acknowledged (T_NAK) after retries")]
    Nak {
        /// The address that NAKed.
        address: IndividualAddress,
    },

    /// The device disconnected (sent `T_Disconnect`) or a protocol error forced
    /// the connection down. The device is **present** but the session failed.
    #[error("connection to {address} was disconnected")]
    Disconnected {
        /// The address whose connection dropped.
        address: IndividualAddress,
    },

    /// A management response could not be parsed (too short, unexpected APCI).
    /// The device answered but not in the shape we expected.
    #[error("malformed response from {address}: {reason}")]
    MalformedResponse {
        /// The address that answered.
        address: IndividualAddress,
        /// What was wrong with the response.
        reason: &'static str,
    },

    /// An underlying transport error (socket, gateway, framing).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl MgmtError {
    /// Whether this error indicates the device is **present** (as opposed to
    /// simply absent). A NAK, disconnect or malformed response all mean a device
    /// answered in some way; only [`MgmtError::NoResponse`] means absent.
    pub fn device_present(&self) -> bool {
        !matches!(self, MgmtError::NoResponse { .. })
    }
}
