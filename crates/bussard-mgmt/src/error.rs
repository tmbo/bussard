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
    ///
    /// `reason` is an owned `String` rather than a `&'static str` so decoders
    /// can fold the raw response evidence (APCI + payload bytes, hex) into the
    /// message — see [`raw_response_detail`]. That evidence lets a KNX Virtual
    /// / field run capture a malformed descriptor without a packet sniffer.
    #[error("malformed response from {address}: {reason}")]
    MalformedResponse {
        /// The address that answered.
        address: IndividualAddress,
        /// What was wrong with the response.
        reason: String,
    },

    /// A memory write-back verification failed: after writing a chunk, an
    /// `A_Memory_Read` of the same address returned octets that differ from what
    /// was written. Names the exact address, what was expected and what was read
    /// so the caller can pinpoint the diverging octet.
    #[error(
        "{address}: memory verify failed at {addr:#06X} (wrote {expected:02X?}, read back \
         {got:02X?})"
    )]
    MemoryVerifyFailed {
        /// The device.
        address: IndividualAddress,
        /// The address of the chunk that did not verify.
        addr: u16,
        /// The octets that were written.
        expected: Vec<u8>,
        /// The octets read back.
        got: Vec<u8>,
    },

    /// An underlying transport error (socket, gateway, framing).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl MgmtError {
    /// Whether this error indicates the device is **present** (as opposed to
    /// simply absent). A NAK, disconnect, malformed response or failed memory
    /// verify all mean a device answered in some way; only
    /// [`MgmtError::NoResponse`] means absent.
    pub fn device_present(&self) -> bool {
        !matches!(self, MgmtError::NoResponse { .. })
    }
}

/// Formats the raw response evidence for a [`MgmtError::MalformedResponse`]
/// reason: the response APCI and its payload octets in hex.
///
/// A malformed management response is only actionable if the exact bytes are
/// visible. Folding them into the error text means a KNX Virtual or field run
/// captures the evidence in its own output — no packet sniffer needed. The
/// format is stable and greppable: `APCI 0x0340, payload [07 B0]`.
pub fn raw_response_detail(apci: u16, payload: &[u8]) -> String {
    let bytes: Vec<String> = payload.iter().map(|b| format!("{b:02X}")).collect();
    format!("APCI {apci:#06X}, payload [{}]", bytes.join(" "))
}

/// Builds the `reason` for a device-descriptor read whose response was **not** a
/// well-formed `A_DeviceDescriptor_Response` (wrong selector or a short answer).
///
/// Names one non-conformance specially: a device that answers the read by
/// **echoing the request** — the response APCI is `A_DeviceDescriptor_Read`
/// (`0x0300`) rather than a `_Response` (`0x0340`). That is not a legal response
/// form; it means the device does not implement descriptor responses at all. The
/// KNX Virtual IP interface does exactly this, so the error names the pattern
/// (rather than a bare "unexpected response") to save a field engineer from
/// chasing a phantom protocol bug. Any other malformed answer folds in the raw
/// APCI + payload evidence via [`raw_response_detail`].
pub fn descriptor_response_reason(resp_apci: u16, data: &[u8]) -> String {
    // The echo: the peer answered the read with the read's own APCI (0x0300).
    if resp_apci == crate::apci::A_DEVICE_DESCRIPTOR_READ {
        return format!(
            "the device echoed the descriptor read instead of answering (APCI 0x0300); this \
             device does not implement descriptor responses (seen on the KNX Virtual IP \
             interface). ({})",
            raw_response_detail(resp_apci, data)
        );
    }
    format!(
        "expected A_DeviceDescriptor_Response but the response's descriptor type (low APCI \
         bits) is {} ({})",
        resp_apci & 0x3f,
        raw_response_detail(resp_apci, data),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_response_detail_is_greppable_hex() {
        assert_eq!(
            raw_response_detail(0x0340, &[0x07, 0xB0]),
            "APCI 0x0340, payload [07 B0]"
        );
    }

    #[test]
    fn raw_response_detail_handles_empty_payload() {
        assert_eq!(raw_response_detail(0x0000, &[]), "APCI 0x0000, payload []");
    }

    #[test]
    fn descriptor_reason_names_the_echo_pattern() {
        // The KNX Virtual IP interface answers A_DeviceDescriptor_Read with an
        // echo of the read (0x0300) rather than a Response (0x0340). The reason
        // must name that pattern verbatim, not report a bare "unexpected type".
        let reason = descriptor_response_reason(crate::apci::A_DEVICE_DESCRIPTOR_READ, &[]);
        assert!(
            reason.contains("echoed the descriptor read instead of answering"),
            "must name the echo: {reason}"
        );
        assert!(
            reason.contains("APCI 0x0300"),
            "must name the APCI: {reason}"
        );
        assert!(
            reason.contains("does not implement descriptor responses"),
            "must state the consequence: {reason}"
        );
        assert!(
            reason.contains("KNX Virtual IP"),
            "must name where it is seen: {reason}"
        );
    }

    #[test]
    fn descriptor_reason_falls_through_for_other_wrong_apci() {
        // A genuinely wrong service (not the echo) keeps the generic
        // "descriptor type (low APCI bits)" form with raw evidence.
        let reason = descriptor_response_reason(crate::apci::A_PROPERTY_VALUE_RESPONSE, &[0x01]);
        assert!(
            reason.contains("descriptor type (low APCI bits)"),
            "generic form: {reason}"
        );
        assert!(!reason.contains("echoed"), "not the echo path: {reason}");
    }
}
