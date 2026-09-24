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

    /// The interface reported a negative `L_Data.con` for the `T_Connect` or
    /// the first numbered telegram: the medium did not acknowledge the frame,
    /// so no device is at the address (issue #45). Like
    /// [`MgmtError::NoResponse`] this means **absent**, only established from
    /// the interface's confirmation in tens of milliseconds instead of by
    /// waiting out the ACK timeout. Raised only under a budget that opts in
    /// ([`Timeouts::absent_on_negative_confirmation`](crate::Timeouts::absent_on_negative_confirmation)).
    #[error("no device at {address} (the interface reported a negative L_Data.con)")]
    NotConfirmed {
        /// The address the frame went to.
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
        "{address}: memory verify failed at {addr:#08X} (wrote {expected:02X?}, read back \
         {got:02X?})"
    )]
    MemoryVerifyFailed {
        /// The device.
        address: IndividualAddress,
        /// The address of the chunk that did not verify (up to 24-bit).
        addr: u32,
        /// The octets that were written.
        expected: Vec<u8>,
        /// The octets read back.
        got: Vec<u8>,
    },

    /// A `NoResponse`/`Disconnected` that struck **mid-session**, after at least
    /// one numbered exchange had already completed on this connection. It folds
    /// the exchange count and sequence-wrap count into the message so a stall is
    /// measured in protocol units (numbered messages), not just in bytes.
    ///
    /// This is the additive form of [`MgmtError::NoResponse`] /
    /// [`MgmtError::Disconnected`]: the first send on a connection that draws no
    /// reaction still surfaces the bare absent/disconnected error (nothing had
    /// happened yet to count); only a silence *after* progress carries this
    /// context. `kind` names which of the two underlying conditions occurred so
    /// [`MgmtError::device_present`] and callers keep the present/absent
    /// distinction. See #50: the next KV run measures the stall point in messages.
    #[error(
        "{kind} from {address} after {exchanges} numbered exchange(s) \
         (sequence wrapped {wraps} time(s))"
    )]
    MidSessionSilence {
        /// The device whose session went silent.
        address: IndividualAddress,
        /// Which underlying condition struck: `no response (device absent)` or
        /// `connection was disconnected`.
        kind: SilenceKind,
        /// How many numbered data telegrams (NDTs) had been acknowledged on this
        /// connection before the silence.
        exchanges: u32,
        /// How many times the 4-bit send sequence wrapped (0..15 → 0) over those
        /// exchanges — `exchanges / 16`.
        wraps: u32,
    },

    /// An `A_Authorize_Request` was answered, but the device granted a
    /// **non-zero** access level: the key presented does not unlock the access
    /// the management session needs. Distinct from a device that does not
    /// implement authorize at all (that is tolerated and continues) — a granted
    /// level is a real, explicit access-denied that must fail loudly.
    #[error(
        "{address} denied access: A_Authorize granted level {level} (0 = full access) for the \
         presented key — the device is keyed and needs its BCU key (pass --bcu-key <hex>)"
    )]
    AccessDenied {
        /// The device that granted limited access.
        address: IndividualAddress,
        /// The non-zero access level the device granted.
        level: u8,
    },

    /// A KNX Data Secure operation failed for `address`: the outgoing APDU could
    /// not be wrapped, or an incoming secured frame failed MAC verification or
    /// was a stale (replayed) sequence. A wrong-MAC response is rejected here
    /// rather than silently accepted (issue #71, spec §6).
    #[error("{address}: KNX Data Secure error: {source}")]
    Secure {
        /// The device the secure operation concerned.
        address: IndividualAddress,
        /// The underlying Data Secure ASDU/session error.
        source: bussard_secure::AsduError,
    },

    /// The device answered a confirmed service with a refusal: a non-zero
    /// return code, or (for a value read) a zero element count. Raised by the
    /// extended property services (issue #156). The message names the service
    /// and the property, never the value (it may be a key).
    #[error("{address} refused {service} on {target}{}", match return_code {
        Some(rc) => format!(" (return code {rc:#04x})"),
        None => String::new(),
    })]
    ServiceRejected {
        /// The device that refused.
        address: IndividualAddress,
        /// The service name, e.g. `A_PropertyExtValue_WriteCon`.
        service: &'static str,
        /// What was addressed (object type, instance, PID, range).
        target: String,
        /// The device's return code, when the service carries one.
        return_code: Option<u8>,
    },

    /// An underlying transport error (socket, gateway, framing).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Which silence struck mid-session, for [`MgmtError::MidSessionSilence`]. Keeps
/// the absent-vs-present distinction the bare errors carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SilenceKind {
    /// The device stopped answering entirely (an absent-style `NoResponse`).
    NoResponse,
    /// The device disconnected or the connection dropped (`Disconnected`).
    Disconnected,
}

impl std::fmt::Display for SilenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SilenceKind::NoResponse => write!(f, "no response (device absent)"),
            SilenceKind::Disconnected => write!(f, "connection was disconnected"),
        }
    }
}

impl MgmtError {
    /// Whether this error indicates the device is **present** (as opposed to
    /// simply absent). A NAK, disconnect, malformed response or failed memory
    /// verify all mean a device answered in some way; only a `NoResponse` (bare
    /// or the mid-session `NoResponse`-kind silence) means absent.
    pub fn device_present(&self) -> bool {
        !matches!(
            self,
            MgmtError::NoResponse { .. }
                | MgmtError::NotConfirmed { .. }
                | MgmtError::MidSessionSilence {
                    kind: SilenceKind::NoResponse,
                    ..
                }
        )
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
    fn raw_response_detail_is_greppable_hex() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            raw_response_detail(0x0340, &[0x07, 0xB0]),
            "APCI 0x0340, payload [07 B0]"
        );
        Ok(())
    }

    #[test]
    fn raw_response_detail_handles_empty_payload()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(raw_response_detail(0x0000, &[]), "APCI 0x0000, payload []");
        Ok(())
    }

    #[test]
    fn descriptor_reason_names_the_echo_pattern()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        Ok(())
    }

    #[test]
    fn mid_session_silence_renders_exchange_and_wrap_counts()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The #50 counter: a mid-session silence names the numbered-exchange count
        // and how many times the 4-bit sequence wrapped, in protocol units.
        let addr: IndividualAddress = "1.1.4".parse()?;
        let err = MgmtError::MidSessionSilence {
            address: addr,
            kind: SilenceKind::NoResponse,
            exchanges: 35,
            wraps: 2,
        };
        assert_eq!(
            err.to_string(),
            "no response (device absent) from 1.1.4 after 35 numbered exchange(s) \
             (sequence wrapped 2 time(s))"
        );
        // A no-response-kind silence keeps the device-absent classification.
        assert!(!err.device_present());

        // A disconnected-kind silence means the device is present.
        let disc = MgmtError::MidSessionSilence {
            address: addr,
            kind: SilenceKind::Disconnected,
            exchanges: 4,
            wraps: 0,
        };
        assert!(disc.device_present());
        assert!(disc.to_string().contains("connection was disconnected"));
        Ok(())
    }

    #[test]
    fn descriptor_reason_falls_through_for_other_wrong_apci()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A genuinely wrong service (not the echo) keeps the generic
        // "descriptor type (low APCI bits)" form with raw evidence.
        let reason = descriptor_response_reason(crate::apci::A_PROPERTY_VALUE_RESPONSE, &[0x01]);
        assert!(
            reason.contains("descriptor type (low APCI bits)"),
            "generic form: {reason}"
        );
        assert!(!reason.contains("echoed"), "not the echo path: {reason}");
        Ok(())
    }
}
