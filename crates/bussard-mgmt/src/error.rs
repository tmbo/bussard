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
    /// waiting out the ACK timeout. A rejected `T_Connect` raises it on every
    /// budget (03_03_04 §5.4.3 E20, issue #507); a rejected numbered telegram
    /// only under a budget that opts in
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

    /// The device answered a memory access with the defined negative answer:
    /// an `A_Memory_Response` with number 0 and no data (03_03_07 Application
    /// Layer §3.5.3, §3.5.4). The memory is protected or not reachable, or
    /// the count was illegal or above what one APDU carries. The device
    /// refused; the frame was well formed.
    #[error(
        "{address} refused the memory {op} at {addr:#06X} ({count} octet(s)): it answered \
         A_Memory_Response with number 0 (protected or unreachable memory, or an illegal count)"
    )]
    MemoryRefused {
        /// The device.
        address: IndividualAddress,
        /// `"read"` or `"write"`.
        op: &'static str,
        /// The memory address of the refused access.
        addr: u32,
        /// The octet count that was asked for.
        count: u8,
    },

    /// An `A_MemoryExtended_Read` or `_Write` came back with a negative return
    /// code (03_03_07 §3.4.9.1.1, §3.4.9.2.1): `name` is the code's spec name,
    /// for example `E_ACCESS_DENIED` (FCh) or
    /// `E_LENGTH_EXCEEDS_MAX_APDU_LENGTH` (F4h).
    #[error(
        "{address} answered the {service} at {addr:#08X} with return code {code:#04X} ({name})"
    )]
    MemoryReturnCode {
        /// The device.
        address: IndividualAddress,
        /// The service that was answered.
        service: &'static str,
        /// The 24-bit memory address of the access.
        addr: u32,
        /// The return code octet.
        code: u8,
        /// The code's name, from [`return_code_name`].
        name: &'static str,
    },

    /// An `A_MemoryExtended_Write` came back with `E_SUCCESS_WITH_CRC` (01h,
    /// 03_03_07 §3.4.9.2.1) and a CRC16-CCITT that does not match the one over
    /// the request bussard sent (count, address and data): the device stored
    /// something else than was written.
    #[error(
        "{address} confirmed the A_MemoryExtended_Write at {addr:#08X} with CRC {got:#06X}, \
         but the CRC over the written request is {expected:#06X} (the chunk did not arrive intact)"
    )]
    MemoryWriteCrc {
        /// The device.
        address: IndividualAddress,
        /// The 24-bit memory address of the write.
        addr: u32,
        /// The CRC over the request octets bussard sent.
        expected: u16,
        /// The CRC the device returned.
        got: u16,
    },

    /// The device answered an `A_DeviceDescriptor_Read` with descriptor type
    /// 3Fh, "unsupported type" (03_03_07 §3.4.2.1).
    #[error("{address} does not support device descriptor type {requested}")]
    DescriptorTypeUnsupported {
        /// The device.
        address: IndividualAddress,
        /// The descriptor type that was asked for.
        requested: u8,
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

    /// A verify-mode echo did not match the write it answers (Management
    /// Procedures 03_05_02 §3.16.3, DMP_MemWrite_RCoV): with verify mode on,
    /// the device answers every `A_Memory_Write` with an `A_Memory_Response`
    /// carrying what it stored, and a different answer is an error. Names the
    /// written address, the echoed one, and both octet strings.
    #[error(
        "{address}: verify echo for the memory write at {addr:#06X} does not match (echo at \
         {echo_addr:#06X}, wrote {expected:02X?}, device stored {got:02X?})"
    )]
    MemoryEchoMismatch {
        /// The device.
        address: IndividualAddress,
        /// The address the chunk was written to.
        addr: u32,
        /// The address the echo names.
        echo_addr: u32,
        /// The octets that were written.
        expected: Vec<u8>,
        /// The octets the echo carries.
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

    /// An `A_Authorize_Request` was answered with the minimum access level (3
    /// or 15), which a device sets for an invalid key (03_03_07 §3.5.7): the
    /// key presented unlocks nothing. Distinct from a device that does not
    /// implement authorize at all (that is tolerated and continues) and from a
    /// level between maximum and minimum (granted) — this is a real, explicit
    /// access-denied that must fail loudly.
    #[error(
        "{address} denied access: A_Authorize granted level {level}, the minimum level a device \
         sets for an invalid key (0 = full access) — the device is keyed and needs its BCU key \
         (pass --bcu-key <hex>)"
    )]
    AccessDenied {
        /// The device that granted limited access.
        address: IndividualAddress,
        /// The minimum access level (3 or 15) the device set.
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

    /// The device did not answer the S-A_Sync under the tool key, and did
    /// under its factory default setup key (FDSK): it was reset to default
    /// (factory security), which drops the tool key and the security
    /// configuration and makes the FDSK active again (issue #532; KNX 3/5/2
    /// §4.1 NOTE 18, KNX 3/5/1 §6.1.4 and §6.3.10.4, AN194 §2.3.2.12). The
    /// session is not used further: nothing is read or written under the
    /// factory key outside an explicit activation.
    #[error(
        "{address} is back on its factory key (FDSK): it did not answer the Data Secure sync \
         under the tool key in the key store and did under its FDSK, so it was reset to default \
         (factory security: the tool key, the group keys and the secured links it held are \
         gone). bussard does not read or write it under the factory key. Next step: commission \
         it again with ETS (download with security), then import the new keyring export \
         (`bussard keys import`) so the key store holds the new tool key"
    )]
    FactoryKeyActive {
        /// The device.
        address: IndividualAddress,
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

/// The spec name of an application-layer return code (03_03_07 §3.4.9, the
/// generic return codes shared by the extended memory, property and function
/// property services). An undefined code reads `"undefined"`.
pub fn return_code_name(code: u8) -> &'static str {
    match code {
        0x00 => "E_SUCCESS",
        0x01 => "E_SUCCESS_WITH_CRC",
        0xF1 => "E_MEMORY_ERROR",
        0xF4 => "E_LENGTH_EXCEEDS_MAX_APDU_LENGTH",
        0xF5 => "E_DATA_OVERFLOW",
        0xF6 => "E_DATA_MIN",
        0xF7 => "E_DATA_MAX",
        0xF8 => "E_DATA_VOID",
        0xF9 => "E_TEMPORARILY_NOT_AVAILABLE",
        0xFA => "E_ACCESS_WRITE_ONLY",
        0xFB => "E_ACCESS_READ_ONLY",
        0xFC => "E_ACCESS_DENIED",
        0xFD => "E_ADDRESS_VOID",
        0xFE => "E_DATA_TYPE_CONFLICT",
        0xFF => "E_ERROR",
        _ => "undefined",
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
    fn test_return_code_name_covers_the_memory_codes() {
        assert_eq!(return_code_name(0xFC), "E_ACCESS_DENIED");
        assert_eq!(return_code_name(0xF4), "E_LENGTH_EXCEEDS_MAX_APDU_LENGTH");
        assert_eq!(return_code_name(0xF9), "E_TEMPORARILY_NOT_AVAILABLE");
        assert_eq!(return_code_name(0xFA), "E_ACCESS_WRITE_ONLY");
        assert_eq!(return_code_name(0xFD), "E_ADDRESS_VOID");
        assert_eq!(return_code_name(0xF1), "E_MEMORY_ERROR");
        assert_eq!(return_code_name(0xFF), "E_ERROR");
        assert_eq!(return_code_name(0x42), "undefined");
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
