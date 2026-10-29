//! The Data Secure diagnostics of a device's security object (issue #533):
//! the security failures log (PID 55), the security report (PID 57) and the
//! security report control (PID 58).
//!
//! A secured write that "was confirmed and nothing happened" has three
//! device-side causes with three footprints: a sender the security individual
//! address table does not list is dropped without a count (KNX 3/3/7
//! §5.2.1.1), a wrong or stale group key counts a cryptographic error, a
//! sequence below the table's entry may count a SeqNr error (KNX 3/3/7 §5.4),
//! and a group-object flag mismatch counts an access error (KNX 3/5/1
//! §6.3.15.3 Table 108). Reading the log after such a write tells them apart.
//!
//! Formats (KNX 3/5/1 §6.3.9.3, the octets after the header of the extended
//! function property services):
//!
//! - clear: `A_FunctionPropertyExt_Command` data `00 00 00` (reserved,
//!   WriteServiceID 00h, ServiceInfo 00h), answered with return code 00h and
//!   the WriteServiceID; it does not reset the report (§6.3.9.3.1).
//! - counters: `A_FunctionPropertyExt_State_Read` data `00 00 00`, answered
//!   with return code, ReadServiceID 00h, ServiceInfo 00h, two reserved
//!   octets, then the SeqNr, cryptographic and access/roles counters (two
//!   octets each, saturating at 65 535).
//! - latest failure n: data `00 01 n`, answered with return code,
//!   ReadServiceID 01h, n, the sender IA (2), two unused octets, one unused
//!   octet, the sender SeqNr (6) and the error type: 02h SeqNr, 03h
//!   cryptographic, 04h access or roles. The SeqNr of a type 04h failure is
//!   not interpreted (it may be a plain access).
//!
//! The report (PID 57) and its control (PID 58) are one-octet values read
//! with `A_PropertyExtValue_Read`; the tool resets the report by writing 0
//! (§6.3.11.5). All of it needs the tool key (access A+C, KNX 3/5/1 §6.3).
//! Nothing here is key material.

use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::property_ext::{
    self, PID_SECURITY_FAILURES_LOG, PID_SECURITY_REPORT, PID_SECURITY_REPORT_CONTROL,
    PropertyExtAddress,
};
use bussard_model::IndividualAddress;

/// The error type of one logged security failure (KNX 3/5/1 §6.3.9.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// 02h: a sequence number below the one the device expects.
    SeqNr,
    /// 03h: a MAC that does not verify, a failed decryption, a frame too short.
    Cryptographic,
    /// 04h: a verified message that a group object's security flags or an
    /// access definition refuse.
    AccessOrRoles,
    /// Any other (reserved) value.
    Other(u8),
}

impl FailureKind {
    /// Decodes the error-type octet.
    pub fn from_octet(octet: u8) -> FailureKind {
        match octet {
            0x02 => FailureKind::SeqNr,
            0x03 => FailureKind::Cryptographic,
            0x04 => FailureKind::AccessOrRoles,
            other => FailureKind::Other(other),
        }
    }

    /// The failure in words, with what usually causes it.
    pub fn words(self) -> String {
        match self {
            FailureKind::SeqNr => "sequence number error (a replayed or stale telegram, or a \
                                   sender whose sequence fell behind the device's table)"
                .to_string(),
            FailureKind::Cryptographic => "cryptographic error (the MAC did not verify: a wrong \
                                           or outdated group key or tool key)"
                .to_string(),
            FailureKind::AccessOrRoles => "access error (a group object's security flags do \
                                           not match the telegram, or a refused access)"
                .to_string(),
            FailureKind::Other(o) => format!("reserved error type {o:02X}h"),
        }
    }
}

/// The most recent failure the device logged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LatestFailure {
    /// The sender of the failing message.
    pub sender: IndividualAddress,
    /// Its sequence number; `None` for an access error, where the standard
    /// says not to interpret it.
    pub sequence: Option<u64>,
    /// What failed.
    pub kind: FailureKind,
}

/// The failure counters (PID 55, ReadServiceID 00h).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct FailureCounters {
    /// SeqNr errors.
    pub sequence: u16,
    /// Cryptographic errors.
    pub cryptographic: u16,
    /// Access or roles errors.
    pub access: u16,
}

impl FailureCounters {
    /// Whether every counter is zero.
    pub fn is_empty(&self) -> bool {
        self.sequence == 0 && self.cryptographic == 0 && self.access == 0
    }
}

/// What the security object reports about failed secured telegrams.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SecurityDiagnostics {
    /// The failure counters; `None` when the device refused the read.
    pub counters: Option<FailureCounters>,
    /// The latest failure; `None` when none is logged or the read was
    /// refused (see `notes`).
    pub latest: Option<LatestFailure>,
    /// The security report's Security Failure bit (PID 57 b0); `None` when
    /// the device refused the read.
    pub report_failure: Option<bool>,
    /// Whether the device broadcasts the report on every failure (PID 58);
    /// `None` when the device refused the read.
    pub report_broadcast: Option<bool>,
    /// What could not be read, one line each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl SecurityDiagnostics {
    /// The diagnostics as text lines (no key material).
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        match &self.counters {
            Some(c) => out.push(format!(
                "security failures (PID 55): {} sequence, {} cryptographic, {} access",
                c.sequence, c.cryptographic, c.access
            )),
            None => out.push("security failures (PID 55): not read".to_string()),
        }
        if let Some(l) = &self.latest {
            let seq = l
                .sequence
                .map(|s| format!(", sequence {s}"))
                .unwrap_or_default();
            out.push(format!(
                "latest failure: from {}{seq}: {}",
                l.sender,
                l.kind.words()
            ));
        }
        out.push(format!(
            "security report (PID 57): {}",
            match self.report_failure {
                Some(true) => "a security failure is flagged",
                Some(false) => "no failure flagged",
                None => "not read",
            }
        ));
        out.push(format!(
            "security report broadcast (PID 58): {}",
            match self.report_broadcast {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "not read",
            }
        ));
        out.extend(self.notes.iter().cloned());
        out
    }
}

/// The address of the failures log.
fn sfl() -> PropertyExtAddress {
    PropertyExtAddress::security(PID_SECURITY_FAILURES_LOG)
}

/// Decodes the counters answer (the data after the return code).
fn decode_counters(data: &[u8]) -> Option<FailureCounters> {
    let word =
        |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*data.get(i)?, *data.get(i + 1)?])) };
    if data.first() != Some(&0x00) {
        return None;
    }
    Some(FailureCounters {
        sequence: word(4)?,
        cryptographic: word(6)?,
        access: word(8)?,
    })
}

/// Decodes the latest-failure answer (the data after the return code).
fn decode_latest(data: &[u8]) -> Option<LatestFailure> {
    if data.first() != Some(&0x01) || data.len() < 14 {
        return None;
    }
    let sender = IndividualAddress::from_raw(u16::from_be_bytes([data[2], data[3]]));
    let mut seq = [0u8; 8];
    seq[2..].copy_from_slice(&data[7..13]);
    let kind = FailureKind::from_octet(data[13]);
    Some(LatestFailure {
        sender,
        sequence: (kind != FailureKind::AccessOrRoles).then_some(u64::from_be_bytes(seq)),
        kind,
    })
}

/// Reads a one-octet value of the security object; `Ok(None)` when refused.
async fn read_flag<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    pid: u16,
) -> Result<Option<u8>, MgmtError> {
    match property_ext::read_property_ext(l4, PropertyExtAddress::security(pid), 1, 1).await {
        Ok(value) => Ok(value.data.first().copied()),
        Err(MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Reads the failures log (counters and the latest failure), the report and
/// the report control over the open, secured session `l4`. Read-only.
///
/// Best effort per item: a refused read leaves the item `None` with a note.
///
/// # Errors
///
/// A transport-level management error.
pub async fn read_security_diagnostics<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<SecurityDiagnostics, MgmtError> {
    let mut out = SecurityDiagnostics::default();
    match property_ext::function_property_ext_state_read(l4, sfl(), &[0x00, 0x00, 0x00]).await {
        Ok(state) => match decode_counters(&state.data) {
            Some(c) => out.counters = Some(c),
            None => out
                .notes
                .push("security failures (PID 55): the counters answer is malformed".to_string()),
        },
        Err(err @ (MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. })) => {
            out.notes
                .push(format!("security failures (PID 55) not read: {err}"));
        }
        Err(err) => return Err(err),
    }
    if out.counters.is_some_and(|c| !c.is_empty()) {
        match property_ext::function_property_ext_state_read(l4, sfl(), &[0x00, 0x01, 0x00]).await {
            Ok(state) => out.latest = decode_latest(&state.data),
            // A device that logs no message answers with a negative return
            // code (KNX 3/5/1 §6.3.9.3.3).
            Err(MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. }) => {
                out.notes
                    .push("latest failure (PID 55): the device logged none it can show".into());
            }
            Err(err) => return Err(err),
        }
    }
    out.report_failure = read_flag(l4, PID_SECURITY_REPORT)
        .await?
        .map(|r| r & 0x01 != 0);
    out.report_broadcast = read_flag(l4, PID_SECURITY_REPORT_CONTROL)
        .await?
        .map(|r| r & 0x01 != 0);
    Ok(out)
}

/// Clears the failures log (PID 55 WriteServiceID 00h) and resets the
/// security report (PID 57 := 0) over the open, secured session `l4`, then
/// reads both back: the counters must be zero and the report clear, or the
/// clear is reported as not taken (no silent success).
///
/// # Errors
///
/// A refused or unconfirmed command or write, a transport failure, or a
/// read-back that still shows counts or the report bit.
pub async fn clear_security_diagnostics<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<SecurityDiagnostics, MgmtError> {
    let target = l4.target();
    let state = property_ext::function_property_ext_command(l4, sfl(), &[0x00, 0x00, 0x00]).await?;
    if state.data.first() != Some(&0x00) {
        return Err(MgmtError::MalformedResponse {
            address: target,
            reason: "the failures-log clear was not confirmed with WriteServiceID 00h".to_string(),
        });
    }
    property_ext::write_property_ext_con(
        l4,
        PropertyExtAddress::security(PID_SECURITY_REPORT),
        1,
        1,
        &[0x00],
    )
    .await?;
    let after = read_security_diagnostics(l4).await?;
    let counted = after.counters.is_none_or(|c| !c.is_empty());
    let flagged = after.report_failure != Some(false);
    if counted || flagged {
        return Err(MgmtError::MalformedResponse {
            address: target,
            reason: format!(
                "the clear was confirmed but the read-back still shows {}",
                after.lines().join("; ")
            ),
        });
    }
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_counters_reads_the_three_words() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0xFF, 0xFF];
        assert_eq!(
            decode_counters(&data),
            Some(FailureCounters {
                sequence: 2,
                cryptographic: 256,
                access: 65535,
            })
        );
        assert_eq!(decode_counters(&data[..9]), None);
        assert_eq!(decode_counters(&[0x01; 10]), None);
    }

    #[test]
    fn test_decode_latest_reads_sender_sequence_and_type() -> Result<(), Box<dyn std::error::Error>>
    {
        // 01h, n = 0, sender 1.1.24, two unused, one unused, seq 7, type 03h.
        let data = [
            0x01, 0x00, 0x11, 0x18, 0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 7, 0x03,
        ];
        let latest = decode_latest(&data).ok_or("no failure")?;
        assert_eq!(latest.sender, "1.1.24".parse()?);
        assert_eq!(latest.sequence, Some(7));
        assert_eq!(latest.kind, FailureKind::Cryptographic);
        // An access error's sequence is not interpreted.
        let mut access = data;
        access[13] = 0x04;
        assert_eq!(decode_latest(&access).ok_or("none")?.sequence, None);
        Ok(())
    }

    #[test]
    fn test_lines_name_the_counts_and_the_report() -> Result<(), Box<dyn std::error::Error>> {
        let diag = SecurityDiagnostics {
            counters: Some(FailureCounters {
                sequence: 0,
                cryptographic: 0,
                access: 1,
            }),
            latest: Some(LatestFailure {
                sender: "1.1.24".parse()?,
                sequence: None,
                kind: FailureKind::AccessOrRoles,
            }),
            report_failure: Some(true),
            report_broadcast: Some(false),
            notes: Vec::new(),
        };
        let text = diag.lines().join("\n");
        assert!(
            text.contains("0 sequence, 0 cryptographic, 1 access"),
            "{text}"
        );
        assert!(
            text.contains("latest failure: from 1.1.24: access error"),
            "{text}"
        );
        assert!(text.contains("a security failure is flagged"), "{text}");
        assert!(text.contains("(PID 58): disabled"), "{text}");
        Ok(())
    }
}
