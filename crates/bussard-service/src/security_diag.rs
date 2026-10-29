//! Reading and clearing a Data Secure device's security failures log, report
//! and report control (issue #533), the one path for `bussard secure diag`,
//! `bussard status <ia>` and `knx_describe_device`.
//!
//! The protocol lives in [`bussard_download::security_diag`]; this module
//! opens the secured management session. Both need the device's tool key:
//! the properties are tool-only (KNX 3/5/1 §6.3.9.2, §6.3.11.2, §6.3.12.2).

use bussard_download::SecurityDiagnostics;
use bussard_mgmt::MgmtError;
use bussard_model::IndividualAddress;

use crate::bus::{BusService, L4Options};
use crate::error::ServiceError;

/// Reads the diagnostics of `target` over a secured session (`options`
/// carries the tool key). Read-only.
///
/// # Errors
///
/// The session could not be opened or a read failed on the transport.
pub async fn read(
    service: &BusService,
    target: IndividualAddress,
    options: &L4Options,
) -> Result<SecurityDiagnostics, ServiceError> {
    service
        .with_l4(target, options, async |l4| {
            Ok::<_, ServiceError>(bussard_download::read_security_diagnostics(l4).await?)
        })
        .await
}

/// Clears the failures log and resets the report of `target`, then reads
/// them back (see [`bussard_download::clear_security_diagnostics`]): an
/// `Ok` means the read-back found every counter zero and the report clear.
///
/// # Errors
///
/// The session could not be opened, the device refused the clear, or the
/// read-back still shows counts.
pub async fn clear(
    service: &BusService,
    target: IndividualAddress,
    options: &L4Options,
) -> Result<SecurityDiagnostics, ServiceError> {
    service
        .with_l4(target, options, async |l4| {
            Ok::<_, ServiceError>(bussard_download::clear_security_diagnostics(l4).await?)
        })
        .await
}

/// The sentence a secured group write without admission evidence adds
/// (issue #533): where to look when the device ignores the telegram.
pub fn dropped_write_hint(receivers: &[IndividualAddress]) -> String {
    let list: Vec<String> = receivers.iter().map(ToString::to_string).collect();
    let first = list.first().map(String::as_str).unwrap_or("<ia>");
    format!(
        "if nothing happens, `bussard secure diag {first}` (knx_describe_device over MCP) reads the \
         device's security failures log: no new count means the sender is not in its security \
         individual address table, a cryptographic count a wrong or stale group key, an access \
         count a group-object security flag mismatch{}",
        if list.len() > 1 {
            format!(" (receivers: {})", list.join(", "))
        } else {
            String::new()
        }
    )
}

/// Whether `err` is a management error a secure diagnostics read reports as
/// "not readable" rather than a failure of the surrounding command.
pub fn is_unreadable(err: &ServiceError) -> bool {
    matches!(
        err,
        ServiceError::Mgmt(
            MgmtError::ServiceRejected { .. }
                | MgmtError::MalformedResponse { .. }
                | MgmtError::NoResponse { .. }
                | MgmtError::MidSessionSilence { .. }
                | MgmtError::Secure { .. }
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dropped_write_hint_names_the_command_and_the_footprints()
    -> Result<(), Box<dyn std::error::Error>> {
        let hint = dropped_write_hint(&["1.1.5".parse()?]);
        assert!(hint.contains("bussard secure diag 1.1.5"), "{hint}");
        assert!(hint.contains("no new count"), "{hint}");
        assert!(!hint.contains("receivers"), "{hint}");
        let two = dropped_write_hint(&["1.1.5".parse()?, "1.1.7".parse()?]);
        assert!(two.contains("receivers: 1.1.5, 1.1.7"), "{two}");
        Ok(())
    }
}
