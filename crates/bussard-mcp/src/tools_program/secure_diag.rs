//! `knx_clear_security_log` (issues #533, #571): the security failures log
//! (PID 55) and report of a KNX Data Secure device, cleared with the plan,
//! digest and explicit-yes flow of the programming tier. The read and the
//! clear are [`bussard_service::security_diag`]'s, the functions `bussard
//! secure diag [--clear]` calls, and the question is the CLI prompt's.

use bussard_model::IndividualAddress;
use bussard_service::L4Options;
use bussard_service::program::plan::Fingerprint;
use bussard_service::secure::SequenceHighWater;
use bussard_service::secure::ToolKeySource;
use bussard_service::report::Approval;
use bussard_service::secure_report::SecureDiagReport;
use serde_json::Value;

use super::{BussardMcp, chain};

/// The digest of a clear plan: the device and the log as read, so a log that
/// moves between the two calls retires the plan.
fn digest(target: IndividualAddress, diagnostics: &Value) -> String {
    let mut digest = Fingerprint::new(b"bussard-clear-security-log-v1")
        .address(target)
        .put(diagnostics.to_string())
        .hex();
    digest.truncate(16);
    digest
}

impl BussardMcp {
    /// Reads, or with `plan_digest` clears, the security failures log of
    /// `address`.
    pub(super) async fn clear_security_log(
        &self,
        address: &str,
        plan_digest: Option<&str>,
    ) -> Result<Value, String> {
        let (tier, service, gateway) = self.programming_preflight()?;
        let target: IndividualAddress = address
            .trim()
            .parse()
            .map_err(|e| format!("not an individual address: {e}"))?;
        // The log is tool-only (KNX 3/5/1 §6.3.9.2): the device counts as
        // activated for the key rule, as in `bussard secure diag`.
        let (tool_key, factory_key) = bussard_service::secure::resolve_session_keys(
            target,
            ToolKeySource {
                keyring: self.state().keyring.as_deref(),
                tool_key: None,
            },
            true,
        )
        .map_err(|err| chain(&err))?;
        if tool_key.is_none() {
            return Err(format!(
                "{target}: the security failures log is readable with the device's tool key \
                 only: {}",
                bussard_service::guidance::tool_key_hint()
            ));
        }
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let source = service.checked_source(false).await?;
        let options = L4Options::secured(source, tool_key, SequenceHighWater::new())
            .with_factory_key(factory_key);
        let read = bussard_service::security_diag::read(&service, target, &options)
            .await
            .map_err(|e| {
                format!(
                    "reading the security failures log of {target}: {}",
                    chain(&e)
                )
            })?;
        let diagnostics = serde_json::to_value(&read).unwrap_or_default();
        let digest = digest(target, &diagnostics);
        let model = self.model();
        let Some(given) = plan_digest else {
            let mut report = SecureDiagReport::new(target, read, false);
            report.gateway = Some(gateway);
            report.approval = Approval {
                question: Some(bussard_service::security_diag::clear_question(target)),
                plan_digest: Some(digest),
                expires_at: None,
            };
            return Ok(crate::reply::report(&report, &model));
        };
        if given != digest {
            return Err(format!(
                "the plan_digest {given} does not match the log as read now ({digest}); the \
                 log moved since the plan. Show the human the new lines and ask again"
            ));
        }
        let report = match bussard_service::security_diag::clear(&service, target, &options).await
        {
            Ok(after) => SecureDiagReport {
                before: Some(read),
                ..SecureDiagReport::new(target, after, true)
            },
            Err(err) => SecureDiagReport {
                ok: false,
                diagnostics: None,
                lines: Vec::new(),
                reason: Some(chain(&err)),
                before: Some(read),
                ..SecureDiagReport::new(target, Default::default(), false)
            },
        };
        Ok(crate::reply::report(&report, &model))
    }
}
