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
use serde_json::{Value, json};

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
        let diagnostics = json!(read);
        let digest = digest(target, &diagnostics);
        let Some(given) = plan_digest else {
            return Ok(json!({
                "ok": true,
                "address": target.to_string(),
                "gateway": gateway,
                "diagnostics": diagnostics,
                "lines": read.lines(),
                "question": bussard_service::security_diag::clear_question(target),
                "plan_digest": digest,
            }));
        };
        if given != digest {
            return Err(format!(
                "the plan_digest {given} does not match the log as read now ({digest}); the \
                 log moved since the plan. Show the human the new lines and ask again"
            ));
        }
        match bussard_service::security_diag::clear(&service, target, &options).await {
            Ok(after) => Ok(json!({
                "ok": true,
                "cleared": true,
                "address": target.to_string(),
                "before": diagnostics,
                "diagnostics": after,
                "lines": after.lines(),
            })),
            Err(err) => Ok(json!({
                "ok": false,
                "cleared": false,
                "address": target.to_string(),
                "before": diagnostics,
                "error": chain(&err),
            })),
        }
    }
}
