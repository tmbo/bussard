//! `knx_restart_device` (issue #717): restart one device in the form ETS uses
//! for it and wait until it answers again, as `bussard restart <address>`
//! does.
//!
//! The form and the restart are the CLI's:
//! [`bussard_service::restart::restart_choice`] picks the form from the
//! product data the lock pins (the confirmed master reset for a
//! secure-capable System B application, a basic `A_Restart` otherwise), and
//! [`bussard_service::restart::restart_device`] sends it, waits the process
//! time the device asks for and reconnects until the device answers with the
//! same mask. Two calls, as every write of the tier: the first names the form
//! and returns the question and a digest, nothing sent; the second, after the
//! human's yes, restarts as a job (`knx_apply_status` reports it).

use bussard_model::IndividualAddress;
use bussard_service::L4Options;
use bussard_service::download::RestartForm;
use bussard_service::program::plan::Fingerprint;
use bussard_service::restart::{RestartWait, restart_choice, restart_device};
use bussard_service::secure::SequenceHighWater;
use serde_json::{Value, json};

use super::{BussardMcp, ProgrammingTier, Subject, chain, merge};

/// The digest of a restart question: the device and the form.
fn restart_digest(target: IndividualAddress, form: RestartForm) -> String {
    Fingerprint::new(b"bussard-restart-v1")
        .address(target)
        .put(form.name())
        .hex()
}

impl BussardMcp {
    /// `knx_restart_device`'s body; `Err` is a refusal reason.
    pub(super) async fn restart_device_tool(
        &self,
        address: &str,
        digest: Option<&str>,
    ) -> Result<Value, String> {
        let target = super::parse_address(address)?;
        let (tier, _, gateway) = self.programming_preflight()?;
        let Some(digest) = digest else {
            return Ok(self.restart_question(tier, target, &gateway));
        };
        let digest = digest.to_string();
        self.run_write(
            Subject::Device(target),
            "restart",
            move |me, job, gate| async move {
                let tier = me.tier()?;
                me.on_bus(tier, async {
                    let (service, options, form, why, mut result) =
                        me.restart_preflight(tier, target, &digest).await?;
                    gate.pass(result.clone(), None);
                    tier.jobs.step(
                        &job,
                        format!(
                            "restarting {target} ({} form) and waiting for it to answer",
                            form.name()
                        ),
                    );
                    let wait = RestartWait::default();
                    let outcome = restart_device(&service, target, &options, form, wait).await;
                    tracing::info!(
                        "audit: knx_restart_device {target} ({}): {}",
                        form.name(),
                        match &outcome {
                            Ok(done) if done.confirmed => "confirmed".to_string(),
                            Ok(_) => "sent, device answered again".to_string(),
                            Err(err) => format!("FAILED: {err}"),
                        }
                    );
                    merge(&mut result, restart_result(target, &why, outcome));
                    Ok(result)
                })
                .await
            },
        )
        .await
    }

    /// The first call: the form, the question and the digest. Nothing is
    /// sent on the bus.
    fn restart_question(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        gateway: &str,
    ) -> Value {
        let model = self.state().model.reload();
        let choice = restart_choice(&self.state().dir, Some(&model), target);
        let name = model
            .devices
            .get(&target)
            .map(|d| format!(" ({})", d.device.name))
            .unwrap_or_default();
        let digest = restart_digest(target, choice.form);
        tier.restarts.insert(digest.clone(), target, choice.form);
        let now = std::time::SystemTime::now();
        json!({
            "ok": true,
            "address": target.to_string(),
            "gateway": gateway,
            "form": choice.form.name(),
            "form_reason": choice.why,
            "question": format!("restart {target}{name} via {gateway}?"),
            "plan_digest": digest,
            "expires_at": tier.restarts.expires_at(now),
            "next_step": format!(
                "Nothing was sent. Tell the human {target} restarts ({} form: {}) and does not \
                 react for a few seconds, and ask the question. Call knx_restart_device with \
                 this plan_digest only after an explicit yes.",
                choice.form.name(),
                choice.why
            ),
        })
    }

    /// The pre-flight of a restart: the digest names a question of this
    /// session for `target` with the form the product data still gives, the
    /// source address is checked and the tool key resolved. `Err` is a
    /// refusal; nothing was sent.
    #[allow(clippy::type_complexity)] // the restart's inputs, named at the caller
    async fn restart_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        digest: &str,
    ) -> Result<
        (
            bussard_service::BusService,
            L4Options,
            RestartForm,
            String,
            Value,
        ),
        String,
    > {
        let (_, service, gateway) = self.programming_preflight()?;
        let again = "call knx_restart_device without plan_digest, ask the human and call again";
        let planned = tier
            .restarts
            .take(digest, target, "restart question", again)?;
        let model = self.state().model.reload();
        let choice = restart_choice(&self.state().dir, Some(&model), target);
        if choice.form != planned {
            return Err(format!(
                "refusing to restart {target}: the restart form changed since the question ({} \
                 then, {} now: {}). Ask again with knx_restart_device.",
                planned.name(),
                choice.form.name(),
                choice.why
            ));
        }
        let material = self.plan_material(target, &model)?;
        let source = service.checked_source(false).await?;
        let options =
            L4Options::secured(source, material.tool_key.clone(), SequenceHighWater::new());
        let result = json!({
            "method": "restart",
            "address": target.to_string(),
            "gateway": gateway,
            "secured": material.tool_key.is_some(),
            "form": choice.form.name(),
        });
        Ok((service, options, choice.form, choice.why, result))
    }
}

/// The result fields of a restart's `outcome`.
fn restart_result(
    target: IndividualAddress,
    why: &str,
    outcome: Result<
        bussard_service::restart::RestartOutcome,
        bussard_service::restart::RestartError,
    >,
) -> Value {
    let done = match outcome {
        Ok(done) => done,
        Err(err) => return json!({"ok": false, "verified": false, "reason": chain(&err)}),
    };
    let after = done.answered_after.as_secs_f64();
    json!({
        "ok": true,
        "verified": done.confirmed,
        "form_reason": why,
        "confirmed": done.confirmed,
        "process_time_s": done.process_time.map(|t| t.as_secs()),
        "mask": format!("{:04X}", done.mask),
        "answered_after_ms": done.answered_after.as_millis() as u64,
        // The technical line; `summary` is the homeowner's (#306).
        "outcome": if done.confirmed {
            format!(
                "{target} restarted: it confirmed the restart (A_Restart_Response) and answered \
                 again after {after:.1} s"
            )
        } else {
            format!(
                "{target}: restart sent (a basic A_Restart, which the device does not confirm); \
                 it answered again after {after:.1} s. The restart itself is not verified."
            )
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_digest_binds_device_and_form() -> Result<(), String> {
        let a: IndividualAddress = "1.1.4".parse().map_err(|_| "address")?;
        let b: IndividualAddress = "1.1.5".parse().map_err(|_| "address")?;
        assert_ne!(
            restart_digest(a, RestartForm::Basic),
            restart_digest(b, RestartForm::Basic)
        );
        assert_ne!(
            restart_digest(a, RestartForm::Basic),
            restart_digest(a, RestartForm::Confirmed)
        );
        Ok(())
    }
}
