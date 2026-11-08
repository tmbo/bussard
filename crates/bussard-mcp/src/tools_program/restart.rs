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
use bussard_service::program::outcome::WriteOutcome;
use bussard_service::program::plan::Fingerprint;
use bussard_service::restart::{
    RestartPlan, RestartWait, restart_choice, restart_device, restart_outcome,
};
use bussard_service::secure::SequenceHighWater;
use serde_json::Value;

use super::{BussardMcp, ProgrammingTier, Subject};

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
                    let (service, options, form, why, result) =
                        me.restart_preflight(tier, target, &digest).await?;
                    gate.pass(&result, None);
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
                    Ok(restart_outcome(result, &why, &outcome))
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
        let name = model.devices.get(&target).map(|d| d.device.name.as_str());
        let mut plan = RestartPlan::new(target, name, gateway, &choice);
        let digest = restart_digest(target, choice.form);
        tier.restarts.insert(digest.clone(), target, choice.form);
        plan.approval.plan_digest = Some(digest);
        plan.approval.expires_at = Some(tier.restarts.expires_at(std::time::SystemTime::now()));
        crate::reply::report(&plan, &model)
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
            WriteOutcome,
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
        let result = WriteOutcome {
            method: Some("restart".to_string()),
            gateway: Some(gateway),
            secured: Some(material.tool_key.is_some()),
            form: Some(choice.form.name().to_string()),
            ..WriteOutcome::new(target)
        };
        Ok((service, options, choice.form, choice.why, result))
    }
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
