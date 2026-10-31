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

use std::time::Instant;

use bussard_download::RestartForm;
use bussard_model::IndividualAddress;
use bussard_secure::SequenceHighWater;
use bussard_service::restart::{RestartWait, restart_choice, restart_device};
use bussard_service::{L4Options, SourcePolicy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{BussardMcp, ProgrammingTier, chain, put};

/// One restart question this session asked, remembered until answered,
/// refused or expired.
#[derive(Debug, Clone)]
pub(super) struct PendingRestart {
    /// The device.
    target: IndividualAddress,
    /// The form the question named.
    form: RestartForm,
    /// When the question was asked.
    created: Instant,
}

/// The digest of a restart question: the device and the form.
fn restart_digest(target: IndividualAddress, form: RestartForm) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-restart-v1");
    put(&mut h, &target.raw().to_be_bytes());
    put(&mut h, form.name().as_bytes());
    let bytes: [u8; 32] = h.finalize().into();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        self.run_job(target, "restart", move |me, job, started| async move {
            me.restart_job(&job, target, &digest, started).await;
        })
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
        {
            let mut pending = tier.restarts();
            pending.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            pending.insert(
                digest.clone(),
                PendingRestart {
                    target,
                    form: choice.form,
                    created: Instant::now(),
                },
            );
        }
        let now = std::time::SystemTime::now();
        json!({
            "ok": true,
            "address": target.to_string(),
            "gateway": gateway,
            "form": choice.form.name(),
            "form_reason": choice.why,
            "question": format!("restart {target}{name} via {gateway}?"),
            "plan_digest": digest,
            "expires_at": bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl),
            "next_step": format!(
                "Nothing was sent. Tell the human {target} restarts ({} form: {}) and does not \
                 react for a few seconds, and ask the question. Call knx_restart_device with \
                 this plan_digest only after an explicit yes.",
                choice.form.name(),
                choice.why
            ),
        })
    }

    /// One restart job: the digest check, then the restart and the wait for
    /// the device, holding the bus lock and the management slot.
    async fn restart_job(
        &self,
        job: &str,
        target: IndividualAddress,
        digest: &str,
        started: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            let _ = started.send(Err("the programming tier is off".into()));
            return;
        };
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let prepared = self.restart_preflight(tier, target, digest).await;
        let (service, options, form, why, mut result) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.refuse(job, &reason);
                let _ = started.send(Err(reason));
                return;
            }
        };
        tier.jobs.started(job, result.clone(), None);
        let _ = started.send(Ok(()));
        tier.jobs.step(
            job,
            format!(
                "restarting {target} ({} form) and waiting for it to answer",
                form.name()
            ),
        );
        let outcome =
            restart_device(&service, target, &options, form, RestartWait::default()).await;
        drop(warm);
        tracing::info!(
            "audit: knx_restart_device {target} ({}): {}",
            form.name(),
            match &outcome {
                Ok(done) if done.confirmed => "confirmed".to_string(),
                Ok(_) => "sent, device answered again".to_string(),
                Err(err) => format!("FAILED: {err}"),
            }
        );
        let extra = match outcome {
            Ok(done) => json!({
                "ok": true,
                "verified": done.confirmed,
                "form_reason": why,
                "confirmed": done.confirmed,
                "process_time_s": done.process_time.map(|t| t.as_secs()),
                "mask": format!("{:04X}", done.mask),
                "answered_after_ms": done.answered_after.as_millis() as u64,
                "summary": if done.confirmed {
                    format!(
                        "{target} restarted: it confirmed the restart (A_Restart_Response) and \
                         answered again after {:.1} s",
                        done.answered_after.as_secs_f64()
                    )
                } else {
                    format!(
                        "{target}: restart sent (a basic A_Restart, which the device does not \
                         confirm); it answered again after {:.1} s. The restart itself is not \
                         verified.",
                        done.answered_after.as_secs_f64()
                    )
                },
            }),
            Err(err) => json!({
                "ok": false,
                "verified": false,
                "reason": chain(&err),
            }),
        };
        if let (Some(into), Value::Object(extra)) = (result.as_object_mut(), extra) {
            into.extend(extra);
        }
        tier.jobs.finish(job, result);
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
        let pending = {
            let mut pending = tier.restarts();
            pending.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            pending.remove(digest)
        };
        let Some(pending) = pending else {
            return Err(format!(
                "no fresh restart question with digest {digest:?} in this session (they expire \
                 after {} minute(s) and are single use); call knx_restart_device without \
                 plan_digest, ask the human and call again",
                tier.plan_ttl.as_secs().div_ceil(60)
            ));
        };
        if pending.target != target {
            return Err(format!(
                "restart digest {digest} is for {}, not {target}",
                pending.target
            ));
        }
        let model = self.state().model.reload();
        let choice = restart_choice(&self.state().dir, Some(&model), target);
        if choice.form != pending.form {
            return Err(format!(
                "refusing to restart {target}: the restart form changed since the question ({} \
                 then, {} now: {}). Ask again with knx_restart_device.",
                pending.form.name(),
                choice.form.name(),
                choice.why
            ));
        }
        let material = self.plan_material(target, &model)?;
        let source = service.checked_source(false).await.map_err(|e| chain(&e))?;
        let options = L4Options {
            source: SourcePolicy::Known(source),
            tool_key: material.tool_key.clone(),
            high_water: SequenceHighWater::new(),
            ..L4Options::default()
        };
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
