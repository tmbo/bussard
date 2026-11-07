//! The flash half of the programming tier (issue #303): a parameter change
//! that shows, hides or reshapes a com-object changes the group-object
//! table, which a parameter-only write cannot touch. `knx_plan_device` then
//! plans a full application download (`method: flash`) instead of refusing,
//! and `knx_apply_device` runs it through the same job as any other apply.
//! The same holds when the application program bussard.lock pins is not
//! the one the device runs, or is not loaded at all (issue #750): the plan
//! says the application must be loaded, and the one yes to its digest
//! covers the load, its read-back and the lock update.
//!
//! The image, its gate and its write are the service's (issue #901):
//! [`bussard_service::program::flash::flash_image`] and
//! [`bussard_service::program::flash::load_need`] plan it from the plan's
//! read with the factory-freshness gate `bussard flash` decides with, and
//! [`bussard_service::program::flash::execute`] runs it, its read-back and
//! the lock update, the function `bussard flash` runs, so the offline oracle
//! (`scripts/campaign/95-offline-oracle.sh`) covers this path too. This
//! module turns the outcome into the job's result.
//!
//! A self-contained application's download writes no link table (issue
//! #779). When the links differ from the model, the job writes them after
//! the verified download with the table write of `bussard apply`, as `bussard
//! replace` runs `flash` and then `apply`; the one yes covers both, and the
//! result is verified only when the table write's read-back matches.

use std::path::Path;

use bussard_model::IndividualAddress;
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::BusService;
use bussard_service::flash_flow::ReadbackInputs;
use bussard_service::program::{self, flash::FlashImage};
use serde_json::{Value, json};

use super::{ProgrammingTier, chain};
use crate::jobs::JobSink;
use crate::server::BussardMcp;

/// What a flash job needs besides the image.
pub(super) struct FlashJob<'a> {
    /// The bus.
    pub(super) service: &'a BusService,
    /// The device.
    pub(super) target: IndividualAddress,
    /// The resolved gateway, for the audit line.
    pub(super) gateway: &'a str,
    /// The model directory.
    pub(super) dir: &'a Path,
    /// The checked source address.
    pub(super) source: IndividualAddress,
    /// The Data Secure tool key, `None` on the plain path.
    pub(super) tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared by the read and the write.
    pub(super) high_water: SequenceHighWater,
    /// The parameters that differ, as the plan listed them.
    pub(super) changed: Value,
    /// The parameter backup taken before the download.
    pub(super) param_backup: Option<&'a str>,
    /// What the read-back after the flash compares with (issue #319).
    pub(super) readback: Option<ReadbackInputs<'a>>,
}

impl BussardMcp {
    /// The write of a flash plan whose pre-flight passed: the full download
    /// with `bussard flash --yes`'s options, the restart and the read-back,
    /// then the lock update the CLI makes. Never refuses: a failure is the
    /// result (`ok: false` with the reason and the recovery).
    pub(super) async fn flash_write(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        image: &FlashImage,
        ctx: FlashJob<'_>,
        mut result: Value,
    ) -> Value {
        let target = ctx.target;
        let backed_up = match ctx.param_backup {
            Some(path) => format!("Its parameter memory before the flash is backed up at {path}."),
            None => "Its parameter memory was not backed up (it held no application bussard \
                     could read with the pinned product data)."
                .to_string(),
        };
        let recovery = format!(
            "The device may be left without a loaded application. {backed_up} Re-planning and \
             re-applying {target} runs the flash again; `bussard flash --force {target}` at \
             the CLI is the recovery when the plan refuses. Do not assume the device works \
             until a new knx_plan_device reports nothing to do."
        );
        if ctx.readback.is_none() {
            tracing::warn!("{target}: the flash runs without its read-back inputs");
        }
        let mut observer = JobSink::new(&tier.jobs, job).download("download", target);
        // The download `bussard flash --yes` runs, with its read-back on the
        // flash's last connection (issues #319, #349) and the lock update:
        // the same function. The yes is the plan digest.
        let execution = program::flash::FlashExecution {
            service: ctx.service,
            target,
            source: ctx.source,
            dir: ctx.dir,
            plan: &image.plan,
            options: image.options,
            facts: image.facts(),
            tool_key: ctx.tool_key,
            high_water: ctx.high_water,
            handover: None,
            readback: ctx.readback,
            senders: image.senders.as_deref(),
            question: program::Question {
                kind: bussard_service::observer::Ask::Write,
                prompt: format!("flash {target}"),
                action: format!("flash {target}"),
            },
            differential: false,
        };
        let written = match program::flash::execute(execution, &mut observer).await {
            Ok(written) => written,
            Err(declined) => {
                result["ok"] = json!(false);
                result["verified"] = json!(false);
                result["reason"] = json!(declined.to_string());
                return result;
            }
        };
        let flashed = &written.flashed;
        // Anything still differing fails the flash; a parameter read-back
        // that could not be made leaves `parameters.verified` false with its
        // note. A flash without its read-back is never reported verified.
        let params_differ = flashed.failure();
        let readback = flashed.readback.as_ref();
        let flashed_params = readback.and_then(|f| f.parameters.as_ref());
        let params_verified =
            flashed_params.is_some_and(bussard_service::params::FlashedParameters::verified);
        let verified = flashed.verified() && readback.is_some();
        tracing::info!(
            "audit: knx_apply_device {target} flash via {}: {}",
            ctx.gateway,
            if verified { "verified" } else { "FAILED" }
        );
        if let Some(why) = &image.load {
            result["load_application"] = json!({
                "why": why,
                "application": image.plan.identity.id,
                "loaded": verified,
            });
        }
        match &flashed.outcome {
            Ok(done) if done.ok() => {
                let ok = params_differ.is_none() && readback.is_some();
                result["ok"] = json!(ok);
                result["verified"] = json!(ok);
                if done.property_only {
                    // A property-only procedure (issue #390) loads no object.
                    result["property_procedure"] = json!(true);
                } else {
                    result["load_state"] = json!(done.load_state.to_string());
                }
                result["application"] = json!(image.plan.identity.id);
                result["warnings"] = json!(done.warnings);
                result["parameters"] = json!({
                    "written": true,
                    "verified": params_verified,
                    "changed": ctx.changed,
                });
                if let Some(note) = flashed_params.and_then(|f| f.note.as_ref()) {
                    result["parameters"]["note"] = json!(format!("not compared: {note}"));
                }
                if let Some(readback) = readback {
                    result["readback"] = json!(readback);
                } else {
                    // A silent success is a P1: no read-back, no "verified".
                    result["reason"] = json!(format!(
                        "the download ended with the application {} on {target}, but it was \
                         not read back and compared with your project",
                        done.load_state
                    ));
                    result["recovery"] = json!(format!(
                        "Plan {target} again with knx_plan_device: it reads the device and \
                         says what still differs."
                    ));
                }
                if let Some(failure) = &params_differ {
                    // Issues #319, #349: the application is loaded, but the
                    // device does not hold the model's configuration. Say
                    // that first.
                    result["reason"] = json!(failure);
                    result["parameters"]["differences"] = json!(
                        flashed_params
                            .map(|f| f.differences.clone())
                            .unwrap_or_default()
                    );
                    result["recovery"] = json!(format!(
                        "The application is loaded on {target}, but the items listed still \
                         differ from your project. Plan {target} again with knx_plan_device to \
                         see what is left, and do not report the change as done until a plan \
                         reports nothing to do."
                    ));
                }
                // The verified flash wrote this PID 54 table and these PID 61
                // flags: recorded in the lock, as `bussard flash` does
                // (issues #297, #331).
                if let Some(record) = &written.lock {
                    super::record_json(&mut result, record);
                }
            }
            Ok(done) => {
                result["ok"] = json!(false);
                result["verified"] = json!(false);
                let sequence = if done.property_only {
                    format!(
                        "the property procedure did not verify: {}",
                        done.warnings.join("; ")
                    )
                } else {
                    format!(
                        "the flash did not verify: load state {}, spot checks {}",
                        done.load_state,
                        if done.spot_checks_match {
                            "matched"
                        } else {
                            "did not match"
                        }
                    )
                };
                // Issue #349: the read-back names what differs.
                result["reason"] = json!(match &params_differ {
                    Some(failure) => format!("{sequence}; {failure}"),
                    None => sequence,
                });
                if let Some(readback) = readback {
                    result["readback"] = json!(readback);
                }
                result["recovery"] = json!(recovery);
            }
            Err(err) => {
                result["ok"] = json!(false);
                result["verified"] = json!(false);
                result["reason"] = json!(format!("the flash failed: {}", chain(err)));
                result["recovery"] = json!(recovery);
            }
        }
        result
    }
}
