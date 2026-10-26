//! The flash half of the programming tier (issue #303): a parameter change
//! that shows, hides or reshapes a com-object changes the group-object
//! table, which a parameter-only write cannot touch. `knx_plan_device` then
//! plans a full application download (`method: flash`) instead of refusing,
//! and `knx_apply_device` runs it through the same job as any other apply.
//!
//! The image is the one `bussard flash --yes` writes: it is built with
//! [`bussard_service::flash::FlashInputs`] from the product data bussard.lock
//! pins, the model and the factory-freshness verdict of the read-only probe,
//! shaped by [`FlashInputs::finish`] and downloaded by
//! [`bussard_service::download::flash_session`], so the offline oracle
//! (`scripts/campaign/95-offline-oracle.sh`) covers this path too. The
//! refusals are the CLI's: no archive pinned in the lock, a device that runs
//! another application (the identity verdict, checked by the caller), a
//! device whose state the probe could not read.

use std::collections::BTreeSet;
use std::path::Path;

use bussard_download::{
    DeviceFacts, FlashOptions, FlashPlan, Freshness, PlanReport, SecureSenderEntry,
    assess_freshness, flash_gate,
};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::flash::{
    DEVICE_OFFLINE_SECONDS, FlashInputs, com_object_words, flash_options,
};
use bussard_service::params::BuiltPlan;
use bussard_service::secure::SecureMaterial;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{DeviceRead, JobObserver, ProductFor, ProgrammingTier, chain, put};
use crate::server::BussardMcp;

/// A full download planned for one device: the image, its options, the
/// security individual address table it writes, and what the plan reports.
pub(super) struct FlashImage {
    /// The plan handed to the download, shaped like `bussard flash --yes`.
    pub(super) plan: FlashPlan,
    /// The download options (`bussard flash --yes`'s).
    pub(super) options: FlashOptions,
    /// The PID 54 table a secured download writes, recorded in the lock
    /// once the flash verifies.
    pub(super) senders: Option<Vec<SecureSenderEntry>>,
    /// The resident object table the probe read, seeding the download.
    pub(super) object_table: Vec<(u8, u16)>,
    /// The plan's `flash` field.
    pub(super) summary: Value,
    /// What the read-back after the flash compares against (issue #319),
    /// set by the apply; `None` on a plan, which never writes.
    pub(super) readback: Option<FlashReadback>,
}

/// The model and product a flash's parameter read-back decodes with (issue
/// #319): the same inputs the plan's read used.
pub(super) struct FlashReadback {
    /// The model the plan was made from.
    pub(super) model: std::sync::Arc<Model>,
    /// The pinned product archive and the application it flashes.
    pub(super) source: bussard_service::params::ProductSource,
    /// The device's mask version, as the pre-flight read it.
    pub(super) device_mask: u16,
}

/// The full download writing the model to `target`, when `built` says the
/// parameter values change the group-object table. `Err` is a refusal
/// reason.
#[allow(clippy::too_many_arguments)] // one plan's context; a struct would only move it
pub(super) fn flash_image(
    dir: &Path,
    model: &Model,
    target: IndividualAddress,
    read: &DeviceRead,
    report: &PlanReport,
    built: &BuiltPlan,
    product: &ProductFor,
    material: &SecureMaterial,
    tunnel: &[IndividualAddress],
) -> Result<FlashImage, String> {
    let why = built
        .needs_flash
        .as_deref()
        .unwrap_or("the group-object table changes");
    let device = model.devices.get(&target).map(|d| &d.device);
    // The CLI flashes the archive the lock pins; so does this.
    let pinned = device.and_then(|d| {
        Some((
            d.lock.product_sha256.clone()?,
            d.lock.product_entry.as_ref()?.file.clone(),
        ))
    });
    let (Some((product_sha256, archive)), Some(source)) = (pinned, product.source.as_ref()) else {
        return Err(format!(
            "the model's parameter values change {target}'s group-object table ({why}), which \
             needs a full download, and bussard.lock pins no product archive for {target}: a \
             flash writes only a pinned archive. Run `bussard import-product` for the device's \
             product (or `bussard import` of the ETS export), then plan again."
        ));
    };
    let Some(app) = source.app() else {
        return Err(format!(
            "the pinned product archive does not carry application {}; run `bussard \
             import-product` for {target}'s product, then plan again",
            source.app_id
        ));
    };
    let Some(detail) = read.params.as_ref().and_then(|p| p.detail.as_ref()) else {
        return Err(format!(
            "{target}'s parameter memory was not read, so a full download cannot be planned; \
             plan again"
        ));
    };
    let device_label = target.to_string();
    let (inputs, malformed) =
        FlashInputs::from_model(&source.product, app, &device_label, Some(model), target);
    for warning in malformed {
        tracing::warn!("{warning}");
    }
    let mask = read.live.tables().mask;
    let mut plan = inputs
        .plan(mask)
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    // The factory-freshness gate of `bussard flash` (issue #79), without its
    // `--force`: a device must carry no application or this one. A System 7
    // device has no readable id, so the read's code sample decides there
    // (issue #314), the verdict the CLI pre-flight decides on too. The image
    // is shaped by the probe's freshness, as `bussard flash` shapes it.
    let freshness = assess_freshness(&detail.resident, &plan.identity);
    let sys7 = read.params.as_ref().and_then(|p| p.sys7_identity.as_ref());
    let gate = flash_gate(&freshness, &plan, Some(&detail.resident), sys7);
    if let Some(why) = gate_refusal(target, &plan, &gate) {
        return Err(why);
    }
    // A self-contained application's download carries no table objects: the
    // flash would leave changed links unwritten.
    if !report.is_noop() && !inputs.table_images().contains_key(&1) {
        return Err(format!(
            "the download of {} does not write the link tables, and {target}'s links change \
             too; this needs `bussard flash {target}` and `bussard apply {target}` at the CLI",
            app.id
        ));
    }
    let senders = inputs
        .finish(
            &mut plan,
            Some(&freshness),
            false,
            Some(model),
            target,
            material,
            tunnel,
        )
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    let options = flash_options(None, false, &plan, &freshness);

    let before = inputs.visible_objects(&detail.decoded.values);
    let after = inputs.visible_objects(inputs.overrides());
    let because: Vec<String> = built
        .parameters
        .iter()
        .map(|p| {
            format!(
                "{} = {}, was {}",
                p.key,
                p.model,
                p.device.as_deref().unwrap_or("unreadable")
            )
        })
        .collect();
    let objects = |numbers: &BTreeSet<u16>| -> Vec<Value> {
        numbers
            .iter()
            .map(|n| {
                let (text, dpt) = com_object_words(app, *n);
                json!({"number": n, "text": text, "dpt": dpt, "because": because})
            })
            .collect()
    };
    let (min, max) = DEVICE_OFFLINE_SECONDS;
    let summary = json!({
        "why": why,
        "identity": read
            .check
            .as_ref()
            .map(|c| bussard_service::identity_line(target, c)),
        "resident": resident_line(&gate),
        "objects": {
            "shown": objects(&after.difference(&before).copied().collect()),
            "hidden": objects(&before.difference(&after).copied().collect()),
        },
        "tables": {
            "address": {
                "before": report.current_address_count,
                "after": report.resulting_address_count,
            },
            "association": {
                "before": report.current_association_count,
                "after": report.resulting_association_count,
            },
            "group_objects": {"before": before.len(), "after": after.len()},
        },
        "device_offline_seconds": {"min": min, "max": max},
        "parameter_backup": {
            "taken_first": true,
            "dir": bussard_download::backup::parameter_backups_dir(dir).display().to_string(),
        },
        "product": {
            "archive": archive,
            "product_sha256": product_sha256,
            "application": app.id,
        },
        "factory_reset": plan.has_factory_reset(),
        "differential": options.skip_matching_mcb,
    });
    Ok(FlashImage {
        plan,
        options,
        senders,
        object_table: detail.resident.object_table.clone(),
        summary,
        readback: None,
    })
}

/// `model` extended with the flash image, so a plan digest binds the exact
/// octets a flash writes. Unchanged without a flash, so an apply plan's
/// digest is what it was.
pub(super) fn with_flash(model: [u8; 32], flash: Option<&FlashImage>) -> [u8; 32] {
    let Some(image) = flash else {
        return model;
    };
    let mut h = Sha256::new();
    put(&mut h, b"flash-v1");
    put(&mut h, &model);
    // The Debug rendering is stable within one build, which is all a digest
    // that lives for one server session needs.
    put(&mut h, format!("{:?}", image.plan).as_bytes());
    put(&mut h, format!("{:?}", image.options).as_bytes());
    h.finalize().into()
}

/// What a flash job needs besides the image.
pub(super) struct FlashJob<'a> {
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
        image: FlashImage,
        ctx: FlashJob<'_>,
        mut result: Value,
    ) -> Value {
        let target = ctx.target;
        let recovery = format!(
            "The device may be left without a loaded application. Its parameter memory before \
             the flash is backed up at {}. Re-planning and re-applying {target} runs the flash \
             again; `bussard flash --force {target}` at the CLI is the recovery when the plan \
             refuses. Do not assume the device works until a new knx_plan_device reports \
             nothing to do.",
            ctx.param_backup.unwrap_or("(no backup)")
        );
        let Some(service) = self.state().bus.service() else {
            result["ok"] = json!(false);
            result["verified"] = json!(false);
            result["reason"] = json!("the bus is not wired");
            return result;
        };
        tier.jobs.step(
            job,
            format!(
                "flashing {target}: the full application download, then the restart (the \
                 device is offline for {} to {} s) and the read-back",
                DEVICE_OFFLINE_SECONDS.0, DEVICE_OFFLINE_SECONDS.1
            ),
        );
        let run = bussard_service::download::FlashRun {
            service,
            target,
            source: ctx.source,
            options: image.options,
            facts: DeviceFacts {
                object_table: image.object_table.clone(),
                ..DeviceFacts::default()
            },
            tool_key: ctx.tool_key,
            high_water: ctx.high_water,
            handover: None,
        };
        let mut observer = JobObserver {
            jobs: &tier.jobs,
            job,
            what: "download",
        };
        // Issue #319: on the flash's last connection, read the parameter
        // memory back and compare it with the model the way a plan does.
        let readback = image.readback.as_ref();
        let jobs = &tier.jobs;
        let flash_plan = &image.plan;
        let (outcome, flashed) =
            bussard_service::download::flash_session(run, flash_plan, &mut observer, async |l4| {
                let rb = readback?;
                let app = rb.source.app()?;
                jobs.step(
                    job,
                    format!(
                        "reading {target} back (tables, parameters, security object) to \
                         compare it with the model"
                    ),
                );
                // Issue #349: the one post-write read-back the CLI runs too.
                let expected = bussard_service::verify::Expected::for_flash(
                    flash_plan,
                    &rb.source.product,
                    app,
                    Some(&rb.model),
                    target,
                    rb.device_mask,
                );
                Some(bussard_service::verify::read_back(l4, &expected).await)
            })
            .await;
        let flashed = flashed.flatten();
        // Anything still differing fails the flash; a parameter read-back
        // that could not be made leaves `parameters.verified` false with its
        // note.
        let params_differ = flashed.as_ref().and_then(|f| f.failure());
        let flashed_params = flashed.as_ref().and_then(|f| f.parameters.as_ref());
        let params_verified =
            flashed_params.is_some_and(bussard_service::params::FlashedParameters::verified);
        let verified = matches!(&outcome, Ok(o) if o.ok()) && params_differ.is_none();
        tracing::info!(
            "audit: knx_apply_device {target} flash via {}: {}",
            ctx.gateway,
            if verified { "verified" } else { "FAILED" }
        );
        match outcome {
            Ok(done) if done.ok() => {
                result["ok"] = json!(params_differ.is_none());
                result["verified"] = json!(params_differ.is_none());
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
                if let Some(readback) = &flashed {
                    result["readback"] = json!(readback);
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
                         differ from the model. Plan {target} again with knx_plan_device to \
                         see what is left, and do not report the change as done until a plan \
                         reports nothing to do."
                    ));
                }
                // The verified flash wrote this PID 54 table: record it in
                // the lock, as `bussard flash` does (issue #297).
                if let Some(senders) = &image.senders {
                    match bussard_service::admission::record_secure_senders(
                        ctx.dir, target, senders,
                    ) {
                        Ok(recorded) => result["secure_senders_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["secure_senders_recorded"] = json!(false);
                            result["secure_senders_note"] = json!(err.to_string());
                        }
                    }
                }
                // And the group-object flags it wrote (PID 61, issue #331).
                if let Some(objects) =
                    bussard_service::security_change::flash_secured_objects(&image.plan)
                {
                    match bussard_service::security_change::record_security_flags(
                        ctx.dir, target, &objects,
                    ) {
                        Ok(recorded) => result["security_flags_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["security_flags_recorded"] = json!(false);
                            result["security_flags_note"] = json!(err.to_string());
                        }
                    }
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
                if let Some(readback) = &flashed {
                    result["readback"] = json!(readback);
                }
                result["recovery"] = json!(recovery);
            }
            Err(err) => {
                result["ok"] = json!(false);
                result["verified"] = json!(false);
                result["reason"] = json!(format!("the flash failed: {}", chain(&err)));
                result["recovery"] = json!(recovery);
            }
        }
        result
    }
}

/// The refusal of the flash gate, `None` when the flash may go ahead: the
/// device carries another application, or what it carries could not be
/// confirmed. Only a device that differs names `bussard flash --force`.
fn gate_refusal(target: IndividualAddress, plan: &FlashPlan, gate: &Freshness) -> Option<String> {
    let expected = &plan.identity.id;
    match gate {
        Freshness::Fresh | Freshness::SameApplication { .. } => None,
        Freshness::Resident {
            reason: Some(reason),
            ..
        } => Some(format!(
            "{target} does not run the application this flash writes ({expected}): {reason}; \
             replacing it is `bussard flash --force {target}` at the CLI"
        )),
        Freshness::Resident {
            resident: Some(id), ..
        } => Some(format!(
            "{target} runs application {id}, not the one this flash writes ({expected}); \
             replacing it is `bussard flash --force {target}` at the CLI"
        )),
        Freshness::Resident { resident: None, .. } => Some(format!(
            "{target} runs an application whose id (PID_PROGRAM_VERSION) cannot be read, so \
             it cannot be confirmed to be {expected}; replacing it is `bussard flash --force \
             {target}` at the CLI"
        )),
        Freshness::Unknown { reason } => Some(format!(
            "{target}'s resident application could not be confirmed ({reason}), so a flash \
             cannot tell what it replaces; check the device and plan again"
        )),
    }
}

/// The flash plan's `resident` field: what the gate found on the device.
fn resident_line(gate: &Freshness) -> String {
    match gate {
        Freshness::Fresh => "no application is loaded (factory-fresh)".to_string(),
        Freshness::SameApplication { resident } => {
            format!("runs this application ({resident})")
        }
        Freshness::Resident { resident, .. } => format!(
            "runs another application ({})",
            resident.as_deref().unwrap_or("unidentified")
        ),
        Freshness::Unknown { reason } => format!("unknown ({reason})"),
    }
}
