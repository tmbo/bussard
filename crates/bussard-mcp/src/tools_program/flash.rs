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
//! The image is the one `bussard flash --yes` writes: it is built with
//! [`bussard_service::flash::FlashInputs`] from the product data bussard.lock
//! pins, the model and the factory-freshness verdict of the read-only probe,
//! shaped by [`FlashInputs::finish`] and downloaded by
//! [`bussard_service::flash_flow::flash_and_verify`], the function `bussard
//! flash` runs, so the offline oracle (`scripts/campaign/95-offline-oracle.sh`)
//! covers this path too. The refusals are the CLI's without `--force`: no
//! archive pinned in the lock, a device whose state the probe could not
//! read or whose application cannot be identified
//! ([`bussard_service::flash_flow::load_refusal`]).
//!
//! A self-contained application's download writes no link table (issue
//! #779). When the links differ from the model, the job writes them after
//! the verified download with the table write of `bussard apply`, as `bussard
//! replace` runs `flash` and then `apply`; the one yes covers both, and the
//! result is verified only when the table write's read-back matches.

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
    /// Why the application must be loaded (issue #750), `None` when the
    /// flash writes a parameter change of the application the device runs.
    pub(super) load: Option<String>,
    /// Whether the links are written after the download (issue #779): the
    /// download of a self-contained application writes no link table, so
    /// when the links differ from the model, or a factory reset erases them,
    /// the job writes them with the table write `bussard apply` runs once
    /// the download verified, as `bussard replace` chains `flash` and
    /// `apply`.
    pub(super) links_after: bool,
    /// What the device reported that the plan relied on (its identity and
    /// the freshness verdict), bound into the digest.
    binds: String,
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
    let pinned = pinned_product(
        model,
        target,
        product,
        &format!(
            "the model's parameter values change {target}'s group-object table ({why}), which \
             needs a full download"
        ),
    )?;
    let Some(app) = pinned.source.app() else {
        return Err(missing_app(target, pinned.source));
    };
    let Some(detail) = read.params.as_ref().and_then(|p| p.detail.as_ref()) else {
        return Err(format!(
            "{target}'s parameter memory was not read, so a full download cannot be planned; \
             plan again"
        ));
    };
    let device_label = target.to_string();
    let (inputs, malformed) = FlashInputs::from_model(
        &pinned.source.product,
        app,
        &device_label,
        Some(model),
        target,
    );
    for warning in malformed {
        tracing::warn!("{warning}");
    }
    let mask = read.live.tables().mask;
    let plan = inputs
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
    // links that change are written after it (issue #779).
    let links_after = links_after(model, target, report, &plan, &freshness, &detail.resident);
    let before = inputs.visible_objects(&detail.decoded.values);
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
    shape(
        Shaping {
            dir,
            model,
            target,
            read,
            report,
            material,
            tunnel,
            why,
            load: None,
            before: Some(before),
            because,
            parameter_backup: true,
            links_after,
        },
        &pinned,
        &inputs,
        plan,
        &freshness,
        &gate,
        &detail.resident,
    )
}

/// Why the application program bussard.lock pins must be loaded into the
/// device before the model can be written to it (issue #750).
pub(super) struct LoadNeed {
    /// The sentence the plan leads with.
    pub(super) why: String,
}

/// Whether `target` needs the application bussard.lock pins loaded: it runs
/// another one (the identity verdict, or the System 7 code sample), has
/// none, or holds the pinned one unloaded. `None` when it runs the pinned
/// application, or when no product data is at hand to load (the caller's
/// drift refusal then names `bussard flash`). `Some(Err)` is a refusal: the
/// load is needed but must not run on a plan's yes.
pub(super) fn load_need(
    model: &Model,
    target: IndividualAddress,
    read: &DeviceRead,
    product: &ProductFor,
) -> Option<Result<LoadNeed, String>> {
    let params = read.params.as_ref()?;
    let resident = params.resident()?;
    let source = product.source.as_ref()?;
    let app = source.app()?;
    let device_label = target.to_string();
    let (inputs, _) =
        FlashInputs::from_model(&source.product, app, &device_label, Some(model), target);
    let drift = read.check.as_ref().is_some_and(|c| c.is_drift());
    let plan = match inputs.plan(read.live.tables().mask) {
        Ok(plan) => plan,
        Err(err) if drift => {
            return Some(Err(format!(
                "{target} needs application {} loaded, and it cannot be planned for this \
                 device: {err}",
                app.id
            )));
        }
        Err(_) => return None,
    };
    // A property-only procedure loads no object (issue #390): there is
    // nothing to load.
    if plan.is_property_only() {
        return None;
    }
    let freshness = assess_freshness(resident, &plan.identity);
    let gate = flash_gate(
        &freshness,
        &plan,
        Some(resident),
        params.sys7_identity.as_ref(),
    );
    let why = bussard_service::flash_flow::load_reason(
        target,
        read.check.as_ref(),
        &gate,
        resident,
        &app.id,
    )?;
    if let Some(refusal) = bussard_service::flash_flow::load_refusal(target, &gate) {
        return Some(Err(format!("{why}; {refusal}")));
    }
    Some(Ok(LoadNeed { why }))
}

/// The full download that loads the application bussard.lock pins (issue
/// #750), shaped as `bussard flash` shapes it for the probe's verdict: a
/// factory reset first when the device runs another application. `Err` is a
/// refusal reason.
#[allow(clippy::too_many_arguments)] // one plan's context; a struct would only move it
pub(super) fn load_image(
    dir: &Path,
    model: &Model,
    target: IndividualAddress,
    read: &DeviceRead,
    report: &PlanReport,
    product: &ProductFor,
    material: &SecureMaterial,
    tunnel: &[IndividualAddress],
    need: &LoadNeed,
) -> Result<FlashImage, String> {
    let pinned = pinned_product(model, target, product, &need.why)?;
    let Some(app) = pinned.source.app() else {
        return Err(missing_app(target, pinned.source));
    };
    let Some(resident) = read.params.as_ref().and_then(|p| p.resident()) else {
        return Err(format!(
            "{target}'s resident application could not be probed, so loading {} cannot be \
             planned; plan again",
            app.id
        ));
    };
    let device_label = target.to_string();
    let (inputs, malformed) = FlashInputs::from_model(
        &pinned.source.product,
        app,
        &device_label,
        Some(model),
        target,
    );
    for warning in malformed {
        tracing::warn!("{warning}");
    }
    let plan = inputs
        .plan(read.live.tables().mask)
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    let freshness = assess_freshness(resident, &plan.identity);
    let sys7 = read.params.as_ref().and_then(|p| p.sys7_identity.as_ref());
    let gate = flash_gate(&freshness, &plan, Some(resident), sys7);
    if let Some(refusal) = bussard_service::flash_flow::load_refusal(target, &gate) {
        return Err(format!("{}; {refusal}", need.why));
    }
    // A download that does not load the link tables leaves them as the
    // device holds them, and a factory reset erases them: the links are then
    // written after the load (issue #779).
    let links_after = links_after(model, target, report, &plan, &freshness, resident);
    shape(
        Shaping {
            dir,
            model,
            target,
            read,
            report,
            material,
            tunnel,
            why: &need.why,
            load: Some(need.why.clone()),
            before: None,
            because: Vec::new(),
            parameter_backup: false,
            links_after,
        },
        &pinned,
        &inputs,
        plan,
        &freshness,
        &gate,
        resident,
    )
}

/// Whether the links must be written after `plan`'s download (issue #779):
/// it loads no link table (a self-contained application), and the links
/// differ from the model, or the factory reset the download starts with
/// erases the links the device holds while the model has some. The flash's
/// read-back does not compare tables it did not write, so without the table
/// write after it the job would end with links that differ from the model.
fn links_after(
    model: &Model,
    target: IndividualAddress,
    report: &PlanReport,
    plan: &FlashPlan,
    freshness: &Freshness,
    resident: &bussard_download::ResidentState,
) -> bool {
    if bussard_service::flash_flow::loads_link_tables(plan) {
        return false;
    }
    if !report.is_noop() {
        return true;
    }
    let mut probe = plan.clone();
    bussard_service::flash::apply_freshness(
        &mut probe,
        Some(freshness),
        Some(resident),
        false,
        false,
    );
    let has_links = model
        .links
        .links
        .get(&target)
        .is_some_and(|l| !l.is_empty());
    probe.erases_resident_objects() && has_links
}

/// The archive bussard.lock pins for the device and its application.
struct Pinned<'p> {
    /// The archive's SHA-256, as the lock records it.
    product_sha256: String,
    /// The archive's path in the model directory.
    archive: Option<String>,
    /// The parsed archive; it carries the application the lock pins
    /// ([`pinned_product`] checked).
    source: &'p bussard_service::params::ProductSource,
}

/// The pinned archive of `target`, or the refusal naming `why` the
/// download is needed: a flash writes only a pinned archive.
fn pinned_product<'p>(
    model: &Model,
    target: IndividualAddress,
    product: &'p ProductFor,
    why: &str,
) -> Result<Pinned<'p>, String> {
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
            "{why}, and bussard.lock pins no product archive for {target}: a flash writes only \
             a pinned archive. Run `bussard import-product` for the device's product (or \
             `bussard import` of the ETS export), then plan again."
        ));
    };
    if source.app().is_none() {
        return Err(missing_app(target, source));
    }
    Ok(Pinned {
        product_sha256,
        archive,
        source,
    })
}

/// The refusal for a pinned archive without the pinned application.
fn missing_app(
    target: IndividualAddress,
    source: &bussard_service::params::ProductSource,
) -> String {
    format!(
        "the pinned product archive does not carry application {}; run `bussard \
         import-product` for {target}'s product, then plan again",
        source.app_id
    )
}

/// The plan-specific inputs of [`shape`].
struct Shaping<'a> {
    dir: &'a Path,
    model: &'a Model,
    target: IndividualAddress,
    read: &'a DeviceRead,
    report: &'a PlanReport,
    material: &'a SecureMaterial,
    tunnel: &'a [IndividualAddress],
    /// Why the download is needed.
    why: &'a str,
    /// Why the application must be loaded, on a load.
    load: Option<String>,
    /// The com-objects the device shows now, when its parameters were read.
    before: Option<BTreeSet<u16>>,
    /// The parameter changes behind a com-object change.
    because: Vec<String>,
    /// Whether the parameter memory is backed up first (it is readable).
    parameter_backup: bool,
    /// Whether the links are written after the download (issue #779).
    links_after: bool,
}

/// Shapes `plan` as `bussard flash` does for the verdict (the factory reset
/// or `par` procedure, the security object, the options) and builds the
/// plan's `flash` field.
fn shape(
    s: Shaping<'_>,
    pinned: &Pinned<'_>,
    inputs: &FlashInputs<'_>,
    mut plan: FlashPlan,
    freshness: &Freshness,
    gate: &Freshness,
    resident: &bussard_download::ResidentState,
) -> Result<FlashImage, String> {
    let target = s.target;
    let senders = inputs
        .finish(
            &mut plan,
            Some(freshness),
            Some(resident),
            false,
            // An application download, as the CLI's `flash` without `--full`:
            // no System 7 pre-download pass (issue #488).
            false,
            Some(s.model),
            target,
            s.material,
            s.tunnel,
        )
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    let options = flash_options(None, false, &plan, freshness);
    let after = inputs.visible_objects(inputs.overrides());
    let app = inputs.app();
    let objects = |numbers: &BTreeSet<u16>| -> Vec<Value> {
        numbers
            .iter()
            .map(|n| {
                let (text, dpt) = com_object_words(app, *n);
                json!({"number": n, "text": text, "dpt": dpt, "because": s.because})
            })
            .collect()
    };
    let (shown, hidden, objects_before) = match &s.before {
        Some(before) => (
            after.difference(before).copied().collect(),
            before.difference(&after).copied().collect(),
            json!(before.len()),
        ),
        // A load: every com-object the model's values show is new.
        None => (after.clone(), BTreeSet::new(), Value::Null),
    };
    let (min, max) = DEVICE_OFFLINE_SECONDS;
    let read = s.read;
    let report = s.report;
    let summary = json!({
        "why": s.why,
        "load_application": s.load.as_ref().map(|why| json!({
            "why": why,
            "application": app.id,
            "replaces": resident_line(gate),
        })),
        "identity": read
            .check
            .as_ref()
            .map(|c| bussard_service::identity_line(target, c)),
        "resident": resident_line(gate),
        "objects": {
            "shown": objects(&shown),
            "hidden": objects(&hidden),
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
            "group_objects": {"before": objects_before, "after": after.len()},
        },
        "device_offline_seconds": {"min": min, "max": max},
        "parameter_backup": {
            "taken_first": s.parameter_backup,
            "dir": bussard_download::backup::parameter_backups_dir(s.dir).display().to_string(),
        },
        "product": {
            "archive": pinned.archive,
            "product_sha256": pinned.product_sha256,
            "application": app.id,
        },
        "factory_reset": plan.has_factory_reset(),
        "differential": options.skip_matching_mcb,
        // Issue #779: the download writes no link table; the job writes the
        // links after it with the table write `bussard apply` runs.
        "links_after_download": s.links_after,
    });
    let binds = format!(
        "{:?}|{:?}|{:?}",
        read.check.as_ref().map(|c| &c.device),
        gate,
        resident.app_id
    );
    Ok(FlashImage {
        plan,
        options,
        senders,
        object_table: resident.object_table.clone(),
        summary,
        readback: None,
        load: s.load,
        links_after: s.links_after,
        binds,
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
    // A yes to a load with the table write after it (issue #779) is a yes
    // to both.
    if image.links_after {
        put(&mut h, b"links-after");
    }
    // What the device reported, for a load (issue #750): a yes to replacing
    // one application is not a yes to replacing another.
    if image.load.is_some() {
        put(&mut h, b"load");
        put(&mut h, image.binds.as_bytes());
    }
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
        // Issues #319, #349: on the flash's last connection, the one
        // read-back `bussard flash` runs too (the same function).
        let expected = image.readback.as_ref().and_then(|rb| {
            rb.source
                .app()
                .map(|app| bussard_service::flash_flow::ReadbackInputs {
                    product: &rb.source.product,
                    app,
                    model: Some(&rb.model),
                    device_mask: rb.device_mask,
                })
        });
        if expected.is_none() {
            tracing::warn!("{target}: the flash runs without its read-back inputs");
        }
        let flashed = bussard_service::flash_flow::flash_and_verify(
            run,
            &image.plan,
            &mut observer,
            expected,
            target,
        )
        .await;
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
                // flags: record them in the lock, as `bussard flash` does
                // (issues #297, #331).
                let record = bussard_service::flash_flow::record_lock(
                    ctx.dir,
                    target,
                    image.senders.as_deref(),
                    &image.plan,
                );
                if let Some((recorded, _)) = record.senders {
                    match recorded {
                        Ok(recorded) => result["secure_senders_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["secure_senders_recorded"] = json!(false);
                            result["secure_senders_note"] = json!(err);
                        }
                    }
                }
                if let Some((recorded, _)) = record.flags {
                    match recorded {
                        Ok(recorded) => result["security_flags_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["security_flags_recorded"] = json!(false);
                            result["security_flags_note"] = json!(err);
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
        Freshness::Mismatch { reason } => Some(format!(
            "{target} does not match this download: {reason}; nothing was written"
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
        Freshness::Mismatch { reason } => format!("does not match ({reason})"),
        Freshness::Unknown { reason } => format!("unknown ({reason})"),
    }
}
