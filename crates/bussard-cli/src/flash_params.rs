//! `bussard flash --parameters-only`: rewrite only a device's parameter memory
//! (issue #119).
//!
//! The full `flash` pipeline builds the plan and runs the read-only pre-flight
//! probe; this module takes over from there:
//!
//! 1. **Refuse** unless the device runs the very application the product file
//!    describes (System B: `PID_PROGRAM_VERSION` matches; System 7, which has no
//!    readable application id: every load-state machine is `Loaded` and the
//!    application's code segments read back as the product's bytes).
//! 2. Read the parameter memory back and cut the full plan down to it
//!    ([`FlashPlan::parameters_only`]). Refuse when a parameter segment cannot
//!    be read, or when the new values would change the group-object table (a
//!    parameter that shows or hides a com-object needs the full flash). On
//!    System 7, also refuse when the model's links differ from the device's
//!    link tables: the table load-state machines are not reloaded (`apply`
//!    rewrites them).
//! 3. Show the plan: the parameters that change, the regions and octets.
//!    Nothing to change exits 0 without touching a load state.
//! 4. Confirm (a terminal, or `--yes`), snapshot the model history, and back up
//!    the parameter memory before the first write.
//! 5. Write only the changed octets, complete the load, restart, and verify by
//!    reading the parameter memory back.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context as _;
use bussard_bus::ops;
use bussard_download::backup::{
    ParameterBackup, ParameterMemory, encode_hex, parameter_backups_dir, rfc3339_utc, unix_seconds,
    write_parameter_backup,
};
use bussard_download::{
    FlashPlan, FlashStep, Freshness, ParamPlan, ParamRegions, ResidentState, assess_freshness,
    decode_parameters, group_object_change, read_parameter_regions, regions_memory,
};
use bussard_mgmt::memory::read_memory_range;
use bussard_model::IndividualAddress;
use bussard_prod::ApplicationProgram;
use bussard_service::{Authorize, BusService, L4Options, ServiceError, SourcePolicy};

/// Everything the parameter-only download needs from the `flash` pipeline.
pub(crate) struct Context<'a> {
    /// The command's runtime (one tunnel for the whole command).
    pub runtime: &'a tokio::runtime::Runtime,
    /// The bus service the pre-flight ran on.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The tunnel's checked source address.
    pub source: IndividualAddress,
    /// The resolved gateway, for the prompt and the history.
    pub gateway: String,
    /// The model directory.
    pub dir: &'a Path,
    /// `--yes`.
    pub yes: bool,
    /// `--json`.
    pub json: bool,
    /// The selected application program.
    pub app: &'a ApplicationProgram,
    /// The full flash plan, as `flash` would run it.
    pub plan: &'a FlashPlan,
    /// The model's parameter overrides, keyed by app-relative ParameterRef id.
    pub overrides: &'a BTreeMap<String, String>,
    /// The module-instance base offsets.
    pub base_offsets: &'a BTreeMap<String, u32>,
    /// What the read-only pre-flight found resident.
    pub resident: Option<&'a ResidentState>,
    /// What the pre-flight learned about the device, for the write session.
    pub facts: bussard_download::DeviceFacts,
    /// The BCU key, if any.
    pub bcu_key: Option<u32>,
    /// The KNX Data Secure tool key, if any.
    pub tool_key: Option<bussard_secure::Key16>,
    /// The command-wide secure sequence high-water mark.
    pub secure_seq: bussard_secure::SequenceHighWater,
}

/// Runs the parameter-only download (module docs).
pub(crate) fn run(ctx: Context<'_>) -> anyhow::Result<ExitCode> {
    let target = ctx.target;
    if let Err(reason) = identity_gate(ctx.plan, ctx.resident) {
        eprintln!("refusing the parameter-only download to {target}: {reason}");
        return Ok(ExitCode::FAILURE);
    }

    // Read the parameter memory (and, on System 7, sample the code segments that
    // stand in for the application id) over one read-only session.
    let read = ctx.runtime.block_on(read_device(&ctx))?;
    if let Some(reason) = read.code_mismatch {
        eprintln!("refusing the parameter-only download to {target}: {reason}");
        return Ok(ExitCode::FAILURE);
    }
    // A parameter-only download leaves the table load-state machines alone,
    // so links that differ from the device need `apply` first (issue #146).
    if let Some(reason) = read.table_change {
        eprintln!(
            "refusing the parameter-only download to {target}: {reason}. A parameter-only \
             download does not rewrite the link tables; run `bussard apply` for the links \
             first, then re-run `bussard flash --parameters-only {target}`."
        );
        return Ok(ExitCode::FAILURE);
    }
    let regions = read.regions;

    let partial = match ctx.plan.parameters_only(&regions) {
        Ok(partial) => partial,
        Err(err) => {
            eprintln!("refusing the parameter-only download to {target}: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };

    // A parameter that shows or hides a com-object changes the group-object
    // table, which this download does not rewrite.
    // The device's values come from the same decoder the read-back uses: the
    // encoder's own placements, so a device holding the model's image decodes
    // to the model and the check cannot misfire on it (issue #142).
    let current = regions_memory(&regions);
    let decoded = decode_parameters(ctx.app, ctx.overrides, ctx.base_offsets, &current);
    let change = group_object_change(ctx.app, &decoded.values, ctx.overrides);
    if !change.is_empty() {
        eprintln!(
            "refusing the parameter-only download to {target}: the new parameter values \
             change the group-object table ({}); a parameter-only download leaves that \
             table as it is. Run a full `bussard flash {target}` instead.",
            describe_group_object_change(&change)
        );
        return Ok(ExitCode::FAILURE);
    }

    let params = ParamPlan {
        changes: decoded.differences,
        unknown: decoded.unknown,
        note: None,
    };
    if ctx.json {
        print_json(target, &partial, &regions, &params)?;
    } else {
        print_plan(target, &partial, &regions, &params);
    }
    if partial.changed_octets() == 0 {
        println!(
            "\nnothing to do: {target} already holds these parameter values (no load state touched)"
        );
        return Ok(ExitCode::SUCCESS);
    }

    if !confirm(target, &ctx.gateway, ctx.yes, partial.changed_octets())? {
        eprintln!("aborted: nothing written.");
        return Ok(ExitCode::FAILURE);
    }

    crate::history_cmd::snapshot(
        ctx.dir,
        bussard_model::history::SnapshotReason::new("flash --parameters-only")
            .with_args([target.to_string()])
            .with_gateway(Some(ctx.gateway.clone()))
            .with_result("before downloading the parameters"),
    );

    // Back up the parameter memory before the first write; no backup, no write.
    let backup_path = write_backup(ctx.dir, target, ctx.plan, &regions).with_context(|| {
        "writing the parameter backup (refusing to write without a backup)".to_string()
    })?;
    println!("parameter backup written to {}", backup_path.display());

    let options = bussard_download::FlashOptions {
        bcu_key: ctx.bcu_key,
        verify_after_restart: true,
        skip_matching_mcb: false,
    };
    let outcome = ctx.runtime.block_on(crate::flash_cmd::execute(
        ctx.service,
        target,
        ctx.source,
        &partial,
        options,
        ctx.facts.clone(),
        ctx.tool_key.clone(),
        ctx.secure_seq.clone(),
        ctx.json,
        &std::cell::Cell::new(None),
    ));
    match outcome {
        Ok(outcome) if outcome.ok() => {}
        Ok(outcome) => {
            eprintln!("\nERROR: the parameter download did not verify: {outcome:?}");
            recovery_notice(target, &backup_path);
            return Ok(ExitCode::FAILURE);
        }
        Err(err) => {
            eprintln!("\nERROR: the parameter download failed: {err}");
            recovery_notice(target, &backup_path);
            return Ok(ExitCode::FAILURE);
        }
    }

    // Verify like `apply`: read the parameter memory back and compare every
    // octet the download meant to change.
    let after = ctx.runtime.block_on(read_device(&ctx))?.regions;
    match verify_readback(&partial, &after, &runtime_segments(ctx.plan)) {
        Ok(octets) => {
            println!(
                "\nparameters verified: {octets} changed octet(s) read back from {target}; \
                 the application is Loaded"
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(reason) => {
            eprintln!("\nERROR: the parameter read-back does not match: {reason}");
            recovery_notice(target, &backup_path);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The resident-application rule: the device must run the application the
/// product file describes, and it must be `Loaded`.
///
/// One rule for every caller that trusts the resident parameter layout (the
/// parameter-only download and the `plan`/`reconstruct` read-back, issue
/// #142). System B compares `PID_PROGRAM_VERSION` (manufacturer, application
/// number and version: a product build with another hash is the same
/// program). System 7 has no readable id: every load-state machine the
/// application's procedure drives must be `Loaded`, and the caller samples the
/// code segments with [`sys7_code_mismatch`].
pub(crate) fn identity_gate(
    plan: &FlashPlan,
    resident: Option<&ResidentState>,
) -> Result<(), String> {
    let Some(state) = resident else {
        return Err(
            "the pre-flight probe did not run, so the resident application is unknown".into(),
        );
    };
    let expected = &plan.identity.id;
    match assess_freshness(state, &plan.identity) {
        Freshness::SameApplication { .. } => Ok(()),
        Freshness::Fresh => Err(format!(
            "the device holds no loaded application (it is not Loaded); a parameter-only \
             download needs {expected} in place. Run a full `bussard flash` first."
        )),
        Freshness::Unknown { reason } => Err(format!(
            "the device's load state could not be read ({reason})"
        )),
        Freshness::Resident {
            resident: Some(id), ..
        } => Err(format!(
            "the device runs application {id}, not {expected}; its parameter memory does not \
             have this application's layout. Run a full `bussard flash` to replace it."
        )),
        Freshness::Resident { resident: None, .. } if plan.is_sys7() => {
            // System 7 exposes no application id. Every load-state machine must
            // be Loaded; the code-segment comparison in `read_device` stands in
            // for the id.
            let driven: std::collections::BTreeSet<u32> = plan
                .steps
                .iter()
                .filter_map(|step| match step {
                    FlashStep::Sys7StartLoading { lsm } => Some(*lsm),
                    _ => None,
                })
                .collect();
            let unloaded: Vec<String> = state
                .objects
                .iter()
                // An LSM the application's procedure never loads (the probe
                // reads every one the mask defines) says nothing about it.
                .filter(|o| driven.is_empty() || driven.contains(&u32::from(o.index)))
                .filter(|o| o.state != bussard_mgmt::load::LoadState::Loaded)
                .map(|o| format!("{} is {}", o.label(), o.state))
                .collect();
            if unloaded.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "the device is not fully Loaded ({}); run a full `bussard flash`",
                    unloaded.join(", ")
                ))
            }
        }
        Freshness::Resident { resident: None, .. } => Err(format!(
            "the device runs an application whose id (PID_PROGRAM_VERSION) cannot be read, so \
             it cannot be confirmed to be {expected}"
        )),
    }
}

/// What one read-only pass learned.
struct DeviceRead {
    /// The parameter regions.
    regions: ParamRegions,
    /// Why the System 7 code comparison says this is another application.
    code_mismatch: Option<String>,
    /// Which System 7 link table the model would change (issue #146).
    table_change: Option<String>,
}

/// Opens a read-only session and reads the parameter regions (plus, on System
/// 7, the code-segment samples).
async fn read_device(ctx: &Context<'_>) -> anyhow::Result<DeviceRead> {
    let options = L4Options {
        source: SourcePolicy::Known(ops::group_source(ctx.service.handle())),
        tool_key: ctx.tool_key.clone(),
        high_water: ctx.secure_seq.clone(),
        // Best-effort: a denial or a device without authorize still reads.
        authorize: Authorize::BestEffort(
            ctx.bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ),
        ..L4Options::default()
    };
    ctx.service
        .with_device(ctx.target, &options, async |dev| {
            // The pre-flight negotiated PID_MAX_APDU_LENGTH; seed it so the
            // read-back goes out in APDU-sized chunks without re-reading it
            // (issue #194).
            dev.l4_mut().set_max_apdu(ctx.facts.max_apdu);
            let regions = read_parameter_regions(dev.l4_mut(), ctx.plan).await;
            let (code_mismatch, table_change) = if ctx.plan.is_sys7() {
                (
                    sys7_code_mismatch(dev.l4_mut(), ctx.plan).await,
                    sys7_table_change(dev.l4_mut(), ctx.plan).await,
                )
            } else {
                (None, None)
            };
            Ok::<_, ServiceError>(DeviceRead {
                regions,
                code_mismatch,
                table_change,
            })
        })
        .await
        .with_context(|| format!("connecting to {} to read its parameters", ctx.target))
}

/// How many leading octets of each System 7 code segment are compared.
const CODE_SAMPLE: usize = 32;

/// Compares the leading octets of every System 7 code segment (a data-bearing
/// segment no parameter targets) against the product's bytes. System 7 has no
/// readable application id, so resident code that differs is the evidence of a
/// different application. `None` when every sampled segment matches, or when
/// there is none to sample.
pub(crate) async fn sys7_code_mismatch<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Option<String> {
    for step in &plan.steps {
        let FlashStep::Sys7AbsSegment {
            address,
            image: Some(image),
            checksum_ctrl,
            ..
        } = step
        else {
            continue;
        };
        // Parameter segments are what changes; runtime-writable segments are
        // rewritten by the running application; table segments are the links.
        let carries_params = plan
            .param_images
            .get(&image.segment_id)
            .is_some_and(|b| !b.is_empty());
        if carries_params || *checksum_ctrl == 0 || image.kind == bussard_download::ImageKind::Table
        {
            continue;
        }
        let Some(expected) = plan.image_bytes(&image.segment_id) else {
            continue;
        };
        let len = expected.len().min(CODE_SAMPLE);
        let Ok(got) = read_memory_range(l4, *address, len).await else {
            continue;
        };
        let mask = plan.segment_mask(&image.segment_id);
        let differs = (0..len)
            .any(|i| mask.is_none_or(|m| m.get(i) == Some(&0xFF)) && got.get(i) != expected.get(i));
        if differs {
            return Some(format!(
                "the code at {address:#06X} ({}) does not match {}; the device runs another \
                 application or version. Run a full `bussard flash` to replace it.",
                image.segment_id, plan.identity.id
            ));
        }
    }
    None
}

/// Names the first System 7 link table (LSM 1 group addresses, LSM 2
/// associations) whose resident content differs from what the full plan
/// computes from the model, or that cannot be read (issue #146). `None` when
/// every table matches.
///
/// The group-address table is compared octet by octet under its mask (the
/// own-address slot is device-owned); the association table as a set of
/// `(TSAP, ASAP)` pairs, since the order of equal links carries no meaning.
pub(crate) async fn sys7_table_change<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Option<String> {
    for step in &plan.steps {
        let FlashStep::Sys7AbsSegment {
            lsm,
            address,
            size,
            image: Some(image),
            ..
        } = step
        else {
            continue;
        };
        if image.kind != bussard_download::ImageKind::Table {
            continue;
        }
        let Some(desired) = plan.image_bytes(&image.segment_id) else {
            continue;
        };
        let got = match read_memory_range(l4, *address, desired.len()).await {
            Ok(got) => got,
            Err(err) => {
                return Some(format!(
                    "the LSM {lsm} link table at {address:#06X} could not be read ({err})"
                ));
            }
        };
        let mask = plan.segment_mask(&image.segment_id);
        let same_octets = desired
            .iter()
            .enumerate()
            .all(|(i, b)| mask.is_some_and(|m| m.get(i) != Some(&0xFF)) || got.get(i) == Some(b));
        if same_octets {
            continue;
        }
        let capacity = usize::try_from(*size).unwrap_or(usize::MAX);
        let same_links = *lsm == 2
            && match (
                bussard_download::decode_sys7_association_table(desired, capacity),
                bussard_download::decode_sys7_association_table(&got, capacity),
            ) {
                (Ok(mut want), Ok(mut have)) => {
                    want.sort_unstable();
                    have.sort_unstable();
                    want == have
                }
                _ => false,
            };
        if !same_links {
            let table = if *lsm == 1 {
                "group-address table"
            } else if *lsm == 2 {
                "association table"
            } else {
                "link table"
            };
            return Some(format!(
                "the model's links differ from the device's {table} (LSM {lsm} at {address:#06X})"
            ));
        }
    }
    None
}

/// Names what a group-object change shows and hides.
pub(crate) fn describe_group_object_change(change: &bussard_download::GroupObjectChange) -> String {
    let list = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
    let mut parts = Vec::new();
    if !change.shown.is_empty() {
        parts.push(format!("shows object(s) {}", list(&change.shown)));
    }
    if !change.hidden.is_empty() {
        parts.push(format!("hides object(s) {}", list(&change.hidden)));
    }
    if parts.is_empty() {
        parts.push("changes an object's size or flags".to_string());
    }
    parts.join(", ")
}

/// The memory regions the download writes: `(segment, address, octets, changed)`.
fn region_rows(partial: &FlashPlan, regions: &ParamRegions) -> Vec<(String, u32, usize, usize)> {
    regions
        .values()
        .filter_map(|r| {
            let current = partial.baseline(&r.segment_id)?;
            let desired = partial.image_bytes(&r.segment_id)?;
            let mask = partial.segment_mask(&r.segment_id);
            let changed = desired
                .iter()
                .enumerate()
                .filter(|(i, b)| {
                    mask.is_none_or(|m| m.get(*i) == Some(&0xFF)) && current.get(*i) != Some(*b)
                })
                .count();
            Some((r.segment_id.clone(), r.address, desired.len(), changed))
        })
        .collect()
}

/// Prints the parameter-only plan.
fn print_plan(
    target: IndividualAddress,
    partial: &FlashPlan,
    regions: &ParamRegions,
    params: &ParamPlan,
) {
    println!("Parameter-only download for {target}");
    println!(
        "  application : {} {}",
        partial.identity.id,
        partial.identity.name.as_deref().unwrap_or("")
    );
    if params.changes.is_empty() {
        println!("  parameters  : no parameter change");
    } else {
        println!("  parameters  : {} change(s):", params.changes.len());
        for change in &params.changes {
            println!("      {}", change.line());
        }
    }
    println!("  memory      :");
    for (segment, address, len, changed) in region_rows(partial, regions) {
        println!("      {segment} at {address:#08X}: {changed} of {len} octet(s) change");
    }
    println!(
        "  procedure   : {} (no unload, no table write)",
        procedure_summary(partial)
    );
}

/// A one-line summary of the op sequence, e.g. `StartLoading, 1 write,
/// LoadCompleted, restart`.
fn procedure_summary(partial: &FlashPlan) -> String {
    partial
        .steps
        .iter()
        .map(|s| partial.step_label(s))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Emits the parameter-only plan as JSON.
fn print_json(
    target: IndividualAddress,
    partial: &FlashPlan,
    regions: &ParamRegions,
    params: &ParamPlan,
) -> anyhow::Result<()> {
    let value = serde_json::json!({
        "device": target.to_string(),
        "mode": "parameters-only",
        "application": partial.identity.id,
        "parameters": params.changes.iter().map(|c| serde_json::json!({
            "key": c.key,
            "name": c.name,
            "old": c.old.to_string(),
            "new": c.new.to_string(),
            "unit": c.unit,
        })).collect::<Vec<_>>(),
        "regions": region_rows(partial, regions).into_iter().map(|(segment, address, len, changed)| serde_json::json!({
            "segment": segment,
            "address": format!("{address:#08X}"),
            "octets": len,
            "changed_octets": changed,
        })).collect::<Vec<_>>(),
        "procedure": bussard_download::trace(partial),
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

/// `flash --parameters-only --dry-run`: the op sequence the download would
/// send, planned offline (no connection).
///
/// With no device memory to diff against, each parameter write is shown at
/// its full segment length; on the bus only the octets that differ from what
/// the device holds are written.
pub(crate) fn dry_run(
    target: IndividualAddress,
    plan: &FlashPlan,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let regions = bussard_download::planned_parameter_regions(plan);
    let partial = match plan.parameters_only(&regions) {
        Ok(partial) => partial,
        Err(err) => {
            eprintln!("refusing the parameter-only download to {target}: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if json {
        let value = serde_json::json!({
            "device": target.to_string(),
            "mode": "parameters-only",
            "dry_run": true,
            "application": partial.identity.id,
            "procedure": bussard_download::trace(&partial),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Parameter-only download for {target} (offline plan)");
        println!(
            "  application : {} {}",
            partial.identity.id,
            partial.identity.name.as_deref().unwrap_or("")
        );
        println!(
            "  memory      : only the octets that differ from the device's parameter memory \
             are written (read before the first write)"
        );
        println!("  procedure   :");
        for (i, step) in partial.steps.iter().enumerate() {
            println!("      {:>2}. {}", i + 1, partial.step_label(step));
        }
    }
    eprintln!("dry run: no connection opened, nothing written.");
    Ok(ExitCode::SUCCESS)
}

/// Confirms on a terminal unless `--yes`; a non-interactive run without `--yes`
/// is refused.
fn confirm(
    target: IndividualAddress,
    gateway: &str,
    yes: bool,
    octets: usize,
) -> anyhow::Result<bool> {
    crate::confirm::confirm(
        yes,
        &format!("download the parameters ({octets} octet(s)) to {target} via {gateway}?"),
        || {
            format!(
                "refusing to write to {target} without a terminal to confirm on; \
                 pass --yes to download the parameters non-interactively"
            )
        },
    )
}

/// Writes the pre-download parameter memory to
/// `<dir>/captures/backups/parameters/<ia>-<ts>.json`.
pub(crate) fn write_backup(
    dir: &Path,
    target: IndividualAddress,
    plan: &FlashPlan,
    regions: &ParamRegions,
) -> anyhow::Result<std::path::PathBuf> {
    let now = std::time::SystemTime::now();
    let backup = ParameterBackup {
        address: target.to_string(),
        mask: format!("{:04X}", plan.device_mask),
        application: plan.identity.id.clone(),
        unix_timestamp: unix_seconds(now),
        read_time: rfc3339_utc(now),
        regions: regions
            .values()
            .map(|r| ParameterMemory {
                base: r.address,
                length: r.bytes.len(),
                bytes: encode_hex(&r.bytes),
                source: format!("parameter segment {}", r.segment_id),
            })
            .collect(),
    };
    Ok(write_parameter_backup(
        &parameter_backups_dir(dir),
        &backup,
    )?)
}

/// The System 7 segments the running application rewrites after the restart
/// (`checksum_ctrl == 0`, the Jung `0x4916` region, issue #89): their
/// read-back proves nothing, so the verify skips them.
pub(crate) fn runtime_segments(plan: &FlashPlan) -> std::collections::BTreeSet<String> {
    plan.steps
        .iter()
        .filter_map(|step| match step {
            FlashStep::Sys7AbsSegment {
                checksum_ctrl: 0,
                image: Some(image),
                ..
            } => Some(image.segment_id.clone()),
            _ => None,
        })
        .collect()
}

/// Compares the read-back against every octet the download meant to change,
/// except in the segments the application rewrites at run time (`skip`).
/// Returns how many octets were checked.
pub(crate) fn verify_readback(
    partial: &FlashPlan,
    after: &ParamRegions,
    skip: &std::collections::BTreeSet<String>,
) -> Result<usize, String> {
    let mut checked = 0usize;
    for (segment, _, _, _) in region_rows(partial, after) {
        if skip.contains(&segment) {
            continue;
        }
        let (Some(current), Some(desired)) =
            (partial.baseline(&segment), partial.image_bytes(&segment))
        else {
            continue;
        };
        let read = after
            .get(&segment)
            .map(|r| r.bytes.as_slice())
            .ok_or_else(|| format!("segment {segment} could not be read back"))?;
        let mask = partial.segment_mask(&segment);
        for (i, want) in desired.iter().enumerate() {
            let writable = mask.is_none_or(|m| m.get(i) == Some(&0xFF));
            if !writable || current.get(i) == Some(want) {
                continue;
            }
            checked += 1;
            if read.get(i) != Some(want) {
                return Err(format!(
                    "segment {segment} octet {i} reads {:?}, expected {want:#04X}",
                    read.get(i)
                ));
            }
        }
    }
    if after.is_empty() {
        return Err("the parameter memory could not be read back".to_string());
    }
    Ok(checked)
}

/// Prints the recovery guidance after a failed parameter download.
fn recovery_notice(target: IndividualAddress, backup: &Path) {
    eprintln!(
        "\nThe device may be left with partly-written parameters or an application that is not\n\
         Loaded. The parameter memory before the download was saved to:\n    {}\n\
         If the application still reads Loaded, re-running `bussard flash --parameters-only\n\
         {target}` rewrites only the octets that still differ. If it is not Loaded (load state\n\
         Error or Loading), recover with a full `bussard flash --force {target}`, which\n\
         reloads every load-state machine. Do not assume the device works until a read-back\n\
         (`bussard plan {target}`) shows no parameter difference.",
        backup.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_download::{ResidentObject, plan_flash};
    use bussard_mgmt::load::LoadState;
    use bussard_prod::application::parse_application_program;

    /// A System B application with a known identity (manufacturer 1, number 1,
    /// version 1) and one parameter segment.
    fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0001_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-0001_A-0001-01-0000_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
           </Code>
           <ParameterTypes><ParameterType Id="M-0001_A-0001-01-0000_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="M-0001_A-0001-01-0000_P-0" Name="thr" ParameterType="M-0001_A-0001-01-0000_PT-0" Value="7"><Memory CodeSegment="M-0001_A-0001-01-0000_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        Ok(parse_application_program(
            "M-0001_A-0001-01-0000",
            xml.as_bytes(),
        )?)
    }

    fn plan() -> Result<FlashPlan, Box<dyn std::error::Error>> {
        Ok(plan_flash(
            &app()?,
            "1.1.4",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?)
    }

    fn state(load: LoadState, app_id: Option<Vec<u8>>) -> ResidentState {
        ResidentState {
            objects: vec![ResidentObject {
                index: 3,
                object_type: Some(3),
                state: load,
            }],
            app_id,
            ..ResidentState::default()
        }
    }

    #[test]
    fn test_identity_gate_same_application_passes() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, Some(vec![0x00, 0x01, 0x00, 0x01, 0x01]));
        assert_eq!(identity_gate(&plan()?, Some(&st)), Ok(()));
        Ok(())
    }

    #[test]
    fn test_identity_gate_other_application_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, Some(vec![0x00, 0x02, 0x00, 0x09, 0x01]));
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("runs application M-0002 A-0009 v1"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unloaded_device_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Unloaded, None);
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("not Loaded"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unidentified_system_b_application_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, None);
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("cannot be read"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unreadable_state_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = ResidentState {
            unreadable: Some("no answer".into()),
            ..ResidentState::default()
        };
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("no answer"), "{err}");
        assert!(identity_gate(&plan()?, None).is_err());
        Ok(())
    }

    /// A System 7 application (mask 0705) whose procedure loads LSMs 1 and 3.
    fn sys7_plan() -> Result<FlashPlan, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0083_A-000E-23-0000" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="S7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-000E-23-0000_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
            <AbsoluteSegment Id="M-0083_A-000E-23-0000_AS-4" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0083_A-000E-23-0000", xml.as_bytes())?;
        Ok(plan_flash(
            &app,
            "1.1.32",
            0x0705,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?)
    }

    fn lsm(index: u8, state: LoadState) -> ResidentObject {
        ResidentObject {
            index,
            object_type: None,
            state,
        }
    }

    #[test]
    fn test_identity_gate_system7_ignores_lsms_the_procedure_never_loads()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = sys7_plan()?;
        assert!(plan.is_sys7());
        // LSM 2 and 5 are not the application's: their state does not matter.
        let st = ResidentState {
            objects: vec![
                lsm(1, LoadState::Loaded),
                lsm(2, LoadState::Unloaded),
                lsm(3, LoadState::Loaded),
                lsm(5, LoadState::Unloaded),
            ],
            ..ResidentState::default()
        };
        assert_eq!(identity_gate(&plan, Some(&st)), Ok(()));
        // An application LSM that is not Loaded still refuses.
        let st = ResidentState {
            objects: vec![lsm(1, LoadState::Loaded), lsm(3, LoadState::Unloaded)],
            ..ResidentState::default()
        };
        let err = identity_gate(&plan, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("not fully Loaded"), "{err}");
        Ok(())
    }

    #[test]
    fn test_describe_group_object_change_names_objects() {
        let change = bussard_download::GroupObjectChange {
            shown: vec![7],
            hidden: vec![3, 4],
            table_differs: true,
        };
        assert_eq!(
            describe_group_object_change(&change),
            "shows object(s) 7, hides object(s) 3, 4"
        );
    }
}
