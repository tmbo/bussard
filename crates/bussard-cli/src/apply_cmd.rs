//! The `bussard apply` subcommand — write the model's link tables to a device.
//!
//! The flow, in order:
//! 1. Load the model, compute the desired tables, read the device's live tables.
//! 2. Refuse a mask outside the two supported families — the same gate as
//!    `reconstruct`.
//! 3. Show the plan (reconstruct-style diff). If nothing changes, print
//!    "nothing to do" and exit 0 **without touching any load state**.
//! 4. Confirm on a TTY (`y/N`) unless `--yes`.
//! 5. **Back up** the pre-state tables to `<dir>/captures/backups/<ia>-<ts>.json`.
//! 6. Execute the load sequence (see [`bussard_download::apply`]) and verify by
//!    reading the tables back byte-for-byte.
//! 7. On any failure, print the backup path and recovery guidance loudly and
//!    exit non-zero.
//!
//! # Two device families
//!
//! **System B** (mask `x7B0`) writes its tables into two loadable interface
//! objects ([`bussard_download::apply`]). **System 7** (mask `0705` / `0701`) has
//! no such objects: its tables are absolute memory regions driven by two of the
//! three parallel load-state machines, so the write runs
//! [`bussard_download::apply_sys7`] instead — `Unload` / `StartLoading` the two
//! table LSMs, allocate each region, stream it in 12-octet chunks with a
//! read-back verify, `TaskSegment`, `LoadCompleted` (issue #91). The parameter
//! LSM and the application image are never touched, which is the whole point:
//! a link change must not reset the device's parameters.
//!
//! Neither family restarts the device — a table object activates its content on
//! `LoadCompleted`. See the ordering and restart rationale in
//! [`bussard_download::apply_sys7`].
//!
//! # Safety
//!
//! This is the only command that writes device tables. Per the phase-2 spec the
//! first real table writes must happen on a sacrificial device; running `apply`
//! against the live reference bus is out of scope until that device exists. The
//! command still gates on the mask family and always writes a backup first.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, ops};
use bussard_download::{
    DesiredTables, PlanReport, Sys7LiveTables, Sys7TableImages, VerifyOutcome, apply_sys7_tables,
    apply_tables, discover_table_objects, plan, sys7_table_images,
};
use bussard_mgmt::tables::DeviceTables;
use bussard_mgmt::{Layer4Connection, LeaseChannel, MaskProfile, system_type};
use bussard_model::IndividualAddress;

use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, resolve_config,
};
use crate::plan_cmd;

/// Applies the model's link tables to a device (plan, confirm, write, verify).
pub fn run(
    address: &str,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // KNX Data Secure (issue #71, spec §6.2): every management APDU below —
    // the read pre-pass and the table writes — rides A_SecureData when the device
    // is security-activated and a tool key is given. One high-water mark for the
    // whole command keeps the send sequence monotonic across both connections
    // (spec §5.9).
    let tool_key = crate::secure_key::resolve(target, tool_key_source)?;
    let secure_seq = bussard_secure::SequenceHighWater::new();

    // A parse error is a hard failure here (surfaced with the file detail); an
    // absent model still bails, since `apply` needs links.yaml.
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard apply` needs the model (links.yaml) to compute the desired tables; \
             none was loaded from {}",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    let desired = plan_cmd::compute_desired(&model, target)?;

    // Phase A (read-only): read the live tables and build the plan.
    let runtime = tokio::runtime::Runtime::new()?;
    let read = {
        let config = config.clone();
        let read_key = tool_key.clone();
        let read_seq = secure_seq.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
            let source = ops::group_source(&handle);
            let lease = handle.lease().await.context("leasing the bus")?;
            let channel = LeaseChannel::new(lease);
            let secure = crate::secure_key::layer(&read_key, &read_seq);
            let result = match Layer4Connection::connect_with_secure(
                channel,
                target,
                source,
                bussard_mgmt::Timeouts::default(),
                secure,
            )
            .await
            {
                Ok(mut l4) => {
                    // Authorize (free access) before reading, as ETS does (issue
                    // #52 finding #1) and as System 7 requires before any memory
                    // access. Best-effort on this read-only pre-pass.
                    if let Err(err) =
                        l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY).await
                    {
                        tracing::debug!("{target} authorize (free access) did not grant: {err}");
                    }
                    let r = plan_cmd::read_live_tables(&mut l4).await;
                    let _ = l4.disconnect().await;
                    r
                }
                Err(err) => Err(anyhow::Error::new(
                    bussard_mgmt::tables::TablesError::Mgmt(err),
                )
                .context("connecting to the device")),
            };
            let _ = handle.close().await;
            anyhow::Ok(result)
        })?
    };

    let live = match read? {
        plan_cmd::LiveRead::Tables(live) => live,
        plan_cmd::LiveRead::UnsupportedMask { address, mask } => {
            plan_cmd::report_unsupported_mask("apply", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let sys7_live = live.sys7().cloned();
    let live = live.tables();

    // The family gate is enforced by the readers (UnsupportedMask above), but
    // assert it here too as a belt-and-braces guard before any write. Routed
    // through the central MaskProfile seam.
    let profile = MaskProfile::from_mask(live.mask);
    if !(profile.is_system_b() || profile.is_system_7()) {
        eprintln!(
            "{target} reports mask {:04X} ({}) — refusing to write a device outside the \
             System B / System 7 families",
            live.mask,
            system_type(live.mask)
        );
        return Ok(ExitCode::FAILURE);
    }

    let report = plan(live, &desired);
    plan_cmd::print_text(target, live, &report);

    // Compute the System 7 region images up front: an image that would not fit
    // its memory region must refuse here, before anything is confirmed, backed up
    // or written.
    let sys7 = match &sys7_live {
        Some(s7) => Some((
            s7.clone(),
            sys7_table_images(s7, &desired, target.raw())
                .context("computing the System 7 table images")?,
        )),
        None => None,
    };

    // Zero-change: print nothing-to-do and exit 0 WITHOUT touching load states.
    if report.is_noop() {
        return Ok(ExitCode::SUCCESS);
    }

    // Confirm unless --yes.
    if !confirm(target, &gateway, yes, &report)? {
        eprintln!("aborted — no changes written.");
        return Ok(ExitCode::FAILURE);
    }

    // Back up the pre-state tables before writing anything.
    let backup_path = write_backup(dir, target, live, sys7_live.as_ref())
        .context("writing the pre-apply backup (refusing to write without a backup)")?;
    println!("backup written to {}", backup_path.display());

    if let Some((_, images)) = &sys7 {
        if let Some((from, to)) = images.group_object_moved {
            println!(
                "the group-object descriptor table moves {from:#06X} → {to:#06X} with the \
                 address table; its {} octets are rewritten verbatim",
                images.address_region.len() - images.address_table_len
            );
        }
    }

    // Phase B (write): execute the load sequence and verify.
    let mask = live.mask;
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let result = match &sys7 {
            Some((_, images)) => {
                execute_sys7(channel, target, source, mask, images, &tool_key, &secure_seq)
                    .await
                    .map(|v| ApplySummary {
                        ok: v.ok(),
                        address_state: v.address_state,
                        association_state: v.association_state,
                        detail: format!("{v:?}"),
                    })
                    .map_err(|e| e.to_string())
            }
            None => execute(channel, target, source, &desired, &tool_key, &secure_seq)
                .await
                .map(|v| ApplySummary {
                    ok: v.ok(),
                    address_state: v.address_state,
                    association_state: v.association_state,
                    detail: format!("{v:?}"),
                })
                .map_err(|e| e.to_string()),
        };
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(summary) if summary.ok => {
            println!(
                "\napply verified: address table {} ({} entries), association table {} ({} entries)",
                summary.address_state,
                report.resulting_address_count,
                summary.association_state,
                report.resulting_association_count,
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(summary) => {
            eprintln!("\nERROR: apply did not verify: {}", summary.detail);
            recovery_notice(&backup_path, target);
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("\nERROR: apply failed: {err}");
            recovery_notice(&backup_path, target);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The family-agnostic result of one write phase, so both paths print the same
/// verified/failed line.
struct ApplySummary {
    /// Whether everything loaded and read back byte-for-byte.
    ok: bool,
    /// The address table's (LSM 1's) final load state.
    address_state: bussard_mgmt::load::LoadState,
    /// The association table's (LSM 2's) final load state.
    association_state: bussard_mgmt::load::LoadState,
    /// The full outcome, printed only when something did not verify.
    detail: String,
}

/// Runs the on-bus write sequence for a **System 7** device: authorize, then
/// drive the two table load-state machines (see [`bussard_download::apply_sys7`]).
///
/// The LSM realisation (property-based on `0705`, memory-mapped on `0701`) comes
/// from the mask-family default profile, exactly as the flash path selects it.
#[allow(clippy::too_many_arguments)] // one connection's worth of context; splitting it hides nothing
async fn execute_sys7(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    images: &Sys7TableImages,
    tool_key: &Option<bussard_secure::Key16>,
    secure_seq: &bussard_secure::SequenceHighWater,
) -> Result<bussard_download::Sys7VerifyOutcome, bussard_download::Sys7ApplyError> {
    let secure = crate::secure_key::layer(tool_key, secure_seq);
    let mut l4 = Layer4Connection::connect_with_secure(
        channel,
        target,
        source,
        bussard_mgmt::Timeouts::default(),
        secure,
    )
    .await
    .map_err(|e| {
        bussard_download::Sys7ApplyError::Write(bussard_mgmt::load::WriteError::Mgmt(e))
    })?;
    // System 7 gates every memory access behind A_Authorize (spec §6); this is
    // the mutating path, so an explicit access-denied fails loudly.
    l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
        .map_err(|e| {
            bussard_download::Sys7ApplyError::Write(bussard_mgmt::load::WriteError::Mgmt(e))
        })?;
    let profile = MaskProfile::from_mask(mask)
        .sys7_default_profile()
        .unwrap_or_else(bussard_mgmt::Sys7Profile::corpus_default);
    let lsm = bussard_mgmt::lsm_access_from_profile(&profile);
    // The TaskSegment marker's middle octets are the product's application number,
    // which a table-only apply does not have (no product is loaded). The device
    // keys the finalize on subtype + address, so a zero application number still
    // drives it to Loaded. `S7-CAL: confirm a 0705/0701 device ignores the
    // TaskSegment marker on a table-only reload.`
    let marker = bussard_mgmt::task_segment_marker(mask, 0, 0);
    let result = apply_sys7_tables(&mut l4, &lsm, &profile, images, marker).await;
    let _ = l4.disconnect().await;
    result
}

/// Runs the on-bus write sequence: discover the table objects, then apply.
async fn execute(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
    tool_key: &Option<bussard_secure::Key16>,
    secure_seq: &bussard_secure::SequenceHighWater,
) -> Result<VerifyOutcome, bussard_mgmt::load::WriteError> {
    let secure = crate::secure_key::layer(tool_key, secure_seq);
    let mut l4 = Layer4Connection::connect_with_secure(
        channel,
        target,
        source,
        bussard_mgmt::Timeouts::default(),
        secure,
    )
    .await
    .map_err(bussard_mgmt::load::WriteError::Mgmt)?;
    // Authorize the write session with the free-access key before any table
    // write, exactly as ETS does (issue #52 finding #1). This is the mutating
    // path, so fail loudly on an explicit access-denied (a keyed device needs its
    // BCU key) rather than proceeding into writes that the device would drop; a
    // device that does not implement authorize is tolerated and continues.
    l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
        .map_err(bussard_mgmt::load::WriteError::Mgmt)?;
    let objects = discover_table_objects(&mut l4).await?;
    let result = apply_tables(&mut l4, objects, desired).await;
    let _ = l4.disconnect().await;
    result
}

/// Confirms on a TTY (y/N), naming the resolved gateway (issue #74).
/// Non-interactive without `--yes` is refused.
fn confirm(
    target: IndividualAddress,
    gateway: &str,
    yes: bool,
    report: &PlanReport,
) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!(
            "refusing to write to {target} without a terminal to confirm on; \
             pass --yes to apply non-interactively"
        );
    }
    eprint!(
        "apply {} change(s) to {target} via {gateway}? [y/N] ",
        report.additions.len() + report.removals.len()
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Serialises the live pre-state tables to a JSON backup under
/// `<dir>/captures/backups/<ia>-<timestamp>.json`.
fn write_backup(
    dir: &Path,
    target: IndividualAddress,
    live: &DeviceTables,
    sys7: Option<&Sys7LiveTables>,
) -> anyhow::Result<std::path::PathBuf> {
    let backups = dir.join("captures").join("backups");
    std::fs::create_dir_all(&backups)
        .with_context(|| format!("creating backup directory {}", backups.display()))?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = backups.join(format!("{target}-{ts}.json"));

    // On System 7 the pre-state is not just the two tables: the group-object
    // descriptors live in the same 0x4000 region and move with the address
    // table, so the backup records them (hex) and where they were.
    let sys7_detail = sys7.map(|s7| {
        serde_json::json!({
            "own_ia": format!("{:04X}", s7.own_ia),
            "group_object_base": format!("{:04X}", s7.group_object_base),
            "group_object_image": s7
                .group_object_image
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
        })
    });
    let json = serde_json::json!({
        "address": target.to_string(),
        "mask": format!("{:04X}", live.mask),
        "unix_timestamp": ts,
        "system7": sys7_detail,
        "addresses": live.addresses.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        "associations": live.associations.iter().map(|&(tsap, asap)| {
            serde_json::json!({ "tsap": tsap, "asap": asap })
        }).collect::<Vec<_>>(),
        "resolved": live.resolved.iter().map(|l| {
            serde_json::json!({ "object": l.object, "ga": l.ga.to_string() })
        }).collect::<Vec<_>>(),
        "notes": live.notes,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json)?)
        .with_context(|| format!("writing backup {}", path.display()))?;
    Ok(path)
}

/// Prints the loud recovery guidance on any apply failure.
fn recovery_notice(backup_path: &Path, target: IndividualAddress) {
    eprintln!(
        "\nThe device may be left with partially-written or unloaded tables.\n\
         The pre-apply state was backed up to:\n    {}\n\
         Recover by re-running `bussard apply {target}` (the tables are rewritten\n\
         wholesale, so a re-apply is safe and idempotent), or by re-downloading the\n\
         device with ETS. Do not assume the device is functional until a re-apply or\n\
         `bussard plan {target}` reports no differences.",
        backup_path.display()
    );
}
