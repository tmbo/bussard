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

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_download::backup::{backups_root, has_installation_backup};
use bussard_download::{
    DesiredTables, PlanReport, Sys7LiveTables, Sys7TableImages, VerifyOutcome, plan,
    sys7_table_images, write_tables_secured,
};
use bussard_mgmt::tables::DeviceTables;
use bussard_mgmt::{LeaseChannel, MaskProfile, system_type};
use bussard_model::IndividualAddress;
use bussard_service::{Authorize, L4Options, SourcePolicy};

use bussard_transport::ConnectionConfig;

use crate::conn_cmd::{
    BusSession, ConnOverrides, enforce_write_gate, gateway_display, load_model_required,
    resolve_config,
};
use crate::plan_cmd;

/// Where the tables a write phase is about to load came from.
///
/// `apply` and `restore` are the same command with a different source of truth,
/// so they share [`apply_desired`] and differ only in this: the verb they print,
/// and whether the desired tables were computed from `links.yaml` or read out of
/// a backup file (issue #96).
#[derive(Debug, Clone)]
pub(crate) enum DesiredSource {
    /// The model's `links.yaml`, computed by `bussard plan`.
    Model,
    /// A device backup file written by `bussard backup` or a previous `apply`.
    Backup(std::path::PathBuf),
}

impl DesiredSource {
    /// The command verb, for the plan header, the confirmation and the errors.
    pub(crate) fn verb(&self) -> &'static str {
        match self {
            DesiredSource::Model => "apply",
            DesiredSource::Backup(_) => "restore",
        }
    }

    /// A one-line description of where the desired tables came from.
    fn origin(&self) -> String {
        match self {
            DesiredSource::Model => "the model's links.yaml".to_string(),
            DesiredSource::Backup(path) => format!("the backup {}", path.display()),
        }
    }
}

/// Applies the model's link tables to a device (plan, confirm, write, verify).
pub fn run(
    address: &str,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    secure_sender: Option<IndividualAddress>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

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
    // An edit made outside bussard (an editor, an assistant writing YAML) is
    // recorded before this command acts on it, so it is never lost.
    crate::history_cmd::capture_external_edit(dir);
    let desired = plan_cmd::compute_desired(&model, target)?;
    hint_installation_backup(dir);
    apply_desired(
        target,
        &desired,
        dir,
        config,
        yes,
        allow_remote_gateway,
        tool_key_source,
        secure_sender,
        &DesiredSource::Model,
        &overrides,
        Some(&model),
    )
}

/// Prints the one-line nudge when the model has no installation-wide backup.
///
/// `apply`'s own pre-write backup covers the device it is about to touch. It
/// does not cover the installation, and the moment to take that snapshot is
/// before the first write, not after (issue #96).
fn hint_installation_backup(dir: &Path) {
    if !has_installation_backup(dir) {
        eprintln!(
            "No installation-wide backup yet. Run `bussard backup` first. \
             (Snapshots land in {}.)",
            backups_root(dir).display()
        );
    }
}

/// The shared plan, confirm, back up, write and verify path behind both
/// `bussard apply` and `bussard restore`.
///
/// `desired` is whatever the caller decided the device's tables should be. The
/// device is read, diffed, shown, confirmed, backed up and written exactly the
/// same way whichever it is.
#[allow(clippy::too_many_arguments)] // one command's context; a struct would only move it
pub(crate) fn apply_desired(
    target: IndividualAddress,
    desired: &DesiredTables,
    dir: &Path,
    config: ConnectionConfig,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    secure_sender: Option<IndividualAddress>,
    origin: &DesiredSource,
    overrides: &ConnOverrides,
    model: Option<&bussard_model::Model>,
) -> anyhow::Result<ExitCode> {
    // KNX Data Secure (issue #71, spec §6.2): every management APDU below —
    // the read pre-pass and the table writes — rides A_SecureData when the device
    // is security-activated and a tool key is given. One high-water mark for the
    // whole command keeps the send sequence monotonic across both connections
    // (spec §5.9).
    let activated = crate::secure_key::model_activated(model, target);
    let material = crate::secure_key::resolve_material(target, tool_key_source, activated)?;
    let tool_key = material.tool_key.clone();
    let secure_seq = bussard_secure::SequenceHighWater::new();
    let desired = desired.clone();
    // A secured System B write also reprograms the security object (issue
    // #156): its group key table indexes the address table being written.
    let security = tool_key.as_ref().map(|_| {
        let empty = std::collections::HashMap::new();
        let keys = material.group_keys.as_ref().unwrap_or(&empty);
        let mut inputs = bussard_download::security_inputs_for(model, target, &desired, keys);
        // The security individual address table (issue #181): the secured
        // senders this device receives from, plus `--secure-sender`.
        inputs.senders = bussard_download::secured_senders(
            model,
            target,
            keys,
            &material.device_sequences,
            secure_sender.as_slice(),
        );
        inputs
    });

    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    // ONE tunnel for the whole command: the read-only pre-pass below, the
    // interactive confirmation, the backup, and the write phase all run over it,
    // and `BusSession` closes it on every exit path. Opening a second tunnel for
    // the write phase used to cost another CONNECT/DISCONNECT round trip — and
    // the gateway's only tunnel slot — for no gain; the tunnel heartbeat holds
    // the slot across the confirmation prompt.
    let runtime = tokio::runtime::Runtime::new()?;
    let bus = BusSession::open(
        &runtime,
        config,
        bussard_service::WritePolicy::transmit(allow_remote_gateway),
    )?;
    // The tunnel-assigned source address, resolved and checked against the bus
    // once for both phases (they share this tunnel, so one probe covers both).
    // `BusSession` closes the tunnel if the check refuses.
    let source = runtime.block_on(bus.service().checked_source(overrides.skip_address_check))?;

    // Phase A (read-only): read the live tables and build the plan.
    let service = bus.service();
    let read_options = L4Options {
        source: SourcePolicy::Known(source),
        tool_key: tool_key.clone(),
        high_water: secure_seq.clone(),
        // Authorize (free access) before reading, as ETS does (issue #52
        // finding #1) and as System 7 requires before any memory access.
        // Best-effort on this read-only pre-pass.
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    };
    let read = runtime.block_on(async {
        service
            .with_l4(target, &read_options, async |l4| {
                plan_cmd::read_live_tables(l4).await
            })
            .await
    });

    let live = match read? {
        plan_cmd::LiveRead::Tables(live) => live,
        plan_cmd::LiveRead::UnsupportedMask { address, mask } => {
            plan_cmd::report_unsupported_mask(origin.verb(), address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let sys7_live = live.sys7().cloned();
    let live = live.tables();

    // The family gate is enforced by the readers (UnsupportedMask above), but
    // assert it here too as a belt-and-braces guard before any write. Routed
    // through the central MaskProfile seam.
    let profile = MaskProfile::from_mask(live.mask);
    if !profile.capabilities().plan_apply {
        eprintln!(
            "{target} reports mask {:04X} ({}) — refusing to write a device outside the \
             System B / System 7 families",
            live.mask,
            system_type(live.mask)
        );
        return Ok(ExitCode::FAILURE);
    }

    let report = plan(live, &desired);
    if matches!(origin, DesiredSource::Backup(_)) {
        println!("restoring {} to {target}", origin.origin());
    }
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

    // Data Secure: say what the security object will receive (never a key).
    let security = if sys7.is_none() { security } else { None };
    if let Some(inputs) = &security {
        let keyed: Vec<String> = desired
            .addresses
            .iter()
            .filter(|ga| inputs.group_keys.contains_key(ga))
            .map(ToString::to_string)
            .collect();
        let objects: Vec<String> = inputs
            .secure_objects
            .iter()
            .map(ToString::to_string)
            .collect();
        let senders: Vec<String> = inputs
            .senders
            .iter()
            .map(|e| format!("{} seq {}", e.address, e.sequence))
            .collect();
        println!(
            "Data Secure: the security object is reprogrammed too (unload, security individual \
             address table: {}, group key table: {}, group-object flags: {}, complete)",
            if senders.is_empty() {
                "no secured senders".to_string()
            } else {
                format!("{} secured sender(s) {}", senders.len(), senders.join(", "))
            },
            if keyed.is_empty() {
                "no keys".to_string()
            } else {
                keyed.join(", ")
            },
            if objects.is_empty() {
                "none secured".to_string()
            } else {
                format!("secured {}", objects.join(", "))
            },
        );
    }

    // Confirm unless --yes.
    if !confirm(target, &gateway, yes, &report, origin)? {
        eprintln!("aborted — no changes written.");
        return Ok(ExitCode::FAILURE);
    }

    // Snapshot the model before the bus write, so `bussard history` records what
    // the installation was asked to become and `bussard undo` can go back.
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new(origin.verb())
            .with_args([target.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before writing the device tables"),
    );

    // Back up the pre-state tables before writing anything. A restore takes one
    // too: the state it is about to overwrite is still the only copy of whatever
    // is on the device right now.
    let backup_path = write_backup(dir, target, live, sys7_live.as_ref()).with_context(|| {
        format!(
            "writing the pre-{} backup (refusing to write without a backup)",
            origin.verb()
        )
    })?;
    println!("backup written to {}", backup_path.display());

    if let Some((_, images)) = &sys7
        && let Some((from, to)) = images.group_object_moved
    {
        println!(
            "the group-object descriptor table moves {from:#06X} → {to:#06X} with the \
                 address table; its {} octets are rewritten verbatim",
            images.address_region.len() - images.address_table_len
        );
    }

    // Phase B (write): execute the load sequence and verify.
    let mask = live.mask;
    // The same tunnel phase A used: its L4 session and bus lease are both
    // released by now, so the write phase simply takes the lease again.
    // Progress (issue #147): the table write emits no finer events, so the live
    // view is a spinner with elapsed time and the last bus event; plain runs
    // print nothing extra.
    let display = crate::progress::TaskDisplay::new(
        format!("{} {target}: writing the tables", origin.verb()),
        false,
    );
    let outcome = runtime.block_on(async {
        let channel = service.lease_channel().await?;
        let secure = crate::secure_key::layer(&tool_key, &secure_seq);
        let images = sys7.as_ref().map(|(_, images)| images);
        anyhow::Ok(
            write_tables_secured(
                channel,
                target,
                source,
                mask,
                &desired,
                images,
                secure,
                security.as_ref(),
            )
            .await,
        )
    });
    display.finish(matches!(&outcome, Ok(Ok(summary)) if summary.ok));
    let outcome = outcome?;

    match outcome {
        Ok(summary) if summary.ok => {
            println!(
                "\n{} verified: address table {} ({} entries), association table {} ({} entries)",
                origin.verb(),
                summary.address_state,
                report.resulting_address_count,
                summary.association_state,
                report.resulting_association_count,
            );
            if let Some(hint) = crate::export_cmd::stale_export_hint(dir) {
                eprintln!("{hint}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Ok(summary) => {
            eprintln!(
                "\nERROR: {} did not verify: {}",
                origin.verb(),
                summary.detail
            );
            recovery_notice(&backup_path, target);
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("\nERROR: {} failed: {err}", origin.verb());
            recovery_notice(&backup_path, target);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Runs the on-bus write sequence for a **System 7** device: authorize, then
/// drive the two table load-state machines (see [`bussard_download::apply_sys7`]).
///
/// The LSM realisation (property-based on `0705`, memory-mapped on `0701`) comes
/// from the mask-family default profile, exactly as the flash path selects it.
#[allow(clippy::too_many_arguments)] // one connection's worth of context; splitting it hides nothing
pub(crate) async fn execute_sys7(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    images: &Sys7TableImages,
    tool_key: &Option<bussard_secure::Key16>,
    secure_seq: &bussard_secure::SequenceHighWater,
) -> Result<bussard_download::Sys7VerifyOutcome, bussard_download::Sys7ApplyError> {
    let secure = crate::secure_key::layer(tool_key, secure_seq);
    bussard_download::write_sys7(channel, target, source, mask, images, secure).await
}

/// Runs the on-bus write sequence: discover the table objects, then apply.
pub(crate) async fn execute(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
    tool_key: &Option<bussard_secure::Key16>,
    secure_seq: &bussard_secure::SequenceHighWater,
    security: Option<&bussard_download::SecurityInputs>,
) -> Result<VerifyOutcome, bussard_mgmt::load::WriteError> {
    let secure = crate::secure_key::layer(tool_key, secure_seq);
    bussard_download::write_system_b_secured(channel, target, source, desired, secure, security)
        .await
}

/// Confirms on a TTY (y/N), naming the resolved gateway (issue #74).
/// Non-interactive without `--yes` is refused.
fn confirm(
    target: IndividualAddress,
    gateway: &str,
    yes: bool,
    report: &PlanReport,
    origin: &DesiredSource,
) -> anyhow::Result<bool> {
    let changes = report.additions.len() + report.removals.len();
    crate::confirm::confirm(
        yes,
        &format!(
            "{} {changes} change(s) to {target} via {gateway}?",
            origin.verb()
        ),
        || {
            format!(
                "refusing to write to {target} without a terminal to confirm on; \
                 pass --yes to {} non-interactively",
                origin.verb()
            )
        },
    )
}

/// Serialises the live pre-state tables to a JSON backup under
/// `<dir>/captures/backups/<ia>-<timestamp>.json`.
///
/// The format itself lives in [`bussard_download::backup`], so `apply`,
/// `bussard backup` and `bussard restore` all read and write one shape
/// (issue #96).
pub(crate) fn write_backup(
    dir: &Path,
    target: IndividualAddress,
    live: &DeviceTables,
    sys7: Option<&Sys7LiveTables>,
) -> anyhow::Result<std::path::PathBuf> {
    Ok(bussard_download::write_pre_write_backup(
        dir, target, live, sys7,
    )?)
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
