//! The `bussard backup` subcommand — snapshot every device in the installation
//! (issue #96).
//!
//! `apply` backs up the one device it is about to write. `flash` backs up
//! nothing. This command backs up everything, before anything has been touched:
//! for every device in the model it reads the group-address and association
//! tables and, where bussard can bound the read from the device itself, the
//! writable parameter memory, and writes one JSON file per device plus a
//! `manifest.json` describing the run.
//!
//! # Read-only, and provably so
//!
//! `backup` sends `A_DeviceDescriptor_Read`, `A_Authorize_Request`,
//! `A_PropertyValue_Read` and `A_Memory_Read` — nothing else. It never writes a
//! property, a load control or a byte of memory, so it is safe to run against a
//! live installation, and the mock-gateway test fails the run if a single write
//! APDU reaches the device.
//!
//! # Which devices, and what "skipped" means
//!
//! The targets come from the model: every device, every device on `--line`, or
//! the individual addresses named on the command line. A device whose mask is
//! outside the System B / System 7 families cannot have its tables read, and is
//! recorded in the manifest as `skipped` with the reason. It is never silently
//! dropped: an owner reading the manifest must be able to see exactly which
//! devices are not covered. A device nothing answers for is `unreachable`: listed,
//! but not a failure, because a switched-off device cannot be backed up. A device
//! that answered and whose read then broke is `failed`, and makes the command
//! exit non-zero.
//!
//! # Connection shape
//!
//! One bus connection for the whole run, leased per device exactly as
//! `bussard scan` and `reconstruct --line` do, so the run is serialised against
//! the rest of the bus rather than opening a connection per device in parallel.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{Context, bail};
use bussard_download::backup::BackupManifest;
use bussard_model::IndividualAddress;
use bussard_service::WritePolicy;
use bussard_service::backup::{
    BackupInputs, BackupProgress, capture_devices, default_out_dir, select_targets,
    write_backup_run,
};

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, gateway_display, load_model_required, open_service,
    resolve_config,
};

/// Runs `bussard backup`.
///
/// The reads are [`bussard_service::backup::capture_devices`] and the files
/// [`bussard_service::backup::write_backup_run`], the functions
/// `knx_backup_device` calls (issue #717); this prints the progress and the
/// summary.
#[allow(clippy::too_many_arguments)] // one command's worth of flags; a struct would only move them
pub fn run(
    addresses: &[String],
    line: Option<&str>,
    out: Option<&Path>,
    dir: &Path,
    json: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(dir, "`bussard backup` reads the devices the model lists")
        );
    };
    let targets = select_targets(&model, addresses, line)?;
    if targets.is_empty() {
        bail!(
            "no devices to back up: the model in {} has no matching device files",
            dir.display()
        );
    }
    let config = resolve_config(Some(&model), &overrides)?;
    let gateway = gateway_display(&config);

    let started = SystemTime::now();
    let out_dir: PathBuf = match out {
        Some(p) => p.to_path_buf(),
        None => default_out_dir(dir, started),
    };

    eprintln!(
        "backing up {} device(s) via {gateway} into {}",
        targets.len(),
        out_dir.display()
    );

    // The device facts (issue #209) and the identity verdict (issue #228,
    // item 5) of every device read.
    let facts = crate::device_facts::cache(dir, true, overrides.refresh_facts);
    // The tool key of a target the model records as security-activated: a
    // keyring without its entry is an error for it, while any other device
    // the keyring does not list is read in the clear (issue #189).
    let tool_key = |target: IndividualAddress, activated: bool| {
        crate::secure_key::resolve(target, tool_key_source, activated)
    };
    // Whether a device's application, from the product data the lock pins,
    // leaves `SupportsExtendedMemoryServices` unset (issue #472).
    let user_memory = |target: IndividualAddress| {
        let app = model
            .devices
            .get(&target)
            .and_then(|d| d.device.product.as_ref())
            .and_then(|p| p.application_ref.as_deref())
            .and_then(|app| crate::product_store::pinned_application(dir, app));
        bussard_download::uses_user_memory(app.as_ref())
    };
    let mut progress = |event: BackupProgress<'_>| match event {
        BackupProgress::Reading {
            index,
            total,
            target,
        } => eprintln!("[{index}/{total}] reading {target}…"),
        BackupProgress::Captured(capture) => {
            if let (Some(check), Ok(target)) = (
                &capture.entry.identity,
                capture.entry.address.parse::<IndividualAddress>(),
            ) {
                eprintln!("  {}", crate::device_facts::identity_line(target, check));
            }
        }
    };
    let runtime = tokio::runtime::Runtime::new()?;
    let captured = runtime.block_on(async {
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = checked_source_or_close(&service, &overrides).await?;
        let inputs = BackupInputs {
            model: &model,
            source,
            facts: &facts,
            probe_timeouts: crate::scan_cmd::discovery_timeouts(),
            tool_key: &tool_key,
            user_memory_above_64k: &user_memory,
        };
        let captured = tokio::select! {
            captured = capture_devices(&service, inputs, &targets, &mut progress) => captured,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Vec::new()
            }
        };
        service.close().await;
        anyhow::Ok(captured)
    })?;

    let (manifest, manifest_path) = write_backup_run(&out_dir, gateway, started, &captured)
        .context("writing the backup (the run is not usable without it)")?;

    if json {
        crate::output::print(crate::output::schema::BACKUP, &manifest)?;
    } else {
        print_text(&manifest, &out_dir, &manifest_path);
    }

    if manifest.any_failed() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Prints the per-device table and the run summary.
fn print_text(manifest: &BackupManifest, out_dir: &Path, manifest_path: &Path) {
    println!();
    for entry in &manifest.devices {
        let mask = entry.mask.as_deref().unwrap_or("----");
        println!("  {:<10} {mask}  {}", entry.address, entry.status);
        if let Some(detail) = &entry.detail {
            println!("      {detail}");
        }
        if let Some(p) = &entry.parameters {
            match (p.captured, p.length, &p.reason) {
                (true, Some(len), _) => println!("      parameters: {len} octet(s)"),
                (false, _, Some(reason)) => println!("      parameters: not captured: {reason}"),
                _ => {}
            }
        }
    }
    let totals = manifest.totals();
    println!(
        "\n{} backed up, {} skipped, {} unreachable, {} failed",
        totals.get("backed_up").copied().unwrap_or(0),
        totals.get("skipped").copied().unwrap_or(0),
        totals.get("unreachable").copied().unwrap_or(0),
        totals.get("failed").copied().unwrap_or(0),
    );
    println!("backup directory: {}", out_dir.display());
    println!("manifest: {}", manifest_path.display());
    println!(
        "\nrestore one device with `bussard restore {} <ia>`",
        out_dir.display()
    );
}
