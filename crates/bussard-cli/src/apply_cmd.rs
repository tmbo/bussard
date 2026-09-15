//! The `bussard apply` subcommand — write the model's link tables to a device.
//!
//! The flow, in order:
//! 1. Load the model, compute the desired tables, read the device's live tables.
//! 2. Refuse a non-System-B (non-07B0) mask — the same gate as `reconstruct`.
//! 3. Show the plan (reconstruct-style diff). If nothing changes, print
//!    "nothing to do" and exit 0 **without touching any load state**.
//! 4. Confirm on a TTY (`y/N`) unless `--yes`.
//! 5. **Back up** the pre-state tables to `<dir>/captures/backups/<ia>-<ts>.json`.
//! 6. Execute the load sequence (see [`bussard_download::apply`]) and verify by
//!    reading the tables back byte-for-byte.
//! 7. On any failure, print the backup path and recovery guidance loudly and
//!    exit non-zero.
//!
//! # Safety
//!
//! This is the only command that writes device tables. Per the phase-2 spec the
//! first real table writes must happen on a sacrificial device; running `apply`
//! against the live reference bus is out of scope until that device exists. The
//! command still gates on the 07B0 mask and always writes a backup first.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, ops};
use bussard_download::{
    DesiredTables, PlanReport, VerifyOutcome, apply_tables, discover_table_objects, plan,
};
use bussard_mgmt::tables::{DeviceTables, TablesError, read_tables};
use bussard_mgmt::{Layer4Connection, LeaseChannel, system_type};
use bussard_model::IndividualAddress;

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};
use crate::plan_cmd;

/// Applies the model's link tables to a device (plan, confirm, write, verify).
pub fn run(
    address: &str,
    dir: &Path,
    yes: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    let Some(model) = load_model_optional(dir) else {
        bail!(
            "`bussard apply` needs the model (links.yaml) to compute the desired tables; \
             none was loaded from {}",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    let desired = plan_cmd::compute_desired(&model, target)?;

    // Phase A (read-only): read the live tables and build the plan.
    let runtime = tokio::runtime::Runtime::new()?;
    let read = {
        let config = config.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            let source = ops::group_source(&handle);
            let lease = handle.lease().await.context("leasing the bus")?;
            let channel = LeaseChannel::new(lease);
            let result = match Layer4Connection::connect(channel, target, source).await {
                Ok(mut l4) => {
                    let r = read_tables(&mut l4).await;
                    let _ = l4.disconnect().await;
                    r
                }
                Err(err) => Err(TablesError::Mgmt(err)),
            };
            let _ = handle.close().await;
            anyhow::Ok(result)
        })?
    };

    let live = match read {
        Ok(live) => live,
        Err(TablesError::UnsupportedMask { address, mask }) => {
            eprintln!(
                "{address} reports mask {mask:04X} ({}) — `bussard apply` supports \
                 System B (mask 07B0) only for now",
                system_type(mask)
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(err) => return Err(anyhow::Error::new(err).context("reading device tables")),
    };

    // The 07B0 gate is enforced by read_tables (UnsupportedMask above), but assert
    // it here too as a belt-and-braces guard before any write.
    if live.mask != 0x07B0 {
        eprintln!(
            "{target} reports mask {:04X} ({}) — refusing to write a non-System-B device",
            live.mask,
            system_type(live.mask)
        );
        return Ok(ExitCode::FAILURE);
    }

    let report = plan(&live, &desired);
    plan_cmd::print_text(target, &live, &report);

    // Zero-change: print nothing-to-do and exit 0 WITHOUT touching load states.
    if report.is_noop() {
        return Ok(ExitCode::SUCCESS);
    }

    // Confirm unless --yes.
    if !confirm(target, yes, &report)? {
        eprintln!("aborted — no changes written.");
        return Ok(ExitCode::FAILURE);
    }

    // Back up the pre-state tables before writing anything.
    let backup_path = write_backup(dir, target, &live)
        .context("writing the pre-apply backup (refusing to write without a backup)")?;
    println!("backup written to {}", backup_path.display());

    // Phase B (write): execute the load sequence and verify.
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let result = execute(channel, target, source, &desired).await;
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(verify) if verify.ok() => {
            println!(
                "\napply verified: address table {} ({} entries), association table {} ({} entries)",
                verify.address_state,
                report.resulting_address_count,
                verify.association_state,
                report.resulting_association_count,
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(verify) => {
            eprintln!("\nERROR: apply did not verify: {verify:?}");
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

/// Runs the on-bus write sequence: discover the table objects, then apply.
async fn execute(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
) -> Result<VerifyOutcome, bussard_mgmt::load::WriteError> {
    let mut l4 = Layer4Connection::connect(channel, target, source)
        .await
        .map_err(bussard_mgmt::load::WriteError::Mgmt)?;
    let objects = discover_table_objects(&mut l4).await?;
    let result = apply_tables(&mut l4, objects, desired).await;
    let _ = l4.disconnect().await;
    result
}

/// Confirms on a TTY (y/N). Non-interactive without `--yes` is refused.
fn confirm(target: IndividualAddress, yes: bool, report: &PlanReport) -> anyhow::Result<bool> {
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
        "apply {} change(s) to {target}? [y/N] ",
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
) -> anyhow::Result<std::path::PathBuf> {
    let backups = dir.join("captures").join("backups");
    std::fs::create_dir_all(&backups)
        .with_context(|| format!("creating backup directory {}", backups.display()))?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = backups.join(format!("{target}-{ts}.json"));

    let json = serde_json::json!({
        "address": target.to_string(),
        "mask": format!("{:04X}", live.mask),
        "unix_timestamp": ts,
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
