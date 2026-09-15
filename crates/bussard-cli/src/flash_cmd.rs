//! The `bussard flash` subcommand — first application download into a
//! factory-fresh device (phase 3).
//!
//! The flow mirrors `bussard apply`'s ladder, adapted for an application
//! download:
//! 1. Read the vendor `.knxprod`, select the application program (by `--application`
//!    id, or the sole candidate).
//! 2. Read the device descriptor (mask). Gate on System B (07B0); refuse others.
//! 3. Build a pre-flight [`FlashPlan`] — this also refuses a mask mismatch or any
//!    unsupported op — and show it. A refused plan exits non-zero before any write.
//! 4. State that **no backup is possible** for a first flash (the device is
//!    assumed factory-fresh; recovery is re-flashing) and confirm on a TTY unless
//!    `--yes`.
//! 5. Execute with a progress line, then verify: the application object must be
//!    `Loaded`, and a sample of each written segment is read back.
//! 6. On any failure, print recovery guidance and exit non-zero.
//!
//! # Safety
//!
//! This is a device-mutating command. Per the phase-3 spec the first real flash
//! must happen against the thelsing virtual device or KNX Virtual, not the live
//! reference bus; the mask gate and the pre-flight validation are the guard-rails
//! that keep it from touching an unsupported or mismatched device.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, ops};
use bussard_download::{
    FlashPlan, FlashStep, Progress, flash, plan_flash, select_application, trace,
};
use bussard_mgmt::{DeviceConnection, Layer4Connection, LeaseChannel};
use bussard_model::IndividualAddress;

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// Flashes an application program from vendor product data into a device.
pub fn run(
    address: &str,
    product: &Path,
    application: Option<&str>,
    dir: &Path,
    yes: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // Load the product data and pick the application program.
    let product_data = bussard_prod::read_knxprod(product)
        .with_context(|| format!("reading product data from {}", product.display()))?;

    // Resolve candidate applications: an explicit id looks it up directly; else
    // every application in the archive is a candidate (a single-app .knxprod is
    // the common case).
    let candidates: Vec<&bussard_prod::ApplicationProgram> =
        product_data.applications.iter().collect();
    let app = match select_application(&candidates, application) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("cannot select an application program: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };

    // Parameter overrides could come from the model; for now, no overrides
    // (parameter selection is a follow-up). The model is loaded only for the
    // connection config.
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    let overrides_map: BTreeMap<String, String> = BTreeMap::new();

    // Phase A (read-only): read the device descriptor.
    let runtime = tokio::runtime::Runtime::new()?;
    let device_mask = {
        let config = config.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
                eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
            }
            let source = ops::group_source(&handle);
            let lease = handle.lease().await.context("leasing the bus")?;
            let channel = LeaseChannel::new(lease);
            let result = match DeviceConnection::connect(channel, target, source).await {
                Ok(mut dev) => {
                    let r = dev.device_descriptor().await;
                    let _ = dev.disconnect().await;
                    r
                }
                Err(err) => Err(err),
            };
            let _ = handle.close().await;
            anyhow::Ok(result)
        })?
    };

    let device_mask = match device_mask {
        Ok(mask) => mask,
        Err(err) => {
            return Err(anyhow::Error::new(err).context("reading the device descriptor"));
        }
    };

    // Pre-flight: build and validate the plan (System B gate, mask match,
    // unsupported-op refusal all happen here).
    let plan = match plan_flash(app, address, device_mask, &overrides_map) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("cannot flash: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };

    print_plan(target, device_mask, &plan);

    // No backup is possible for a first flash — state it plainly.
    eprintln!(
        "\nNOTE: a first flash assumes the device is factory-fresh; no backup is \n\
         possible (there is no prior application to save). Recovery from a failed \n\
         flash is re-running `bussard flash`."
    );

    // Confirm unless --yes.
    if !confirm(target, yes, &plan)? {
        eprintln!("aborted — nothing written.");
        return Ok(ExitCode::FAILURE);
    }

    // Phase B (write): execute the flash with a progress line.
    let plan_ref = &plan;
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let result = execute(channel, target, source, plan_ref).await;
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(verify) if verify.ok() => {
            println!(
                "\nflash verified: application program {} is {} on {target}",
                plan.identity.id, verify.load_state,
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(verify) => {
            eprintln!("\nERROR: flash did not verify: {verify:?}");
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("\nERROR: flash failed: {err}");
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Runs the on-bus flash sequence with a progress line.
async fn execute(
    channel: LeaseChannel,
    target: IndividualAddress,
    source: IndividualAddress,
    plan: &FlashPlan,
) -> Result<bussard_download::FlashOutcome, bussard_mgmt::load::WriteError> {
    let mut l4 = Layer4Connection::connect(channel, target, source)
        .await
        .map_err(bussard_mgmt::load::WriteError::Mgmt)?;
    let result = flash(&mut l4, plan, |p| match p {
        Progress::Step {
            index,
            total,
            label,
        } => {
            eprintln!("  [{index}/{total}] {label}");
        }
        Progress::Bytes { written, total } => {
            eprint!("\r      {written}/{total} bytes");
            let _ = std::io::stderr().flush();
            if written == total {
                eprintln!();
            }
        }
    })
    .await;
    let _ = l4.disconnect().await;
    result
}

/// Prints the pre-flight plan: application identity, mask compatibility, and the
/// ordered step list with byte counts and time estimate.
fn print_plan(target: IndividualAddress, device_mask: u16, plan: &FlashPlan) {
    println!("Flash plan for {target}");
    println!(
        "  application : {} {}",
        plan.identity.id,
        plan.identity.name.as_deref().unwrap_or(""),
    );
    if let (Some(num), Some(ver)) = (
        plan.identity.application_number,
        plan.identity.application_version,
    ) {
        println!("  app number  : {num} (version {ver})");
    }
    println!(
        "  mask        : app {} vs device {device_mask:04X} — compatible",
        plan.identity.mask_version,
    );
    println!(
        "  writes      : {} byte(s) across {} step(s), ~{} memory frame(s), est. {:.1}s on TP1",
        plan.total_write_bytes(),
        plan.steps.len(),
        plan.estimated_write_frames(),
        plan.estimated_duration().as_secs_f64(),
    );
    println!("  procedure   :");
    for line in trace(plan) {
        println!("    {line}");
    }
}

/// Confirms on a TTY (y/N). Non-interactive without `--yes` is refused.
fn confirm(target: IndividualAddress, yes: bool, plan: &FlashPlan) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!(
            "refusing to flash {target} without a terminal to confirm on; \
             pass --yes to flash non-interactively"
        );
    }
    let writes = plan
        .steps
        .iter()
        .filter(|s| {
            matches!(
                s,
                FlashStep::WriteRelMem { .. } | FlashStep::WriteMem { .. }
            )
        })
        .count();
    eprint!(
        "flash {} ({writes} memory write(s)) to {target}? [y/N] ",
        plan.identity.id
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Prints loud recovery guidance on any flash failure.
fn recovery_notice(target: IndividualAddress) {
    eprintln!(
        "\nThe device may be left with a partially-written or unloaded application.\n\
         Because this was a first flash there is no prior state to restore.\n\
         Recover by re-running `bussard flash {target}` (the download is idempotent —\n\
         it re-unloads and rewrites the application wholesale), or by downloading the\n\
         device with ETS. Do not assume the device is functional until a re-flash\n\
         reports the application is Loaded and verified.",
    );
}
