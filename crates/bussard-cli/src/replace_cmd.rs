//! The `bussard replace` subcommand — guided replacement of a dead device
//! (issue #98).
//!
//! Replacing a failed actuator is the repair that most often sends an owner back
//! to an integrator. In bussard the pieces already existed — `assign`, `flash`,
//! `apply` — but as three separate commands with three confirmations and nothing
//! checking that the new box is the same product as the old one. In ETS, an
//! incompatible application wipes parameters and links; here it would flash the
//! wrong image onto the wrong hardware.
//!
//! `replace` is those three steps behind one guided flow and one confirmation:
//!
//! 1. **Confirm the old device is gone.** A device that still answers is not a
//!    replacement case; that needs `--force`, which is how you say "yes, I know
//!    it answers, re-address it anyway".
//! 2. **Prompt for the programming button** and read what answers: its order
//!    number, mask version and resident application id. Any of those differing
//!    from the model's device file refuses the run unless `--force`.
//! 3. **Confirm once**, naming the gateway, then assign the address, flash the
//!    application with the model's parameters (skip with `--no-flash`), apply
//!    the model's tables, and verify.
//! 4. **Record the replacement** as `replaced: <RFC3339>` in the device file, so
//!    the history of that address shows the hardware swap.
//!
//! # No new write primitive
//!
//! The flow is [`bussard_service::replace`], the step machine `knx_replace_device`
//! runs too (issue #751). Every write here is an existing command's: the
//! address goes on with [`bussard_service::assign::write_address`] and is
//! verified by [`crate::assign_cmd::verify_assignment`]; the application is
//! written by [`crate::flash_cmd::run`]; the tables by [`crate::apply_cmd::run`].
//! `replace` adds sequencing, the identity cross-check and the record —
//! nothing that touches the bus on its own.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_download::backup::rfc3339_utc;
use bussard_mgmt::system_type;
use bussard_model::IndividualAddress;
use bussard_service::replace::{self, Pressed, Replacement, Step};
use bussard_service::{BusService, WritePolicy};

use crate::assign_cmd;
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display,
    load_model_required, open_service, resolve_config,
};

/// Runs `bussard replace`.
#[allow(clippy::too_many_arguments)] // the subcommand's flags, 1:1
pub fn run(
    address: &str,
    product: Option<&Path>,
    dir: &Path,
    yes: bool,
    force: bool,
    no_flash: bool,
    allow_remote_gateway: bool,
    bcu_key: Option<&str>,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A non-TTY run without --yes was refused before this (issue #74), by
    // `confirm::require_terminal_or_yes` in `main`.

    let Some(model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                &format!(
                    "`bussard replace` reads which product belongs at {target} from its device file"
                )
            )
        );
    };
    let replacement = Replacement::from_model(&model, dir, target, no_flash)?;
    let Some(loaded) = model.devices.get(&target) else {
        bail!("the model has no device file for {target}");
    };
    // The product data comes from the lock and the store (issue #228, item
    // 4): `--product` overrides, and one that contradicts the lock needs
    // `--force`. Resolved before anything reaches the bus, so a missing
    // archive refuses the run with its recovery step.
    let product_path = if no_flash {
        None
    } else {
        crate::lock_pin::enforce_override(dir, &loaded.device, product, None, force, "replace")?;
        let order = replacement
            .expected
            .order_number
            .clone()
            .unwrap_or_default();
        Some(crate::product_store::resolve(
            dir,
            product,
            Some(&loaded.device),
            &order,
        )?)
    };

    let config = resolve_config(Some(&model), &overrides)?;
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    // Phase 1 (read-only, on its own runtime): confirm the old device is gone,
    // capture the pressed device, cross-check it, confirm, and write the address.
    // The runtime is dropped before `flash` / `apply`, each of which builds its
    // own (a runtime cannot be created inside a runtime).
    let assigned = {
        let runtime = tokio::runtime::Runtime::new()?;
        let config = config.clone();
        let gateway = gateway.clone();
        let conn = overrides.clone();
        let replacement = replacement.clone();
        runtime.block_on(async move {
            let service = open_service(config, WritePolicy::transmit(allow_remote_gateway)).await?;
            let source = checked_source_or_close(&service, &conn).await?;
            let result = tokio::select! {
                result = swap_flow(&service, source, &replacement, &gateway, yes, force) => result,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\ninterrupted; closing the bus connection");
                    Err(anyhow!("replace interrupted by Ctrl-C"))
                }
            };
            service.close().await;
            result
        })?
    };

    let Some(pressed) = assigned else {
        return Ok(ExitCode::FAILURE);
    };
    // The stored device facts describe the old box: drop them, so the flash
    // and apply below read the replacement's (issue #209, #228 item 5).
    replace::forget_facts(dir, target);

    // Phase 2: the application image, through `bussard flash`.
    let mut flashed = false;
    if let Some(product) = product_path.as_deref() {
        println!("\nflashing the application from {}…", product.display());
        let code = crate::flash_cmd::run(
            address,
            Some(product),
            None,
            None,
            dir,
            true,
            // The replacement device is a different physical box; whatever it
            // carries from the factory or a previous life is not the model's
            // application, so the freshness refusal would always fire here. The
            // operator already consented to the whole run.
            true,
            false,
            false,
            false,
            allow_remote_gateway,
            bcu_key,
            tool_key_source,
            None,
            overrides.clone(),
            crate::flash_cmd::FlashOutput::default(),
        )?;
        if code != ExitCode::SUCCESS {
            eprintln!(
                "\nERROR: the flash step failed. {target} now has the right address but not the \
                 right application; re-run `bussard flash {target} --product {}` once the cause \
                 is fixed.",
                product.display()
            );
            return Ok(ExitCode::FAILURE);
        }
        flashed = true;
    } else {
        println!("\n--no-flash: leaving the application image alone");
    }

    // Phase 3: the link tables, through `bussard apply`.
    println!("\napplying the model's link tables…");
    let code = crate::apply_cmd::run(
        address,
        dir,
        true,
        allow_remote_gateway,
        tool_key_source,
        None,
        overrides,
        crate::apply_cmd::ApplyInputs::default(),
    )?;
    if code != ExitCode::SUCCESS {
        eprintln!(
            "\nERROR: the apply step failed. {target} is addressed and programmed but its links \
             are not loaded; re-run `bussard apply {target}`."
        );
        return Ok(ExitCode::FAILURE);
    }

    // Phase 4: the record.
    let when = rfc3339_utc(std::time::SystemTime::now());
    let recorded = replace::record(dir, &replacement, pressed.serial.as_deref(), &when)
        .with_context(|| {
            format!(
                "recording the replacement in {}",
                replacement.device_file.display()
            )
        })?;

    print_summary(
        target,
        &pressed,
        &gateway,
        flashed,
        &recorded.device_file,
        &when,
    );
    Ok(ExitCode::SUCCESS)
}

/// The read, cross-check, confirm and address-write half of a replacement:
/// the steps of [`bussard_service::replace`] up to [`Step::Assign`], with
/// this command's lines and prompt.
///
/// Returns `Ok(Some(pressed))` when the new device took the address, `Ok(None)`
/// when the run was declined or nothing could be identified (a clean command
/// failure, not an error).
async fn swap_flow(
    service: &BusService,
    source: IndividualAddress,
    replacement: &Replacement,
    gateway: &str,
    yes: bool,
    force: bool,
) -> anyhow::Result<Option<Pressed>> {
    let target = replacement.target;
    let mut step = Step::CheckGone;
    let mut current = None;
    let mut pressed = None;
    loop {
        match step {
            // 1. The old device must be gone.
            Step::CheckGone => {
                if let Some(occupant) =
                    bussard_service::assign::probe_occupant(service, source, target).await
                {
                    if !force {
                        eprintln!(
                            "{target} still answers on the bus ({}).\n\
                             `replace` is for a device that has failed or been removed. If you \
                             really mean to re-address whatever is in programming mode onto \
                             {target}, re-run with --force.",
                            occupant.describe()
                        );
                        return Ok(None);
                    }
                    eprintln!(
                        "warning: {target} still answers ({}); --force given, continuing",
                        occupant.describe()
                    );
                } else {
                    println!(
                        "{target} does not answer, consistent with a failed or removed device"
                    );
                }
            }
            // 2. The replacement, via its programming button.
            Step::PressButton => {
                println!("\nPress the programming button on the replacement device for {target}.");
                let Some(found) = assign_cmd::wait_for_single_device(service, source).await? else {
                    return Ok(None);
                };
                current = Some(found);
            }
            Step::Identify => {
                let Some(at) = current else {
                    return Ok(None);
                };
                let read = replace::identify(service, source, at).await;
                print_identity(&read);
                if let Some(check) = replacement.identity_check(&read) {
                    println!("  {}", crate::device_facts::identity_line(target, &check));
                }
                pressed = Some(read);
            }
            // 3. Cross-check against the model's device file.
            Step::CrossCheck => {
                let Some(read) = &pressed else {
                    return Ok(None);
                };
                if let Some(problem) = replacement.mismatch(read) {
                    if !force {
                        eprintln!(
                            "\nrefusing to replace {target}: {problem}\n\
                             A different product means a different application, and flashing it \
                             would load the wrong image. Fix the device file, use the right \
                             spare, or re-run with --force if you know the model is out of date."
                        );
                        return Ok(None);
                    }
                    eprintln!("\nwarning: {problem}; --force given, continuing");
                }
            }
            // 4. One confirmation for the whole run.
            Step::Confirm => {
                let Some(at) = current else {
                    return Ok(None);
                };
                if !confirm(target, at, gateway, yes)? {
                    eprintln!("aborted; nothing was written.");
                    return Ok(None);
                }
            }
            // 5. The address, exactly as `assign` writes it.
            Step::Assign => {
                let (Some(at), Some(read)) = (current, pressed.take()) else {
                    return Ok(None);
                };
                bussard_service::assign::write_address(service, source, target)
                    .await
                    .context("broadcasting the new individual address")?;
                eprintln!("wrote {target}; verifying…");
                let verified = assign_cmd::verify_assignment(
                    service,
                    source,
                    target,
                    &assign_cmd::VerifyKey::default(),
                )
                .await?;
                if verified.programming_mode_cleared {
                    eprintln!(
                        "cleared programming mode on {target} (PID_PROGMODE = 0), as ETS does."
                    );
                }
                assign_cmd::warn_if_still_in_programming_mode(service, source, target).await;
                println!("assigned {at} → {target}");
                return Ok(Some(replace::assigned(read, &verified)));
            }
            // The flash and the apply run on their own runtimes, in `run`.
            Step::Flash | Step::Apply | Step::Record | Step::Done => return Ok(None),
        }
        step = replacement.next(step);
    }
}

/// Prints what the pressed device says it is.
fn print_identity(pressed: &Pressed) {
    println!("device in programming mode: {}", pressed.address);
    match pressed.mask {
        Some(mask) => println!("  mask: {mask:04X} ({})", system_type(mask)),
        None => println!("  mask: unreadable"),
    }
    println!(
        "  order number: {}",
        pressed.order.as_deref().unwrap_or("unreadable")
    );
    println!(
        "  application: {}",
        pressed.application.as_deref().unwrap_or("none resident")
    );
    if let Some(serial) = &pressed.serial {
        println!("  serial: {}", assign_cmd::hex(serial));
    }
}

/// The single confirmation for the whole run, naming the gateway.
fn confirm(
    target: IndividualAddress,
    current: IndividualAddress,
    gateway: &str,
    yes: bool,
) -> anyhow::Result<bool> {
    crate::confirm::confirm(
        yes,
        &format!(
            "replace {target}: address {current} → {target}, flash the application and apply \
             the model's tables, via {gateway}?"
        ),
        &format!("replace {target} via {gateway}"),
    )
}

/// Prints the closing summary.
fn print_summary(
    target: IndividualAddress,
    pressed: &Pressed,
    gateway: &str,
    flashed: bool,
    device_file: &Path,
    when: &str,
) {
    println!("\nreplaced {target} via {gateway}");
    println!(
        "  new hardware answered at {} before assignment",
        pressed.address
    );
    if let Some(order) = &pressed.order {
        println!("  order number: {order}");
    }
    if let Some(mask) = pressed.mask {
        println!("  mask: {mask:04X} ({})", system_type(mask));
    }
    if let Some(serial) = &pressed.serial {
        println!("  serial: {}", assign_cmd::hex(serial));
    }
    println!(
        "  application: {}",
        if flashed {
            "flashed from the product data"
        } else {
            "left alone (--no-flash)"
        }
    );
    println!("  link tables: applied and verified");
    println!("  recorded replaced: {when} in {}", device_file.display());
    println!("\nnext steps:");
    println!("  - `bussard plan {target}` to confirm the links match the model");
    println!("  - `bussard backup` to refresh the installation snapshot");
}
