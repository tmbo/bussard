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
//! The flow is [`bussard_service::replace`], which `knx_replace_device`
//! runs too (issues #751, #902). Every write here is an existing command's:
//! the address goes on through
//! [`bussard_service::program::assign::AssignFlow`]; the application is
//! written by `bussard flash`; the tables by `bussard apply`.
//! `replace` adds sequencing, the identity cross-check and the record —
//! nothing that touches the bus on its own.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_model::IndividualAddress;
use bussard_service::WritePolicy;
use bussard_service::download::backup::rfc3339_utc;
use bussard_service::mgmt::system_type;
use bussard_service::program::Question;
use bussard_service::program::assign::{AssignFlow, Stop};
use bussard_service::replace::{self, Pressed, Replacement};

use crate::addressing::stopped;
use crate::apply_cmd::ApplyArgs;
use crate::assign_cmd::hex;
use crate::cli::{BenchToolKey, Consent, Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{
    enforce_write_gate, gateway_display, load_model_required, open_checked, resolve_config,
};
use crate::flash_cmd::FlashArgs;
use crate::progress::Terminal;

/// `bussard replace`.
#[derive(Debug, clap::Args)]
pub(crate) struct ReplaceArgs {
    /// The address of the device being replaced, e.g. `1.1.4`.
    #[arg(value_name = "ADDRESS")]
    address: String,
    /// The vendor `.knxprod` to flash the replacement with. Default: the
    /// archive `bussard.lock` pins for the device in `<dir>/products/`.
    #[arg(long, value_name = "FILE")]
    product: Option<PathBuf>,
    #[command(flatten)]
    consent: Consent,
    /// Override the replacement-identity refusals: proceed although the old
    /// device still answers, or although the pressed device's order number,
    /// mask or application does not match the device file.
    #[arg(long)]
    force: bool,
    /// Assign and apply, but leave the application image alone — for a spare
    /// that already carries the right application.
    #[arg(long)]
    no_flash: bool,
    /// The device's BCU access key, in hex, presented with A_Authorize on
    /// every management connect.
    // Issue #52.
    #[arg(long, value_name = "HEX")]
    bcu_key: Option<String>,
    #[command(flatten)]
    tool_key: BenchToolKey,
    /// Write the device even though its application program is not on
    /// bussard's list of supported devices (`bussard device --supported`).
    /// Back the device up first. A loopback gateway (a simulator) is never
    /// refused.
    // Issue #1089.
    #[arg(long)]
    allow_unsupported: bool,
}

impl Run for ReplaceArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.tool_key(self.tool_key.tool_key.is_some())
    }

    fn early_consent(&self) -> Option<(bool, String)> {
        Some((self.consent.yes, format!("replace {}", self.address)))
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self, g)
    }
}

/// Runs `bussard replace`.
fn run(args: ReplaceArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (address, product) = (args.address.as_str(), args.product.as_deref());
    let (yes, force, no_flash) = (args.consent.yes, args.force, args.no_flash);
    let (dir, allow_remote_gateway, overrides) = (g.dir(), g.allow_remote_gateway, g.mgmt());
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
        bail!("your project has no device file for {target}");
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
    // The supported-device list (issue #1089), before the address is
    // written, so a refusal leaves nothing half done. `flash` and `apply`
    // ask it again with the same answer.
    crate::support_gate::authorize(
        &config,
        target,
        bussard_service::support::verdict_at(Some(&model), target),
        args.allow_unsupported,
    )?;
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
            let (service, source) =
                open_checked(config, WritePolicy::transmit(allow_remote_gateway), &conn).await?;
            let flow = AssignFlow {
                service: &service,
                source,
            };
            let result = tokio::select! {
                result = swap_flow(flow, dir, &replacement, &gateway, yes, force) => result,
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
    // Phase 2: the application image, through `bussard flash`.
    let mut flashed = false;
    if let Some(product) = product_path.as_deref() {
        println!("\nflashing the application from {}…", product.display());
        let code = FlashArgs {
            address: address.to_string(),
            product: Some(product.to_path_buf()),
            consent: Consent { yes: true },
            // The replacement device is a different physical box; whatever it
            // carries from the factory or a previous life is not the model's
            // application, so the freshness refusal would always fire here. The
            // operator already consented to the whole run.
            force: true,
            bcu_key: args.bcu_key.clone(),
            tool_key: ToolKey {
                tool_key: args.tool_key.tool_key.clone(),
            },
            allow_unsupported: args.allow_unsupported,
            ..FlashArgs::default()
        }
        .run(&g.step())?;
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
    println!("\napplying the link tables in your project…");
    let code = ApplyArgs {
        address: Some(address.to_string()),
        consent: Consent { yes: true },
        tool_key: ToolKey {
            tool_key: args.tool_key.tool_key.clone(),
        },
        allow_unsupported: args.allow_unsupported,
        ..ApplyArgs::default()
    }
    .run(&g.step())?;
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

/// The read, cross-check, confirm and address-write half of a replacement
/// ([`replace::locate`], [`replace::assign_replacement`]), with this
/// command's lines and prompt.
///
/// Returns `Ok(Some(pressed))` when the new device took the address, `Ok(None)`
/// when the run was declined or refused (a clean command failure, not an
/// error).
async fn swap_flow(
    flow: AssignFlow<'_>,
    dir: &Path,
    replacement: &Replacement,
    gateway: &str,
    yes: bool,
    force: bool,
) -> anyhow::Result<Option<Pressed>> {
    let target = replacement.target;
    let bench = &mut Terminal::new(yes, false).press(format!(
        "\nPress the programming button on the replacement device for {target}."
    ));
    let refused = |stop| stopped(stop, "replace").map(|_| None);
    // 1. The old device must be gone.
    match flow.check_free(target, force, bench).await {
        Ok(None) => {
            println!("{target} does not answer, consistent with a failed or removed device")
        }
        Ok(Some(occupant)) => eprintln!(
            "warning: {target} still answers ({}); --force given, continuing",
            occupant.describe()
        ),
        Err(Stop::Occupied { occupant, .. }) => {
            eprintln!(
                "{target} still answers on the bus ({}).\n`replace` is for a device that has \
                 failed or been removed. If you really mean to re-address whatever is in \
                 programming mode onto {target}, re-run with --force.",
                occupant.describe()
            );
            return Ok(None);
        }
        Err(stop) => return refused(stop),
    }
    // 2. The replacement, via its programming button, checked against the
    //    model's device file.
    let located = match replace::locate(&flow, replacement, bench).await {
        Ok(located) => located,
        Err(stop) => return refused(stop),
    };
    print_identity(&located.pressed);
    if let Some(check) = replacement.identity_check(&located.pressed) {
        println!("  {}", bussard_service::identity_line(target, &check));
    }
    match &located.mismatch {
        Some(problem) if !force => {
            eprintln!(
                "\nrefusing to replace {target}: {problem}\nA different product means a \
                 different application, and flashing it would load the wrong image. Fix the \
                 device file, use the right spare, or re-run with --force if you know your project \
                 is out of date."
            );
            return Ok(None);
        }
        Some(problem) => eprintln!("\nwarning: {problem}; --force given, continuing"),
        None => {}
    }
    // 3. One confirmation for the whole run, then the address, exactly as
    //    `assign` writes it.
    let current = located.pressed.address;
    let question = Question {
        kind: bussard_service::observer::Ask::Write,
        prompt: format!(
            "replace {target}: address {current} → {target}, flash the application and apply \
             the tables in your project, via {gateway}?"
        ),
        action: format!("replace {target} via {gateway}"),
    };
    let assigned = replace::assign_replacement(
        &flow,
        dir,
        replacement,
        located.pressed,
        Some(&question),
        false,
        bench,
    )
    .await;
    match assigned {
        Ok((pressed, _)) => {
            println!("assigned {current} → {target}");
            Ok(Some(pressed))
        }
        Err(stop) => refused(stop),
    }
}

/// Prints what the pressed device says it is.
fn print_identity(pressed: &Pressed) {
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
        println!("  serial: {}", hex(serial));
    }
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
        println!("  serial: {}", hex(serial));
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
    println!("  - `bussard plan {target}` to confirm the links match your project");
    println!("  - `bussard backup` to refresh the installation snapshot");
}
