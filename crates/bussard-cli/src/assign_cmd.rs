//! The `bussard assign` subcommand — individual address assignment via
//! programming mode.
//!
//! The "I added a new device" flow. A device in programming mode announces
//! itself to a broadcast read; `assign` picks a target address (explicit or the
//! next free device number on the model's dominant line), writes it with
//! `A_IndividualAddress_Write`, verifies by connecting to the new address, and
//! drops a stub device file so the user can flesh out name/room and import the
//! product later.
//!
//! The bus write is irreversible-ish (it re-addresses whatever single device is
//! in programming mode), so the flow is conservative: it refuses to proceed with
//! more than one device in programming mode, and refuses an *implicit* address
//! allocation when there is no TTY to confirm on.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_mgmt::system_type;
use bussard_model::Model;
use bussard_service::assign::{VerifyKey, build_stub_device, write_device_file};
use bussard_service::identity::SecureStatus;
use bussard_service::program::assign::{Assign, AssignFlow};
use bussard_service::secure::{ToolKeySource, ToolKeys};
use bussard_service::{BusService, WritePolicy};

use crate::addressing::{Bench, question, stopped, warn_forced};

/// Formats a byte slice as lowercase hex.
pub(crate) use bussard_service::assign::hex;

use crate::cli::{Consent, Resolved, Run, Spec};
use crate::conn_cmd::{
    checked_source_or_close, enforce_write_gate, gateway_display, resolve_config,
};

/// `bussard assign`.
#[derive(Debug, clap::Args)]
pub(crate) struct AssignArgs {
    /// The address to assign, e.g. `1.1.47` (default: next free on the line).
    #[arg(value_name = "ADDRESS")]
    address: Option<String>,
    #[command(flatten)]
    consent: Consent,
    /// A raw KNX Data Secure tool key (32 hex characters) to verify a
    /// secured device with after the address write.
    /// Overrides the keyring, which lists devices by address and
    /// so only knows the new address once ETS re-exports it. For a test or
    /// bench device: process arguments are visible to other users.
    // Issue #203.
    #[arg(long, value_name = "HEX")]
    tool_key: Option<String>,
    /// Write the address although another device already answers at it
    /// (the check is step 1 of the standard's address write).
    // Issue #530.
    #[arg(long)]
    force: bool,
}

impl Run for AssignArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json().tool_key(self.tool_key.is_some())
    }

    fn early_consent(&self) -> Option<(bool, String)> {
        let action = match &self.address {
            Some(address) => format!("assign {address}"),
            None => "assign the next free address".to_string(),
        };
        Some((self.consent.yes, action))
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(&self, g)
    }
}

/// Runs `bussard assign`.
fn run(args: &AssignArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, allow_remote_gateway, overrides) = (g.dir(), g.allow_remote_gateway, g.mgmt());
    // `--tool-key` overrides the keyring's device entries; the keyring
    // still opens a KNXnet/IP Secure tunnel (issue #203).
    let tool_key_source = ToolKeySource {
        keyring: g.keyring().filter(|_| args.tool_key.is_none()),
        tool_key: args.tool_key.as_deref(),
    };
    // A non-TTY run without --yes was refused before this (issue #74), by
    // `confirm::require_terminal_or_yes` in `main`.
    // Address allocation needs the model; an explicit address on a missing
    // model is allowed with a warning, a broken model never (issue #55).
    let model = load_model_optional(
        dir,
        args.address.is_some(),
        "assign",
        "pass an explicit address (e.g. `bussard assign 1.1.47`) to proceed without one",
    )?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    // The tool keys for the post-write verification (issue #203), loaded
    // before the bus is touched so a wrong keyring password fails fast.
    let keys = ToolKeys::load(tool_key_source).context("loading the tool key for assign")?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let service = BusService::open(config, WritePolicy::transmit(allow_remote_gateway))?;
        // Wait for the actor to connect so the tunnel-assigned source address is
        // available (falling back to 0.0.255 on routing) — issue #30.
        service
            .wait_connected(crate::conn_cmd::connect_wait())
            .await;
        let source = checked_source_or_close(&service, &overrides).await?;
        // Guard the assign flow with Ctrl-C: on interrupt, fall through to a
        // clean `service.close()` so the gateway tunnel slot is released rather
        // than leaked — see issue #31.
        let result = tokio::select! {
            result = assign_flow(AssignFlow { service: &service, source }, args, g, &gateway, model.as_ref(), &keys) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Err(anyhow!("assign interrupted by Ctrl-C"))
            }
        };
        service.close().await;
        result
    })
}

/// The model load shared by `assign` and `adopt`: an absent directory is a
/// fresh project (allowed, with a warning, under an explicit address); a
/// present directory that fails to parse is always a hard error (issue #55).
/// `missing_hint` tells the operator how to proceed without a model.
pub(crate) fn load_model_optional(
    dir: &Path,
    have_explicit_address: bool,
    command: &str,
    missing_hint: &str,
) -> anyhow::Result<Option<Model>> {
    if !bussard_model::discover::is_model_dir(dir) {
        if have_explicit_address {
            eprintln!(
                "warning: no model in {}; continuing because an explicit address was given",
                crate::conn_cmd::describe_dir(dir)
            );
            return Ok(None);
        }
        return Err(anyhow!(
            "no model in {}: {command} picks a free address from the devices the model \
             lists; {missing_hint}",
            crate::conn_cmd::describe_dir(dir)
        ));
    }
    match Model::load(dir) {
        Ok(model) => Ok(Some(model)),
        // A present-but-broken model is a hard error regardless of an explicit
        // address: never run a management command against a model that failed to
        // parse.
        Err(err) => Err(anyhow!(
            "could not load model from {}: {err}\n\
             refusing to run {command} against a model that failed to parse; fix the model files first",
            dir.display()
        )),
    }
}

/// The end-to-end assign flow ([`AssignFlow`]). Each broadcast and each
/// connected verify leases the bus for the duration of that step
/// (releasing it in between), so other bus consumers keep observing.
async fn assign_flow(
    flow: AssignFlow<'_>,
    args: &AssignArgs,
    g: &Resolved,
    gateway: &str,
    model: Option<&Model>,
    keys: &ToolKeys,
) -> anyhow::Result<ExitCode> {
    let (dir, json) = (g.dir(), g.json);
    let bench = &mut Bench::new(args.consent.yes);
    // The model says the target is free; the bus has the last word
    // (NM_IndividualAddress_Write step 1, issue #530).
    let target = bussard_service::assign::target_address(
        args.address.as_deref(),
        model,
        "pass one explicitly, e.g. `bussard assign 1.1.47`",
    )?;
    let located = async {
        if let Some(occupant) = flow.check_free(target, args.force, bench).await? {
            warn_forced(target, &occupant);
        }
        flow.wait_for_one(bench).await
    };
    let current = match located.await {
        Ok(current) => current,
        Err(stop) => return stopped(stop, "assign"),
    };
    // The keyring lists devices by address: the tool key of the new address,
    // else of the old one (issue #203).
    let key = VerifyKey::resolve(keys, current, target);
    let question = question("assign", current, target, gateway);
    let request = Assign {
        current,
        target,
        question: Some(&question),
        key: &key,
        clear_programming_mode: true,
        identified: None,
        refuse_hidden: false,
        require_identified: false,
        forget_facts: None,
    };
    let verified = match flow.assign(&request, bench).await {
        Ok(assigned) => assigned.verified,
        Err(stop) => return stopped(stop, "assign"),
    };
    if key.from_old_address {
        eprintln!(
            "note: the keyring lists this device under its old address {current}; the tool key \
             was taken from that entry. Re-export the keyring from ETS after the address \
             change so it lists {target} (bussard looks tool keys up by individual address)."
        );
    }

    // The identity verdict at the new address (issue #228, item 5).
    if let Some(mask) = verified.mask {
        let modelled = model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device);
        let check =
            bussard_service::scan::observe_identity(dir, model.is_some(), target, mask, modelled);
        println!("  {}", bussard_service::identity_line(target, &check));
    }
    // A certificate entered before the device had an address (issue #728).
    if let Some(serial) = &verified.serial {
        crate::keys_cmd::attach_learned_serials(dir, &[(target, serial.clone())]).print(json);
    }
    // The stub device file; the lock records the serial (#752).
    let device = build_stub_device(target, &verified);
    let path = write_device_file(
        model,
        dir,
        device,
        verified.serial.as_deref(),
        "stub device file",
    )?;

    if json {
        crate::output::print(
            crate::output::schema::ASSIGN,
            &serde_json::json!({
                "from": current.to_string(),
                "to": target.to_string(),
                "gateway": gateway,
                "mask": verified.mask.map(|m| format!("{m:04X}")),
                "manufacturer_id": verified.manufacturer_id,
                "serial": verified.serial.as_deref().map(hex),
                "secure": verified.secure.as_str(),
                "programming_mode_cleared": verified.programming_mode_cleared,
                "device_file": path.display().to_string(),
            }),
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("assigned {current} → {target}");
    match (verified.secure, verified.mask) {
        (SecureStatus::ActivatedNoKey, _) => println!(
            "  verified: the device answers at {target}; secured (mask hidden), bussard \
             has no tool key for it (pass --keyring with a current export, or --tool-key)"
        ),
        (SecureStatus::Activated, Some(mask)) => println!(
            "  verified (secured): mask {mask:#06x} ({})",
            system_type(mask)
        ),
        (_, Some(mask)) => println!("  verified: mask {mask:#06x} ({})", system_type(mask)),
        (_, None) => {}
    }
    if let Some(serial) = &verified.serial {
        println!("  serial: {}", hex(serial));
    }
    println!("  wrote stub device file: {}", path.display());
    println!();
    println!("next steps:");
    println!("  - edit the name/room in {}", path.display());
    println!("  - `bussard import-product <file.knxprod>` to attach its product data");
    println!(
        "  - wire its group objects in {} ([links] or [channel.<handle>])",
        path.display()
    );
    Ok(ExitCode::SUCCESS)
}
