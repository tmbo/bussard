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

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_mgmt::system_type;
use bussard_model::schema::Device;
use bussard_model::{IndividualAddress, Model};
use bussard_service::assign::{ProgrammingWait, WaitEvent, wait_for_programming_mode};
use bussard_service::identity::SecureStatus;
use bussard_service::secure::ToolKeys;
use bussard_service::{BusService, WritePolicy};

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display, resolve_config,
};

/// The on/off flags of one `bussard assign` run.
#[derive(Debug, Clone, Copy, Default)]
pub struct AssignFlags {
    /// `--yes`: skip the confirmation prompt.
    pub yes: bool,
    /// `--allow-remote-gateway`: permit a write through a non-loopback gateway.
    pub allow_remote_gateway: bool,
    /// `--json`: print the result as a JSON document.
    pub json: bool,
    /// `--force`: write the address although another device answers at it.
    pub force: bool,
}

/// Runs `bussard assign`.
pub fn run(
    address: Option<&str>,
    dir: &Path,
    flags: AssignFlags,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let AssignFlags {
        yes,
        allow_remote_gateway,
        json,
        force,
    } = flags;
    // A non-TTY run without --yes was refused before this (issue #74), by
    // `confirm::require_terminal_or_yes` in `main`.
    // 1. Load the model. Address allocation needs it; an explicit --address on an
    //    empty/missing model is allowed with a warning.
    let model = load_model_for_assign(dir, address.is_some())?;
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
            result = assign_flow(&service, source, address, AssignRun { yes, json, force, gateway: &gateway }, model.as_ref(), dir, &keys) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Err(anyhow!("assign interrupted by Ctrl-C"))
            }
        };
        service.close().await;
        result
    })
}

/// The per-run choices `assign_flow` needs besides the bus and the model.
#[derive(Clone, Copy)]
struct AssignRun<'a> {
    /// `--yes`: skip the confirmation prompt.
    yes: bool,
    /// `--json`: print the result as a JSON document.
    json: bool,
    /// `--force`: write the address although another device answers at it.
    force: bool,
    /// The resolved gateway, for the prompt.
    gateway: &'a str,
}

/// Loads the model for an assign run.
///
/// The model is required for implicit allocation (we need the device list to
/// pick a free number and the dominant line). Two failure modes are kept
/// distinct (issue #55): an **absent** model directory is a fresh project, so
/// with an explicit address we warn and continue (a brand-new project can assign
/// its first device); a directory that is **present but fails to parse** is a
/// hard error either way — assign is a management command and must never proceed
/// against a broken model, even with an explicit address.
fn load_model_for_assign(dir: &Path, have_explicit_address: bool) -> anyhow::Result<Option<Model>> {
    load_model_optional(
        dir,
        have_explicit_address,
        "assign",
        "pass an explicit address (e.g. `bussard assign 1.1.47`) to proceed without one",
    )
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

/// The end-to-end assign flow over the bus actor. Each connectionless broadcast
/// and each connection-oriented verify leases the bus for the duration of that
/// step (releasing it in between), so other bus consumers keep observing.
#[allow(clippy::too_many_arguments)] // one call site; the flow's inputs, spelled out
async fn assign_flow(
    service: &BusService,
    source: IndividualAddress,
    address: Option<&str>,
    run: AssignRun<'_>,
    model: Option<&Model>,
    dir: &Path,
    keys: &ToolKeys,
) -> anyhow::Result<ExitCode> {
    let AssignRun {
        yes,
        json,
        force,
        gateway,
    } = run;
    // 2. Decide the target address. The model says it is free; the bus has
    //    the last word (step 3).
    let target = bussard_service::assign::target_address(
        address,
        model,
        "pass one explicitly, e.g. `bussard assign 1.1.47`",
    )?;

    // 3. NM_IndividualAddress_Write step 1 (Management Procedures 03_05_02
    //    §2.3, issue #530): nothing may answer at the target before it is
    //    given away, or two devices end up on one address.
    if !target_is_free(service, source, target, force, "assign").await {
        return Ok(ExitCode::FAILURE);
    }

    // 4. Find exactly one device in programming mode.
    let current = match wait_for_single_device(service, source).await? {
        Some(addr) => addr,
        None => return Ok(ExitCode::FAILURE),
    };
    eprintln!("device in programming mode: {current} (its current address)");

    // The tool key the verification needs, if the device is Data Secure
    // activated (issue #203): the keyring lists devices by IA, so look for the
    // new address first and fall back to the old one.
    let verify_key = VerifyKey::resolve(keys, current, target);

    // 4. Confirm.
    if !confirm_assignment(current, target, yes, gateway)? {
        eprintln!("aborted; no address was written.");
        return Ok(ExitCode::FAILURE);
    }

    // 5. Write, then verify.
    bussard_service::assign::write_address(service, source, target)
        .await
        .context("broadcasting the new individual address")?;
    eprintln!("wrote {target}; verifying…");

    let verified = verify_assignment(service, source, target, &verify_key).await?;
    if verified.programming_mode_cleared {
        eprintln!("cleared programming mode on {target} (PID_PROGMODE = 0), as ETS does.");
    }
    if verify_key.from_old_address {
        eprintln!(
            "note: the keyring lists this device under its old address {current}; the tool key \
             was taken from that entry. Re-export the keyring from ETS after the address \
             change so it lists {target} (bussard looks tool keys up by individual address)."
        );
    }

    // 5a. Programming-mode persistence check (fallback). We already cleared
    //     programming mode explicitly above (PID_PROGMODE = 0), exactly as ETS
    //     does. This re-runs the programming-mode broadcast once, briefly, and
    //     warns only if `target` STILL answers it — meaning neither the explicit
    //     clear nor the device's own auto-clear took, so the next assign/adopt
    //     would re-capture and re-address it. On a conformant device this is now a
    //     no-op; the warning remains the backstop for a device that ignored both.
    warn_if_still_in_programming_mode(service, source, target).await;

    // The identity verdict at the new address (issue #228, item 5): the
    // device the model has there, if any, against what answered; facts
    // stored under another mask are dropped.
    if let Some(mask) = verified.mask {
        let modelled = model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device);
        let check = crate::device_facts::observe(dir, model.is_some(), target, mask, modelled);
        println!("  {}", crate::device_facts::identity_line(target, &check));
    }

    // A certificate entered before the device had an address (issue #728):
    // its factory key moves to the new address now that the serial is known.
    if let Some(serial) = &verified.serial {
        crate::keys_cmd::attach_learned_serials(dir, &[(target, serial.clone())], json);
    }

    // 6. Create the stub device file; the lock records the serial (#752).
    let device = build_stub_device(target, &verified);
    let path = write_stub_device_file(model, dir, device, verified.serial.as_deref())?;

    // 7. Next steps.
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
            "  verified: the device answers at {target}; Data Secure activated (mask hidden), \
             no tool key in the keyring (pass --keyring with a current export, or --tool-key)"
        ),
        (SecureStatus::Activated, Some(mask)) => println!(
            "  verified (secured): mask {mask:#06x} ({}); Data Secure activated",
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

/// What answers at an address bussard is about to give a device
/// ([`bussard_service::assign::Occupant`]).
pub(crate) use bussard_service::assign::Occupant;

/// What the post-write verification read back from the device
/// ([`bussard_service::assign::Verified`]).
pub(crate) use bussard_service::assign::Verified;

/// The tool key for the post-write verification
/// ([`bussard_service::assign::VerifyKey`]).
pub(crate) use bussard_service::assign::VerifyKey;

pub(crate) use bussard_service::assign::{build_stub_device, hex};

/// Step 1 of NM_IndividualAddress_Write
/// ([`bussard_service::assign::probe_occupant`]).
pub(crate) async fn probe_occupant(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) -> Option<Occupant> {
    bussard_service::assign::probe_occupant(service, source, target).await
}

/// Whether `verb` may write `target`: nothing answers there, or `force`
/// overrides an occupant (with a warning). Prints the refusal otherwise.
pub(crate) async fn target_is_free(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    force: bool,
    verb: &str,
) -> bool {
    let Some(occupant) = probe_occupant(service, source, target).await else {
        return true;
    };
    if force {
        eprintln!(
            "warning: {target} already answers on the bus ({}); --force given, continuing",
            occupant.describe()
        );
        return true;
    }
    eprintln!(
        "{}",
        bussard_service::assign::occupied_refusal(target, &occupant, verb)
    );
    false
}

/// Polls for devices in programming mode, nagging the user to press the button
/// if none appear, until exactly one is found or the budget is exhausted.
///
/// Returns `Ok(Some(addr))` for the single found device, or `Ok(None)` after
/// printing friendly guidance for the zero-found (timeout) and multiple-found
/// cases — both of which are a clean command failure, not an error.
pub(crate) async fn wait_for_single_device(
    service: &BusService,
    source: IndividualAddress,
) -> anyhow::Result<Option<IndividualAddress>> {
    wait_for_single_device_as(service, source, "assign").await
}

/// [`wait_for_single_device`], naming `verb` (the command, e.g. `adopt`) in the
/// guidance it prints. The wait is
/// [`bussard_service::assign::wait_for_programming_mode`].
pub(crate) async fn wait_for_single_device_as(
    service: &BusService,
    source: IndividualAddress,
    verb: &str,
) -> anyhow::Result<Option<IndividualAddress>> {
    let mut on_event = |event: WaitEvent| match event {
        WaitEvent::Remind => eprintln!(
            "no device in programming mode yet — press the programming button on the device, \
             then keep waiting (or re-run)."
        ),
        WaitEvent::Waiting { remaining } => {
            eprint!("\rwaiting for a device… {}s left   ", remaining.as_secs());
            let _ = std::io::stderr().flush();
        }
    };
    match wait_for_programming_mode(service, source, &mut on_event).await? {
        ProgrammingWait::One(addr) => Ok(Some(addr)),
        ProgrammingWait::Several(found) => {
            eprintln!("{} devices are in programming mode:", found.len());
            for addr in &found {
                eprintln!("  {addr}");
            }
            eprintln!(
                "{verb} works on one device at a time — leave programming mode on all but \
                 the one you want, then re-run."
            );
            Ok(None)
        }
        ProgrammingWait::Nothing { waited } => {
            eprintln!();
            eprintln!(
                "no device entered programming mode within {}s.",
                waited.as_secs()
            );
            eprintln!(
                "press the programming button on the new device (its LED usually lights up), \
                 then re-run `bussard {verb}`."
            );
            Ok(None)
        }
    }
}

/// Confirms the assignment on a TTY (y/N), naming the resolved gateway. `--yes`
/// (`yes = true`) skips the prompt. The non-TTY-without-`--yes` case is refused
/// up front in [`run`] (issue #74), so this is only reached on a TTY or with
/// `--yes`.
fn confirm_assignment(
    current: IndividualAddress,
    target: IndividualAddress,
    yes: bool,
    gateway: &str,
) -> anyhow::Result<bool> {
    // `run` already refused the non-interactive shape without --yes; the
    // refusal here is defensive, failing loudly if that invariant ever breaks.
    crate::confirm::confirm(
        yes,
        &format!("assign {current} → {target} via {gateway}?"),
        &format!("assign {current} → {target} via {gateway}"),
    )
}

/// Verifies the write by connecting to `target`
/// ([`bussard_service::assign::verify_assignment_with`]), clearing programming
/// mode as ETS does.
pub(crate) async fn verify_assignment(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    key: &VerifyKey,
) -> anyhow::Result<Verified> {
    verify_assignment_with(service, source, target, true, key).await
}

/// [`verify_assignment`], with the explicit programming-mode clear optional:
/// `adopt` reads back without clearing it (its wizard re-checks the broadcast
/// itself). Prints the warnings the read raised.
pub(crate) async fn verify_assignment_with(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    clear_programming_mode: bool,
    key: &VerifyKey,
) -> anyhow::Result<Verified> {
    let verified = bussard_service::assign::verify_assignment_with(
        service,
        source,
        target,
        clear_programming_mode,
        key,
    )
    .await?;
    for warning in &verified.warnings {
        eprintln!("{warning}");
    }
    Ok(verified)
}

/// Re-runs the programming-mode broadcast once
/// ([`bussard_service::assign::still_in_programming_mode`]) and warns if the
/// just-assigned `target` still answers it. Best-effort and non-fatal.
pub(crate) async fn warn_if_still_in_programming_mode(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) {
    if bussard_service::assign::still_in_programming_mode(service, source, target).await {
        eprintln!();
        for line in bussard_service::assign::still_in_programming_mode_warning(target) {
            eprintln!("{line}");
        }
    }
}

/// Writes the stub device file.
fn write_stub_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
    serial: Option<&[u8]>,
) -> anyhow::Result<std::path::PathBuf> {
    write_device_file(model, dir, device, serial, "stub device file")
}

/// Inserts `device` into the model (or a fresh one) and saves it without
/// pruning ([`bussard_service::assign::write_device_file`]); shared by
/// `assign` and `adopt`.
pub(crate) fn write_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
    serial: Option<&[u8]>,
    what: &str,
) -> anyhow::Result<std::path::PathBuf> {
    Ok(bussard_service::assign::write_device_file(
        model, dir, device, serial, what,
    )?)
}
