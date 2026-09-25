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

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::{broadcast, manufacturers, system_type, write_individual_address};
use bussard_model::schema::{Device, Product};
use bussard_model::{IndividualAddress, LoadedDevice, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::identity::{HIDDEN_MASK, SecureStatus};
use bussard_service::secure::ToolKeys;
use bussard_service::{
    Authorize, BusService, Device as ServiceDevice, L4Options, ServiceError, SourcePolicy,
    WritePolicy,
};

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display, resolve_config,
};

/// The line to allocate on when the model has no devices to infer one from.
const FALLBACK_LINE: (u8, u8) = (1, 1);

/// Total time to wait for a device to enter programming mode before giving up.
const PROGRAMMING_WAIT_TOTAL: Duration = Duration::from_secs(30);

/// The initial polling budget before we start nagging the user to press the
/// programming button.
const INITIAL_POLL_TOTAL: Duration = Duration::from_secs(3);

/// Environment variable that shortens the programming-mode wait windows. Set by
/// the integration tests so both the outer poll budgets (initial-nag / total)
/// and the per-poll response-collection window shrink together; unset in normal
/// use so the full [`PROGRAMMING_WAIT_TOTAL`] and default collection window
/// apply. Behaviour is unchanged without the variable.
const WAIT_MS_ENV: &str = "BUSSARD_ASSIGN_WAIT_MS";

/// Runs `bussard assign`.
pub fn run(
    address: Option<&str>,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    json: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
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
            .wait_connected(std::time::Duration::from_secs(10))
            .await;
        let source = checked_source_or_close(&service, &overrides).await?;
        // Guard the assign flow with Ctrl-C: on interrupt, fall through to a
        // clean `service.close()` so the gateway tunnel slot is released rather
        // than leaked — see issue #31.
        let result = tokio::select! {
            result = assign_flow(&service, source, address, AssignRun { yes, json, gateway: &gateway }, model.as_ref(), dir, &keys) => result,
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
    if !dir.exists() {
        if have_explicit_address {
            eprintln!(
                "warning: model directory {} not found; continuing because an explicit address was given",
                dir.display()
            );
            return Ok(None);
        }
        return Err(anyhow!(
            "no model in {}: {command} picks a free address from the devices the model \
             lists; {missing_hint}",
            dir.display()
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
    let AssignRun { yes, json, gateway } = run;
    // 2. Find exactly one device in programming mode.
    let current = match wait_for_single_device(service, source).await? {
        Some(addr) => addr,
        None => return Ok(ExitCode::FAILURE),
    };
    eprintln!("device in programming mode: {current} (its current address)");

    // 3. Decide the target address.
    let target = match address {
        Some(s) => validate_explicit_address(s, model)?,
        None => match allocate_address(model) {
            Some(addr) => addr,
            None => bail!(
                "could not allocate a free address automatically; pass one explicitly, \
                 e.g. `bussard assign 1.1.47`"
            ),
        },
    };

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
    let write_channel = service.lease_channel().await?;
    write_individual_address(write_channel, source, target)
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

    // 6. Create the stub device file.
    let device = build_stub_device(target, &verified);
    let path = write_stub_device_file(model, dir, device)?;

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
/// guidance it prints.
pub(crate) async fn wait_for_single_device_as(
    service: &BusService,
    source: IndividualAddress,
    verb: &str,
) -> anyhow::Result<Option<IndividualAddress>> {
    let (initial, total) = wait_budgets();
    let start = tokio::time::Instant::now();
    let mut nagged = false;

    let window = collection_window();
    loop {
        // Lease a fresh channel for this broadcast read (released each poll).
        let channel = service.lease_channel().await?;
        let found = broadcast::devices_in_programming_mode_within(channel, source, window).await?;
        match found.len() {
            1 => return Ok(Some(found[0])),
            n if n > 1 => {
                eprintln!("{n} devices are in programming mode:");
                for addr in &found {
                    eprintln!("  {addr}");
                }
                eprintln!(
                    "{verb} works on one device at a time — leave programming mode on all but \
                     the one you want, then re-run."
                );
                return Ok(None);
            }
            _ => {}
        }

        let elapsed = start.elapsed();
        if elapsed >= total {
            eprintln!();
            eprintln!(
                "no device entered programming mode within {}s.",
                total.as_secs()
            );
            eprintln!(
                "press the programming button on the new device (its LED usually lights up), \
                 then re-run `bussard {verb}`."
            );
            return Ok(None);
        }

        if elapsed >= initial && !nagged {
            eprintln!(
                "no device in programming mode yet — press the programming button on the device, \
                 then keep waiting (or re-run)."
            );
            nagged = true;
        }

        if nagged {
            let remaining = total.saturating_sub(elapsed).as_secs();
            eprint!("\rwaiting for a device… {remaining}s left   ");
            let _ = std::io::stderr().flush();
        }
    }
}

/// Reads [`WAIT_MS_ENV`] as a millisecond budget, if set and parseable.
fn wait_ms_override() -> Option<Duration> {
    std::env::var(WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// The (initial-nag, total) wait budgets, honouring [`WAIT_MS_ENV`] for tests.
/// With the override set, the initial-nag budget scales to half the total so
/// [`INITIAL_POLL_TOTAL`] is gated under the same variable as the total.
fn wait_budgets() -> (Duration, Duration) {
    match wait_ms_override() {
        Some(total) => (total / 2, total),
        None => (INITIAL_POLL_TOTAL, PROGRAMMING_WAIT_TOTAL),
    }
}

/// The per-poll response-collection window, honouring [`WAIT_MS_ENV`] for tests.
/// Without the override the mgmt default ([`PROGRAMMING_MODE_WINDOW`]) applies,
/// so behaviour is unchanged in normal use.
fn collection_window() -> Duration {
    wait_ms_override().unwrap_or(bussard_mgmt::broadcast::PROGRAMMING_MODE_WINDOW)
}

/// Validates an explicit `--address`/positional argument against the model.
///
/// Checks: it parses as an individual address; it is not already used by a model
/// device; and — when a model is present — it sits on a line the model already
/// uses (a soft consistency check surfaced as a hard error, since assigning onto
/// an unmodeled line is almost always a typo).
pub(crate) fn validate_explicit_address(
    s: &str,
    model: Option<&Model>,
) -> anyhow::Result<IndividualAddress> {
    let addr: IndividualAddress = s.parse().with_context(|| {
        format!("invalid address {s:?}; expected area.line.device like \"1.1.47\"")
    })?;

    if let Some(model) = model {
        if model.devices.contains_key(&addr) {
            let name = model
                .devices
                .get(&addr)
                .map(|d| d.device.name.as_str())
                .unwrap_or("");
            bail!("address {addr} is already used in the model (\"{name}\"); pick a free one");
        }
        let lines = model_lines(model);
        if !lines.is_empty() && !lines.contains(&(addr.area(), addr.line())) {
            let known: Vec<String> = lines.iter().map(|(a, l)| format!("{a}.{l}")).collect();
            bail!(
                "address {addr} is on line {}.{}, which the model does not use (known lines: {}); \
                 double-check the address",
                addr.area(),
                addr.line(),
                known.join(", ")
            );
        }
    }
    Ok(addr)
}

/// Allocates the lowest free device number on the model's dominant line.
///
/// Returns `None` only when there is no model at all (the caller then requires
/// an explicit address). See [`allocate_on_line`] for the number-picking rule.
pub(crate) fn allocate_address(model: Option<&Model>) -> Option<IndividualAddress> {
    let model = model?;
    let (area, line) = dominant_line(model).unwrap_or(FALLBACK_LINE);
    let used = used_devices_on_line(model, area, line);
    allocate_on_line(area, line, &used)
}

/// Picks the lowest unused device number ≥ 1 on `area.line`, given the set of
/// already-used numbers. Device 0 is the line/coupler address, so allocation
/// starts at 1. Returns `None` if the line is somehow full (all of 1..=255 used).
fn allocate_on_line(area: u8, line: u8, used: &BTreeSet<u8>) -> Option<IndividualAddress> {
    (1u8..=255)
        .find(|d| !used.contains(d))
        .and_then(|d| IndividualAddress::new(area, line, d).ok())
}

/// The device numbers already spoken for on `area.line`: every model device on
/// that line.
fn used_devices_on_line(model: &Model, area: u8, line: u8) -> BTreeSet<u8> {
    model
        .devices
        .keys()
        .filter(|ia| ia.area() == area && ia.line() == line)
        .map(|ia| ia.device())
        .collect()
}

/// The model's dominant line: the `(area, line)` with the most devices, ties
/// broken by the lowest `(area, line)`. `None` when the model has no devices.
fn dominant_line(model: &Model) -> Option<(u8, u8)> {
    let mut counts: std::collections::BTreeMap<(u8, u8), usize> = std::collections::BTreeMap::new();
    for ia in model.devices.keys() {
        *counts.entry((ia.area(), ia.line())).or_default() += 1;
    }
    // `max_by_key` keeps the LAST maximal element, so break count ties by
    // preferring the lowest (area, line) explicitly.
    counts
        .into_iter()
        .max_by_key(|&(line, count)| (count, std::cmp::Reverse(line)))
        .map(|(line, _)| line)
}

/// The set of distinct `(area, line)` pairs the model uses.
fn model_lines(model: &Model) -> BTreeSet<(u8, u8)> {
    model
        .devices
        .keys()
        .map(|ia| (ia.area(), ia.line()))
        .collect()
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

/// What the post-write verification read back from the device.
#[derive(Default)]
pub(crate) struct Verified {
    /// The mask version read back from the device.
    pub(crate) mask: Option<u16>,
    /// The KNX manufacturer id, when readable.
    pub(crate) manufacturer_id: Option<u16>,
    /// The device serial number, when readable.
    pub(crate) serial: Option<Vec<u8>>,
    /// The device's order info string, when readable.
    pub(crate) order: Option<String>,
    /// Whether the explicit `PID_PROGMODE = 0` write to clear programming mode was
    /// confirmed by the device (it echoed the stored `0x00`). `false` when the
    /// write was not confirmed or the device refused it — the broadcast-based
    /// persistence check then remains the fallback.
    pub(crate) programming_mode_cleared: bool,
    /// How the device was verified with respect to KNX Data Secure
    /// (issue #203). With [`SecureStatus::ActivatedNoKey`] the mask is `None`:
    /// the plain read only returned the hidden `FFFF`.
    pub(crate) secure: SecureStatus,
}

/// The tool key for the post-write verification of a Data Secure-activated
/// device (issue #203).
#[derive(Debug, Clone, Default)]
pub(crate) struct VerifyKey {
    /// The tool key, or `None` to verify in the clear.
    pub(crate) tool_key: Option<Key16>,
    /// The key came from the keyring entry of the OLD address: the keyring must
    /// be re-exported after the address change.
    pub(crate) from_old_address: bool,
}

impl VerifyKey {
    /// Picks the key for a device moving from `current` to `target`: a raw
    /// `--tool-key` wins; else the keyring entry of `target`; else the entry of
    /// `current` (flagged, since the keyring is then stale); else none.
    pub(crate) fn resolve(
        keys: &ToolKeys,
        current: IndividualAddress,
        target: IndividualAddress,
    ) -> VerifyKey {
        if keys.raw_given() || keys.lists(target) {
            return VerifyKey {
                tool_key: keys.tool_key(target),
                from_old_address: false,
            };
        }
        if keys.lists(current) {
            return VerifyKey {
                tool_key: keys.tool_key(current),
                from_old_address: true,
            };
        }
        VerifyKey::default()
    }
}

/// Verifies the write by connecting to `target` and reading its descriptor plus
/// best-effort manufacturer/serial/order properties.
///
/// A device descriptor read is the proof the address took: if it fails, the
/// write did not land (or the device dropped programming mode without applying
/// it), which is a clear error naming both the old and new addresses. With a
/// tool key every read rides A_SecureData; without one, a Data
/// Secure-activated device answers mask `FFFF`, which verifies the address
/// but not the mask (issue #203).
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
/// itself), so it passes `false` and gets `programming_mode_cleared: false`.
pub(crate) async fn verify_assignment_with(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    clear_programming_mode: bool,
    key: &VerifyKey,
) -> anyhow::Result<Verified> {
    let result = verify_session(service, source, target, clear_programming_mode, key).await;
    let Err(secured_err) = result else {
        return result;
    };
    if key.tool_key.is_none() || secured_err.downcast_ref::<ServiceError>().is_some() {
        return Err(secured_err);
    }
    // The keyring listed the device but the secured read failed: a keyring
    // entry for a device that is not activated (any more) answers in the
    // clear. Accept a plain read with a real mask, and say so; otherwise the
    // secured failure stands.
    match verify_session(
        service,
        source,
        target,
        clear_programming_mode,
        &VerifyKey::default(),
    )
    .await
    {
        Ok(verified) if verified.secure == SecureStatus::Plain => {
            eprintln!(
                "warning: {target} did not answer the secured read with its keyring tool key but \
                 answers in the clear: it is not Data Secure-activated, or the keyring is stale"
            );
            Ok(verified)
        }
        _ => Err(secured_err),
    }
}

/// One verification session, secured when `key` carries a tool key.
async fn verify_session(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    clear_programming_mode: bool,
    key: &VerifyKey,
) -> anyhow::Result<Verified> {
    // Authorize comes after the descriptor read here (see below), so the
    // session opens without it.
    let secured = key.tool_key.is_some();
    let options = L4Options {
        source: SourcePolicy::Known(source),
        authorize: Authorize::Skip,
        tool_key: key.tool_key.clone(),
        high_water: SequenceHighWater::new(),
        ..L4Options::default()
    };
    let session = service
        .with_device(target, &options, async |dev| {
            Ok::<_, ServiceError>(read_back(dev, target, clear_programming_mode, secured).await)
        })
        .await;
    match session {
        Ok(verified) => verified,
        Err(err @ ServiceError::Lease(_)) => Err(err.into()),
        Err(err) => Err(anyhow!(
            "wrote {target} but could not connect to it afterwards ({err}); the address may \
             not have been applied — check the device and re-run"
        )),
    }
}

/// The read-back half of [`verify_assignment_with`], on the open session.
/// `secured` says the session rides A_SecureData.
async fn read_back(
    dev: &mut ServiceDevice,
    target: IndividualAddress,
    clear_programming_mode: bool,
    secured: bool,
) -> anyhow::Result<Verified> {
    let mask = dev.device_descriptor().await.map_err(|err| {
        if secured {
            anyhow!(
                "wrote {target} and connected, but the device did not answer the SECURED \
                 descriptor read ({err}): either the tool key is not this device's, or the \
                 device is not Data Secure-activated (retry without --keyring/--tool-key); the \
                 assignment is unverified"
            )
        } else if matches!(err, bussard_mgmt::MgmtError::Disconnected { .. }) {
            anyhow!(
                "wrote {target} and connected, but the device disconnected on the first read: \
                 typical for devices whose management is gated on a loaded application or a \
                 different medium profile (e.g. KNX Virtual IP-medium `*.ip` devices, which \
                 disconnect on descriptor reads while their `*.tp` siblings answer). The address \
                 was written but could not be verified."
            )
        } else {
            anyhow!(
                "wrote {target} and connected, but the device did not answer a descriptor read \
                 ({err}); the assignment is unverified"
            )
        }
    })?;

    // A Data Secure-activated device read in the clear (issue #203): it
    // answered at the new address, which verifies the write, but it hides its
    // mask and drops every further plain read.
    if !secured && mask == HIDDEN_MASK {
        return Ok(Verified {
            secure: SecureStatus::ActivatedNoKey,
            ..Verified::default()
        });
    }
    // Authorize the session (free access), as ETS does after the descriptor read
    // (issue #52 finding #1). Best-effort here — the assignment was already
    // verified by the descriptor read; the property reads below are informational.
    if let Err(err) = dev.authorize(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
        tracing::debug!("{target} authorize (free access) did not grant: {err}");
    }

    // Best-effort property reads: any failure just leaves the field empty.
    let manufacturer_id = match dev.read_device_property(PID_MANUFACTURER_ID).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    };
    let serial = dev
        .read_device_property(PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty());
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());

    // Explicitly clear programming mode, exactly as ETS does after assigning an
    // address: write PID_PROGMODE = 0 on the device object over this same
    // authorized connection. A conformant device also clears it on its own, but
    // ETS does not rely on that, and neither do we. Best-effort: an unconfirmed or
    // refused write is not fatal — the broadcast persistence check below remains
    // the fallback that warns if the device is still in programming mode.
    let programming_mode_cleared = if !clear_programming_mode {
        false
    } else {
        match dev.clear_programming_mode().await {
            Ok(cleared) => cleared,
            Err(err) => {
                tracing::debug!("{target} clear programming mode (PID_PROGMODE=0) failed: {err}");
                false
            }
        }
    };

    Ok(Verified {
        mask: Some(mask),
        manufacturer_id,
        serial,
        order,
        programming_mode_cleared,
        secure: if secured {
            SecureStatus::Activated
        } else {
            SecureStatus::Plain
        },
    })
}

/// Re-runs the programming-mode broadcast once, briefly, after a successful
/// write+verify and warns if the just-assigned `target` still answers it.
///
/// A device that applied `A_IndividualAddress_Write` normally leaves programming
/// mode; if it still answers, the next `assign`/`adopt` would re-capture and
/// re-address it. On KNX Virtual this is expected (the emulation does not clear
/// programming mode) and the fix is to toggle it off in the GUI; on real hardware
/// it usually means a stuck programming button.
///
/// Best-effort and non-fatal: any bus error while re-checking is swallowed (the
/// assignment already succeeded), so this never turns a good write into a
/// failure.
pub(crate) async fn warn_if_still_in_programming_mode(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) {
    // A short window: the device answers instantly if at all, and we do not want
    // to stall the command tail. Honour the same test override the wait loop uses.
    let window = collection_window();
    let Ok(channel) = service.lease_channel().await else {
        return;
    };
    let found = match broadcast::devices_in_programming_mode_within(channel, source, window).await {
        Ok(found) => found,
        Err(_) => return,
    };
    if found.contains(&target) {
        eprintln!();
        eprintln!(
            "warning: {target} is still in programming mode after the assignment. A conformant \
             device leaves programming mode when it takes its new address; this one did not, so \
             the next `assign`/`adopt` would re-capture and re-address it."
        );
        eprintln!(
            "  - on KNX Virtual: toggle programming mode off for this device in the GUI.\n  \
             - on real hardware: this usually means a stuck programming button — release it."
        );
    }
}

/// Builds the stub [`Device`] from the verified read-back. Fields that could not
/// be read are left empty; the whole product block is omitted when nothing was
/// readable.
pub(crate) fn build_stub_device(address: IndividualAddress, v: &Verified) -> Device {
    let manufacturer = v.manufacturer_id.map(manufacturers::display);
    let order_number = v.order.clone();
    let mask = v.mask.map(|m| format!("{m:#06X}"));

    let product = if manufacturer.is_some() || order_number.is_some() || mask.is_some() {
        Some(Product {
            manufacturer,
            manufacturer_ref: None,
            order_number,
            hardware_ref: None,
            application_ref: None,
            mask,
        })
    } else {
        None
    };

    Device {
        address,
        name: "New device (assign)".to_string(),
        description: None,
        location: None,
        replaced: None,
        product,
        channels: Default::default(),
        parameters: Default::default(),
        module_bases: Default::default(),
        com_objects: Default::default(),
        // KNX Secure state comes only from the knxproj importer (issue #71).
        security: None,
        application_override: None,
        lock: Default::default(),
    }
}

/// Writes the stub device file.
///
/// When a model is loaded we insert the device and `Model::save` (plain, not
/// pruning — `save` preserves an existing `bussard.toml` byte-for-byte and does
/// not delete other files). When there is no model, we save a minimal one
/// containing just this device so the file lands in `devices/`. Returns the path
/// of the device file that was written.
fn write_stub_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
) -> anyhow::Result<std::path::PathBuf> {
    write_device_file(model, dir, device, "stub device file")
}

/// Inserts `device` into the model (or a fresh one) and saves it without
/// pruning; shared by `assign` and `adopt`. `what` names the file in the error
/// context. Returns the path of the device file that was written.
pub(crate) fn write_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
    what: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let address = device.address;
    let file_stem = device_file_stem(&device);

    let mut model = model.cloned().unwrap_or_else(empty_model);
    model.devices.insert(
        address,
        LoadedDevice {
            device,
            file_stem: file_stem.clone(),
        },
    );
    model
        .save(dir)
        .with_context(|| format!("saving the {what} to {}", dir.display()))?;

    Ok(dir.join("devices").join(format!("{file_stem}.toml")))
}

/// The file stem of a device file: its individual address
/// (`devices/1.1.47.toml`).
pub(crate) fn device_file_stem(device: &Device) -> String {
    device.address.to_string()
}

/// An empty model with default config (used when assigning into a directory that
/// has no model yet, given an explicit address).
pub(crate) fn empty_model() -> Model {
    Model {
        config: Default::default(),
        groups: Default::default(),
        links: Default::default(),
        devices: Default::default(),
    }
}

/// Formats a byte slice as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cleans a raw property value to printable ASCII, trimming trailing NULs/space.
pub(crate) fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_with(addrs: &[&str]) -> Model {
        let mut model = empty_model();
        for s in addrs {
            let addr: IndividualAddress = s.parse().expect("test fixture");
            model.devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: "d".to_string(),
                        description: None,
                        location: None,
                        replaced: None,
                        product: None,
                        channels: Default::default(),
                        parameters: Default::default(),
                        module_bases: Default::default(),
                        com_objects: Default::default(),
                        security: None,
                        application_override: None,
                        lock: Default::default(),
                    },
                    file_stem: addr.to_string(),
                },
            );
        }
        model
    }

    #[test]
    fn allocate_picks_lowest_free_on_dominant_line() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.1", "1.1.2", "1.1.4"]);
        // Lowest free ≥ 1 on 1.1 is 3.
        assert_eq!(allocate_address(Some(&model)), Some("1.1.3".parse()?));
        Ok(())
    }

    #[test]
    fn allocate_starts_at_one_not_zero() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.5"]);
        assert_eq!(allocate_address(Some(&model)), Some("1.1.1".parse()?));
        Ok(())
    }

    #[test]
    fn dominant_line_is_the_busiest() -> Result<(), Box<dyn std::error::Error>> {
        // 2.4 has two devices, 1.1 has one → dominant is 2.4.
        let model = model_with(&["1.1.1", "2.4.1", "2.4.9"]);
        assert_eq!(dominant_line(&model), Some((2, 4)));
        assert_eq!(allocate_address(Some(&model)), Some("2.4.2".parse()?));
        Ok(())
    }

    #[test]
    fn dominant_line_ties_pick_lowest() {
        let model = model_with(&["1.1.1", "2.2.1"]);
        assert_eq!(dominant_line(&model), Some((1, 1)));
    }

    #[test]
    fn empty_model_falls_back_to_one_one() -> Result<(), Box<dyn std::error::Error>> {
        let model = empty_model();
        assert_eq!(dominant_line(&model), None);
        assert_eq!(allocate_address(Some(&model)), Some("1.1.1".parse()?));
        Ok(())
    }

    #[test]
    fn no_model_cannot_allocate() {
        assert_eq!(allocate_address(None), None);
    }

    #[test]
    fn allocate_on_line_skips_used() -> Result<(), Box<dyn std::error::Error>> {
        let used: BTreeSet<u8> = [1, 2, 3, 5].into_iter().collect();
        assert_eq!(allocate_on_line(1, 1, &used), Some("1.1.4".parse()?));
        Ok(())
    }

    #[test]
    fn allocate_on_line_full_is_none() {
        let used: BTreeSet<u8> = (1u8..=255).collect();
        assert_eq!(allocate_on_line(1, 1, &used), None);
    }

    #[test]
    fn explicit_address_rejects_already_used() {
        let model = model_with(&["1.1.1"]);
        let err = validate_explicit_address("1.1.1", Some(&model)).expect_err("expected an error");
        assert!(err.to_string().contains("already used"), "got {err}");
    }

    #[test]
    fn explicit_address_rejects_unmodeled_line() {
        let model = model_with(&["1.1.1"]);
        let err = validate_explicit_address("2.2.5", Some(&model)).expect_err("expected an error");
        assert!(err.to_string().contains("does not use"), "got {err}");
    }

    #[test]
    fn explicit_address_accepts_free_on_known_line() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.1"]);
        assert_eq!(
            validate_explicit_address("1.1.9", Some(&model))?,
            "1.1.9".parse()?
        );
        Ok(())
    }

    #[test]
    fn explicit_address_without_model_just_parses() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(validate_explicit_address("3.4.5", None)?, "3.4.5".parse()?);
        assert!(validate_explicit_address("not-an-address", None).is_err());
        Ok(())
    }

    #[test]
    fn device_file_stem_is_the_address() -> Result<(), Box<dyn std::error::Error>> {
        let dev = build_stub_device("1.1.7".parse()?, &Verified::default());
        assert_eq!(device_file_stem(&dev), "1.1.7");
        Ok(())
    }

    #[test]
    fn stub_device_omits_empty_product() -> Result<(), Box<dyn std::error::Error>> {
        let dev = build_stub_device("1.1.7".parse()?, &Verified::default());
        assert!(dev.product.is_none());
        assert_eq!(dev.name, "New device (assign)");
        Ok(())
    }

    #[test]
    fn stub_device_carries_readable_product() -> Result<(), Box<dyn std::error::Error>> {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("MDT-JAL0410".to_string()),
            ..Default::default()
        };
        let dev = build_stub_device("1.1.7".parse()?, &v);
        let product = dev.product.ok_or("expected a value")?;
        assert_eq!(product.manufacturer.as_deref(), Some("MDT"));
        assert_eq!(product.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(product.mask.as_deref(), Some("0x07B0"));
        Ok(())
    }
}
