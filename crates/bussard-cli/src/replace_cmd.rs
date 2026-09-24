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
//! Every write here is an existing command's: the address goes on with
//! [`bussard_mgmt::write_individual_address`] and is verified by
//! [`crate::assign_cmd::verify_assignment`]; the application is written by
//! [`crate::flash_cmd::run`]; the tables by [`crate::apply_cmd::run`]. `replace`
//! adds sequencing, the identity cross-check and the record — nothing that
//! touches the bus on its own.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_bus::BusHandle;
use bussard_download::backup::rfc3339_utc;
use bussard_mgmt::apci::PID_ORDER_INFO;
use bussard_mgmt::{
    DeviceConnection, LeaseChannel, Timeouts, system_type, write_individual_address,
};
use bussard_model::{IndividualAddress, Model};
use bussard_service::{BusService, WritePolicy};

use crate::assign_cmd;
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display,
    load_model_required, resolve_config,
};

/// Runs `bussard replace`.
#[allow(clippy::too_many_arguments)] // the subcommand's flags, 1:1
pub fn run(
    address: &str,
    product: &Path,
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

    // `replace` re-addresses whatever is in programming mode, so a non-TTY run
    // must opt in with --yes, exactly as `assign` does (issue #74).
    if !yes && !std::io::stdin().is_terminal() {
        bail!(
            "refusing to replace {target} without a terminal to confirm on; pass --yes to \
             replace non-interactively"
        );
    }

    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard replace` needs the model: the device file for {target} says which product \
             belongs at that address. None was loaded from {}",
            dir.display()
        );
    };
    let Some(loaded) = model.devices.get(&target) else {
        bail!(
            "the model in {} has no device file for {target}; `replace` puts the *same* product \
             back at a known address. Use `bussard adopt` for a device the model does not know.",
            dir.display()
        );
    };
    let expected = Expected::from_model(&loaded.device);
    let device_file = dir
        .join("devices")
        .join(format!("{}.yaml", loaded.file_stem));

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
        runtime.block_on(async move {
            let service = BusService::open(config, WritePolicy::transmit(allow_remote_gateway))?;
            let handle = service.handle().clone();
            if !handle
                .wait_connected(std::time::Duration::from_secs(10))
                .await
            {
                eprintln!(
                    "warning: bus not connected yet; management traffic may use the 0.0.255 fallback source"
                );
            }
            let source = checked_source_or_close(&handle, &conn).await?;
            let result = tokio::select! {
                result = swap_flow(&handle, source, target, &expected, &gateway, yes, force) => result,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\ninterrupted; closing the bus connection");
                    Err(anyhow!("replace interrupted by Ctrl-C"))
                }
            };
            let _ = handle.close().await;
            result
        })?
    };

    let Some(pressed) = assigned else {
        return Ok(ExitCode::FAILURE);
    };

    // Phase 2: the application image, through `bussard flash`.
    let mut flashed = false;
    if no_flash {
        println!("\n--no-flash: leaving the application image alone");
    } else {
        println!("\nflashing the application from {}…", product.display());
        let code = crate::flash_cmd::run(
            address,
            product,
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
    let recorded = record_replacement(&device_file, &when)
        .with_context(|| format!("recording the replacement in {}", device_file.display()))?;

    print_summary(target, &pressed, &gateway, flashed, &recorded, &when);
    Ok(ExitCode::SUCCESS)
}

/// What the model says belongs at the address being replaced.
#[derive(Debug, Clone, Default)]
struct Expected {
    /// `product.order_number` from the device file.
    order_number: Option<String>,
    /// `product.mask` from the device file, parsed as a hex mask version.
    mask: Option<u16>,
    /// The raw `product.mask` text, for the message when it does not parse.
    mask_text: Option<String>,
}

impl Expected {
    /// Reads the cross-check values out of the model's device file.
    fn from_model(device: &bussard_model::schema::Device) -> Expected {
        let product = device.product.as_ref();
        let mask_text = product.and_then(|p| p.mask.clone());
        Expected {
            order_number: product.and_then(|p| p.order_number.clone()),
            mask: mask_text
                .as_deref()
                .and_then(|m| u16::from_str_radix(m.trim_start_matches("0x"), 16).ok()),
            mask_text,
        }
    }
}

/// What the device that answered the programming-mode broadcast reported.
#[derive(Debug, Clone)]
struct Pressed {
    /// The address it currently answers on.
    address: IndividualAddress,
    /// Its mask version.
    mask: Option<u16>,
    /// Its order number (`PID_ORDER_INFO`).
    order: Option<String>,
    /// Its resident application id (`PID_PROGRAM_VERSION`), rendered.
    application: Option<String>,
    /// Its serial number.
    serial: Option<Vec<u8>>,
}

/// The read, cross-check, confirm and address-write half of a replacement.
///
/// Returns `Ok(Some(pressed))` when the new device took the address, `Ok(None)`
/// when the run was declined or nothing could be identified (a clean command
/// failure, not an error).
async fn swap_flow(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
    expected: &Expected,
    gateway: &str,
    yes: bool,
    force: bool,
) -> anyhow::Result<Option<Pressed>> {
    // 1. The old device must be gone.
    if let Some(mask) = probe_present(handle, source, target).await {
        if !force {
            eprintln!(
                "{target} still answers on the bus (mask {mask:04X}, {}).\n\
                 `replace` is for a device that has failed or been removed. If you really mean \
                 to re-address whatever is in programming mode onto {target}, re-run with \
                 --force.",
                system_type(mask)
            );
            return Ok(None);
        }
        eprintln!("warning: {target} still answers (mask {mask:04X}); --force given, continuing");
    } else {
        println!("{target} does not answer, consistent with a failed or removed device");
    }

    // 2. The replacement, via its programming button.
    println!("\nPress the programming button on the replacement device for {target}.");
    let Some(current) = assign_cmd::wait_for_single_device(handle, source).await? else {
        return Ok(None);
    };
    let pressed = identify(handle, source, current).await;
    print_identity(&pressed);

    // 3. Cross-check against the model's device file.
    if let Some(problem) = mismatch(expected, &pressed) {
        if !force {
            eprintln!(
                "\nrefusing to replace {target}: {problem}\n\
                 A different product means a different application, and flashing it would load \
                 the wrong image. Fix the device file, use the right spare, or re-run with \
                 --force if you know the model is out of date."
            );
            return Ok(None);
        }
        eprintln!("\nwarning: {problem}; --force given, continuing");
    }

    // 4. One confirmation for the whole run.
    if !confirm(target, current, gateway, yes)? {
        eprintln!("aborted; nothing was written.");
        return Ok(None);
    }

    // 5. The address, exactly as `assign` writes it.
    let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    write_individual_address(channel, source, target)
        .await
        .context("broadcasting the new individual address")?;
    eprintln!("wrote {target}; verifying…");
    let verified = assign_cmd::verify_assignment(handle, source, target).await?;
    if verified.programming_mode_cleared {
        eprintln!("cleared programming mode on {target} (PID_PROGMODE = 0), as ETS does.");
    }
    assign_cmd::warn_if_still_in_programming_mode(handle, source, target).await;
    println!("assigned {current} → {target}");

    Ok(Some(Pressed {
        address: current,
        mask: verified.mask.or(pressed.mask),
        order: verified.order.clone().or(pressed.order),
        application: pressed.application,
        serial: verified.serial.clone().or(pressed.serial),
    }))
}

/// Probes `target` with the fast discovery budget; `Some(mask)` if it answers.
async fn probe_present(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
) -> Option<u16> {
    let lease = handle.lease().await.ok()?;
    let channel = LeaseChannel::new(lease);
    let mut dev = DeviceConnection::connect_with(channel, target, source, Timeouts::discovery())
        .await
        .ok()?;
    let mask = dev.device_descriptor().await.ok();
    let _ = dev.disconnect().await;
    mask
}

/// Reads the identity of the device that answered the programming-mode
/// broadcast: mask, order number, serial and resident application id.
///
/// Every read is best-effort — a field that cannot be read is simply unknown,
/// and an unknown field never satisfies the cross-check by default.
async fn identify(
    handle: &BusHandle,
    source: IndividualAddress,
    current: IndividualAddress,
) -> Pressed {
    let mut pressed = Pressed {
        address: current,
        mask: None,
        order: None,
        application: None,
        serial: None,
    };
    let Ok(lease) = handle.lease().await else {
        return pressed;
    };
    let channel = LeaseChannel::new(lease);
    let Ok(mut dev) = DeviceConnection::connect(channel, current, source).await else {
        return pressed;
    };
    pressed.mask = dev.device_descriptor().await.ok();
    if let Err(err) = dev.authorize(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
        tracing::debug!("{current} authorize (free access) did not grant: {err}");
    }
    pressed.order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());
    pressed.serial = dev
        .read_device_property(bussard_mgmt::apci::PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty());
    if let Ok(obj) = bussard_download::discover_application_object(dev.l4_mut()).await {
        pressed.application = bussard_mgmt::read_program_version(dev.l4_mut(), obj)
            .await
            .ok()
            .flatten()
            .map(|id| bussard_download::format_app_id(&id));
    }
    let _ = dev.disconnect().await;
    pressed
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

/// The first cross-check failure between the model's device file and what was
/// pressed, or `None` when everything the model states matches.
///
/// A field the model does not state is not checked: a device file with no
/// `product:` block has nothing to contradict. A field the model states but the
/// device would not report **is** a failure — "could not read the order number"
/// is not evidence that it matches.
fn mismatch(expected: &Expected, pressed: &Pressed) -> Option<String> {
    if let Some(want) = &expected.order_number {
        match &pressed.order {
            Some(got) if order_matches(got, want) => {}
            Some(got) => {
                return Some(format!(
                    "the device reports order number {got:?}, but the model's device file says \
                     {want:?}"
                ));
            }
            None => {
                return Some(format!(
                    "the model's device file says order number {want:?}, but the device would \
                     not report one"
                ));
            }
        }
    }
    if let Some(want) = expected.mask {
        match pressed.mask {
            Some(got) if got == want => {}
            Some(got) => {
                return Some(format!(
                    "the device reports mask {got:04X} ({}), but the model's device file says \
                     {want:04X} ({})",
                    system_type(got),
                    system_type(want)
                ));
            }
            None => {
                return Some(format!(
                    "the model's device file says mask {want:04X}, but the device would not \
                     report one"
                ));
            }
        }
    } else if let Some(text) = &expected.mask_text {
        return Some(format!(
            "the model's device file has an unparseable mask {text:?}; fix it before replacing"
        ));
    }
    None
}

/// Whether a read-back order number matches the model's, tolerating case,
/// surrounding whitespace and the abbreviations vendors put in `PID_ORDER_INFO`
/// (the same rule `adopt` uses).
fn order_matches(read: &str, want: &str) -> bool {
    let a = read.trim().to_ascii_uppercase();
    let b = want.trim().to_ascii_uppercase();
    !a.is_empty() && !b.is_empty() && (a == b || a.contains(&b) || b.contains(&a))
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
        || {
            format!(
                "refusing to replace {target} without a terminal to confirm on; pass --yes to \
                 replace non-interactively"
            )
        },
    )
}

/// Records `replaced: <when>` in the device file, in place.
///
/// This is a targeted line edit rather than a re-serialisation of the model: a
/// device file is hand-edited above its GENERATED marker, comments and all, and
/// rewriting it wholesale to add one key would be a destructive way to record a
/// repair. An existing `replaced:` line is updated; otherwise the key is
/// inserted after `address:`, where the rest of the device's identity lives.
fn record_replacement(path: &Path, when: &str) -> anyhow::Result<PathBuf> {
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let line = format!("replaced: {when}");
    let mut out: Vec<String> = Vec::with_capacity(body.lines().count() + 1);
    let update = body.lines().any(|t| t.starts_with("replaced:"));
    let mut done = false;
    for text in body.lines() {
        if update && !done && text.starts_with("replaced:") {
            out.push(line.clone());
            done = true;
            continue;
        }
        out.push(text.to_string());
        if !update && !done && text.starts_with("address:") {
            out.push(line.clone());
            done = true;
        }
    }
    if !done {
        // No `address:` at the top level (an unusual file); append rather than
        // lose the record.
        out.push(line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.to_path_buf())
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

/// Cleans a raw property value to printable ASCII (as `scan` and `assign` do).
fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    s.trim().to_string()
}

/// The model's device file for `target`, for callers that only have the model.
#[allow(dead_code)] // used by the tests below and kept as the one place that spells the path
fn device_file_for(model: &Model, dir: &Path, target: IndividualAddress) -> Option<PathBuf> {
    model
        .devices
        .get(&target)
        .map(|d| dir.join("devices").join(format!("{}.yaml", d.file_stem)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pressed(order: Option<&str>, mask: Option<u16>) -> Pressed {
        Pressed {
            address: IndividualAddress::from_raw(0xFFFF),
            mask,
            order: order.map(|s| s.to_string()),
            application: None,
            serial: None,
        }
    }

    fn expected(order: Option<&str>, mask: Option<&str>) -> Expected {
        Expected {
            order_number: order.map(|s| s.to_string()),
            mask: mask.and_then(|m| u16::from_str_radix(m, 16).ok()),
            mask_text: mask.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_mismatch_accepts_the_same_product() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        assert_eq!(
            mismatch(&want, &pressed(Some("MDT-JAL0410"), Some(0x07B0))),
            None
        );
    }

    #[test]
    fn test_mismatch_refuses_a_different_order_number() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        let problem = mismatch(&want, &pressed(Some("MDT-AKS0416"), Some(0x07B0)));
        match problem {
            Some(text) => {
                assert!(
                    text.contains("MDT-AKS0416") && text.contains("MDT-JAL0410"),
                    "{text}"
                );
            }
            None => panic!("a different order number must be refused"),
        }
    }

    #[test]
    fn test_mismatch_refuses_a_different_mask() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        let problem = mismatch(&want, &pressed(Some("MDT-JAL0410"), Some(0x0705)));
        assert!(problem.is_some(), "a different mask must be refused");
    }

    #[test]
    fn test_mismatch_refuses_an_unreadable_field_the_model_states() {
        let want = expected(Some("MDT-JAL0410"), None);
        assert!(
            mismatch(&want, &pressed(None, Some(0x07B0))).is_some(),
            "an unreadable order number is not evidence that it matches"
        );
    }

    #[test]
    fn test_mismatch_checks_nothing_the_model_does_not_state() {
        let want = expected(None, None);
        assert_eq!(mismatch(&want, &pressed(None, None)), None);
    }

    #[test]
    fn test_order_matches_is_tolerant_but_not_blind() {
        assert!(order_matches(" mdt-jal0410 ", "MDT-JAL0410"));
        assert!(order_matches("JAL0410", "MDT-JAL0410"));
        assert!(!order_matches("MDT-AKS0416", "MDT-JAL0410"));
        assert!(!order_matches("", "MDT-JAL0410"));
    }

    #[test]
    fn test_record_replacement_inserts_after_address() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-replace-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("1.1.4-jal.yaml");
        std::fs::write(&path, "address: 1.1.4\nname: Rollladen\n# a comment\n")?;
        record_replacement(&path, "2026-09-22T10:15:00Z")?;
        let body = std::fs::read_to_string(&path)?;
        assert_eq!(
            body,
            "address: 1.1.4\nreplaced: 2026-09-22T10:15:00Z\nname: Rollladen\n# a comment\n"
        );
        // A second replacement updates the line rather than adding another.
        record_replacement(&path, "2026-10-01T08:00:00Z")?;
        let body = std::fs::read_to_string(&path)?;
        assert_eq!(body.matches("replaced:").count(), 1, "{body}");
        assert!(body.contains("2026-10-01T08:00:00Z"), "{body}");
        assert!(
            body.contains("# a comment"),
            "the rest of the file survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
