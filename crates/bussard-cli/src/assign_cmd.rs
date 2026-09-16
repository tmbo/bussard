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
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::{
    DeviceConnection, LeaseChannel, broadcast, manufacturers, system_type, write_individual_address,
};
use bussard_model::schema::{Device, Product};
use bussard_model::{IndividualAddress, LoadedDevice, Model};

use crate::conn_cmd::{ConnOverrides, resolve_config};

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
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    // 1. Load the model. Address allocation needs it; an explicit --address on an
    //    empty/missing model is allowed with a warning.
    let model = load_model_for_assign(dir, address.is_some())?;
    let config = resolve_config(model.as_ref(), &overrides)?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        // Wait for the actor to connect so the tunnel-assigned source address is
        // available (falling back to 0.0.255 on routing) — issue #30.
        handle
            .wait_connected(std::time::Duration::from_secs(10))
            .await;
        let source = ops::group_source(&handle);
        // Guard the assign flow with Ctrl-C: on interrupt, fall through to a
        // clean `handle.close()` so the gateway tunnel slot is released rather
        // than leaked — see issue #31.
        let result = tokio::select! {
            result = assign_flow(&handle, source, address, model.as_ref(), dir) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Err(anyhow!("assign interrupted by Ctrl-C"))
            }
        };
        let _ = handle.close().await;
        result
    })
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
    if !dir.exists() {
        if have_explicit_address {
            eprintln!(
                "warning: model directory {} not found; continuing because an explicit address was given",
                dir.display()
            );
            return Ok(None);
        }
        return Err(anyhow!(
            "model directory {} not found\n\
             assign needs the model to allocate a free address; pass an explicit address \
             (e.g. `bussard assign 1.1.47`) to proceed without one",
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
             refusing to run assign against a model that failed to parse; fix the model files first",
            dir.display()
        )),
    }
}

/// The end-to-end assign flow over the bus actor. Each connectionless broadcast
/// and each connection-oriented verify leases the bus for the duration of that
/// step (releasing it in between), so other bus consumers keep observing.
async fn assign_flow(
    handle: &BusHandle,
    source: IndividualAddress,
    address: Option<&str>,
    model: Option<&Model>,
    dir: &Path,
) -> anyhow::Result<ExitCode> {
    // 2. Find exactly one device in programming mode.
    let current = match wait_for_single_device(handle, source).await? {
        Some(addr) => addr,
        None => return Ok(ExitCode::FAILURE),
    };
    eprintln!("device in programming mode: {current} (its current address)");

    // 3. Decide the target address.
    let explicit = address.is_some();
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

    // 4. Confirm.
    if !confirm_assignment(current, target, explicit)? {
        eprintln!("aborted; no address was written.");
        return Ok(ExitCode::FAILURE);
    }

    // 5. Write, then verify.
    let write_channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    write_individual_address(write_channel, source, target)
        .await
        .context("broadcasting the new individual address")?;
    eprintln!("wrote {target}; verifying…");

    let verified = verify_assignment(handle, source, target).await?;
    if verified.programming_mode_cleared {
        eprintln!("cleared programming mode on {target} (PID_PROGMODE = 0), as ETS does.");
    }

    // 5a. Programming-mode persistence check (fallback). We already cleared
    //     programming mode explicitly above (PID_PROGMODE = 0), exactly as ETS
    //     does. This re-runs the programming-mode broadcast once, briefly, and
    //     warns only if `target` STILL answers it — meaning neither the explicit
    //     clear nor the device's own auto-clear took, so the next assign/adopt
    //     would re-capture and re-address it. On a conformant device this is now a
    //     no-op; the warning remains the backstop for a device that ignored both.
    warn_if_still_in_programming_mode(handle, source, target).await;

    // 6. Create the stub device file.
    let device = build_stub_device(target, &verified);
    let path = write_stub_device_file(model, dir, device)?;

    // 7. Next steps.
    println!("assigned {current} → {target}");
    if let Some(mask) = verified.mask {
        println!("  verified: mask {mask:#06x} ({})", system_type(mask));
    }
    if let Some(serial) = &verified.serial {
        println!("  serial: {}", hex(serial));
    }
    println!("  wrote stub device file: {}", path.display());
    println!();
    println!("next steps:");
    println!("  - edit the name/room in {}", path.display());
    println!("  - `bussard import-product <file.knxprod>` to attach its product data");
    println!("  - wire its group objects in links.yaml");

    Ok(ExitCode::SUCCESS)
}

/// Polls for devices in programming mode, nagging the user to press the button
/// if none appear, until exactly one is found or the budget is exhausted.
///
/// Returns `Ok(Some(addr))` for the single found device, or `Ok(None)` after
/// printing friendly guidance for the zero-found (timeout) and multiple-found
/// cases — both of which are a clean command failure, not an error.
async fn wait_for_single_device(
    handle: &BusHandle,
    source: IndividualAddress,
) -> anyhow::Result<Option<IndividualAddress>> {
    let (initial, total) = wait_budgets();
    let start = tokio::time::Instant::now();
    let mut nagged = false;

    let window = collection_window();
    loop {
        // Lease a fresh channel for this broadcast read (released each poll).
        let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
        let found = broadcast::devices_in_programming_mode_within(channel, source, window).await?;
        match found.len() {
            1 => return Ok(Some(found[0])),
            n if n > 1 => {
                eprintln!("{n} devices are in programming mode:");
                for addr in &found {
                    eprintln!("  {addr}");
                }
                eprintln!(
                    "assign works on one device at a time — leave programming mode on all but \
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
                 then re-run `bussard assign`."
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
fn validate_explicit_address(s: &str, model: Option<&Model>) -> anyhow::Result<IndividualAddress> {
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
fn allocate_address(model: Option<&Model>) -> Option<IndividualAddress> {
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

/// Confirms the assignment on a TTY (y/N). On a non-TTY, an implicit allocation
/// is refused for safety (a wrong write re-addresses a device); an explicit
/// address is accepted without prompting.
fn confirm_assignment(
    current: IndividualAddress,
    target: IndividualAddress,
    explicit: bool,
) -> anyhow::Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        if explicit {
            eprintln!("non-interactive: assigning {current} → {target} (address was explicit).");
            return Ok(true);
        }
        bail!(
            "refusing to assign an automatically-chosen address ({target}) without a terminal to \
             confirm on; pass the address explicitly (e.g. `bussard assign {target}`) to proceed \
             non-interactively"
        );
    }

    eprint!("assign {current} → {target}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// What the post-write verification read back from the device.
#[derive(Default)]
struct Verified {
    mask: Option<u16>,
    manufacturer_id: Option<u16>,
    serial: Option<Vec<u8>>,
    order: Option<String>,
    /// Whether the explicit `PID_PROGMODE = 0` write to clear programming mode was
    /// confirmed by the device (it echoed the stored `0x00`). `false` when the
    /// write was not confirmed or the device refused it — the broadcast-based
    /// persistence check then remains the fallback.
    programming_mode_cleared: bool,
}

/// Verifies the write by connecting to `target` and reading its descriptor plus
/// best-effort manufacturer/serial/order properties.
///
/// A device descriptor read is the proof the address took: if it fails, the
/// write did not land (or the device dropped programming mode without applying
/// it), which is a clear error naming both the old and new addresses.
async fn verify_assignment(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
) -> anyhow::Result<Verified> {
    let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    let mut dev = DeviceConnection::connect(channel, target, source)
        .await
        .map_err(|err| {
            anyhow!(
                "wrote {target} but could not connect to it afterwards ({err}); the address may \
                 not have been applied — check the device and re-run"
            )
        })?;

    let mask = dev.device_descriptor().await.map_err(|err| {
        if matches!(err, bussard_mgmt::MgmtError::Disconnected { .. }) {
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
    let programming_mode_cleared = match dev.clear_programming_mode().await {
        Ok(cleared) => cleared,
        Err(err) => {
            tracing::debug!("{target} clear programming mode (PID_PROGMODE=0) failed: {err}");
            false
        }
    };

    let _ = dev.disconnect().await;
    Ok(Verified {
        mask: Some(mask),
        manufacturer_id,
        serial,
        order,
        programming_mode_cleared,
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
async fn warn_if_still_in_programming_mode(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
) {
    // A short window: the device answers instantly if at all, and we do not want
    // to stall the command tail. Honour the same test override the wait loop uses.
    let window = collection_window();
    let Ok(lease) = handle.lease().await else {
        return;
    };
    let channel = LeaseChannel::new(lease);
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
fn build_stub_device(address: IndividualAddress, v: &Verified) -> Device {
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
        product,
        channels: Default::default(),
        parameters: Default::default(),
        module_bases: Default::default(),
        com_objects: Default::default(),
    }
}

/// Writes the stub device file.
///
/// When a model is loaded we insert the device and `Model::save` (plain, not
/// pruning — `save` preserves an existing `bussard.yaml` byte-for-byte and does
/// not delete other files). When there is no model, we save a minimal one
/// containing just this device so the file lands in `devices/`. Returns the path
/// of the device file that was written.
fn write_stub_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
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
        .with_context(|| format!("saving the stub device file to {}", dir.display()))?;

    Ok(dir.join("devices").join(format!("{file_stem}.yaml")))
}

/// The `<address>-<slug>` file stem used for a device file, matching the
/// importer's naming convention (`1.1.47-new-device`).
fn device_file_stem(device: &Device) -> String {
    format!("{}-{}", device.address, slugify(&device.name))
}

/// A minimal lower-kebab slug for filenames.
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// An empty model with default config (used when assigning into a directory that
/// has no model yet, given an explicit address).
fn empty_model() -> Model {
    Model {
        config: Default::default(),
        groups: Default::default(),
        links: Default::default(),
        devices: Default::default(),
    }
}

/// Formats a byte slice as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cleans a raw property value to printable ASCII, trimming trailing NULs/space.
fn clean_ascii(bytes: &[u8]) -> String {
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
            let addr: IndividualAddress = s.parse().unwrap();
            model.devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: "d".to_string(),
                        description: None,
                        location: None,
                        product: None,
                        channels: Default::default(),
                        parameters: Default::default(),
                        module_bases: Default::default(),
                        com_objects: Default::default(),
                    },
                    file_stem: format!("{addr}-d"),
                },
            );
        }
        model
    }

    #[test]
    fn allocate_picks_lowest_free_on_dominant_line() {
        let model = model_with(&["1.1.1", "1.1.2", "1.1.4"]);
        // Lowest free ≥ 1 on 1.1 is 3.
        assert_eq!(
            allocate_address(Some(&model)),
            Some("1.1.3".parse().unwrap())
        );
    }

    #[test]
    fn allocate_starts_at_one_not_zero() {
        let model = model_with(&["1.1.5"]);
        assert_eq!(
            allocate_address(Some(&model)),
            Some("1.1.1".parse().unwrap())
        );
    }

    #[test]
    fn dominant_line_is_the_busiest() {
        // 2.4 has two devices, 1.1 has one → dominant is 2.4.
        let model = model_with(&["1.1.1", "2.4.1", "2.4.9"]);
        assert_eq!(dominant_line(&model), Some((2, 4)));
        assert_eq!(
            allocate_address(Some(&model)),
            Some("2.4.2".parse().unwrap())
        );
    }

    #[test]
    fn dominant_line_ties_pick_lowest() {
        let model = model_with(&["1.1.1", "2.2.1"]);
        assert_eq!(dominant_line(&model), Some((1, 1)));
    }

    #[test]
    fn empty_model_falls_back_to_one_one() {
        let model = empty_model();
        assert_eq!(dominant_line(&model), None);
        assert_eq!(
            allocate_address(Some(&model)),
            Some("1.1.1".parse().unwrap())
        );
    }

    #[test]
    fn no_model_cannot_allocate() {
        assert_eq!(allocate_address(None), None);
    }

    #[test]
    fn allocate_on_line_skips_used() {
        let used: BTreeSet<u8> = [1, 2, 3, 5].into_iter().collect();
        assert_eq!(
            allocate_on_line(1, 1, &used),
            Some("1.1.4".parse().unwrap())
        );
    }

    #[test]
    fn allocate_on_line_full_is_none() {
        let used: BTreeSet<u8> = (1u8..=255).collect();
        assert_eq!(allocate_on_line(1, 1, &used), None);
    }

    #[test]
    fn explicit_address_rejects_already_used() {
        let model = model_with(&["1.1.1"]);
        let err = validate_explicit_address("1.1.1", Some(&model)).unwrap_err();
        assert!(err.to_string().contains("already used"), "got {err}");
    }

    #[test]
    fn explicit_address_rejects_unmodeled_line() {
        let model = model_with(&["1.1.1"]);
        let err = validate_explicit_address("2.2.5", Some(&model)).unwrap_err();
        assert!(err.to_string().contains("does not use"), "got {err}");
    }

    #[test]
    fn explicit_address_accepts_free_on_known_line() {
        let model = model_with(&["1.1.1"]);
        assert_eq!(
            validate_explicit_address("1.1.9", Some(&model)).unwrap(),
            "1.1.9".parse().unwrap()
        );
    }

    #[test]
    fn explicit_address_without_model_just_parses() {
        assert_eq!(
            validate_explicit_address("3.4.5", None).unwrap(),
            "3.4.5".parse().unwrap()
        );
        assert!(validate_explicit_address("not-an-address", None).is_err());
    }

    #[test]
    fn slugify_makes_kebab() {
        assert_eq!(slugify("New device (assign)"), "new-device-assign");
        assert_eq!(slugify("  spaced  "), "spaced");
    }

    #[test]
    fn stub_device_omits_empty_product() {
        let dev = build_stub_device("1.1.7".parse().unwrap(), &Verified::default());
        assert!(dev.product.is_none());
        assert_eq!(dev.name, "New device (assign)");
    }

    #[test]
    fn stub_device_carries_readable_product() {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("MDT-JAL0410".to_string()),
            ..Default::default()
        };
        let dev = build_stub_device("1.1.7".parse().unwrap(), &v);
        let product = dev.product.unwrap();
        assert_eq!(product.manufacturer.as_deref(), Some("MDT"));
        assert_eq!(product.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(product.mask.as_deref(), Some("0x07B0"));
    }
}
