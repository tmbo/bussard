//! The `bussard commission` subcommand — bench mode for a whole line
//! (issue #100).
//!
//! The commissioning-day ritual, once per device: press the programming button,
//! check that the device on the bench really is the product the model expects at
//! that address, write the address, optionally flash and apply, then stick a
//! label on it. `assign` does one device and knows nothing about the model's
//! intent; `commission` walks the model's devices on a line and drives the whole
//! ceremony.
//!
//! The order-number check is the point of the command. A bench full of
//! identical-looking DIN modules is exactly where the wrong device gets pressed,
//! and an address written to the wrong product is only discovered much later. So
//! `commission` reads the responding device's order info **before** it writes
//! anything and stops on a mismatch — for that device only: the run moves on to
//! the next one, because one wrong module must not end the session.
//!
//! What it reuses:
//!
//! * [`crate::assign_cmd::wait_for_single_device`] for the programming-mode
//!   wait (same nagging, same budgets, same refusal to act on two devices at
//!   once) and [`crate::assign_cmd::verify_assignment`] for the write-back
//!   verify plus the explicit `PID_PROGMODE = 0` clear;
//! * [`crate::flash_cmd::run`] and [`crate::apply_cmd::run`] verbatim for
//!   `--flash` and `--apply`, so a commissioned device is programmed exactly the
//!   way the single-device commands program it.
//!
//! Each device's bus work runs on its own short-lived tunnel, which is then
//! closed before `flash`/`apply` open theirs: a gateway has few tunnel slots and
//! bench mode is human-paced anyway.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO};
use bussard_mgmt::{DeviceConnection, LeaseChannel, manufacturers, write_individual_address};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::normalize_order_number;

use crate::assign_cmd;
use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, resolve_config,
};
use crate::secure_key::ToolKeySource;

/// The flags `commission` takes, bundled so the runner keeps one signature.
pub struct CommissionOptions<'a> {
    /// Also flash the device's application program after assigning it.
    pub flash: bool,
    /// Also apply the model's link tables after assigning (and flashing) it.
    pub apply: bool,
    /// Append one label row per commissioned device to this CSV file.
    pub labels: Option<&'a Path>,
    /// The vendor `.knxprod` to flash from; without it the model directory's
    /// `vendor/` cache is searched by order number.
    pub product: Option<&'a Path>,
    /// Skip the single run confirmation (for a non-TTY bench script).
    pub yes: bool,
    /// Emit the JSON summary instead of the table.
    pub json: bool,
    /// Permit writes to a non-loopback gateway.
    pub allow_remote_gateway: bool,
}

/// What happened to one device in a commissioning run.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// The address was written, verified, and everything asked for was done.
    Commissioned,
    /// The device already answered at its model address, so nothing was pressed.
    AlreadyPresent,
    /// The ceremony stopped for this device, for the stated reason.
    Failed(String),
}

impl Status {
    /// The machine-readable status key for the JSON summary.
    fn key(&self) -> &'static str {
        match self {
            Status::Commissioned => "commissioned",
            Status::AlreadyPresent => "present",
            Status::Failed(_) => "failed",
        }
    }

    /// The human cell for the summary table.
    fn label(&self) -> String {
        match self {
            Status::Commissioned => "commissioned".to_string(),
            Status::AlreadyPresent => "present (already assigned)".to_string(),
            Status::Failed(detail) => format!("failed: {detail}"),
        }
    }

    /// The reason text for a failure.
    fn detail(&self) -> Option<&str> {
        match self {
            Status::Failed(d) => Some(d),
            _ => None,
        }
    }
}

/// One device's row in the summary.
#[derive(Debug, Clone)]
struct Outcome {
    address: IndividualAddress,
    name: String,
    order_number: Option<String>,
    status: Status,
    /// The printed label line, when the device was commissioned.
    label: Option<String>,
}

/// The stable JSON shape of one device row.
#[derive(Debug, serde::Serialize)]
struct DeviceJson {
    address: String,
    name: String,
    order_number: Option<String>,
    status: &'static str,
    detail: Option<String>,
    label: Option<String>,
}

/// The stable JSON shape of a commissioning run.
#[derive(Debug, serde::Serialize)]
struct CommissionJson {
    line: String,
    gateway: String,
    devices: Vec<DeviceJson>,
    total: usize,
    commissioned: usize,
    present: usize,
    failed: usize,
    labels_file: Option<String>,
}

/// One device the model expects on the line.
struct Target {
    address: IndividualAddress,
    name: String,
    order_number: Option<String>,
    manufacturer: Option<String>,
    floor: Option<String>,
    room: Option<String>,
}

/// The model's devices on `area.line`, in address order.
fn targets_on_line(model: &Model, area: u8, line_no: u8) -> Vec<Target> {
    model
        .devices
        .iter()
        .filter(|(ia, _)| ia.area() == area && ia.line() == line_no)
        .map(|(ia, loaded)| {
            let device = &loaded.device;
            let product = device.product.as_ref();
            Target {
                address: *ia,
                name: device.name.clone(),
                order_number: product.and_then(|p| p.order_number.clone()),
                manufacturer: product.and_then(|p| p.manufacturer.clone()),
                floor: device.location.as_ref().and_then(|l| l.floor.clone()),
                room: device.location.as_ref().and_then(|l| l.room.clone()),
            }
        })
        .collect()
}

/// Runs `bussard commission`.
pub fn run(
    line: &str,
    dir: &Path,
    options: CommissionOptions<'_>,
    tool_key_source: ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let (area, line_no) = crate::line_cmd::parse_line(line)?;
    let line = format!("{area}.{line_no}");

    // A non-TTY run must opt in with --yes before anything touches the bus, the
    // same rule `assign` applies (issue #74).
    if !options.yes && !std::io::stdin().is_terminal() {
        bail!(
            "refusing to commission without a terminal to confirm on; pass --yes to run \
             non-interactively"
        );
    }

    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard commission` needs the model (devices/) to know which devices belong on \
             line {line}; none was loaded from {}",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    // Safety envelope (issue #74): the same gate every write goes through.
    enforce_write_gate(&config, options.allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    let targets = targets_on_line(&model, area, line_no);
    if targets.is_empty() {
        bail!(
            "the model has no devices on line {line} (looked in {}/devices)",
            dir.display()
        );
    }

    // Phase 1 (read-only): which model devices already answer at their address?
    // Those are commissioned already and are not part of the bench ritual.
    let runtime = tokio::runtime::Runtime::new()?;
    let present = {
        let config = config.clone();
        let addresses: Vec<IndividualAddress> = targets.iter().map(|t| t.address).collect();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            let _ = handle
                .wait_connected(std::time::Duration::from_secs(10))
                .await;
            let source = ops::group_source(&handle);
            let mut present = Vec::new();
            for addr in addresses {
                eprint!("\rchecking {addr}…   ");
                let _ = std::io::stderr().flush();
                if answers(&handle, source, addr).await {
                    present.push(addr);
                }
            }
            eprintln!("\r                       ");
            let _ = handle.close().await;
            present
        })
    };

    let pending = targets.len() - present.len();
    if pending == 0 {
        eprintln!("every device the model has on line {line} already answers at its address.");
    } else if !confirm(&line, pending, &gateway, options.yes)? {
        eprintln!("aborted — nothing was written.");
        return Ok(ExitCode::FAILURE);
    }
    if pending > 0 {
        // One history snapshot before the first bus write (#110).
        crate::history_cmd::capture_external_edit(dir);
        crate::history_cmd::snapshot(
            dir,
            bussard_model::history::SnapshotReason::new("commission")
                .with_args(["--line".to_string(), line.clone()])
                .with_gateway(Some(gateway.clone()))
                .with_result("before assigning addresses on the line"),
        );
    }

    // Phase 2: the bench ritual, one device at a time.
    let mut outcomes = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        if present.contains(&target.address) {
            outcomes.push(Outcome {
                address: target.address,
                name: target.name.clone(),
                order_number: target.order_number.clone(),
                status: Status::AlreadyPresent,
                label: None,
            });
            continue;
        }
        eprintln!(
            "\n[{}/{}] {} — {}",
            index + 1,
            targets.len(),
            target.address,
            target.name
        );
        let outcome = commission_one(
            &runtime,
            &config,
            target,
            dir,
            &options,
            tool_key_source,
            &overrides,
        );
        if let Some(detail) = outcome.status.detail() {
            eprintln!("  failed: {detail}");
        }
        // The label goes to stdout as it is produced, so the operator can print
        // and stick it while the next device is on the bench. Under `--json` it
        // rides in the summary instead, keeping stdout parseable.
        if let Some(label) = &outcome.label {
            if options.json {
                eprintln!("  {label}");
            } else {
                println!("{label}");
            }
        }
        outcomes.push(outcome);
    }

    // Labels are appended after each device would risk a half-written row on a
    // crash; writing them in one pass at the end keeps the CSV consistent with
    // the summary the operator just read.
    let labels_file = match options.labels {
        Some(path) => {
            append_labels(path, &outcomes, &targets)
                .with_context(|| format!("writing the labels CSV {}", path.display()))?;
            Some(path.display().to_string())
        }
        None => None,
    };

    let failed = outcomes
        .iter()
        .filter(|o| matches!(o.status, Status::Failed(_)))
        .count();

    if options.json {
        let out = to_json(&line, &gateway, &outcomes, labels_file);
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_summary(&line, &gateway, &outcomes);
        if let Some(path) = options.labels {
            println!("labels appended to {}", path.display());
        }
    }

    if failed > 0 {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Commissions one device: prompt, wait, verify the product, assign, then the
/// optional flash / apply and the label.
fn commission_one(
    runtime: &tokio::runtime::Runtime,
    config: &bussard_transport::ConnectionConfig,
    target: &Target,
    dir: &Path,
    options: &CommissionOptions<'_>,
    tool_key_source: ToolKeySource<'_>,
    overrides: &ConnOverrides,
) -> Outcome {
    let fail = |detail: String| Outcome {
        address: target.address,
        name: target.name.clone(),
        order_number: target.order_number.clone(),
        status: Status::Failed(detail),
        label: None,
    };

    // The bus half: wait for the button, read the identity, write the address.
    let assigned = {
        let config = config.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            let _ = handle
                .wait_connected(std::time::Duration::from_secs(10))
                .await;
            let source = ops::group_source(&handle);
            let result = assign_on_bus(&handle, source, target).await;
            let _ = handle.close().await;
            result
        })
    };
    let identity = match assigned {
        Ok(identity) => identity,
        Err(err) => return fail(one_line(&format!("{err:#}"))),
    };

    // The optional programming half. Both run on their own tunnels, after the
    // bench tunnel above was closed.
    if options.flash {
        let order = match &target.order_number {
            Some(order) => order.clone(),
            None => {
                return fail(
                    "--flash needs an order number in the model's product block to resolve the \
                     application program"
                        .to_string(),
                );
            }
        };
        let product = match resolve_product_file(dir, options.product, &order) {
            Ok(path) => path,
            Err(err) => return fail(one_line(&format!("{err:#}"))),
        };
        eprintln!("  flashing from {}", product.display());
        let flashed = crate::flash_cmd::run(
            &target.address.to_string(),
            &product,
            None,
            Some(&order),
            dir,
            true,
            false,
            options.allow_remote_gateway,
            None,
            tool_key_source,
            overrides.clone(),
            crate::flash_cmd::FlashOutput::default(),
        );
        match flashed {
            Ok(code) if exited_ok(&code) => {}
            Ok(_) => return fail("the flash did not complete (see the output above)".to_string()),
            Err(err) => return fail(one_line(&format!("flash: {err:#}"))),
        }
    }

    if options.apply {
        eprintln!("  applying the model's links");
        let applied = crate::apply_cmd::run(
            &target.address.to_string(),
            dir,
            true,
            options.allow_remote_gateway,
            tool_key_source,
            overrides.clone(),
        );
        match applied {
            Ok(code) if exited_ok(&code) => {}
            Ok(_) => return fail("the apply did not complete (see the output above)".to_string()),
            Err(err) => return fail(one_line(&format!("apply: {err:#}"))),
        }
    }

    let label = label_line(target, &identity);
    Outcome {
        address: target.address,
        name: target.name.clone(),
        order_number: target.order_number.clone(),
        status: Status::Commissioned,
        label: Some(label),
    }
}

/// What the device on the bench told us about itself before it was addressed.
struct Identity {
    /// The mask version, when the descriptor read answered.
    mask: Option<u16>,
    /// The KNX manufacturer id, when readable.
    manufacturer_id: Option<u16>,
    /// The order info string, when readable.
    order: Option<String>,
}

/// The bus half of one device: wait for the programming button, check the
/// product, write and verify the address.
async fn assign_on_bus(
    handle: &BusHandle,
    source: IndividualAddress,
    target: &Target,
) -> anyhow::Result<Identity> {
    match &target.order_number {
        Some(order) => eprintln!(
            "  press the programming button on {} ({order})",
            target.name
        ),
        None => eprintln!(
            "  press the programming button on {} (no order number in the model)",
            target.name
        ),
    }

    let current = assign_cmd::wait_for_single_device(handle, source)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no single device was in programming mode; nothing was written for {}",
                target.address
            )
        })?;
    eprintln!("  device in programming mode: {current} (its current address)");

    let identity = read_identity(handle, source, current).await?;
    check_order_number(target, &identity)?;

    let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    write_individual_address(channel, source, target.address)
        .await
        .context("broadcasting the new individual address")?;
    let verified = assign_cmd::verify_assignment(handle, source, target.address).await?;
    if verified.programming_mode_cleared {
        eprintln!(
            "  cleared programming mode on {} (PID_PROGMODE = 0)",
            target.address
        );
    }
    assign_cmd::warn_if_still_in_programming_mode(handle, source, target.address).await;
    eprintln!("  assigned {current} → {}", target.address);

    Ok(Identity {
        mask: verified.mask.or(identity.mask),
        manufacturer_id: verified.manufacturer_id.or(identity.manufacturer_id),
        order: verified.order.or(identity.order),
    })
}

/// Reads the identity of the device answering at `addr`: descriptor, then
/// best-effort manufacturer and order info.
async fn read_identity(
    handle: &BusHandle,
    source: IndividualAddress,
    addr: IndividualAddress,
) -> anyhow::Result<Identity> {
    let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    let mut dev = DeviceConnection::connect(channel, addr, source)
        .await
        .with_context(|| format!("connecting to the device in programming mode at {addr}"))?;
    let mask = dev.device_descriptor().await.ok();
    // Authorize with the free-access key before the property reads, as ETS does.
    if let Err(err) = dev.authorize(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
        tracing::debug!("{addr} authorize (free access) did not grant: {err}");
    }
    let manufacturer_id = match dev.read_device_property(PID_MANUFACTURER_ID).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    };
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| assign_cmd::clean_ascii(&v))
        .filter(|s| !s.is_empty());
    let _ = dev.disconnect().await;
    Ok(Identity {
        mask,
        manufacturer_id,
        order,
    })
}

/// The hard stop: the pressed device must be the product the model expects.
///
/// Three cases. The order numbers match (normalised the way the product index
/// normalises them) — proceed. They differ — refuse, naming both, and nothing is
/// written. The model has no order number — proceed with a warning, because
/// there is nothing to check against; a device that cannot be *read* while the
/// model does expect a number is a refusal, since the check was asked for and
/// could not be made.
fn check_order_number(target: &Target, identity: &Identity) -> anyhow::Result<()> {
    let Some(expected) = target.order_number.as_deref() else {
        eprintln!(
            "  warning: the model has no order number for {}, so the pressed device was not \
             verified against it",
            target.address
        );
        return Ok(());
    };
    let Some(read) = identity.order.as_deref() else {
        bail!(
            "the device in programming mode did not answer an order-number read, so it cannot be \
             verified against the model's {expected:?} for {}; nothing was written. Read it with \
             `bussard scan`, or clear the model's order number if this device cannot report one",
            target.address
        );
    };
    if normalize_order_number(read) == normalize_order_number(expected) {
        return Ok(());
    }
    bail!(
        "the device in programming mode reports order number {read:?}, but the model expects \
         {expected:?} for {} ({}); nothing was written. Leave programming mode on this device and \
         press the right one, then re-run",
        target.address,
        target.name
    )
}

/// Whether the device at `addr` answers a descriptor read.
async fn answers(handle: &BusHandle, source: IndividualAddress, addr: IndividualAddress) -> bool {
    let Ok(lease) = handle.lease().await else {
        return false;
    };
    let channel = LeaseChannel::new(lease);
    let Ok(mut dev) = DeviceConnection::connect_with(
        channel,
        addr,
        source,
        crate::scan_cmd::discovery_timeouts(),
    )
    .await
    else {
        return false;
    };
    let answered = dev.device_descriptor().await.is_ok();
    let _ = dev.disconnect().await;
    answered
}

/// Finds the `.knxprod` to flash: the explicit `--product`, else the first
/// archive in `<dir>/vendor/` whose hardware catalogue carries `order`.
fn resolve_product_file(
    dir: &Path,
    explicit: Option<&Path>,
    order: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let vendor = dir.join("vendor");
    let entries = std::fs::read_dir(&vendor).with_context(|| {
        format!(
            "no --product given and the vendor cache {} could not be read; \
             run `bussard import-product` first",
            vendor.display()
        )
    })?;
    let want = normalize_order_number(order);
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"))
        })
        .collect();
    candidates.sort();
    for path in &candidates {
        let Ok(product) = bussard_prod::read_knxprod(path) else {
            continue;
        };
        if product
            .hardware
            .order_to_apps
            .keys()
            .any(|o| normalize_order_number(o) == want)
        {
            return Ok(path.clone());
        }
    }
    bail!(
        "no cached `.knxprod` under {} carries order number {order:?}; pass --product <FILE> or \
         run `bussard import-product --order-number {order}`",
        vendor.display()
    )
}

/// Builds the label line stuck on the device, e.g.
/// `1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room`.
fn label_line(target: &Target, identity: &Identity) -> String {
    let manufacturer = target
        .manufacturer
        .clone()
        .or_else(|| identity.manufacturer_id.map(manufacturers::display));
    let order = target
        .order_number
        .clone()
        .or_else(|| identity.order.clone());
    let product = [manufacturer, order]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let location = [target.floor.clone(), target.room.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" / ");
    [
        target.address.to_string(),
        target.name.clone(),
        product,
        location,
    ]
    .into_iter()
    .filter(|f| !f.is_empty())
    .collect::<Vec<_>>()
    .join("  ")
}

/// Appends one row per commissioned device to the labels CSV, writing the header
/// when the file is created.
fn append_labels(path: &Path, outcomes: &[Outcome], targets: &[Target]) -> anyhow::Result<()> {
    let rows: Vec<String> = outcomes
        .iter()
        .filter(|o| o.status == Status::Commissioned)
        .filter_map(|o| targets.iter().find(|t| t.address == o.address))
        .map(|t| {
            [
                t.address.to_string(),
                t.name.clone(),
                t.order_number.clone().unwrap_or_default(),
                t.floor.clone().unwrap_or_default(),
                t.room.clone().unwrap_or_default(),
            ]
            .iter()
            .map(|f| csv_field(f))
            .collect::<Vec<_>>()
            .join(";")
        })
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let fresh = !path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    if fresh {
        writeln!(file, "address;name;order_number;floor;room")?;
    }
    for row in rows {
        writeln!(file, "{row}")?;
    }
    Ok(())
}

/// Quotes a CSV field when it carries the `;` separator, a quote or a newline.
fn csv_field(value: &str) -> String {
    if value.contains(';') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Asks the one confirmation for the whole run, naming the resolved gateway.
fn confirm(line: &str, devices: usize, gateway: &str, yes: bool) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "refusing to commission {devices} device(s) on line {line} via {gateway} without a \
             terminal to confirm on; pass --yes to run non-interactively"
        );
    }
    eprint!("commission {devices} device(s) on line {line} via {gateway}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading confirmation")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Whether a subcommand's returned [`ExitCode`] is the success code.
///
/// [`ExitCode`] is deliberately opaque (it implements neither `PartialEq` nor an
/// accessor), so this compares its `Debug` rendering against
/// [`ExitCode::SUCCESS`]'s. Both strings come from the same impl on the same
/// platform, so the comparison is exact rather than a guess at the encoding.
fn exited_ok(code: &ExitCode) -> bool {
    format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
}

/// Flattens a multi-line error into one summary-table cell.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Builds the JSON summary.
fn to_json(
    line: &str,
    gateway: &str,
    outcomes: &[Outcome],
    labels_file: Option<String>,
) -> CommissionJson {
    let devices: Vec<DeviceJson> = outcomes
        .iter()
        .map(|o| DeviceJson {
            address: o.address.to_string(),
            name: o.name.clone(),
            order_number: o.order_number.clone(),
            status: o.status.key(),
            detail: o.status.detail().map(str::to_string),
            label: o.label.clone(),
        })
        .collect();
    let count = |key: &str| devices.iter().filter(|d| d.status == key).count();
    CommissionJson {
        line: line.to_string(),
        gateway: gateway.to_string(),
        total: devices.len(),
        commissioned: count("commissioned"),
        present: count("present"),
        failed: count("failed"),
        devices,
        labels_file,
    }
}

/// Prints the one summary table the run ends with.
fn print_summary(line: &str, gateway: &str, outcomes: &[Outcome]) {
    println!(
        "\ncommission line {line} via {gateway} — {} device(s)\n",
        outcomes.len()
    );
    let name_width = outcomes
        .iter()
        .map(|o| o.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 32);
    println!("{:<9} {:<name_width$} status", "address", "name");
    for o in outcomes {
        let name: String = o.name.chars().take(name_width).collect();
        println!(
            "{:<9} {:<name_width$} {}",
            o.address.to_string(),
            name,
            o.status.label()
        );
    }
    let count = |f: fn(&Status) -> bool| outcomes.iter().filter(|o| f(&o.status)).count();
    println!(
        "\n{} commissioned, {} already present, {} failed",
        count(|s| matches!(s, Status::Commissioned)),
        count(|s| matches!(s, Status::AlreadyPresent)),
        count(|s| matches!(s, Status::Failed(_))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            address: "1.1.7".parse().expect("a valid address"),
            name: "Blind actuator".to_string(),
            order_number: Some("JAL-0810.03".to_string()),
            manufacturer: Some("MDT".to_string()),
            floor: Some("Ground floor".to_string()),
            room: Some("Living room".to_string()),
        }
    }

    fn identity(order: Option<&str>) -> Identity {
        Identity {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: order.map(str::to_string),
        }
    }

    #[test]
    fn test_label_line_matches_the_documented_shape() {
        assert_eq!(
            label_line(&target(), &identity(Some("JAL-0810.03"))),
            "1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room"
        );
    }

    #[test]
    fn test_label_line_drops_absent_fields() {
        let mut t = target();
        t.manufacturer = None;
        t.floor = None;
        t.room = None;
        // The manufacturer falls back to the id read from the device (0x0083 = MDT).
        assert_eq!(
            label_line(&t, &identity(Some("JAL-0810.03"))),
            "1.1.7  Blind actuator  MDT JAL-0810.03"
        );
    }

    #[test]
    fn test_check_order_number_accepts_a_match() -> anyhow::Result<()> {
        // Case and surrounding space are normalised, as the product index does.
        check_order_number(&target(), &identity(Some("  jal-0810.03 ")))?;
        Ok(())
    }

    #[test]
    fn test_check_order_number_refuses_a_mismatch() {
        let err = check_order_number(&target(), &identity(Some("AKK-0216.03")))
            .expect_err("a mismatch must be refused");
        let msg = err.to_string();
        assert!(msg.contains("AKK-0216.03"), "names what was read: {msg}");
        assert!(
            msg.contains("JAL-0810.03"),
            "names what was expected: {msg}"
        );
        assert!(msg.contains("nothing was written"), "{msg}");
    }

    #[test]
    fn test_check_order_number_refuses_an_unreadable_one() {
        let err = check_order_number(&target(), &identity(None))
            .expect_err("an unverifiable device must be refused");
        assert!(
            err.to_string()
                .contains("did not answer an order-number read"),
            "{err}"
        );
    }

    #[test]
    fn test_check_order_number_warns_without_a_model_number() -> anyhow::Result<()> {
        let mut t = target();
        t.order_number = None;
        check_order_number(&t, &identity(None))?;
        Ok(())
    }

    #[test]
    fn test_csv_field_quotes_only_when_needed() {
        assert_eq!(csv_field("Living room"), "Living room");
        assert_eq!(csv_field("a;b"), "\"a;b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_exited_ok_distinguishes_the_two_codes() {
        assert!(exited_ok(&ExitCode::SUCCESS));
        assert!(!exited_ok(&ExitCode::FAILURE));
    }
}
