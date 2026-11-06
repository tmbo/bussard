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
//! The flow is [`bussard_service::commission`] (issue #753), which
//! `knx_commission_line` runs too: the line walk, the presence pre-pass, the
//! identification with the order-number check, the address write with its
//! read-back, and the label. This module keeps the prompts and the printing,
//! and reuses:
//!
//! * [`crate::assign_cmd::wait_for_single_device`] for the programming-mode
//!   wait (same nagging, same budgets, same refusal to act on two devices at
//!   once);
//! * [`crate::flash_cmd::run`] and [`crate::apply_cmd::run`] verbatim for
//!   `--flash` and `--apply`, so a commissioned device is programmed exactly the
//!   way the single-device commands program it.
//!
//! Each device's bus work runs on its own short-lived tunnel, which is then
//! closed before `flash`/`apply` open theirs: a gateway has few tunnel slots and
//! bench mode is human-paced anyway.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_service::commission::{
    Assigned, CommissionError, LineRun, Next, OrderCheck, Outcome, Status, Target,
};
use bussard_service::{BusService, WritePolicy};

use crate::apply_cmd::ApplyArgs;
use crate::assign_cmd;
use crate::cli::{Consent, Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{
    checked_source_or_close, enforce_write_gate, gateway_display, load_model_required,
    resolve_config, session_open_error,
};
use crate::flash_cmd::FlashArgs;

/// `bussard commission`.
#[derive(Debug, clap::Args)]
pub(crate) struct CommissionArgs {
    /// The line to commission, e.g. `1.1`.
    #[arg(long, value_name = "LINE")]
    line: String,
    /// Also flash each device's application program after assigning it.
    #[arg(long)]
    flash: bool,
    /// Also apply the project's link tables after assigning (and flashing).
    #[arg(long)]
    apply: bool,
    /// Append one label row per commissioned device to this CSV file
    /// (columns `address;name;order_number;floor;room`).
    #[arg(long, value_name = "FILE")]
    labels: Option<PathBuf>,
    /// The vendor `.knxprod` to flash from. Default: the archive
    /// `bussard.lock` pins for each device in `<dir>/products/`.
    #[arg(long, value_name = "FILE", requires = "flash")]
    product: Option<PathBuf>,
    #[command(flatten)]
    consent: Consent,
    /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
    /// escape hatch. Prefer `--keyring` for a real installation.
    #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
    tool_key: Option<String>,
}

impl Run for CommissionArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json().tool_key(self.tool_key.is_some())
    }

    fn early_consent(&self) -> Option<(bool, String)> {
        Some((self.consent.yes, format!("commission line {}", self.line)))
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(&self, g)
    }
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

/// The product archives `--flash` downloads from, by device, resolved before
/// any bus access (issue #228).
type Products = BTreeMap<IndividualAddress, PathBuf>;

/// Runs `bussard commission`.
fn run(options: &CommissionArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (line, dir, overrides) = (options.line.as_str(), g.dir(), g.mgmt());
    let (area, line_no) = crate::line_cmd::parse_line(line)?;
    let line = format!("{area}.{line_no}");

    // A non-TTY run without --yes was refused before this (issue #74), by
    // `confirm::require_terminal_or_yes` in `main`.

    let Some(model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                &format!("`bussard commission` walks the devices the model has on line {line}")
            )
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    // Safety envelope (issue #74): the same gate every write goes through.
    enforce_write_gate(&config, g.allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    let mut walk = LineRun::new(&model, area, line_no);
    if walk.targets().is_empty() {
        bail!(
            "the model has no devices on line {line} (looked in {}/devices)",
            dir.display()
        );
    }
    // `--flash` needs every device's product data: a missing or changed
    // archive refuses the run before anything touches the bus (issue #228).
    let mut products = Products::new();
    if options.flash {
        let mut refusals = Vec::new();
        for target in walk.targets() {
            let Some(order) = target.order_number.clone() else {
                continue;
            };
            let device = model.devices.get(&target.address).map(|d| &d.device);
            match crate::product_store::resolve(dir, options.product.as_deref(), device, &order) {
                Ok(path) => {
                    products.insert(target.address, path);
                }
                Err(err) => refusals.push(format!("{}: {err:#}", target.address)),
            }
        }
        if !refusals.is_empty() {
            bail!(
                "refusing to commission with --flash: product data is missing\n  {}",
                refusals.join("\n  ")
            );
        }
    }

    // Phase 1 (read-only): which model addresses already answer? NM_IndividualAddress_Write
    // step 1 (Management Procedures 03_05_02 §2.3, issue #530): an answer
    // means the address is in use. It is the modelled device, commissioned
    // already, only when its order number says so; anything else holds the
    // address and that device is refused.
    let runtime = tokio::runtime::Runtime::new()?;
    let verdicts = {
        let config = config.clone();
        let targets = walk.targets().to_vec();
        let conn = overrides.clone();
        runtime.block_on(async move {
            let service = BusService::open(config, WritePolicy::transmit(g.allow_remote_gateway))?;
            let _ = service
                .wait_connected(crate::conn_cmd::connect_wait())
                .await;
            let source = checked_source_or_close(&service, &conn).await?;
            let mut on_probe = |event: bussard_service::line::WalkEvent<'_, _>| {
                if let bussard_service::line::WalkEvent::Probing { address, .. } = event {
                    eprint!("\rchecking {address}…   ");
                    let _ = std::io::stderr().flush();
                }
            };
            let verdicts =
                bussard_service::commission::probe_line(&service, source, &targets, &mut on_probe)
                    .await;
            eprintln!("\r                       ");
            service.close().await;
            anyhow::Ok(verdicts)
        })?
    };
    walk.set_verdicts(verdicts);

    let pending = walk.pending();
    if pending == 0 {
        eprintln!("every device the model has on line {line} already answers at its address.");
    } else if !confirm(&line, pending, &gateway, options.consent.yes)? {
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
    while let Some(next) = walk.advance() {
        let (position, total, target) = match next {
            Next::Settled(outcome) => {
                if let Some(detail) = outcome.status.detail() {
                    eprintln!("{}: {detail}", outcome.address);
                }
                continue;
            }
            Next::Device {
                position,
                total,
                target,
            } => (position, total, target),
        };
        eprintln!(
            "\n[{position}/{total}] {} — {}",
            target.address, target.name
        );
        let outcome = commission_one(
            &runtime,
            &config,
            &target,
            products.get(&target.address).cloned(),
            options,
            g,
        );
        if let Some(detail) = outcome.status.detail() {
            eprintln!("  failed: {detail}");
        }
        // The label goes to stdout as it is produced, so the operator can print
        // and stick it while the next device is on the bench. Under `--json` it
        // rides in the summary instead, keeping stdout parseable.
        if let Some(label) = &outcome.label {
            if g.json {
                eprintln!("  {label}");
            } else {
                println!("{label}");
            }
        }
        walk.record(outcome);
    }
    let outcomes = walk.outcomes();

    // Labels are appended after each device would risk a half-written row on a
    // crash; writing them in one pass at the end keeps the CSV consistent with
    // the summary the operator just read.
    let labels_file = match options.labels.as_deref() {
        Some(path) => {
            append_labels(path, outcomes, walk.targets())
                .with_context(|| format!("writing the labels CSV {}", path.display()))?;
            Some(path.display().to_string())
        }
        None => None,
    };

    let failed = walk.totals().failed;

    if g.json {
        let out = to_json(&line, &gateway, outcomes, labels_file);
        crate::output::print(crate::output::schema::COMMISSION, &out)?;
    } else {
        print_summary(&line, &gateway, outcomes);
        if let Some(path) = options.labels.as_deref() {
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
    product: Option<PathBuf>,
    options: &CommissionArgs,
    g: &Resolved,
) -> Outcome {
    let (dir, overrides) = (g.dir(), &g.mgmt());
    let fail = |detail: String| Outcome::failed(target, detail);

    // The bus half: wait for the button, read the identity, write the address.
    let assigned = {
        let config = config.clone();
        runtime.block_on(async move {
            let service = BusService::open(config, WritePolicy::transmit(g.allow_remote_gateway))?;
            let _ = service
                .wait_connected(crate::conn_cmd::connect_wait())
                .await;
            let source = checked_source_or_close(&service, overrides).await?;
            let result = assign_on_bus(&service, source, target).await;
            service.close().await;
            result
        })
    };
    let assigned = match assigned {
        Ok(assigned) => {
            // A new box now answers at the address: facts stored for it
            // describe whatever was there before (issue #228, item 5). The
            // flash and apply below read the new device's and report its
            // identity; apply refuses a device that drifted from the lock.
            bussard_service::commission::forget_facts(dir, target.address);
            assigned
        }
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
        let Some(product) = product else {
            return fail(format!("no product data resolved for {order}"));
        };
        eprintln!("  flashing from {}", product.display());
        let flashed = FlashArgs {
            address: target.address.to_string(),
            product: Some(product),
            order_number: Some(order),
            consent: Consent { yes: true },
            tool_key: ToolKey {
                tool_key: options.tool_key.clone(),
            },
            ..FlashArgs::default()
        }
        .run(&g.step());
        match flashed {
            Ok(code) if exited_ok(&code) => {}
            Ok(_) => return fail("the flash did not complete (see the output above)".to_string()),
            Err(err) => return fail(one_line(&format!("flash: {err:#}"))),
        }
    }

    if options.apply {
        eprintln!("  applying the model's links");
        let applied = ApplyArgs {
            address: Some(target.address.to_string()),
            consent: Consent { yes: true },
            tool_key: ToolKey {
                tool_key: options.tool_key.clone(),
            },
            ..ApplyArgs::default()
        }
        .run(&g.step());
        match applied {
            Ok(code) if exited_ok(&code) => {}
            Ok(_) => return fail("the apply did not complete (see the output above)".to_string()),
            Err(err) => return fail(one_line(&format!("apply: {err:#}"))),
        }
    }

    Outcome::commissioned(target, assigned.label)
}

/// The bus half of one device: wait for the programming button, check the
/// product, write and verify the address
/// ([`bussard_service::commission::identify_pressed`] and
/// [`bussard_service::commission::assign_pressed`]).
async fn assign_on_bus(
    service: &BusService,
    source: IndividualAddress,
    target: &Target,
) -> anyhow::Result<Assigned> {
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

    let current = assign_cmd::wait_for_single_device(service, source)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no single device was in programming mode; nothing was written for {}",
                target.address
            )
        })?;
    eprintln!("  device in programming mode: {current} (its current address)");

    let identified =
        bussard_service::commission::identify_pressed(service, source, target, current)
            .await
            .map_err(cli_error)?;
    match &identified.check {
        OrderCheck::Matches => {}
        OrderCheck::NoModelNumber => eprintln!(
            "  {}",
            bussard_service::commission::unchecked_warning(target)
        ),
        OrderCheck::Refused(sentence) => bail!("{sentence}"),
    }

    let assigned =
        bussard_service::commission::assign_pressed(service, source, target, &identified)
            .await
            .map_err(cli_error)?;
    for warning in &assigned.warnings {
        eprintln!("{warning}");
    }
    if assigned.programming_mode_cleared {
        eprintln!(
            "  cleared programming mode on {} (PID_PROGMODE = 0)",
            target.address
        );
    }
    if assigned.still_in_programming_mode {
        eprintln!();
        for line in bussard_service::assign::still_in_programming_mode_warning(target.address) {
            eprintln!("{line}");
        }
    }
    eprintln!("  assigned {current} → {}", target.address);
    Ok(assigned)
}

/// A commission step's error as the CLI reports it: an identification that
/// could not open its session keeps a lease error as it is.
fn cli_error(err: CommissionError) -> anyhow::Error {
    match err {
        CommissionError::Identify { current, source } => session_open_error(source, || {
            format!("connecting to the device in programming mode at {current}")
        }),
        other => other.into(),
    }
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
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
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
    crate::confirm::confirm(
        yes,
        &format!("commission {devices} device(s) on line {line} via {gateway}?"),
        &format!("commission line {line} ({devices} device(s)) via {gateway}"),
    )
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

    #[test]
    fn test_append_labels_writes_only_commissioned_rows() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-commission-labels-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?
        ));
        let path = dir.join("labels.csv");
        let target = Target {
            address: "1.1.7".parse()?,
            name: "Blind actuator".to_string(),
            order_number: Some("JAL-0810.03".to_string()),
            manufacturer: Some("MDT".to_string()),
            floor: Some("Ground floor".to_string()),
            room: Some("Living room".to_string()),
        };
        let mut other = target.clone();
        other.address = "1.1.8".parse()?;
        let outcomes = [
            Outcome::commissioned(&target, "label".to_string()),
            Outcome::failed(&other, "skipped".to_string()),
        ];
        append_labels(&path, &outcomes, &[target, other])?;
        let csv = std::fs::read_to_string(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            csv?,
            "address;name;order_number;floor;room\n\
             1.1.7;Blind actuator;JAL-0810.03;Ground floor;Living room\n"
        );
        Ok(())
    }
}
