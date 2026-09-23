//! The `bussard plan` subcommand — diff the model against a device's live tables.
//!
//! Reads the device's group-address and association tables over the bus,
//! computes the desired tables from the model's `links.yaml` for that device (via
//! [`bussard_download`]), and shows what `apply` would change: additions,
//! removals, unchanged links, resulting table sizes, and the load-op sequence.
//!
//! Two device families are read here, behind one seam ([`read_live_tables`]):
//! **System B** (mask `x7B0`) serves its tables as interface-object property
//! arrays ([`bussard_mgmt::tables`]); **System 7** (mask `0705` / `0701`) keeps
//! them in absolute memory at `0x4000` / `0x4201`
//! ([`bussard_download::tables_sys7`], issue #91). Both decode into the same
//! [`DeviceTables`] shape, so the diff and the report below are family-agnostic.
//!
//! This command is **read-only on the bus** — it never writes a load control or
//! a property, so it is safe to run against a live installation.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, ops};
use bussard_download::{
    DesiredTables, PlanReport, Sys7LiveTables, compute_tables, plan, read_sys7_tables,
};
use bussard_mgmt::tables::{DeviceTables, TablesError, read_tables};
use bussard_mgmt::{L4Channel, Layer4Connection, LeaseChannel, MaskProfile, system_type};
use bussard_model::{IndividualAddress, Model};

use crate::conn_cmd::{ConnOverrides, load_model_required, resolve_config};

/// A serialisable `(object, GA)` pair for the JSON output.
#[derive(Debug, serde::Serialize)]
struct ObjectGaJson {
    object: u16,
    ga: String,
}

/// The stable JSON shape of a plan.
#[derive(Debug, serde::Serialize)]
struct PlanJson {
    address: String,
    mask: String,
    system_type: String,
    unchanged: Vec<ObjectGaJson>,
    additions: Vec<ObjectGaJson>,
    removals: Vec<ObjectGaJson>,
    current_address_count: usize,
    current_association_count: usize,
    resulting_address_count: usize,
    resulting_association_count: usize,
    load_steps: Vec<String>,
    noop: bool,
}

/// A device's live tables, whichever family served them.
///
/// Both variants carry the shared [`DeviceTables`] view (mask, address table,
/// association table, resolved links), so every consumer — the diff, the
/// `reconstruct` report, the `apply` backup — works on either. The System 7
/// variant additionally carries the device's own individual address and its
/// group-object descriptor image, which `apply` needs to rewrite the `0x4000`
/// region without disturbing what the download put there.
pub(crate) enum LiveTables {
    /// A System B (`x7B0`) device read through interface-object properties.
    SystemB(DeviceTables),
    /// A System 7 (`0705` / `0701`) device read out of absolute memory.
    Sys7(Box<Sys7LiveTables>),
}

impl LiveTables {
    /// The family-agnostic table view.
    pub(crate) fn tables(&self) -> &DeviceTables {
        match self {
            LiveTables::SystemB(t) => t,
            LiveTables::Sys7(s) => &s.tables,
        }
    }

    /// The System 7 detail, when this is a System 7 device.
    pub(crate) fn sys7(&self) -> Option<&Sys7LiveTables> {
        match self {
            LiveTables::SystemB(_) => None,
            LiveTables::Sys7(s) => Some(s),
        }
    }
}

/// The outcome of one live table read: the tables, or a mask no family reader
/// speaks (System 1 / 2 / unknown), which the caller reports and exits on.
pub(crate) enum LiveRead {
    /// The tables were read.
    Tables(LiveTables),
    /// The device answered with a mask bussard cannot read tables for.
    UnsupportedMask {
        /// The device.
        address: IndividualAddress,
        /// The mask version it reported.
        mask: u16,
    },
}

/// Reads a device's live tables on an open (and authorized) connection, picking
/// the reader by mask family.
///
/// System B is tried first; its `UnsupportedMask` refusal carries the mask, which
/// routes a System 7 device to the memory-mapped reader instead of failing. Any
/// other family is reported back as [`LiveRead::UnsupportedMask`].
pub(crate) async fn read_live_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> anyhow::Result<LiveRead> {
    match read_tables(l4).await {
        Ok(tables) => Ok(LiveRead::Tables(LiveTables::SystemB(tables))),
        Err(TablesError::UnsupportedMask { address, mask })
            if MaskProfile::from_mask(mask).is_system_7() =>
        {
            let live = read_sys7_tables(l4)
                .await
                .with_context(|| format!("reading {address}'s System 7 tables"))?;
            Ok(LiveRead::Tables(LiveTables::Sys7(Box::new(live))))
        }
        Err(TablesError::UnsupportedMask { address, mask }) => {
            Ok(LiveRead::UnsupportedMask { address, mask })
        }
        Err(err) => Err(anyhow::Error::new(err).context("reading device tables")),
    }
}

/// Prints the friendly refusal for a mask no table reader speaks.
pub(crate) fn report_unsupported_mask(command: &str, address: IndividualAddress, mask: u16) {
    eprintln!(
        "{address} reports mask {mask:04X} ({}) — `bussard {command}` supports the \
         System B (x7B0) and System 7 (0705 / 0701) families",
        system_type(mask)
    );
}

/// Reads a device's live tables and shows what `apply` would change.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A parse error is a hard failure here (surfaced with the file detail); an
    // absent model still bails, since `plan` needs links.yaml.
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard plan` needs the model (links.yaml) to compute the desired tables; \
             none was loaded from {}",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;

    // Issue #112: say in plain sentences what the model now asks for that the
    // last snapshot did not, before the com-object table below says it in
    // numbers. Text output only — `--json` stays a single JSON document.
    if !json {
        if let Some(pending) = crate::history_cmd::pending_changes(dir) {
            println!(
                "pending model changes since the last snapshot ({} change(s)):\n",
                pending.changes.len()
            );
            print!("{}", bussard_model::change::render_text(&pending.changes));
            println!();
        }
    }
    // Whatever was edited outside bussard is now recorded, so it cannot be lost.
    crate::history_cmd::capture_external_edit(dir);

    let desired = compute_desired(&model, target)?;

    let runtime = tokio::runtime::Runtime::new()?;
    let read = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let result = match Layer4Connection::connect(channel, target, source).await {
            Ok(mut l4) => {
                // Authorize (free access) before reading, as ETS does (issue #52
                // finding #1) and as System 7 requires before any memory access.
                // Best-effort on this read-only plan pre-pass.
                if let Err(err) = l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
                    tracing::debug!("{target} authorize (free access) did not grant: {err}");
                }
                let r = read_live_tables(&mut l4).await;
                let _ = l4.disconnect().await;
                r
            }
            Err(err) => Err(anyhow::Error::new(TablesError::Mgmt(err))
                .context("connecting to the device")),
        };
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    let live = match read? {
        LiveRead::Tables(live) => live,
        LiveRead::UnsupportedMask { address, mask } => {
            report_unsupported_mask("plan", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let live = live.tables();

    let report = plan(live, &desired);
    if json {
        let out = to_json(target, live, &report);
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_text(target, live, &report);
    }
    Ok(ExitCode::SUCCESS)
}

/// Computes the desired tables from the model's links for `target`.
pub(crate) fn compute_desired(
    model: &Model,
    target: IndividualAddress,
) -> anyhow::Result<DesiredTables> {
    let links = model
        .links
        .links
        .get(&target)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    if links.is_empty() {
        // A device with no links in the model would compute empty tables; that is
        // almost certainly a mistake (would wipe the device), so refuse.
        bail!(
            "the model has no links for {target}; refusing to plan an empty table set \
             (add links to links.yaml, or check the device address)"
        );
    }
    Ok(compute_tables(links))
}

fn to_json(target: IndividualAddress, live: &DeviceTables, report: &PlanReport) -> PlanJson {
    let map = |pairs: &[bussard_download::ObjectGa]| {
        pairs
            .iter()
            .map(|p| ObjectGaJson {
                object: p.object,
                ga: p.ga.to_string(),
            })
            .collect()
    };
    PlanJson {
        address: target.to_string(),
        mask: format!("{:04X}", live.mask),
        system_type: system_type(live.mask).to_string(),
        unchanged: map(&report.unchanged),
        additions: map(&report.additions),
        removals: map(&report.removals),
        current_address_count: report.current_address_count,
        current_association_count: report.current_association_count,
        resulting_address_count: report.resulting_address_count,
        resulting_association_count: report.resulting_association_count,
        load_steps: report.load_steps.iter().map(|s| s.to_string()).collect(),
        noop: report.is_noop(),
    }
}

/// Prints the reconstruct-style plan with additions/removals prominent.
pub(crate) fn print_text(target: IndividualAddress, live: &DeviceTables, report: &PlanReport) {
    println!(
        "plan for {target} — mask {:04X} ({})",
        live.mask,
        system_type(live.mask)
    );
    if report.is_noop() {
        println!("\nnothing to do — the device tables already match the model");
        return;
    }

    println!(
        "\n{} addition(s), {} removal(s), {} unchanged:",
        report.additions.len(),
        report.removals.len(),
        report.unchanged.len()
    );
    for p in &report.additions {
        println!("  + add:    object {:>4} → {}", p.object, p.ga);
    }
    for p in &report.removals {
        println!("  - remove: object {:>4} → {}", p.object, p.ga);
    }

    println!(
        "\ntable sizes: group addresses {} → {}, associations {} → {}",
        report.current_address_count,
        report.resulting_address_count,
        report.current_association_count,
        report.resulting_association_count,
    );

    println!("\nload operations `apply` would run (in order):");
    for step in &report.load_steps {
        println!("  StartLoading → write → LoadCompleted: {step}");
    }
    println!("\nrun `bussard apply {target}` to write these changes (with confirmation).");
}
