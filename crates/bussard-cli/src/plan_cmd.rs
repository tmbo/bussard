//! The `bussard plan` subcommand — diff the model against a device's live tables.
//!
//! Reads a System B device's group-address and association tables over the bus
//! (via [`bussard_mgmt::tables`], read-only), computes the desired tables from
//! the model's `links.yaml` for that device (via [`bussard_download`]), and shows
//! what `apply` would change: additions, removals, unchanged links, resulting
//! table sizes, and the load-op sequence.
//!
//! This command is **read-only on the bus** — it never writes a load control or
//! a property, so it is safe to run against a live installation.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, ops};
use bussard_download::{DesiredTables, PlanReport, compute_tables, plan};
use bussard_mgmt::tables::{DeviceTables, TablesError, read_tables};
use bussard_mgmt::{Layer4Connection, LeaseChannel, system_type};
use bussard_model::{IndividualAddress, Model};

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

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

    let Some(model) = load_model_optional(dir) else {
        bail!(
            "`bussard plan` needs the model (links.yaml) to compute the desired tables; \
             none was loaded from {}",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;

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
                let r = read_tables(&mut l4).await;
                let _ = l4.disconnect().await;
                r
            }
            Err(err) => Err(TablesError::Mgmt(err)),
        };
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    let live = match read {
        Ok(live) => live,
        Err(TablesError::UnsupportedMask { address, mask }) => {
            eprintln!(
                "{address} reports mask {mask:04X} ({}) — `bussard plan` supports \
                 System B (mask 07B0) only for now",
                system_type(mask)
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(err) => return Err(anyhow::Error::new(err).context("reading device tables")),
    };

    let report = plan(&live, &desired);
    if json {
        let out = to_json(target, &live, &report);
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_text(target, &live, &report);
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
