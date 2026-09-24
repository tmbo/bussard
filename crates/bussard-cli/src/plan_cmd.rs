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
use bussard_download::{DesiredTables, PlanReport, plan};
use bussard_mgmt::tables::{DeviceTables, TablesError};
use bussard_mgmt::{L4Channel, Layer4Connection, LeaseChannel, MaskProfile, system_type};
use bussard_model::{IndividualAddress, Model};
use bussard_service::{BusService, WritePolicy};

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_required, resolve_config,
};

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
    /// The parameter read-back (issue #119), when a product file was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<crate::param_readback::Readback>,
}

// The live read, the desired-table computation and the plan rendering are
// shared with the MCP programming tier (issue #118), so they live in
// `bussard_download::program`; the CLI keeps its anyhow-returning wrappers.
pub(crate) use bussard_download::LiveRead;

/// Reads a device's live tables on an open (and authorized) connection, picking
/// the reader by mask family (see [`bussard_download::read_live_tables`]).
pub(crate) async fn read_live_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> anyhow::Result<LiveRead> {
    Ok(bussard_download::read_live_tables(l4).await?)
}

/// Prints the friendly refusal for a mask no table reader speaks.
///
/// The wording is derived from the central capability table
/// ([`MaskProfile::capabilities`]), so a mask that gains support cannot leave a
/// stale refusal behind.
pub(crate) fn report_unsupported_mask(command: &str, address: IndividualAddress, mask: u16) {
    let caps = MaskProfile::from_mask(mask).capabilities();
    eprintln!(
        "{address} reports mask {mask:04X} ({}) — `bussard {command}` supports the \
         System B (x7B0) and System 7 (0705 / 0701) families; on this mask bussard can: {}",
        system_type(mask),
        caps.summary()
    );
}

/// Reads a device's live tables and shows what `apply` would change.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
    selection: crate::param_readback::Selection<'_>,
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
    if !json && let Some(pending) = crate::history_cmd::pending_changes(dir) {
        println!(
            "pending model changes since the last snapshot ({} change(s)):\n",
            pending.changes.len()
        );
        print!("{}", bussard_model::change::render_text(&pending.changes));
        println!();
    }
    // Whatever was edited outside bussard is now recorded, so it cannot be lost.
    crate::history_cmd::capture_external_edit(dir);

    let desired = compute_desired(&model, target)?;
    // The product file the parameter read-back decodes with (issue #119), when
    // one is given or cached.
    let product = crate::param_readback::resolve(dir, selection, Some(&model), target)?;
    let model_ref = &model;
    let product_ref = product.as_ref();

    let runtime = tokio::runtime::Runtime::new()?;
    let read = runtime.block_on(async move {
        let service = BusService::open(config, WritePolicy::ReadOnly)?;
        let handle = service.handle().clone();
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = checked_source_or_close(&handle, &overrides).await?;
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
                let params = match (&r, product_ref) {
                    (Ok(LiveRead::Tables(live)), Some(product)) => Some(
                        crate::param_readback::read(
                            &mut l4,
                            product,
                            Some(model_ref),
                            target,
                            live.tables().mask,
                        )
                        .await,
                    ),
                    _ => None,
                };
                let _ = l4.disconnect().await;
                r.map(|r| (r, params))
            }
            Err(err) => Err(anyhow::Error::new(TablesError::Mgmt(err))
                .context("connecting to the device")),
        };
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    let (read, params) = read?;
    let live = match read {
        LiveRead::Tables(live) => live,
        LiveRead::UnsupportedMask { address, mask } => {
            report_unsupported_mask("plan", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let live = live.tables();

    let report = plan(live, &desired);
    if json {
        let mut out = to_json(target, live, &report);
        out.parameters = params;
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_text(target, live, &report);
        match &params {
            Some(params) => crate::param_readback::print_text(params, target),
            None => crate::param_readback::print_missing_product_note(Some(&model), target),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Computes the desired tables from the model's links for `target`, refusing a
/// device with no links (see [`bussard_download::desired_tables_for`]).
pub(crate) fn compute_desired(
    model: &Model,
    target: IndividualAddress,
) -> anyhow::Result<DesiredTables> {
    Ok(bussard_download::desired_tables_for(model, target)?)
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
        parameters: None,
    }
}

/// Prints the reconstruct-style plan with additions/removals prominent.
pub(crate) fn print_text(target: IndividualAddress, live: &DeviceTables, report: &PlanReport) {
    print!(
        "{}",
        bussard_download::render_plan_text(target, live, report)
    );
    if !report.is_noop() {
        println!("\nrun `bussard apply {target}` to write these changes (with confirmation).");
    }
}
