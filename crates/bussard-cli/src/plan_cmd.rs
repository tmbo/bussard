//! The `bussard plan` subcommand — diff the model against a device's live tables.
//!
//! Reads the device's group-address and association tables over the bus,
//! computes the desired tables from the links in the model's device file for that device (via
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
//! a property, so it is safe to run against a live installation. A KNX Data
//! Secure device is read with `--keyring` / `--tool-key` (issue #170), see
//! [`read_device`].

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_download::{DesiredTables, PlanReport, plan};
use bussard_mgmt::tables::DeviceTables;
use bussard_mgmt::{L4Channel, Layer4Connection, MaskProfile, system_type};
use bussard_model::{IndividualAddress, Model};
use bussard_service::{L4Options, SourcePolicy, WritePolicy};
use bussard_transport::ConnectionConfig;

use crate::conn_cmd::{ConnOverrides, load_model_required, open_service, resolve_config};
use crate::param_readback::ProductSource;
use crate::secure_key::ToolKeySource;

/// A serialisable `(object, GA)` pair for the JSON output.
#[derive(Debug, serde::Serialize)]
struct ObjectGaJson {
    object: u16,
    ga: String,
}

/// The stable JSON shape of a plan: the device plan (changes in the model's
/// words, unchanged counts, writes, backup, `state_hash`) plus the table
/// detail the plan has always carried.
#[derive(Debug, serde::Serialize)]
struct PlanJson {
    #[serde(flatten)]
    plan: bussard_download::DevicePlan,
    /// The one question `apply` asks, `None` for an empty plan.
    question: Option<String>,
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
    /// The device's identity compared with `bussard.lock` (lock v2, issue
    /// #228), when the device facts were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<bussard_model::identity::IdentityCheck>,
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
    if mask == SECURE_PLAIN_MASK {
        eprintln!(
            "mask {SECURE_PLAIN_MASK:04X} is what a KNX Data Secure-activated device answers to an \
             unsecured descriptor read: {}",
            crate::secure_key::no_key_guidance()
        );
    }
}

/// The mask a KNX Data Secure-activated device reports to a plain (unsecured)
/// `A_DeviceDescriptor_Read` (observed on 1.1.12, issue #170); the secured read
/// returns the real one.
const SECURE_PLAIN_MASK: u16 = 0xFFFF;

/// What one read-only management session returned: the live tables (or the
/// unsupported-mask refusal) and, when a product file was given, the parameter
/// read-back.
pub(crate) type DeviceRead = (
    LiveRead,
    Option<crate::param_readback::ParamState>,
    Option<bussard_model::identity::ReportedIdentity>,
);

/// Opens a read-only bus service, reads `target`'s live tables in one management
/// session and, when `product` is given and the tables read, the parameter
/// memory too. Shared by `plan` and `reconstruct` (issue #170).
///
/// With a tool key from `tool_key_source` every APDU, the device descriptor
/// read included, rides `A_SecureData`, so a KNX Data Secure device reports its
/// real mask instead of the `FFFF` it answers in the clear. Without one the
/// frames are exactly those of the plain path before KNX Secure existed.
pub(crate) fn read_device(
    config: ConnectionConfig,
    target: IndividualAddress,
    overrides: &ConnOverrides,
    tool_key_source: ToolKeySource<'_>,
    product: Option<&ProductSource>,
    model: Option<&Model>,
    mut facts: bussard_service::FactsCache,
) -> anyhow::Result<DeviceRead> {
    let activated = crate::secure_key::model_activated(model, target);
    let tool_key = crate::secure_key::resolve(target, tool_key_source, activated)?;
    let presented_tool_key = tool_key.is_some();
    let options = L4Options {
        source: SourcePolicy::Check {
            skip: overrides.skip_address_check,
        },
        tool_key,
        high_water: bussard_secure::SequenceHighWater::new(),
        // Authorize (free access) before reading, as ETS does (issue #52
        // finding #1) and as System 7 requires before any memory access.
        // Best-effort on a read; skipped for a device whose facts say it never
        // answers (issue #209).
        authorize: crate::device_facts::read_only_authorize(&mut facts, target),
        ..L4Options::default()
    };
    let runtime = tokio::runtime::Runtime::new()?;
    runtime
        .block_on(async move {
            let service = open_service(config, WritePolicy::ReadOnly).await?;
            let outcome = service
                .with_l4(target, &options, async |l4| {
                    // The device facts (issue #209): a valid set seeds the
                    // connection so neither the table reader nor the parameter
                    // read-back walks the interface objects again.
                    let established =
                        crate::device_facts::establish_table_facts(l4, &facts).await?;
                    // What the device says it is, for the lock comparison
                    // (lock v2, issue #228).
                    let identity = established.and_then(|e| e.record).map(|record| {
                        bussard_model::identity::ReportedIdentity {
                            mask: record.mask,
                            application_id: record.application_id,
                        }
                    });
                    let read = read_live_tables(l4).await?;
                    let params = match (&read, product) {
                        (LiveRead::Tables(live), Some(product)) => Some(
                            crate::param_readback::read_state(
                                l4,
                                product,
                                model,
                                target,
                                live.tables().mask,
                            )
                            .await,
                        ),
                        _ => None,
                    };
                    anyhow::Ok((read, params, identity))
                })
                .await;
            // Close the bus cleanly (release the gateway tunnel slot), issue #31.
            service.close().await;
            outcome
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))
}

/// Reads a device's live tables and shows what `apply` would change.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
    selection: crate::param_readback::Selection<'_>,
    tool_key_source: ToolKeySource<'_>,
    verbose: u8,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A parse error is a hard failure here (surfaced with the file detail).
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "no model in {}: `bussard plan` compares a device with its devices/<address>.toml; \
             run `bussard init` or `bussard import` first",
            dir.display()
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    let gateway = crate::conn_cmd::gateway_display(&config);

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
    let product = crate::param_readback::resolve(
        dir,
        selection,
        Some(&model),
        target,
        crate::param_readback::MissingProduct::Warn,
    )?;
    let model_ref = &model;
    let product_ref = product.as_ref();

    let (read, params, identity) = read_device(
        config,
        target,
        &overrides,
        tool_key_source,
        product_ref,
        Some(model_ref),
        crate::device_facts::cache(dir, true, overrides.refresh_facts),
    )?;
    let live_tables = match read {
        LiveRead::Tables(live) => live,
        LiveRead::UnsupportedMask { address, mask } => {
            report_unsupported_mask("plan", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let live = live_tables.tables();

    let report = plan(live, &desired);
    let built = crate::device_plan::build(
        &model,
        target,
        &gateway,
        dir,
        &live_tables,
        &report,
        params.as_ref(),
    );
    let identity = identity.map(|reported| {
        bussard_model::identity::IdentityCheck::compare(
            model.devices.get(&target).map(|d| &d.device),
            reported,
        )
    });
    if json {
        let mut out = to_json(live, &report, built.plan.clone());
        out.parameters = params.map(|p| p.readback);
        out.identity = identity;
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        if let Some(check) = identity.as_ref().filter(|c| c.is_drift()) {
            println!(
                "warning: {target}: {}; `bussard apply` refuses until `bussard flash {target}` \
                 loads the application the lock pins\n",
                check.summary()
            );
        }
        print!("{}", built.plan.render_text());
        if let Some(refusal) = &built.refusal {
            println!("  note: {refusal}");
        }
        if verbose > 0 {
            println!();
            print!(
                "{}",
                bussard_download::render_plan_text(target, live, &report)
            );
            if let Some(params) = &params {
                crate::param_readback::print_text(&params.readback, target);
            }
        }
        if !built.plan.is_empty() && built.refusal.is_none() {
            println!(
                "\nrun `bussard apply {target}` to write these changes (it asks once), or \
                 `bussard apply {target} --plan {}` to refuse if the device changes first.",
                built.plan.state_hash
            );
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

fn to_json(
    live: &DeviceTables,
    report: &PlanReport,
    device_plan: bussard_download::DevicePlan,
) -> PlanJson {
    let map = |pairs: &[bussard_download::ObjectGa]| {
        pairs
            .iter()
            .map(|p| ObjectGaJson {
                object: p.object,
                ga: p.ga.to_string(),
            })
            .collect()
    };
    let question = (!device_plan.is_empty()).then(|| device_plan.question());
    PlanJson {
        plan: device_plan,
        question,
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
        identity: None,
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
