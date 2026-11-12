//! The `bussard plan` subcommand — diff the model against a device's live tables.
//!
//! Reads the device's group-address and association tables over the bus,
//! computes the desired tables from the links in the model's device file for that device (via
//! `bussard_download`), and shows what `apply` would change: additions,
//! removals, unchanged links, resulting table sizes, and the load-op sequence.
//!
//! Two device families are read here, behind one seam ([`bussard_service::program::read`]):
//! **System B** (mask `x7B0`) serves its tables as interface-object property
//! arrays (`bussard_mgmt::tables`); **System 7** (mask `0705` / `0701`) keeps
//! them in absolute memory at `0x4000` / `0x4201`
//! (`bussard_download::tables_sys7`, issue #91). Both decode into the same
//! [`DeviceTables`] shape, so the diff and the report below are family-agnostic.
//!
//! This command is **read-only on the bus** — it never writes a load control or
//! a property, so it is safe to run against a live installation. A KNX Data
//! Secure device is read with `--keyring` / `--tool-key` (issue #170), see
//! [`read_device`].

use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::{IndividualAddress, Model};
use bussard_service::download::{DesiredTables, PlanReport};
use bussard_service::mgmt::tables::DeviceTables;
use bussard_service::mgmt::{MaskProfile, system_type};
use bussard_service::program;
use bussard_service::transport::ConnectionConfig;
use bussard_service::{L4Options, SourcePolicy, WritePolicy};

use crate::cli::{ProductSelection, Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{ConnOverrides, load_model_required, open_service, resolve_config};
use bussard_service::params::ProductSource;
use bussard_service::program::plan_outcome::{PlanOutcome, PlanParts, PropertyPlan};
use bussard_service::secure::ToolKeySource;

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

/// What `plan` and `reconstruct` read besides the device's identity and
/// tables ([`bussard_service::program::read::ReadRequest`]).
pub(crate) struct Reading<'a> {
    /// The product data the parameter memory is decoded with.
    pub product: Option<&'a ProductSource>,
    /// The tunnelling addresses `admit_tunnel_senders` admits (PID 54).
    pub tunnel: &'a [IndividualAddress],
    /// The PID 61 cache.
    pub flags_cache: program::read::FlagsCache<'a>,
    /// A property-only load procedure whose properties are read.
    pub properties: Option<&'a bussard_service::download::FlashPlan>,
}

/// Opens a read-only bus service and reads `target` in one management
/// session ([`bussard_service::program::read`]). Shared by `plan` and
/// `reconstruct` (issue #170).
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
    model: Option<&Model>,
    mut facts: bussard_service::FactsCache,
    reading: Reading<'_>,
) -> anyhow::Result<program::read::DeviceRead> {
    let activated = bussard_service::secure::model_activated(model, target);
    let (tool_key, factory_key) = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_session_keys(target, tool_key_source, activated)
    })?;
    let presented_tool_key = tool_key.is_some();
    // Authorize (free access) before reading, as ETS does (issue #52 finding
    // #1) and as System 7 requires before any memory access; skipped for a
    // device whose facts say it never answers (#209).
    let options = L4Options::secured(
        SourcePolicy::Check {
            skip: overrides.skip_address_check,
        },
        tool_key,
        bussard_service::secure::SequenceHighWater::new(),
    )
    .with_factory_key(factory_key)
    .with_authorize(bussard_service::status::read_only_authorize(
        &mut facts, target,
    ));
    let request = program::read::ReadRequest {
        target,
        model,
        product: reading.product,
        facts: &facts,
        tunnel: reading.tunnel,
        secured: presented_tool_key,
        flags_cache: reading.flags_cache,
        properties: reading.properties,
    };
    let runtime = tokio::runtime::Runtime::new()?;
    let read = runtime
        .block_on(async {
            let service = open_service(config, WritePolicy::ReadOnly).await?;
            let read = program::read::read_device(&service, &options, &request).await;
            // Close the bus cleanly (release the gateway tunnel slot), issue #31.
            service.close().await;
            anyhow::Ok(read?)
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))?;
    if let Some(elapsed) = read.parameter_time {
        // The parameter memory's reads plus its plan and decode (issue
        // #367), a `--timing` phase.
        crate::timing::record("parameter read", elapsed, "bus reads, plan and decode");
    }
    Ok(read)
}

/// `bussard plan`.
#[derive(Debug, clap::Args)]
pub(crate) struct PlanArgs {
    /// The device to plan for, e.g. `1.1.4` (mutually exclusive with
    /// `--line`).
    #[arg(value_name = "ADDRESS", required_unless_present = "line")]
    address: Option<String>,
    /// Plan every device the project has on this line, e.g. `1.1`, in address
    /// order, and print one summary table.
    // Issue #100.
    #[arg(long, value_name = "LINE", conflicts_with = "address")]
    line: Option<String>,
    #[command(flatten)]
    product: ProductSelection,
    #[command(flatten)]
    tool_key: ToolKey,
}

impl Run for PlanArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
            .json()
            .tool_key(self.tool_key.tool_key.is_some())
            .device_management()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let tool_keys = g.tool_keys(self.tool_key.tool_key.as_deref());
        match (&self.line, &self.address) {
            (Some(line), _) => crate::line_cmd::run_plan(line, tool_keys, g),
            (None, Some(address)) => run(address, self.product.selection(), tool_keys, g),
            // clap requires ADDRESS without --line.
            (None, None) => anyhow::bail!("give a device ADDRESS or --line"),
        }
    }
}

/// Reads a device's live tables and shows what `apply` would change.
fn run(
    address: &str,
    selection: bussard_service::params::Selection<'_>,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    let (dir, json, overrides, verbose) = (g.dir(), g.json, g.mgmt_with_facts(), g.verbose);
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A parse error is a hard failure here (surfaced with the file detail).
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                "`bussard plan` compares a device with its devices/<address>.toml"
            )
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    let gateway = crate::conn_cmd::gateway_display(&config);

    // Issue #112: say in plain sentences what the model now asks for that the
    // last snapshot did not, before the com-object table below says it in
    // numbers. Text output only — `--json` stays a single JSON document.
    if !json && let Some(pending) = crate::history_cmd::pending_changes(dir) {
        println!(
            "pending project changes since the last snapshot ({} change(s)):\n",
            pending.changes.len()
        );
        print!("{}", bussard_model::change::render_text(&pending.changes));
        println!();
    }
    // Whatever was edited outside bussard is now recorded, so it cannot be lost.
    crate::history_cmd::capture_external_edit(dir);

    // The product file the parameter read-back decodes with (issue #119), when
    // one is given or cached.
    // A read-only command only warns about an override that contradicts the
    // lock (issue #228, item 4).
    if let Some(device) = model.devices.get(&target)
        && let Some(conflict) = crate::lock_pin::override_conflict(
            &device.device,
            selection.product,
            selection.application,
        )?
    {
        eprintln!("warning: {conflict}");
    }
    let product = crate::param_readback::resolve(
        dir,
        selection,
        Some(&model),
        target,
        bussard_service::params::MissingProduct::Warn,
    )?;
    let model_ref = &model;
    let product_ref = product.as_ref();
    let app = product_ref.and_then(|p| p.app());
    // A KNX IP interface (a `[knxnet]` table, no links): its KNXnet/IP
    // parameter object, plus the properties its property-only load
    // procedure writes when it has one, in one plan (issue #391).
    crate::interface_cmd::refuse_device_management(&overrides, &model, target)?;
    if crate::interface_cmd::interface_only(&model, target).is_some() {
        return crate::interface_cmd::plan(
            target,
            dir,
            json,
            &model,
            config,
            &overrides,
            tool_key_source,
            verbose,
            crate::interface_cmd::Procedure {
                app_id: app.map(|a| a.id.as_str()),
                plan: app
                    .and_then(|a| {
                        bussard_service::property_plan::property_plan(a, Some(model_ref), target)
                    })
                    .as_ref(),
            },
        );
    }
    let desired = compute_desired(&model, target, product_ref)?;
    // A property-only load procedure (issue #390): what `plan` reads instead
    // of tables.
    let properties =
        app.and_then(|a| bussard_service::property_plan::property_plan(a, Some(model_ref), target));

    // `admit_tunnel_senders` (issue #297): the tunnelling addresses to admit,
    // when the device is written secured.
    let material = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_material(
            target,
            tool_key_source,
            bussard_service::secure::model_activated(Some(model_ref), target),
        )
    })?;
    let tunnel = crate::secure_key::admitted_tunnel(
        Some(model_ref),
        tool_key_source,
        material.tool_key.is_some(),
    )?;
    // The supported-device verdict (issue #1089): what `apply` would decide
    // on this gateway.
    let support = bussard_service::support::verdict_at(Some(model_ref), target).view_on(&config);
    let mut read = read_device(
        config,
        target,
        &overrides,
        tool_key_source,
        Some(model_ref),
        crate::conn_cmd::facts_cache(dir, true, overrides.refresh_facts),
        Reading {
            product: product_ref,
            tunnel: &tunnel,
            // The read budget of PID 61 (issue #336): a cached read is used
            // when the model asks for exactly those flags.
            flags_cache: program::read::FlagsCache::Plan {
                dir,
                refresh: overrides.refresh_facts,
                desired: &desired,
                group_keys: material.group_keys.as_ref(),
            },
            properties: properties.as_ref(),
        },
    )?;
    let property_rows = read.property_rows.take();
    let read = match read.into_tables() {
        Ok(read) => read,
        Err((address, mask)) => {
            if let (Some(rows), Some(app)) = (property_rows, app) {
                return print_property_plan(target, mask, &app.id, &rows, json);
            }
            report_unsupported_mask("plan", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let live = read.live.tables();
    // The plan in the model's words, with the tunnel admission (issue #297)
    // and the security-object change (issue #331).
    let planned = program::plan::plan_device(
        &program::plan::PlanInputs {
            model: model_ref,
            target,
            gateway: &gateway,
            dir,
            desired: &desired,
            tunnel: &tunnel,
            group_keys: material.group_keys.as_ref(),
            parameters_skipped: None,
        },
        &read,
    );
    let (report, built) = (&planned.report, &planned.built);
    let identity = read.check().cloned();
    let params = read.params.as_ref();
    if json {
        let mut out = PlanOutcome::new(PlanParts {
            target,
            live,
            report,
            built,
            device_plan: built.plan.clone(),
            secured: material.tool_key.is_some(),
            identity,
            parameters: params.map(|p| p.readback.clone()),
        });
        out.support = Some(support);
        crate::output::report(&out)?;
    } else {
        let style = crate::style::Style::stdout();
        let line = crate::describe_cmd::support_line(&support);
        if support.override_needed {
            println!(
                "{}\n",
                style.warn(&format!("{line}; `bussard apply` refuses without it"))
            );
        } else {
            println!("{}\n", style.dim(&line));
        }
        if let Some(check) = &identity {
            let line = bussard_service::identity_line(target, check);
            if check.is_drift() {
                println!(
                    "{}\n",
                    style.warn(&format!(
                        "{line}; `bussard apply` refuses until `bussard flash {target}` loads \
                         the application your project pins"
                    ))
                );
            } else {
                println!("{}\n", style.dim(&line));
            }
        }
        print!(
            "{}",
            crate::plan_view::render(&built.plan, crate::style::Style::stdout())
        );
        if let Some(refusal) = &built.refusal {
            println!("  {}", style.warn(&format!("note: {refusal}")));
        }
        if verbose > 0 {
            println!();
            print!(
                "{}",
                bussard_service::download::render_plan_text(target, live, report)
            );
            if let Some(params) = params {
                crate::param_readback::print_text(&params.readback, target);
            }
        }
        if !built.plan.is_empty() && built.refusal.is_none() {
            let apply = format!("bussard apply {target}");
            let pinned = format!("bussard apply {target} --plan {}", built.plan.state_hash);
            print!(
                "\n{}",
                style.next_steps(&[
                    (apply.as_str(), "writes these changes (it asks once)"),
                    (
                        pinned.as_str(),
                        "the same, but refuses if the device changed since this plan"
                    ),
                ])
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Computes the desired tables from the model's links for `target`, refusing a
/// device with no links unless its application has no group objects
/// ([`program::plan::desired_tables`]).
pub(crate) fn compute_desired(
    model: &Model,
    target: IndividualAddress,
    product: Option<&ProductSource>,
) -> anyhow::Result<DesiredTables> {
    program::plan::desired_tables(model, target, product).map_err(anyhow::Error::msg)
}

/// Prints the plan of a property-only load procedure (issue #390): each
/// property it writes, as the device holds it and as the model asks.
fn print_property_plan(
    target: IndividualAddress,
    mask: u16,
    app_id: &str,
    rows: &[bussard_service::property_plan::PropertyRow],
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        crate::output::report(&PropertyPlan::new(target, mask, app_id, rows))?;
    } else {
        print!(
            "{}",
            bussard_service::property_plan::render_text(target, app_id, rows)
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the reconstruct-style plan with additions/removals prominent.
pub(crate) fn print_text(target: IndividualAddress, live: &DeviceTables, report: &PlanReport) {
    print!(
        "{}",
        bussard_service::download::render_plan_text(target, live, report)
    );
    if !report.is_noop() {
        let apply = format!("bussard apply {target}");
        print!(
            "\n{}",
            crate::style::Style::stdout()
                .next_steps(&[(apply.as_str(), "writes these changes (it asks first)")])
        );
    }
}
