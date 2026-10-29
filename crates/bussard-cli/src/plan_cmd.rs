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

/// Where the device's product puts a System 7 device's tables (see
/// [`bussard_download::sys7_table_bases`]); the corpus defaults without a
/// product.
pub(crate) fn table_bases(
    product: Option<&crate::param_readback::ProductSource>,
) -> bussard_download::Sys7TableBases {
    product
        .and_then(|p| p.app())
        .map(bussard_download::sys7_table_bases)
        .unwrap_or_default()
}

/// Reads a device's live tables on an open (and authorized) connection, picking
/// the reader by mask family (see [`bussard_download::read_live_tables_at`]).
/// With the device's `product`, a System 7 device that does not answer
/// `PID_TABLE_REFERENCE` is read where the product puts its tables.
pub(crate) async fn read_live_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    product: Option<&crate::param_readback::ProductSource>,
) -> anyhow::Result<LiveRead> {
    Ok(bussard_download::read_live_tables_at(l4, table_bases(product)).await?)
}

/// Reads the device's security individual address table (PID 54) when
/// `admit_tunnel_senders` has tunnelling addresses to admit (`tunnel` not
/// empty) and the device is System B (issue #297). `None` when it is not read
/// or the device refuses the read.
pub(crate) async fn read_admission_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    read: &LiveRead,
    tunnel: &[IndividualAddress],
) -> anyhow::Result<Option<Vec<bussard_download::SecureSenderEntry>>> {
    match read {
        LiveRead::Tables(live) if !tunnel.is_empty() && live.sys7().is_none() => {
            Ok(bussard_download::read_security_sender_table(l4).await?)
        }
        _ => Ok(None),
    }
}

/// Reads the device's group-object security flags (PID 61) on a secured
/// session (`secured`) of a System B device (issue #331), as the session's
/// last read. `None` when it is not read, or the device refuses or does not
/// answer the read: the flags are then unknown and the plan shows no
/// security-object change (the write still programs the whole object).
///
/// `known` is a plan's cached read that shows no pending security change
/// ([`bussard_service::security_change::unchanged_cached_flags`], issue
/// #336): it is returned instead of reading the device.
pub(crate) async fn read_security_flags<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    read: &LiveRead,
    secured: bool,
    known: Option<Vec<u8>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    match read {
        LiveRead::Tables(live) if secured && live.sys7().is_none() && known.is_some() => Ok(known),
        LiveRead::Tables(live) if secured && live.sys7().is_none() => {
            match bussard_download::read_security_flags(l4).await {
                Ok(flags) => Ok(flags),
                Err(err) => {
                    tracing::debug!("{}: PID 61 not read: {err}", l4.target());
                    Ok(None)
                }
            }
        }
        _ => Ok(None),
    }
}

/// The security-object change of `target` (issue #331): its PID 61 as read
/// (`live`) against the flags the model and the key store's group keys ask
/// for. `None` without a secured read of PID 61.
pub(crate) fn security_change(
    model: Option<&Model>,
    target: IndividualAddress,
    desired: &DesiredTables,
    group_keys: Option<
        &std::collections::HashMap<bussard_model::GroupAddress, bussard_secure::Key16>,
    >,
    live: Option<&[u8]>,
) -> Option<bussard_service::security_change::SecurityObjectChange> {
    let live = live?;
    let empty = std::collections::HashMap::new();
    let keys = group_keys.unwrap_or(&empty);
    let inputs = bussard_download::security_inputs_for(model, target, desired, keys);
    Some(
        bussard_service::security_change::SecurityObjectChange::compare(
            target, desired, &inputs, live,
        ),
    )
}

/// The `admit_tunnel_senders` comparison of `target` (issue #297), or `None`
/// when there is nothing to admit (the option is off, no tool key, no
/// tunnelling address) or the device is System 7, whose security object a
/// table write does not reprogram.
pub(crate) fn tunnel_admission(
    target: IndividualAddress,
    tunnel: &[IndividualAddress],
    sys7: bool,
    live: Option<Vec<bussard_download::SecureSenderEntry>>,
) -> Option<bussard_service::admission::TunnelAdmission> {
    if tunnel.is_empty() || sys7 {
        return None;
    }
    Some(bussard_service::admission::TunnelAdmission::new(
        target,
        tunnel,
        live.as_deref(),
    ))
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
    Option<Vec<bussard_download::SecureSenderEntry>>,
    Option<Vec<u8>>,
    Option<Vec<bussard_service::property_plan::PropertyRow>>,
);

/// Opens a read-only bus service, reads `target`'s live tables in one management
/// session and, when `product` is given and the tables read, the parameter
/// memory too. Shared by `plan` and `reconstruct` (issue #170).
///
/// With a tool key from `tool_key_source` every APDU, the device descriptor
/// read included, rides `A_SecureData`, so a KNX Data Secure device reports its
/// real mask instead of the `FFFF` it answers in the clear. Without one the
/// frames are exactly those of the plain path before KNX Secure existed.
#[allow(clippy::too_many_arguments)] // one read's context; a struct would only move it
pub(crate) fn read_device(
    config: ConnectionConfig,
    target: IndividualAddress,
    overrides: &ConnOverrides,
    tool_key_source: ToolKeySource<'_>,
    product: Option<&ProductSource>,
    model: Option<&Model>,
    mut facts: bussard_service::FactsCache,
    tunnel: &[IndividualAddress],
    properties: Option<&bussard_download::FlashPlan>,
    known_flags: Option<Vec<u8>>,
) -> anyhow::Result<DeviceRead> {
    let activated = crate::secure_key::model_activated(model, target);
    let (tool_key, factory_key) =
        crate::secure_key::resolve_session_keys(target, tool_key_source, activated)?;
    let presented_tool_key = tool_key.is_some();
    let options = L4Options {
        source: SourcePolicy::Check {
            skip: overrides.skip_address_check,
        },
        tool_key,
        factory_key,
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
                    // The facts and what the device says it is, for the lock
                    // comparison (issue #228, item 5).
                    let identity = crate::device_facts::identify(l4, &facts, None)
                        .await?
                        .check
                        .map(|check| check.device);
                    let read = read_live_tables(l4, product).await?;
                    let params = match (&read, product) {
                        (LiveRead::Tables(live), Some(product)) => {
                            let started = std::time::Instant::now();
                            let state = crate::param_readback::read_state(
                                l4,
                                product,
                                model,
                                target,
                                live.tables().mask,
                            )
                            .await;
                            // The parameter memory's reads plus its plan and
                            // decode (issue #367), a `--timing` phase.
                            crate::timing::record(
                                "parameter read",
                                started.elapsed(),
                                "bus reads, plan and decode",
                            );
                            Some(state)
                        }
                        _ => None,
                    };
                    // PID 54, for `admit_tunnel_senders` only (issue #297).
                    let senders = read_admission_table(l4, &read, tunnel).await?;
                    // PID 61 on a secured session (issue #331).
                    let flags =
                        read_security_flags(l4, &read, presented_tool_key, known_flags).await?;
                    // A property-only procedure (issue #390): no table reader
                    // speaks the mask, the properties it writes are the plan.
                    let rows = match (&read, properties) {
                        (LiveRead::UnsupportedMask { .. }, Some(plan)) => {
                            Some(bussard_service::property_plan::read_property_rows(l4, plan).await)
                        }
                        _ => None,
                    };
                    anyhow::Ok((read, params, identity, senders, flags, rows))
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
            "pending model changes since the last snapshot ({} change(s)):\n",
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
        crate::param_readback::MissingProduct::Warn,
    )?;
    let model_ref = &model;
    let product_ref = product.as_ref();
    let app = product_ref.and_then(|p| p.app());
    // A KNX IP interface (a `[knxnet]` table, no links): its KNXnet/IP
    // parameter object, plus the properties its property-only load
    // procedure writes when it has one, in one plan (issue #391).
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
    let desired = compute_desired(&model, target, app)?;
    // A property-only load procedure (issue #390): what `plan` reads instead
    // of tables.
    let properties =
        app.and_then(|a| bussard_service::property_plan::property_plan(a, Some(model_ref), target));

    // `admit_tunnel_senders` (issue #297): the tunnelling addresses to admit,
    // when the device is written secured.
    let material = crate::secure_key::resolve_material(
        target,
        tool_key_source,
        crate::secure_key::model_activated(Some(model_ref), target),
    )?;
    let secured = material.tool_key.is_some();
    let tunnel = crate::secure_key::admitted_tunnel(Some(model_ref), tool_key_source, secured)?;
    // The read budget of PID 61 (issue #336): a cached read is used when the
    // model asks for exactly those flags, so no security change is pending.
    let empty_keys = std::collections::HashMap::new();
    let security_inputs = bussard_download::security_inputs_for(
        Some(model_ref),
        target,
        &desired,
        material.group_keys.as_ref().unwrap_or(&empty_keys),
    );
    let known_flags = secured
        .then(|| {
            bussard_service::security_change::unchanged_cached_flags(
                dir,
                target,
                &desired,
                &security_inputs,
                overrides.refresh_facts,
            )
        })
        .flatten();
    let flags_cached = known_flags.is_some();
    let (read, params, identity, live_senders, live_flags, property_rows) = read_device(
        config,
        target,
        &overrides,
        tool_key_source,
        product_ref,
        Some(model_ref),
        crate::device_facts::cache(dir, true, overrides.refresh_facts),
        &tunnel,
        properties.as_ref(),
        known_flags,
    )?;
    if let (false, Some(flags)) = (flags_cached, live_flags.as_deref()) {
        bussard_service::security_change::remember_flags(dir, target, flags);
    }
    let live_tables = match read {
        LiveRead::Tables(live) => live,
        LiveRead::UnsupportedMask { address, mask } => {
            if let (Some(rows), Some(app)) = (property_rows, app) {
                return print_property_plan(target, mask, &app.id, &rows, json);
            }
            report_unsupported_mask("plan", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let live = live_tables.tables();

    let report = plan(live, &desired);
    let admission = tunnel_admission(target, &tunnel, live_tables.sys7().is_some(), live_senders);
    let mut built = crate::device_plan::build(
        &model,
        target,
        &gateway,
        dir,
        &live_tables,
        &report,
        params.as_ref(),
    );
    if let Some(admission) = &admission {
        admission.add_to(&mut built.plan, &report);
    }
    // A group address that left or joined Data Secure (issue #331).
    if let Some(change) = security_change(
        Some(model_ref),
        target,
        &desired,
        material.group_keys.as_ref(),
        live_flags.as_deref(),
    ) {
        change.add_to(&mut built.plan, &report, Some(model_ref));
    }
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
        crate::output::print(crate::output::schema::PLAN, &out)?;
    } else {
        if let Some(check) = &identity {
            let line = crate::device_facts::identity_line(target, check);
            if check.is_drift() {
                println!(
                    "{line}; `bussard apply` refuses until `bussard flash {target}` loads the \
                     application the lock pins\n"
                );
            } else {
                println!("{line}\n");
            }
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
/// device with no links unless its application `app` has no group objects
/// (see [`bussard_download::desired_tables_for_app`]).
pub(crate) fn compute_desired(
    model: &Model,
    target: IndividualAddress,
    app: Option<&bussard_prod::ApplicationProgram>,
) -> anyhow::Result<DesiredTables> {
    Ok(bussard_download::desired_tables_for_app(
        model, target, app,
    )?)
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
    let noop = !rows.iter().any(|r| r.differs());
    if json {
        let out = serde_json::json!({
            "address": target.to_string(),
            "mask": format!("{mask:04X}"),
            "application": app_id,
            "method": "flash",
            "property_procedure": rows,
            "noop": noop,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print!(
            "{}",
            bussard_service::property_plan::render_text(target, app_id, rows)
        );
    }
    Ok(ExitCode::SUCCESS)
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
    // The tables are rewritten for a security-object change too (issue #297),
    // and a System B group-object table that differs is reloaded (issue #540).
    let noop = report.is_noop()
        && !device_plan.writes.security_object
        && device_plan.writes.group_object_table.is_none();
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
        noop,
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
