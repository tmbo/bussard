//! `bussard plan` and `bussard apply` for a KNX IP interface (issue #391): the
//! `[knxnet]` table of its device file against its KNXnet/IP parameter object.
//!
//! A device whose file has a `[knxnet]` table and no links is planned here
//! instead of through its group tables: the IP assignment, the static address
//! set, the friendly name and the tunnelling addresses, as property writes on
//! the KNXnet/IP parameter object. The read, the plan and the write with its
//! read-back are [`bussard_service::knxnet`]'s, the same functions the MCP
//! `knx_plan_device` / `knx_apply_device` call.
//!
//! `apply` refuses a write that changes the IP assignment or the static
//! address set or the tunnel addresses (PID 53) of the interface the command
//! tunnels through, unless `--allow-self-reconfigure`: the
//! tunnel drops once the interface applies it.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::knxnet::KnxnetConfig;
use bussard_model::{IndividualAddress, Model};
use bussard_service::knxnet::InterfacePlanOutcome;
use bussard_service::knxnet::{
    self, InterfacePlan, InterfaceRead, InterfaceReadPlan, InterfaceRequest, SessionLink,
    apply_interface, write_interface_backup,
};
use bussard_service::property_plan::PropertyRow;
use bussard_service::transport::ConnectionConfig;
use bussard_service::{L4Options, WritePolicy};

use crate::conn_cmd::{BusSession, ConnOverrides, enforce_write_gate, gateway_display};

/// The `[knxnet]` table of `target` when the device is planned as an IP
/// interface ([`bussard_service::knxnet::interface_config`]).
pub(crate) fn interface_only(model: &Model, target: IndividualAddress) -> Option<&KnxnetConfig> {
    bussard_service::knxnet::interface_config(model, target)
}

/// Refuses `--device-management` for a device that is not planned as an IP
/// interface: the connection reaches the KNXnet/IP server's own device only
/// (issue #523).
///
/// # Errors
///
/// The flag is set and `target` has no `[knxnet]` table (or has links).
pub(crate) fn refuse_device_management(
    overrides: &ConnOverrides,
    model: &Model,
    target: IndividualAddress,
) -> anyhow::Result<()> {
    if overrides.device_management && interface_only(model, target).is_none() {
        anyhow::bail!(
            "--device-management reaches the KNX IP interface itself; {target} is not planned as \
             one (devices/{target}.toml needs a [knxnet] table and no links)"
        );
    }
    Ok(())
}

/// The property-only load procedure of the interface's application (issue
/// #390), when its product data is at hand: `plan` reads the properties it
/// writes on the same session and shows them after the `[knxnet]` changes;
/// `bussard flash` writes them.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Procedure<'a> {
    /// The application program id.
    pub app_id: Option<&'a str>,
    /// The property-only download of the application.
    pub plan: Option<&'a bussard_service::download::FlashPlan>,
}

/// What one interface session needs besides the bus.
struct Session<'a> {
    target: IndividualAddress,
    dir: &'a Path,
    model: &'a Model,
    config: &'a KnxnetConfig,
    overrides: &'a ConnOverrides,
    tool_key_source: bussard_service::secure::ToolKeySource<'a>,
}

impl Session<'_> {
    /// The read options: the checked `source`, the tool key when the model
    /// says the device is Secure-activated.
    fn options(&self, source: IndividualAddress) -> anyhow::Result<L4Options> {
        let activated = bussard_service::secure::model_activated(Some(self.model), self.target);
        let tool_key = crate::timing::time("tool keys", || {
            bussard_service::secure::resolve(self.target, self.tool_key_source, activated)
        })?;
        Ok(L4Options::secured(
            source,
            tool_key,
            bussard_service::secure::SequenceHighWater::new(),
        ))
    }

    /// The device's name in the model.
    fn name(&self) -> String {
        self.model
            .devices
            .get(&self.target)
            .map(|d| d.device.name.clone())
            .unwrap_or_default()
    }
}

/// Reads the interface on `service` and plans `session.config` against it;
/// with `procedure`, also reads the properties that procedure writes
/// ([`bussard_service::knxnet::read_and_plan`]).
fn read_and_plan(
    runtime: &tokio::runtime::Runtime,
    bus: &BusSession,
    session: &Session<'_>,
    options: &L4Options,
    link: &SessionLink,
    procedure: Option<&bussard_service::download::FlashPlan>,
) -> anyhow::Result<(InterfaceRead, InterfacePlan, Option<Vec<PropertyRow>>)> {
    let target = session.target;
    let facts = crate::conn_cmd::facts_cache(session.dir, true, session.overrides.refresh_facts);
    let req = InterfaceRequest {
        target,
        config: session.config,
        device: session.model.devices.get(&target).map(|d| &d.device),
        facts: &facts,
        link,
        procedure,
    };
    match runtime.block_on(knxnet::read_and_plan(bus.service(), options, req)) {
        Ok(InterfaceReadPlan { read, plan, rows }) => Ok((read, plan, rows)),
        Err(err @ bussard_service::ServiceError::Refused(_)) => Err(err.into()),
        Err(err) => Err(crate::secure_key::secure_hint(
            target,
            options.tool_key.is_some(),
            err.into(),
        )),
    }
}

/// Prints the plan as text, with the writes on the wire under `-v`.
fn print_plan(
    plan: &InterfacePlan,
    device_plan: &bussard_service::download::DevicePlan,
    verbose: bool,
) {
    print!(
        "{}",
        crate::plan_view::render(device_plan, crate::style::Style::stdout())
    );
    if verbose {
        for step in &plan.steps {
            println!("  write: {}", step.wire());
        }
    }
}

/// The link a session through `config` has, with its checked `source`.
fn link_of(config: &ConnectionConfig, source: IndividualAddress) -> SessionLink {
    SessionLink {
        source: Some(source),
        gateway: config.gateway.map(|g| *g.ip()),
    }
}

/// `bussard plan <interface>`: read the KNXnet/IP parameter object and show
/// what `apply` would write. Read-only on the bus.
#[allow(clippy::too_many_arguments)] // mirrors `plan_cmd::run`
pub(crate) fn plan(
    target: IndividualAddress,
    dir: &Path,
    json: bool,
    model: &Model,
    config: ConnectionConfig,
    overrides: &ConnOverrides,
    tool_key_source: bussard_service::secure::ToolKeySource<'_>,
    verbose: u8,
    procedure: Procedure<'_>,
) -> anyhow::Result<ExitCode> {
    let Some(knxnet) = interface_only(model, target) else {
        anyhow::bail!("{target} is not planned as an IP interface");
    };
    let session = Session {
        target,
        dir,
        model,
        config: knxnet,
        overrides,
        tool_key_source,
    };
    let gateway = gateway_display(&config);
    let runtime = tokio::runtime::Runtime::new()?;
    let crate::interface_session::InterfaceSession {
        bus,
        source,
        config,
    } = crate::interface_session::open(
        &runtime,
        config,
        WritePolicy::ReadOnly,
        target,
        tool_key_source.keyring,
        overrides.skip_address_check,
    )?;
    let options = session.options(source)?;
    let (read, plan, rows) = read_and_plan(
        &runtime,
        &bus,
        &session,
        &options,
        &link_of(&config, source),
        procedure.plan,
    )?;
    drop(bus);
    let backup_dir = bussard_service::download::backup::backups_root(dir)
        .display()
        .to_string();
    let mut device_plan = plan.device_plan(target, &session.name(), &gateway, backup_dir);
    device_plan
        .notes
        .extend(bussard_service::knxnet::parameters_note(model, target));
    let refusal = plan.refusal(false);
    if json {
        let procedure_text = match (&rows, procedure.app_id) {
            (Some(rows), Some(app_id)) => format!(
                "\n{}",
                bussard_service::property_plan::render_text(target, app_id, rows)
            ),
            _ => String::new(),
        };
        let out = InterfacePlanOutcome::new(
            &plan,
            device_plan,
            read.mask,
            options.tool_key.is_some(),
            read.check,
            rows,
            &procedure_text,
        );
        crate::output::report(&out)?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("{}\n", bussard_service::identity_line(target, &read.check));
    print_plan(&plan, &device_plan, verbose > 0);
    if let (Some(rows), Some(app_id)) = (&rows, procedure.app_id) {
        println!();
        print!(
            "{}",
            bussard_service::property_plan::render_text(target, app_id, rows)
        );
    }
    if !plan.is_empty() {
        match &refusal {
            Some(why) if plan.refusals.is_empty() => println!(
                "\n`bussard apply {target}` refuses this without --allow-self-reconfigure: {why}"
            ),
            Some(why) => println!("\n`bussard apply {target}` refuses this: {why}"),
            None => {
                let apply = format!("bussard apply {target}");
                let pinned = format!("bussard apply {target} --plan {}", device_plan.state_hash);
                print!(
                    "\n{}",
                    crate::style::Style::stdout().next_steps(&[
                        (apply.as_str(), "writes these changes (it asks once)"),
                        (
                            pinned.as_str(),
                            "the same, but refuses if the device changed since this plan"
                        ),
                    ])
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// What `apply <interface>` takes beyond the model and the connection.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InterfaceApplyInputs<'a> {
    /// `--yes`.
    pub yes: bool,
    /// `--allow-remote-gateway`.
    pub allow_remote_gateway: bool,
    /// `--plan <hash>`.
    pub plan_hash: Option<&'a str>,
    /// `--allow-self-reconfigure`.
    pub allow_self_reconfigure: bool,
}

/// `bussard apply <interface>`: read, plan, refuse or ask once, back up the
/// values as read, write, read back.
pub(crate) fn apply(
    target: IndividualAddress,
    dir: &Path,
    model: &Model,
    config: ConnectionConfig,
    overrides: &ConnOverrides,
    tool_key_source: bussard_service::secure::ToolKeySource<'_>,
    inputs: InterfaceApplyInputs<'_>,
) -> anyhow::Result<ExitCode> {
    let Some(knxnet) = interface_only(model, target) else {
        anyhow::bail!("{target} is not planned as an IP interface");
    };
    let session = Session {
        target,
        dir,
        model,
        config: knxnet,
        overrides,
        tool_key_source,
    };
    enforce_write_gate(&config, inputs.allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    let runtime = tokio::runtime::Runtime::new()?;
    let crate::interface_session::InterfaceSession {
        bus,
        source,
        config,
    } = crate::interface_session::open(
        &runtime,
        config,
        WritePolicy::transmit(inputs.allow_remote_gateway),
        target,
        tool_key_source.keyring,
        overrides.skip_address_check,
    )?;
    let options = session.options(source)?;
    let (read, plan, _) = read_and_plan(
        &runtime,
        &bus,
        &session,
        &options,
        &link_of(&config, source),
        None,
    )?;
    eprintln!("{}", bussard_service::identity_line(target, &read.check));
    if let Some(err) = bussard_service::drift_refusal(target, &read.check, "apply to") {
        eprintln!("{err}");
        return Ok(ExitCode::FAILURE);
    }
    let backup_root = bussard_service::download::backup::backups_root(dir);
    let device_plan = plan.device_plan(
        target,
        &session.name(),
        &gateway,
        backup_root.display().to_string(),
    );
    if let Some(hash) = inputs.plan_hash
        && !hash.trim().eq_ignore_ascii_case(&device_plan.state_hash)
    {
        eprintln!(
            "refusing to apply to {target}: the device state no longer matches the plan (plan {}, \
             device now {}). Run `bussard plan {target}` again and approve the new plan.",
            hash.trim(),
            device_plan.state_hash
        );
        return Ok(ExitCode::FAILURE);
    }
    print_plan(&plan, &device_plan, true);
    if plan.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(why) = plan.refusal(inputs.allow_self_reconfigure) {
        eprintln!("refusing to apply to {target}: {why}");
        return Ok(ExitCode::FAILURE);
    }
    if !crate::confirm::confirm(
        inputs.yes,
        &device_plan.question(),
        &format!("apply {target} via {gateway}"),
    )? {
        eprintln!("aborted — no changes written.");
        return Ok(ExitCode::FAILURE);
    }
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("apply")
            .with_args([target.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before writing the KNXnet/IP parameter object"),
    );
    let Some(before) = &read.knxnet else {
        anyhow::bail!("{target}: no KNXnet/IP parameter object");
    };
    let backup = write_interface_backup(dir, target, before)
        .context("writing the pre-apply backup (refusing to write without a backup)")?;
    println!("backup written to {}", backup.display());

    let facts = crate::conn_cmd::facts_cache(dir, true, false);
    let mut established = read.established;
    let applied = runtime.block_on(bus.service().with_l4(target, &options, async |l4| {
        anyhow::Ok(
            apply_interface(
                l4,
                target,
                session.config,
                &plan,
                Some((&facts, &mut established)),
            )
            .await,
        )
    }));
    drop(bus);
    let applied = match applied {
        Ok(applied) => applied,
        Err(err) => {
            eprintln!(
                "\nERROR: apply {target}: {err:#}\nNothing is known to be written. The values \
                 before the apply are in {}.",
                backup.display()
            );
            return Ok(ExitCode::FAILURE);
        }
    };
    for note in &applied.readback.notes {
        eprintln!("warning: {note}");
    }
    match applied.failure() {
        Some(failure) => {
            eprintln!(
                "\nERROR: apply {target}: {failure}\nThe values before the apply are in {}; \
                 run `bussard plan {target}` to see what the device holds now.",
                backup.display()
            );
            if plan.self_reconfigure.is_some() {
                eprintln!(
                    "This write reconfigured the interface the command tunnelled through; a \
                     read-back that did not reach it is expected. Plan {target} again through \
                     its new address."
                );
            }
            Ok(ExitCode::FAILURE)
        }
        None => {
            println!(
                "\napply verified: {} propert{} written to {target}, read back and compared \
                 with the model: {}",
                applied.written,
                if applied.written == 1 { "y" } else { "ies" },
                applied.readback.summary()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
