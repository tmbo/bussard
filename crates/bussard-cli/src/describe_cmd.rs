//! The `bussard describe` subcommand — introspect a device's interface objects
//! and their properties over the bus (issue #72).
//!
//! Connects to a single device, discovers its interface objects (by probing
//! `PID_OBJECT_TYPE` per index, the same discovery `reconstruct` uses), and for
//! each object enumerates its properties with `A_PropertyDescription_Read`,
//! printing each property's PID (with a name when known), data type, element
//! count and read/write access levels as a table.
//!
//! The objects and property descriptions are device facts (issue #209): the
//! first describe stores them under `<dir>/.bussard/facts/<ia>.toml`, and a
//! later one prints them from there once the device's mask and application id
//! still match, instead of sending one description read per property. `--full`
//! walks the descriptions again; `--refresh-facts` re-reads everything.
//!
//! The command is **read-only on the bus**: it only ever sends
//! `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` (for object discovery) and
//! `A_PropertyDescription_Read`. It never writes.

use std::process::ExitCode;

use anyhow::Context;
use bussard_model::IndividualAddress;
use bussard_service::WritePolicy;
use bussard_service::describe::{
    DescribeReport, DescribeRequest, PlainManagement, RunError, SecuredManagement, Walk,
};

use crate::cli::{Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{load_model_required, resolve_config};
use crate::style::{Cell, Style, Table, Tone};

/// `bussard describe`.
#[derive(Debug, clap::Args)]
pub(crate) struct DescribeArgs {
    /// The device to introspect, e.g. `1.1.4`.
    #[arg(value_name = "ADDRESS")]
    address: String,
    /// Skip nothing: walk every object's property descriptions again, even
    /// when the device facts (`<dir>/.bussard/facts/<ia>.toml`) already
    /// hold them.
    #[arg(long)]
    full: bool,
    #[command(flatten)]
    tool_key: ToolKey,
}

impl Run for DescribeArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
            .json()
            .tool_key(self.tool_key.tool_key.is_some())
            .device_management()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(&self, g)
    }
}

/// Runs `bussard describe`.
fn run(args: &DescribeArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (address, dir, json, overrides) = (args.address.as_str(), g.dir(), g.json, g.mgmt());
    let tool_key_source = g.tool_keys(args.tool_key.tool_key.as_deref());
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let name = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| d.device.name.clone());
    // KNX Data Secure (issue #71, spec §6.2): a security-activated device
    // refuses the plain reads, so `describe` takes the same tool-key surfaces
    // as `flash`; a keyring without an entry for the target serves the tunnel
    // only (issue #189).
    let keys = crate::timing::time("tool keys", || {
        bussard_service::describe::session_keys(model.as_ref(), target, tool_key_source)
    })?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Device facts live next to the model; without one they are read each time.
    let mut facts = crate::conn_cmd::facts_cache(dir, model.is_some(), g.refresh_facts);
    // Authorize (free access) as ETS does before configuration access (issue
    // #52 finding #1), best-effort for a read; skipped for a device the facts
    // say never answers it.
    let authorize = bussard_service::status::read_only_authorize(&mut facts, target);

    let runtime = tokio::runtime::Runtime::new()?;
    // Read-only on the bus. The interface itself may be read over a device
    // management connection (issue #523, see `interface_session`).
    let session = crate::interface_session::open(
        &runtime,
        config,
        WritePolicy::ReadOnly,
        target,
        tool_key_source.keyring,
        overrides.skip_address_check,
    )?;
    let service = session.bus.service();
    let request = DescribeRequest {
        target,
        model: model.as_ref(),
        dir: Some(dir),
        keys,
        source: session.source.into(),
        authorize,
        walk: Walk::Facts {
            facts: &facts,
            full: args.full,
        },
    };
    let outcome = runtime.block_on(async {
        let outcome = bussard_service::describe::run(service, &request, None).await;
        service.close().await;
        outcome
    });
    let report = match (outcome.walk, outcome.report) {
        (Ok(walked), Some(report)) => {
            if let Some(note) = &walked.facts_note
                && !json
            {
                eprintln!("{note}");
            }
            // The serial number goes into the lock (issue #752).
            if let (Some(serial), Some(check)) = (&walked.serial, &outcome.identity) {
                crate::keys_cmd::learn_serials(
                    dir,
                    model.as_ref(),
                    &[(target, serial.clone(), check.verdict)],
                )
                .print(json);
            }
            report
        }
        (Err(_), _) if outcome.on_factory_key => {
            return Err(crate::secure_key::secure_hint(
                target,
                outcome.presented_tool_key,
                anyhow::Error::new(crate::secure_key::FactoryKeyAnswered(
                    bussard_service::identity::factory_key_message(target),
                )),
            ));
        }
        (Err(err), _) => {
            return Err(crate::secure_key::secure_hint(
                target,
                outcome.presented_tool_key,
                run_error(err),
            ));
        }
        (Ok(_), None) => anyhow::bail!("{target}: the describe read no device descriptor"),
    };
    if json {
        crate::output::report(&report)?;
    } else {
        print_text(&report, name.as_deref());
    }
    if let Some(error) = &report.reason {
        eprintln!("error: {error}");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// A failed describe session as the error it was before the walk moved to
/// the service: the management and service errors stay downcastable for
/// [`crate::secure_key::secure_hint`].
fn run_error(err: RunError) -> anyhow::Error {
    match err {
        RunError::Session(err) => err.into(),
        RunError::Mgmt(err) => err.into(),
        other => anyhow::Error::new(other),
    }
}

/// Prints the aligned human-readable report.
/// `group keys 1500, security IAs 5000, P2P keys 100`, "not declared" for a
/// figure the product leaves out.
fn table_capacity_line(tables: &bussard_model::param_model::DataSecureCapacity) -> String {
    let n = |v: Option<u32>| v.map_or_else(|| "not declared".to_string(), |v| v.to_string());
    format!(
        "group keys {}, security individual addresses {}, P2P keys {}",
        n(tables.group_key_table_entries),
        n(tables.individual_address_entries),
        n(tables.p2p_key_table_entries)
    )
}

fn print_text(report: &DescribeReport, name: Option<&str>) {
    print!("{}", render_text(report, name, Style::stdout()));
}

/// The report as text: the heading, the serial number, KNX Secure in the
/// project and in this run, the identity, KNXnet/IP and one property table
/// per interface object.
fn render_text(report: &DescribeReport, name: Option<&str>, style: Style) -> String {
    let mut out = crate::status_cmd::device_heading(
        &report.address,
        name,
        report.mask.as_deref().unwrap_or("?"),
        report.system_type.as_deref().unwrap_or("?"),
        style,
    );
    let label = |text: &str| style.dim(&format!("{text:<22}"));
    if let Some(serial) = &report.serial {
        out.push_str(&format!(
            "  {}{}\n",
            label("serial number"),
            serial.to_uppercase()
        ));
    }
    if let Some(sec) = &report.secure {
        if let Some(model) = &sec.model {
            let state = if model.activated {
                "secured"
            } else if model.secure_capable {
                "supports Secure, not secured"
            } else {
                "does not support Secure"
            };
            let certificate = if model.has_fdsk_certificate {
                "; certificate in the key store"
            } else {
                ""
            };
            out.push_str(&format!(
                "  {}{state}{certificate}\n",
                label("Secure in your project")
            ));
            if let Some(tables) = &model.tables {
                out.push_str(&format!(
                    "  {}{}\n",
                    label("Data Secure tables"),
                    table_capacity_line(tables)
                ));
            }
        }
        let plain = match sec.device.plain_management {
            PlainManagement::Answered => style.ok("answered"),
            PlainManagement::Refused => style.warn("refused"),
            PlainManagement::NotAttempted => style.dim("not attempted"),
        };
        let secured = match sec.device.secured_management {
            SecuredManagement::Used => style.ok("used"),
            SecuredManagement::NotAttempted => style.dim("not attempted"),
            SecuredManagement::Unanswered => style.warn("unanswered"),
            SecuredManagement::FactoryKey => style.ok("answered under the factory key"),
        };
        out.push_str(&format!(
            "  {}plain management {plain}; secured management {secured}\n",
            label("Secure in this run")
        ));
    }
    if let (Some(identity), Ok(target)) = (&report.identity, report.address.parse()) {
        let line = bussard_service::identity_line(target, identity);
        let line = if identity.is_drift() {
            style.warn(&line)
        } else {
            line
        };
        out.push_str(&format!("  {line}\n"));
    }
    if let Some(knxnet) = &report.knxnet {
        out.push_str(&crate::status_cmd::render_knxnet(knxnet, style));
    }
    let Some(objects) = &report.objects else {
        return out;
    };
    if objects.is_empty() {
        out.push_str(&format!(
            "  {}\n",
            style.dim("no interface objects discoverable")
        ));
        return out;
    }
    for obj in objects {
        out.push_str(&format!(
            "\n{} {}\n",
            style.bold(&format!(
                "Object {}: type {} ({})",
                obj.index, obj.object_type, obj.object_type_name
            )),
            style.dim(&crate::style::count(
                obj.properties.len(),
                "property",
                "properties"
            ))
        ));
        if obj.properties.is_empty() {
            out.push_str(&format!(
                "  {}\n",
                style.dim(
                    "no properties enumerable (the device may not support \
                     A_PropertyDescription_Read)"
                )
            ));
            continue;
        }
        let mut table = Table::new(&[
            "Index", "PID", "Name", "Type", "Count", "Writable", "Access",
        ]);
        for p in &obj.properties {
            table.row(vec![
                Cell::plain(p.index.to_string()),
                Cell::plain(p.pid.to_string()),
                Cell::plain(p.name.to_string()),
                Cell::plain(p.pdt.to_string()),
                Cell::plain(p.max_elements.to_string()),
                if p.writable {
                    Cell::new("yes", Tone::Plain)
                } else {
                    Cell::new("no", Tone::Dim)
                },
                Cell::plain(format!("r{} w{}", p.read_level, p.write_level)),
            ]);
        }
        for line in table.render(style).lines() {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}
