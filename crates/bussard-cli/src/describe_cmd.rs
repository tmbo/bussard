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

use anyhow::{Context, anyhow};
use bussard_mgmt::profile::{MaskFamily, MaskProfile};
use bussard_mgmt::{Layer4Connection, PropertyDesc, system_type};
use bussard_model::IndividualAddress;
use bussard_service::describe::{object_type_name, pid_name};
use bussard_service::facts::property_desc;
use bussard_service::{FactsCache, FactsSource, FactsWant, L4Options, WritePolicy};

use crate::cli::{Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{load_model_required, resolve_config};

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
use crate::style::{Cell, Style, Table, Tone};

/// One interface object plus its enumerated properties, shaped for text and
/// `--json`.
#[derive(Debug, serde::Serialize)]
struct ObjectReport {
    /// The interface-object index.
    index: u8,
    /// The interface-object type (IOT) code.
    object_type: u16,
    /// A human name for the object type, when known.
    object_type_name: &'static str,
    /// The properties enumerated on this object.
    properties: Vec<PropertyReport>,
}

/// One property descriptor row.
#[derive(Debug, serde::Serialize)]
struct PropertyReport {
    /// The property index (1-based).
    index: u8,
    /// The property id (PID).
    pid: u8,
    /// A human name for the PID, when known.
    name: &'static str,
    /// The property data type (PDT) code, as `0xNN`.
    pdt: String,
    /// Whether the property is writable.
    writable: bool,
    /// The maximum number of elements.
    max_elements: u16,
    /// The read access level (0 = highest).
    read_level: u8,
    /// The write access level (0 = highest).
    write_level: u8,
}

/// The full report.
#[derive(Debug, serde::Serialize)]
struct Report {
    /// The device address.
    address: String,
    /// The mask version, formatted `07B0`.
    mask: String,
    /// Human-readable system type for the mask.
    system_type: String,
    /// `"refused"` when the device answered the plain descriptor read but
    /// refused the unsecured interface-object walk (issue #155). Absent on a
    /// successful walk.
    #[serde(skip_serializing_if = "Option::is_none")]
    unsecured_management: Option<&'static str>,
    /// `"unanswered"` when a tool key was presented but the secured walk
    /// yielded no interface object (issue #155). Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    secured_management: Option<&'static str>,
    /// Why the run failed, with the KNX Data Secure hint, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The interface objects and their properties. Absent when the walk was
    /// refused: an empty walk is a failure, not an empty device.
    #[serde(skip_serializing_if = "Option::is_none")]
    objects: Option<Vec<ObjectReport>>,
    /// KNX Secure status (issue #71, #155): what the model says and what the
    /// device did this run. Present when the model has a security block, a tool
    /// key was used, or plain management was refused; absent for a plain device.
    #[serde(skip_serializing_if = "Option::is_none")]
    secure: Option<SecureReport>,
    /// The device's identity compared with `bussard.lock` (lock v2, issue
    /// #228): `match`, `drift` or `unmodelled`. Read-only, never refuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<bussard_model::identity::IdentityCheck>,
    /// What the KNXnet/IP parameter object (object type 11) of an IP
    /// interface reported (issue #391); absent on any other device.
    #[serde(skip_serializing_if = "Option::is_none")]
    knxnet: Option<bussard_model::knxnet::KnxnetFacts>,
    /// The serial number the device reported (PID 11 of the device object),
    /// lowercase hex; recorded in `bussard.lock` (issue #752).
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
}

/// KNX Secure status, split into the imported model's claims and what this run
/// observed on the bus (issue #155). Flags only, never any key material.
#[derive(Debug, serde::Serialize)]
struct SecureReport {
    /// What the knxproj import recorded. It can be stale: an export made before
    /// ETS activated security says `activated: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<ModelSecure>,
    /// What the device did in this run.
    device: DeviceSecure,
}

/// The security flags from the committed model (the knxproj import, spec §5).
#[derive(Debug, serde::Serialize)]
struct ModelSecure {
    /// The application is Data-Secure-capable (`IsSecureEnabled`).
    secure_capable: bool,
    /// The project recorded security as activated at export time.
    activated: bool,
    /// A factory FDSK certificate was present in the imported knxproj.
    has_fdsk_certificate: bool,
    /// The Data Secure table capacities the product declares (issue #537),
    /// for a Data-Secure-capable application whose product model is at hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    tables: Option<bussard_model::param_model::DataSecureCapacity>,
}

/// How the device answered management in this run.
#[derive(Debug, serde::Serialize)]
struct DeviceSecure {
    /// Plain (unsecured) management access.
    plain_management: PlainManagement,
    /// Secured (A_SecureData) management access.
    secured_management: SecuredManagement,
}

/// The device's answer to plain management access in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PlainManagement {
    /// The plain walk returned interface objects.
    Answered,
    /// The descriptor read was answered but the interface-object walk was not.
    Refused,
    /// A tool key was presented, so every access rode A_SecureData.
    NotAttempted,
}

/// The device's answer to secured management access in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SecuredManagement {
    /// The secured walk returned interface objects.
    Used,
    /// No tool key was available, so no secured frame was sent.
    NotAttempted,
    /// A tool key was presented but the secured walk returned no object.
    Unanswered,
    /// No tool key was available, and the device answered a secured read
    /// under its factory key (FDSK) from the key store (issue #532).
    FactoryKey,
}

/// Runs `bussard describe`.
fn run(args: &DescribeArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (address, dir, json, overrides) = (args.address.as_str(), g.dir(), g.json, g.mgmt());
    let tool_key_source = g.tool_keys(args.tool_key.tool_key.as_deref());
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // KNX Data Secure (issue #71, spec §6.2): a security-activated device refuses
    // the plain reads below, so `describe` takes the same tool-key surfaces as
    // `flash`. `None` is the plain, byte-identical path.
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let name = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| d.device.name.clone());
    // A keyring without an entry for the target serves the tunnel only; the
    // device is read in the clear unless the model says it is activated
    // (issue #189).
    let activated = bussard_service::secure::model_activated(model.as_ref(), target);
    let (tool_key, factory_key) = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_session_keys(target, tool_key_source, activated)
    })?;
    let secure_seq = bussard_secure::SequenceHighWater::new();
    let presented_tool_key = tool_key.is_some();
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Device facts live next to the model; without one they are read each time.
    let mut facts = crate::conn_cmd::facts_cache(dir, model.is_some(), g.refresh_facts);
    // Authorize (free access) as ETS does before configuration access (issue
    // #52 finding #1), best-effort for a read; skipped for a device the facts
    // say never answers it (the unanswered request costs the full response
    // timeout), a stale verdict being corrected on the same connection.
    let authorize = bussard_service::status::read_only_authorize(&mut facts, target);
    let full = args.full;

    let runtime = tokio::runtime::Runtime::new()?;
    // Read-only on the bus: descriptor, property and description reads. The
    // interface itself may be read over a device management connection
    // (issue #523, see `interface_session`).
    let session = crate::interface_session::open(
        &runtime,
        config,
        WritePolicy::ReadOnly,
        target,
        tool_key_source.keyring,
        overrides.skip_address_check,
    )?;
    let source = session.source;
    let service = session.bus.service();
    let (result, on_factory_key) = runtime
        .block_on(async move {
            let options = L4Options::secured(source, tool_key, secure_seq)
                .with_factory_key(factory_key)
                .with_authorize(authorize);
            let outcome = service
                .with_l4(target, &options, async |l4| {
                    introspect(l4, &facts, full).await
                })
                .await;
            // Plain access refused and no tool key: the FDSK from the key
            // store is tried before the "export a keyring" advice (#532).
            // A failed plain session (an activated device drops the plain
            // reads) counts as refused too.
            let refused = outcome.as_ref().map_or(true, walk_refused);
            let on_factory_key = bussard_service::identity::refused_walk_answers_under_factory_key(
                service, target, &options, refused,
            )
            .await;
            service.close().await;
            match outcome {
                Ok(o) => Ok((o, on_factory_key)),
                Err(_) if on_factory_key => Err(anyhow::Error::new(
                    crate::secure_key::FactoryKeyAnswered(factory_key_message(target)),
                )),
                Err(err) => Err(err),
            }
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))?;

    // An empty walk after a successful descriptor read is a refusal, not an
    // empty device (issue #155): an activated device answers the plain
    // descriptor read and PID 56 but not the interface-object walk. System 1
    // (BCU1) devices have no interface objects at all, so they are exempt.
    let refused = walk_refused(&result);
    let (plain, secured) = match (presented_tool_key, refused) {
        (false, true) if on_factory_key => {
            (PlainManagement::Refused, SecuredManagement::FactoryKey)
        }
        (false, false) => (PlainManagement::Answered, SecuredManagement::NotAttempted),
        (false, true) => (PlainManagement::Refused, SecuredManagement::NotAttempted),
        (true, false) => (PlainManagement::NotAttempted, SecuredManagement::Used),
        (true, true) => (PlainManagement::NotAttempted, SecuredManagement::Unanswered),
    };
    if let Some(note) = &result.facts_note
        && !json
    {
        eprintln!("{note}");
    }
    let mut report = result.report;
    if !refused {
        report.identity = Some(bussard_model::identity::IdentityCheck::compare(
            model
                .as_ref()
                .and_then(|m| m.devices.get(&target))
                .map(|d| &d.device),
            bussard_model::identity::ReportedIdentity {
                mask: report.mask.clone(),
                application_id: result.application_id.clone(),
            },
        ));
    }
    // The serial number goes into the lock (issue #752).
    if let (Some(serial), Some(check)) = (&result.serial, &report.identity) {
        crate::keys_cmd::learn_serials(
            dir,
            model.as_ref(),
            &[(target, serial.clone(), check.verdict)],
        )
        .print(json);
    }
    let loaded = model.as_ref().and_then(|m| m.devices.get(&target));
    // The product's Data Secure table capacities (issue #537).
    let tables = loaded
        .and_then(|d| d.device.product.as_ref())
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|app| {
            bussard_model::param_model::ProductModels::load_apps(dir, [app])
                .get(app)
                .and_then(|p| p.data_secure)
        });
    let model_secure = loaded
        .and_then(|d| d.device.security.as_ref())
        .map(|sec| ModelSecure {
            secure_capable: sec.secure_capable,
            activated: sec.activated,
            has_fdsk_certificate: sec.has_fdsk_certificate,
            tables: tables.filter(|_| sec.secure_capable),
        });
    if model_secure.is_some() || presented_tool_key || refused {
        report.secure = Some(SecureReport {
            model: model_secure,
            device: DeviceSecure {
                plain_management: plain,
                secured_management: secured,
            },
        });
    }
    if refused {
        let message = if on_factory_key {
            factory_key_message(target)
        } else {
            refused_walk_message(target, presented_tool_key)
        };
        report.objects = None;
        if presented_tool_key {
            report.secured_management = Some("unanswered");
        } else {
            report.unsecured_management = Some("refused");
        }
        report.error = Some(message.clone());
        if json {
            crate::output::print(crate::output::schema::DESCRIBE, &report)?;
        } else {
            print_text(&report, name.as_deref());
        }
        eprintln!("error: {message}");
        return Ok(ExitCode::FAILURE);
    }

    if json {
        crate::output::print(crate::output::schema::DESCRIBE, &report)?;
    } else {
        print_text(&report, name.as_deref());
    }
    Ok(ExitCode::SUCCESS)
}

/// Whether the walk found no interface object after a successful descriptor
/// read (issue #155); System 1 devices have none at all and are exempt.
fn walk_refused(result: &Introspection) -> bool {
    result.report.objects.as_ref().is_some_and(Vec::is_empty)
        && !matches!(result.mask_family, MaskFamily::System1)
}

/// The error for a device that refuses plain access and answers under its
/// factory key (issue #532).
fn factory_key_message(target: IndividualAddress) -> String {
    bussard_service::identity::factory_key_message(target)
}

/// The error for a walk that found no interface object after the device
/// answered the descriptor read (issue #155).
fn refused_walk_message(target: IndividualAddress, presented_tool_key: bool) -> String {
    if presented_tool_key {
        format!(
            "{target} answered the secured device descriptor read but returned no interface \
             object: the tool key may lack the access level for the walk"
        )
    } else {
        format!(
            "{target} answered the device descriptor read but refused the interface-object walk: \
             {}",
            crate::secure_key::no_key_guidance()
        )
    }
}

/// Reads the descriptor, discovers the interface objects and enumerates each
/// object's properties.
async fn introspect<Ch: bussard_mgmt::L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    full: bool,
) -> anyhow::Result<Introspection> {
    let address = l4.target();

    // The device descriptor (mask version) — mirrors `reconstruct`'s approach
    // but here it is informational, not a gate: `describe` introspects any
    // device that answers the property-description service.
    let (req_apci, payload) = bussard_mgmt::apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    let mask = if resp_apci & bussard_mgmt::apci::APCI_SELECTOR_MASK
        == bussard_mgmt::apci::A_DEVICE_DESCRIPTOR_RESPONSE
        && data.len() >= 2
    {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        return Err(anyhow!(
            "{address} did not answer A_DeviceDescriptor_Read with a mask version"
        ));
    };

    // The objects and their property descriptions: from the device facts when
    // the mask and application id still match, read (and stored) otherwise.
    // The property descriptions are walked only when the facts lack them or
    // `--full` asks (issue #209).
    let mut established = facts
        .establish(l4, mask, FactsWant::Properties { force: full })
        .await
        .with_context(|| format!("describing the interface objects of {address}"))?;
    // An IP interface's KNXnet/IP parameter object (issue #391): read every
    // time (the address in use can change under DHCP) and kept with the facts.
    let knxnet =
        match bussard_service::knxnet::read_knxnet_with_facts(l4, facts, &mut established).await {
            Ok(knxnet) => knxnet,
            Err(err) => {
                tracing::warn!("{address}: the KNXnet/IP parameter object did not read: {err}");
                None
            }
        };
    let facts_note = match (&established.source, &established.record) {
        (FactsSource::Cached, Some(record)) if !full => Some(format!(
            "(device facts of {} reused; pass --full to walk the property descriptions again)",
            record.read_at
        )),
        _ => None,
    };
    let application_id = established
        .record
        .as_ref()
        .and_then(|record| record.application_id.clone());
    // The serial number (PID 11 of the device object), one request on the
    // open session (issue #752): never cached, it names the hardware, not
    // the product. Skipped when the walk shows no device object or a device
    // object without PID 11 (a System 1 device has no interface objects).
    let has_serial = established.record.as_ref().is_some_and(|record| {
        record.objects.iter().any(|o| {
            o.index == bussard_mgmt::apci::DEVICE_OBJECT_INDEX
                && o.object_type == 0
                && o.properties.as_ref().is_none_or(|ps| {
                    ps.iter()
                        .any(|p| p.pid == bussard_mgmt::apci::PID_SERIAL_NUMBER)
                })
        })
    });
    let serial = if has_serial {
        bussard_mgmt::read_property_elements(
            l4,
            bussard_mgmt::apci::DEVICE_OBJECT_INDEX,
            bussard_mgmt::apci::PID_SERIAL_NUMBER,
            1,
            1,
        )
        .await
        .inspect_err(|err| tracing::debug!("{address}: the serial number did not read: {err}"))
        .ok()
        .filter(|v| v.len() == 6)
    } else {
        None
    };
    let object_reports = established
        .record
        .map(|record| record.objects)
        .unwrap_or_default()
        .into_iter()
        .map(|object| ObjectReport {
            index: object.index,
            object_type: object.object_type,
            object_type_name: object_type_name(object.object_type),
            properties: object
                .properties
                .unwrap_or_default()
                .iter()
                .map(|p| property_report(&property_desc(object.index, p)))
                .collect(),
        })
        .collect();

    Ok(Introspection {
        facts_note,
        mask_family: MaskProfile::from_mask(mask).family(),
        report: Report {
            address: address.to_string(),
            mask: format!("{mask:04X}"),
            system_type: system_type(mask).to_string(),
            unsecured_management: None,
            secured_management: None,
            error: None,
            objects: Some(object_reports),
            // Filled in by `run` from the model (introspect has no model handle).
            secure: None,
            identity: None,
            knxnet,
            serial: serial.as_deref().map(crate::assign_cmd::hex),
        },
        application_id,
        serial,
    })
}

/// What [`introspect`] read off the bus, before `run` adds the model's view.
struct Introspection {
    /// A stderr note when the report came from stored facts.
    facts_note: Option<String>,
    /// The mask family, which decides whether an empty walk is legitimate.
    mask_family: MaskFamily,
    /// The report, with `secure` still unset.
    report: Report,
    /// The application id the device reported, when read.
    application_id: Option<String>,
    /// The serial number the device reported (PID 11), when read.
    serial: Option<Vec<u8>>,
}

/// Builds a [`PropertyReport`] row from a [`PropertyDesc`].
fn property_report(p: &PropertyDesc) -> PropertyReport {
    PropertyReport {
        index: p.property_index,
        pid: p.property_id,
        name: pid_name(p.property_id),
        pdt: format!("0x{:02X}", p.pdt),
        writable: p.writable,
        max_elements: p.max_elements,
        read_level: p.read_level,
        write_level: p.write_level,
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

fn print_text(report: &Report, name: Option<&str>) {
    print!("{}", render_text(report, name, Style::stdout()));
}

/// The report as text: the heading, the serial number, KNX Secure in the
/// project and in this run, the identity, KNXnet/IP and one property table
/// per interface object.
fn render_text(report: &Report, name: Option<&str>, style: Style) -> String {
    let mut out = crate::status_cmd::device_heading(
        &report.address,
        name,
        &report.mask,
        &report.system_type,
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
