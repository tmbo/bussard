//! The `bussard describe` subcommand — introspect a device's interface objects
//! and their properties over the bus (issue #72).
//!
//! Connects to a single device, discovers its interface objects (by probing
//! `PID_OBJECT_TYPE` per index, the same discovery `reconstruct` uses), and for
//! each object enumerates its properties with `A_PropertyDescription_Read`,
//! printing each property's PID (with a name when known), data type, element
//! count and read/write access levels as a table.
//!
//! The command is **read-only on the bus**: it only ever sends
//! `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` (for object discovery) and
//! `A_PropertyDescription_Read`. It never writes.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_mgmt::profile::{MaskFamily, MaskProfile};
use bussard_mgmt::{Layer4Connection, PropertyDesc, system_type};
use bussard_model::IndividualAddress;
use bussard_service::describe::{object_type_name, pid_name, walk_objects};
use bussard_service::{Authorize, L4Options, SourcePolicy, WritePolicy};

use crate::conn_cmd::{ConnOverrides, load_model_required, open_service, resolve_config};

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
}

/// Runs `bussard describe`.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // KNX Data Secure (issue #71, spec §6.2): a security-activated device refuses
    // the plain reads below, so `describe` takes the same tool-key surfaces as
    // `flash`. `None` is the plain, byte-identical path.
    let tool_key = crate::secure_key::resolve(target, tool_key_source)?;
    let secure_seq = bussard_secure::SequenceHighWater::new();
    let presented_tool_key = tool_key.is_some();
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime
        .block_on(async move {
            // Read-only on the bus: descriptor, property and description reads.
            let service = open_service(config, WritePolicy::ReadOnly).await?;
            let options = L4Options {
                source: SourcePolicy::Check {
                    skip: overrides.skip_address_check,
                },
                tool_key,
                high_water: secure_seq,
                // Authorize (free access) as ETS does before configuration
                // access (issue #52 finding #1). Best-effort for a read.
                authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
                ..L4Options::default()
            };
            let outcome = service
                .with_l4(target, &options, async |l4| introspect(l4).await)
                .await;
            service.close().await;
            outcome
        })
        .map_err(|err| crate::secure_key::secure_hint(target, presented_tool_key, err))?;

    // An empty walk after a successful descriptor read is a refusal, not an
    // empty device (issue #155): an activated device answers the plain
    // descriptor read and PID 56 but not the interface-object walk. System 1
    // (BCU1) devices have no interface objects at all, so they are exempt.
    let refused = result.report.objects.as_ref().is_some_and(Vec::is_empty)
        && !matches!(result.mask_family, MaskFamily::System1);
    let (plain, secured) = match (presented_tool_key, refused) {
        (false, false) => (PlainManagement::Answered, SecuredManagement::NotAttempted),
        (false, true) => (PlainManagement::Refused, SecuredManagement::NotAttempted),
        (true, false) => (PlainManagement::NotAttempted, SecuredManagement::Used),
        (true, true) => (PlainManagement::NotAttempted, SecuredManagement::Unanswered),
    };
    let mut report = result.report;
    let model_secure = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .and_then(|d| d.device.security.as_ref())
        .map(|sec| ModelSecure {
            secure_capable: sec.secure_capable,
            activated: sec.activated,
            has_fdsk_certificate: sec.has_fdsk_certificate,
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
        let message = refused_walk_message(target, presented_tool_key);
        report.objects = None;
        if presented_tool_key {
            report.secured_management = Some("unanswered");
        } else {
            report.unsecured_management = Some("refused");
        }
        report.error = Some(message.clone());
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_text(&report);
        }
        eprintln!("error: {message}");
        return Ok(ExitCode::FAILURE);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
    }
    Ok(ExitCode::SUCCESS)
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
) -> anyhow::Result<Introspection> {
    let address = l4.target();
    // Scale property reads to the device's max APDU when available (best-effort).
    let _ = l4.negotiate_max_apdu().await;

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

    let object_reports = walk_objects(l4)
        .await?
        .into_iter()
        .map(|object| ObjectReport {
            index: object.index,
            object_type: object.object_type,
            object_type_name: object_type_name(object.object_type),
            properties: object.properties.iter().map(property_report).collect(),
        })
        .collect();

    Ok(Introspection {
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
        },
    })
}

/// What [`introspect`] read off the bus, before `run` adds the model's view.
struct Introspection {
    /// The mask family, which decides whether an empty walk is legitimate.
    mask_family: MaskFamily,
    /// The report, with `secure` still unset.
    report: Report,
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
fn print_text(report: &Report) {
    println!(
        "device {} — mask {} ({})",
        report.address, report.mask, report.system_type
    );
    if let Some(sec) = &report.secure {
        if let Some(model) = &sec.model {
            let state = if model.activated {
                "activated"
            } else if model.secure_capable {
                "capable, not activated"
            } else {
                "not secure-capable"
            };
            print!("  KNX Secure (model): {state}");
            if model.has_fdsk_certificate {
                print!("; FDSK certificate present");
            }
            println!();
        }
        let plain = match sec.device.plain_management {
            PlainManagement::Answered => "answered",
            PlainManagement::Refused => "refused",
            PlainManagement::NotAttempted => "not attempted",
        };
        let secured = match sec.device.secured_management {
            SecuredManagement::Used => "used",
            SecuredManagement::NotAttempted => "not attempted",
            SecuredManagement::Unanswered => "unanswered",
        };
        println!("  KNX Secure (this run): plain management {plain}; secured management {secured}");
    }
    let Some(objects) = &report.objects else {
        return;
    };
    if objects.is_empty() {
        println!("  no interface objects discoverable");
        return;
    }
    for obj in objects {
        println!(
            "\nobject {} — type {} ({}), {} propert{}",
            obj.index,
            obj.object_type,
            obj.object_type_name,
            obj.properties.len(),
            if obj.properties.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
        if obj.properties.is_empty() {
            println!(
                "  (no properties enumerable — device may not support A_PropertyDescription_Read)"
            );
            continue;
        }
        println!(
            "  {:<4}  {:<5}  {:<20}  {:<6}  {:<5}  {:<5}  {:<6}",
            "IDX", "PID", "NAME", "TYPE", "COUNT", "W?", "ACCESS"
        );
        for p in &obj.properties {
            println!(
                "  {:<4}  {:<5}  {:<20}  {:<6}  {:<5}  {:<5}  r{} w{}",
                p.index,
                p.pid,
                p.name,
                p.pdt,
                p.max_elements,
                if p.writable { "yes" } else { "no" },
                p.read_level,
                p.write_level
            );
        }
    }
}
