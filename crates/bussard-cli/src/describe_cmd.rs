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
use bussard_bus::{Bus, ops};
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE, discover_interface_objects,
};
use bussard_mgmt::{
    Layer4Connection, LeaseChannel, PropertyDesc, describe_object_properties, system_type,
};
use bussard_model::IndividualAddress;

use crate::conn_cmd::{ConnOverrides, load_model_required, resolve_config};

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
    /// The interface objects and their properties.
    objects: Vec<ObjectReport>,
    /// KNX Secure status from the model, when the device is secure-capable
    /// (issue #71). `None` for a plain device (no secure block in the model).
    #[serde(skip_serializing_if = "Option::is_none")]
    secure: Option<SecureReport>,
}

/// The KNX Secure status surfaced from the committed model (issue #71, spec §5
/// CLI surface). Flags only — never any key material.
#[derive(Debug, serde::Serialize)]
struct SecureReport {
    /// The device's application is Data-Secure-capable (`IsSecureEnabled`).
    secure_capable: bool,
    /// Security has been activated (management goes behind A_SecureData).
    activated: bool,
    /// A factory FDSK certificate was present in the imported knxproj.
    has_fdsk_certificate: bool,
    /// The ETS-tracked Data Secure sequence number, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence_number: Option<u64>,
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
    let result = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle
            .wait_connected(std::time::Duration::from_secs(10))
            .await
        {
            eprintln!(
                "warning: bus not connected yet; management traffic may use the 0.0.255 fallback source"
            );
        }
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let secure = crate::secure_key::layer(&tool_key, &secure_seq);
        let outcome = match Layer4Connection::connect_with_secure(
            channel,
            target,
            source,
            bussard_mgmt::Timeouts::default(),
            secure,
        )
        .await
        {
            Ok(mut l4) => {
                // Authorize (free access) as ETS does before configuration access
                // (issue #52 finding #1). Best-effort for a read.
                if let Err(err) = l4
                    .authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
                    .await
                {
                    tracing::debug!("{target} authorize (free access) did not grant: {err}");
                }
                let out = introspect(&mut l4).await;
                let _ = l4.disconnect().await;
                out
            }
            Err(err) => Err(anyhow::Error::new(err)),
        };
        let _ = handle.close().await;
        outcome
    })
    .map_err(|err| secure_hint(target, presented_tool_key, err))?;

    let mut result = result;
    // Surface KNX Secure status from the model (issue #71, spec §5). Flags only.
    if let Some(sec) = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .and_then(|d| d.device.security.as_ref())
    {
        result.secure = Some(SecureReport {
            secure_capable: sec.secure_capable,
            activated: sec.activated,
            has_fdsk_certificate: sec.has_fdsk_certificate,
            sequence_number: sec.sequence_number,
        });
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_text(&result);
    }
    Ok(ExitCode::SUCCESS)
}

/// Adds KNX Data Secure guidance to a failed introspection (issue #71,
/// spec §6.4).
///
/// An activated device drops a management APDU it cannot accept, which reaches
/// us as a disconnect or a silence — identical for "no tool key" and "wrong tool
/// key", so the hint names whichever cause is still open.
fn secure_hint(
    target: IndividualAddress,
    presented_tool_key: bool,
    err: anyhow::Error,
) -> anyhow::Error {
    if presented_tool_key {
        err.context(format!(
            "{target} did not answer the SECURED management access: either the tool key is not \
             this device's key, or the device is not security-activated and ignores A_SecureData \
             (retry without --keyring/--tool-key)"
        ))
    } else {
        err.context(format!(
            "{target} did not answer: if this device is KNX Data Secure-activated it refuses \
             unsecured management — pass its tool key with --keyring <file.knxkeys> (password in \
             BUSSARD_KEYRING_PASSWORD), or --tool-key <32 hex> for a test device"
        ))
    }
}

/// Reads the descriptor, discovers the interface objects and enumerates each
/// object's properties.
async fn introspect<Ch: bussard_mgmt::L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> anyhow::Result<Report> {
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

    let objects = discover_interface_objects(l4)
        .await
        .context("discovering interface objects")?;

    let mut object_reports = Vec::with_capacity(objects.len());
    for (index, object_type) in objects {
        let properties = describe_object_properties(l4, index)
            .await
            .with_context(|| format!("enumerating properties of object {index}"))?;
        object_reports.push(ObjectReport {
            index,
            object_type,
            object_type_name: object_type_name(object_type),
            properties: properties.iter().map(property_report).collect(),
        });
    }

    Ok(Report {
        address: address.to_string(),
        mask: format!("{mask:04X}"),
        system_type: system_type(mask).to_string(),
        objects: object_reports,
        // Filled in by `run` from the model (introspect has no model handle).
        secure: None,
    })
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

/// A human name for a well-known interface-object type, or `"?"`.
fn object_type_name(object_type: u16) -> &'static str {
    match object_type {
        OT_DEVICE => "device",
        OT_ADDRESS_TABLE => "address table",
        OT_ASSOCIATION_TABLE => "association table",
        OT_APPLICATION_PROGRAM => "application program",
        OT_GROUP_OBJECT_TABLE => "group object table",
        _ => "?",
    }
}

/// A human name for a well-known standardised PID (KNX 3/5/1 global properties
/// and the common device-object PIDs bussard already knows), or `"?"`. Only the
/// PIDs bussard names elsewhere are covered; an unknown PID is honestly `"?"`.
fn pid_name(pid: u8) -> &'static str {
    use bussard_mgmt::apci;
    match pid {
        1 => "PID_OBJECT_TYPE",
        apci::PID_SERIAL_NUMBER => "PID_SERIAL_NUMBER",
        apci::PID_MANUFACTURER_ID => "PID_MANUFACTURER_ID",
        apci::PID_ORDER_INFO => "PID_ORDER_INFO",
        apci::PID_PROGMODE => "PID_PROGMODE",
        apci::PID_MAX_APDU_LENGTH => "PID_MAX_APDU_LENGTH",
        apci::PID_HARDWARE_TYPE => "PID_HARDWARE_TYPE",
        5 => "PID_LOAD_STATE_CONTROL",
        7 => "PID_TABLE_REFERENCE",
        23 => "PID_TABLE",
        27 => "PID_MCB_TABLE",
        _ => "?",
    }
}

/// Prints the aligned human-readable report.
fn print_text(report: &Report) {
    println!(
        "device {} — mask {} ({})",
        report.address, report.mask, report.system_type
    );
    if let Some(sec) = &report.secure {
        let state = if sec.activated {
            "activated (management requires KNX Data Secure)"
        } else if sec.secure_capable {
            "capable, not activated"
        } else {
            "not secure-capable"
        };
        print!("  KNX Secure: {state}");
        if sec.has_fdsk_certificate {
            print!("; FDSK certificate present");
        }
        if let Some(seq) = sec.sequence_number {
            print!("; seqnum {seq}");
        }
        println!();
    }
    if report.objects.is_empty() {
        println!("  no interface objects discoverable");
        return;
    }
    for obj in &report.objects {
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
