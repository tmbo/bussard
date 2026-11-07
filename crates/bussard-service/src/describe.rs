//! Device introspection shared by `bussard describe` and the MCP
//! `knx_describe_device` tool (issue #72): the interface-object walk, the
//! human names for object types and property ids, and the one describe flow
//! both surfaces run ([`run`], issue #903).
//!
//! Read-only on the bus: [`walk_objects`] sends `A_PropertyValue_Read` (object
//! discovery) and `A_PropertyDescription_Read` only; [`run`] adds the device
//! descriptor read, the KNXnet/IP parameter object, the serial number and, on
//! a secured session, the Data Secure diagnostics, all reads.

use std::path::Path;

use bussard_download::SecurityDiagnostics;
use bussard_mgmt::profile::{MaskFamily, MaskProfile};
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE, discover_interface_objects,
};
use bussard_mgmt::{L4Channel, Layer4Connection, MgmtError, PropertyDesc, apci, system_type};
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::knxnet::KnxnetFacts;
use bussard_model::param_model::DataSecureCapacity;
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};

use crate::bus::{Authorize, BusService, L4Options, Management, SourcePolicy};
use crate::error::ServiceError;
use crate::facts::{FactsCache, FactsSource, FactsWant, property_desc};
use crate::secure::{SecureKeyError, ToolKeySource};
use crate::warm::WarmGuard;

/// One interface object and its enumerated property descriptions.
#[derive(Debug, Clone)]
pub struct ObjectDescription {
    /// The interface-object index.
    pub index: u8,
    /// The interface-object type (IOT) code.
    pub object_type: u16,
    /// The object's property descriptions, in index order.
    pub properties: Vec<PropertyDesc>,
}

/// Why the walk failed.
#[derive(Debug, thiserror::Error)]
pub enum DescribeError {
    /// Discovering the interface objects failed.
    #[error("discovering interface objects")]
    Discover(#[source] bussard_mgmt::tables::TablesError),
    /// Enumerating one object's properties failed.
    #[error("enumerating properties of object {index}")]
    Enumerate {
        /// The object index.
        index: u8,
        /// The management error.
        #[source]
        source: MgmtError,
    },
}

/// Discovers a device's interface objects and enumerates each one's property
/// descriptions over an open management session.
///
/// Call [`Layer4Connection::negotiate_max_apdu`] first (best-effort) so the
/// property reads scale to the device's maximum APDU. An empty result after a successful descriptor read usually
/// means a KNX Data Secure device refused the plain walk (issue #155); the
/// caller decides how to report that.
///
/// # Errors
///
/// The first discovery or enumeration failure.
pub async fn walk_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<ObjectDescription>, DescribeError> {
    let objects = discover_interface_objects(l4)
        .await
        .map_err(DescribeError::Discover)?;
    let mut out = Vec::with_capacity(objects.len());
    for (index, object_type) in objects {
        let properties = bussard_mgmt::describe_object_properties(l4, index)
            .await
            .map_err(|source| DescribeError::Enumerate { index, source })?;
        out.push(ObjectDescription {
            index,
            object_type,
            properties,
        });
    }
    Ok(out)
}

/// A human name for a well-known standardised interface-object type
/// (KNX 3/5/1), or `"?"`.
pub fn object_type_name(object_type: u16) -> &'static str {
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
pub fn pid_name(pid: u8) -> &'static str {
    match pid {
        1 => "PID_OBJECT_TYPE",
        5 => "PID_LOAD_STATE_CONTROL",
        7 => "PID_TABLE_REFERENCE",
        apci::PID_SERIAL_NUMBER => "PID_SERIAL_NUMBER",
        apci::PID_MANUFACTURER_ID => "PID_MANUFACTURER_ID",
        apci::PID_ORDER_INFO => "PID_ORDER_INFO",
        23 => "PID_TABLE",
        27 => "PID_MCB_TABLE",
        apci::PID_PROGMODE => "PID_PROGMODE",
        apci::PID_MAX_APDU_LENGTH => "PID_MAX_APDU_LENGTH",
        apci::PID_HARDWARE_TYPE => "PID_HARDWARE_TYPE",
        _ => "?",
    }
}

/// The keys of a describe session: the tool key (`None`: plain management)
/// and the device's factory key from the key store (issue #532).
#[derive(Debug, Clone, Default)]
pub struct SessionKeys {
    /// The tool key that wraps every management APDU, when the device has one.
    pub tool_key: Option<Key16>,
    /// The device's factory default setup key (FDSK), when the key store has it.
    pub factory_key: Option<Key16>,
}

/// The keys to describe `target` with: its tool key from `source` when the
/// model records the device as Secure-activated or the keyring lists it
/// (issue #189), and its FDSK.
///
/// # Errors
///
/// The keyring or tool key could not be loaded.
pub fn session_keys(
    model: Option<&Model>,
    target: IndividualAddress,
    source: ToolKeySource<'_>,
) -> Result<SessionKeys, SecureKeyError> {
    let activated = crate::secure::model_activated(model, target);
    let (tool_key, factory_key) = crate::secure::resolve_session_keys(target, source, activated)?;
    Ok(SessionKeys {
        tool_key,
        factory_key,
    })
}

/// What a describe reads in its session.
#[derive(Debug, Clone, Copy)]
pub enum Walk<'a> {
    /// `bussard describe`: the device descriptor, the objects and property
    /// descriptions through the device facts (issue #209), the KNXnet/IP
    /// parameter object (issue #391) and the serial number (issue #752).
    Facts {
        /// The device facts.
        facts: &'a FactsCache,
        /// Walk the property descriptions again even when the facts hold them.
        full: bool,
    },
    /// `knx_describe_device`: the max-APDU negotiation and the object walk,
    /// with the Data Secure diagnostics on a secured session (issue #533).
    Objects,
}

/// One describe: the device, its keys and how the session opens.
#[derive(Debug, Clone)]
pub struct DescribeRequest<'a> {
    /// The device to describe.
    pub target: IndividualAddress,
    /// The model, for the identity check and the Secure block of the report.
    pub model: Option<&'a Model>,
    /// The model directory, for the product's Data Secure table capacities.
    pub dir: Option<&'a Path>,
    /// The session keys ([`session_keys`]).
    pub keys: SessionKeys,
    /// Where the session's source address comes from.
    pub source: SourcePolicy,
    /// The authorize step after `T_Connect`.
    pub authorize: Authorize,
    /// What the session reads.
    pub walk: Walk<'a>,
}

/// One interface object plus its enumerated properties, as both surfaces
/// show it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectReport {
    /// The interface-object index.
    pub index: u8,
    /// The interface-object type (IOT) code.
    pub object_type: u16,
    /// A human name for the object type, when known.
    pub object_type_name: &'static str,
    /// The properties enumerated on this object.
    pub properties: Vec<PropertyReport>,
}

impl ObjectReport {
    /// The row of object `index` of type `object_type` with `properties`.
    pub fn new(index: u8, object_type: u16, properties: &[PropertyDesc]) -> ObjectReport {
        ObjectReport {
            index,
            object_type,
            object_type_name: object_type_name(object_type),
            properties: properties.iter().map(PropertyReport::from).collect(),
        }
    }
}

/// One property descriptor row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PropertyReport {
    /// The property index (1-based).
    pub index: u8,
    /// The property id (PID).
    pub pid: u8,
    /// A human name for the PID, when known.
    pub name: &'static str,
    /// The property data type (PDT) code, as `0xNN`.
    pub pdt: String,
    /// Whether the property is writable.
    pub writable: bool,
    /// The maximum number of elements.
    pub max_elements: u16,
    /// The read access level (0 = highest).
    pub read_level: u8,
    /// The write access level (0 = highest).
    pub write_level: u8,
}

impl From<&PropertyDesc> for PropertyReport {
    fn from(p: &PropertyDesc) -> PropertyReport {
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
}

/// The `bussard describe` report, the `--json` document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DescribeReport {
    /// The device address.
    pub address: String,
    /// The mask version, formatted `07B0`.
    pub mask: String,
    /// Human-readable system type for the mask.
    pub system_type: String,
    /// `"refused"` when the device answered the plain descriptor read but
    /// refused the unsecured interface-object walk (issue #155). Absent on a
    /// successful walk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsecured_management: Option<&'static str>,
    /// `"unanswered"` when a tool key was presented but the secured walk
    /// yielded no interface object (issue #155). Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secured_management: Option<&'static str>,
    /// Why the run failed, with the KNX Data Secure hint, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The interface objects and their properties. Absent when the walk was
    /// refused: an empty walk is a failure, not an empty device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<ObjectReport>>,
    /// KNX Secure status (issue #71, #155): what the model says and what the
    /// device did this run. Present when the model has a security block, a tool
    /// key was used, or plain management was refused; absent for a plain device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureReport>,
    /// The device's identity compared with `bussard.lock` (lock v2, issue
    /// #228): `match`, `drift` or `unmodelled`. Read-only, never refuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
    /// What the KNXnet/IP parameter object (object type 11) of an IP
    /// interface reported (issue #391); absent on any other device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knxnet: Option<KnxnetFacts>,
    /// The serial number the device reported (PID 11 of the device object),
    /// lowercase hex; recorded in `bussard.lock` (issue #752).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// KNX Secure status, split into the imported model's claims and what this run
/// observed on the bus (issue #155). Flags only, never any key material.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecureReport {
    /// What the knxproj import recorded. It can be stale: an export made before
    /// ETS activated security says `activated: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelSecure>,
    /// What the device did in this run.
    pub device: DeviceSecure,
}

/// The security flags from the committed model (the knxproj import, spec §5).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelSecure {
    /// The application is Data-Secure-capable (`IsSecureEnabled`).
    pub secure_capable: bool,
    /// The project recorded security as activated at export time.
    pub activated: bool,
    /// A factory FDSK certificate was present in the imported knxproj.
    pub has_fdsk_certificate: bool,
    /// The Data Secure table capacities the product declares (issue #537),
    /// for a Data-Secure-capable application whose product model is at hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables: Option<DataSecureCapacity>,
}

/// How the device answered management in this run.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DeviceSecure {
    /// Plain (unsecured) management access.
    pub plain_management: PlainManagement,
    /// Secured (A_SecureData) management access.
    pub secured_management: SecuredManagement,
}

/// The device's answer to plain management access in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlainManagement {
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
pub enum SecuredManagement {
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

/// How the device answered plain and secured management, from whether a tool
/// key was presented, whether the walk was refused and whether the device
/// answered under its factory key.
pub fn classify(
    presented_tool_key: bool,
    refused: bool,
    on_factory_key: bool,
) -> (PlainManagement, SecuredManagement) {
    match (presented_tool_key, refused) {
        (false, true) if on_factory_key => {
            (PlainManagement::Refused, SecuredManagement::FactoryKey)
        }
        (false, false) => (PlainManagement::Answered, SecuredManagement::NotAttempted),
        (false, true) => (PlainManagement::Refused, SecuredManagement::NotAttempted),
        (true, false) => (PlainManagement::NotAttempted, SecuredManagement::Used),
        (true, true) => (PlainManagement::NotAttempted, SecuredManagement::Unanswered),
    }
}

/// What a describe read off the bus.
#[derive(Debug, Clone)]
pub struct Walked {
    /// The mask version, when the walk read the descriptor ([`Walk::Facts`]).
    pub mask: Option<u16>,
    /// The interface objects and their properties.
    pub objects: Vec<ObjectReport>,
    /// The KNXnet/IP parameter object of an IP interface.
    pub knxnet: Option<KnxnetFacts>,
    /// A note when the objects came from stored device facts.
    pub facts_note: Option<String>,
    /// The application id the device reported, when read.
    pub application_id: Option<String>,
    /// The serial number the device reported (PID 11), when read.
    pub serial: Option<Vec<u8>>,
    /// The Data Secure diagnostics of a secured [`Walk::Objects`] session, or
    /// why they were not read.
    pub security: Option<Result<SecurityDiagnostics, String>>,
}

impl Walked {
    /// Whether the walk found no interface object after a successful
    /// descriptor read (issue #155); System 1 devices have none at all and
    /// are exempt.
    pub fn refused(&self) -> bool {
        self.objects.is_empty()
            && !self
                .mask
                .is_some_and(|m| matches!(MaskProfile::from_mask(m).family(), MaskFamily::System1))
    }
}

/// Why a describe session failed.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The session did not open (the source check, the lease, the connect).
    #[error(transparent)]
    Session(#[from] ServiceError),
    /// The device descriptor read failed.
    #[error(transparent)]
    Mgmt(MgmtError),
    /// The device answered the descriptor read without a mask version.
    #[error("{address} did not answer A_DeviceDescriptor_Read with a mask version")]
    NoMask {
        /// The device.
        address: IndividualAddress,
    },
    /// The objects and their descriptions could not be established.
    #[error("describing the interface objects of {address}")]
    Facts {
        /// The device.
        address: IndividualAddress,
        /// The management error.
        #[source]
        source: MgmtError,
    },
    /// The object walk failed.
    #[error(transparent)]
    Walk(DescribeError),
}

/// What one describe found.
#[derive(Debug)]
pub struct DescribeOutcome {
    /// The device.
    pub target: IndividualAddress,
    /// The walk, or why the session failed.
    pub walk: Result<Walked, RunError>,
    /// Whether a tool key was presented.
    pub presented_tool_key: bool,
    /// Whether the walk was refused (or failed): no interface object after
    /// the descriptor read.
    pub refused: bool,
    /// The device refused plain access and answered under its factory key.
    pub on_factory_key: bool,
    /// Plain management in this run.
    pub plain: PlainManagement,
    /// Secured management in this run.
    pub secured: SecuredManagement,
    /// The identity against `bussard.lock`, for a walk that read the
    /// descriptor and was not refused.
    pub identity: Option<IdentityCheck>,
    /// The `bussard describe` report, for a [`Walk::Facts`] walk that did not
    /// fail.
    pub report: Option<DescribeReport>,
}

impl DescribeOutcome {
    /// The error of a refused walk: the factory-key sentence, or the refusal
    /// with the key guidance.
    pub fn refusal(&self) -> Option<String> {
        if !self.refused {
            return None;
        }
        Some(if self.on_factory_key {
            crate::identity::factory_key_message(self.target)
        } else {
            refused_walk_message(self.target, self.presented_tool_key)
        })
    }
}

/// The guidance for a device without a tool key that may be Data
/// Secure-activated (issue #71, spec §6.4).
pub fn no_key_guidance() -> String {
    format!(
        "if this device is KNX Data Secure-activated it refuses unsecured management: {} (a \
         keyring that does not list the device only opens the tunnel)",
        crate::guidance::tool_key_hint()
    )
}

/// The error for a walk that found no interface object after the device
/// answered the descriptor read (issue #155).
pub fn refused_walk_message(target: IndividualAddress, presented_tool_key: bool) -> String {
    if presented_tool_key {
        format!(
            "{target} answered the secured device descriptor read but returned no interface \
             object: the tool key may lack the access level for the walk"
        )
    } else {
        format!(
            "{target} answered the device descriptor read but refused the interface-object walk: \
             {}",
            no_key_guidance()
        )
    }
}

/// Describes `req.target`: opens the session (on `reuse`'s warm connection
/// when it fits, issue #215), walks as `req.walk` says, decides whether the
/// walk was refused (issue #155), tries the factory key on a refused plain
/// walk (issue #532) and builds the report.
///
/// With `reuse`, a failure on the reused connection is repeated once on a
/// fresh one, and the connection is kept for the next call unless the plain
/// walk was refused and the factory key probe follows. A fresh connect that
/// fails there ends the describe without the probe.
pub async fn run(
    service: &BusService,
    req: &DescribeRequest<'_>,
    reuse: Option<&mut WarmGuard<'_>>,
) -> DescribeOutcome {
    let target = req.target;
    let options = L4Options::secured(
        req.source,
        req.keys.tool_key.clone(),
        SequenceHighWater::new(),
    )
    .with_factory_key(req.keys.factory_key.clone())
    .with_authorize(req.authorize);
    let presented_tool_key = options.tool_key.is_some();
    let (walk, probe) = match reuse {
        None => (
            service
                .with_l4(target, &options, async |l4| walk(l4, &req.walk).await)
                .await,
            true,
        ),
        Some(warm) => warm_walk(service, &options, &req.walk, target, warm).await,
    };
    let refused = walk.as_ref().map_or(true, Walked::refused);
    let on_factory_key = probe
        && crate::identity::refused_walk_answers_under_factory_key(
            service, target, &options, refused,
        )
        .await;
    let (plain, secured) = classify(presented_tool_key, refused, on_factory_key);
    let mut outcome = DescribeOutcome {
        target,
        walk,
        presented_tool_key,
        refused,
        on_factory_key,
        plain,
        secured,
        identity: None,
        report: None,
    };
    if let Ok(walked) = &outcome.walk
        && let Some(mask) = walked.mask
    {
        let device = req
            .model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device);
        if !refused {
            outcome.identity = Some(IdentityCheck::compare(
                device,
                ReportedIdentity {
                    mask: format!("{mask:04X}"),
                    application_id: walked.application_id.clone(),
                },
            ));
        }
        outcome.report = Some(report(&outcome, walked, mask, req));
    }
    outcome
}

/// The `bussard describe` report of a walk that read the descriptor.
fn report(
    outcome: &DescribeOutcome,
    walked: &Walked,
    mask: u16,
    req: &DescribeRequest<'_>,
) -> DescribeReport {
    let loaded = req.model.and_then(|m| m.devices.get(&req.target));
    // The product's Data Secure table capacities (issue #537).
    let tables = loaded
        .and_then(|d| d.device.product.as_ref())
        .and_then(|p| p.application_ref.as_deref())
        .zip(req.dir)
        .and_then(|(app, dir)| {
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
    let refused = outcome.refused;
    let secure =
        (model_secure.is_some() || outcome.presented_tool_key || refused).then_some(SecureReport {
            model: model_secure,
            device: DeviceSecure {
                plain_management: outcome.plain,
                secured_management: outcome.secured,
            },
        });
    DescribeReport {
        address: req.target.to_string(),
        mask: format!("{mask:04X}"),
        system_type: system_type(mask).to_string(),
        unsecured_management: (refused && !outcome.presented_tool_key).then_some("refused"),
        secured_management: (refused && outcome.presented_tool_key).then_some("unanswered"),
        error: outcome.refusal(),
        objects: (!refused).then(|| walked.objects.clone()),
        secure,
        identity: outcome.identity.clone(),
        knxnet: walked.knxnet.clone(),
        serial: walked.serial.as_deref().map(bussard_model::text::hex),
    }
}

/// The walk on the warm connection (issue #215); the second value is false
/// when a fresh connect failed, which skips the factory key probe.
async fn warm_walk(
    service: &BusService,
    options: &L4Options,
    how: &Walk<'_>,
    target: IndividualAddress,
    warm: &mut WarmGuard<'_>,
) -> (Result<Walked, RunError>, bool) {
    let secure = options.tool_key.is_some();
    let reused = warm
        .take(target, secure, service.handle().link_losses())
        .await;
    let mut kept: Option<Management> = None;
    let mut reused_walk = None;
    if let Some(mut l4) = reused {
        match walk(&mut l4, how).await {
            Ok(walked) => {
                kept = Some(l4);
                reused_walk = Some(walked);
            }
            // A failure on a reused connection is repeated once on a fresh
            // one: the device may have dropped it in the meantime.
            Err(err) => {
                tracing::debug!(
                    "{target}: the warm connection failed ({}); reconnecting",
                    crate::program::chain(&err)
                );
                let _ = l4.disconnect().await;
            }
        }
    }
    let result = match reused_walk {
        Some(walked) => Ok(walked),
        None => {
            let mut l4 = match service.connect_l4(target, options).await {
                Ok(l4) => l4,
                Err(err) => return (Err(RunError::Session(err)), false),
            };
            let walked = walk(&mut l4, how).await;
            if walked.is_ok() {
                kept = Some(l4);
            } else {
                let _ = l4.disconnect().await;
            }
            walked
        }
    };
    // A refused plain walk: the factory key probe runs next on a connection
    // of its own (issues #532, #571), so the plain one is not kept.
    let refused = result.as_ref().map_or(true, Walked::refused);
    match kept {
        Some(l4) if refused && options.factory_key.is_some() && !secure => {
            let _ = l4.disconnect().await;
        }
        Some(l4) => warm.keep(l4, target, secure, service.handle().link_losses()),
        None => {}
    }
    (result, true)
}

/// Reads what `how` names on an open session.
async fn walk<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    how: &Walk<'_>,
) -> Result<Walked, RunError> {
    match how {
        Walk::Facts { facts, full } => walk_facts(l4, facts, *full).await,
        Walk::Objects => {
            // Scale property reads to the device's max APDU when it exposes it.
            let _ = l4.negotiate_max_apdu().await;
            let objects = walk_objects(l4).await.map_err(RunError::Walk)?;
            // A Data Secure device read with its tool key: the security
            // failures log, report and report control too (issue #533).
            let security = if l4.is_secure() {
                Some(
                    bussard_download::read_security_diagnostics(l4)
                        .await
                        .map_err(|err| format!("Data Secure diagnostics not read: {err}")),
                )
            } else {
                None
            };
            Ok(Walked {
                mask: None,
                objects: objects
                    .iter()
                    .map(|o| ObjectReport::new(o.index, o.object_type, &o.properties))
                    .collect(),
                knxnet: None,
                facts_note: None,
                application_id: None,
                serial: None,
                security,
            })
        }
    }
}

/// Reads the descriptor, establishes the objects and their descriptions
/// through the device facts, the KNXnet/IP parameter object and the serial
/// number.
async fn walk_facts<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    full: bool,
) -> Result<Walked, RunError> {
    let address = l4.target();
    // The device descriptor (mask version) is informational, not a gate:
    // `describe` introspects any device that answers the property-description
    // service.
    let (req_apci, payload) = apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4
        .request(req_apci, &payload)
        .await
        .map_err(RunError::Mgmt)?;
    let mask = if resp_apci & apci::APCI_SELECTOR_MASK == apci::A_DEVICE_DESCRIPTOR_RESPONSE
        && data.len() >= 2
    {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        return Err(RunError::NoMask { address });
    };
    // The objects and their property descriptions: from the device facts when
    // the mask and application id still match, read (and stored) otherwise.
    // The property descriptions are walked only when the facts lack them or
    // `full` asks (issue #209).
    let mut established = facts
        .establish(l4, mask, FactsWant::Properties { force: full })
        .await
        .map_err(|source| RunError::Facts { address, source })?;
    // An IP interface's KNXnet/IP parameter object (issue #391): read every
    // time (the address in use can change under DHCP) and kept with the facts.
    let knxnet = match crate::knxnet::read_knxnet_with_facts(l4, facts, &mut established).await {
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
            o.index == apci::DEVICE_OBJECT_INDEX
                && o.object_type == 0
                && o.properties
                    .as_ref()
                    .is_none_or(|ps| ps.iter().any(|p| p.pid == apci::PID_SERIAL_NUMBER))
        })
    });
    let serial = if has_serial {
        bussard_mgmt::read_property_elements(
            l4,
            apci::DEVICE_OBJECT_INDEX,
            apci::PID_SERIAL_NUMBER,
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
    let objects = established
        .record
        .map(|record| record.objects)
        .unwrap_or_default()
        .into_iter()
        .map(|object| {
            let properties: Vec<PropertyDesc> = object
                .properties
                .unwrap_or_default()
                .iter()
                .map(|p| property_desc(object.index, p))
                .collect();
            ObjectReport::new(object.index, object.object_type, &properties)
        })
        .collect();
    Ok(Walked {
        mask: Some(mask),
        objects,
        knxnet,
        facts_note,
        application_id,
        serial,
        security: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_name_known_and_unknown() {
        assert_eq!(pid_name(1), "PID_OBJECT_TYPE");
        assert_eq!(pid_name(11), "PID_SERIAL_NUMBER");
        assert_eq!(pid_name(12), "PID_MANUFACTURER_ID");
        assert_eq!(pid_name(15), "PID_ORDER_INFO");
        assert_eq!(pid_name(54), "PID_PROGMODE");
        assert_eq!(pid_name(56), "PID_MAX_APDU_LENGTH");
        assert_eq!(pid_name(78), "PID_HARDWARE_TYPE");
        assert_eq!(pid_name(200), "?");
    }

    #[test]
    fn test_object_type_name_known_and_unknown() {
        assert_eq!(object_type_name(0), "device");
        assert_eq!(object_type_name(9), "group object table");
        assert_eq!(object_type_name(42), "?");
    }
}
