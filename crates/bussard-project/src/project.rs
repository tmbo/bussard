//! Streaming parser for the ETS project `0.xml`.
//!
//! Extracts the group-address plan (with two levels of ranges), the topology
//! (device instances and their individual addresses), each device's
//! com-object instance references (with send/listen links and flag/DPT
//! overrides), and the building locations (floor/room per device).
//!
//! The heavy resolution against manufacturer XML happens later in
//! [`crate::build`]; this module only reads the project file itself.

// quick-xml 0.41 deprecates unescape_value in favor of normalized_value,
// which adds attribute-value whitespace normalization. Import output is held
// to byte-equal stability, so the plain-unescape semantics are deliberate.
#![allow(deprecated)]
use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::dpt_map::parse_ets_dpt;
use crate::error::{ImportError, Result};
use crate::flag_map::{FlagSet, parse_flag_value};
use crate::version::SchemaVersion;
use bussard_model::{Dpt, GroupAddress, IndividualAddress};

/// A group address as read from the project file.
#[derive(Debug, Clone)]
pub struct RawGroupAddress {
    /// The `GA-N` suffix of the `Id` attribute (used to resolve `Links`).
    pub ref_suffix: String,
    /// The parsed 3-level address.
    pub address: GroupAddress,
    /// Display name.
    pub name: String,
    /// Explicit DPT from the `DatapointType` attribute, if present.
    pub dpt: Option<Dpt>,
    /// Free-text description.
    pub description: Option<String>,
    /// Whether ETS runs this group address with KNX Data Secure: the element
    /// carries its (encrypted) group `Key`, or `Security="On"`. CONFIRMED from
    /// the post-activation export (issue #156): the one secured GA 0/3/47 is
    /// `<GroupAddress … Key="…"/>` and no GA carries a `Security` attribute.
    /// The key value is never read.
    pub secure: bool,
}

/// A two-level named range around a set of group addresses.
#[derive(Debug, Clone)]
pub struct RawRange {
    /// The `main` level (or `main/middle`) key, e.g. `"3"` or `"3/2"`.
    pub key: String,
    /// Display name.
    pub name: String,
}

/// A com-object instance reference on a device.
#[derive(Debug, Clone)]
pub struct RawComObjectInstance {
    /// The instance `RefId` (relative, e.g. `O-0_R-1`).
    pub ref_id: String,
    /// The `Links` GA ref suffixes, in order (first = sending GA).
    pub links: Vec<String>,
    /// Instance-level DPT override.
    pub dpt: Option<Dpt>,
    /// Instance-level flag overrides.
    pub flags: FlagSet,
    /// `ChannelId`, if any.
    pub channel: Option<String>,
    /// Instance-level object-size override.
    pub object_size: Option<String>,
    /// The instance's `Security` attribute, when ETS wrote one (absent means
    /// the ETS default, `Auto`).
    pub security: Option<SecuritySetting>,
}

/// A device instance as read from the topology.
#[derive(Debug, Clone)]
pub struct RawDevice {
    /// The `Id` attribute (e.g. `P-05E7-0_DI-1`), used by locations.
    pub id: String,
    /// The resolved individual address.
    pub address: IndividualAddress,
    /// Display name (may be empty).
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// `ProductRefId`.
    pub product_ref_id: Option<String>,
    /// `Hardware2ProgramRefId`.
    pub hardware2program_ref_id: Option<String>,
    /// The com-object instances on this device.
    pub com_objects: Vec<RawComObjectInstance>,
    /// Module instances on this device, keyed by module-instance id
    /// (e.g. `MD-1_M-6_MI-1`); the value maps argument ref id → value.
    pub module_instances: HashMap<String, HashMap<String, String>>,
    /// Parameter instance references on this device: `(RefId, Value)` in
    /// document order. The `RefId` is a fully-qualified `ParameterRef` id (with
    /// the module-instance selector preserved for module parameters); the
    /// `Value` is the configured value. Only instances that carry a `Value` are
    /// recorded — an absent `Value` means the ref/type default applies and there
    /// is nothing to store.
    pub parameters: Vec<(String, String)>,
    /// The ETS-tracked KNX Data Secure sequence number from the device's
    /// `<Security SequenceNumber="…">` child, if present (issue #71, spec §11).
    /// Flags/state only — never a key.
    pub secure_sequence_number: Option<u64>,
    /// Whether a `<DeviceCertificate>` (the factory FDSK certificate) was present
    /// for this device in the knxproj (issue #71, spec §11). Presence only; the
    /// FDSK value is deliberately NOT captured (spec §2.2).
    pub has_device_certificate: bool,
    /// The device's `<Security>` child carries a `ToolKey`: secure
    /// commissioning is enabled for it in the project. Presence only.
    pub has_tool_key: bool,
    /// The device's `<Security>` child carries a `LoadedToolKey`: ETS has
    /// loaded the tool key into the device, i.e. Data Secure is activated.
    /// Presence only.
    pub has_loaded_tool_key: bool,
}

/// A device's location within the building.
#[derive(Debug, Clone, Default)]
pub struct RawLocation {
    /// Nearest enclosing floor name.
    pub floor: Option<String>,
    /// Nearest enclosing room name.
    pub room: Option<String>,
}

/// The group-address numbering style declared in `project.xml`.
///
/// ETS projects address group values in one of three styles. bussard's
/// [`GroupAddress`] model is fixed to the 3-level `main/middle/sub` layout, so
/// only [`ThreeLevel`](GroupAddressStyle::ThreeLevel) can be imported without
/// corrupting the addresses; the other two are detected so the importer can
/// refuse with a clear message rather than silently mis-splitting raw addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupAddressStyle {
    /// `main/middle/sub` (5/3/8 bits). The only style bussard imports today.
    ThreeLevel,
    /// `main/sub` (5/11 bits).
    TwoLevel,
    /// A single flat 16-bit number.
    Free,
}

impl GroupAddressStyle {
    /// Parses the `GroupAddressStyle` attribute value from `project.xml`.
    ///
    /// ETS writes `"ThreeLevel"`, `"TwoLevel"`, or `"Free"`. Unknown values map
    /// to `None`.
    pub fn from_attr(s: &str) -> Option<Self> {
        match s {
            "ThreeLevel" => Some(Self::ThreeLevel),
            "TwoLevel" => Some(Self::TwoLevel),
            "Free" => Some(Self::Free),
            _ => None,
        }
    }
}

impl std::fmt::Display for GroupAddressStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GroupAddressStyle::ThreeLevel => "ThreeLevel",
            GroupAddressStyle::TwoLevel => "TwoLevel",
            GroupAddressStyle::Free => "Free",
        };
        f.write_str(s)
    }
}

/// The project metadata read from `project.xml`.
///
/// ETS stores the human project name and the group-address numbering style in a
/// separate `project.xml` (the topology, group addresses and devices live in
/// `0.xml`). This is parsed independently of [`parse_project`].
#[derive(Debug, Clone, Default)]
pub struct ProjectInfo {
    /// The `ProjectInformation@Name`, if present and non-empty.
    pub name: Option<String>,
    /// The declared `GroupAddressStyle`, if present and recognised.
    pub group_address_style: Option<GroupAddressStyle>,
}

/// Parses `project.xml` for the project name and group-address style.
///
/// The relevant element is `<Project><ProjectInformation Name="…"
/// GroupAddressStyle="ThreeLevel" …/></Project>`. Only those two attributes are
/// read; everything else is ignored. Returns an empty [`ProjectInfo`] if the
/// element is absent.
pub fn parse_project_info(xml: &str) -> Result<ProjectInfo> {
    let context = "project project.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut info = ProjectInfo::default();
    loop {
        let ev = reader.read_event().map_err(|source| ImportError::Xml {
            context: context.to_string(),
            source,
        })?;
        match ev {
            Event::Eof => break,
            // `ProjectInformation` may be a start tag (it can carry children like
            // `HistoryEntries`) or, in leaner exports, an empty element.
            Event::Start(e) | Event::Empty(e)
                if e.local_name().as_ref() == b"ProjectInformation" =>
            {
                info.name = non_empty(attr(&e, b"Name", context)?.as_deref());
                info.group_address_style = attr(&e, b"GroupAddressStyle", context)?
                    .as_deref()
                    .and_then(GroupAddressStyle::from_attr);
                // The first ProjectInformation is authoritative; stop early.
                break;
            }
            _ => {}
        }
    }
    Ok(info)
}

/// The parsed project.
#[derive(Debug, Clone, Default)]
pub struct RawProject {
    /// Project id (`P-XXXX`).
    pub project_id: Option<String>,
    /// Project display name.
    pub project_name: Option<String>,
    /// Group-address ranges (two levels), in document order.
    pub ranges: Vec<RawRange>,
    /// Group addresses.
    pub group_addresses: Vec<RawGroupAddress>,
    /// Devices.
    pub devices: Vec<RawDevice>,
    /// Locations keyed by device `Id`.
    pub locations: HashMap<String, RawLocation>,
}

/// Reads an attribute as an owned string.
fn attr(e: &BytesStart, key: &[u8], context: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a.map_err(|source| ImportError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        if a.key.as_ref() == key {
            let v = a.unescape_value().map_err(|source| ImportError::Xml {
                context: context.to_string(),
                source,
            })?;
            return Ok(Some(v.into_owned()));
        }
    }
    Ok(None)
}

/// Reads all attributes into a map.
fn attrs(e: &BytesStart, context: &str) -> Result<HashMap<Vec<u8>, String>> {
    let mut map = HashMap::new();
    for a in e.attributes() {
        let a = a.map_err(|source| ImportError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        let v = a
            .unescape_value()
            .map_err(|source| ImportError::Xml {
                context: context.to_string(),
                source,
            })?
            .into_owned();
        map.insert(a.key.as_ref().to_vec(), v);
    }
    Ok(map)
}

fn get<'a>(m: &'a HashMap<Vec<u8>, String>, k: &[u8]) -> Option<&'a str> {
    m.get(k).map(String::as_str)
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.filter(|v| !v.is_empty()).map(str::to_string)
}

/// The `GA-N` suffix of a group-address `Id` like `P-05E7-0_GA-213`.
fn ga_suffix(id: &str) -> String {
    id.rsplit('_').next().unwrap_or(id).to_string()
}

/// Parses the project `0.xml`.
///
/// `schema` selects the com-object link encoding: ETS 5.7 and ETS 6 (schema
/// ≥ 20) carry the linked group addresses in a space-separated `Links`
/// attribute on `ComObjectInstanceRef`; ETS 4 and ETS 5≤5.6 (schema < 20) carry
/// them instead in `Connectors/Send` and `Connectors/Receive` child elements,
/// each with a `GroupAddressRefId` of the `<projectId>_<gaId>` form.
pub fn parse_project(xml: &str, schema: SchemaVersion) -> Result<RawProject> {
    let context = "project 0.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let uses_links_attr = schema.uses_links_attribute();
    // The com-object instance currently being assembled from `Connectors`
    // children (ETS 4/5 form only); its `Send` GA leads its `Receive` GAs.
    let mut current_com_object: Option<RawComObjectInstance> = None;

    let mut project = RawProject::default();

    // Topology nesting: current area/line addresses.
    let mut area_addr: Option<u8> = None;
    let mut line_addr: Option<u8> = None;

    // Group-range nesting depth (1 = main range, 2 = middle range).
    let mut range_depth: u32 = 0;

    // Location nesting: stack of (type, name) for enclosing spaces.
    let mut space_stack: Vec<(String, Option<String>)> = Vec::new();

    // Current device being assembled.
    let mut current_device: Option<RawDevice> = None;
    // Whether we're inside a ComObjectInstanceRefs block of the current device.
    let mut in_com_object_refs = false;
    // Whether we're inside a ParameterInstanceRefs block of the current device.
    let mut in_parameter_refs = false;
    // The id of the module instance whose `<Arguments>` we are currently reading.
    let mut current_module_instance: Option<String> = None;

    loop {
        let ev = reader.read_event().map_err(|source| ImportError::Xml {
            context: context.to_string(),
            source,
        })?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                match e.local_name().as_ref() {
                    b"Project" => {
                        project.project_id = attr(&e, b"Id", context)?;
                    }
                    b"Area" => {
                        area_addr =
                            attr(&e, b"Address", context)?.and_then(|v| v.parse::<u8>().ok());
                    }
                    b"Line" => {
                        line_addr =
                            attr(&e, b"Address", context)?.and_then(|v| v.parse::<u8>().ok());
                    }
                    b"GroupRange" => {
                        // The range key mirrors ETS numbering, derived from
                        // `RangeStart`: a top-level range is the main group
                        // (`RangeStart >> 11`); a nested range is `main/middle`
                        // (`(RangeStart >> 8) & 7`).
                        range_depth += 1;
                        let name = attr(&e, b"Name", context)?.unwrap_or_default();
                        let range_start = attr(&e, b"RangeStart", context)?
                            .and_then(|v| v.parse::<u16>().ok())
                            .unwrap_or(0);
                        let main = range_start >> 11;
                        let middle = (range_start >> 8) & 0x7;
                        let key = if range_depth <= 1 {
                            format!("{main}")
                        } else {
                            format!("{main}/{middle}")
                        };
                        project.ranges.push(RawRange { key, name });
                    }
                    b"DeviceInstance" => {
                        current_device = parse_device_start(&e, area_addr, line_addr, context)?;
                    }
                    b"ComObjectInstanceRefs" => {
                        in_com_object_refs = true;
                    }
                    // ETS 4/5 form: `ComObjectInstanceRef` is a *start* tag whose
                    // `Connectors/Send`+`Receive` children hold the links. Begin
                    // assembling it; links accrue from the child elements below,
                    // and the End handler pushes it onto the device.
                    b"ComObjectInstanceRef" if in_com_object_refs && !uses_links_attr => {
                        current_com_object = parse_com_object_instance(&e, context)?;
                    }
                    b"ParameterInstanceRefs" => {
                        in_parameter_refs = true;
                    }
                    b"ModuleInstance" => {
                        if let (Some(dev), Some(id)) =
                            (current_device.as_mut(), attr(&e, b"Id", context)?)
                        {
                            dev.module_instances.entry(id.clone()).or_default();
                            current_module_instance = Some(id);
                        }
                    }
                    b"Space" => {
                        let ty = attr(&e, b"Type", context)?.unwrap_or_default();
                        let name = attr(&e, b"Name", context)?;
                        space_stack.push((ty, name));
                    }
                    // KNX Secure state (issue #71, spec §11): a `<Security>` start
                    // tag (it may carry children) still carries the sequence
                    // number attribute. Flags/state only, never a key.
                    b"Security" => {
                        if let Some(dev) = current_device.as_mut() {
                            apply_device_security(dev, &e, context)?;
                        }
                    }
                    _ => {}
                }
            }
            Event::Empty(e) => {
                match e.local_name().as_ref() {
                    b"GroupAddress" => {
                        if let Some(ga) = parse_group_address(&e, context)? {
                            project.group_addresses.push(ga);
                        }
                    }
                    b"ComObjectInstanceRef" => {
                        if in_com_object_refs {
                            // ETS 5.7/6 form: a self-closing element carrying the
                            // space-separated `Links` attribute directly.
                            if let Some(dev) = current_device.as_mut() {
                                if let Some(ci) = parse_com_object_instance(&e, context)? {
                                    dev.com_objects.push(ci);
                                }
                            }
                        }
                    }
                    // ETS 4/5 link children: `Send` leads, `Receive` follows.
                    b"Send" | b"Receive" if current_com_object.is_some() => {
                        if let Some(suffix) = connector_ga_suffix(&e, context)? {
                            if let Some(ci) = current_com_object.as_mut() {
                                // `Send` is the primary/sending GA: keep it first.
                                if e.local_name().as_ref() == b"Send" {
                                    ci.links.insert(0, suffix);
                                } else {
                                    ci.links.push(suffix);
                                }
                            }
                        }
                    }
                    b"ParameterInstanceRef" => {
                        if in_parameter_refs {
                            if let Some(dev) = current_device.as_mut() {
                                if let (Some(ref_id), Some(value)) =
                                    (attr(&e, b"RefId", context)?, attr(&e, b"Value", context)?)
                                {
                                    dev.parameters.push((ref_id, value));
                                }
                            }
                        }
                    }
                    b"Argument" => {
                        if let (Some(dev), Some(mi_id)) =
                            (current_device.as_mut(), current_module_instance.as_ref())
                        {
                            if let (Some(ref_id), Some(value)) =
                                (attr(&e, b"RefId", context)?, attr(&e, b"Value", context)?)
                            {
                                if let Some(args) = dev.module_instances.get_mut(mi_id) {
                                    args.insert(ref_id, value);
                                }
                            }
                        }
                    }
                    b"DeviceInstanceRef" => {
                        // Attach the current location to this device id.
                        if let Some(ref_id) = attr(&e, b"RefId", context)? {
                            let loc = current_location(&space_stack);
                            project.locations.insert(ref_id, loc);
                        }
                    }
                    // KNX Secure state (issue #71, spec §11): the ETS-tracked
                    // Data Secure sequence number, if the device carries a
                    // `<Security SequenceNumber="…">` child. Flags/state only.
                    b"Security" => {
                        if let Some(dev) = current_device.as_mut() {
                            apply_device_security(dev, &e, context)?;
                        }
                    }
                    // Factory FDSK certificate presence (spec §11 / §2.2): record
                    // ONLY that a certificate exists — never the FDSK value.
                    b"DeviceCertificate" => {
                        if let Some(dev) = current_device.as_mut() {
                            dev.has_device_certificate = true;
                        }
                    }
                    // A self-closing DeviceInstance (no com-objects): finalize.
                    b"DeviceInstance" => {
                        if let Some(dev) = parse_device_start(&e, area_addr, line_addr, context)? {
                            project.devices.push(dev);
                        }
                    }
                    _ => {}
                }
            }
            Event::End(e) => match e.local_name().as_ref() {
                b"GroupRange" => {
                    if range_depth >= 1 {
                        range_depth -= 1;
                    }
                }
                b"DeviceInstance" => {
                    if let Some(dev) = current_device.take() {
                        project.devices.push(dev);
                    }
                }
                // ETS 4/5 form: close the instance assembled from `Connectors`
                // children and attach it to the current device.
                b"ComObjectInstanceRef" => {
                    if let (Some(dev), Some(ci)) =
                        (current_device.as_mut(), current_com_object.take())
                    {
                        dev.com_objects.push(ci);
                    }
                }
                b"ComObjectInstanceRefs" => {
                    in_com_object_refs = false;
                }
                b"ParameterInstanceRefs" => {
                    in_parameter_refs = false;
                }
                b"ModuleInstance" => {
                    current_module_instance = None;
                }
                b"Space" => {
                    space_stack.pop();
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(project)
}

/// Builds a [`RawDevice`] from a `DeviceInstance` start/empty tag.
fn parse_device_start(
    e: &BytesStart,
    area: Option<u8>,
    line: Option<u8>,
    context: &str,
) -> Result<Option<RawDevice>> {
    let m = attrs(e, context)?;
    let addr_raw = match get(&m, b"Address").and_then(|v| v.parse::<u8>().ok()) {
        Some(a) => a,
        None => return Ok(None),
    };
    let (area, line) = match (area, line) {
        (Some(a), Some(l)) => (a, l),
        _ => {
            return Err(ImportError::Malformed {
                context: context.to_string(),
                message: format!(
                    "DeviceInstance {} has no enclosing Area/Line",
                    get(&m, b"Id").unwrap_or("?")
                ),
            });
        }
    };
    let address =
        IndividualAddress::new(area, line, addr_raw).map_err(|e| ImportError::Malformed {
            context: context.to_string(),
            message: format!("invalid individual address {area}.{line}.{addr_raw}: {e}"),
        })?;

    Ok(Some(RawDevice {
        id: get(&m, b"Id").unwrap_or_default().to_string(),
        address,
        name: get(&m, b"Name").unwrap_or_default().to_string(),
        description: non_empty(get(&m, b"Description")),
        product_ref_id: non_empty(get(&m, b"ProductRefId")),
        hardware2program_ref_id: non_empty(get(&m, b"Hardware2ProgramRefId")),
        com_objects: Vec::new(),
        module_instances: HashMap::new(),
        parameters: Vec::new(),
        secure_sequence_number: None,
        has_device_certificate: false,
        has_tool_key: false,
        has_loaded_tool_key: false,
    }))
}

/// Records a device's `<Security>` child: the sequence number, and whether the
/// project holds a tool key (`ToolKey`) and whether ETS has loaded it into the
/// device (`LoadedToolKey`).
///
/// CONFIRMED against two exports of the same project (issue #156): before ETS
/// activated Data Secure on 1.1.12 its child was
/// `<Security SequenceNumber=… SequenceNumberTimestamp=…/>`; after the secured
/// download it is `<Security ToolKey=… LoadedToolKey=… SequenceNumber=… …/>`,
/// while 1.1.10 (secure commissioning enabled, never downloaded) carries
/// `ToolKey` without `LoadedToolKey`. The key values themselves are never read
/// into the model: only their presence is recorded (keys come from the
/// `.knxkeys` keyring).
fn apply_device_security(dev: &mut RawDevice, e: &BytesStart, context: &str) -> Result<()> {
    let m = attrs(e, context)?;
    if let Some(seq) = get(&m, b"SequenceNumber").and_then(|s| s.parse::<u64>().ok()) {
        dev.secure_sequence_number = Some(seq);
    }
    dev.has_tool_key |= get(&m, b"ToolKey").is_some_and(|v| !v.is_empty());
    dev.has_loaded_tool_key |= get(&m, b"LoadedToolKey").is_some_and(|v| !v.is_empty());
    Ok(())
}

/// The ETS per-object / per-address Data Secure setting (`Security` attribute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySetting {
    /// `Security="On"`: always Data Secure.
    On,
    /// `Security="Off"`: never Data Secure.
    Off,
    /// `Security="Auto"` (the ETS default): secure when the linked group
    /// addresses are.
    Auto,
}

impl SecuritySetting {
    /// Parses an ETS `Security` attribute value; unknown values map to `None`.
    pub fn from_attr(value: &str) -> Option<Self> {
        match value {
            "On" => Some(Self::On),
            "Off" => Some(Self::Off),
            "Auto" => Some(Self::Auto),
            _ => None,
        }
    }
}

/// Parses a `GroupAddress` element.
fn parse_group_address(e: &BytesStart, context: &str) -> Result<Option<RawGroupAddress>> {
    let m = attrs(e, context)?;
    let id = match get(&m, b"Id") {
        Some(v) => v,
        None => return Ok(None),
    };
    let raw = match get(&m, b"Address").and_then(|v| v.parse::<u16>().ok()) {
        Some(v) => v,
        None => return Ok(None),
    };
    Ok(Some(RawGroupAddress {
        ref_suffix: ga_suffix(id),
        address: GroupAddress::from_raw(raw),
        name: get(&m, b"Name").unwrap_or_default().to_string(),
        dpt: get(&m, b"DatapointType").and_then(parse_ets_dpt),
        description: non_empty(get(&m, b"Description")),
        secure: match get(&m, b"Security").and_then(SecuritySetting::from_attr) {
            Some(SecuritySetting::On) => true,
            Some(SecuritySetting::Off) => false,
            Some(SecuritySetting::Auto) | None => get(&m, b"Key").is_some_and(|k| !k.is_empty()),
        },
    }))
}

/// Parses a `ComObjectInstanceRef` element.
fn parse_com_object_instance(
    e: &BytesStart,
    context: &str,
) -> Result<Option<RawComObjectInstance>> {
    let m = attrs(e, context)?;
    let ref_id = match get(&m, b"RefId") {
        Some(v) => v.to_string(),
        None => return Ok(None),
    };
    let links = get(&m, b"Links")
        .map(|s| {
            s.split_whitespace()
                .map(|t| t.rsplit('_').next().unwrap_or(t).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let flags = FlagSet {
        communication: get(&m, b"CommunicationFlag").and_then(parse_flag_value),
        read: get(&m, b"ReadFlag").and_then(parse_flag_value),
        write: get(&m, b"WriteFlag").and_then(parse_flag_value),
        transmit: get(&m, b"TransmitFlag").and_then(parse_flag_value),
        update: get(&m, b"UpdateFlag").and_then(parse_flag_value),
        read_on_init: get(&m, b"ReadOnInitFlag").and_then(parse_flag_value),
    };
    Ok(Some(RawComObjectInstance {
        ref_id,
        links,
        dpt: get(&m, b"DatapointType").and_then(parse_ets_dpt),
        flags,
        channel: non_empty(get(&m, b"ChannelId")),
        object_size: non_empty(get(&m, b"ObjectSize")),
        security: get(&m, b"Security").and_then(SecuritySetting::from_attr),
    }))
}

/// Extracts the `GA-N` suffix from a `Send`/`Receive` connector element's
/// `GroupAddressRefId` (ETS 4/5 form), whose value is `<projectId>_<gaId>`.
///
/// Returns `None` if the attribute is absent (a connector with no linked GA).
fn connector_ga_suffix(e: &BytesStart, context: &str) -> Result<Option<String>> {
    Ok(attr(e, b"GroupAddressRefId", context)?
        .map(|id| id.rsplit('_').next().unwrap_or(&id).to_string()))
}

/// Computes the nearest floor/room from the current space stack.
fn current_location(stack: &[(String, Option<String>)]) -> RawLocation {
    let mut loc = RawLocation::default();
    for (ty, name) in stack {
        match ty.as_str() {
            "Floor" => loc.floor = name.clone(),
            "Room" => loc.room = name.clone(),
            _ => {}
        }
    }
    loc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_project_info_extracts_name_and_three_level_style() {
        // Fabricated project.xml mirroring the real ETS layout (no real data).
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <Project Id="P-0001">
    <ProjectInformation Name="Test Home" GroupAddressStyle="ThreeLevel" Comment="x">
      <HistoryEntries/>
    </ProjectInformation>
  </Project>
</KNX>"#;
        let info = parse_project_info(xml).unwrap();
        assert_eq!(info.name.as_deref(), Some("Test Home"));
        assert_eq!(
            info.group_address_style,
            Some(GroupAddressStyle::ThreeLevel)
        );
    }

    #[test]
    fn parse_project_info_detects_two_level_and_free_styles() {
        for (attr, expect) in [
            ("TwoLevel", GroupAddressStyle::TwoLevel),
            ("Free", GroupAddressStyle::Free),
        ] {
            let xml = format!(
                r#"<KNX><Project Id="P-1"><ProjectInformation Name="N" GroupAddressStyle="{attr}"/></Project></KNX>"#
            );
            let info = parse_project_info(&xml).unwrap();
            assert_eq!(info.group_address_style, Some(expect), "style {attr}");
        }
    }

    #[test]
    fn parse_project_info_handles_empty_element_and_missing_fields() {
        // Self-closing ProjectInformation with no GroupAddressStyle.
        let xml = r#"<KNX><Project><ProjectInformation Name="Only Name"/></Project></KNX>"#;
        let info = parse_project_info(xml).unwrap();
        assert_eq!(info.name.as_deref(), Some("Only Name"));
        assert_eq!(info.group_address_style, None);

        // No ProjectInformation at all -> empty info.
        let xml = r#"<KNX><Project Id="P-1"/></KNX>"#;
        let info = parse_project_info(xml).unwrap();
        assert!(info.name.is_none());
        assert!(info.group_address_style.is_none());

        // Empty Name is treated as absent.
        let xml = r#"<KNX><ProjectInformation Name="" GroupAddressStyle="ThreeLevel"/></KNX>"#;
        let info = parse_project_info(xml).unwrap();
        assert!(info.name.is_none());
        assert_eq!(
            info.group_address_style,
            Some(GroupAddressStyle::ThreeLevel)
        );
    }

    #[test]
    fn test_parse_project_ets6_links_attribute() {
        // ETS 5.7/6 form (schema >= 20): links in a space-separated `Links`
        // attribute on a self-closing ComObjectInstanceRef. Synthetic data.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <Project Id="P-0001">
    <Installations><Installation>
      <Topology>
        <Area Address="1"><Line Address="1">
          <DeviceInstance Id="P-0001-0_DI-1" Address="4" Name="Switch">
            <ComObjectInstanceRefs>
              <ComObjectInstanceRef RefId="O-1_R-1" Links="P-0001_GA-10 P-0001_GA-11"/>
            </ComObjectInstanceRefs>
          </DeviceInstance>
        </Line></Area>
      </Topology>
    </Installation></Installations>
  </Project>
</KNX>"#;
        let schema = SchemaVersion::from_version(23).unwrap();
        let project = parse_project(xml, schema).unwrap();
        let dev = &project.devices[0];
        assert_eq!(dev.com_objects.len(), 1);
        assert_eq!(dev.com_objects[0].links, vec!["GA-10", "GA-11"]);
    }

    #[test]
    fn test_parse_project_secure_state_and_group_keys()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Synthetic data shaped like the post-activation ETS 6.4 export (issue
        // #156): an activated device (ToolKey + LoadedToolKey), one with secure
        // commissioning configured only (ToolKey), a keyed GA and explicit
        // `Security` settings. The attribute values are placeholders, not keys.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <Project Id="P-0001">
    <Installations><Installation>
      <Topology>
        <Area Address="1"><Line Address="1">
          <DeviceInstance Id="P-0001-0_DI-1" Address="12" Name="Activated">
            <ComObjectInstanceRefs>
              <ComObjectInstanceRef RefId="O-1_R-1" Links="GA-1"/>
              <ComObjectInstanceRef RefId="O-2_R-2" Links="GA-2" Security="On"/>
              <ComObjectInstanceRef RefId="O-3_R-3" Links="GA-1" Security="Off"/>
            </ComObjectInstanceRefs>
            <Security ToolKey="cGxhY2Vob2xkZXI=" LoadedToolKey="cGxhY2Vob2xkZXI=" SequenceNumber="42" SequenceNumberTimestamp="2026-09-23T19:12:40Z" />
          </DeviceInstance>
          <DeviceInstance Id="P-0001-0_DI-2" Address="10" Name="Configured">
            <Security ToolKey="cGxhY2Vob2xkZXI=" SequenceNumber="7" />
          </DeviceInstance>
          <DeviceInstance Id="P-0001-0_DI-3" Address="11" Name="Capable">
            <Security SequenceNumber="9" />
          </DeviceInstance>
        </Line></Area>
      </Topology>
      <GroupAddresses><GroupRanges><GroupRange Id="P-0001-0_GR-1" RangeStart="1" RangeEnd="2047" Name="R">
        <GroupAddress Id="P-0001-0_GA-1" Address="815" Name="Secured" Key="cGxhY2Vob2xkZXI=" />
        <GroupAddress Id="P-0001-0_GA-2" Address="816" Name="Plain" />
        <GroupAddress Id="P-0001-0_GA-3" Address="817" Name="Forced" Security="On" />
        <GroupAddress Id="P-0001-0_GA-4" Address="818" Name="Off" Security="Off" Key="cGxhY2Vob2xkZXI=" />
      </GroupRange></GroupRanges></GroupAddresses>
    </Installation></Installations>
  </Project>
</KNX>"#;
        let schema = SchemaVersion::from_version(23)?;
        let project = parse_project(xml, schema)?;
        let dev = |a: u8| project.devices.iter().find(|d| d.address.device() == a);
        let activated = dev(12).ok_or("1.1.12")?;
        assert!(activated.has_tool_key && activated.has_loaded_tool_key);
        assert_eq!(activated.secure_sequence_number, Some(42));
        assert_eq!(activated.com_objects[0].security, None);
        assert_eq!(activated.com_objects[1].security, Some(SecuritySetting::On));
        assert_eq!(
            activated.com_objects[2].security,
            Some(SecuritySetting::Off)
        );
        let configured = dev(10).ok_or("1.1.10")?;
        assert!(configured.has_tool_key && !configured.has_loaded_tool_key);
        let capable = dev(11).ok_or("1.1.11")?;
        assert!(!capable.has_tool_key && !capable.has_loaded_tool_key);
        assert_eq!(capable.secure_sequence_number, Some(9));
        let secure: Vec<(u16, bool)> = project
            .group_addresses
            .iter()
            .map(|g| (g.address.raw(), g.secure))
            .collect();
        assert_eq!(
            secure,
            vec![(815, true), (816, false), (817, true), (818, false)]
        );
        Ok(())
    }

    #[test]
    fn test_parse_project_ets4_connectors_links() {
        // ETS 4/5 form (schema < 20): links in Connectors/Send + Receive child
        // elements, each with a `<projectId>_<gaId>` GroupAddressRefId.
        // Synthetic hand-written data (no vendored fixtures).
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/11">
  <Project Id="P-0001">
    <Installations><Installation>
      <Topology>
        <Area Address="1"><Line Address="1">
          <DeviceInstance Id="P-0001-0_DI-1" Address="4" Name="Switch">
            <ComObjectInstanceRefs>
              <ComObjectInstanceRef RefId="O-1_R-1" CommunicationFlag="Enabled" TransmitFlag="Enabled">
                <Connectors>
                  <Send GroupAddressRefId="P-0001_GA-10"/>
                  <Receive GroupAddressRefId="P-0001_GA-11"/>
                  <Receive GroupAddressRefId="P-0001_GA-12"/>
                </Connectors>
              </ComObjectInstanceRef>
            </ComObjectInstanceRefs>
          </DeviceInstance>
        </Line></Area>
      </Topology>
    </Installation></Installations>
  </Project>
</KNX>"#;
        let schema = SchemaVersion::from_version(11).unwrap();
        let project = parse_project(xml, schema).unwrap();
        let dev = &project.devices[0];
        assert_eq!(dev.com_objects.len(), 1);
        // Send GA leads; the two Receive GAs follow, in order.
        assert_eq!(dev.com_objects[0].links, vec!["GA-10", "GA-11", "GA-12"]);
        assert_eq!(dev.com_objects[0].ref_id, "O-1_R-1");
    }

    #[test]
    fn test_parse_project_ets4_receive_only_com_object() {
        // A listen-only object in ETS 4/5 form: no Send, only Receive children.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/14">
  <Project Id="P-0001"><Installations><Installation><Topology>
    <Area Address="1"><Line Address="1">
      <DeviceInstance Id="P-0001-0_DI-1" Address="4" Name="Sensor">
        <ComObjectInstanceRefs>
          <ComObjectInstanceRef RefId="O-2_R-1">
            <Connectors><Receive GroupAddressRefId="P-0001_GA-20"/></Connectors>
          </ComObjectInstanceRef>
        </ComObjectInstanceRefs>
      </DeviceInstance>
    </Line></Area>
  </Topology></Installation></Installations></Project>
</KNX>"#;
        let schema = SchemaVersion::from_version(14).unwrap();
        let project = parse_project(xml, schema).unwrap();
        let dev = &project.devices[0];
        assert_eq!(dev.com_objects[0].links, vec!["GA-20"]);
    }

    #[test]
    fn group_address_style_from_attr_rejects_unknown() {
        assert_eq!(
            GroupAddressStyle::from_attr("ThreeLevel"),
            Some(GroupAddressStyle::ThreeLevel)
        );
        assert_eq!(GroupAddressStyle::from_attr("Nonsense"), None);
        assert_eq!(GroupAddressStyle::ThreeLevel.to_string(), "ThreeLevel");
    }
}
