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
}

/// A device's location within the building.
#[derive(Debug, Clone, Default)]
pub struct RawLocation {
    /// Nearest enclosing floor name.
    pub floor: Option<String>,
    /// Nearest enclosing room name.
    pub room: Option<String>,
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
pub fn parse_project(xml: &str) -> Result<RawProject> {
    let context = "project 0.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

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
                            if let Some(dev) = current_device.as_mut() {
                                if let Some(ci) = parse_com_object_instance(&e, context)? {
                                    dev.com_objects.push(ci);
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
    }))
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
    }))
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
