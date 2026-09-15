//! The on-disk YAML schema for a bussard KNX-as-code repository.
//!
//! These structs mirror the files described in the design document (§5.2):
//! `bussard.yaml`, `groups.yaml`, `links.yaml` and `devices/*.yaml`. All use
//! `deny_unknown_fields` so typos are rejected rather than silently ignored.
//!
//! Serialization is isolated in the [`crate::loader`] module; these types just
//! define the shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::address::{GroupAddress, IndividualAddress};
use crate::dpt::Dpt;
use crate::flags::Flags;

/// The default routing multicast endpoint (`224.0.23.12:3671`).
pub const DEFAULT_MULTICAST: &str = "224.0.23.12:3671";

/// The transport used to reach the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// KNXnet/IP tunneling (unicast to a gateway).
    Tunnel,
    /// KNXnet/IP routing (multicast).
    Routing,
}

/// Connection configuration (`bussard.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BussardConfig {
    /// Connection settings.
    #[serde(default)]
    pub connection: Connection,
}

/// The `connection` block of `bussard.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    /// Transport to use.
    pub transport: Transport,
    /// Gateway `host:port` for tunneling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Multicast `addr:port` for routing (default `224.0.23.12:3671`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multicast: Option<String>,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            transport: Transport::Tunnel,
            gateway: None,
            multicast: None,
        }
    }
}

/// The group-address plan (`groups.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Groups {
    /// Optional project name metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Optional provenance metadata (e.g. source `.knxproj`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<String>,
    /// Named main/middle ranges, keyed by `"3"` or `"3/2"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ranges: BTreeMap<String, Range>,
    /// The group addresses, keyed by GA.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<GroupAddress, Group>,
}

/// A named GA range (main or main/middle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    /// Display name for the range.
    pub name: String,
}

/// A single group address definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Display name.
    pub name: String,
    /// Datapoint type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<Dpt>,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this GA is safety-critical and guarded against casual writes.
    ///
    /// When `true`, the CLI refuses to write to it without `--force` and the MCP
    /// server refuses outright (there is no MCP override). Used for objects like
    /// a wind alarm or central functions (see the design document §8). Serialized
    /// only when `true`, so unprotected GAs stay diff-clean.
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected: bool,
}

/// Serde helper: skip a `bool` field when it is `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Com-object → GA assignments (`links.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Links {
    /// Links keyed by device individual address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<IndividualAddress, Vec<Link>>,
}

/// A single com-object link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    /// The ETS com-object number (the stable handle).
    pub object: u16,
    /// Informational name (refreshed on import).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The single sending GA, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<GroupAddress>,
    /// The listening GAs (may be empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen: Vec<GroupAddress>,
}

/// A device definition (`devices/*.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// The device's individual address.
    pub address: IndividualAddress,
    /// Display name.
    pub name: String,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Physical location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Product identity (for matching `.knxprod` in later phases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// Named channels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, Channel>,
    /// Generated com-object table, keyed by com-object number.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub com_objects: BTreeMap<u16, ComObject>,
}

/// A device's physical location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    /// Floor, e.g. `"EG"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
    /// Room, e.g. `"Wohnzimmer"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
}

/// Product identity for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Manufacturer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// Manufacturer reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer_ref: Option<String>,
    /// Order number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// Hardware reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_ref: Option<String>,
    /// Application program reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ref: Option<String>,
    /// Mask version (decides property- vs memory-based links).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
}

/// A named device channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// Channel display name.
    pub name: String,
}

/// A single generated com object on a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComObject {
    /// Display name.
    pub name: String,
    /// Datapoint type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<Dpt>,
    /// Declared size string (e.g. `"1 bit"`), if given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// Communication flags.
    pub flags: Flags,
    /// Cross-reference id from the product data (`ref` is a keyword).
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Owning channel key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}
