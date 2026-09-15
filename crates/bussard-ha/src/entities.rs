//! The Home Assistant KNX entity types and the output document.
//!
//! These structs serialize to the `knx:` platform schema documented at
//! <https://www.home-assistant.io/integrations/knx/>. The document groups
//! entities by platform (`switch`, `light`, `cover`, `sensor`,
//! `binary_sensor`), each a list. Group addresses serialize as their 3-level
//! string form (e.g. `"1/0/4"`), matching what HA expects.
//!
//! Only the fields bussard can derive from the model are emitted; all optional
//! fields use `skip_serializing_if` so the output stays minimal and stable.

use bussard_model::GroupAddress;
use serde::Serialize;

/// The platform an entity belongs to. Determines which list it lands in and how
/// entities sort relative to one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    /// A `binary_sensor` entity.
    BinarySensor,
    /// A `climate` entity.
    Climate,
    /// A `cover` entity.
    Cover,
    /// A `light` entity.
    Light,
    /// A `sensor` entity.
    Sensor,
    /// A `switch` entity.
    Switch,
}

impl Platform {
    /// The YAML key this platform lives under in the `knx:` document.
    pub fn key(self) -> &'static str {
        match self {
            Platform::BinarySensor => "binary_sensor",
            Platform::Climate => "climate",
            Platform::Cover => "cover",
            Platform::Light => "light",
            Platform::Sensor => "sensor",
            Platform::Switch => "switch",
        }
    }
}

/// A `switch` entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Switch {
    /// Display name.
    pub name: String,
    /// The GA on/off commands are sent to.
    pub address: GroupAddress,
    /// The GA the switch state is read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_address: Option<GroupAddress>,
    /// HA device class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_class: Option<String>,
}

/// A `light` entity (a switchable actuator promoted to a light).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Light {
    /// Display name.
    pub name: String,
    /// The GA that switches the light on/off.
    pub address: GroupAddress,
    /// The GA the on/off state is read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_address: Option<GroupAddress>,
    /// The GA brightness is written to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brightness_address: Option<GroupAddress>,
    /// The GA brightness is read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brightness_state_address: Option<GroupAddress>,
}

/// A `cover` entity (a jalousie / blind / shutter channel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cover {
    /// Display name.
    pub name: String,
    /// The GA for long (full) up/down movement (1.008).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub move_long_address: Option<GroupAddress>,
    /// The GA for short (step) movement / stop (1.007).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub move_short_address: Option<GroupAddress>,
    /// The GA position is written to (5.001, 0–100 %).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_address: Option<GroupAddress>,
    /// The GA position is read from (5.001, 0–100 %).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_state_address: Option<GroupAddress>,
    /// The GA slat angle is written to (5.001).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub angle_address: Option<GroupAddress>,
    /// The GA slat angle is read from (5.001).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub angle_state_address: Option<GroupAddress>,
    /// HA device class (`blind`, `shutter`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_class: Option<String>,
}

/// A `sensor` entity (a numeric value, e.g. temperature or illuminance).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sensor {
    /// Display name.
    pub name: String,
    /// The GA the value is read from.
    pub state_address: GroupAddress,
    /// The HA sensor `type` (e.g. `temperature`, `illuminance`).
    #[serde(rename = "type")]
    pub sensor_type: String,
}

/// A `binary_sensor` entity (a boolean, e.g. presence or a window contact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinarySensor {
    /// Display name.
    pub name: String,
    /// The GA the boolean is read from.
    pub state_address: GroupAddress,
    /// HA device class (`motion`, `window`, `safety`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_class: Option<String>,
}

/// A `climate` entity (a room heating controller).
///
/// Assembled from a per-room cluster of KNX group addresses that span several
/// devices (a room controller sends the operation mode; a heating actuator
/// drives the valve; a sensor sends the temperature), correlated by room name.
/// Field names match the HA KNX `climate` schema exactly.
///
/// For the central-heating installation this targets, the operation mode is the
/// control and temperature/valve are read-only telemetry; the setpoint-shift and
/// target-temperature fields are part of the schema but left unwired by the
/// derivation (see `derive::derive_climate` and docs/ha-config.md). They remain
/// on the struct so an `ha.yaml` override can populate them for installations
/// that do per-room setpoint control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Climate {
    /// Display name.
    pub name: String,
    /// The GA the current room temperature is read from (DPT 9.001).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature_address: Option<GroupAddress>,
    /// The GA the current target (setpoint) temperature is read from (9.001).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_temperature_state_address: Option<GroupAddress>,
    /// The GA setpoint shift is written to (DPT 9.002).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setpoint_shift_address: Option<GroupAddress>,
    /// The GA setpoint shift is read from (DPT 9.002).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setpoint_shift_state_address: Option<GroupAddress>,
    /// The DPT of the setpoint-shift addresses (`DPT9002` for a 9.002 shift).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setpoint_shift_mode: Option<String>,
    /// The GA the HVAC operation mode is written to (DPT 20.102).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_mode_address: Option<GroupAddress>,
    /// The GA the HVAC operation mode is read from (DPT 20.102).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_mode_state_address: Option<GroupAddress>,
    /// The GA the current valve/command value (percent) is read from (5.001).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_value_state_address: Option<GroupAddress>,
}

/// One derived entity, before it is placed into the platform-keyed document.
///
/// Carries its [`Platform`] and sort name so the emitter can order entities
/// deterministically (by platform, then name, then primary GA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entity {
    /// A switch entity.
    Switch(Switch),
    /// A light entity.
    Light(Light),
    /// A cover entity.
    Cover(Cover),
    /// A sensor entity.
    Sensor(Sensor),
    /// A binary sensor entity.
    BinarySensor(BinarySensor),
    /// A climate entity.
    Climate(Climate),
}

impl Entity {
    /// The platform this entity belongs to.
    pub fn platform(&self) -> Platform {
        match self {
            Entity::Switch(_) => Platform::Switch,
            Entity::Light(_) => Platform::Light,
            Entity::Cover(_) => Platform::Cover,
            Entity::Sensor(_) => Platform::Sensor,
            Entity::BinarySensor(_) => Platform::BinarySensor,
            Entity::Climate(_) => Platform::Climate,
        }
    }

    /// The display name (used as the primary sort key within a platform).
    pub fn name(&self) -> &str {
        match self {
            Entity::Switch(e) => &e.name,
            Entity::Light(e) => &e.name,
            Entity::Cover(e) => &e.name,
            Entity::Sensor(e) => &e.name,
            Entity::BinarySensor(e) => &e.name,
            Entity::Climate(e) => &e.name,
        }
    }

    /// Every group address this entity references (command + state + position …).
    ///
    /// Used to mark GAs as consumed so no other entity re-maps them and so the
    /// coverage count is accurate.
    pub fn all_gas(&self) -> Vec<GroupAddress> {
        match self {
            Entity::Switch(e) => [Some(e.address), e.state_address]
                .into_iter()
                .flatten()
                .collect(),
            Entity::Light(e) => [
                Some(e.address),
                e.state_address,
                e.brightness_address,
                e.brightness_state_address,
            ]
            .into_iter()
            .flatten()
            .collect(),
            Entity::Cover(e) => [
                e.move_long_address,
                e.move_short_address,
                e.position_address,
                e.position_state_address,
                e.angle_address,
                e.angle_state_address,
            ]
            .into_iter()
            .flatten()
            .collect(),
            Entity::Sensor(e) => vec![e.state_address],
            Entity::BinarySensor(e) => vec![e.state_address],
            Entity::Climate(e) => [
                e.temperature_address,
                e.target_temperature_state_address,
                e.setpoint_shift_address,
                e.setpoint_shift_state_address,
                e.operation_mode_address,
                e.operation_mode_state_address,
                e.command_value_state_address,
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }

    /// The primary group address (the tie-breaker sort key).
    ///
    /// For switch/light/cover this is the command address; for sensors it is
    /// the state address. A cover is always constructed with at least a
    /// `move_long_address`; the fallback chain (and the final reserved `0/0/0`)
    /// only guard the type and are not expected to be reached.
    pub fn primary_ga(&self) -> GroupAddress {
        match self {
            Entity::Switch(e) => e.address,
            Entity::Light(e) => e.address,
            Entity::Cover(e) => e
                .move_long_address
                .or(e.move_short_address)
                .or(e.position_address)
                .or(e.position_state_address)
                .unwrap_or_else(|| GroupAddress::from_raw(0)),
            Entity::Sensor(e) => e.state_address,
            Entity::BinarySensor(e) => e.state_address,
            // A climate entity is always constructed with at least an operation
            // mode or a setpoint-shift command (the anchor requirement). The
            // fallback chain (and the reserved `0/0/0`) only guard the type.
            Entity::Climate(e) => e
                .operation_mode_address
                .or(e.setpoint_shift_address)
                .or(e.operation_mode_state_address)
                .or(e.setpoint_shift_state_address)
                .or(e.temperature_address)
                .unwrap_or_else(|| GroupAddress::from_raw(0)),
        }
    }
}
