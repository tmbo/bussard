//! The heuristic entity-derivation engine.
//!
//! Home Assistant needs entities (a switch, a cover, a temperature sensor);
//! bussard's model has devices, com-objects and group addresses. This module
//! bridges the two by reasoning per device, grouping a device's com-objects
//! into *roles* (command, status, position, …) and assembling entities from
//! those roles.
//!
//! # Why per-device and not per-GA
//!
//! A cover needs several GAs (up/down, step/stop, position, position status)
//! that belong together only because they sit on the same actuator channel.
//! That grouping is invisible at the GA level but clear at the device level:
//! the com-objects carry a `channel`, a DPT and flags, and `links.yaml` tells
//! us which GA each object sends or listens to. So derivation walks each
//! device's objects, clusters them (by channel where present, else by
//! object-number adjacency), and emits one entity per cluster.
//!
//! # Roles from flags
//!
//! - An object with the **W** flag *receives* commands — its listened GA is a
//!   *command* address (what HA sends to).
//! - An object with the **T** flag *transmits* status — its sent GA is a
//!   *state* address (what HA reads).
//!
//! # The mapping rules (summary)
//!
//! | Shape | HA entity |
//! |---|---|
//! | 1.008 up/down [+ 1.007 step/stop, 5.001 position ± status] | `cover` |
//! | 1.001 switch [+ 5.001 brightness] | `light` (if brightness or override) or `switch` |
//! | 9.xxx value sent by a sensor | `sensor` (`type` per DPT sub) |
//! | 1.xxx sent by a sensor | `binary_sensor` (device_class per name/DPT) |
//!
//! Anything that does not fit is reported as *unmapped* rather than dropped.

use std::collections::{BTreeMap, BTreeSet};

use bussard_model::schema::{ComObject, Device};
use bussard_model::{Dpt, Flags, GroupAddress, Model};

use crate::entities::{BinarySensor, Cover, Entity, Light, Sensor, Switch};
use crate::overrides::{Overrides, PlatformOverride, SwitchPlatform};

/// The result of deriving entities from a model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Derived {
    /// The derived entities (unsorted; the emitter sorts).
    pub entities: Vec<Entity>,
    /// GAs that could not be mapped, grouped by DPT main number for the summary.
    ///
    /// Keyed by DPT main (or `None` for GAs with no DPT), value is the count.
    pub unmapped: BTreeMap<Option<u16>, usize>,
    /// The total number of GAs defined in the model.
    pub total_gas: usize,
    /// The number of distinct GAs consumed by at least one emitted entity.
    pub mapped_gas: usize,
}

/// Which kind of entity a derivation pass produces.
///
/// Actuators are derived first and claim their GAs; sensors are derived second,
/// only on GAs no actuator claimed. This prevents a command GA from producing
/// both a `switch` (on the actuator) and a `binary_sensor` (on a push-button
/// that sends the same GA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Covers, switches and lights.
    Actuators,
    /// Sensors and binary sensors.
    Sensors,
}

/// A com-object paired with the GAs it links to, resolved from `links.yaml`.
#[derive(Debug, Clone)]
struct ObjectLink<'a> {
    /// The com-object number.
    number: u16,
    /// The com-object definition (DPT, flags, channel).
    obj: &'a ComObject,
    /// The GA this object sends (from `links.yaml`), if any.
    send: Option<GroupAddress>,
    /// The GAs this object listens to (from `links.yaml`).
    listen: Vec<GroupAddress>,
}

impl ObjectLink<'_> {
    fn dpt(&self) -> Option<Dpt> {
        self.obj.dpt
    }

    /// The command GA: the first listened GA on a writable object.
    fn command_ga(&self) -> Option<GroupAddress> {
        if self.obj.flags.contains(Flags::WRITE) {
            self.listen.first().copied()
        } else {
            None
        }
    }

    /// The state GA: the sent GA on a transmitting object.
    fn state_ga(&self) -> Option<GroupAddress> {
        if self.obj.flags.contains(Flags::TRANSMIT) {
            self.send
        } else {
            None
        }
    }

    /// Any GA associated with this object, regardless of direction.
    fn any_ga(&self) -> Option<GroupAddress> {
        self.send.or_else(|| self.listen.first().copied())
    }
}

/// Derives Home Assistant entities from the model under the given overrides.
pub fn derive(model: &Model, overrides: &Overrides) -> Derived {
    let mut out = Derived {
        total_gas: model.groups.groups.len(),
        ..Default::default()
    };

    // GAs consumed by an emitted entity, so we can compute coverage and know
    // which GAs remain unmapped.
    let mut consumed: BTreeSet<GroupAddress> = BTreeSet::new();
    // Primary GAs already claimed by an entity — prevents two devices touching
    // the same GA (e.g. an actuator and the push-buttons that command it) from
    // producing duplicate entities. First writer (lowest device address, since
    // `devices` is a BTreeMap) wins.
    let mut claimed: BTreeSet<GroupAddress> = BTreeSet::new();

    // Pass 1 — actuators (cover, switch, light). These "own" their command and
    // state GAs; a later sensor pass must not re-map those GAs.
    for loaded in model.devices.values() {
        derive_device(
            &loaded.device,
            model,
            overrides,
            Phase::Actuators,
            &mut out.entities,
            &mut consumed,
            &mut claimed,
        );
    }
    // Pass 2 — sensors and binary_sensors on the GAs actuators did not claim.
    for loaded in model.devices.values() {
        derive_device(
            &loaded.device,
            model,
            overrides,
            Phase::Sensors,
            &mut out.entities,
            &mut consumed,
            &mut claimed,
        );
    }

    // Deduplicate entity names (HA requires unique names per platform). Covers
    // on adjacent channels of one actuator often share a GA name; suffix
    // collisions with the primary GA to keep them distinct and stable.
    dedupe_names(&mut out.entities);

    // Unmapped = GAs neither consumed nor excluded.
    for (&ga, group) in &model.groups.groups {
        if consumed.contains(&ga) || overrides.is_excluded(ga) {
            continue;
        }
        let main = group.dpt.map(|d| d.main);
        *out.unmapped.entry(main).or_default() += 1;
    }
    out.mapped_gas = consumed.len();

    out
}

/// Derives entities for one device, appending to `entities` and recording every
/// consumed GA in `consumed`.
#[allow(clippy::too_many_arguments)]
fn derive_device(
    device: &Device,
    model: &Model,
    overrides: &Overrides,
    phase: Phase,
    entities: &mut Vec<Entity>,
    consumed: &mut BTreeSet<GroupAddress>,
    claimed: &mut BTreeSet<GroupAddress>,
) {
    let links = model.links.links.get(&device.address);
    // Resolve every com-object to its links. Objects without a DPT or without
    // any GA are skipped (nothing to map).
    let mut objects: Vec<ObjectLink<'_>> = Vec::new();
    for (&number, obj) in &device.com_objects {
        let (send, listen) = match links {
            Some(ls) => ls
                .iter()
                .find(|l| l.object == number)
                .map(|l| (l.send, l.listen.clone()))
                .unwrap_or((None, Vec::new())),
            None => (None, Vec::new()),
        };
        let ol = ObjectLink {
            number,
            obj,
            send,
            listen,
        };
        if ol.any_ga().is_some() {
            objects.push(ol);
        }
    }
    if objects.is_empty() {
        return;
    }

    // Cluster objects: by channel when both objects carry one, else each object
    // sits in its own object-number-adjacency window. We build clusters keyed by
    // a stable cluster id derived from the channel, or from the object number
    // rounded down to a small window when there is no channel.
    let clusters = cluster_objects(&objects);

    for cluster in clusters {
        let cluster_objs: Vec<&ObjectLink<'_>> = cluster.iter().map(|&i| &objects[i]).collect();
        derive_cluster(
            device,
            model,
            &cluster_objs,
            overrides,
            phase,
            entities,
            consumed,
            claimed,
        );
    }
}

/// Groups object indices into clusters that should become one entity.
///
/// Strategy: objects that share a non-empty `channel` cluster together. Objects
/// with no channel each form their own singleton cluster (they are typically
/// standalone sensors or one-off switches). Clusters are returned in a stable
/// order (by the smallest object number they contain).
fn cluster_objects(objects: &[ObjectLink<'_>]) -> Vec<Vec<usize>> {
    let mut by_channel: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut singletons: Vec<usize> = Vec::new();

    for (i, o) in objects.iter().enumerate() {
        match &o.obj.channel {
            Some(ch) if !ch.is_empty() => by_channel.entry(ch.clone()).or_default().push(i),
            _ => singletons.push(i),
        }
    }

    // Collect (min_object_number, cluster) so we can sort deterministically.
    let mut clusters: Vec<(u16, Vec<usize>)> = Vec::new();
    for (_ch, idxs) in by_channel {
        let min = idxs.iter().map(|&i| objects[i].number).min().unwrap_or(0);
        clusters.push((min, idxs));
    }
    for i in singletons {
        clusters.push((objects[i].number, vec![i]));
    }
    clusters.sort_by_key(|(min, _)| *min);
    clusters.into_iter().map(|(_, c)| c).collect()
}

/// Derives at most one entity from a cluster of related objects.
///
/// Only produces entities matching `phase`, and skips any entity whose primary
/// GA has already been claimed. When an entity is produced, its primary GA is
/// recorded in `claimed` and all its GAs in `consumed`.
#[allow(clippy::too_many_arguments)]
fn derive_cluster(
    device: &Device,
    model: &Model,
    cluster: &[&ObjectLink<'_>],
    overrides: &Overrides,
    phase: Phase,
    entities: &mut Vec<Entity>,
    consumed: &mut BTreeSet<GroupAddress>,
    claimed: &mut BTreeSet<GroupAddress>,
) {
    match phase {
        Phase::Actuators => {
            // Cover first (most GAs, most specific), then switch/light.
            if let Some(e) = try_cover(device, model, cluster, overrides) {
                push_merged(e, overrides, entities, claimed, consumed);
                return;
            }
            if let Some(e) = try_switchable(device, model, cluster, overrides) {
                push_merged(e, overrides, entities, claimed, consumed);
            }
        }
        Phase::Sensors => {
            // One sensor/binary_sensor per object (no clustering benefit).
            for o in cluster {
                if let Some(e) = try_sensor(device, model, o, overrides, &*consumed) {
                    push_merged(e, overrides, entities, claimed, consumed);
                } else if let Some(e) = try_binary_sensor(device, model, o, overrides, &*consumed) {
                    push_merged(e, overrides, entities, claimed, consumed);
                }
            }
        }
    }
}

/// Applies any `merge` override for `entity`'s primary GA, then pushes it.
///
/// See [`crate::overrides::EntityOverride::merge`] for the exact per-platform
/// semantics. In short: each merged GA that is not excluded is wired into a free
/// state slot on the entity where the platform has one, and every merged GA is
/// folded into the entity's consumed set so it is claimed and no longer reported
/// as unmapped. Exclusion wins over merge: an excluded merged GA is ignored (and
/// still surfaces in the unmapped footer if nothing else maps it).
fn push_merged(
    mut entity: Entity,
    overrides: &Overrides,
    entities: &mut Vec<Entity>,
    claimed: &mut BTreeSet<GroupAddress>,
    consumed: &mut BTreeSet<GroupAddress>,
) {
    let primary = entity.primary_ga();
    let merged: Vec<GroupAddress> = overrides
        .entity(primary)
        .map(|ov| ov.merge.clone())
        .unwrap_or_default()
        .into_iter()
        // Exclusion wins over merge.
        .filter(|ga| !overrides.is_excluded(*ga))
        .collect();

    let mut extra_consumed = Vec::new();
    for ga in merged {
        // Skip a merged GA already owned by an earlier entity: wiring it into a
        // slot would make `push_unclaimed` drop this whole entity as a duplicate.
        if consumed.contains(&ga) {
            continue;
        }
        // Wire into a free platform slot where one exists; otherwise just mark it
        // consumed so it is claimed and drops out of the unmapped summary.
        if !wire_merged_ga(&mut entity, ga) {
            extra_consumed.push(ga);
        }
    }

    push_unclaimed(entity, entities, claimed, consumed);
    // Only fold in the leftover merged GAs if the entity was actually accepted
    // (its own GAs are now consumed). If it was dropped as a duplicate, leave the
    // merged GAs untouched so they can still map elsewhere.
    if !extra_consumed.is_empty() && claimed.contains(&primary) {
        consumed.extend(extra_consumed);
    }
}

/// Wires a merged GA into a free state slot on `entity`, returning `true` if it
/// found a home. Only fills an empty slot — merge never overwrites a GA the
/// heuristic already derived.
fn wire_merged_ga(entity: &mut Entity, ga: GroupAddress) -> bool {
    match entity {
        // Switch/light/binary_sensor: the state address is the natural extra slot.
        Entity::Switch(e) if e.state_address.is_none() => {
            e.state_address = Some(ga);
            true
        }
        Entity::Light(e) if e.state_address.is_none() => {
            e.state_address = Some(ga);
            true
        }
        // Cover: prefer position-state, then angle-state.
        Entity::Cover(e) if e.position_state_address.is_none() => {
            e.position_state_address = Some(ga);
            true
        }
        Entity::Cover(e) if e.angle_state_address.is_none() => {
            e.angle_state_address = Some(ga);
            true
        }
        // Sensor/binary_sensor have only one address and no spare state slot.
        _ => false,
    }
}

/// Pushes an entity unless one of its GAs is already spoken for.
///
/// An entity is dropped if its primary GA is already claimed *or* if any of its
/// GAs was already consumed by an earlier entity — this catches actuators whose
/// command/status GAs cross-reference another actuator's (a device that models
/// "switch" and "status" as two mirror objects) as well as a sensor trying to
/// re-map an actuator's state GA. On acceptance, all the entity's GAs are marked
/// consumed and its primary is claimed.
fn push_unclaimed(
    entity: Entity,
    entities: &mut Vec<Entity>,
    claimed: &mut BTreeSet<GroupAddress>,
    consumed: &mut BTreeSet<GroupAddress>,
) {
    let primary = entity.primary_ga();
    let gas = entity.all_gas();
    if claimed.contains(&primary) || gas.iter().any(|ga| consumed.contains(ga)) {
        // A stronger/earlier entity already owns one of these GAs. Drop it.
        return;
    }
    claimed.insert(primary);
    consumed.extend(gas);
    entities.push(entity);
}

/// Whether a DPT has the given main number.
fn is_main(dpt: Option<Dpt>, main: u16) -> bool {
    dpt.is_some_and(|d| d.main == main)
}

/// Attempts to assemble a `cover` from a cluster.
///
/// Requires a 1.008 up/down *command* object (a W-flag object whose listened GA
/// HA drives). Requiring a command — like [`try_switchable`] — stops a
/// push-button's T-flag 1.008 sender from anchoring a cover and pre-empting the
/// actuator's richer cover cluster: the button has no command GA here, so it
/// falls through to the sensor pass instead. Adds 1.007 step/stop, 5.001
/// position (command + state) and 5.003 slat angle (command + state) when
/// present in the cluster.
fn try_cover(
    device: &Device,
    model: &Model,
    cluster: &[&ObjectLink<'_>],
    overrides: &Overrides,
) -> Option<Entity> {
    let up_down = cluster
        .iter()
        .find(|o| is_main(o.dpt(), 1) && o.dpt().and_then(|d| d.sub) == Some(8))?;
    // Require a command GA (a writable up/down), not merely any GA.
    let move_long = up_down.command_ga()?;
    if overrides.is_excluded(move_long) {
        return None;
    }

    let step_stop = cluster
        .iter()
        .find(|o| is_main(o.dpt(), 1) && o.dpt().and_then(|d| d.sub) == Some(7))
        .and_then(|o| o.command_ga().or_else(|| o.any_ga()));

    // Position is DPT 5.001 (scaling, 0–100 %); slat angle is DPT 5.003 (angle).
    // Match on the sub so a 5.003 angle is never mistaken for a position (and
    // vice-versa) — the fields exist on `Cover` and were previously hardwired to
    // `None`. A writable object is the command; a transmitting one is the state.
    let is_dpt5_sub = |o: &&&ObjectLink<'_>, sub: u16| {
        is_main(o.dpt(), 5) && o.dpt().and_then(|d| d.sub) == Some(sub)
    };
    let position_cmd = cluster
        .iter()
        .filter(|o| is_dpt5_sub(o, 1))
        .find_map(|o| o.command_ga());
    let position_state = cluster
        .iter()
        .filter(|o| is_dpt5_sub(o, 1))
        .find_map(|o| o.state_ga());
    let angle_cmd = cluster
        .iter()
        .filter(|o| is_dpt5_sub(o, 3))
        .find_map(|o| o.command_ga());
    let angle_state = cluster
        .iter()
        .filter(|o| is_dpt5_sub(o, 3))
        .find_map(|o| o.state_ga());

    let name = entity_name(device, model, move_long);
    let inferred_class = cover_device_class(&name);
    let (name, device_class) = apply_entity_override(
        overrides,
        move_long,
        name,
        inferred_class,
        None, // covers are not platform-overridable
    )
    .map(|(n, dc, _)| (n, dc))?;

    Some(Entity::Cover(Cover {
        name,
        move_long_address: Some(move_long),
        move_short_address: step_stop,
        position_address: position_cmd,
        position_state_address: position_state,
        angle_address: angle_cmd,
        angle_state_address: angle_state,
        device_class,
    }))
}

/// Attempts to assemble a `switch` or `light` from a cluster.
///
/// Requires a 1.001 object. Promotes to `light` when the cluster also has a
/// 5.001 brightness object, or when configured/overridden to a light.
fn try_switchable(
    device: &Device,
    model: &Model,
    cluster: &[&ObjectLink<'_>],
    overrides: &Overrides,
) -> Option<Entity> {
    // A switch/light is anchored by a *command* object: a 1.001 that receives
    // on/off (W flag), whose listened GA is the address HA sends to. A pure
    // status object (1.001 with only T) is not a switch — it becomes a
    // binary_sensor in the sensor pass (or is merged in as `state_address`
    // here when it shares this cluster).
    let switch_objs: Vec<&&ObjectLink<'_>> = cluster
        .iter()
        .filter(|o| is_main(o.dpt(), 1) && o.dpt().and_then(|d| d.sub) == Some(1))
        .collect();
    if switch_objs.is_empty() {
        return None;
    }

    let address = switch_objs.iter().find_map(|o| o.command_ga())?;
    if overrides.is_excluded(address) {
        return None;
    }
    let state_address = switch_objs.iter().find_map(|o| o.state_ga());

    // Brightness objects (5.001).
    let brightness_address = cluster
        .iter()
        .filter(|o| is_main(o.dpt(), 5))
        .find_map(|o| o.command_ga());
    let brightness_state_address = cluster
        .iter()
        .filter(|o| is_main(o.dpt(), 5))
        .find_map(|o| o.state_ga());

    let has_brightness = brightness_address.is_some() || brightness_state_address.is_some();

    let name = entity_name(device, model, address);
    // Default platform: light if it has brightness, else the configured default.
    let default_light =
        has_brightness || overrides.global.default_platform_for_switches == SwitchPlatform::Light;

    let (name, device_class, platform) =
        apply_entity_override(overrides, address, name, None, Some(default_light))?;

    let as_light = platform.unwrap_or(default_light);
    if as_light {
        Some(Entity::Light(Light {
            name,
            address,
            state_address,
            brightness_address,
            brightness_state_address,
        }))
    } else {
        Some(Entity::Switch(Switch {
            name,
            address,
            state_address,
            device_class,
        }))
    }
}

/// Attempts to map a single object to a numeric `sensor`.
///
/// Fires for transmitting (or readable) 9.xxx / 7 / 12 / 13 / 14 objects — the
/// value families a KNX sensor emits. The HA `type` is chosen per DPT sub.
fn try_sensor(
    device: &Device,
    model: &Model,
    o: &ObjectLink<'_>,
    overrides: &Overrides,
    consumed: &BTreeSet<GroupAddress>,
) -> Option<Entity> {
    let dpt = o.dpt()?;
    let sensor_type = sensor_type_for(dpt)?;
    // Sensors read a state address: prefer the sent GA, else any GA.
    let state = o.send.or_else(|| o.listen.first().copied())?;
    if overrides.is_excluded(state) || consumed.contains(&state) {
        return None;
    }

    let name = entity_name(device, model, state);
    let name = apply_name_override(overrides, state, name);

    Some(Entity::Sensor(Sensor {
        name,
        state_address: state,
        sensor_type,
    }))
}

/// Attempts to map a single object to a `binary_sensor`.
///
/// Fires for a 1.xxx object that a sensor *sends* (T flag) — presence, contacts,
/// alarms. Command inputs (W-only) are not binary sensors.
fn try_binary_sensor(
    device: &Device,
    model: &Model,
    o: &ObjectLink<'_>,
    overrides: &Overrides,
    consumed: &BTreeSet<GroupAddress>,
) -> Option<Entity> {
    let dpt = o.dpt()?;
    if dpt.main != 1 {
        return None;
    }
    // Must be transmitting a state (a sensor output), not a pure command input.
    let state = o.state_ga()?;
    if overrides.is_excluded(state) || consumed.contains(&state) {
        return None;
    }

    // The GA's own name drives device-class hinting. The com-object no longer
    // carries a name (issue #19); the informational name in links.yaml isn't
    // threaded here, so fall back to the device name for the hint.
    let hint_name = model
        .groups
        .groups
        .get(&state)
        .map(|g| g.name.as_str())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or(device.name.as_str());
    let device_class = binary_sensor_device_class(dpt, hint_name);

    let name = entity_name(device, model, state);
    let (name, device_class, _) =
        apply_entity_override(overrides, state, name, device_class, None)?;

    Some(Entity::BinarySensor(BinarySensor {
        name,
        state_address: state,
        device_class,
    }))
}

/// The HA sensor `type` for a numeric DPT, or `None` if bussard does not map it.
fn sensor_type_for(dpt: Dpt) -> Option<String> {
    let t = match (dpt.main, dpt.sub) {
        (9, Some(1)) => "temperature",
        (9, Some(2)) => "temperature", // temperature difference (Kelvin)
        (9, Some(4)) => "illuminance",
        (9, Some(5)) => "wind_speed_ms",
        (9, Some(6)) => "pressure_2byte",
        (9, Some(7)) => "humidity",
        (9, Some(8)) => "ppm",
        (9, Some(24)) => "power",
        // Generic 2-byte float when the sub is unknown but the family is a value.
        (9, _) => "2byte_float",
        (5, Some(1)) => "percent",
        (5, Some(4)) => "percentU8",
        (7, Some(_)) | (7, None) => "pulse_2byte",
        (12, _) => "pulse_4byte",
        (13, Some(10)) => "active_energy",
        (13, Some(13)) => "active_energy_kwh",
        (13, _) => "4byte_signed",
        (14, _) => "4byte_float",
        _ => return None,
    };
    Some(t.to_string())
}

/// The HA cover `device_class` inferred from the entity name.
fn cover_device_class(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    if lower.contains("rolllade") || lower.contains("rollo") || lower.contains("shutter") {
        Some("shutter".to_string())
    } else if lower.contains("raffstore")
        || lower.contains("jalousie")
        || lower.contains("blind")
        || lower.contains("venetian")
    {
        Some("blind".to_string())
    } else if lower.contains("markise") || lower.contains("awning") {
        Some("awning".to_string())
    } else {
        None
    }
}

/// The HA binary_sensor `device_class` inferred from the DPT sub and name.
fn binary_sensor_device_class(dpt: Dpt, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    // DPT sub gives strong hints for a few subtypes.
    match dpt.sub {
        Some(5) => return Some("problem".to_string()), // 1.005 alarm
        Some(19) => return Some("window".to_string()), // 1.019 window/door open
        _ => {}
    }
    if lower.contains("präsenz")
        || lower.contains("presence")
        || lower.contains("bewegung")
        || lower.contains("motion")
    {
        Some("motion".to_string())
    } else if lower.contains("fenster") || lower.contains("window") {
        Some("window".to_string())
    } else if lower.contains("tür") || lower.contains("door") {
        Some("door".to_string())
    } else if lower.contains("regen") || lower.contains("rain") {
        Some("moisture".to_string())
    } else if lower.contains("alarm") || lower.contains("wind") {
        Some("safety".to_string())
    } else {
        None
    }
}

/// Builds an entity name for the entity whose primary GA is `ga`.
///
/// Prefers the group address's own name from `groups.yaml` (the human label the
/// user gave the GA — the most descriptive source); falls back to the device
/// name when the GA is unnamed.
fn entity_name(device: &Device, model: &Model, ga: GroupAddress) -> String {
    model
        .groups
        .groups
        .get(&ga)
        .map(|g| g.name.clone())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| device.name.clone())
}

/// Ensures entity names are unique within each platform (HA requires it).
///
/// When two entities on the same platform share a name, every colliding entity
/// gets its primary GA appended in parentheses — a stable, deterministic
/// suffix. Non-colliding names are left untouched.
fn dedupe_names(entities: &mut [Entity]) {
    use std::collections::HashMap;

    // Count (platform, name) occurrences.
    let mut counts: HashMap<(crate::entities::Platform, String), usize> = HashMap::new();
    for e in entities.iter() {
        *counts
            .entry((e.platform(), e.name().to_string()))
            .or_default() += 1;
    }
    for e in entities.iter_mut() {
        let key = (e.platform(), e.name().to_string());
        if counts.get(&key).copied().unwrap_or(0) > 1 {
            let ga = e.primary_ga();
            let new_name = format!("{} ({ga})", e.name());
            set_name(e, new_name);
        }
    }
}

/// Overwrites an entity's display name in place.
fn set_name(e: &mut Entity, name: String) {
    match e {
        Entity::Switch(x) => x.name = name,
        Entity::Light(x) => x.name = name,
        Entity::Cover(x) => x.name = name,
        Entity::Sensor(x) => x.name = name,
        Entity::BinarySensor(x) => x.name = name,
    }
}

/// Applies a per-entity override (name + device_class + optional platform).
///
/// Returns `None` only when the entity is excluded. `default_light` is the
/// pre-override platform choice for switchables (ignored for other entities).
fn apply_entity_override(
    overrides: &Overrides,
    primary: GroupAddress,
    name: String,
    device_class: Option<String>,
    default_light: Option<bool>,
) -> Option<(String, Option<String>, Option<bool>)> {
    if overrides.is_excluded(primary) {
        return None;
    }
    let Some(ov) = overrides.entity(primary) else {
        return Some((name, device_class, default_light));
    };
    let name = ov.name.clone().unwrap_or(name);
    let device_class = ov.device_class.clone().or(device_class);
    let platform = match ov.platform {
        Some(PlatformOverride::Light) => Some(true),
        Some(PlatformOverride::Switch) => Some(false),
        None => default_light,
    };
    Some((name, device_class, platform))
}

/// Applies only a name override (for entities without device_class/platform).
fn apply_name_override(overrides: &Overrides, primary: GroupAddress, name: String) -> String {
    overrides
        .entity(primary)
        .and_then(|o| o.name.clone())
        .unwrap_or(name)
}
