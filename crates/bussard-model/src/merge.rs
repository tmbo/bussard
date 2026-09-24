//! Re-import merge: refresh generated sections while preserving hand edits.
//!
//! A first import writes the whole `knx/` model from the `.knxproj`. A
//! *re-import* into an existing repo must not clobber the fields a human has
//! since refined. The model has two kinds of content:
//!
//! * **Generated** data, regenerated from ETS truth on every import: a device's
//!   [`com_objects`](Device::com_objects), [`module_bases`](Device::module_bases)
//!   and [`parameters`](Device::parameters), plus the *existence* of devices,
//!   group addresses and links. These are refreshed (theirs wins) — the device
//!   banner and the GENERATED marker say so.
//! * **Hand-authored** fields, owned by the human once written: a device's
//!   `name`, `description`, `location`, its product's `manufacturer` and
//!   `order_number`, and its channel *names*; a group's `name`, `dpt`,
//!   `description` and `protected`; a link's `name`. These are **never**
//!   overwritten by a re-import. Where the fresh import disagrees with the
//!   existing value, the difference is **reported** (path, field, ours vs
//!   theirs) and the existing value is kept.
//!
//! The product's **identity** fields (`application_ref`, `mask`,
//! `hardware_ref`, `manufacturer_ref`) and the **channel set** are generated,
//! not hand-authored: they name the very application program the regenerated
//! `parameters:`/`com_objects:` were read out of. Keeping them from `ours` while
//! taking the tables from `theirs` produced a model that contradicted itself
//! after an ETS application upgrade — new parameter keys under the old
//! `application_ref`, so every key read E016 and the flasher resolved the wrong
//! product model. They follow `theirs`, and a changed `application_ref`/`mask`
//! is recorded in [`MergeReport::notes`].
//!
//! [`merge`] takes the existing on-disk model (`ours`) and the freshly-imported
//! model (`theirs`) and returns the merged model plus a [`MergeReport`]. The
//! merged model is what should be saved: generated sections come from `theirs`,
//! hand-authored fields from `ours`.

use crate::address::{GroupAddress, IndividualAddress};
use crate::schema::{Device, Group, Link};
use crate::{LoadedDevice, Model};

/// A single hand-authored field whose fresh-import value differs from the value
/// already on disk. Reported, never applied — the existing value is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The model location, e.g. `devices/1.1.4` or `groups/3/2/0` or
    /// `links/1.1.4#3`.
    pub path: String,
    /// The conflicting field name, e.g. `name`, `location.room`, `dpt`.
    pub field: String,
    /// The value on disk (kept).
    pub ours: String,
    /// The value the fresh import would have written (reported, not applied).
    pub theirs: String,
}

/// The outcome of a re-import [`merge`]: the hand-authored conflicts that were
/// reported (and left un-applied), plus counts of what was refreshed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Hand-authored field conflicts, in a stable sorted order (by path then
    /// field). Each was reported and the existing value kept.
    pub conflicts: Vec<Conflict>,
    /// Devices present in the fresh import but not on disk (newly added).
    pub devices_added: usize,
    /// Devices on disk but absent from the fresh import (dropped).
    pub devices_removed: usize,
    /// Group addresses present in the fresh import but not on disk.
    pub groups_added: usize,
    /// Group addresses on disk but absent from the fresh import.
    pub groups_removed: usize,
    /// Informational lines about *generated* data the fresh import changed —
    /// notably a device whose `product.application_ref` or `product.mask` moved
    /// (an ETS application upgrade), or a channel that left the project. These
    /// are not conflicts: the fresh value was applied. They are recorded because
    /// they change what the regenerated parameter keys mean.
    pub notes: Vec<String>,
}

impl MergeReport {
    /// Whether any hand-authored conflict was reported.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Merges a freshly-imported model (`theirs`) into the existing on-disk model
/// (`ours`), refreshing generated sections while preserving hand-authored
/// fields, and returns the model to save plus a [`MergeReport`].
///
/// Merge rules, per the field ownership documented on the schema banners:
///
/// * The set of devices, group addresses and links is taken from `theirs` (the
///   ETS project is authoritative on what *exists*). A device/group present in
///   `ours` but gone from `theirs` is dropped and counted as removed.
/// * A device's generated tables (`com_objects`, `module_bases`, `parameters`)
///   are taken from `theirs`.
/// * A device's hand-authored fields (`name`, `description`, `location`, the
///   product's `manufacturer`/`order_number`, and channel *names*) are taken
///   from `ours`; a differing fresh value is recorded as a [`Conflict`] and
///   *not* applied.
/// * A device's generated identity (`product.application_ref`, `product.mask`,
///   `product.hardware_ref`, `product.manufacturer_ref`) and its channel *set*
///   are taken from `theirs`, so they stay consistent with the regenerated
///   `parameters:`/`com_objects:`; a changed application program or mask is
///   recorded in [`MergeReport::notes`].
/// * A group's hand-authored fields (`name`, `dpt`, `description`, `protected`)
///   are taken from `ours`, with differences reported.
/// * A link's generated wiring (`send`, `listen`) is taken from `theirs`; its
///   hand-authored `name` is taken from `ours`, with differences reported.
/// * A device's on-disk filename (`file_stem`) is preserved from `ours` so the
///   slug a human may have renamed does not churn.
///
/// New devices/groups/links (only in `theirs`) are taken wholesale from
/// `theirs`; there is nothing on disk to conflict with.
pub fn merge(ours: &Model, theirs: &Model) -> (Model, MergeReport) {
    let mut report = MergeReport::default();

    let groups = merge_groups(ours, theirs, &mut report);
    let links = merge_links(ours, theirs, &mut report);
    let devices = merge_devices(ours, theirs, &mut report);

    report
        .conflicts
        .sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.field.cmp(&b.field)));

    let merged = Model {
        // `bussard.yaml` is user-owned and never derived from the project.
        config: ours.config.clone(),
        groups,
        links,
        devices,
    };
    (merged, report)
}

/// Records a conflict when two optional string-ish fields differ, keeping ours.
fn report_opt(
    report: &mut MergeReport,
    path: &str,
    field: &str,
    ours: Option<&str>,
    theirs: Option<&str>,
) {
    if ours != theirs {
        report.conflicts.push(Conflict {
            path: path.to_string(),
            field: field.to_string(),
            ours: ours.unwrap_or("(none)").to_string(),
            theirs: theirs.unwrap_or("(none)").to_string(),
        });
    }
}

/// Merges `groups.yaml`: generated project/range metadata refreshed from theirs;
/// per-GA hand-authored fields kept from ours with differences reported.
fn merge_groups(ours: &Model, theirs: &Model, report: &mut MergeReport) -> crate::schema::Groups {
    let mut groups = theirs.groups.clone();

    // The GA set and range names come from ETS truth (theirs). Overlay the
    // hand-authored per-GA fields from ours, reporting where they differ.
    for (ga, their_group) in groups.groups.iter_mut() {
        match ours.groups.groups.get(ga) {
            Some(our_group) => overlay_group(*ga, our_group, their_group, report),
            None => report.groups_added += 1,
        }
    }
    report.groups_removed = ours
        .groups
        .groups
        .keys()
        .filter(|ga| !theirs.groups.groups.contains_key(*ga))
        .count();

    // Project name is hand-editable metadata: keep ours if it is set.
    if ours.groups.project.is_some() {
        report_opt(
            report,
            "groups",
            "project",
            ours.groups.project.as_deref(),
            groups.project.as_deref(),
        );
        groups.project = ours.groups.project.clone();
    }

    groups
}

/// Overlays one group's hand-authored fields (name, dpt, description,
/// protected) from ours onto the fresh (theirs) entry, reporting differences.
fn overlay_group(ga: GroupAddress, ours: &Group, theirs: &mut Group, report: &mut MergeReport) {
    let path = format!("groups/{ga}");
    report_opt(report, &path, "name", Some(&ours.name), Some(&theirs.name));
    let our_dpt = ours.dpt.map(|d| d.to_string());
    let their_dpt = theirs.dpt.map(|d| d.to_string());
    report_opt(
        report,
        &path,
        "dpt",
        our_dpt.as_deref(),
        their_dpt.as_deref(),
    );
    report_opt(
        report,
        &path,
        "description",
        ours.description.as_deref(),
        theirs.description.as_deref(),
    );
    if ours.protected != theirs.protected {
        report.conflicts.push(Conflict {
            path: path.clone(),
            field: "protected".to_string(),
            ours: ours.protected.to_string(),
            theirs: theirs.protected.to_string(),
        });
    }

    // Keep ours for every hand-authored field.
    theirs.name = ours.name.clone();
    theirs.dpt = ours.dpt;
    theirs.description = ours.description.clone();
    theirs.protected = ours.protected;
}

/// Merges `links.yaml`: wiring (send/listen) refreshed from theirs; the
/// hand-authored `name` on each link kept from ours with differences reported.
fn merge_links(ours: &Model, theirs: &Model, report: &mut MergeReport) -> crate::schema::Links {
    let mut links = theirs.links.clone();

    for (ia, their_links) in links.links.iter_mut() {
        let our_links = match ours.links.links.get(ia) {
            Some(l) => l,
            None => continue,
        };
        // Index ours by com-object number (the stable handle).
        for their_link in their_links.iter_mut() {
            if let Some(our_link) = our_links.iter().find(|l| l.object == their_link.object) {
                overlay_link(*ia, our_link, their_link, report);
            }
        }
    }

    links
}

/// Overlays a link's hand-authored `name` from ours, reporting a difference.
fn overlay_link(ia: IndividualAddress, ours: &Link, theirs: &mut Link, report: &mut MergeReport) {
    // Only report when ours carries a name (a human set it); an absent name on
    // our side means the human never touched it, so theirs may refresh freely.
    if ours.name.is_some() && ours.name != theirs.name {
        report.conflicts.push(Conflict {
            path: format!("links/{ia}#{}", theirs.object),
            field: "name".to_string(),
            ours: ours.name.clone().unwrap_or_default(),
            theirs: theirs.name.clone().unwrap_or_else(|| "(none)".to_string()),
        });
    }
    if ours.name.is_some() {
        theirs.name = ours.name.clone();
    }
}

/// Merges `devices/*.yaml`: the device set comes from theirs; each device's
/// generated tables refreshed from theirs; hand-authored fields kept from ours.
fn merge_devices(
    ours: &Model,
    theirs: &Model,
    report: &mut MergeReport,
) -> std::collections::BTreeMap<IndividualAddress, LoadedDevice> {
    let mut devices = theirs.devices.clone();

    for (ia, their_loaded) in devices.iter_mut() {
        match ours.devices.get(ia) {
            Some(our_loaded) => {
                overlay_device(*ia, &our_loaded.device, &mut their_loaded.device, report);
                // Preserve the on-disk filename slug so a human rename does not
                // churn (address is the identity; the slug is cosmetic).
                their_loaded.file_stem = our_loaded.file_stem.clone();
            }
            None => report.devices_added += 1,
        }
    }
    report.devices_removed = ours
        .devices
        .keys()
        .filter(|ia| !theirs.devices.contains_key(*ia))
        .count();

    devices
}

/// Overlays one device's hand-authored fields from ours onto the fresh entry,
/// reporting differences. Generated tables (`com_objects`, `module_bases`,
/// `parameters`) are left as theirs.
fn overlay_device(
    ia: IndividualAddress,
    ours: &Device,
    theirs: &mut Device,
    report: &mut MergeReport,
) {
    let path = format!("devices/{ia}");
    report_opt(report, &path, "name", Some(&ours.name), Some(&theirs.name));
    report_opt(
        report,
        &path,
        "description",
        ours.description.as_deref(),
        theirs.description.as_deref(),
    );

    // Location floor/room.
    let (our_floor, our_room) = split_location(ours);
    let (their_floor, their_room) = split_location(theirs);
    report_opt(report, &path, "location.floor", our_floor, their_floor);
    report_opt(report, &path, "location.room", our_room, their_room);

    // Product: hand-authored halves kept from ours, generated identity from
    // theirs (see `overlay_product`).
    overlay_product(&path, ours, theirs, report);

    // Channel names: keyed by channel key; report differing names, keep ours.
    // The channel *set* is generated, so a channel ETS no longer has is dropped
    // (noted) and a new one is taken as-is.
    for (key, our_ch) in &ours.channels {
        match theirs.channels.get_mut(key) {
            Some(their_ch) => {
                if our_ch.name != their_ch.name {
                    report.conflicts.push(Conflict {
                        path: path.clone(),
                        field: format!("channels.{key}.name"),
                        ours: our_ch.name.clone(),
                        theirs: their_ch.name.clone(),
                    });
                }
                // Hand-authored name wins, in the channel set theirs defines.
                their_ch.name = our_ch.name.clone();
            }
            None => report.notes.push(format!(
                "{path}: channel `{key}` ({}) is gone from the project and was dropped",
                our_ch.name
            )),
        }
    }

    // Keep ours for every hand-authored field; leave generated tables (and the
    // channel set overlaid above) as theirs.
    theirs.name = ours.name.clone();
    theirs.description = ours.description.clone();
    theirs.location = ours.location.clone();
    // `replaced:` is bus history written by `bussard replace`, not project data:
    // a re-import from ETS knows nothing about it, so keeping ours is the only
    // way the record survives (issue #98).
    theirs.replaced = ours.replaced.clone();

    // A com-object may name the channel it belongs to; after the merge that name
    // must resolve, or the model points at a channel that does not exist.
    for (number, co) in &mut theirs.com_objects {
        if let Some(key) = co.channel.clone()
            && !theirs.channels.contains_key(&key)
        {
            report.notes.push(format!(
                "{path}: com-object {number} referenced channel `{key}`, which the project \
                     no longer defines; the reference was dropped"
            ));
            co.channel = None;
        }
    }
}

/// The (floor, room) of a device's optional location.
fn split_location(d: &Device) -> (Option<&str>, Option<&str>) {
    match &d.location {
        Some(l) => (l.floor.as_deref(), l.room.as_deref()),
        None => (None, None),
    }
}

/// Merges the two halves of a device's `product` block.
///
/// `manufacturer` and `order_number` are hand-authored: kept from ours, with a
/// difference reported as a [`Conflict`]. `manufacturer_ref`, `hardware_ref`,
/// `application_ref` and `mask` are generated identity — they name the
/// application program the regenerated `parameters:`/`com_objects:` came out of
/// — so they follow theirs, and a moved `application_ref`/`mask` is noted.
///
/// A fresh import with no product at all (nothing in ETS to read) leaves ours
/// untouched: there is no generated value to take.
fn overlay_product(path: &str, ours: &Device, theirs: &mut Device, report: &mut MergeReport) {
    let op = ours.product.as_ref();
    let tp = theirs.product.as_ref();
    // `get` reads one field from an optional product; comparing per field
    // reports exactly which identity attribute diverged.
    let hand_authored = [
        (
            "product.manufacturer",
            field(op, |p| &p.manufacturer),
            field(tp, |p| &p.manufacturer),
        ),
        (
            "product.order_number",
            field(op, |p| &p.order_number),
            field(tp, |p| &p.order_number),
        ),
    ];
    for (name, o, t) in hand_authored {
        report_opt(report, path, name, o, t);
    }

    // Note the generated moves that change what the regenerated tables mean.
    for (name, o, t) in [
        (
            "application_ref",
            field(op, |p| &p.application_ref),
            field(tp, |p| &p.application_ref),
        ),
        ("mask", field(op, |p| &p.mask), field(tp, |p| &p.mask)),
    ] {
        if let (Some(o), Some(t)) = (o, t)
            && o != t
        {
            report.notes.push(format!(
                "{path}: product.{name} changed {o} -> {t}; parameters and com_objects were \
                     regenerated for the new application program"
            ));
        }
    }

    // Keep ours for the hand-authored halves, inside the fresh product block.
    let (our_manufacturer, our_order_number) = (
        field(op, |p| &p.manufacturer).map(str::to_string),
        field(op, |p| &p.order_number).map(str::to_string),
    );
    match theirs.product.as_mut() {
        Some(tp) => {
            if our_manufacturer.is_some() {
                tp.manufacturer = our_manufacturer;
            }
            if our_order_number.is_some() {
                tp.order_number = our_order_number;
            }
        }
        // Nothing generated to take: keep what is on disk.
        None => theirs.product = ours.product.clone(),
    }
}

/// Reads one optional string field out of an optional product.
fn field<'a>(
    product: Option<&'a crate::schema::Product>,
    get: impl Fn(&'a crate::schema::Product) -> &'a Option<String>,
) -> Option<&'a str> {
    product.and_then(|p| get(p).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ComObject, Device, Group, Groups, Link, Links, Location};
    use crate::{Dpt, Flags};
    use std::collections::BTreeMap;

    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    fn device(addr: &str, name: &str) -> Device {
        Device {
            address: ia(addr),
            name: name.to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            security: None,
            application_override: None,
            lock: Default::default(),
        }
    }

    fn loaded(d: Device) -> LoadedDevice {
        let stem = format!("{}-{}", d.address, d.name.to_lowercase());
        LoadedDevice {
            device: d,
            file_stem: stem,
        }
    }

    fn model_with(devices: Vec<Device>, groups: Groups, links: Links) -> Model {
        let mut map = BTreeMap::new();
        for d in devices {
            map.insert(d.address, loaded(d));
        }
        Model {
            config: Default::default(),
            groups,
            links,
            devices: map,
        }
    }

    #[test]
    fn test_merge_preserves_hand_edited_device_name() {
        let ours = model_with(
            vec![device("1.1.4", "Hand Named Switch")],
            Groups::default(),
            Links::default(),
        );
        let theirs = model_with(
            vec![device("1.1.4", "Switch Actuator")],
            Groups::default(),
            Links::default(),
        );

        let (merged, report) = merge(&ours, &theirs);
        // The hand-edited name survives.
        assert_eq!(
            merged.devices.get(&ia("1.1.4")).unwrap().device.name,
            "Hand Named Switch"
        );
        // ...and the difference is reported.
        assert_eq!(report.conflicts.len(), 1);
        let c = &report.conflicts[0];
        assert_eq!(c.path, "devices/1.1.4");
        assert_eq!(c.field, "name");
        assert_eq!(c.ours, "Hand Named Switch");
        assert_eq!(c.theirs, "Switch Actuator");
    }

    #[test]
    fn test_merge_refreshes_generated_com_objects() {
        let mut our_dev = device("1.1.4", "Switch");
        our_dev.com_objects.insert(
            0,
            ComObject {
                dpt: Some(Dpt::new(1, Some(1))),
                size: None,
                flags: Flags::default(),
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        let ours = model_with(vec![our_dev], Groups::default(), Links::default());

        let mut their_dev = device("1.1.4", "Switch");
        // A different (refreshed) generated com-object table.
        their_dev.com_objects.insert(
            0,
            ComObject {
                dpt: Some(Dpt::new(1, Some(1))),
                size: None,
                flags: Flags::default(),
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        their_dev.com_objects.insert(
            1,
            ComObject {
                dpt: Some(Dpt::new(5, Some(1))),
                size: None,
                flags: Flags::default(),
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        let theirs = model_with(vec![their_dev], Groups::default(), Links::default());

        let (merged, report) = merge(&ours, &theirs);
        // Generated com-objects refreshed to theirs (now two entries).
        assert_eq!(
            merged
                .devices
                .get(&ia("1.1.4"))
                .unwrap()
                .device
                .com_objects
                .len(),
            2
        );
        // No hand-authored conflict (names match).
        assert!(!report.has_conflicts());
    }

    #[test]
    fn test_merge_reports_location_and_group_conflicts() {
        let mut our_dev = device("1.1.4", "Switch");
        our_dev.location = Some(Location {
            floor: Some("EG".to_string()),
            room: Some("Wohnzimmer".to_string()),
        });
        let mut our_groups = Groups::default();
        our_groups.groups.insert(
            ga("3/2/0"),
            Group {
                name: "Hand Named GA".to_string(),
                dpt: Some(Dpt::new(1, Some(1))),
                description: None,
                protected: true,
                secure: false,
            },
        );
        let ours = model_with(vec![our_dev], our_groups, Links::default());

        let mut their_dev = device("1.1.4", "Switch");
        their_dev.location = Some(Location {
            floor: Some("EG".to_string()),
            room: Some("Living Room".to_string()),
        });
        let mut their_groups = Groups::default();
        their_groups.groups.insert(
            ga("3/2/0"),
            Group {
                name: "Living Room Light".to_string(),
                dpt: Some(Dpt::new(1, Some(1))),
                description: None,
                protected: false,
                secure: false,
            },
        );
        let theirs = model_with(vec![their_dev], their_groups, Links::default());

        let (merged, report) = merge(&ours, &theirs);

        // Hand edits survive.
        let g = merged.groups.groups.get(&ga("3/2/0")).unwrap();
        assert_eq!(g.name, "Hand Named GA");
        assert!(g.protected);
        assert_eq!(
            merged
                .devices
                .get(&ia("1.1.4"))
                .unwrap()
                .device
                .location
                .as_ref()
                .unwrap()
                .room
                .as_deref(),
            Some("Wohnzimmer")
        );

        // Conflicts: room, group name, group protected. Sorted by path/field.
        let fields: Vec<(&str, &str)> = report
            .conflicts
            .iter()
            .map(|c| (c.path.as_str(), c.field.as_str()))
            .collect();
        assert!(fields.contains(&("devices/1.1.4", "location.room")));
        assert!(fields.contains(&("groups/3/2/0", "name")));
        assert!(fields.contains(&("groups/3/2/0", "protected")));
    }

    #[test]
    fn test_merge_counts_added_and_removed() {
        let ours = model_with(
            vec![device("1.1.4", "Old"), device("1.1.5", "Gone")],
            Groups::default(),
            Links::default(),
        );
        let theirs = model_with(
            vec![device("1.1.4", "Old"), device("1.1.6", "New")],
            Groups::default(),
            Links::default(),
        );
        let (merged, report) = merge(&ours, &theirs);
        // Device set is theirs.
        assert!(merged.devices.contains_key(&ia("1.1.6")));
        assert!(!merged.devices.contains_key(&ia("1.1.5")));
        assert_eq!(report.devices_added, 1);
        assert_eq!(report.devices_removed, 1);
    }

    #[test]
    fn test_merge_preserves_link_name() {
        let mut our_links = Links::default();
        our_links.links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 0,
                name: Some("Hand Named Link".to_string()),
                send: Some(ga("1/0/1")),
                listen: vec![],
            }],
        );
        let ours = model_with(vec![device("1.1.4", "d")], Groups::default(), our_links);

        let mut their_links = Links::default();
        their_links.links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 0,
                name: Some("Fresh Name".to_string()),
                send: Some(ga("1/0/2")),
                listen: vec![ga("2/0/0")],
            }],
        );
        let theirs = model_with(vec![device("1.1.4", "d")], Groups::default(), their_links);

        let (merged, report) = merge(&ours, &theirs);
        let link = &merged.links.links.get(&ia("1.1.4")).unwrap()[0];
        // Name preserved from ours; wiring refreshed from theirs.
        assert_eq!(link.name.as_deref(), Some("Hand Named Link"));
        assert_eq!(link.send, Some(ga("1/0/2")));
        assert_eq!(link.listen, vec![ga("2/0/0")]);
        assert!(
            report
                .conflicts
                .iter()
                .any(|c| c.field == "name" && c.path == "links/1.1.4#0")
        );
    }
}
