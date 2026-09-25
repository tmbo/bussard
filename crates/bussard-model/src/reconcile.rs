//! Resolving re-import merge conflicts (issue #111).
//!
//! [`merge`](crate::merge::merge) keeps every hand-authored field from the local
//! model and reports each disagreement as a [`Conflict`]. This module turns a
//! conflict into a sentence a homeowner can judge and, when she chooses the
//! incoming value, applies it to the merged model.
//!
//! `bussard import --mine` keeps the local value for every conflict (the merge
//! default), `--theirs` applies [`take_theirs`] to every conflict, and
//! `--interactive` asks per conflict.

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::Model;
use crate::merge::Conflict;
use crate::schema::Location;

/// Which side of a conflict to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The local model's value (what the merge already kept).
    Mine,
    /// The incoming project's or bundle's value.
    Theirs,
}

/// Renders a conflict as one sentence: what the field is, the local value and
/// the incoming one. `source` names the incoming side, e.g. `"bundle"` or
/// `"project"`.
///
/// ```
/// use bussard_model::merge::Conflict;
/// use bussard_model::reconcile::conflict_sentence;
/// use bussard_model::Model;
/// let conflict = Conflict {
///     path: "groups/0/0/4".into(),
///     field: "name".into(),
///     ours: "Porch light".into(),
///     theirs: "Front light".into(),
/// };
/// let empty = Model::from_texts(&Default::default()).map_err(|e| e.to_string())?;
/// assert_eq!(
///     conflict_sentence(&conflict, &empty, "bundle"),
///     "Group address 0/0/4: the name is \"Porch light\" here and \"Front light\" in the bundle."
/// );
/// # Ok::<(), String>(())
/// ```
pub fn conflict_sentence(conflict: &Conflict, ours: &Model, source: &str) -> String {
    let subject = subject(conflict, ours);
    let field = field_phrase(&conflict.field);
    format!(
        "{subject}: {field} is {} here and {} in the {source}.",
        value(&conflict.ours),
        value(&conflict.theirs)
    )
}

/// Applies the incoming value of `conflict` to `merged`, taking it from
/// `theirs`. Returns `false` when the conflict names something this module
/// does not know how to resolve (the local value then stays).
pub fn take_theirs(merged: &mut Model, theirs: &Model, conflict: &Conflict) -> bool {
    let path = conflict.path.as_str();
    let field = conflict.field.as_str();
    if path == "groups" && field == "project" {
        merged.groups.project = theirs.groups.project.clone();
        return true;
    }
    if let Some(ga) = path.strip_prefix("groups/") {
        let Ok(ga) = ga.parse::<GroupAddress>() else {
            return false;
        };
        let (Some(mine), Some(incoming)) = (
            merged.groups.groups.get_mut(&ga),
            theirs.groups.groups.get(&ga),
        ) else {
            return false;
        };
        match field {
            "name" => mine.name = incoming.name.clone(),
            "dpt" => mine.dpt = incoming.dpt,
            "description" => mine.description = incoming.description.clone(),
            "protected" => mine.protected = incoming.protected,
            _ => return false,
        }
        return true;
    }
    if let Some(rest) = path.strip_prefix("links/") {
        let Some((ia, object)) = rest.split_once('#') else {
            return false;
        };
        let (Ok(ia), Ok(object)) = (ia.parse::<IndividualAddress>(), object.parse::<u16>()) else {
            return false;
        };
        if field == "send" || field == "listen" {
            return take_their_wiring(merged, theirs, ia, object, field);
        }
        let incoming = theirs
            .links
            .links
            .get(&ia)
            .and_then(|links| links.iter().find(|l| l.object == object));
        let mine = merged
            .links
            .links
            .get_mut(&ia)
            .and_then(|links| links.iter_mut().find(|l| l.object == object));
        let (Some(mine), Some(incoming)) = (mine, incoming) else {
            return false;
        };
        if field != "name" {
            return false;
        }
        mine.name = incoming.name.clone();
        return true;
    }
    if let Some(ia) = path.strip_prefix("devices/") {
        let Ok(ia) = ia.parse::<IndividualAddress>() else {
            return false;
        };
        let (Some(mine), Some(incoming)) = (merged.devices.get_mut(&ia), theirs.devices.get(&ia))
        else {
            return false;
        };
        let (mine, incoming) = (&mut mine.device, &incoming.device);
        match field {
            "name" => mine.name = incoming.name.clone(),
            "description" => mine.description = incoming.description.clone(),
            "location.floor" | "location.room" => {
                let theirs_loc = incoming.location.as_ref();
                let loc = mine.location.get_or_insert(Location {
                    floor: None,
                    room: None,
                });
                if field == "location.floor" {
                    loc.floor = theirs_loc.and_then(|l| l.floor.clone());
                } else {
                    loc.room = theirs_loc.and_then(|l| l.room.clone());
                }
                if loc.floor.is_none() && loc.room.is_none() {
                    mine.location = None;
                }
            }
            "product.manufacturer" | "product.order_number" => {
                let Some(product) = mine.product.as_mut() else {
                    return false;
                };
                let incoming = incoming.product.as_ref();
                if field == "product.manufacturer" {
                    product.manufacturer = incoming.and_then(|p| p.manufacturer.clone());
                } else {
                    product.order_number = incoming.and_then(|p| p.order_number.clone());
                }
            }
            other if other.starts_with("parameters.") => {
                let key = &other["parameters.".len()..];
                let Some(value) = incoming.parameters.get(key) else {
                    return false;
                };
                mine.parameters.insert(key.to_string(), value.clone());
            }
            other => {
                let Some(key) = other
                    .strip_prefix("channels.")
                    .and_then(|k| k.strip_suffix(".name"))
                else {
                    return false;
                };
                let (Some(channel), Some(incoming)) =
                    (mine.channels.get_mut(key), incoming.channels.get(key))
                else {
                    return false;
                };
                channel.name = incoming.name.clone();
            }
        }
        return true;
    }
    false
}

/// Takes the incoming `send` or `listen` wiring of com object `object` on
/// device `ia`: the merge kept a link the project no longer has (see
/// [`merge`](crate::merge::merge)), and taking theirs removes it. Entries of
/// the object are matched by position; one left with nothing linked that the
/// project does not list either is dropped, and so is a device's link list
/// left empty.
fn take_their_wiring(
    merged: &mut Model,
    theirs: &Model,
    ia: IndividualAddress,
    object: u16,
    field: &str,
) -> bool {
    let no_links = Vec::new();
    let incoming: Vec<&crate::schema::Link> = theirs
        .links
        .links
        .get(&ia)
        .unwrap_or(&no_links)
        .iter()
        .filter(|l| l.object == object)
        .collect();
    let Some(entries) = merged.links.links.get_mut(&ia) else {
        return false;
    };
    let mut index = 0;
    let mut touched = false;
    entries.retain_mut(|link| {
        if link.object != object {
            return true;
        }
        let counterpart = incoming.get(index).copied();
        index += 1;
        touched = true;
        if field == "send" {
            link.send = counterpart.and_then(|l| l.send);
        } else {
            link.listen = counterpart.map(|l| l.listen.clone()).unwrap_or_default();
        }
        counterpart.is_some() || link.send.is_some() || !link.listen.is_empty()
    });
    if entries.is_empty() && !theirs.links.links.contains_key(&ia) {
        merged.links.links.remove(&ia);
    }
    touched
}

/// Applies `side` to every conflict: [`Side::Mine`] leaves `merged` as the
/// merge produced it, [`Side::Theirs`] takes every incoming value. Returns how
/// many conflicts took the incoming value.
pub fn resolve_all(
    merged: &mut Model,
    theirs: &Model,
    conflicts: &[Conflict],
    side: Side,
) -> usize {
    match side {
        Side::Mine => 0,
        Side::Theirs => conflicts
            .iter()
            .filter(|c| take_theirs(merged, theirs, c))
            .count(),
    }
}

/// The thing a conflict is about, as a human reads it.
fn subject(conflict: &Conflict, ours: &Model) -> String {
    let path = conflict.path.as_str();
    if path == "groups" {
        return "The project".to_string();
    }
    if let Some(ga) = path.strip_prefix("groups/") {
        return match ga.parse::<GroupAddress>() {
            Ok(address) => match ours.groups.groups.get(&address) {
                Some(g) if !g.name.trim().is_empty() => {
                    format!("Group address {} ({address})", g.name.trim())
                }
                _ => format!("Group address {address}"),
            },
            Err(_) => format!("Group address {ga}"),
        };
    }
    if let Some(rest) = path.strip_prefix("links/") {
        let (ia, object) = rest.split_once('#').unwrap_or((rest, "?"));
        return format!("Com object {object} on {}", device_label(ia, ours));
    }
    if let Some(ia) = path.strip_prefix("devices/") {
        return device_label(ia, ours);
    }
    path.to_string()
}

/// `Hallway push button (1.1.5)`, or `Device 1.1.5` when it has no name.
fn device_label(ia: &str, ours: &Model) -> String {
    let name = ia
        .parse::<IndividualAddress>()
        .ok()
        .and_then(|address| ours.devices.get(&address))
        .map(|d| d.device.name.trim().to_string())
        .filter(|n| !n.is_empty());
    match name {
        Some(name) => format!("{name} ({ia})"),
        None => format!("Device {ia}"),
    }
}

/// The field as a phrase: `name` → `the name`, `channels.1.name` → `the name
/// of channel 1`.
fn field_phrase(field: &str) -> String {
    match field {
        "name" => "the name".to_string(),
        "dpt" => "the datapoint type".to_string(),
        "description" => "the description".to_string(),
        "protected" => "the protected flag".to_string(),
        "project" => "the project name".to_string(),
        "location.floor" => "the floor".to_string(),
        "location.room" => "the room".to_string(),
        "product.manufacturer" => "the manufacturer".to_string(),
        "product.order_number" => "the order number".to_string(),
        "send" => "the send address".to_string(),
        "listen" => "the listen addresses".to_string(),
        other => {
            if let Some(key) = other.strip_prefix("parameters.") {
                let slug = key.split_once('@').map_or(key, |(slug, _)| slug);
                return format!("the parameter `{slug}`");
            }
            match other
                .strip_prefix("channels.")
                .and_then(|k| k.strip_suffix(".name"))
            {
                Some(key) => format!("the name of channel {key}"),
                None => format!("`{other}`"),
            }
        }
    }
}

/// A value quoted for a sentence; the merge's `(none)` reads as `nothing`.
fn value(v: &str) -> String {
    if v == "(none)" || v.trim().is_empty() {
        "nothing".to_string()
    } else {
        format!("{v:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A model from `groups.toml` and one device file.
    fn model(groups: &str, device: &str) -> Result<Model, Box<dyn std::error::Error>> {
        let mut files = BTreeMap::new();
        files.insert("groups.toml".to_string(), groups.to_string());
        files.insert("devices/1.1.4.toml".to_string(), device.to_string());
        Ok(Model::from_texts(&files)?)
    }

    #[test]
    fn test_take_theirs_applies_every_reported_conflict() -> TestResult {
        let ours = model(
            "groups = [{ address = \"0/0/4\", name = \"Porch light\", dpt = \"1.001\" }]\n",
            "address = \"1.1.4\"\nname = \"Actuator\"\n[location]\nroom = \"Hall\"\n",
        )?;
        let theirs = model(
            "groups = [{ address = \"0/0/4\", name = \"Front light\", dpt = \"1.001\" }]\n",
            "address = \"1.1.4\"\nname = \"Switch actuator\"\n[location]\nroom = \"Porch\"\n",
        )?;
        let (mut merged, report) = crate::merge::merge(&ours, &theirs);
        assert_eq!(report.conflicts.len(), 3, "{:?}", report.conflicts);
        let taken = resolve_all(&mut merged, &theirs, &report.conflicts, Side::Theirs);
        assert_eq!(taken, 3);
        assert!(crate::change::describe(&theirs, &merged).is_empty());
        Ok(())
    }

    #[test]
    fn test_conflict_sentence_names_the_device_and_values() -> TestResult {
        let ours = model(
            "groups = []\n",
            "address = \"1.1.4\"\nname = \"Actuator\"\n",
        )?;
        let conflict = Conflict {
            path: "devices/1.1.4".into(),
            field: "location.room".into(),
            ours: "(none)".into(),
            theirs: "Porch".into(),
        };
        assert_eq!(
            conflict_sentence(&conflict, &ours, "bundle"),
            "Actuator (1.1.4): the room is nothing here and \"Porch\" in the bundle."
        );
        Ok(())
    }
}
