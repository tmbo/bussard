//! A device's tables read back and diffed against the model: the report of
//! `bussard reconstruct <address>` and `knx_reconstruct_device` (issue #717).
//!
//! The address and association tables recover *which* GAs each com-object is
//! linked to, but not the transmit direction: the send/listen distinction
//! lives in the group object table's flags, which many devices do not expose
//! readably. The diff therefore compares **GA sets per object**: a model
//! `send` and a model `listen` entry are treated alike.

use std::collections::{BTreeMap, BTreeSet};

use bussard_mgmt::system_type;
use bussard_mgmt::tables::DeviceTables;
use bussard_model::identity::IdentityCheck;
use bussard_model::{GroupAddress, IndividualAddress, Model};

use crate::params::Readback;

/// One (object, GA) pair in the diff.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct ObjectGa {
    /// The com-object number.
    pub object: u16,
    /// The group address, formatted `main/middle/sub`.
    pub ga: String,
}

/// The read-back of one device, shaped for the CLI's text and `--json`
/// outputs and for the MCP tool.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconstructReport {
    /// The device address.
    pub address: String,
    /// The mask version, formatted `07B0`.
    pub mask: String,
    /// Human-readable system type for the mask.
    pub system_type: String,
    /// Which read path produced each table (`"property"` or `"memory"`).
    pub table_source: BTreeMap<String, String>,
    /// Every GA in the device's address table, in table order.
    pub addresses: Vec<String>,
    /// The raw association table as (tsap, asap) pairs.
    pub associations: Vec<Association>,
    /// Per-path notes from the table reader.
    pub notes: Vec<String>,
    /// Com-object → GAs as resolved from the tables, keyed by object number.
    pub objects: BTreeMap<u16, Vec<String>>,
    /// The model diff, when a model was loaded.
    pub diff: Option<Diff>,
    /// The parameter read-back (issue #119), when a product file was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Readback>,
    /// The device's identity compared with `bussard.lock` (lock v2, issue
    /// #228), when the device facts were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
}

/// A raw association table entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Association {
    /// Index into the address table (1-based).
    pub tsap: u16,
    /// The com-object number domain (see [`bussard_mgmt::tables`]).
    pub asap: u16,
}

/// The (object, GA)-level diff against the model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diff {
    /// Pairs present both on the device and in the model.
    pub matches: Vec<ObjectGa>,
    /// Pairs the device has but the model does not.
    pub on_device_not_in_model: Vec<ObjectGa>,
    /// Pairs the model has but the device does not.
    pub in_model_not_on_device: Vec<ObjectGa>,
    /// The limitation note about send/listen.
    pub note: &'static str,
}

/// The limitation baked into every diff.
pub const DIRECTION_NOTE: &str = "send/listen direction is not recoverable from the address and \
     association tables alone (the transmit flag lives in the group object table); the diff \
     compares GA sets per object";

/// Which side of the diff a pair is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceKind {
    /// On the device, not in the model.
    OnDeviceNotInModel,
    /// In the model, not on the device.
    InModelNotOnDevice,
}

/// One difference between the device and the model, in the model's words.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Difference {
    /// Which side the pair is on.
    pub kind: DifferenceKind,
    /// The com-object number.
    pub object: u16,
    /// The group address.
    pub ga: String,
    /// The group address's name in the model, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ga_name: Option<String>,
    /// Whether the group address is `protected` in the model.
    pub protected: bool,
    /// The difference as one sentence.
    pub sentence: String,
}

impl Diff {
    /// Whether the device's tables and the model's links agree.
    pub fn is_empty(&self) -> bool {
        self.on_device_not_in_model.is_empty() && self.in_model_not_on_device.is_empty()
    }

    /// Every difference as a sentence naming the group address the model
    /// knows (`Object 22 listens to 1/2/2 (Blind position) in the model, but
    /// not on 1.1.4.`), the device's extras first.
    pub fn differences(&self, target: IndividualAddress, model: Option<&Model>) -> Vec<Difference> {
        let group = |ga: &str| {
            let parsed: Option<GroupAddress> = ga.parse().ok();
            parsed
                .and_then(|ga| model.and_then(|m| m.groups.groups.get(&ga)))
                .map(|g| (g.name.clone(), g.protected))
        };
        let mut out = Vec::new();
        for (kind, pairs) in [
            (
                DifferenceKind::OnDeviceNotInModel,
                &self.on_device_not_in_model,
            ),
            (
                DifferenceKind::InModelNotOnDevice,
                &self.in_model_not_on_device,
            ),
        ] {
            for pair in pairs {
                let known = group(&pair.ga);
                let named = match &known {
                    Some((name, _)) if !name.is_empty() => format!("{} ({name})", pair.ga),
                    _ => pair.ga.clone(),
                };
                let sentence = match kind {
                    DifferenceKind::OnDeviceNotInModel => format!(
                        "Object {} on {target} is linked to {named}, which the model does not \
                         link to it.",
                        pair.object
                    ),
                    DifferenceKind::InModelNotOnDevice => format!(
                        "Object {} is linked to {named} in the model, but not on {target}.",
                        pair.object
                    ),
                };
                out.push(Difference {
                    kind,
                    object: pair.object,
                    ga: pair.ga.clone(),
                    ga_name: known
                        .as_ref()
                        .map(|(name, _)| name.clone())
                        .filter(|n| !n.is_empty()),
                    protected: known.is_some_and(|(_, protected)| protected),
                    sentence,
                });
            }
        }
        out
    }
}

/// Assembles the report of `target`'s tables `read`: the raw inventory, the
/// resolved objects and, with a `model`, the diff against its links for the
/// device. The parameter read-back and the identity are left for the caller.
pub fn build_report(
    target: IndividualAddress,
    read: &DeviceTables,
    model: Option<&Model>,
) -> ReconstructReport {
    // Resolved (object → GA set) from the device tables.
    let mut device_objects: BTreeMap<u16, BTreeSet<GroupAddress>> = BTreeMap::new();
    for link in &read.resolved {
        device_objects
            .entry(link.object)
            .or_default()
            .insert(link.ga);
    }

    // The model's (object → GA set) for this device, send and listen merged.
    let model_objects: Option<BTreeMap<u16, BTreeSet<GroupAddress>>> = model.map(|m| {
        let mut map: BTreeMap<u16, BTreeSet<GroupAddress>> = BTreeMap::new();
        if let Some(links) = m.links.links.get(&target) {
            for link in links {
                let entry = map.entry(link.object).or_default();
                entry.extend(link.send);
                entry.extend(link.listen.iter().copied());
            }
        }
        map
    });

    let diff = model_objects.map(|model_objects| diff_objects(&device_objects, &model_objects));

    ReconstructReport {
        address: target.to_string(),
        mask: format!("{:04X}", read.mask),
        system_type: system_type(read.mask).to_string(),
        table_source: read
            .sources
            .iter()
            .map(|(table, source)| (table.to_string(), source.to_string()))
            .collect(),
        addresses: read.addresses.iter().map(|ga| ga.to_string()).collect(),
        associations: read
            .associations
            .iter()
            .map(|&(tsap, asap)| Association { tsap, asap })
            .collect(),
        notes: read.notes.clone(),
        objects: device_objects
            .iter()
            .map(|(obj, gas)| (*obj, gas.iter().map(|ga| ga.to_string()).collect()))
            .collect(),
        diff,
        parameters: None,
        identity: None,
    }
}

/// Computes the (object, GA)-pair diff between device and model.
fn diff_objects(
    device: &BTreeMap<u16, BTreeSet<GroupAddress>>,
    model: &BTreeMap<u16, BTreeSet<GroupAddress>>,
) -> Diff {
    let pairs = |map: &BTreeMap<u16, BTreeSet<GroupAddress>>| -> BTreeSet<(u16, GroupAddress)> {
        map.iter()
            .flat_map(|(obj, gas)| gas.iter().map(|ga| (*obj, *ga)).collect::<Vec<_>>())
            .collect()
    };
    let dev = pairs(device);
    let mdl = pairs(model);
    let to_vec = |set: Vec<&(u16, GroupAddress)>| -> Vec<ObjectGa> {
        set.into_iter()
            .map(|&(object, ga)| ObjectGa {
                object,
                ga: ga.to_string(),
            })
            .collect()
    };
    Diff {
        matches: to_vec(dev.intersection(&mdl).collect()),
        on_device_not_in_model: to_vec(dev.difference(&mdl).collect()),
        in_model_not_on_device: to_vec(mdl.difference(&dev).collect()),
        note: DIRECTION_NOTE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    #[test]
    fn test_diff_objects_splits_pairs() -> Result<(), Box<dyn std::error::Error>> {
        let mut device = BTreeMap::new();
        device.insert(1, BTreeSet::from([ga("1/0/1")?, ga("1/0/2")?]));
        let mut model = BTreeMap::new();
        model.insert(1, BTreeSet::from([ga("1/0/1")?]));
        model.insert(2, BTreeSet::from([ga("1/0/3")?]));
        let diff = diff_objects(&device, &model);
        assert_eq!(diff.matches.len(), 1);
        assert_eq!(diff.on_device_not_in_model[0].ga, "1/0/2");
        assert_eq!(diff.in_model_not_on_device[0].object, 2);
        let target: IndividualAddress = "1.1.4".parse()?;
        let sentences = diff.differences(target, None);
        assert_eq!(sentences.len(), 2);
        assert_eq!(sentences[0].kind, DifferenceKind::OnDeviceNotInModel);
        assert!(sentences[1].sentence.contains("not on 1.1.4"));
        Ok(())
    }
}
