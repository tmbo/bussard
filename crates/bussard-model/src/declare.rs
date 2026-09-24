//! Declaring a group address where it is first used.
//!
//! A device file may link a com object to a group address that `groups.toml`
//! does not define yet. `bussard validate` reports that as a warning (E001);
//! the commands that write the model (`import`, `apply` and the MCP edit
//! tools) instead add the address to `groups.toml` with a name and a DPT taken
//! from the first object that uses it, and report the addition.
//!
//! The name is `<channel name or device name> <object function or key>`, the
//! DPT the object's. The first use in address order wins: devices by
//! individual address, objects by number, the sending address before the
//! listening ones.

use std::collections::BTreeSet;

use crate::address::{GroupAddress, IndividualAddress};
use crate::dpt::Dpt;
use crate::loader::Model;
use crate::schema::{Device, Group};

/// One group address added to `groups.toml` because a device file used it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredGroup {
    /// The address.
    pub address: GroupAddress,
    /// The name it was given.
    pub name: String,
    /// The DPT it was given (the using object's), when the object has one.
    pub dpt: Option<Dpt>,
    /// The device whose file used it first.
    pub device: IndividualAddress,
    /// The com object that used it first.
    pub object: u16,
}

impl DeclaredGroup {
    /// The report line: `added 0/1/3 "Fenster Süd Langzeitbetrieb" (DPT 1.008)
    /// to groups.toml, first used by 1.1.47 object 144`.
    pub fn sentence(&self) -> String {
        let dpt = match &self.dpt {
            Some(dpt) => format!(" (DPT {dpt})"),
            None => String::new(),
        };
        format!(
            "added {} {:?}{dpt} to groups.toml, first used by {} object {}",
            self.address, self.name, self.device, self.object
        )
    }
}

/// Adds every group address a device file links but `groups.toml` does not
/// define, and returns what was added, in address order.
///
/// Addresses already defined are never touched. Pure apart from `model`: the
/// caller decides whether and how to save.
pub fn declare_used_groups(model: &mut Model) -> Vec<DeclaredGroup> {
    let mut added: Vec<DeclaredGroup> = Vec::new();
    let mut seen: BTreeSet<GroupAddress> = model.groups.groups.keys().copied().collect();
    for (ia, links) in &model.links.links {
        let device = model.devices.get(ia).map(|d| &d.device);
        let mut sorted: Vec<_> = links.iter().collect();
        sorted.sort_by_key(|l| l.object);
        for link in sorted {
            for ga in link.send.iter().chain(link.listen.iter()) {
                if !seen.insert(*ga) {
                    continue;
                }
                added.push(DeclaredGroup {
                    address: *ga,
                    name: group_name(device, *ia, link.object),
                    dpt: device
                        .and_then(|d| d.com_objects.get(&link.object))
                        .and_then(|co| co.dpt),
                    device: *ia,
                    object: link.object,
                });
            }
        }
    }
    for d in &added {
        model.groups.groups.insert(
            d.address,
            Group {
                name: d.name.clone(),
                dpt: d.dpt,
                description: None,
                protected: false,
                secure: false,
            },
        );
    }
    added.sort_by_key(|d| d.address.raw());
    added
}

/// `<channel name or device name> <object function or key>`.
fn group_name(device: Option<&Device>, ia: IndividualAddress, object: u16) -> String {
    let co = device.and_then(|d| d.com_objects.get(&object));
    let owner = device
        .and_then(|d| {
            let id = co?.channel.as_deref()?;
            let name = d.channels.get(id)?.name.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .or_else(|| {
            device
                .map(|d| d.name.trim().to_string())
                .filter(|n| !n.is_empty())
        })
        .unwrap_or_else(|| ia.to_string());
    let function = co
        .and_then(|c| {
            [c.function.as_deref(), c.key.as_deref(), c.text.as_deref()]
                .into_iter()
                .flatten()
                .map(str::trim)
                .find(|s| !s.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("object {object}"));
    format!("{owner} {function}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadedDevice;
    use crate::schema::{Channel, ComObject, Link};

    fn model() -> Result<Model, Box<dyn std::error::Error>> {
        let ia: IndividualAddress = "1.1.47".parse()?;
        let mut device = Device {
            address: ia,
            name: "Jalousieaktor".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            application_override: None,
            lock: Default::default(),
            security: None,
        };
        device.channels.insert(
            "CH-1".to_string(),
            Channel {
                name: "Fenster Süd".to_string(),
                ..Channel::default()
            },
        );
        device.com_objects.insert(
            144,
            ComObject {
                dpt: Some("1.008".parse()?),
                channel: Some("CH-1".to_string()),
                function: Some("Langzeitbetrieb".to_string()),
                key: Some("langzeitbetrieb".to_string()),
                ..ComObject::default()
            },
        );
        device.com_objects.insert(
            138,
            ComObject {
                key: Some("in-betrieb".to_string()),
                ..ComObject::default()
            },
        );
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        model.devices.insert(
            ia,
            LoadedDevice {
                device,
                file_stem: ia.to_string(),
            },
        );
        model.links.links.insert(
            ia,
            vec![
                Link {
                    object: 144,
                    name: None,
                    send: Some("0/1/3".parse()?),
                    listen: vec!["0/1/9".parse()?],
                },
                Link {
                    object: 138,
                    name: None,
                    send: Some("4/1/2".parse()?),
                    listen: Vec::new(),
                },
                Link {
                    object: 150,
                    name: None,
                    send: None,
                    listen: vec!["0/1/3".parse()?],
                },
            ],
        );
        model.groups.groups.insert(
            "0/1/9".parse()?,
            Group {
                name: "Defined".to_string(),
                dpt: None,
                description: None,
                protected: true,
                secure: false,
            },
        );
        Ok(model)
    }

    #[test]
    fn test_declare_used_groups_names_by_channel_and_function()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut model = model()?;
        let added = declare_used_groups(&mut model);
        let names: Vec<(String, String)> = added
            .iter()
            .map(|d| (d.address.to_string(), d.name.clone()))
            .collect();
        assert_eq!(
            names,
            vec![
                (
                    "0/1/3".to_string(),
                    "Fenster Süd Langzeitbetrieb".to_string()
                ),
                ("4/1/2".to_string(), "Jalousieaktor in-betrieb".to_string()),
            ]
        );
        let g = &model.groups.groups[&"0/1/3".parse()?];
        assert_eq!(g.dpt.map(|d| d.to_string()).as_deref(), Some("1.008"));
        // An address already defined keeps everything it had.
        assert!(model.groups.groups[&"0/1/9".parse()?].protected);
        assert_eq!(
            added[0].sentence(),
            "added 0/1/3 \"Fenster Süd Langzeitbetrieb\" (DPT 1.008) to groups.toml, first used \
             by 1.1.47 object 144"
        );
        // A second run finds nothing left to add.
        assert!(declare_used_groups(&mut model).is_empty());
        Ok(())
    }
}
