//! Pure model analysis: the one code path behind `bussard audit`'s static
//! section and the viz Problems panel.
//!
//! Everything here is a function of the loaded [`Model`] alone — no bus, no
//! files, no clock — so the CLI report, the `--json` contract and the web UI
//! cannot drift apart. The viz server publishes [`analyze`]'s output as the
//! `analysis` object of `GET /api/model`, and the browser renders it instead of
//! recomputing it.
//!
//! # What counts as a finding
//!
//! A KNX installation is *expected* to have loose ends, and calling them
//! problems trains people to ignore the panel. Two things are therefore
//! **neutral information**, not findings:
//!
//! * **Unlinked com-objects.** An actuator ships hundreds of objects and a
//!   project links a fraction of them.
//! * **Unused group addresses.** A GA with neither a sender nor a listener is a
//!   reserve address someone planned ahead for.
//!
//! What *is* a finding is a **one-sided link**: a GA with senders but no
//! listener (telegrams go nowhere) or listeners but no sender (never triggered).
//! Both mean the wiring is half-done, which is a real defect.
//!
//! Everything else the analysis reports — devices without a name or location,
//! GAs without a DPT, links pointing at an unknown com-object — is a *gap in the
//! model*, listed so an owner can close it, and kept separate from the findings.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::Model;
use crate::validate::{Diagnostic, validate};

/// The kind of one-sided link a [`Finding`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    /// The GA has at least one sender and no listener: telegrams go nowhere.
    GaNoListener,
    /// The GA has at least one listener and no sender: it is never triggered.
    GaNoSender,
}

impl FindingKind {
    /// The stable lowercase tag used in JSON and by the viz frontend.
    pub fn tag(self) -> &'static str {
        match self {
            FindingKind::GaNoListener => "ga-no-listener",
            FindingKind::GaNoSender => "ga-no-sender",
        }
    }
}

/// One half-wired group address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Which side is missing.
    #[serde(rename = "type")]
    pub kind: FindingKind,
    /// The group address, as `"3/2/0"`.
    pub ga: String,
    /// The GA's name from `groups.toml`, or `None` for a GA that exists only in
    /// the device files' links.
    pub ga_name: Option<String>,
    /// A ready-to-print sentence explaining the finding.
    pub message: String,
}

/// A device count for one KNX line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineCount {
    /// The line, as `"1.1"`.
    pub line: String,
    /// How many modelled devices sit on it.
    pub devices: usize,
}

/// A link whose com-object number is absent from the device's
/// generated `com_objects:` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownObjectLink {
    /// The device the link belongs to.
    pub device: String,
    /// The com-object number the link names.
    pub object: u16,
    /// The link's informational name, if it carries one.
    pub name: Option<String>,
}

/// A device the model marks as KNX Secure capable or activated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecureDevice {
    /// The device's individual address.
    pub address: String,
    /// The device's name.
    pub name: String,
    /// The application declares Data Secure support.
    pub secure_capable: bool,
    /// Security has been activated on the device (management needs the tool key).
    pub activated: bool,
}

/// Neutral counts that are informational, never findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NeutralInfo {
    /// Com-objects with neither a `send` nor a `listen` GA.
    pub unlinked_com_objects: usize,
    /// GAs with neither a sender nor a listener (reserve addresses).
    pub unused_group_addresses: usize,
}

/// The complete static analysis of a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelAnalysis {
    /// The project name from `groups.toml`, if recorded.
    pub project: Option<String>,
    /// The source the model was last imported from, if recorded.
    pub imported_from: Option<String>,
    /// Total modelled devices.
    pub devices: usize,
    /// Devices per line, ascending.
    pub devices_per_line: Vec<LineCount>,
    /// Devices whose `name:` is empty, ascending.
    pub devices_without_name: Vec<String>,
    /// Devices with no `location:` floor or room, ascending.
    pub devices_without_location: Vec<String>,
    /// Total group addresses, counting GAs that appear only in links.
    pub group_addresses: usize,
    /// GAs with no DPT (undecodable on the bus), ascending.
    pub group_addresses_without_dpt: Vec<String>,
    /// GAs with no name, including the link-only ones, ascending.
    pub group_addresses_without_name: Vec<String>,
    /// Total links.
    pub links: usize,
    /// Links naming a com-object the device's table does not declare.
    pub links_to_unknown_objects: Vec<UnknownObjectLink>,
    /// Individual addresses that have links but no `devices/*.toml` file.
    pub links_to_unknown_devices: Vec<String>,
    /// GAs marked `protected: true`, ascending.
    pub protected_group_addresses: Vec<String>,
    /// Devices the model records as KNX Secure capable or activated.
    pub secure_devices: Vec<SecureDevice>,
    /// The one-sided links — the only entries that are defects.
    pub findings: Vec<Finding>,
    /// Counts that look like problems but are not.
    pub info: NeutralInfo,
}

/// Analyses a loaded model: [`ModelAnalysis::new`] over [`validate`]'s
/// diagnostics.
///
/// Every list is sorted (by address) so the output is stable across runs and
/// diffable.
pub fn analyze(model: &Model) -> ModelAnalysis {
    ModelAnalysis::new(model, &validate(model))
}

impl ModelAnalysis {
    /// The analysis of `model` from its diagnostics (the rules' structured
    /// fields) plus the counts: one-sided links are I048/I049, unknown
    /// devices E013, unknown objects E003, GAs without a DPT W011 (and E001
    /// for the ones only links name), unlinked objects I009, unused GAs I010,
    /// protected GAs I015.
    pub fn new(model: &Model, diags: &[Diagnostic]) -> ModelAnalysis {
        let with =
            |codes: &'static [&'static str]| diags.iter().filter(move |d| codes.contains(&d.code));
        let groups =
            |codes| -> BTreeSet<GroupAddress> { with(codes).filter_map(|d| d.group).collect() };
        let listed = |set: BTreeSet<GroupAddress>| set.iter().map(ToString::to_string).collect();
        let link_only = groups(&["E001"]);
        let mut addresses: BTreeSet<GroupAddress> = model.groups.groups.keys().copied().collect();
        addresses.extend(&link_only);
        let mut without_name = link_only;
        without_name.extend(
            (model.groups.groups.iter())
                .filter(|(_, g)| g.name.trim().is_empty())
                .map(|(ga, _)| *ga),
        );
        let mut findings: Vec<(GroupAddress, Finding)> = with(&["I048", "I049"])
            .filter_map(|d| {
                let kind = match d.code {
                    "I048" => FindingKind::GaNoListener,
                    _ => FindingKind::GaNoSender,
                };
                let ga = d.group?;
                let message = d.message.clone();
                Some((
                    ga,
                    Finding {
                        kind,
                        ga: ga.to_string(),
                        ga_name: d.name.clone(),
                        message,
                    },
                ))
            })
            .collect();
        findings.sort_by_key(|(ga, _)| *ga);
        let mut unknown_objects: Vec<(IndividualAddress, UnknownObjectLink)> = with(&["E003"])
            .filter_map(|d| {
                let link = UnknownObjectLink {
                    device: d.device?.to_string(),
                    object: d.object?,
                    name: d.name.clone(),
                };
                Some((d.device?, link))
            })
            .collect();
        unknown_objects.sort_by_key(|(ia, link)| (*ia, link.object));
        let unknown_devices: BTreeSet<IndividualAddress> =
            with(&["E013"]).filter_map(|d| d.device).collect();

        // Devices: naming, location, per-line counts, Secure status.
        let mut per_line: BTreeMap<(u8, u8), usize> = BTreeMap::new();
        let (mut nameless, mut unlocated, mut secure_devices) =
            (Vec::new(), Vec::new(), Vec::new());
        for (addr, loaded) in &model.devices {
            let device = &loaded.device;
            *per_line.entry((addr.area(), addr.line())).or_default() += 1;
            if device.name.trim().is_empty() {
                nameless.push(addr.to_string());
            }
            let location = device.location.as_ref();
            if !location.is_some_and(|l| l.floor.is_some() || l.room.is_some()) {
                unlocated.push(addr.to_string());
            }
            if let Some(security) = &device.security
                && (security.secure_capable || security.activated)
            {
                secure_devices.push(SecureDevice {
                    address: addr.to_string(),
                    name: device.name.clone(),
                    secure_capable: security.secure_capable,
                    activated: security.activated,
                });
            }
        }

        ModelAnalysis {
            project: model.groups.project.clone(),
            imported_from: model.groups.imported_from.clone(),
            devices: model.devices.len(),
            devices_per_line: (per_line.into_iter())
                .map(|((area, line), devices)| LineCount {
                    line: format!("{area}.{line}"),
                    devices,
                })
                .collect(),
            devices_without_name: nameless,
            devices_without_location: unlocated,
            group_addresses: addresses.len(),
            group_addresses_without_dpt: listed(groups(&["W011", "E001"])),
            group_addresses_without_name: listed(without_name),
            links: model.links.links.values().map(Vec::len).sum(),
            links_to_unknown_objects: unknown_objects.into_iter().map(|(_, l)| l).collect(),
            links_to_unknown_devices: unknown_devices.iter().map(ToString::to_string).collect(),
            protected_group_addresses: listed(groups(&["I015"])),
            secure_devices,
            findings: findings.into_iter().map(|(_, f)| f).collect(),
            info: NeutralInfo {
                unlinked_com_objects: with(&["I009"]).count(),
                unused_group_addresses: with(&["I010"]).count(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadedDevice;
    use crate::schema::{ComObject, Device, Group, Groups, Link, Links, Location};

    /// Builds a model from GA definitions and per-device links.
    fn model_with(
        groups: Vec<(&str, Group)>,
        devices: Vec<(&str, Device)>,
        links: Vec<(&str, Vec<Link>)>,
    ) -> Model {
        let mut model = Model {
            config: Default::default(),
            groups: Groups {
                project: Some("test".to_string()),
                imported_from: None,
                ranges: Default::default(),
                groups: Default::default(),
            },
            links: Links::default(),
            devices: Default::default(),
        };
        for (ga, group) in groups {
            model
                .groups
                .groups
                .insert(ga.parse().expect("a group address"), group);
        }
        for (ia, device) in devices {
            model.devices.insert(
                ia.parse().expect("an individual address"),
                LoadedDevice {
                    device,
                    file_stem: ia.to_string(),
                },
            );
        }
        for (ia, entries) in links {
            model
                .links
                .links
                .insert(ia.parse().expect("an individual address"), entries);
        }
        model
    }

    fn device(name: &str, addr: &str) -> Device {
        Device {
            address: addr.parse().expect("an individual address"),
            name: name.to_string(),
            description: None,
            location: Some(Location {
                floor: Some("EG".to_string()),
                room: Some("Hall".to_string()),
            }),
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
            replaced: None,
            application_override: None,
            knxnet: None,
            lock: Default::default(),
        }
    }

    fn group(name: &str, dpt: Option<&str>) -> Group {
        Group {
            name: name.to_string(),
            dpt: dpt.map(|d| d.parse().expect("a DPT")),
            description: None,
            protected: false,
            secure: false,
        }
    }

    fn link(object: u16, send: Option<&str>, listen: &[&str]) -> Link {
        Link {
            object,
            name: Some(format!("object {object}")),
            send: send.map(|g| g.parse().expect("a group address")),
            listen: listen
                .iter()
                .map(|g| g.parse().expect("a group address"))
                .collect(),
        }
    }

    #[test]
    fn test_analyze_one_sided_links_are_the_only_findings() {
        let model = model_with(
            vec![
                ("1/0/1", group("Wired", Some("1.001"))),
                ("1/0/2", group("Sender only", Some("1.001"))),
                ("1/0/3", group("Listener only", Some("1.001"))),
                ("1/0/4", group("Reserve", Some("1.001"))),
            ],
            vec![
                ("1.1.1", device("Switch", "1.1.1")),
                ("1.1.2", device("Actuator", "1.1.2")),
            ],
            vec![
                (
                    "1.1.1",
                    vec![link(1, Some("1/0/1"), &[]), link(2, Some("1/0/2"), &[])],
                ),
                (
                    "1.1.2",
                    vec![link(1, None, &["1/0/1"]), link(2, None, &["1/0/3"])],
                ),
            ],
        );

        let analysis = analyze(&model);
        assert_eq!(analysis.findings.len(), 2, "{:?}", analysis.findings);
        assert_eq!(analysis.findings[0].ga, "1/0/2");
        assert_eq!(analysis.findings[0].kind, FindingKind::GaNoListener);
        assert_eq!(analysis.findings[1].ga, "1/0/3");
        assert_eq!(analysis.findings[1].kind, FindingKind::GaNoSender);
        // The reserve GA is info, not a finding.
        assert_eq!(analysis.info.unused_group_addresses, 1);
        assert_eq!(analysis.group_addresses, 4);
        assert_eq!(analysis.links, 4);
    }

    #[test]
    fn test_analyze_counts_unlinked_com_objects_as_info() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut dev = device("Actuator", "1.1.2");
        dev.com_objects.insert(
            1,
            ComObject {
                dpt: None,
                size: None,
                flags: "CWT".parse()?,
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        dev.com_objects.insert(
            2,
            ComObject {
                dpt: None,
                size: None,
                flags: "CWT".parse()?,
                reference: None,
                channel: None,
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        let model = model_with(
            vec![("1/0/1", group("Wired", Some("1.001")))],
            vec![("1.1.2", dev)],
            vec![("1.1.2", vec![link(1, Some("1/0/1"), &[])])],
        );

        let analysis = analyze(&model);
        assert_eq!(analysis.info.unlinked_com_objects, 1);
        assert!(
            analysis
                .findings
                .iter()
                .all(|f| f.kind != FindingKind::GaNoSender),
        );
        Ok(())
    }

    #[test]
    fn test_analyze_reports_model_gaps() {
        let mut nameless = device("", "1.1.3");
        nameless.location = None;
        let model = model_with(
            vec![
                ("1/0/1", group("Named", Some("1.001"))),
                ("1/0/2", group("No DPT", None)),
                ("1/0/3", group("", Some("1.001"))),
            ],
            vec![("1.1.3", nameless)],
            // A link on a device with no com-object table, plus links for a
            // device that has no file at all.
            vec![
                ("1.1.3", vec![link(7, Some("1/0/1"), &[])]),
                ("1.9.9", vec![link(1, Some("1/0/1"), &[])]),
            ],
        );

        let analysis = analyze(&model);
        assert_eq!(analysis.devices_without_name, vec!["1.1.3"]);
        assert_eq!(analysis.devices_without_location, vec!["1.1.3"]);
        assert_eq!(analysis.group_addresses_without_dpt, vec!["1/0/2"]);
        assert_eq!(analysis.group_addresses_without_name, vec!["1/0/3"]);
        assert_eq!(analysis.links_to_unknown_devices, vec!["1.9.9"]);
        assert_eq!(analysis.links_to_unknown_objects.len(), 1);
        assert_eq!(analysis.links_to_unknown_objects[0].object, 7);
        assert_eq!(analysis.devices_per_line.len(), 1);
        assert_eq!(analysis.devices_per_line[0].line, "1.1");
    }

    #[test]
    fn test_analyze_link_only_ga_has_no_name_and_no_dpt() {
        let model = model_with(
            vec![],
            vec![("1.1.1", device("Switch", "1.1.1"))],
            vec![("1.1.1", vec![link(1, Some("5/5/5"), &[])])],
        );

        let analysis = analyze(&model);
        assert_eq!(analysis.group_addresses, 1);
        assert_eq!(analysis.group_addresses_without_name, vec!["5/5/5"]);
        assert_eq!(analysis.group_addresses_without_dpt, vec!["5/5/5"]);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].ga_name, None);
    }

    #[test]
    fn test_analyze_protected_and_secure_are_listed() {
        let mut protected = group("Wind alarm", Some("1.005"));
        protected.protected = true;
        let mut secure = device("Secure actuator", "1.1.4");
        secure.security = Some(crate::schema::DeviceSecurity {
            secure_capable: true,
            activated: true,
            has_fdsk_certificate: false,
            sequence_number: None,
            secure_commissioning: false,
            secure_senders: Vec::new(),
            group_keys: None,
        });
        let model = model_with(vec![("9/0/1", protected)], vec![("1.1.4", secure)], vec![]);

        let analysis = analyze(&model);
        assert_eq!(analysis.protected_group_addresses, vec!["9/0/1"]);
        assert_eq!(analysis.secure_devices.len(), 1);
        assert!(analysis.secure_devices[0].activated);
    }
}
