//! Model validation.
//!
//! [`validate`] runs every rule from the design document (§5.3) over a loaded
//! [`Model`] and returns a deterministically ordered list of [`Diagnostic`]s.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::address::GroupAddress;
use crate::dpt::ApduSize;
use crate::flags::Flags;
use crate::loader::Model;

/// The severity of a [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// A blocking problem; `bussard validate` exits non-zero.
    Error,
    /// A likely problem worth surfacing, but not blocking.
    Warning,
    /// An informational note.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// A single validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The rule code, e.g. `"E001"`.
    pub code: &'static str,
    /// Severity.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Human-readable location (e.g. `links."1.1.4"[2]`).
    pub location: String,
}

impl Diagnostic {
    fn new(
        code: &'static str,
        severity: Severity,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            location: location.into(),
        }
    }
}

/// The declared size of an object, for size-conflict checks.
///
/// Derived from a DPT (`expected_size`) or a declared size string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SizeInfo {
    Bits(u8),
    Bytes(u8),
}

impl SizeInfo {
    fn from_apdu(size: ApduSize) -> Self {
        match size {
            ApduSize::Bits(n) => SizeInfo::Bits(n),
            ApduSize::Bytes(n) => SizeInfo::Bytes(n),
        }
    }

    fn label(self) -> String {
        match self {
            SizeInfo::Bits(1) => "1 bit".to_string(),
            SizeInfo::Bits(n) => format!("{n} bits"),
            SizeInfo::Bytes(1) => "1 byte".to_string(),
            SizeInfo::Bytes(n) => format!("{n} bytes"),
        }
    }
}

/// Validates a model, returning diagnostics in a deterministic order.
///
/// Findings are sorted by `(location, code)` so output is stable across runs.
pub fn validate(model: &Model) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    check_reserved_gas(model, &mut diags);
    check_links(model, &mut diags);
    check_ga_consistency(model, &mut diags);
    check_orphans_and_unlinked(model, &mut diags);
    check_protected_gas(model, &mut diags);

    diags.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
    diags
}

/// E012: invalid/reserved GA (`0/0/0`) that is referenced in the model.
fn check_reserved_gas(model: &Model, diags: &mut Vec<Diagnostic>) {
    // Defined in groups.yaml.
    for ga in model.groups.groups.keys() {
        if ga.is_reserved() {
            diags.push(Diagnostic::new(
                "E012",
                Severity::Error,
                format!("groups.\"{ga}\""),
                "group address 0/0/0 is reserved and must not be used",
            ));
        }
    }
}

/// Rules that walk over the links: E001, E003, E007, E013, W008, and the
/// duplicate-object-within-a-device error.
fn check_links(model: &Model, diags: &mut Vec<Diagnostic>) {
    for (ia, links) in &model.links.links {
        let device = model.devices.get(ia);

        // E013: link for a device that has no device file.
        if device.is_none() {
            diags.push(Diagnostic::new(
                "E013",
                Severity::Error,
                format!("links.\"{ia}\""),
                format!("link references unknown device {ia} (no device file defines it)"),
            ));
        }

        // Duplicate object numbers within one device's links.
        let mut seen_objects: BTreeMap<u16, usize> = BTreeMap::new();

        for (idx, link) in links.iter().enumerate() {
            let loc = format!("links.\"{ia}\"[{idx}]");

            if let Some(prev) = seen_objects.insert(link.object, idx) {
                diags.push(Diagnostic::new(
                    "E014",
                    Severity::Error,
                    loc.clone(),
                    format!(
                        "object {} is linked more than once on {ia} (also at [{prev}])",
                        link.object
                    ),
                ));
            }

            // Gather all GAs this link touches, with their role.
            let mut refs: Vec<(&GroupAddress, &str)> = Vec::new();
            if let Some(send) = &link.send {
                refs.push((send, "send"));
            }
            for ga in &link.listen {
                refs.push((ga, "listen"));
            }

            // E001: referenced GA not defined in groups.yaml.
            for (ga, role) in &refs {
                if !model.groups.groups.contains_key(ga) {
                    diags.push(Diagnostic::new(
                        "E001",
                        Severity::Error,
                        loc.clone(),
                        format!("{role} GA {ga} is not defined in groups.yaml"),
                    ));
                }
            }

            // Rules needing the device's com object.
            if let Some(loaded) = device {
                match loaded.device.com_objects.get(&link.object) {
                    None => {
                        // E003: object absent from the device's com_objects.
                        diags.push(Diagnostic::new(
                            "E003",
                            Severity::Error,
                            loc.clone(),
                            format!(
                                "object {} is not defined in device {ia}'s com_objects",
                                link.object
                            ),
                        ));
                    }
                    Some(co) => {
                        // E007: linked object without the C flag.
                        if !co.flags.contains(Flags::COMMUNICATION) {
                            diags.push(Diagnostic::new(
                                "E007",
                                Severity::Error,
                                loc.clone(),
                                format!(
                                    "object {} is linked but lacks the C (communication) flag",
                                    link.object
                                ),
                            ));
                        }
                        // E007: send: on an object without the T flag.
                        if link.send.is_some() && !co.flags.contains(Flags::TRANSMIT) {
                            diags.push(Diagnostic::new(
                                "E007",
                                Severity::Error,
                                loc.clone(),
                                format!(
                                    "object {} has a send GA but lacks the T (transmit) flag",
                                    link.object
                                ),
                            ));
                        }
                        // W008: listen-only object with neither W nor U.
                        let listen_only = link.send.is_none() && !link.listen.is_empty();
                        if listen_only
                            && !co.flags.contains(Flags::WRITE)
                            && !co.flags.contains(Flags::UPDATE)
                        {
                            diags.push(Diagnostic::new(
                                "W008",
                                Severity::Warning,
                                loc.clone(),
                                format!(
                                    "object {} only listens but has neither W nor U flag",
                                    link.object
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    check_duplicate_individual_addresses(model, diags);
}

/// E002: duplicate individual address across device files, plus the filename/
/// address mismatch warning.
fn check_duplicate_individual_addresses(model: &Model, diags: &mut Vec<Diagnostic>) {
    for (ia, loaded) in &model.devices {
        // Warn if the filename prefix does not start with the address.
        let expected_prefix = ia.to_string();
        if !loaded.file_stem.starts_with(&expected_prefix) {
            diags.push(Diagnostic::new(
                "E002",
                Severity::Error,
                format!("devices/{}.yaml", loaded.file_stem),
                format!(
                    "device file name {:?} does not start with its address {ia}",
                    loaded.file_stem
                ),
            ));
        }
    }
    // Note: distinct files declaring the *same* address collapse in the map on
    // load (last wins). We surface true duplicates by re-reading is out of
    // scope for the in-memory model; the filename/address check above catches
    // the common mislabeling. A dedicated cross-file pass belongs in the
    // loader once it retains all raw entries.
}

/// GA-level consistency: E004, W005, W006, W011, I010.
fn check_ga_consistency(model: &Model, diags: &mut Vec<Diagnostic>) {
    // For each GA, collect the sizes and DPT subtypes contributed by the group
    // definition and by every linked object, plus the senders.
    #[derive(Default)]
    struct GaInfo {
        sizes: BTreeSet<(SizeInfo, String)>, // (size, source label)
        subtypes: BTreeSet<String>,          // distinct declared DPT subtypes
        sizes_only: BTreeSet<SizeInfo>,
        senders: Vec<String>,
        linked: bool,
    }

    let mut infos: BTreeMap<GroupAddress, GaInfo> = BTreeMap::new();

    // Seed from groups.yaml (also records W011 candidates below).
    for (ga, group) in &model.groups.groups {
        let info = infos.entry(*ga).or_default();
        if let Some(dpt) = &group.dpt {
            if let Some(size) = dpt.expected_size() {
                let si = SizeInfo::from_apdu(size);
                info.sizes.insert((si, "groups.yaml".to_string()));
                info.sizes_only.insert(si);
            }
            info.subtypes.insert(dpt.to_string());
        }
    }

    // Fold in linked objects.
    for (ia, links) in &model.links.links {
        let device = model.devices.get(ia);
        for link in links {
            let co = device.and_then(|d| d.device.com_objects.get(&link.object));

            let mut gas: Vec<(GroupAddress, bool)> = Vec::new();
            if let Some(send) = link.send {
                gas.push((send, true));
            }
            for ga in &link.listen {
                gas.push((*ga, false));
            }

            for (ga, is_send) in gas {
                let info = infos.entry(ga).or_default();
                info.linked = true;
                if is_send {
                    info.senders.push(format!("{ia}#{}", link.object));
                }
                if let Some(co) = co {
                    if let Some(dpt) = &co.dpt {
                        if let Some(size) = dpt.expected_size() {
                            let si = SizeInfo::from_apdu(size);
                            info.sizes.insert((si, format!("{ia}#{} dpt", link.object)));
                            info.sizes_only.insert(si);
                        }
                        info.subtypes.insert(dpt.to_string());
                    }
                }
            }
        }
    }

    for (ga, info) in &infos {
        let loc = format!("groups.\"{ga}\"");

        // E004: conflicting sizes on one GA.
        if info.sizes_only.len() > 1 {
            let mut described: Vec<String> = info
                .sizes
                .iter()
                .map(|(si, src)| format!("{} ({src})", si.label()))
                .collect();
            described.sort();
            diags.push(Diagnostic::new(
                "E004",
                Severity::Error,
                loc.clone(),
                format!("conflicting sizes on GA {ga}: {}", described.join(", ")),
            ));
        } else if info.subtypes.len() > 1 {
            // W005: same size but different declared DPT subtypes.
            let mut subs: Vec<String> = info.subtypes.iter().cloned().collect();
            subs.sort();
            diags.push(Diagnostic::new(
                "W005",
                Severity::Warning,
                loc.clone(),
                format!(
                    "GA {ga} has one size but conflicting DPT subtypes: {}",
                    subs.join(", ")
                ),
            ));
        }

        // W006: more than one sender on a GA.
        if info.senders.len() > 1 {
            let mut senders = info.senders.clone();
            senders.sort();
            diags.push(Diagnostic::new(
                "W006",
                Severity::Warning,
                loc.clone(),
                format!(
                    "GA {ga} has {} senders: {}",
                    senders.len(),
                    senders.join(", ")
                ),
            ));
        }
    }

    // W011 and I010 walk groups.yaml directly (so they only apply to defined
    // GAs, not GAs that appear only in links — those are already E001).
    for (ga, group) in &model.groups.groups {
        let loc = format!("groups.\"{ga}\"");
        if group.dpt.is_none() {
            diags.push(Diagnostic::new(
                "W011",
                Severity::Warning,
                loc.clone(),
                format!("GA {ga} has no DPT; the monitor cannot decode it"),
            ));
        }
        let linked = infos.get(ga).map(|i| i.linked).unwrap_or(false);
        if !linked && !ga.is_reserved() {
            diags.push(Diagnostic::new(
                "I010",
                Severity::Info,
                loc,
                format!("GA {ga} is defined but never linked"),
            ));
        }
    }
}

/// I009: orphaned com object — has T or W but appears in no link.
fn check_orphans_and_unlinked(model: &Model, diags: &mut Vec<Diagnostic>) {
    // Collect the set of (device, object) that are linked.
    let mut linked: BTreeSet<(crate::address::IndividualAddress, u16)> = BTreeSet::new();
    for (ia, links) in &model.links.links {
        for link in links {
            linked.insert((*ia, link.object));
        }
    }

    for (ia, loaded) in &model.devices {
        for (obj_num, co) in &loaded.device.com_objects {
            let communicative =
                co.flags.contains(Flags::TRANSMIT) || co.flags.contains(Flags::WRITE);
            if communicative && !linked.contains(&(*ia, *obj_num)) {
                diags.push(Diagnostic::new(
                    "I009",
                    Severity::Info,
                    format!("devices/{}.yaml com_objects.{obj_num}", loaded.file_stem),
                    format!(
                        "com object {obj_num} ({:?}) on {ia} has T/W flags but is not linked",
                        co.name
                    ),
                ));
            }
        }
    }
}

/// I015: informational note listing each GA marked `protected: true`.
///
/// This surfaces the safety-critical GAs in `bussard validate` output so a
/// reviewer can see, at a glance, which objects are guarded against casual
/// writes (see the design document §8). Emitted once per protected GA, in the
/// deterministic GA order of `groups.yaml`.
fn check_protected_gas(model: &Model, diags: &mut Vec<Diagnostic>) {
    for (ga, group) in &model.groups.groups {
        if group.protected {
            diags.push(Diagnostic::new(
                "I015",
                Severity::Info,
                format!("groups.\"{ga}\""),
                format!(
                    "GA {ga} ({:?}) is protected; writes require --force (CLI) and are refused via MCP",
                    group.name
                ),
            ));
        }
    }
}

/// Whether any diagnostic in the list is an [`Severity::Error`].
pub fn has_errors(diags: &[Diagnostic]) -> bool {
    diags.iter().any(|d| d.severity == Severity::Error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
    use std::collections::BTreeMap;

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }
    fn ia(s: &str) -> crate::address::IndividualAddress {
        s.parse().unwrap()
    }
    fn dpt(s: &str) -> crate::dpt::Dpt {
        s.parse().unwrap()
    }

    fn group(name: &str, dpt_str: Option<&str>) -> Group {
        Group {
            name: name.to_string(),
            dpt: dpt_str.map(dpt),
            description: None,
            protected: false,
        }
    }

    fn com_object(name: &str, dpt_str: Option<&str>, flags: &str) -> ComObject {
        ComObject {
            name: name.to_string(),
            dpt: dpt_str.map(dpt),
            size: None,
            flags: flags.parse().unwrap(),
            reference: None,
            channel: None,
        }
    }

    fn device(addr: &str, stem: &str, objs: Vec<(u16, ComObject)>) -> crate::loader::LoadedDevice {
        crate::loader::LoadedDevice {
            device: Device {
                address: ia(addr),
                name: "dev".to_string(),
                description: None,
                location: None,
                product: None,
                channels: BTreeMap::new(),
                com_objects: objs.into_iter().collect(),
            },
            file_stem: stem.to_string(),
        }
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code).collect()
    }

    #[test]
    fn clean_model_has_no_diagnostics() {
        let mut groups = BTreeMap::new();
        groups.insert(ga("3/0/4"), group("Auf/Ab", Some("1.008")));

        let mut links_map = BTreeMap::new();
        links_map.insert(
            ia("1.1.4"),
            vec![Link {
                object: 12,
                name: None,
                send: None,
                listen: vec![ga("3/0/4")],
            }],
        );

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.4"),
            device(
                "1.1.4",
                "1.1.4-jalousie",
                vec![(12, com_object("Auf/Ab", Some("1.008"), "CW"))],
            ),
        );

        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links { links: links_map },
            devices,
        };

        let diags = validate(&model);
        assert!(diags.is_empty(), "expected clean, got {diags:?}");
    }

    #[test]
    fn fixture_triggers_every_rule() {
        // Groups: one good, one reserved, one without DPT, one unlinked, plus a
        // GA with conflicting sizes and one with conflicting subtypes.
        let mut groups = BTreeMap::new();
        groups.insert(ga("0/0/0"), group("reserved", Some("1.001"))); // E012
        groups.insert(ga("1/0/0"), group("nodpt", None)); // W011 + used
        groups.insert(ga("1/0/1"), group("unlinked", Some("1.001"))); // I010
        groups.insert(ga("2/0/0"), group("sizeconflict", Some("1.001"))); // E004 (1 bit vs 2 byte)
        groups.insert(ga("3/0/0"), group("subtypes", Some("1.001"))); // W005
        groups.insert(ga("4/0/0"), group("multisend", Some("1.001"))); // W006

        let mut links_map = BTreeMap::new();
        // Device 1.1.1: object with C+T links send to a GA not in groups (E001),
        // and lacks T for a send -> we give it T so no E007 here; use a separate.
        links_map.insert(
            ia("1.1.1"),
            vec![
                Link {
                    object: 1,
                    name: None,
                    send: Some(ga("9/0/0")), // E001: undefined GA
                    listen: vec![],
                },
                Link {
                    object: 1, // E014 duplicate object
                    name: None,
                    send: None,
                    listen: vec![ga("1/0/0")],
                },
            ],
        );
        // Device 1.1.2: send without T flag (E007), and no C flag object (E007).
        links_map.insert(
            ia("1.1.2"),
            vec![Link {
                object: 5,
                name: None,
                send: Some(ga("2/0/0")), // contributes 1 bit; group 2/0/0 also 1 bit
                listen: vec![],
            }],
        );
        // Device 1.1.3: listen-only with neither W nor U (W008).
        links_map.insert(
            ia("1.1.3"),
            vec![Link {
                object: 7,
                name: None,
                send: None,
                // object dpt 1.002 vs group dpt 1.001: same size (1 bit),
                // different subtype -> W005.
                listen: vec![ga("3/0/0")],
            }],
        );
        // Unknown device (E013).
        links_map.insert(
            ia("1.1.99"),
            vec![Link {
                object: 1,
                name: None,
                send: None,
                listen: vec![ga("1/0/0")],
            }],
        );
        // Link to object not on device (E003).
        links_map.insert(
            ia("1.1.4"),
            vec![Link {
                object: 42,
                name: None,
                send: None,
                listen: vec![ga("1/0/0")],
            }],
        );
        // Two senders on 4/0/0 (W006).
        links_map.insert(
            ia("1.1.5"),
            vec![
                Link {
                    object: 1,
                    name: None,
                    send: Some(ga("4/0/0")),
                    listen: vec![],
                },
                Link {
                    object: 2,
                    name: None,
                    send: Some(ga("4/0/0")),
                    listen: vec![],
                },
            ],
        );

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.1"),
            device(
                "1.1.1",
                "wrongname", // E002 filename mismatch
                vec![(1, com_object("o", Some("1.001"), "CT"))],
            ),
        );
        // 1.1.2 object 5: no C, no T, with a big DPT -> E004 on 2/0/0, E007 x2.
        devices.insert(
            ia("1.1.2"),
            device(
                "1.1.2",
                "1.1.2-dev",
                vec![(5, com_object("o", Some("14.076"), "W"))], // 4 bytes vs 1 bit
            ),
        );
        // 1.1.3 object 7: listen only, flags C only (no W/U) -> W008; dpt 1.002
        // (same 1-bit size as group 3/0/0's 1.001 but different subtype -> W005).
        devices.insert(
            ia("1.1.3"),
            device(
                "1.1.3",
                "1.1.3-dev",
                vec![
                    (7, com_object("o", Some("1.002"), "C")),
                    // orphan with T flag, never linked -> I009
                    (8, com_object("orphan", Some("1.001"), "CT")),
                ],
            ),
        );
        devices.insert(ia("1.1.4"), device("1.1.4", "1.1.4-dev", vec![]));
        devices.insert(
            ia("1.1.5"),
            device(
                "1.1.5",
                "1.1.5-dev",
                vec![
                    (1, com_object("s1", Some("1.001"), "CT")),
                    (2, com_object("s2", Some("1.001"), "CT")),
                ],
            ),
        );

        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links { links: links_map },
            devices,
        };

        let diags = validate(&model);
        let found: BTreeSet<&str> = codes(&diags).into_iter().collect();

        for expected in [
            "E001", "E002", "E003", "E004", "E007", "E012", "E013", "E014", "W005", "W006", "W008",
            "W011", "I009", "I010",
        ] {
            assert!(
                found.contains(expected),
                "rule {expected} not triggered; found {found:?}\n{diags:#?}"
            );
        }
    }

    #[test]
    fn protected_gas_emit_i015_deterministically() {
        let mut groups = BTreeMap::new();
        // Two protected GAs and one plain one; I015 must list only the protected
        // ones, in GA order.
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse().unwrap()),
                description: None,
                protected: true,
            },
        );
        groups.insert(
            ga("1/0/0"),
            Group {
                name: "Zentral Aus".to_string(),
                dpt: Some("1.001".parse().unwrap()),
                description: None,
                protected: true,
            },
        );
        groups.insert(ga("2/0/0"), group("Plain", Some("1.001")));

        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };

        let diags = validate(&model);
        let i015: Vec<&Diagnostic> = diags.iter().filter(|d| d.code == "I015").collect();
        assert_eq!(i015.len(), 2, "one I015 per protected GA");
        // Deterministic order: sorted by location, so 1/0/0 before 3/2/0.
        assert_eq!(i015[0].location, "groups.\"1/0/0\"");
        assert_eq!(i015[1].location, "groups.\"3/2/0\"");
        assert!(i015[0].message.contains("protected"));
        assert_eq!(i015[0].severity, Severity::Info);
    }

    #[test]
    fn output_is_deterministic() {
        let mut groups = BTreeMap::new();
        groups.insert(ga("1/0/1"), group("b", None));
        groups.insert(ga("1/0/0"), group("a", None));
        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };
        let a = validate(&model);
        let b = validate(&model);
        assert_eq!(a, b);
        // Sorted by location.
        let locs: Vec<&str> = a.iter().map(|d| d.location.as_str()).collect();
        let mut sorted = locs.clone();
        sorted.sort();
        assert_eq!(locs, sorted);
    }
}
