//! Model validation.
//!
//! [`validate`] runs every rule from the design document (§5.3) over a loaded
//! [`Model`] and returns a deterministically ordered list of [`Diagnostic`]s.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use std::path::Path;

use crate::address::GroupAddress;
use crate::dpt::ApduSize;
use crate::flags::Flags;
use crate::loader::Model;
use crate::param_model::{ParamKind, ProductModels, key_to_param_id};

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
    /// Builds a diagnostic. Crate-internal so every rule pass (including the
    /// opt-in lints in [`crate::lint`]) constructs them the same way.
    pub(crate) fn new(
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
    // Opt-in topology/convention lints (issue #102). Without a `[lint]` table in
    // `bussard.toml` this contributes nothing, so existing models are unchanged.
    // The bus-current rule (L002) needs the on-disk product cache and therefore
    // only runs from `validate_in_dir`.
    diags.extend(crate::lint::lint(model, None));

    diags.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
    diags
}

/// Validates a model together with its on-disk directory, so device parameter
/// values can be checked against the generated product models under
/// `<dir>/models/`.
///
/// This runs every rule [`validate`] runs, plus the parameter rules (E016 /
/// E017 / I017 / E026 — unknown key, bad value, redundant value, no model) and
/// the rules that need the files themselves (E020–E023: duplicates, a missing
/// or stale lock entry, keys the lock does not know), which report
/// `file:line:column`. The product models are read lazily and only here; a
/// device whose application has no model file yields a warning rather than a
/// hard error, since `models/` is local-only vendor-derived data that is
/// frequently absent.
pub fn validate_in_dir(model: &Model, dir: &Path) -> Vec<Diagnostic> {
    let mut diags = crate::file_checks::check_dir(dir);

    check_reserved_gas(model, &mut diags);
    check_links(model, &mut diags);
    check_ga_consistency(model, &mut diags);
    check_orphans_and_unlinked(model, &mut diags);
    check_protected_gas(model, &mut diags);

    let models = ProductModels::load(dir);
    check_parameters(model, &models, &mut diags);
    // Opt-in lints, with the product cache so L002 can total the bus current.
    diags.extend(crate::lint::lint(model, Some(&models)));

    diags.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
    diags
}

/// Parameter rules (issue #46), run only by [`validate_in_dir`] since they need
/// the on-disk `models/`:
///
/// * **E026** — a device carries parameters but its application has no model
///   file under `models/`, so its values cannot be normalized or checked
///   (warning).
/// * **E016** — a parameter key names a parameter absent from the model (a typo
///   or a stale key after a re-import that dropped the parameter).
/// * **E017** — a value is not parseable for its type, is out of the declared
///   range, or is not a declared enumeration member.
/// * **I017** — a value equals the vendor default and is therefore redundant
///   (the importer omits these, but a hand edit can reintroduce one).
fn check_parameters(model: &Model, models: &ProductModels, diags: &mut Vec<Diagnostic>) {
    for (ia, loaded) in &model.devices {
        let dev = &loaded.device;
        if dev.parameters.is_empty() {
            continue;
        }
        let file = format!("devices/{}.toml", loaded.file_stem);
        let app_ref = dev
            .product
            .as_ref()
            .and_then(|p| p.application_ref.as_deref());

        // Locate the product model for this device's application.
        let product_model = app_ref.and_then(|r| models.get(r));
        let Some(product_model) = product_model else {
            let reason = match app_ref {
                Some(r) => format!("no model for {r}"),
                None => "the lock pins no application for the device".to_string(),
            };
            diags.push(Diagnostic::new(
                "E026",
                Severity::Warning,
                format!("{file} parameters"),
                format!(
                    "{} parameter value(s) on {ia} could not be normalized or checked ({reason}); \
                     run `bussard import-product` to fetch the product model",
                    dev.parameters.len()
                ),
            ));
            continue;
        };

        for (key, value) in &dev.parameters {
            let loc = format!("{file} parameters.{key:?}");

            let Some(param_id) = key_to_param_id(key) else {
                diags.push(Diagnostic::new(
                    "E016",
                    Severity::Error,
                    loc,
                    format!("parameter key {key:?} is malformed (expected `<name>@<ref-id>`)"),
                ));
                continue;
            };

            let Some(def) = product_model.parameters.get(&param_id) else {
                diags.push(Diagnostic::new(
                    "E016",
                    Severity::Error,
                    loc,
                    format!(
                        "unknown parameter {param_id:?} (from key {key:?}) — not in the model for {}",
                        app_ref.unwrap_or("?")
                    ),
                ));
                continue;
            };

            if let Some(reason) = value_error(&def.kind, value) {
                diags.push(Diagnostic::new(
                    "E017",
                    Severity::Error,
                    loc.clone(),
                    reason,
                ));
                continue;
            }

            if def.default.as_deref() == Some(value.as_str()) {
                diags.push(Diagnostic::new(
                    "I017",
                    Severity::Info,
                    loc,
                    format!("value {value:?} equals the vendor default (redundant)"),
                ));
            }
        }
    }
}

/// Checks a parameter value against its definition, returning the reason it is
/// unacceptable, or `None` when it is fine.
///
/// The public face of the `E017` rule, so a caller that wants to reject a bad
/// value *before* writing it (the MCP `knx_set_parameter` tool) uses exactly the
/// same check the validator applies afterwards.
pub fn parameter_value_error(kind: &ParamKind, value: &str) -> Option<String> {
    value_error(kind, value)
}

/// Checks a value against a parameter kind, returning an error message if it is
/// unparseable, out of range, or not a declared enum member; `None` if valid.
fn value_error(kind: &ParamKind, value: &str) -> Option<String> {
    let v = value.trim();
    match kind {
        ParamKind::Int { min, max, signed } => {
            let Ok(n) = v.parse::<i64>() else {
                return Some(format!("value {value:?} is not an integer"));
            };
            if !*signed && n < 0 {
                return Some(format!("value {n} is negative for an unsigned parameter"));
            }
            if let Some(lo) = min
                && n < *lo
            {
                return Some(format!("value {n} is below the minimum {lo}"));
            }
            if let Some(hi) = max
                && n > *hi
            {
                return Some(format!("value {n} is above the maximum {hi}"));
            }
            None
        }
        ParamKind::Enum { values } => match v.parse::<i64>() {
            Ok(n) => {
                if values.is_empty() || values.contains(&n) {
                    None
                } else {
                    let list: Vec<String> = values.iter().map(|x| x.to_string()).collect();
                    Some(format!(
                        "value {n} is not a declared enum member (allowed: {})",
                        list.join(", ")
                    ))
                }
            }
            Err(_) => Some(format!("enum value {value:?} is not an integer")),
        },
        ParamKind::Text { len } => match len {
            Some(len) if value.len() > *len => Some(format!(
                "text {value:?} is {} bytes but the field holds {len}",
                value.len()
            )),
            _ => None,
        },
        ParamKind::Float => {
            if v.parse::<f64>().is_ok() {
                None
            } else {
                Some(format!("value {value:?} is not a number"))
            }
        }
        // No declared constraints to check.
        ParamKind::None | ParamKind::Other => None,
    }
}

/// E012: invalid/reserved GA (`0/0/0`) that is referenced in the model.
fn check_reserved_gas(model: &Model, diags: &mut Vec<Diagnostic>) {
    // Defined in groups.toml.
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

/// Rules that walk over the links: E001 (warning), E003, E007, E013, E024,
/// E025, and the duplicate-object-within-a-device error.
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

            // E001: referenced GA not defined in groups.toml. A warning: import,
            // apply and the MCP edit tools add such a GA to the plan.
            for (ga, role) in &refs {
                if !model.groups.groups.contains_key(ga) {
                    diags.push(Diagnostic::new(
                        "E001",
                        Severity::Warning,
                        loc.clone(),
                        format!("{role} GA {ga} is not defined in groups.toml"),
                    ));
                }
            }

            // Rules needing the device's com object.
            if let Some(loaded) = device {
                match loaded.device.com_objects.get(&link.object) {
                    // A device with no com-object table at all (adopted or
                    // imported without product data) cannot have its links
                    // checked; that is a gap to fill, not a contradiction.
                    None if loaded.device.com_objects.is_empty() => {
                        diags.push(Diagnostic::new(
                            "E003",
                            Severity::Warning,
                            loc.clone(),
                            format!(
                                "object {} cannot be checked: device {ia} has no com-object \
                                 table (no product data; `bussard import-product` or a \
                                 re-import adds it)",
                                link.object
                            ),
                        ));
                    }
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
                        // E025: `send` on an object without the T flag.
                        if link.send.is_some() && !co.flags.contains(Flags::TRANSMIT) {
                            diags.push(Diagnostic::new(
                                "E025",
                                Severity::Error,
                                loc.clone(),
                                format!(
                                    "object {} has a send GA but lacks the T (transmit) flag",
                                    link.object
                                ),
                            ));
                        }
                        // E025: `listen` on an object without the W flag.
                        if !link.listen.is_empty() && !co.flags.contains(Flags::WRITE) {
                            diags.push(Diagnostic::new(
                                "E025",
                                Severity::Error,
                                loc.clone(),
                                format!(
                                    "object {} has listen GAs but lacks the W (write) flag",
                                    link.object
                                ),
                            ));
                        }
                        // E024: the object's DPT is of another main type than
                        // the GA's.
                        if let Some(odpt) = &co.dpt {
                            for (ga, _) in &refs {
                                let gdpt = model.groups.groups.get(*ga).and_then(|g| g.dpt);
                                if let Some(gdpt) = gdpt
                                    && gdpt.main != odpt.main
                                {
                                    diags.push(Diagnostic::new(
                                        "E024",
                                        Severity::Error,
                                        loc.clone(),
                                        format!(
                                            "object {} is DPT {odpt} but GA {ga} is DPT {gdpt}",
                                            link.object
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    check_duplicate_individual_addresses(model, diags);
}

/// E002: a device file whose name is not its address.
fn check_duplicate_individual_addresses(model: &Model, diags: &mut Vec<Diagnostic>) {
    for (ia, loaded) in &model.devices {
        // The file must be named `<address>.toml`.
        let expected = ia.to_string();
        if loaded.file_stem != expected {
            diags.push(Diagnostic::new(
                "E002",
                Severity::Error,
                format!("devices/{}.toml", loaded.file_stem),
                format!(
                    "device file name {:?} does not match its address {ia}; rename it to \
                     devices/{ia}.toml",
                    loaded.file_stem
                ),
            ));
        }
    }
    // Two files declaring one address are a load error (the loader names both).
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

    // Seed from groups.toml (also records W011 candidates below).
    for (ga, group) in &model.groups.groups {
        let info = infos.entry(*ga).or_default();
        if let Some(dpt) = &group.dpt {
            if let Some(size) = dpt.expected_size() {
                let si = SizeInfo::from_apdu(size);
                info.sizes.insert((si, "groups.toml".to_string()));
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
                if let Some(co) = co
                    && let Some(dpt) = &co.dpt
                {
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

    // W011 and I010 walk groups.toml directly (so they only apply to defined
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
                    format!("devices/{}.toml object {obj_num}", loaded.file_stem),
                    format!("com object {obj_num} on {ia} has T/W flags but is not linked"),
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
/// deterministic GA order of `groups.toml`.
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
        s.parse().expect("test fixture")
    }
    fn ia(s: &str) -> crate::address::IndividualAddress {
        s.parse().expect("test fixture")
    }
    fn dpt(s: &str) -> crate::dpt::Dpt {
        s.parse().expect("test fixture")
    }

    fn group(name: &str, dpt_str: Option<&str>) -> Group {
        Group {
            name: name.to_string(),
            dpt: dpt_str.map(dpt),
            description: None,
            protected: false,
            secure: false,
        }
    }

    // `_name` is kept for call-site readability; the name now lives in
    // the device files' links, not on the com-object (issue #19).
    fn com_object(_name: &str, dpt_str: Option<&str>, flags: &str) -> ComObject {
        ComObject {
            dpt: dpt_str.map(dpt),
            size: None,
            flags: flags.parse().expect("test fixture"),
            reference: None,
            channel: None,
            secure: false,
            function: None,
            key: None,
            text: None,
        }
    }

    fn device(addr: &str, stem: &str, objs: Vec<(u16, ComObject)>) -> crate::loader::LoadedDevice {
        crate::loader::LoadedDevice {
            device: Device {
                address: ia(addr),
                name: "dev".to_string(),
                description: None,
                location: None,
                replaced: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: BTreeMap::new(),
                com_objects: objs.into_iter().collect(),
                security: None,
                application_override: None,
                lock: Default::default(),
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
                "1.1.4",
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
        // Device 1.1.2: send without T flag (E025), no C flag object (E007), and
        // a 14.x object on a 1.x GA (E024).
        links_map.insert(
            ia("1.1.2"),
            vec![Link {
                object: 5,
                name: None,
                send: Some(ga("2/0/0")), // contributes 1 bit; group 2/0/0 also 1 bit
                listen: vec![],
            }],
        );
        // Device 1.1.3: listens without the W flag (E025).
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
        // 1.1.2 object 5: no C, no T, with a big DPT -> E004 and E024 on 2/0/0,
        // E007 (no C) and E025 (send without T).
        devices.insert(
            ia("1.1.2"),
            device(
                "1.1.2",
                "1.1.2",
                vec![(5, com_object("o", Some("14.076"), "W"))], // 4 bytes vs 1 bit
            ),
        );
        // 1.1.3 object 7: listen only, flags C only (no W) -> E025; dpt 1.002
        // (same 1-bit size as group 3/0/0's 1.001 but different subtype -> W005).
        devices.insert(
            ia("1.1.3"),
            device(
                "1.1.3",
                "1.1.3",
                vec![
                    (7, com_object("o", Some("1.002"), "C")),
                    // orphan with T flag, never linked -> I009
                    (8, com_object("orphan", Some("1.001"), "CT")),
                ],
            ),
        );
        devices.insert(ia("1.1.4"), device("1.1.4", "1.1.4", vec![]));
        devices.insert(
            ia("1.1.5"),
            device(
                "1.1.5",
                "1.1.5",
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

        assert!(
            diags
                .iter()
                .filter(|d| d.code == "E001")
                .all(|d| d.severity == Severity::Warning),
            "an undeclared GA is a warning: {diags:#?}"
        );
        for expected in [
            "E001", "E002", "E003", "E004", "E007", "E012", "E013", "E014", "E024", "E025", "W005",
            "W006", "W011", "I009", "I010",
        ] {
            assert!(
                found.contains(expected),
                "rule {expected} not triggered; found {found:?}\n{diags:#?}"
            );
        }
    }

    #[test]
    fn protected_gas_emit_i015_deterministically() -> Result<(), Box<dyn std::error::Error>> {
        let mut groups = BTreeMap::new();
        // Two protected GAs and one plain one; I015 must list only the protected
        // ones, in GA order.
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse()?),
                description: None,
                protected: true,
                secure: false,
            },
        );
        groups.insert(
            ga("1/0/0"),
            Group {
                name: "Zentral Aus".to_string(),
                dpt: Some("1.001".parse()?),
                description: None,
                protected: true,
                secure: false,
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
        Ok(())
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

    // ---- Parameter validation (issue #46) ----------------------------------

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bussard-validate-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test fixture")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test fixture");
        dir
    }

    const APP_REF: &str = "M-00FA_A-1";

    /// A model with one device whose parameter map is `params`, plus a
    /// product identity pointing at `APP_REF`.
    fn model_with_params(params: &[(&str, &str)]) -> Model {
        let mut parameters = BTreeMap::new();
        for (k, v) in params {
            parameters.insert(k.to_string(), v.to_string());
        }
        let device = Device {
            address: ia("1.1.4"),
            name: "dev".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: Some(Product {
                manufacturer: None,
                manufacturer_ref: None,
                order_number: None,
                hardware_ref: None,
                application_ref: Some(APP_REF.to_string()),
                mask: None,
            }),
            channels: BTreeMap::new(),
            parameters,
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            security: None,
            application_override: None,
            lock: Default::default(),
        };
        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.4"),
            crate::loader::LoadedDevice {
                device,
                file_stem: "1.1.4".to_string(),
            },
        );
        Model {
            config: BussardConfig::default(),
            groups: Groups::default(),
            links: Links {
                links: BTreeMap::new(),
            },
            devices,
        }
    }

    /// Writes `models/<APP_REF>.yaml` with an int (`MD-1_P-3`, 0..=3), an enum
    /// (`P-9`, {0,7}) and a text (`P-20`, 6 bytes) parameter.
    fn write_model(dir: &std::path::Path) {
        let models = dir.join("models");
        std::fs::create_dir_all(&models).expect("test fixture");
        let yaml = "\
identity:
  id: M-00FA_A-1
parameters:
  - id: M-00FA_A-1_MD-1_P-3
    type: !int
      min: 0
      max: 3
    default: '0'
  - id: M-00FA_A-1_P-9
    type: !enum
      values:
        - value: 0
          text: Off
        - value: 7
          text: On
    default: '0'
  - id: M-00FA_A-1_P-20
    type: !text
      size: 48
";
        std::fs::write(models.join(format!("{APP_REF}.yaml")), yaml).expect("test fixture");
    }

    fn codes_at<'a>(diags: &'a [Diagnostic], key_frag: &str) -> Vec<(&'a str, Severity)> {
        diags
            .iter()
            .filter(|d| d.location.contains(key_frag))
            .map(|d| (d.code, d.severity))
            .collect()
    }

    #[test]
    fn parameters_no_model_yields_warning_e026() {
        // No models/ directory: a device with parameters gets an E026 warning
        // (the values could not be normalized or checked).
        let dir = tmp_dir("no-model");
        let model = model_with_params(&[("windalarm@MD-1_M-3_MI-1_P-3_R-5", "1")]);
        let diags = validate_in_dir(&model, &dir);
        let e026: Vec<_> = diags.iter().filter(|d| d.code == "E026").collect();
        assert_eq!(e026.len(), 1, "{diags:#?}");
        assert_eq!(e026[0].severity, Severity::Warning);
        assert!(e026[0].message.contains("no model"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parameters_valid_values_are_clean() {
        let dir = tmp_dir("clean");
        write_model(&dir);
        // In-range int, valid enum member, in-length text — all non-default.
        let model = model_with_params(&[
            ("windalarm@MD-1_M-3_MI-1_P-3_R-5", "2"),
            ("mode@P-9_R-1", "7"),
            ("label@P-20_R-1", "Hi"),
        ]);
        let diags = validate_in_dir(&model, &dir);
        assert!(
            diags.iter().all(|d| d.severity != Severity::Error),
            "unexpected errors: {diags:#?}"
        );
        assert!(
            !diags.iter().any(|d| d.code == "I017"),
            "no redundant notes: {diags:#?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parameters_flag_unknown_out_of_range_enum_and_redundant() {
        let dir = tmp_dir("bad");
        write_model(&dir);
        let model = model_with_params(&[
            // E016: names a parameter absent from the model.
            ("bogus@MD-9_M-1_MI-1_P-99_R-1", "1"),
            // E017: int above the declared maximum (3).
            ("windalarm@MD-1_M-3_MI-1_P-3_R-5", "9"),
            // E017: value not a declared enum member.
            ("mode@P-9_R-1", "3"),
            // I017: equals the vendor default '0'.
            ("redundant@MD-1_M-3_MI-1_P-3_R-8", "0"),
        ]);
        let diags = validate_in_dir(&model, &dir);

        assert_eq!(codes_at(&diags, "bogus@")[0].0, "E016");
        assert_eq!(codes_at(&diags, "windalarm@")[0], ("E017", Severity::Error));
        assert_eq!(codes_at(&diags, "mode@")[0], ("E017", Severity::Error));
        assert_eq!(codes_at(&diags, "redundant@")[0], ("I017", Severity::Info));
        assert!(has_errors(&diags));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parameters_malformed_key_is_e016() {
        let dir = tmp_dir("malformed");
        write_model(&dir);
        // Key with no `@`/ref suffix cannot resolve to a parameter id.
        let model = model_with_params(&[("noatsign", "1")]);
        let diags = validate_in_dir(&model, &dir);
        let e016: Vec<_> = diags.iter().filter(|d| d.code == "E016").collect();
        assert_eq!(e016.len(), 1, "{diags:#?}");
        assert!(e016[0].message.contains("malformed"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
