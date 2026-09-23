//! Topology and convention lints (issue #102).
//!
//! [`crate::validate`] checks that the YAML is structurally sound. It knows
//! nothing about the rules an integrator plans by: how many devices a line may
//! carry, how much bus current a power supply can deliver, or which group
//! address a given function is supposed to live at. Those rules are project
//! policy, not KNX law, so they are **opt-in**: nothing here fires until a
//! `lint:` block appears in `bussard.yaml`.
//!
//! ```yaml
//! lint:
//!   topology:
//!     max_devices_per_line: 64
//!     supply_ma: { "1.1": 640 }
//!   groups:
//!     scheme: floor-trade-block    # or function-floor
//!     blocks: { light: 5, blind: 10, heating: 10 }
//!     feedback_pairing: true
//!     name_pattern: "* * *"
//! ```
//!
//! Every finding is a warning with an `L0xx` code (see `docs/reference.md`).
//! The convention lints read the same block and role tables the scaffolder
//! writes ([`crate::scaffold`]), so `bussard scaffold` output is clean by
//! construction.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::Model;
use crate::param_model::ProductModels;
use crate::scaffold::{Scheme, TradeSpec, trade_by_index};
use crate::validate::{Diagnostic, Severity};

/// The `lint:` block of `bussard.yaml`. Absent means no lints run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LintConfig {
    /// Topology limits (devices per line, bus current, line membership).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<TopologyLint>,
    /// Group-address convention rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<GroupsLint>,
}

/// The `lint.topology` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TopologyLint {
    /// The most devices one line may carry (the KNX TP limit is 64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_devices_per_line: Option<usize>,
    /// The bus current each line's power supply delivers, in mA, keyed by line
    /// (`"1.1"`). Declaring a line here also declares that the line exists.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub supply_ma: BTreeMap<String, u32>,
}

/// The `lint.groups` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GroupsLint {
    /// The addressing scheme the project follows. Without it, the convention
    /// lints cannot tell which level carries the trade, so they do not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
    /// How many consecutive sub addresses each trade reserves per room, keyed by
    /// trade (`light`, `blind`, `heating`, `socket`). A trade that is absent is
    /// not part of this project's plan.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blocks: BTreeMap<String, u8>,
    /// Require a feedback address for every command address that has one in the
    /// block layout.
    #[serde(default)]
    pub feedback_pairing: bool,
    /// A glob every group-address name must match. `*` matches any run of
    /// characters (including none), `?` exactly one; everything else is literal.
    /// `"* * *"` therefore means "at least three space-separated parts".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_pattern: Option<String>,
}

/// Runs the opt-in lints over a model.
///
/// Returns an empty list when `bussard.yaml` has no `lint:` block. `models` is
/// the product cache; without it the bus-current lint (`L002`) is skipped, since
/// the per-device current lives only in the generated `models/*.yaml`.
pub fn lint(model: &Model, models: Option<&ProductModels>) -> Vec<Diagnostic> {
    let Some(config) = &model.config.lint else {
        return Vec::new();
    };
    let mut diags = Vec::new();
    if let Some(topology) = &config.topology {
        check_topology(model, topology, models, &mut diags);
    }
    if let Some(groups) = &config.groups {
        check_conventions(model, groups, &mut diags);
    }
    diags
}

/// A device's line, as the `"a.l"` string `supply_ma` is keyed by.
fn line_of(ia: IndividualAddress) -> String {
    format!("{}.{}", ia.area(), ia.line())
}

/// Topology rules: `L001` devices per line, `L002` bus current against the
/// declared supply, `L003` a device on a line the config does not declare, and
/// `L004` a Secure device behind a coupler that is not Secure-capable.
fn check_topology(
    model: &Model,
    config: &TopologyLint,
    models: Option<&ProductModels>,
    diags: &mut Vec<Diagnostic>,
) {
    // Group devices by line, preserving address order within a line.
    let mut by_line: BTreeMap<String, Vec<IndividualAddress>> = BTreeMap::new();
    for ia in model.devices.keys() {
        by_line.entry(line_of(*ia)).or_default().push(*ia);
    }

    if let Some(max) = config.max_devices_per_line {
        for (line, devices) in &by_line {
            if devices.len() > max {
                diags.push(Diagnostic::new(
                    "L001",
                    Severity::Warning,
                    format!("line {line}"),
                    format!(
                        "{} devices on line {line}, over the configured limit of {max} \
                         (split the line or add a coupler)",
                        devices.len()
                    ),
                ));
            }
        }
    }

    if !config.supply_ma.is_empty() {
        for (line, devices) in &by_line {
            if !config.supply_ma.contains_key(line) {
                for ia in devices {
                    diags.push(Diagnostic::new(
                        "L003",
                        Severity::Warning,
                        format!("devices \"{ia}\""),
                        format!(
                            "{ia} sits on line {line}, which lint.topology.supply_ma does not \
                             declare (a typo in the address, or a line missing from the config)"
                        ),
                    ));
                }
            }
        }
    }

    if let Some(models) = models {
        check_bus_current(model, config, models, &by_line, diags);
    }

    check_secure_couplers(model, diags);
}

/// `L002`: the summed bus current of a line's devices against its supply.
fn check_bus_current(
    model: &Model,
    config: &TopologyLint,
    models: &ProductModels,
    by_line: &BTreeMap<String, Vec<IndividualAddress>>,
    diags: &mut Vec<Diagnostic>,
) {
    for (line, supply) in &config.supply_ma {
        let Some(devices) = by_line.get(line) else {
            continue;
        };
        let mut total: u32 = 0;
        let mut unknown = 0usize;
        for ia in devices {
            let current = model
                .devices
                .get(ia)
                .and_then(|d| d.device.product.as_ref())
                .and_then(|p| p.application_ref.as_deref())
                .and_then(|app| models.get(app))
                .and_then(|m| m.bus_current_ma);
            match current {
                Some(ma) => total += ma,
                None => unknown += 1,
            }
        }
        if total > *supply {
            let note = if unknown > 0 {
                format!(
                    " ({unknown} device(s) have no cached product data, so the real draw is higher)"
                )
            } else {
                String::new()
            };
            diags.push(Diagnostic::new(
                "L002",
                Severity::Warning,
                format!("line {line}"),
                format!("line {line} draws {total} mA from a {supply} mA supply{note}"),
            ));
        }
    }
}

/// `L004`: a Secure-capable device behind a line coupler that is not itself
/// Secure-capable. Only checked where the model actually knows the coupler (a
/// device at `<area>.<line>.0`); otherwise there is nothing to compare against.
fn check_secure_couplers(model: &Model, diags: &mut Vec<Diagnostic>) {
    for (ia, loaded) in &model.devices {
        if ia.device() == 0 {
            continue;
        }
        let secure = loaded
            .device
            .security
            .as_ref()
            .is_some_and(|s| s.secure_capable || s.activated);
        if !secure {
            continue;
        }
        let Ok(coupler_ia) = IndividualAddress::new(ia.area(), ia.line(), 0) else {
            continue;
        };
        let Some(coupler) = model.devices.get(&coupler_ia) else {
            continue;
        };
        let coupler_secure = coupler
            .device
            .security
            .as_ref()
            .is_some_and(|s| s.secure_capable || s.activated);
        if !coupler_secure {
            diags.push(Diagnostic::new(
                "L004",
                Severity::Warning,
                format!("devices \"{ia}\""),
                format!(
                    "{ia} is KNX Secure but its line coupler {coupler_ia} is not Secure-capable; \
                     secured traffic cannot cross it"
                ),
            ));
        }
    }
}

/// The block a group address falls in, under a scheme and a block table.
struct Block {
    spec: &'static TradeSpec,
    size: u8,
    start: u8,
    offset: u8,
}

/// Resolves a group address to its trade block, or `None` when its trade is not
/// part of the configured plan.
fn block_of(ga: GroupAddress, scheme: Scheme, blocks: &BTreeMap<String, u8>) -> Option<Block> {
    let (_, trade_index) = scheme.split(ga);
    let spec = trade_by_index(trade_index)?;
    let size = *blocks.get(spec.key)?;
    if size == 0 {
        return None;
    }
    let offset = ga.sub() % size;
    Some(Block {
        spec,
        size,
        start: ga.sub() - offset,
        offset,
    })
}

/// Convention rules: `L005` a GA outside any declared block, `L006` a missing
/// feedback address, `L007` a name that does not match the pattern, and `L008` a
/// DPT that contradicts the role the address sits on.
fn check_conventions(model: &Model, config: &GroupsLint, diags: &mut Vec<Diagnostic>) {
    if let Some(pattern) = &config.name_pattern {
        for (ga, group) in &model.groups.groups {
            if !glob_match(pattern, &group.name) {
                diags.push(Diagnostic::new(
                    "L007",
                    Severity::Warning,
                    format!("groups.\"{ga}\""),
                    format!(
                        "name {:?} does not match the project naming pattern {pattern:?}",
                        group.name
                    ),
                ));
            }
        }
    }

    let Some(scheme) = config.scheme else {
        return;
    };
    if config.blocks.is_empty() {
        return;
    }

    // Blocks that carry at least one address, so the pairing check knows which
    // blocks are actually in use.
    let mut used: BTreeSet<(u8, u8, u8)> = BTreeSet::new();

    for (ga, group) in &model.groups.groups {
        let Some(block) = block_of(*ga, scheme, &config.blocks) else {
            diags.push(Diagnostic::new(
                "L005",
                Severity::Warning,
                format!("groups.\"{ga}\""),
                format!(
                    "{ga} is outside every block declared in lint.groups.blocks \
                     (no trade is addressed at that level under the {scheme} scheme)"
                ),
            ));
            continue;
        };
        used.insert((ga.main(), ga.middle(), block.start));

        let Some(role) = block.spec.role(block.offset) else {
            continue;
        };
        if let Some(dpt) = group.dpt {
            if dpt.main != role.dpt_main {
                diags.push(Diagnostic::new(
                    "L008",
                    Severity::Warning,
                    format!("groups.\"{ga}\""),
                    format!(
                        "offset {} of a {} block is the \"{}\" role (DPT {}), but this address is \
                         DPT {dpt}",
                        block.offset,
                        block.spec.key,
                        role.label,
                        role.dpt()
                    ),
                ));
            }
        }
    }

    if config.feedback_pairing {
        for (main, middle, start) in used {
            let Ok(probe) = GroupAddress::new(main, middle, start) else {
                continue;
            };
            let Some(block) = block_of(probe, scheme, &config.blocks) else {
                continue;
            };
            for role in block.spec.roles {
                let Some(command_offset) = role.status_of else {
                    continue;
                };
                if role.offset >= block.size || command_offset >= block.size {
                    continue;
                }
                let (Some(command_sub), Some(status_sub)) = (
                    start.checked_add(command_offset),
                    start.checked_add(role.offset),
                ) else {
                    continue;
                };
                let (Ok(command), Ok(status)) = (
                    GroupAddress::new(main, middle, command_sub),
                    GroupAddress::new(main, middle, status_sub),
                ) else {
                    continue;
                };
                if model.groups.groups.contains_key(&command)
                    && !model.groups.groups.contains_key(&status)
                {
                    diags.push(Diagnostic::new(
                        "L006",
                        Severity::Warning,
                        format!("groups.\"{command}\""),
                        format!(
                            "{command} has no feedback address; the {} block reserves {status} \
                             for its \"{}\" role",
                            block.spec.key, role.label
                        ),
                    ));
                }
            }
        }
    }
}

/// Matches `text` against a glob of `*` (any run, possibly empty) and `?` (one
/// character). Everything else is literal. No regex crate, no backtracking blow-up.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            resume = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BussardConfig, Group, Groups};

    fn model_with(config: LintConfig, groups: Groups) -> Model {
        Model {
            config: BussardConfig {
                connection: Default::default(),
                lint: Some(config),
            },
            groups,
            links: Default::default(),
            devices: Default::default(),
        }
    }

    fn groups_from(entries: &[(&str, &str, Option<&str>)]) -> Groups {
        let mut groups = Groups::default();
        for (ga, name, dpt) in entries {
            let address: GroupAddress = ga.parse().expect("test GA parses");
            groups.groups.insert(
                address,
                Group {
                    name: (*name).to_string(),
                    dpt: dpt.map(|d| d.parse().expect("test DPT parses")),
                    description: None,
                    protected: false,
                    secure: false,
                },
            );
        }
        groups
    }

    fn convention_config() -> LintConfig {
        LintConfig {
            topology: None,
            groups: Some(GroupsLint {
                scheme: Some(Scheme::FloorTradeBlock),
                blocks: BTreeMap::from([("light".to_string(), 5u8)]),
                feedback_pairing: true,
                name_pattern: None,
            }),
        }
    }

    #[test]
    fn test_lint_without_a_config_block_is_silent() {
        let model = Model {
            config: BussardConfig::default(),
            groups: groups_from(&[("7/7/200", "x", Some("9.001"))]),
            links: Default::default(),
            devices: Default::default(),
        };
        assert!(lint(&model, None).is_empty());
    }

    #[test]
    fn test_glob_match_semantics() {
        assert!(glob_match("* * *", "Ground floor Kitchen Light Switch"));
        assert!(!glob_match("* * *", "Kitchen Light"));
        assert!(glob_match("*", ""));
        assert!(glob_match("EG ?", "EG A"));
        assert!(!glob_match("EG ?", "EG AB"));
        assert!(glob_match("Licht*", "Licht Küche"));
    }

    #[test]
    fn test_l005_flags_a_ga_outside_every_declared_block() {
        // Middle 6 is not a trade index that the block table declares.
        let model = model_with(
            convention_config(),
            groups_from(&[("1/6/0", "Stray", Some("1.001"))]),
        );
        let codes: Vec<&str> = lint(&model, None).iter().map(|d| d.code).collect();
        assert_eq!(codes, vec!["L005"]);
    }

    #[test]
    fn test_l006_flags_a_switch_without_feedback() {
        let model = model_with(
            convention_config(),
            groups_from(&[("1/1/0", "EG Kitchen Light Switch", Some("1.001"))]),
        );
        let diags = lint(&model, None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "L006");
        assert!(diags[0].message.contains("1/1/3"), "{:?}", diags[0].message);
    }

    #[test]
    fn test_l006_is_satisfied_by_the_paired_status_address() {
        let model = model_with(
            convention_config(),
            groups_from(&[
                ("1/1/0", "EG Kitchen Light Switch", Some("1.001")),
                ("1/1/3", "EG Kitchen Light Switch status", Some("1.001")),
            ]),
        );
        assert!(lint(&model, None).is_empty());
    }

    #[test]
    fn test_l007_flags_a_name_off_the_pattern() {
        let mut config = convention_config();
        if let Some(groups) = config.groups.as_mut() {
            groups.name_pattern = Some("* * *".to_string());
            groups.feedback_pairing = false;
        }
        let model = model_with(config, groups_from(&[("1/1/0", "Light", Some("1.001"))]));
        let codes: Vec<&str> = lint(&model, None).iter().map(|d| d.code).collect();
        assert_eq!(codes, vec!["L007"]);
    }

    #[test]
    fn test_l008_flags_a_dpt_that_contradicts_the_role() {
        let mut config = convention_config();
        if let Some(groups) = config.groups.as_mut() {
            groups.feedback_pairing = false;
        }
        // Offset 1 of a light block is the "Dim" role (DPT 3.007).
        let model = model_with(
            config,
            groups_from(&[("1/1/1", "EG Kitchen Light Dim", Some("1.001"))]),
        );
        let diags = lint(&model, None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "L008");
    }
}
