//! Group-address scaffolding from a room-and-function plan (issue #103).
//!
//! An integrator's room book lists floors, rooms and the functions each room
//! needs. The KNX guidelines describe how that becomes a group-address plan, but
//! every integrator implements the mapping by hand. This module implements it:
//! [`scaffold`] turns a [`Plan`] into `groups.yaml` entries with reserved blocks,
//! conventional names and DPTs, under one of two addressing schemes.
//!
//! # The two schemes
//!
//! Both use the 3-level form `main/middle/sub`. They differ only in which level
//! carries the floor and which carries the trade:
//!
//! | Scheme | main | middle | sub |
//! |---|---|---|---|
//! | [`Scheme::FloorTradeBlock`] | floor | trade | block + role |
//! | [`Scheme::FunctionFloor`] | trade | floor | block + role |
//!
//! Index 0 is left free on both levels (it conventionally holds central
//! functions, and it keeps the reserved address `0/0/0` out of reach), so floors
//! and trades count from 1. `middle` is three bits, so `function-floor` supports
//! at most seven floors.
//!
//! # Blocks and roles
//!
//! A trade reserves a fixed block of consecutive sub addresses per room (five
//! for light, ten for blind and heating). Inside a block, each **role** sits at
//! a fixed offset with a fixed DPT, so a reader can tell what an address does
//! from its position alone. A function fills only the roles it needs; the rest of
//! the block stays free for growth (a plain `light` fills 2 of its 5 slots, so a
//! later dimmer upgrade needs no renumbering).
//!
//! The same tables drive the convention lints in [`crate::lint`], so scaffolded
//! output passes them by construction.
//!
//! # Re-running
//!
//! [`scaffold`] merges into an existing plan. Existing addresses, names and DPTs
//! are never touched: a room/function pair is recognised by the name of its
//! primary role, and one that is already present is skipped. New blocks are
//! allocated after the highest sub address already used in their range, and new
//! floors after the highest floor index already named in `ranges:`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::address::GroupAddress;
use crate::dpt::Dpt;
use crate::schema::{Group, Groups, Range};

/// The addressing scheme a project follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    /// `main` = floor, `middle` = trade, `sub` = block + role.
    FloorTradeBlock,
    /// `main` = trade, `middle` = floor, `sub` = block + role.
    FunctionFloor,
}

impl Scheme {
    /// The scheme's name as it appears in `bussard.yaml` (`floor-trade-block`).
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::FloorTradeBlock => "floor-trade-block",
            Scheme::FunctionFloor => "function-floor",
        }
    }

    /// Splits a group address into `(floor index, trade index)` under this scheme.
    pub fn split(self, ga: GroupAddress) -> (u8, u8) {
        match self {
            Scheme::FloorTradeBlock => (ga.main(), ga.middle()),
            Scheme::FunctionFloor => (ga.middle(), ga.main()),
        }
    }

    /// Builds the `(main, middle)` pair for a floor and trade index.
    pub fn join(self, floor: u8, trade: u8) -> (u8, u8) {
        match self {
            Scheme::FloorTradeBlock => (floor, trade),
            Scheme::FunctionFloor => (trade, floor),
        }
    }

    /// The highest floor index the scheme can express (floors on the 3-bit
    /// middle level in `function-floor`, on the 5-bit main level otherwise).
    pub fn max_floor_index(self) -> u8 {
        match self {
            Scheme::FloorTradeBlock => 31,
            Scheme::FunctionFloor => 7,
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One role inside a trade's block: a fixed offset with a fixed meaning and DPT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    /// The offset inside the block (0-based).
    pub offset: u8,
    /// The role's label, appended to the group-address name.
    pub label: &'static str,
    /// The DPT main number for this role.
    pub dpt_main: u16,
    /// The DPT sub number for this role.
    pub dpt_sub: u16,
    /// When this role is the feedback for a command role, that role's offset.
    pub status_of: Option<u8>,
}

impl Role {
    /// The role's datapoint type.
    pub fn dpt(&self) -> Dpt {
        Dpt::new(self.dpt_main, Some(self.dpt_sub))
    }
}

/// A trade (KNX "Gewerk"): the functional category a block belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeSpec {
    /// The key used in `lint.groups.blocks` and in plans.
    pub key: &'static str,
    /// The display label used for the range name.
    pub label: &'static str,
    /// The trade's index on its address level.
    pub index: u8,
    /// How many consecutive sub addresses one room reserves for this trade.
    pub block: u8,
    /// The roles defined inside the block; offsets not listed are free.
    pub roles: &'static [Role],
}

impl TradeSpec {
    /// The role at `offset`, if the trade defines one.
    pub fn role(&self, offset: u8) -> Option<&'static Role> {
        self.roles.iter().find(|r| r.offset == offset)
    }
}

/// A function a room can ask for: a trade plus the block offsets it fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionSpec {
    /// The key used in a plan's `functions:` list.
    pub key: &'static str,
    /// The label used in generated names (distinct per function so two
    /// functions of the same trade in one room never collide).
    pub label: &'static str,
    /// The trade key this function belongs to.
    pub trade: &'static str,
    /// The block offsets this function fills.
    pub offsets: &'static [u8],
}

/// Light: switch, dim, value and their feedbacks in a five-address block.
const LIGHT_ROLES: &[Role] = &[
    Role {
        offset: 0,
        label: "Switch",
        dpt_main: 1,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 1,
        label: "Dim",
        dpt_main: 3,
        dpt_sub: 7,
        status_of: None,
    },
    Role {
        offset: 2,
        label: "Value",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 3,
        label: "Switch status",
        dpt_main: 1,
        dpt_sub: 1,
        status_of: Some(0),
    },
    Role {
        offset: 4,
        label: "Value status",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: Some(2),
    },
];

/// Socket: a switched outlet, laid out like a light's switch/feedback pair.
const SOCKET_ROLES: &[Role] = &[
    Role {
        offset: 0,
        label: "Switch",
        dpt_main: 1,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 3,
        label: "Switch status",
        dpt_main: 1,
        dpt_sub: 1,
        status_of: Some(0),
    },
];

/// Blind: move/step/position/slat plus their feedbacks; offsets 7-9 stay free.
const BLIND_ROLES: &[Role] = &[
    Role {
        offset: 0,
        label: "Move",
        dpt_main: 1,
        dpt_sub: 8,
        status_of: None,
    },
    Role {
        offset: 1,
        label: "Step",
        dpt_main: 1,
        dpt_sub: 7,
        status_of: None,
    },
    Role {
        offset: 2,
        label: "Position",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 3,
        label: "Slat",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 4,
        label: "Position status",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: Some(2),
    },
    Role {
        offset: 5,
        label: "Slat status",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: Some(3),
    },
    Role {
        offset: 6,
        label: "Moving status",
        dpt_main: 1,
        dpt_sub: 11,
        status_of: Some(0),
    },
];

/// Heating: setpoint, mode, measured values and feedbacks; 6-9 stay free.
const HEATING_ROLES: &[Role] = &[
    Role {
        offset: 0,
        label: "Setpoint",
        dpt_main: 9,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 1,
        label: "Operating mode",
        dpt_main: 20,
        dpt_sub: 102,
        status_of: None,
    },
    Role {
        offset: 2,
        label: "Actual temperature",
        dpt_main: 9,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 3,
        label: "Control value",
        dpt_main: 5,
        dpt_sub: 1,
        status_of: None,
    },
    Role {
        offset: 4,
        label: "Setpoint status",
        dpt_main: 9,
        dpt_sub: 1,
        status_of: Some(0),
    },
    Role {
        offset: 5,
        label: "Operating mode status",
        dpt_main: 20,
        dpt_sub: 102,
        status_of: Some(1),
    },
];

/// Every trade bussard scaffolds and lints, in index order.
pub const TRADES: &[TradeSpec] = &[
    TradeSpec {
        key: "light",
        label: "Light",
        index: 1,
        block: 5,
        roles: LIGHT_ROLES,
    },
    TradeSpec {
        key: "blind",
        label: "Blind",
        index: 2,
        block: 10,
        roles: BLIND_ROLES,
    },
    TradeSpec {
        key: "heating",
        label: "Heating",
        index: 3,
        block: 10,
        roles: HEATING_ROLES,
    },
    TradeSpec {
        key: "socket",
        label: "Socket",
        index: 4,
        block: 5,
        roles: SOCKET_ROLES,
    },
];

/// Every function a plan may list.
pub const FUNCTIONS: &[FunctionSpec] = &[
    FunctionSpec {
        key: "light",
        label: "Light",
        trade: "light",
        offsets: &[0, 3],
    },
    FunctionSpec {
        key: "light-dim",
        label: "Dimmer",
        trade: "light",
        offsets: &[0, 1, 2, 3, 4],
    },
    FunctionSpec {
        key: "blind",
        label: "Blind",
        trade: "blind",
        offsets: &[0, 1, 2, 3, 4, 5, 6],
    },
    FunctionSpec {
        key: "heating",
        label: "Heating",
        trade: "heating",
        offsets: &[0, 1, 2, 3, 4, 5],
    },
    FunctionSpec {
        key: "socket",
        label: "Socket",
        trade: "socket",
        offsets: &[0, 3],
    },
];

/// Looks up a trade by its key.
pub fn trade(key: &str) -> Option<&'static TradeSpec> {
    TRADES.iter().find(|t| t.key == key)
}

/// Looks up a trade by its index on the address level that carries it.
pub fn trade_by_index(index: u8) -> Option<&'static TradeSpec> {
    TRADES.iter().find(|t| t.index == index)
}

/// Looks up a function by its plan key.
pub fn function(key: &str) -> Option<&'static FunctionSpec> {
    FUNCTIONS.iter().find(|f| f.key == key)
}

/// The comma-separated list of known function keys, for error messages.
fn known_functions() -> String {
    FUNCTIONS
        .iter()
        .map(|f| f.key)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A device-free planning file: which rooms exist and what each one needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The rooms, in the order they should be numbered.
    #[serde(default)]
    pub rooms: Vec<PlanRoom>,
}

/// One room in a [`Plan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRoom {
    /// The floor's display name, e.g. `"Ground floor"`.
    pub floor: String,
    /// The room's display name, e.g. `"Kitchen"`.
    pub room: String,
    /// The functions this room needs, by key (see [`FUNCTIONS`]).
    #[serde(default)]
    pub functions: Vec<String>,
}

impl Plan {
    /// Parses a plan from YAML (a JSON document parses too, YAML being a
    /// superset), so the CLI and the MCP tool share one entry point.
    pub fn from_yaml(text: &str) -> Result<Self, ScaffoldError> {
        Ok(serde_norway::from_str(text)?)
    }
}

/// One group address the scaffolder added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedGroup {
    /// The address.
    pub address: GroupAddress,
    /// Its generated name.
    pub name: String,
    /// Its DPT.
    pub dpt: Dpt,
}

/// The result of a scaffold run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldReport {
    /// The merged plan, ready to write.
    pub groups: Groups,
    /// The addresses added by this run, in address order.
    pub added: Vec<AddedGroup>,
    /// The trade keys the plan used, for the `lint.groups.blocks` block.
    pub trades_used: Vec<&'static str>,
}

/// Anything that can go wrong while scaffolding.
#[derive(Debug, thiserror::Error)]
pub enum ScaffoldError {
    /// The plan named a function bussard does not know.
    #[error("unknown function {key:?} (known functions: {known})")]
    UnknownFunction {
        /// The offending key.
        key: String,
        /// The known function keys.
        known: String,
    },
    /// The scheme cannot express that many floors.
    #[error(
        "the {scheme} scheme addresses floors on a {bits}-bit level, so it supports at most \
         {max} floors; the plan needs floor index {needed}"
    )]
    TooManyFloors {
        /// The scheme in use.
        scheme: &'static str,
        /// The width of the level that carries the floor.
        bits: u8,
        /// The highest expressible floor index.
        max: u8,
        /// The index the plan would have needed.
        needed: u16,
    },
    /// No free block is left in a range.
    #[error(
        "range {main}/{middle} has no free {trade} block of {block} addresses left \
         (sub addresses stop at 255)"
    )]
    RangeExhausted {
        /// The main group.
        main: u8,
        /// The middle group.
        middle: u8,
        /// The trade whose block did not fit.
        trade: &'static str,
        /// The block size.
        block: u8,
    },
    /// A computed address was out of range.
    #[error("computed an invalid group address: {0}")]
    Address(#[from] crate::address::AddressParseError),
    /// The existing plan could not be read.
    #[error(transparent)]
    Load(#[from] crate::loader::LoadError),
    /// The merged plan could not be written.
    #[error(transparent)]
    Save(#[from] crate::loader::SaveError),
    /// The plan file was not valid YAML/JSON.
    #[error("the plan is not valid YAML: {0}")]
    Plan(#[from] serde_norway::Error),
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// Scaffolds `plan` into `existing`, returning the merged plan and what it added.
///
/// Existing entries are never renumbered, renamed or re-typed: a room/function
/// pair whose primary role name is already present is left alone. See the module
/// docs for the allocation rules.
pub fn scaffold(
    existing: &Groups,
    plan: &Plan,
    scheme: Scheme,
) -> Result<ScaffoldReport, ScaffoldError> {
    let mut groups = existing.clone();
    let mut names: BTreeSet<String> = groups.groups.values().map(|g| g.name.clone()).collect();
    let mut floors = FloorIndex::recover(&groups, scheme);
    let mut added: Vec<AddedGroup> = Vec::new();
    let mut trades_used: Vec<&'static str> = Vec::new();

    for room in &plan.rooms {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for key in &room.functions {
            if !seen.insert(key.as_str()) {
                continue;
            }
            let func = function(key).ok_or_else(|| ScaffoldError::UnknownFunction {
                key: key.clone(),
                known: known_functions(),
            })?;
            let spec = trade(func.trade).ok_or_else(|| ScaffoldError::UnknownFunction {
                key: key.clone(),
                known: known_functions(),
            })?;
            if !trades_used.contains(&spec.key) {
                trades_used.push(spec.key);
            }

            // The primary role's name identifies this room/function pair. If it
            // is already in the plan, the block was allocated on an earlier run.
            let Some(primary) = func.offsets.first().and_then(|o| spec.role(*o)) else {
                continue;
            };
            let primary_name = group_name(&room.floor, &room.room, func.label, primary.label);
            if names.contains(&primary_name) {
                continue;
            }

            let floor_idx = floors.index_of(&room.floor, scheme)?;
            let (main, middle) = scheme.join(floor_idx, spec.index);
            let start = next_block_start(&groups, main, middle, spec)?;

            for offset in func.offsets {
                let Some(role) = spec.role(*offset) else {
                    continue;
                };
                let sub = start + u16::from(*offset);
                let address = GroupAddress::new(main, middle, sub as u8)?;
                let name = group_name(&room.floor, &room.room, func.label, role.label);
                let dpt = role.dpt();
                groups.groups.insert(
                    address,
                    Group {
                        name: name.clone(),
                        dpt: Some(dpt),
                        description: None,
                        protected: false,
                        secure: false,
                    },
                );
                names.insert(name.clone());
                added.push(AddedGroup { address, name, dpt });
            }

            // Name the ranges so a re-run can recover the floor numbering.
            let (main_name, middle_name) = match scheme {
                Scheme::FloorTradeBlock => (room.floor.clone(), spec.label.to_string()),
                Scheme::FunctionFloor => (spec.label.to_string(), room.floor.clone()),
            };
            groups
                .ranges
                .entry(main.to_string())
                .or_insert(Range { name: main_name });
            groups
                .ranges
                .entry(format!("{main}/{middle}"))
                .or_insert(Range { name: middle_name });
        }
    }

    added.sort_by_key(|a| a.address.raw());
    Ok(ScaffoldReport {
        groups,
        added,
        trades_used,
    })
}

/// The conventional name for one address: `<Floor> <Room> <Function> <Role>`.
fn group_name(floor: &str, room: &str, function: &str, role: &str) -> String {
    format!("{floor} {room} {function} {role}")
}

/// The floor -> index mapping, recovered from `ranges:` and extended on demand.
struct FloorIndex {
    by_name: BTreeMap<String, u8>,
    next: u16,
}

impl FloorIndex {
    /// Recovers the mapping from the range names an earlier run wrote.
    ///
    /// Under `floor-trade-block` floors name main groups (`"3"`); under
    /// `function-floor` they name middle groups (`"3/2"`), where the index is
    /// the middle component. A range level that carries trade labels instead is
    /// ignored, so a hand-written `ranges:` block cannot misassign a floor.
    fn recover(groups: &Groups, scheme: Scheme) -> Self {
        let mut by_name: BTreeMap<String, u8> = BTreeMap::new();
        // Index 0 stays free on both levels: it holds central functions by
        // convention, and it keeps the reserved address 0/0/0 out of reach.
        let mut next: u16 = 1;
        for (key, range) in &groups.ranges {
            let idx = match (scheme, key.split_once('/')) {
                (Scheme::FloorTradeBlock, None) => key.parse::<u8>().ok(),
                (Scheme::FunctionFloor, Some((_, middle))) => middle.parse::<u8>().ok(),
                _ => None,
            };
            let Some(idx) = idx else { continue };
            if TRADES.iter().any(|t| t.label == range.name) {
                continue;
            }
            by_name.entry(range.name.clone()).or_insert(idx);
            next = next.max(u16::from(idx) + 1);
        }
        FloorIndex { by_name, next }
    }

    /// The index for a floor, allocating a fresh one if it is new.
    fn index_of(&mut self, floor: &str, scheme: Scheme) -> Result<u8, ScaffoldError> {
        if let Some(idx) = self.by_name.get(floor) {
            return Ok(*idx);
        }
        let max = scheme.max_floor_index();
        if self.next > u16::from(max) {
            return Err(ScaffoldError::TooManyFloors {
                scheme: scheme.as_str(),
                bits: if max == 7 { 3 } else { 5 },
                max,
                needed: self.next,
            });
        }
        let idx = self.next as u8;
        self.next += 1;
        self.by_name.insert(floor.to_string(), idx);
        Ok(idx)
    }
}

/// The first free block start in `main/middle`: the block boundary after the
/// highest sub address already used there, or 0 when the range is empty.
fn next_block_start(
    groups: &Groups,
    main: u8,
    middle: u8,
    spec: &'static TradeSpec,
) -> Result<u16, ScaffoldError> {
    let block = u16::from(spec.block);
    let highest = groups
        .groups
        .keys()
        .filter(|ga| ga.main() == main && ga.middle() == middle)
        .map(|ga| u16::from(ga.sub()))
        .max();
    let start = match highest {
        Some(sub) => (sub / block + 1) * block,
        None => 0,
    };
    if start + block > 256 {
        return Err(ScaffoldError::RangeExhausted {
            main,
            middle,
            trade: spec.key,
            block: spec.block,
        });
    }
    Ok(start)
}

/// Reads a plan file, scaffolds it into `groups_path`, and writes the result.
///
/// `groups_path` is both the plan read and the file written, so `--out` picks a
/// different file to extend. A missing file starts from an empty plan.
pub fn scaffold_file(
    groups_path: &Path,
    plan: &Plan,
    scheme: Scheme,
) -> Result<ScaffoldReport, ScaffoldError> {
    let existing = crate::loader::load_groups(groups_path)?;
    let report = scaffold(&existing, plan, scheme)?;
    crate::loader::save_groups(groups_path, &report.groups)?;
    Ok(report)
}

/// The `lint:` block that matches a scaffolded plan, as YAML text.
///
/// Emitted with the trades the plan actually used, so the convention lints check
/// exactly the blocks that exist.
pub fn lint_config_yaml(scheme: Scheme, trades_used: &[&str]) -> String {
    let mut out = String::from(
        "\n# Lint rules for `bussard validate` (written by `bussard scaffold`).\n\
         # Topology limits and the group-address convention this project follows.\n\
         lint:\n  topology:\n    max_devices_per_line: 64\n  groups:\n",
    );
    out.push_str(&format!("    scheme: {}\n", scheme.as_str()));
    out.push_str("    blocks:\n");
    let mut any = false;
    for spec in TRADES {
        if trades_used.contains(&spec.key) {
            out.push_str(&format!("      {}: {}\n", spec.key, spec.block));
            any = true;
        }
    }
    if !any {
        for spec in TRADES {
            out.push_str(&format!("      {}: {}\n", spec.key, spec.block));
        }
    }
    out.push_str("    feedback_pairing: true\n");
    out.push_str("    name_pattern: \"* * *\"\n");
    out
}

/// Appends [`lint_config_yaml`] to `bussard.yaml` unless it already has a
/// `lint:` block. Returns whether it wrote anything.
///
/// The append is textual so a hand-written `bussard.yaml` keeps its comments and
/// key order; `lint:` is a new top-level key, so appending is a valid merge.
pub fn ensure_lint_config(
    config_path: &Path,
    scheme: Scheme,
    trades_used: &[&str],
) -> Result<bool, ScaffoldError> {
    let existing = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(ScaffoldError::Io {
                path: config_path.display().to_string(),
                source,
            });
        }
    };
    if existing.lines().any(|l| l.trim_end() == "lint:") {
        return Ok(false);
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&lint_config_yaml(scheme, trades_used));
    std::fs::write(config_path, text).map_err(|source| ScaffoldError::Io {
        path: config_path.display().to_string(),
        source,
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(rooms: &[(&str, &str, &[&str])]) -> Plan {
        Plan {
            rooms: rooms
                .iter()
                .map(|(floor, room, functions)| PlanRoom {
                    floor: (*floor).to_string(),
                    room: (*room).to_string(),
                    functions: functions.iter().map(|f| (*f).to_string()).collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_scaffold_floor_trade_block_layout() -> Result<(), Box<dyn std::error::Error>> {
        let p = plan(&[("Ground floor", "Kitchen", &["light", "blind"])]);
        let report = scaffold(&Groups::default(), &p, Scheme::FloorTradeBlock)?;

        let switch: GroupAddress = "1/1/0".parse()?;
        let status: GroupAddress = "1/1/3".parse()?;
        assert_eq!(
            report.groups.groups[&switch].name,
            "Ground floor Kitchen Light Switch"
        );
        assert_eq!(
            report.groups.groups[&switch].dpt,
            Some(Dpt::new(1, Some(1)))
        );
        assert!(report.groups.groups.contains_key(&status));
        // The dim/value slots stay free for a later upgrade.
        assert!(!report.groups.groups.contains_key(&"1/1/1".parse()?));

        // Blind is trade 2, so it lands in the next middle group.
        let move_ga: GroupAddress = "1/2/0".parse()?;
        assert_eq!(
            report.groups.groups[&move_ga].name,
            "Ground floor Kitchen Blind Move"
        );
        assert_eq!(report.trades_used, vec!["light", "blind"]);
        Ok(())
    }

    #[test]
    fn test_scaffold_function_floor_transposes_levels() -> Result<(), Box<dyn std::error::Error>> {
        let p = plan(&[("Ground floor", "Kitchen", &["light"])]);
        let report = scaffold(&Groups::default(), &p, Scheme::FunctionFloor)?;
        // Trade on main, floor on middle.
        assert!(report.groups.groups.contains_key(&"1/1/0".parse()?));

        let p2 = plan(&[("First floor", "Bath", &["blind"])]);
        let report2 = scaffold(&report.groups, &p2, Scheme::FunctionFloor)?;
        // Blind is trade 2 (main), first floor is index 2 (middle).
        assert!(report2.groups.groups.contains_key(&"2/2/0".parse()?));
        Ok(())
    }

    #[test]
    fn test_scaffold_rerun_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let p = plan(&[("Ground floor", "Kitchen", &["light", "heating"])]);
        let first = scaffold(&Groups::default(), &p, Scheme::FloorTradeBlock)?;
        let second = scaffold(&first.groups, &p, Scheme::FloorTradeBlock)?;
        assert!(second.added.is_empty(), "added: {:?}", second.added);
        assert_eq!(first.groups, second.groups);
        Ok(())
    }

    #[test]
    fn test_scaffold_extension_does_not_renumber() -> Result<(), Box<dyn std::error::Error>> {
        let p = plan(&[("Ground floor", "Kitchen", &["light"])]);
        let first = scaffold(&Groups::default(), &p, Scheme::FloorTradeBlock)?;

        // A new room on a new floor, plus the original room unchanged.
        let extended = plan(&[
            ("Ground floor", "Kitchen", &["light"]),
            ("Ground floor", "Hall", &["light"]),
            ("First floor", "Bath", &["light"]),
        ]);
        let second = scaffold(&first.groups, &extended, Scheme::FloorTradeBlock)?;

        for (ga, group) in &first.groups.groups {
            assert_eq!(
                second.groups.groups.get(ga).map(|g| &g.name),
                Some(&group.name),
                "{ga} must keep its name and address"
            );
        }
        // The hall gets the next block in the same range; the first floor a new main.
        assert!(second.groups.groups.contains_key(&"1/1/5".parse()?));
        assert!(second.groups.groups.contains_key(&"2/1/0".parse()?));
        Ok(())
    }

    #[test]
    fn test_scaffold_two_light_functions_do_not_collide() -> Result<(), Box<dyn std::error::Error>>
    {
        let p = plan(&[("Ground floor", "Kitchen", &["light", "light-dim"])]);
        let report = scaffold(&Groups::default(), &p, Scheme::FloorTradeBlock)?;
        assert_eq!(
            report.groups.groups[&"1/1/0".parse::<GroupAddress>()?].name,
            "Ground floor Kitchen Light Switch"
        );
        assert_eq!(
            report.groups.groups[&"1/1/5".parse::<GroupAddress>()?].name,
            "Ground floor Kitchen Dimmer Switch"
        );
        Ok(())
    }

    #[test]
    fn test_scaffold_unknown_function_is_an_error() {
        let p = plan(&[("EG", "Bad", &["teleporter"])]);
        let err = scaffold(&Groups::default(), &p, Scheme::FloorTradeBlock)
            .expect_err("unknown function must fail");
        assert!(
            matches!(err, ScaffoldError::UnknownFunction { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_function_floor_rejects_more_than_seven_floors() {
        let rooms: Vec<(String, String, Vec<String>)> = (0..9)
            .map(|i| {
                (
                    format!("Floor {i}"),
                    "Room".to_string(),
                    vec!["light".to_string()],
                )
            })
            .collect();
        let p = Plan {
            rooms: rooms
                .into_iter()
                .map(|(floor, room, functions)| PlanRoom {
                    floor,
                    room,
                    functions,
                })
                .collect(),
        };
        let err = scaffold(&Groups::default(), &p, Scheme::FunctionFloor)
            .expect_err("floors 1-7 are all a 3-bit level can hold");
        assert!(
            matches!(err, ScaffoldError::TooManyFloors { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_plan_parses_from_json_too() -> Result<(), Box<dyn std::error::Error>> {
        let p =
            Plan::from_yaml(r#"{"rooms":[{"floor":"EG","room":"Küche","functions":["light"]}]}"#)?;
        assert_eq!(p.rooms.len(), 1);
        assert_eq!(p.rooms[0].room, "Küche");
        Ok(())
    }

    #[test]
    fn test_lint_config_yaml_lists_used_trades() {
        let text = lint_config_yaml(Scheme::FloorTradeBlock, &["light", "heating"]);
        assert!(text.contains("scheme: floor-trade-block"), "{text}");
        assert!(text.contains("light: 5"), "{text}");
        assert!(text.contains("heating: 10"), "{text}");
        assert!(!text.contains("blind:"), "{text}");
    }
}
