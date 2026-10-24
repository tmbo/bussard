//! What a device offers, in the device file's words: `bussard device` and the
//! MCP `knx_show_device` tool.
//!
//! [`device_view`] lists a device's channels (handle, vendor text, the user's
//! name) and, for one channel (or `device` for the device-level scope), its
//! parameters (key, current value, the enum choices or range from the product
//! model, whether it is at the vendor default) and objects (key, number,
//! text/function, DPT, flags, what it sends and listens on). The data comes
//! from the lock (joined into the in-memory [`Device`]) and the product models
//! under `models/`; without a product model the view says so and lists what
//! the lock has.
//!
//! For an application without channels of its own (none, or one generic
//! channel) the view also lists the ETS parameter pages of the product
//! model's `blocks` in ETS order, and for one with channels the channels its
//! configuration does not show (issue #298). A page or channel the
//! configuration does not show is marked inactive with the parameters that
//! enable it, the objects it would show and how the change reaches the
//! device; `summary` counts them. A page handle selects one page as the
//! scope.
//!
//! [`DeviceView::render_table`] is the terminal rendering, and
//! [`DeviceView::render_toml`] the paste-ready device-file snippet: what the
//! file sets, plus commented lines `# key = "value"   # choice | choice` for
//! what it could set.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::address::IndividualAddress;
use crate::blocks::{
    BlockDef, BlockKind, BlockState, Gate, block_states, object_number, parent_indexes,
    ref_param_id, subtree,
};
use crate::flags::Flags;
use crate::loader::Model;
use crate::param_model::{ParamDef, ParamKind, ProductModel, ProductModels, enum_label};
use crate::schema::Device;

/// The channel argument that selects the device-level scope (`[parameters]`
/// and `[links]` of the device file).
pub const DEVICE_SCOPE: &str = "device";

/// [`Inactive::needs`] for a page or channel whose parameters reach the
/// device with a parameter push: what changes, not how (the CLI and the MCP
/// server each say how at their end).
pub const NEEDS_PUSH: &str = "a parameter push (the com-objects stay as they are)";

/// [`Inactive::needs`] for a page or channel that shows com-objects once
/// enabled: the push is a full download.
pub const NEEDS_FLASH: &str = "shows com-objects, so the push is a flash (a parameter push \
     does not change the object table)";

/// One channel in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelRow {
    /// The handle the device file uses (`[channel.<handle>]`).
    pub handle: String,
    /// The vendor's channel number, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u32>,
    /// The vendor's channel text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The user's name for it, when it differs from the vendor text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// How many parameters the lock lists for it.
    pub parameters: usize,
    /// How many objects it has.
    pub objects: usize,
}

/// One parameter of a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParamRow {
    /// The key the device file uses.
    pub key: String,
    /// The app-relative `ParameterRef` id.
    pub reference: String,
    /// The vendor's text, from the product model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The value the device file sets, rendered as the file would write it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The vendor default, rendered like `value`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Whether the effective value is the vendor default; `None` when the
    /// product model is not at hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_default: Option<bool>,
    /// The enum labels (or codes), for an enumeration.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    /// The range of an integer, `min..max`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    /// Set when the file stores a value the configuration does not reach
    /// (issue #321): the value is never written to the device. Says why, as
    /// [`IgnoredOverride::reason`] does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored: Option<String>,
}

/// One object of a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectRow {
    /// The key the device file uses, or the number when the lock gives none.
    pub key: String,
    /// The com-object number.
    pub number: u16,
    /// The vendor's text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The vendor's function text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The datapoint type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
    /// The communication flags (`CWU`, `CRT`, …).
    pub flags: String,
    /// The group address it sends on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send: Option<String>,
    /// The group addresses it listens on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listen: Vec<String>,
}

/// A parameter to set so the device shows an inactive block or channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnableStep {
    /// The key the device file uses, when the lock lists the parameter (one
    /// that the configuration does not show yet has none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The app-relative `ParameterRef` id.
    pub reference: String,
    /// The vendor's text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The value that shows the block.
    pub set_to: String,
    /// The vendor default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// The device's value now (stored, else the default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
}

/// A com-object an inactive block would show once enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShownObject {
    /// The com-object number.
    pub number: u16,
    /// The vendor's text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The vendor's function text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The datapoint type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
    /// The communication flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}

/// Why a block or channel is inactive and what enabling it takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inactive {
    /// The parameters to set, outermost first (a later one appears once the
    /// earlier ones are set).
    pub enable: Vec<EnableStep>,
    /// The com-objects it shows with the vendor defaults once enabled.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub would_show: Vec<ShownObject>,
    /// What kind of push the change takes: [`NEEDS_PUSH`] or
    /// [`NEEDS_FLASH`]. How to run it is the caller's to say.
    pub needs: String,
    /// The handles of earlier inactive pages or channels whose `enable`
    /// steps this one needs too, when [`DeviceView::collapse_enable_chains`]
    /// left only the steps of its own in `enable`. Enable those first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also_needs: Vec<String>,
}

/// One ETS parameter page (`<ParameterBlock>`) of a channel-less
/// application, or an inactive channel of an application with channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockRow {
    /// The handle `bussard device <ia> <handle>` takes: the slug of the
    /// title.
    pub handle: String,
    /// The app-relative element id (`PB-7243`, `CH-4`).
    pub id: String,
    /// The title ETS shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// How deep it is nested in other pages (0: top level).
    pub depth: usize,
    /// Whether the configuration shows it.
    pub active: bool,
    /// Active: how many of the device's parameters sit directly on it.
    /// Inactive: how many it and its nested pages hold.
    pub parameters: usize,
    /// Active: how many of the device's objects sit directly on it.
    /// Inactive: how many it would show once enabled.
    pub objects: usize,
    /// Set for an inactive one: what enables it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive: Option<Inactive>,
    /// The ids of the pages folded into this row: inactive pages the same
    /// settings show (Theben's "Objekte zu C4" behind "Universalkanal C4").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,
}

/// One scope in detail: a channel, or the device level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeView {
    /// The channel handle, `None` for the device level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// The vendor's channel text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The user's channel name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The page handle, when the scope is an ETS parameter page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<String>,
    /// For an inactive page: what enables it. Its parameters are then the
    /// ones it would show (under the lock's key and with the stored value when it
    /// has them, else the slug of the vendor text), and its objects
    /// the ones it would show with the vendor defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive: Option<Inactive>,
    /// Its parameters, by key.
    pub parameters: Vec<ParamRow>,
    /// Its objects, by number.
    pub objects: Vec<ObjectRow>,
}

/// A device as `bussard device` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceView {
    /// The individual address.
    pub address: String,
    /// The device name.
    pub name: String,
    /// The order number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The application program the lock pins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// Whether the product model (`models/<application>.yaml`) was at hand.
    pub product_model: bool,
    /// Every channel.
    pub channels: Vec<ChannelRow>,
    /// How many device-level parameters and objects there are.
    pub device_level: (usize, usize),
    /// For an application without channels of its own (none, or one generic
    /// channel): its ETS parameter pages in ETS order, each active or
    /// inactive. Pages nested in an inactive page are not listed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<BlockRow>,
    /// For an application with channels: the channels its configuration does
    /// not show, with what enables each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inactive_channels: Vec<BlockRow>,
    /// Spare capacity at a glance: how many pages or channels are inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The scope asked for, in detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeView>,
    /// What the view could not show, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Why a view could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// The model has no such device.
    #[error("{0} is not a device in this model")]
    NoDevice(IndividualAddress),
    /// The device has no such channel.
    #[error("{address} has no channel {channel:?}; its channels are: {known}")]
    NoChannel {
        /// The device.
        address: IndividualAddress,
        /// What was asked for.
        channel: String,
        /// The handles it has.
        known: String,
    },
}

/// One parameter the lock or the file knows, before rendering.
struct ParamEntry {
    reference: String,
    key: String,
    channel: Option<String>,
    param: Option<String>,
    stored: Option<String>,
    /// The ref's own default when it overrides the parameter's (the lock's
    /// `default`), else `None` and the product model's default applies.
    ref_default: Option<String>,
}

/// Every parameter of `device`: the lock's index plus what the file stores.
fn parameter_entries(device: &Device) -> Vec<ParamEntry> {
    let mut by_ref: BTreeMap<String, ParamEntry> = BTreeMap::new();
    for (reference, p) in &device.lock.parameters {
        by_ref.insert(
            reference.clone(),
            ParamEntry {
                reference: reference.clone(),
                key: p.key.clone(),
                channel: p.channel.clone(),
                param: p.param.clone(),
                stored: None,
                ref_default: p.default.clone(),
            },
        );
    }
    for (mem_key, value) in &device.parameters {
        let Some((_, reference)) = mem_key.split_once('@') else {
            continue;
        };
        let entry = by_ref
            .entry(reference.to_string())
            .or_insert_with(|| ParamEntry {
                reference: reference.to_string(),
                key: mem_key.clone(),
                channel: None,
                param: crate::param_model::key_to_param_id(mem_key),
                stored: None,
                ref_default: None,
            });
        entry.stored = Some(value.clone());
    }
    by_ref.into_values().collect()
}

/// Renders a stored or default code as the file writes it: the enum label
/// when there is a usable one, else the value as is.
fn display_value(def: Option<&ParamDef>, value: &str) -> String {
    match def {
        Some(d) if !d.labels.is_empty() => enum_label(&d.labels, value)
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

/// Whether two renderings of a value mean the same (a label and its code).
fn same_value(def: Option<&ParamDef>, a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a == b {
        return true;
    }
    let Some(d) = def else { return false };
    let code = |v: &str| {
        v.parse::<i64>()
            .ok()
            .or_else(|| crate::param_model::enum_code(&d.labels, v))
    };
    matches!((code(a), code(b)), (Some(x), Some(y)) if x == y)
}

fn param_row(entry: &ParamEntry, product: Option<&ProductModel>) -> ParamRow {
    let def = entry
        .param
        .as_deref()
        .and_then(|id| product.and_then(|p| p.parameters.get(id)));
    let default = default_value(product, entry.ref_default.as_deref(), &entry.reference, def);
    let value = entry.stored.as_deref().map(|v| display_value(def, v));
    let at_default = def.map(|_| match (entry.stored.as_deref(), default) {
        (None, _) => true,
        (Some(v), Some(d)) => same_value(def, v, d),
        (Some(_), None) => false,
    });
    let choices = def
        .map(|d| {
            if d.labels.is_empty() {
                match &d.kind {
                    ParamKind::Enum { values } => values.iter().map(i64::to_string).collect(),
                    _ => Vec::new(),
                }
            } else {
                d.labels.iter().map(|(_, t)| t.clone()).collect()
            }
        })
        .unwrap_or_default();
    let range = def.and_then(|d| match &d.kind {
        ParamKind::Int { min, max, .. } => match (min, max) {
            (None, None) => None,
            (a, b) => Some(format!(
                "{}..{}",
                a.map(|v| v.to_string()).unwrap_or_default(),
                b.map(|v| v.to_string()).unwrap_or_default()
            )),
        },
        ParamKind::Text { len: Some(n) } => Some(format!("text, up to {n} bytes")),
        _ => None,
    });
    ParamRow {
        key: entry.key.clone(),
        reference: entry.reference.clone(),
        text: def.and_then(|d| d.text.clone()),
        value,
        default: default.map(|d| display_value(def, d)),
        at_default,
        choices,
        range,
        ignored: None,
    }
}

/// The numeric value of a stored or default parameter value: the number,
/// or the code of an enum label.
fn value_number(def: Option<&ParamDef>, value: &str) -> Option<f64> {
    let v = value.trim();
    v.parse::<f64>().ok().or_else(|| {
        def.and_then(|d| crate::param_model::enum_code(&d.labels, v))
            .map(|c| c as f64)
    })
}

/// The enum codes of a parameter, in order (empty for other kinds).
fn enum_codes(def: &ParamDef) -> Vec<i64> {
    match &def.kind {
        ParamKind::Enum { values } if !values.is_empty() => values.clone(),
        _ => def.labels.iter().map(|(c, _)| *c).collect(),
    }
}

/// The default of parameter ref `reference` (definition `def`) when nothing
/// is stored, in the order the download side resolves it (issue #326): the
/// lock's `default` (`locked`, the ref's own value as the lock indexes it),
/// else the product model's `ParameterRef` value, else the parameter's
/// default.
fn default_value<'b>(
    product: Option<&'b ProductModel>,
    locked: Option<&'b str>,
    reference: &str,
    def: Option<&'b ParamDef>,
) -> Option<&'b str> {
    locked
        .or_else(|| {
            product
                .and_then(|p| p.ref_values.get(reference))
                .map(String::as_str)
        })
        .or_else(|| def.and_then(|d| d.default.as_deref()))
}

/// The device's value of parameter ref `reference`, as written: the stored
/// value (a hidden one too: a download writes it), else
/// [`default_value`]. The one lookup the page states, the conditions and
/// the rendered values share, so they agree with the image a download
/// writes.
fn raw_value<'b>(
    product: &'b ProductModel,
    values: &HashMap<&str, &'b ParamEntry>,
    reference: &str,
) -> Option<&'b str> {
    let def = product.parameters.get(ref_param_id(reference));
    let entry = values.get(reference);
    entry.and_then(|e| e.stored.as_deref()).or_else(|| {
        default_value(
            Some(product),
            entry.and_then(|e| e.ref_default.as_deref()),
            reference,
            def,
        )
    })
}

/// The ETS parameter pages of one device: which it shows, and where its
/// parameters and objects sit.
struct Pages<'a> {
    product: &'a ProductModel,
    blocks: &'a [BlockDef],
    parents: Vec<Option<usize>>,
    states: Vec<BlockState>,
    /// The device's parameters by ref, without the hidden ones.
    entries: HashMap<&'a str, &'a ParamEntry>,
    /// The device's parameters by ref, the hidden ones too: what the value
    /// lookup reads.
    values: HashMap<&'a str, &'a ParamEntry>,
    /// The block each of the device's parameter refs sits on.
    param_block: HashMap<&'a str, usize>,
    /// The block each of the device's object refs sits on.
    object_block: HashMap<String, usize>,
}

impl<'a> Pages<'a> {
    fn new(device: &'a Device, product: &'a ProductModel, params: &'a [ParamEntry]) -> Self {
        let blocks = product.blocks.as_slice();
        // A stored value of a parameter the configuration hides (`hidden@…`)
        // is no evidence that its page is shown.
        let entries: HashMap<&str, &ParamEntry> = params
            .iter()
            .filter(|p| !crate::files::is_hidden_mem_key(&p.key))
            .map(|p| (p.reference.as_str(), p))
            .collect();
        let values: HashMap<&str, &ParamEntry> =
            params.iter().map(|p| (p.reference.as_str(), p)).collect();
        let active_params: HashSet<&str> = entries.keys().copied().collect();
        let object_refs: Vec<&str> = device
            .com_objects
            .values()
            .filter_map(|o| o.reference.as_deref())
            .collect();
        let active_objects: HashSet<&str> = object_refs.iter().copied().collect();
        let value_of = |reference: &str| -> Option<f64> {
            let def = product.parameters.get(ref_param_id(reference));
            value_number(def, raw_value(product, &values, reference)?)
        };
        let states = block_states(blocks, &active_params, &active_objects, &value_of);
        let parents = parent_indexes(blocks);
        // Active blocks claim a ref first, so a parameter that alternative
        // pages share sits on the one the device shows.
        let order: Vec<usize> = (0..blocks.len())
            .filter(|i| states[*i].active)
            .chain((0..blocks.len()).filter(|i| !states[*i].active))
            .collect();
        let mut param_block: HashMap<&str, usize> = HashMap::new();
        let mut object_block: HashMap<String, usize> = HashMap::new();
        for &i in &order {
            for r in &blocks[i].parameters {
                if let Some((key, _)) = entries.get_key_value(r.as_str()) {
                    param_block.entry(*key).or_insert(i);
                }
            }
            for r in blocks[i].objects.iter().chain(&blocks[i].other_objects) {
                if active_objects.contains(r.as_str()) {
                    object_block.entry(r.clone()).or_insert(i);
                }
            }
        }
        Pages {
            product,
            blocks,
            parents,
            states,
            entries,
            values,
            param_block,
            object_block,
        }
    }

    /// How many `<ParameterBlock>` ancestors block `i` has.
    fn depth(&self, i: usize) -> usize {
        let mut depth = 0;
        let mut at = self.parents[i];
        while let Some(p) = at {
            if self.blocks[p].kind == BlockKind::Block {
                depth += 1;
            }
            at = self.parents[p];
        }
        depth
    }

    /// The device's value of a parameter ref, rendered as the file writes it.
    fn current(&self, reference: &str) -> Option<String> {
        let def = self.product.parameters.get(ref_param_id(reference));
        let raw = raw_value(self.product, &self.values, reference)?;
        Some(display_value(def, raw))
    }

    /// The parameter definitions blocks `members` and their nested blocks
    /// hold, one per parameter, without headings (`type: none`). Of several
    /// refs of one parameter, the first whose conditions inside its block
    /// hold, else the first.
    fn held_params(&self, members: &[usize]) -> Vec<(&'a str, &'a ParamDef)> {
        // Per parameter id: its index in `out` and whether that ref's
        // branch holds.
        let mut seen: HashMap<&str, (usize, bool)> = HashMap::new();
        let mut out = Vec::new();
        let all = members
            .iter()
            .flat_map(|i| subtree(self.blocks, &self.parents, *i));
        for j in all {
            for r in &self.blocks[j].parameters {
                let id = ref_param_id(r);
                let Some(def) = self.product.parameters.get(id) else {
                    continue;
                };
                if matches!(def.kind, ParamKind::None) {
                    continue;
                }
                let holds = self.on_branch(j, r);
                match seen.get_mut(id) {
                    Some((at, taken)) => {
                        if holds && !*taken {
                            out[*at] = (r.as_str(), def);
                            *taken = true;
                        }
                    }
                    None => {
                        seen.insert(id, (out.len(), holds));
                        out.push((r.as_str(), def));
                    }
                }
            }
        }
        out
    }

    /// The objects blocks `members` show with the vendor defaults once
    /// enabled: their own, and those of nested blocks whose conditions hold.
    fn would_show(&self, members: &[usize]) -> Vec<ShownObject> {
        let mut shown: HashSet<usize> = HashSet::new();
        let mut refs: Vec<&str> = Vec::new();
        let all = members
            .iter()
            .flat_map(|i| subtree(self.blocks, &self.parents, *i));
        for j in all {
            let reached = members.contains(&j)
                || (self.parents[j].is_some_and(|p| shown.contains(&p))
                    && self.blocks[j]
                        .when
                        .iter()
                        .all(|g| g.holds(self.value_number(&g.reference))));
            if !reached {
                continue;
            }
            shown.insert(j);
            refs.extend(self.blocks[j].objects.iter().map(String::as_str));
        }
        let mut out: Vec<ShownObject> = Vec::new();
        for r in refs {
            let Some(number) = object_number(r) else {
                continue;
            };
            if out.iter().any(|o| o.number == number) {
                continue;
            }
            let o = self.product.object_def(r);
            out.push(ShownObject {
                number,
                text: o.and_then(|o| o.text.clone()),
                function: o.and_then(|o| o.function.clone()),
                dpt: o.and_then(|o| o.dpt.clone()),
                flags: o.and_then(|o| o.flags.clone()),
            });
        }
        out.sort_by_key(|o| o.number);
        out
    }

    fn value_number(&self, reference: &str) -> Option<f64> {
        let def = self.product.parameters.get(ref_param_id(reference));
        value_number(def, raw_value(self.product, &self.values, reference)?)
    }

    /// Whether the configuration shows parameter ref `reference` of block
    /// `i`: the block is active and every condition inside it between the
    /// block and the ref holds for the device's values.
    fn shows_ref(&self, i: usize, reference: &str) -> bool {
        self.states[i].active && self.on_branch(i, reference)
    }

    /// Whether every condition inside block `i` between the block and
    /// parameter ref `reference` holds for the device's values: the block
    /// shows the ref once it shows itself.
    fn on_branch(&self, i: usize, reference: &str) -> bool {
        self.blocks[i]
            .parameter_when
            .get(reference)
            .is_none_or(|gates| {
                gates
                    .iter()
                    .all(|g| g.holds(self.value_number(&g.reference)))
            })
    }

    /// Whether the configuration shows parameter ref `reference` of block
    /// `i`, and what it needs when it does not (issue #321).
    fn ref_visibility(&self, i: usize, reference: &str) -> RefVisibility {
        let gates = self.blocks[i].parameter_when.get(reference);
        let shown = self.shows_ref(i, reference);
        let (needs, now) = if shown {
            (None, None)
        } else {
            // The page that hides it: the block itself, or the enclosing
            // block whose own conditions fail.
            let mut page = i;
            while self.states[page].parent_inactive
                && let Some(p) = self.parents[page]
            {
                page = p;
            }
            let mut failing: Vec<&Gate> = if self.states[page].active {
                Vec::new()
            } else {
                self.states[page]
                    .failing
                    .iter()
                    .filter_map(|n| self.blocks[page].when.get(*n))
                    .collect()
            };
            failing.extend(
                gates
                    .into_iter()
                    .flatten()
                    .filter(|g| !g.holds(self.value_number(&g.reference))),
            );
            let mut needs: Vec<String> = Vec::new();
            let mut now: Vec<String> = Vec::new();
            for g in failing {
                let words = self.gate_words(g);
                if !needs.contains(&words) {
                    needs.push(words);
                }
                let def = self.product.parameters.get(ref_param_id(&g.reference));
                let name = def
                    .and_then(|d| d.text.clone().or_else(|| d.name.clone()))
                    .unwrap_or_else(|| g.reference.clone());
                let line = format!(
                    "{name} is {}",
                    self.current(&g.reference)
                        .unwrap_or_else(|| "unset".to_string())
                );
                if !now.contains(&line) {
                    now.push(line);
                }
            }
            if needs.is_empty() {
                let text = self.blocks[page]
                    .text
                    .clone()
                    .unwrap_or_else(|| self.blocks[page].id.clone());
                needs.push(format!("the page {text:?} active"));
            }
            (
                Some(needs.join(" and ")),
                (!now.is_empty()).then(|| now.join(", ")),
            )
        };
        RefVisibility {
            shown,
            on_branch: self.on_branch(i, reference),
            condition: gates.filter(|gates| !gates.is_empty()).map(|gates| {
                gates
                    .iter()
                    .map(|g| self.gate_words(g))
                    .collect::<Vec<_>>()
                    .join(" and ")
            }),
            needs,
            now,
        }
    }

    /// A condition in words: the controlling parameter's text and the values
    /// that satisfy the test, as the device file writes them ("Funktion des
    /// Kanals = Helligkeit").
    fn gate_words(&self, gate: &Gate) -> String {
        let def = self.product.parameters.get(ref_param_id(&gate.reference));
        let name = def
            .and_then(|d| d.text.clone().or_else(|| d.name.clone()))
            .unwrap_or_else(|| gate.reference.clone());
        // `1 2` becomes "A or B", `!=0` becomes "!= A".
        let plain = |test: &str, join: &str| -> String {
            let t = test.trim();
            for op in ["!=", "<=", ">=", "<", ">"] {
                if let Some(rest) = t.strip_prefix(op) {
                    return format!("{op} {}", display_value(def, rest.trim()));
                }
            }
            t.split_whitespace()
                .map(|v| display_value(def, v))
                .collect::<Vec<_>>()
                .join(join)
        };
        let test = gate.test.trim();
        if test == "default" {
            if gate.others.is_empty() {
                return format!("{name} at any value");
            }
            let others: Vec<String> = gate.others.iter().map(|o| plain(o, ", ")).collect();
            return format!("{name} is none of {}", others.join(", "));
        }
        if test.starts_with(['!', '<', '>', '?']) {
            return format!("{name} {}", plain(test, " or "));
        }
        format!("{name} = {}", plain(test, " or "))
    }

    /// What enables inactive block `i` (shown together with `members`).
    fn inactive(&self, i: usize, members: &[usize]) -> Inactive {
        let enable = self.states[i]
            .failing
            .iter()
            .filter_map(|n| self.blocks[i].when.get(*n))
            .map(|g| {
                let def = self.product.parameters.get(ref_param_id(&g.reference));
                let codes = def.map(enum_codes).unwrap_or_default();
                let set_to = g
                    .satisfying(&codes)
                    .first()
                    .copied()
                    .or_else(|| g.first_value())
                    .map(|c| display_value(def, &c.to_string()))
                    .unwrap_or_else(|| g.test.clone());
                EnableStep {
                    key: self
                        .entries
                        .get(g.reference.as_str())
                        .map(|e| e.key.clone()),
                    reference: g.reference.clone(),
                    text: def.and_then(|d| d.text.clone().or_else(|| d.name.clone())),
                    set_to,
                    default: default_value(
                        Some(self.product),
                        self.values
                            .get(g.reference.as_str())
                            .and_then(|e| e.ref_default.as_deref()),
                        &g.reference,
                        def,
                    )
                    .map(|d| display_value(def, d)),
                    current: self.current(&g.reference),
                }
            })
            .collect();
        let would_show = self.would_show(members);
        let needs = if would_show.is_empty() {
            NEEDS_PUSH
        } else {
            NEEDS_FLASH
        }
        .to_string();
        Inactive {
            enable,
            would_show,
            needs,
            also_needs: Vec::new(),
        }
    }

    /// Whether the device has a parameter or object on active block `i` or a
    /// block nested in it. A page of only internal parameters
    /// (`Access="None"`, which the lock leaves out) shows nothing.
    fn shows_something(&self, i: usize) -> bool {
        let tree: HashSet<usize> = subtree(self.blocks, &self.parents, i).into_iter().collect();
        self.param_block.values().any(|b| tree.contains(b))
            || self.object_block.values().any(|b| tree.contains(b))
    }

    /// Whether block `i` (with its nested blocks) holds anything to show.
    fn has_content(&self, i: usize) -> bool {
        subtree(self.blocks, &self.parents, i).into_iter().any(|j| {
            let b = &self.blocks[j];
            !b.objects.is_empty()
                || !b.other_objects.is_empty()
                || b.parameters.iter().any(|r| {
                    self.product
                        .parameters
                        .get(ref_param_id(r))
                        .is_some_and(|d| !matches!(d.kind, ParamKind::None))
                })
        })
    }

    /// The row of block `i` (with the blocks folded into it, `members`)
    /// under `handle`.
    fn row(&self, listed: &Listed) -> BlockRow {
        let i = listed.index;
        let members = listed.members.as_slice();
        let b = &self.blocks[i];
        let active = self.states[i].active;
        let (parameters, objects, inactive) = if active {
            (
                self.param_block.values().filter(|j| **j == i).count(),
                self.object_block.values().filter(|j| **j == i).count(),
                None,
            )
        } else {
            let inactive = self.inactive(i, members);
            (
                self.held_params(members).len(),
                inactive.would_show.len(),
                Some(inactive),
            )
        };
        BlockRow {
            handle: listed.handle.clone(),
            id: b.id.clone(),
            text: b.text.clone(),
            depth: self.depth(i),
            active,
            parameters,
            objects,
            inactive,
            includes: members
                .iter()
                .filter(|m| **m != i)
                .map(|m| self.blocks[*m].id.clone())
                .collect(),
        }
    }

    /// The failing conditions of inactive block `i`, as (ref, test) pairs.
    fn failing(&self, i: usize) -> Vec<(&str, &str)> {
        self.states[i]
            .failing
            .iter()
            .filter_map(|n| self.blocks[i].when.get(*n))
            .map(|g| (g.reference.as_str(), g.test.as_str()))
            .collect()
    }

    /// The blocks a channel-less device lists, with their handles: every
    /// `<ParameterBlock>` with something to show, except those nested in an
    /// inactive one. An inactive block whose failing conditions extend those
    /// of an earlier inactive block with the same parent and a title of
    /// another shape (Theben's "Objekte" or "Sicherheit" pages behind a
    /// channel's switch) is folded into that block; when the conditions are
    /// the same, enabling the earlier block shows it too, so its parameters
    /// and objects count there.
    fn listed(&self, taken: &[String]) -> Vec<Listed> {
        let candidates: Vec<usize> = self
            .blocks
            .iter()
            .enumerate()
            .filter(|(i, b)| {
                b.kind == BlockKind::Block
                    && !self.states[*i].parent_inactive
                    && self.has_content(*i)
                    && (!self.states[*i].active || self.shows_something(*i))
            })
            .map(|(i, _)| i)
            .collect();
        let mut out: Vec<Listed> = Vec::new();
        for i in candidates {
            if !self.states[i].active {
                let mine = self.failing(i);
                let host = out.iter_mut().rev().find(|l| {
                    let a = l.index;
                    if self.states[a].active || self.parents[a] != self.parents[i] {
                        return false;
                    }
                    let theirs = self.failing(a);
                    mine.starts_with(&theirs)
                        && title_shape(self.blocks[a].text.as_deref())
                            != title_shape(self.blocks[i].text.as_deref())
                });
                if let Some(host) = host {
                    if self.failing(host.index) == mine {
                        host.members.push(i);
                    }
                    continue;
                }
            }
            out.push(Listed {
                index: i,
                handle: String::new(),
                members: vec![i],
            });
        }
        // Handles: the slug of the title, else of the name when titles
        // repeat, made unique with `-2`, `-3`, ….
        let slug_of = |t: Option<&str>| t.map(crate::slug).filter(|s| !s.is_empty());
        let mut title_count: HashMap<String, usize> = HashMap::new();
        for l in &out {
            if let Some(t) = slug_of(self.blocks[l.index].text.as_deref()) {
                *title_count.entry(t).or_default() += 1;
            }
        }
        let mut used: HashSet<String> = taken.iter().cloned().collect();
        used.insert(DEVICE_SCOPE.to_string());
        for l in &mut out {
            let b = &self.blocks[l.index];
            let title = slug_of(b.text.as_deref());
            let base = match (&title, slug_of(b.name.as_deref())) {
                (Some(t), Some(n)) if title_count.get(t).is_some_and(|c| *c > 1) => n,
                (Some(t), _) => t.clone(),
                (None, Some(n)) => n,
                (None, None) => b.id.to_lowercase(),
            };
            let mut handle = base.clone();
            let mut n = 2;
            while used.contains(&handle) {
                handle = format!("{base}-{n}");
                n += 1;
            }
            used.insert(handle.clone());
            l.handle = handle;
        }
        out
    }
}

/// A block a device lists: its index, handle and the blocks shown with it.
struct Listed {
    index: usize,
    handle: String,
    /// `index` and the inactive blocks folded into it that the same settings
    /// show.
    members: Vec<usize>,
}

/// A title with its numbering taken out: digit runs and single-letter words
/// become `#`, so "Universalkanal C4" and "Universalkanal C10", or "Channel
/// A" and "Channel B", have the same shape.
fn title_shape(text: Option<&str>) -> String {
    let text = text.unwrap_or("");
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let boundary_before = i == 0 || !chars[i - 1].is_alphanumeric();
        let boundary_after = chars.get(i + 1).is_none_or(|n| !n.is_alphanumeric());
        if c.is_ascii_digit() {
            while chars.get(i).is_some_and(char::is_ascii_digit) {
                i += 1;
            }
            out.push('#');
            continue;
        }
        if c.is_alphabetic() && boundary_before && boundary_after {
            out.push('#');
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// "17 of 40 pages inactive: 7 Universalkanal C4: Funktion .. Universalkanal
/// C10: Funktion; …": the inactive rows grouped by their title with the
/// numbers taken out.
fn summary(rows: &[BlockRow], what: &str) -> Option<String> {
    let top: Vec<&BlockRow> = rows.iter().filter(|r| !r.active).collect();
    if top.is_empty() {
        return None;
    }
    let mut groups: Vec<(String, Vec<&BlockRow>)> = Vec::new();
    for r in &top {
        let title = r.text.clone().unwrap_or_else(|| r.id.clone());
        let key = title_shape(Some(&title));
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push(r),
            None => groups.push((key, vec![r])),
        }
    }
    let parts: Vec<String> = groups
        .iter()
        .map(|(_, members)| {
            let title = |r: &BlockRow| r.text.clone().unwrap_or_else(|| r.id.clone());
            match members.as_slice() {
                [one] => format!("1 {}", title(one)),
                [first, .., last] => {
                    format!("{} {} .. {}", members.len(), title(first), title(last))
                }
                [] => String::new(),
            }
        })
        .collect();
    Some(format!(
        "{} of {} {what} inactive: {}",
        top.len(),
        rows.len(),
        parts.join("; ")
    ))
}

/// One of the device's objects as a scope lists it, with its links.
fn object_row(
    number: u16,
    o: &crate::schema::ComObject,
    links: Option<&Vec<crate::schema::Link>>,
) -> ObjectRow {
    let link = links.and_then(|l| l.iter().find(|l| l.object == number));
    ObjectRow {
        key: o.key.clone().unwrap_or_else(|| number.to_string()),
        number,
        text: o.text.clone(),
        function: o.function.clone(),
        dpt: o.dpt.map(|d| d.to_string()),
        flags: o.flags.to_string(),
        send: link.and_then(|l| l.send).map(|g| g.to_string()),
        listen: link
            .map(|l| l.listen.iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
    }
}

/// The scope of ETS parameter page `i`: the device's parameters and objects
/// on it and its nested pages, or, for an inactive page, the parameters and
/// objects it would show.
fn block_scope(
    pg: &Pages<'_>,
    device: &Device,
    links: Option<&Vec<crate::schema::Link>>,
    listed: &Listed,
) -> ScopeView {
    let i = listed.index;
    let handle = listed.handle.clone();
    let tree: HashSet<usize> = listed
        .members
        .iter()
        .flat_map(|m| subtree(pg.blocks, &pg.parents, *m))
        .collect();
    let text = pg.blocks[i].text.clone();
    if pg.states[i].active {
        let mut parameters: Vec<ParamRow> = pg
            .entries
            .iter()
            .filter(|(r, _)| pg.param_block.get(*r).is_some_and(|b| tree.contains(b)))
            .map(|(_, e)| param_row(e, Some(pg.product)))
            .collect();
        parameters.sort_by(|a, b| a.key.cmp(&b.key));
        let objects: Vec<ObjectRow> = device
            .com_objects
            .iter()
            .filter(|(_, o)| {
                o.reference
                    .as_ref()
                    .and_then(|r| pg.object_block.get(r))
                    .is_some_and(|b| tree.contains(b))
            })
            .map(|(n, o)| object_row(*n, o, links))
            .collect();
        return ScopeView {
            handle: None,
            text,
            name: None,
            block: Some(handle),
            inactive: None,
            parameters,
            objects,
        };
    }
    let parameters: Vec<ParamRow> = pg
        .held_params(&listed.members)
        .into_iter()
        .map(|(reference, def)| {
            // A ref the lock indexes (or the file stores) keeps its key and
            // value, so the key printed here is the one the edit tools take.
            if let Some(e) = pg.entries.get(reference) {
                return param_row(e, Some(pg.product));
            }
            let entry = ParamEntry {
                reference: reference.to_string(),
                key: unindexed_key(def, reference),
                channel: None,
                param: Some(ref_param_id(reference).to_string()),
                stored: None,
                ref_default: None,
            };
            param_row(&entry, Some(pg.product))
        })
        .collect();
    let inactive = pg.inactive(i, &listed.members);
    let objects: Vec<ObjectRow> = inactive
        .would_show
        .iter()
        .map(|o| ObjectRow {
            key: o.number.to_string(),
            number: o.number,
            text: o.text.clone(),
            function: o.function.clone(),
            dpt: o.dpt.clone(),
            flags: o.flags.clone().unwrap_or_default(),
            send: None,
            listen: Vec::new(),
        })
        .collect();
    ScopeView {
        handle: None,
        text,
        name: None,
        block: Some(handle),
        inactive: Some(inactive),
        parameters,
        objects,
    }
}

/// Builds the view of `address`, with `channel` (a handle, a channel id, the
/// vendor number, or [`DEVICE_SCOPE`]) in detail when given.
pub fn device_view(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
    channel: Option<&str>,
) -> Result<DeviceView, ViewError> {
    let device = &model
        .devices
        .get(&address)
        .ok_or(ViewError::NoDevice(address))?
        .device;
    let application = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.clone());
    let product = application.as_deref().and_then(|a| products.get(a));
    let params = parameter_entries(device);
    let links = model.links.links.get(&address);

    let user_name = |id: &str| {
        let ch = device.channels.get(id)?;
        let name = ch.name.trim();
        (!name.is_empty() && Some(name) != ch.text.as_deref().map(str::trim))
            .then(|| name.to_string())
    };
    let channels: Vec<ChannelRow> = device
        .channels
        .iter()
        .map(|(id, ch)| ChannelRow {
            handle: device.channel_handle(id),
            number: ch.number,
            text: ch.text.clone(),
            name: user_name(id),
            parameters: params
                .iter()
                .filter(|p| p.channel.as_deref() == Some(id))
                .count(),
            objects: device
                .com_objects
                .values()
                .filter(|o| o.channel.as_deref() == Some(id))
                .count(),
        })
        .collect();
    let device_level = (
        params.iter().filter(|p| p.channel.is_none()).count(),
        device
            .com_objects
            .values()
            .filter(|o| o.channel.is_none())
            .count(),
    );

    // The ETS parameter pages: listed for a device without channels of its
    // own, and the inactive channels of one with channels (issue #298).
    let pages = product
        .filter(|p| !p.blocks.is_empty())
        .map(|p| Pages::new(device, p, &params));
    let channel_less = device.channels.len() <= 1;
    let listed: Vec<Listed> = match &pages {
        Some(pg) if channel_less => pg.listed(
            &channels
                .iter()
                .map(|c| c.handle.clone())
                .collect::<Vec<_>>(),
        ),
        _ => Vec::new(),
    };
    let blocks: Vec<BlockRow> = match &pages {
        Some(pg) => listed.iter().map(|l| pg.row(l)).collect(),
        None => Vec::new(),
    };
    let inactive_channels: Vec<BlockRow> = match &pages {
        Some(pg) if !channel_less => pg
            .blocks
            .iter()
            .enumerate()
            .filter(|(i, b)| {
                b.kind == BlockKind::Channel
                    && !pg.states[*i].active
                    && !pg.states[*i].parent_inactive
                    && !device.channels.contains_key(&b.id)
                    && pg.has_content(*i)
            })
            .map(|(i, b)| {
                let handle = b
                    .text
                    .as_deref()
                    .map(crate::slug)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| b.id.to_lowercase());
                pg.row(&Listed {
                    index: i,
                    handle,
                    members: vec![i],
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let summary = summary(&blocks, "pages").or_else(|| {
        (!inactive_channels.is_empty()).then(|| {
            let names: Vec<String> = inactive_channels
                .iter()
                .map(|r| r.text.clone().unwrap_or_else(|| r.id.clone()))
                .collect();
            format!(
                "{} channel(s) inactive: {}",
                inactive_channels.len(),
                names.join(", ")
            )
        })
    });
    let block_hit = channel.and_then(|wanted| {
        let pg = pages.as_ref()?;
        let hit = listed
            .iter()
            .find(|l| l.handle == wanted || pg.blocks[l.index].id == wanted)?;
        Some((pg, hit))
    });

    let scope = match channel {
        None => None,
        Some(_) if block_hit.is_some() => {
            block_hit.map(|(pg, hit)| block_scope(pg, device, links, hit))
        }
        Some(wanted) => {
            let id: Option<String> = if wanted == DEVICE_SCOPE {
                None
            } else {
                let found = device.channels.iter().find(|(id, ch)| {
                    device.channel_handle(id) == wanted
                        || id.as_str() == wanted
                        || ch.number.is_some_and(|n| n.to_string() == wanted)
                });
                match found {
                    Some((id, _)) => Some(id.clone()),
                    None => {
                        let mut known: Vec<String> =
                            channels.iter().map(|c| c.handle.clone()).collect();
                        known.push(DEVICE_SCOPE.to_string());
                        known.extend(listed.iter().map(|l| l.handle.clone()));
                        return Err(ViewError::NoChannel {
                            address,
                            channel: wanted.to_string(),
                            known: known.join(", "),
                        });
                    }
                }
            };
            let parameters: Vec<ParamRow> = params
                .iter()
                .filter(|p| p.channel == id)
                .map(|p| param_row(p, product))
                .collect();
            let objects: Vec<ObjectRow> = device
                .com_objects
                .iter()
                .filter(|(_, o)| o.channel == id)
                .map(|(number, o)| object_row(*number, o, links))
                .collect();
            Some(ScopeView {
                handle: id.as_deref().map(|i| device.channel_handle(i)),
                text: id
                    .as_deref()
                    .and_then(|i| device.channels.get(i))
                    .and_then(|c| c.text.clone()),
                name: id.as_deref().and_then(user_name),
                block: None,
                inactive: None,
                parameters,
                objects,
            })
        }
    };

    // Issue #321: a stored value the configuration does not reach is never
    // written; the row says so next to its value.
    let mut scope = scope;
    if let (Some(pg), Some(scope)) = (&pages, scope.as_mut()) {
        let ignored: HashMap<String, String> = ignored_in(device, pg)
            .into_iter()
            .map(|i| (i.reference.clone(), i.reason()))
            .collect();
        for row in &mut scope.parameters {
            row.ignored = ignored.get(&row.reference).cloned();
        }
    }

    let mut notes = Vec::new();
    if product.is_none() {
        notes.push(match &application {
            Some(app) => match crate::lock_products::archive_file_for(
                device.lock.product_entry.as_ref(),
                [],
                app,
            ) {
                Some(archive) => format!(
                    "no product data: .bussard/models/{app}.yaml is missing, so there are no \
                     choices, ranges or defaults. It regenerates automatically from {archive}; \
                     if this note stays, that archive could not be read (bussard warns why). \
                     Showing what the lock has"
                ),
                None => format!(
                    "no product data: no stored archive carries {app}, so there are no choices, \
                     ranges or defaults (run `bussard import-product --order-number <order>` or \
                     re-run `bussard import`); showing what the lock has"
                ),
            },
            None => "no product data: the lock pins no application for this device; showing \
                     what the lock has"
                .to_string(),
        });
    }
    Ok(DeviceView {
        address: address.to_string(),
        name: device.name.clone(),
        product: device.product.as_ref().and_then(|p| p.order_number.clone()),
        application,
        product_model: product.is_some(),
        channels,
        device_level,
        blocks,
        inactive_channels,
        summary,
        scope,
        notes,
    })
}

/// Leaves in each inactive row of `rows` only the `enable` steps of its own
/// when an earlier inactive row's steps are a strict subset of them, and
/// names that row and the ones it needs in turn in `also_needs`.
fn collapse_rows(rows: &mut [BlockRow]) {
    let full: Vec<Option<HashSet<String>>> = rows
        .iter()
        .map(|r| {
            r.inactive
                .as_ref()
                .map(|i| i.enable.iter().map(|e| e.reference.clone()).collect())
        })
        .collect();
    for i in 0..rows.len() {
        let Some(mine) = &full[i] else { continue };
        // The earlier row with the most steps that this row repeats.
        let host = (0..i)
            .filter(|j| {
                full[*j]
                    .as_ref()
                    .is_some_and(|t| !t.is_empty() && t.len() < mine.len() && t.is_subset(mine))
            })
            .max_by_key(|j| full[*j].as_ref().map_or(0, HashSet::len));
        let Some(j) = host else { continue };
        let mut also = rows[j]
            .inactive
            .as_ref()
            .map(|h| h.also_needs.clone())
            .unwrap_or_default();
        also.push(rows[j].handle.clone());
        let theirs = full[j].clone().unwrap_or_default();
        if let Some(inactive) = rows[i].inactive.as_mut() {
            inactive.enable.retain(|e| !theirs.contains(&e.reference));
            inactive.also_needs = also;
        }
    }
}

impl DeviceView {
    /// Shortens the `enable` chains of inactive pages and channels that only
    /// repeat an earlier one's (Theben's universal channel C10 behind C5 ..
    /// C9): such a row keeps the steps of its own and names the earlier rows
    /// in `also_needs`. A scope's own `inactive` keeps its full chain.
    pub fn collapse_enable_chains(&mut self) {
        collapse_rows(&mut self.blocks);
        collapse_rows(&mut self.inactive_channels);
    }
}

/// The ETS page handle (as [`DeviceView::blocks`] lists it) each parameter
/// ref of `address` sits on, keyed by the app-relative `ParameterRef` id.
/// Empty for a device whose view lists no pages (one with channels of its
/// own, or without a product model).
pub fn parameter_pages(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
) -> Result<BTreeMap<String, String>, ViewError> {
    let device = &model
        .devices
        .get(&address)
        .ok_or(ViewError::NoDevice(address))?
        .device;
    let mut out = BTreeMap::new();
    let product = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|a| products.get(a))
        .filter(|p| !p.blocks.is_empty());
    let Some(product) = product else {
        return Ok(out);
    };
    if device.channels.len() > 1 {
        return Ok(out);
    }
    let params = parameter_entries(device);
    let pg = Pages::new(device, product, &params);
    let taken: Vec<String> = device
        .channels
        .keys()
        .map(|id| device.channel_handle(id))
        .collect();
    let listed = pg.listed(&taken);
    let mut handle_of: HashMap<usize, &str> = HashMap::new();
    for l in &listed {
        for m in &l.members {
            handle_of.entry(*m).or_insert(l.handle.as_str());
        }
    }
    for (reference, block) in &pg.param_block {
        let mut at = Some(*block);
        while let Some(i) = at {
            if let Some(handle) = handle_of.get(&i) {
                out.insert((*reference).to_string(), (*handle).to_string());
                break;
            }
            at = pg.parents[i];
        }
    }
    Ok(out)
}

/// A parameter of a device's application that its pages hold but the lock
/// does not index: one on a page that was inactive at import and that ETS
/// stores nothing for (it is at its default). See [`unindexed_parameters`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnindexedParameter {
    /// The key [`device_view`] prints for it on an inactive page: the slug of
    /// its vendor text.
    pub key: String,
    /// The handle of the page [`device_view`] lists it under, when the device
    /// lists pages and one of them holds it. A page enabled since import with
    /// nothing on it indexed yet is not listed; it keeps the handle of its
    /// title here, the one the view gave it while it was inactive.
    pub page: Option<String>,
    /// The application parameter id (`P-7305`).
    pub param: String,
    /// The vendor text.
    pub text: Option<String>,
}

/// The key the view gives a parameter the lock does not index: the slug of
/// its vendor text, else of its name, else the ref itself.
fn unindexed_key(def: &ParamDef, reference: &str) -> String {
    crate::slug(
        def.text
            .as_deref()
            .or(def.name.as_deref())
            .unwrap_or(reference),
    )
}

/// Every parameter ref the product model's pages hold for device `address`
/// that neither the lock indexes nor the device file stores, keyed by the
/// app-relative `ParameterRef` id: what [`device_view`] prints on an
/// inactive page, and what an active page holds beyond the lock. Headings
/// (`type: none`) are left out. Empty without a product model with pages.
pub fn unindexed_parameters(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
) -> Result<BTreeMap<String, UnindexedParameter>, ViewError> {
    let device = &model
        .devices
        .get(&address)
        .ok_or(ViewError::NoDevice(address))?
        .device;
    let mut out = BTreeMap::new();
    let product = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|a| products.get(a))
        .filter(|p| !p.blocks.is_empty());
    let Some(product) = product else {
        return Ok(out);
    };
    let params = parameter_entries(device);
    let known: HashSet<&str> = params.iter().map(|p| p.reference.as_str()).collect();
    let pg = Pages::new(device, product, &params);
    let mut handle_of: HashMap<usize, &str> = HashMap::new();
    let listed = if device.channels.len() > 1 {
        Vec::new()
    } else {
        let taken: Vec<String> = device
            .channels
            .keys()
            .map(|id| device.channel_handle(id))
            .collect();
        pg.listed(&taken)
    };
    for l in &listed {
        for m in &l.members {
            handle_of.entry(*m).or_insert(l.handle.as_str());
        }
    }
    let mut used: HashSet<String> = listed.iter().map(|l| l.handle.clone()).collect();
    used.extend(device.channels.keys().map(|id| device.channel_handle(id)));
    used.insert(DEVICE_SCOPE.to_string());
    // Active blocks claim a ref first, as `Pages::new` does.
    let order = (0..pg.blocks.len())
        .filter(|i| pg.states[*i].active)
        .chain((0..pg.blocks.len()).filter(|i| !pg.states[*i].active));
    for i in order {
        for reference in &pg.blocks[i].parameters {
            if known.contains(reference.as_str()) || out.contains_key(reference) {
                continue;
            }
            let id = ref_param_id(reference);
            let Some(def) = product.parameters.get(id) else {
                continue;
            };
            if matches!(def.kind, ParamKind::None) {
                continue;
            }
            let mut page = None;
            let mut at = Some(i);
            while let Some(b) = at {
                if let Some(handle) = handle_of.get(&b) {
                    page = Some((*handle).to_string());
                    break;
                }
                at = pg.parents[b];
            }
            // An active page the view does not list (just enabled, nothing
            // on it indexed yet) keeps the handle it had while inactive, when
            // that handle is free.
            if page.is_none() && !listed.is_empty() && pg.blocks[i].kind == BlockKind::Block {
                let b = &pg.blocks[i];
                let base = [b.text.as_deref(), b.name.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(crate::slug)
                    .find(|s| !s.is_empty())
                    .unwrap_or_else(|| b.id.to_lowercase());
                if !used.contains(&base) {
                    page = Some(base);
                }
            }
            out.insert(
                reference.clone(),
                UnindexedParameter {
                    key: unindexed_key(def, reference),
                    page,
                    param: id.to_string(),
                    text: def.text.clone().or_else(|| def.name.clone()),
                },
            );
        }
    }
    Ok(out)
}

/// Whether a device's configuration shows a parameter ref its pages hold,
/// and the conditions inside its page that decide it (issue #315). See
/// [`parameter_visibility`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefVisibility {
    /// The configuration shows it: its page is active and every condition
    /// inside the page between the page and the ref holds for the device's
    /// values (stored, else the default).
    pub shown: bool,
    /// Every condition inside its page between the page and the ref holds:
    /// the page shows this ref once it shows itself.
    pub on_branch: bool,
    /// Those conditions in words ("Funktion des Kanals = Helligkeit"),
    /// joined with "and"; `None` for a ref outside any `<choose>` of its
    /// page.
    pub condition: Option<String>,
    /// What the configuration needs to show it, in words: the failing
    /// conditions of its page (or the enclosing page that hides it) and of
    /// its branch ("Art der Verknüpfung = XOR"); `None` when it is shown
    /// (issue #321).
    pub needs: Option<String>,
    /// The current values of the parameters those failing conditions test
    /// ("Art der Verknüpfung is UND"); `None` when it is shown.
    pub now: Option<String>,
}

/// Every parameter ref the product model's pages hold for device `address`,
/// keyed by the app-relative `ParameterRef` id, with whether the device's
/// configuration shows it under its current values: the page states
/// [`device_view`] lists, and the conditions inside each page. A ref on
/// several pages counts as shown when one of them shows it. Empty without a
/// product model with pages.
pub fn parameter_visibility(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
) -> Result<BTreeMap<String, RefVisibility>, ViewError> {
    let device = &model
        .devices
        .get(&address)
        .ok_or(ViewError::NoDevice(address))?
        .device;
    let product = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|a| products.get(a))
        .filter(|p| !p.blocks.is_empty());
    let Some(product) = product else {
        return Ok(BTreeMap::new());
    };
    let params = parameter_entries(device);
    let pg = Pages::new(device, product, &params);
    Ok(pg.visibility())
}

impl Pages<'_> {
    /// [`parameter_visibility`] of every ref the pages hold.
    fn visibility(&self) -> BTreeMap<String, RefVisibility> {
        let mut out: BTreeMap<String, RefVisibility> = BTreeMap::new();
        for (i, b) in self.blocks.iter().enumerate() {
            for reference in &b.parameters {
                let seen = self.ref_visibility(i, reference);
                match out.get_mut(reference) {
                    Some(v) if (seen.shown, seen.on_branch) > (v.shown, v.on_branch) => *v = seen,
                    Some(_) => {}
                    None => {
                        out.insert(reference.clone(), seen);
                    }
                }
            }
        }
        out
    }
}

/// A value the device file stores for a parameter ref the configuration
/// does not reach under the device's current values (issue #321): the image
/// a flash or a parameter push writes holds one slot per reached ref, so the
/// value is never written until the configuration shows the ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IgnoredOverride {
    /// The key the device file uses (the lock's, else the in-memory key).
    pub key: String,
    /// The app-relative `ParameterRef` id.
    pub reference: String,
    /// The stored value, rendered as the file writes it.
    pub value: String,
    /// What the configuration needs to show the ref, in words
    /// ("Funktion des Kanals = Wind").
    pub needs: String,
}

impl IgnoredOverride {
    /// Why the value is ignored: "not shown under the current values (needs
    /// …)".
    pub fn reason(&self) -> String {
        format!("not shown under the current values (needs {})", self.needs)
    }

    /// The plan line: "`key` = value ignored: not shown under the current
    /// values (needs …)".
    pub fn sentence(&self) -> String {
        format!("`{}` = {} ignored: {}", self.key, self.value, self.reason())
    }
}

/// Every value the file of device `address` stores for a parameter ref the
/// configuration does not reach under its current values, by ref (issue
/// #321). A value at the ref's default, a hidden value ETS stored
/// (`hidden@…`, which a flash writes as is) and a channel label are left
/// out. Empty without a product model with pages.
///
/// # Errors
///
/// [`ViewError::NoDevice`] when the model has no device `address`.
pub fn ignored_overrides(
    model: &Model,
    products: &ProductModels,
    address: IndividualAddress,
) -> Result<Vec<IgnoredOverride>, ViewError> {
    let device = &model
        .devices
        .get(&address)
        .ok_or(ViewError::NoDevice(address))?
        .device;
    let product = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .and_then(|a| products.get(a))
        .filter(|p| !p.blocks.is_empty());
    let Some(product) = product else {
        return Ok(Vec::new());
    };
    let params = parameter_entries(device);
    let pg = Pages::new(device, product, &params);
    Ok(ignored_in(device, &pg))
}

/// [`ignored_overrides`] on the pages `pg` of `device`.
fn ignored_in(device: &Device, pg: &Pages<'_>) -> Vec<IgnoredOverride> {
    let visibility = pg.visibility();
    let mut out = Vec::new();
    for (mem_key, value) in &device.parameters {
        if crate::files::is_hidden_mem_key(mem_key) {
            continue;
        }
        let Some((head, reference)) = mem_key.split_once('@') else {
            continue;
        };
        if head == "label" {
            continue;
        }
        let Some(needs) = visibility.get(reference).and_then(|v| v.needs.clone()) else {
            continue;
        };
        let def = pg.product.parameters.get(ref_param_id(reference));
        let locked = device.lock.parameters.get(reference);
        let default = default_value(
            Some(pg.product),
            locked.and_then(|p| p.default.as_deref()),
            reference,
            def,
        );
        if default.is_some_and(|d| same_value(def, value, d)) {
            continue;
        }
        out.push(IgnoredOverride {
            key: locked.map_or_else(|| mem_key.clone(), |p| p.key.clone()),
            reference: reference.to_string(),
            value: display_value(def, value),
            needs,
        });
    }
    out
}

/// Pads `rows` into columns under `header`.
fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| one_line(c)).collect())
        .collect();
    let rows = rows.as_slice();
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    let line = |cells: Vec<String>| {
        let mut out = String::from("  ");
        for (i, cell) in cells.iter().enumerate() {
            let last = i + 1 == cells.len();
            if last {
                out.push_str(cell);
            } else {
                let pad = widths[i].saturating_sub(cell.chars().count());
                out.push_str(cell);
                out.push_str(&" ".repeat(pad + 2));
            }
        }
        format!("{}\n", out.trim_end())
    };
    let mut out = line(header.iter().map(|h| h.to_string()).collect());
    for row in rows {
        out.push_str(&line(row.clone()));
    }
    out
}

/// A vendor text on one line: a line break becomes a space (a parameter
/// text like "Soll ein zweites Telegramm\ngesendet werden ?" would break the
/// table).
fn one_line(text: &str) -> String {
    text.replace("\r\n", " ").replace(['\n', '\r'], " ")
}

/// A TOML key as the device file writes it: bare when TOML allows, quoted
/// otherwise; a page-qualified key (`sollwerte.komfort`) stays dotted.
fn toml_key(key: &str) -> String {
    let bare = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if bare(key) {
        return key.to_string();
    }
    if !key.contains('@') && key.split('.').all(bare) {
        return key.to_string();
    }
    toml_string(key)
}

/// A TOML basic string.
fn toml_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// How the terminal user runs the push [`Inactive::needs`] names, for
/// device `address`.
fn cli_push(needs: &str, address: &str) -> String {
    if needs == NEEDS_FLASH {
        format!("{needs}: `bussard flash {address}`")
    } else {
        format!("{needs}: `bussard plan {address}` and `bussard apply {address}`")
    }
}

/// What enables an inactive page or channel of device `address`, in one
/// line.
fn inactive_line(inactive: &Inactive, address: &str) -> String {
    let steps: Vec<String> = inactive
        .enable
        .iter()
        .map(|e| {
            let name = e
                .key
                .clone()
                .or_else(|| e.text.clone().map(|t| format!("{t:?}")))
                .unwrap_or_else(|| e.reference.clone());
            match &e.default {
                Some(d) => format!("{name} = {:?} (default {d:?})", e.set_to),
                None => format!("{name} = {:?}", e.set_to),
            }
        })
        .collect();
    let mut line = if steps.is_empty() {
        "not shown under the current configuration".to_string()
    } else {
        format!("set {}", steps.join(", then "))
    };
    if !inactive.also_needs.is_empty() {
        line = format!("after {}: {line}", inactive.also_needs.join(", "));
    }
    if !inactive.would_show.is_empty() {
        line.push_str(&format!("; shows {} object(s)", inactive.would_show.len()));
    }
    line.push_str(&format!("; {}", cli_push(&inactive.needs, address)));
    line
}

/// The page or channel rows as a table.
fn block_table(rows: &[BlockRow], address: &str) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                format!("{}{}", "  ".repeat(r.depth), r.handle),
                r.text.clone().unwrap_or_default(),
                r.parameters.to_string(),
                r.objects.to_string(),
                match &r.inactive {
                    Some(i) => format!("inactive: {}", inactive_line(i, address)),
                    None => "active".to_string(),
                },
            ]
        })
        .collect();
    table(&["page", "text", "params", "objects", "state"], &rows)
}

impl DeviceView {
    /// The terminal rendering: the channel table, then the scope in detail.
    pub fn render_table(&self) -> String {
        let mut out = format!("{} {}", self.address, self.name.trim());
        if let Some(p) = &self.product {
            out.push_str(&format!("  ({p}"));
            if let Some(app) = &self.application {
                out.push_str(&format!(", {app}"));
            }
            out.push(')');
        }
        out.push('\n');
        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        match &self.scope {
            None => {
                if self.channels.is_empty() {
                    out.push_str("no channels\n");
                } else {
                    let rows: Vec<Vec<String>> = self
                        .channels
                        .iter()
                        .map(|c| {
                            vec![
                                c.handle.clone(),
                                c.number.map(|n| n.to_string()).unwrap_or_default(),
                                c.text.clone().unwrap_or_default(),
                                c.name.clone().unwrap_or_default(),
                                c.parameters.to_string(),
                                c.objects.to_string(),
                            ]
                        })
                        .collect();
                    out.push_str(&table(
                        &["channel", "no.", "vendor text", "name", "params", "objects"],
                        &rows,
                    ));
                }
                out.push_str(&format!(
                    "device level: {} parameter(s), {} object(s)\n",
                    self.device_level.0, self.device_level.1
                ));
                if !self.blocks.is_empty() {
                    out.push_str("pages (ETS parameter blocks, in ETS order):\n");
                    out.push_str(&block_table(&self.blocks, &self.address));
                }
                if !self.inactive_channels.is_empty() {
                    out.push_str("inactive channels:\n");
                    out.push_str(&block_table(&self.inactive_channels, &self.address));
                }
                if let Some(summary) = &self.summary {
                    out.push_str(&format!("summary: {summary}\n"));
                }
                out.push_str(&format!(
                    "`bussard device {} <channel>` lists a channel's parameters and objects \
                     (`{DEVICE_SCOPE}` for the device level{}); `--toml` prints them ready to \
                     paste.\n",
                    self.address,
                    if self.blocks.is_empty() {
                        ""
                    } else {
                        ", a page handle for one page"
                    }
                ));
            }
            Some(scope) => {
                match &scope.handle {
                    Some(h) => {
                        out.push_str(&format!("channel {h}"));
                        if let Some(t) = &scope.text {
                            out.push_str(&format!(" ({t})"));
                        }
                        if let Some(n) = &scope.name {
                            out.push_str(&format!(", named {n:?}"));
                        }
                        out.push('\n');
                    }
                    None => match &scope.block {
                        Some(b) => {
                            out.push_str(&format!("page {b}"));
                            if let Some(t) = &scope.text {
                                out.push_str(&format!(" ({t})"));
                            }
                            out.push('\n');
                        }
                        None => out.push_str("device level\n"),
                    },
                }
                if let Some(inactive) = &scope.inactive {
                    out.push_str(&format!(
                        "inactive: {}\n",
                        inactive_line(inactive, &self.address)
                    ));
                    out.push_str(
                        "it would show these parameters (at their defaults) and objects:\n",
                    );
                }
                out.push_str("parameters:\n");
                if scope.parameters.is_empty() {
                    out.push_str("  (none)\n");
                } else {
                    let rows: Vec<Vec<String>> = scope
                        .parameters
                        .iter()
                        .map(|p| {
                            let value = p
                                .value
                                .clone()
                                .or_else(|| p.default.clone())
                                .unwrap_or_else(|| "-".to_string());
                            let marker = match (&p.ignored, p.at_default) {
                                (Some(why), _) => format!("ignored: {why}"),
                                (None, Some(true)) => "default".to_string(),
                                (None, Some(false)) => "set".to_string(),
                                (None, None) if p.value.is_some() => "set".to_string(),
                                (None, None) => String::new(),
                            };
                            let allowed = if !p.choices.is_empty() {
                                p.choices.join(" | ")
                            } else {
                                p.range.clone().unwrap_or_default()
                            };
                            vec![
                                p.key.clone(),
                                value,
                                marker,
                                allowed,
                                p.text.clone().unwrap_or_default(),
                            ]
                        })
                        .collect();
                    out.push_str(&table(
                        &["key", "value", "", "choices / range", "text"],
                        &rows,
                    ));
                }
                out.push_str("objects:\n");
                if scope.objects.is_empty() {
                    out.push_str("  (none)\n");
                } else {
                    let rows: Vec<Vec<String>> = scope
                        .objects
                        .iter()
                        .map(|o| {
                            let mut links = Vec::new();
                            if let Some(s) = &o.send {
                                links.push(format!("sends {s}"));
                            }
                            if !o.listen.is_empty() {
                                links.push(format!("listens on {}", o.listen.join(", ")));
                            }
                            let label = match (&o.text, &o.function) {
                                (Some(t), Some(f)) => format!("{t}: {f}"),
                                (Some(t), None) => t.clone(),
                                (None, Some(f)) => f.clone(),
                                (None, None) => String::new(),
                            };
                            vec![
                                o.key.clone(),
                                o.number.to_string(),
                                label,
                                o.dpt.clone().unwrap_or_default(),
                                o.flags.clone(),
                                links.join("; "),
                            ]
                        })
                        .collect();
                    out.push_str(&table(
                        &["key", "no.", "text", "dpt", "flags", "links"],
                        &rows,
                    ));
                }
            }
        }
        out
    }

    /// The paste-ready device-file snippet for the scope (or, without one,
    /// the channel tables with their names).
    pub fn render_toml(&self) -> String {
        let mut out = format!(
            "# devices/{}.toml: {}; uncomment what you want to set\n",
            self.address,
            self.name.trim()
        );
        for note in &self.notes {
            out.push_str(&format!("# note: {note}\n"));
        }
        let Some(scope) = &self.scope else {
            for c in &self.channels {
                out.push_str(&format!("\n[channel.{}]", toml_key(&c.handle)));
                if let Some(t) = &c.text {
                    out.push_str(&format!("   # {t}"));
                }
                out.push('\n');
                match &c.name {
                    Some(n) => out.push_str(&format!("name = {}\n", toml_string(n))),
                    None => out.push_str(&format!(
                        "# name = {}\n",
                        toml_string(c.text.as_deref().unwrap_or(""))
                    )),
                }
            }
            return out;
        };
        match &scope.handle {
            Some(h) => {
                out.push_str(&format!("\n[channel.{}]", toml_key(h)));
                if let Some(t) = &scope.text {
                    out.push_str(&format!("   # {t}"));
                }
                out.push('\n');
                match &scope.name {
                    Some(n) => out.push_str(&format!("name = {}\n", toml_string(n))),
                    None => out.push_str(&format!(
                        "# name = {}\n",
                        toml_string(scope.text.as_deref().unwrap_or(""))
                    )),
                }
            }
            None => out.push_str("\n[parameters]\n"),
        }
        for p in &scope.parameters {
            let hint = if !p.choices.is_empty() {
                p.choices.join(" | ")
            } else {
                p.range.clone().unwrap_or_default()
            };
            let hint = match (&p.text, hint.is_empty()) {
                (Some(t), false) => format!("{t}: {hint}"),
                (Some(t), true) => t.clone(),
                (None, _) => hint,
            };
            let hint = match (&p.ignored, hint.is_empty()) {
                (Some(why), true) => format!("ignored: {why}"),
                (Some(why), false) => format!("ignored: {why}; {hint}"),
                (None, _) => hint,
            };
            let comment = if hint.is_empty() {
                String::new()
            } else {
                format!("   # {hint}")
            };
            match &p.value {
                Some(v) => out.push_str(&format!(
                    "{} = {}{comment}\n",
                    toml_key(&p.key),
                    toml_string(v)
                )),
                None => out.push_str(&format!(
                    "# {} = {}{comment}\n",
                    toml_key(&p.key),
                    toml_string(p.default.as_deref().unwrap_or(""))
                )),
            }
        }
        if scope.handle.is_none() && !scope.objects.is_empty() {
            out.push_str("\n[links]\n");
        }
        for o in &scope.objects {
            let flags: Flags = o.flags.parse().unwrap_or_default();
            let what = [o.function.as_deref(), o.text.as_deref(), o.dpt.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
            let comment = format!("   # {} {what}", o.flags);
            let key = toml_key(&o.key);
            if o.send.is_none() && o.listen.is_empty() {
                // Commands take `listen` (W flag), status objects `send` (T).
                if flags.contains(Flags::WRITE) {
                    out.push_str(&format!("# {key}.listen = []{comment}\n"));
                } else if flags.contains(Flags::TRANSMIT) {
                    out.push_str(&format!("# {key}.send = \"\"{comment}\n"));
                }
                continue;
            }
            if let Some(s) = &o.send {
                out.push_str(&format!("{key}.send = {}{comment}\n", toml_string(s)));
            }
            if !o.listen.is_empty() {
                let list: Vec<String> = o.listen.iter().map(|g| toml_string(g)).collect();
                out.push_str(&format!("{key}.listen = [{}]{comment}\n", list.join(", ")));
            }
        }
        out
    }
}
