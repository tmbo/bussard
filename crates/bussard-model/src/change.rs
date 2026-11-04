//! Plain-language rendering of a model change (issue #112).
//!
//! [`describe`] takes two model states and returns a [`ChangeSet`]: one
//! [`Change`] per difference, each carrying a short sentence built from device
//! names, locations, channel names and group-address names, plus the structured
//! fields behind it. The sentences are what an assistant quotes back to a
//! homeowner before she confirms, and what `bussard status`, `history`, `show`
//! and `undo` print. The YAML diff stays available behind `--raw`.
//!
//! Two rules hold everywhere:
//!
//! * **Nothing degrades to silence.** An unnamed group address renders as its
//!   address, an unnamed device as its individual address. A change never
//!   produces an empty sentence.
//! * **Names, not ids (issue #306).** A named group address or device is
//!   called by its name alone; the address follows in parentheses only when
//!   another group address or device of either model has the same name, or
//!   when the group address is protected. The structured fields of a
//!   [`Change`] keep every address.
//! * **Protected group addresses are called out.** A change that touches a GA
//!   marked `protected: true` in either model sets
//!   [`Change::touches_protected`] and its sentence ends with
//!   "This group address is protected."
//!
//! The order is deterministic: connection, then group addresses by address,
//! then devices by individual address, then links by device, com-object and
//! group address. [`render_text`] prints one sentence per line with the
//! protected ones first.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::{LoadedDevice, Model};
use crate::param_model::{ParamDef, ProductModels, enum_code, enum_label, key_to_param_id};
use crate::schema::{Device, Group, Location, Product};

/// The kind of a single model change.
///
/// One variant per change the YAML schema allows a human or an assistant to
/// make. Generated tables (`com_objects:`, `module_bases:`) are not rendered:
/// they are a re-import artefact, not an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A group address was added to `groups.toml`.
    GroupAdded,
    /// A group address was removed from `groups.toml`.
    GroupRemoved,
    /// A group address kept its address but changed name.
    GroupRenamed,
    /// A group address's datapoint type changed (or was set / cleared).
    GroupDptChanged,
    /// A group address's free-text description changed.
    GroupDescriptionChanged,
    /// A group address's `protected:` flag was set or cleared.
    GroupProtectionChanged,
    /// A group address's `secure` flag (KNX Data Secure) was set or cleared
    /// (issue #331).
    GroupSecurityChanged,
    /// The `secure` flag of one or more com-objects of a device was set or
    /// cleared (issue #331): the device's security object changes.
    ObjectSecurityChanged,
    /// A com-object gained a sending or listening group address.
    LinkAdded,
    /// A com-object lost a sending or listening group address.
    LinkRemoved,
    /// A device file appeared.
    DeviceAdded,
    /// A device file disappeared.
    DeviceRemoved,
    /// A device kept its address but changed name.
    DeviceRenamed,
    /// A device's floor or room changed.
    DeviceMoved,
    /// A device's product identity changed.
    DeviceProductChanged,
    /// A device parameter value was set, changed or cleared.
    ParameterChanged,
    /// A device channel's display name changed.
    ChannelRenamed,
    /// The connection block of `bussard.toml` changed.
    ConnectionChanged,
    /// The `[knxnet]` table of an IP interface changed (issue #391): the IP
    /// assignment, a static setting, the friendly name or a tunnel address.
    InterfaceChanged,
}

/// Which side of a com-object link a group address sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkRole {
    /// The single sending group address of the com object.
    Send,
    /// One of the com object's listening group addresses.
    Listen,
}

/// One difference between two models, as a sentence plus its structured fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// What kind of change this is.
    pub kind: ChangeKind,
    /// The plain-language sentence, ready to quote to a human.
    pub sentence: String,
    /// Whether this change touches a `protected: true` group address.
    pub touches_protected: bool,
    /// The device's individual address, when the change is about a device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The group address, when the change is about one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The com-object number, for link changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<u16>,
    /// Which side of the link the group address sits on, for link changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<LinkRole>,
    /// The field that changed (`"name"`, `"dpt"`, `"gateway"`, a parameter key,
    /// a channel key), when the change is a field edit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The previous value, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The new value, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

impl Change {
    /// Starts a change with its kind and sentence; the structured fields are
    /// filled in by the `with_*` builders.
    fn new(kind: ChangeKind, sentence: impl Into<String>) -> Self {
        Change {
            kind,
            sentence: sentence.into(),
            touches_protected: false,
            device: None,
            group: None,
            object: None,
            role: None,
            field: None,
            from: None,
            to: None,
        }
    }

    /// Records the device this change is about.
    fn with_device(mut self, ia: IndividualAddress) -> Self {
        self.device = Some(ia.to_string());
        self
    }

    /// Records the group address this change is about.
    fn with_group(mut self, ga: GroupAddress) -> Self {
        self.group = Some(ga.to_string());
        self
    }

    /// Records the com object and role of a link change.
    fn with_link(mut self, object: u16, role: LinkRole) -> Self {
        self.object = Some(object);
        self.role = Some(role);
        self
    }

    /// Records the edited field and its old/new values.
    fn with_field(
        mut self,
        field: impl Into<String>,
        from: Option<String>,
        to: Option<String>,
    ) -> Self {
        self.field = Some(field.into());
        self.from = from;
        self.to = to;
        self
    }

    /// Marks the change as touching a protected GA and appends the warning
    /// sentence. Idempotent.
    fn protected(mut self) -> Self {
        if !self.touches_protected {
            self.touches_protected = true;
            self.sentence.push(' ');
            self.sentence.push_str(PROTECTED_NOTE);
        }
        self
    }

    /// Marks the change protected when `yes`, otherwise leaves it alone.
    fn protected_if(self, yes: bool) -> Self {
        if yes { self.protected() } else { self }
    }
}

/// The trailing sentence appended to any change touching a protected GA.
pub const PROTECTED_NOTE: &str = "This group address is protected.";

/// Every difference between two models, in a deterministic order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChangeSet {
    /// The changes, ordered: connection, group addresses, devices, links.
    pub changes: Vec<Change>,
}

impl ChangeSet {
    /// Whether the two models were identical in every rendered respect.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// How many changes there are.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether any change touches a protected group address.
    pub fn touches_protected(&self) -> bool {
        self.changes.iter().any(|c| c.touches_protected)
    }

    /// A one-line summary: the first sentence, plus "and N more" when there are
    /// others. Empty when there are no changes.
    ///
    /// Protected changes sort first here too, so the riskiest sentence is the
    /// one a listing shows.
    pub fn summary(&self) -> String {
        let ordered = self.ordered();
        let Some(first) = ordered.first() else {
            return String::new();
        };
        match ordered.len() {
            1 => first.sentence.clone(),
            n => format!("{} and {} more", first.sentence, n - 1),
        }
    }

    /// The changes with the protected ones first, each group keeping the
    /// deterministic order [`describe`] produced.
    fn ordered(&self) -> Vec<&Change> {
        let mut out: Vec<&Change> = self
            .changes
            .iter()
            .filter(|c| c.touches_protected)
            .collect();
        out.extend(self.changes.iter().filter(|c| !c.touches_protected));
        out
    }
}

/// Renders a change set as text: one sentence per line, protected ones first.
///
/// Returns an empty string for an empty change set; the caller decides what to
/// say when there is nothing to report.
pub fn render_text(set: &ChangeSet) -> String {
    let mut out = String::new();
    for change in set.ordered() {
        out.push_str(&change.sentence);
        out.push('\n');
    }
    out
}

/// Describes the change from `old` to `new` as plain-language sentences.
///
/// Pure: it reads the two models and touches nothing else. The result is
/// deterministic, so golden tests can pin it.
pub fn describe(old: &Model, new: &Model) -> ChangeSet {
    let mut changes = Vec::new();
    let labels = Labels::new([new, old]);
    describe_connection(old, new, &mut changes);
    describe_groups(old, new, &labels, &mut changes);
    describe_devices(old, new, &labels, &mut changes);
    describe_links(old, new, &labels, &mut changes);
    ChangeSet { changes }
}

/// Replaces the key-derived label of every parameter change with the
/// parameter's text from the cached product model, e.g. `Nachtabsenkung on …`
/// becomes `Night setback on …`.
///
/// `models` are the two sides the set was described from, the new side
/// first, then the old (the device is looked up in each, in order, for its
/// `application_ref`). A change whose device has
/// no cached product model, or whose parameter has no text, keeps the label
/// derived from its key: nothing degrades to silence.
///
/// It settles the values first ([`settle_parameters`]): a change whose two
/// sides name the same enum member is dropped, and enum values read as their
/// label with the code after it.
///
/// Then it brings in the parameter calculations ([`compute_parameters`]): a
/// calculation output reads as the value the calculation computes on each
/// side, so an output that changes because one of its inputs did is a change
/// too (issue #712).
pub fn name_parameters(set: &mut ChangeSet, models: [&Model; 2], products: &ProductModels) {
    settle_parameters(set, models, products);
    compute_parameters(set, models, products);
    for change in &mut set.changes {
        if change.kind != ChangeKind::ParameterChanged {
            continue;
        }
        let (Some(device), Some(key)) = (change.device.as_deref(), change.field.as_deref()) else {
            continue;
        };
        let Ok(ia) = device.parse::<IndividualAddress>() else {
            continue;
        };
        let text = models
            .iter()
            .filter_map(|m| m.devices.get(&ia))
            .filter_map(|d| d.device.product.as_ref()?.application_ref.as_deref())
            .filter_map(|app| products.get(app))
            .find_map(|product| {
                let id = key_to_param_id(key)?;
                product.parameters.get(&id)?.text.clone()
            });
        let Some(text) = text else {
            continue;
        };
        let label = parameter_label(key);
        if let Some(rest) = change.sentence.strip_prefix(&label) {
            change.sentence = format!("{}{rest}", text.trim());
        }
    }
}

/// Settles every parameter change against the cached product models (issue
/// #279).
///
/// A device file writes an enum member by its label in the project language
/// and the loader keeps the code when a product model translates it, so one
/// side of a comparison can hold `Fussbodenheizung` and the other `8` for the
/// same member. Such a change is no change and is dropped. A change that
/// remains renders each enum value as its label with the code after it
/// (`Kurzer und langer Tastendruck (5)`); the structured `from` and `to`
/// fields keep the values as the models hold them. A parameter without a
/// cached product model, or not an enumeration, is left as described.
pub fn settle_parameters(set: &mut ChangeSet, models: [&Model; 2], products: &ProductModels) {
    let labels = Labels::new(models);
    set.changes.retain_mut(|change| {
        if change.kind != ChangeKind::ParameterChanged {
            return true;
        }
        let (Some(device), Some(key)) = (change.device.as_deref(), change.field.as_deref()) else {
            return true;
        };
        let Ok(ia) = device.parse::<IndividualAddress>() else {
            return true;
        };
        let Some(def) = parameter_def(models, products, ia, key) else {
            return true;
        };
        if def.labels.is_empty() {
            return true;
        }
        let code = |v: &str| enum_value_code(def, v);
        if let (Some(from), Some(to)) = (change.from.as_deref(), change.to.as_deref())
            && code(from) == code(to)
        {
            return false;
        }
        let shown = |v: &str| shown_enum_value(def, v);
        let device = labels.device(ia);
        let from = change.from.as_deref().map(shown);
        let to = change.to.as_deref().map(shown);
        if let Some(sentence) = parameter_sentence(
            &parameter_label(key),
            &device,
            from.as_deref(),
            to.as_deref(),
        ) {
            change.sentence = sentence;
        }
        true
    });
}

/// Brings the `<ParameterCalculation>` outputs of every device with a
/// parameter change into the set (issue #712). `models` are the new side,
/// then the old.
///
/// Each side is evaluated over the device's cached product model, the same
/// evaluation (and trigger rule) a download runs. An output a calculation
/// computes on either side reads as its effective value on each: when the two
/// differ it is one change, marked with the calculation's id, in place of any
/// change of the value the file stores; when they are the same, a change of
/// the stored value is dropped, as the device does not change. A device whose
/// application differs between the sides, or that has no cached product
/// model, is left as described.
pub fn compute_parameters(set: &mut ChangeSet, models: [&Model; 2], products: &ProductModels) {
    let [new, old] = models;
    let labels = Labels::new(models);
    let devices: BTreeSet<IndividualAddress> = set
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::ParameterChanged)
        .filter_map(|c| c.device.as_deref()?.parse().ok())
        .collect();
    for ia in devices {
        let (Some(after), Some(before)) = (new.devices.get(&ia), old.devices.get(&ia)) else {
            continue;
        };
        let app_of = |d: &LoadedDevice| -> Option<String> {
            d.device.product.as_ref()?.application_ref.clone()
        };
        let Some(app) = app_of(after) else {
            continue;
        };
        if app_of(before).as_deref() != Some(app.as_str()) {
            continue;
        }
        let Some(product) = products.get(&app) else {
            continue;
        };
        if product.calculations.is_empty() {
            continue;
        }
        let eval_after = crate::device_view::Evaluated::of_device(product, &after.device);
        let eval_before = crate::device_view::Evaluated::of_device(product, &before.device);
        let computed_after = eval_after.computed_parameters();
        let computed_before = eval_before.computed_parameters();
        let outputs: BTreeSet<&String> = computed_after
            .keys()
            .chain(computed_before.keys())
            .collect();
        let device_name = labels.device(ia);
        let address = ia.to_string();
        let of_device = |c: &Change| {
            c.kind == ChangeKind::ParameterChanged && c.device.as_deref() == Some(address.as_str())
        };
        for reference in outputs {
            let held = set.changes.iter().position(|c| {
                of_device(c)
                    && c.field.as_deref().map(parameter_identity) == Some(reference.as_str())
            });
            // In the held change's place, else after the device's last one.
            let at = held.or_else(|| set.changes.iter().rposition(&of_device).map(|i| i + 1));
            let held = held.map(|i| set.changes.remove(i));
            let from = eval_before.value(reference);
            let to = eval_after.value(reference);
            if from == to {
                continue;
            }
            let calc = computed_after
                .get(reference)
                .or_else(|| computed_before.get(reference))
                .map(|(calc, _)| calc.as_str())
                .unwrap_or_default();
            let key = held
                .and_then(|c| c.field)
                .or_else(|| {
                    after
                        .device
                        .lock
                        .parameters
                        .get(reference.as_str())
                        .map(|p| format!("{}@{reference}", p.key))
                })
                .unwrap_or_else(|| format!("{reference}@{reference}"));
            // Shown as a set value of the parameter is ([`settle_parameters`]).
            let shown = |v: Option<&str>| -> Option<String> {
                let v = v?;
                Some(match parameter_def(models, products, ia, &key) {
                    Some(def) if !def.labels.is_empty() => shown_enum_value(def, v),
                    _ => v.to_string(),
                })
            };
            let Some(sentence) = parameter_sentence(
                &parameter_label(&key),
                &device_name,
                shown(from.as_deref()).as_deref(),
                shown(to.as_deref()).as_deref(),
            ) else {
                continue;
            };
            let change = Change::new(
                ChangeKind::ParameterChanged,
                format!("{sentence} Computed by calculation {calc}."),
            )
            .with_device(ia)
            .with_field(key, from, to);
            let at = at.unwrap_or(set.changes.len()).min(set.changes.len());
            set.changes.insert(at, change);
        }
    }
}

/// The code of enumeration value `v` of `def`, written as a label or a code.
fn enum_value_code(def: &ParamDef, v: &str) -> String {
    enum_code(&def.labels, v)
        .map(|c| c.to_string())
        .unwrap_or_else(|| v.trim().to_string())
}

/// How a parameter change shows value `v` of `def`: an enumeration member as
/// its label with the code after it (`Kurzer und langer Tastendruck (5)`),
/// anything else as it is.
fn shown_enum_value(def: &ParamDef, v: &str) -> String {
    let c = enum_value_code(def, v);
    match enum_label(&def.labels, &c) {
        Some(label) => format!("{} ({c})", label.trim()),
        None => v.to_string(),
    }
}

/// The product-model definition of parameter `key` on device `ia`, looked
/// up through the device's `application_ref` in each model in turn.
fn parameter_def<'a>(
    models: [&Model; 2],
    products: &'a ProductModels,
    ia: IndividualAddress,
    key: &str,
) -> Option<&'a ParamDef> {
    models
        .iter()
        .filter_map(|m| m.devices.get(&ia))
        .filter_map(|d| d.device.product.as_ref()?.application_ref.as_deref())
        .find_map(|app| products.param_def(app, key))
}

/// The sentence of a parameter set, changed or cleared on `device`; `None`
/// when neither side has a value.
fn parameter_sentence(
    label: &str,
    device: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> Option<String> {
    Some(match (before, after) {
        (Some(from), Some(to)) => format!("{label} on {device}: {from} to {to}."),
        (None, Some(to)) => format!("{label} on {device} is set to {to}."),
        (Some(from), None) => {
            format!("{label} on {device} goes back to the vendor default (was {from}).")
        }
        (None, None) => return None,
    })
}

/// The most items [`summarize`] names before it counts the rest.
const SUMMARY_ITEMS: usize = 4;

/// The most links or parameters of one device [`summarize`] spells out.
const SUMMARY_PER_DEVICE: usize = 3;

/// A homeowner's summary of `set` (issue #306): one or two sentences in
/// rooms, device, channel and group names, without a group address,
/// individual address, com-object number or parameter key unless the item
/// has no name. `models` are the two sides the set was described from, the
/// new side first.
///
/// It says what changes, not how it reaches a device: the caller adds that.
/// A change touching a protected group address adds a sentence saying so.
pub fn summarize(set: &ChangeSet, models: [&Model; 2]) -> String {
    if set.is_empty() {
        return "Nothing changes.".to_string();
    }
    let labels = Labels::plain(models);
    let mut items: Vec<String> = Vec::new();
    // Group-address changes, one item per address.
    let mut groups: BTreeMap<String, Vec<&Change>> = BTreeMap::new();
    let mut devices: Vec<(String, Vec<&Change>)> = Vec::new();
    let mut connection = false;
    for change in &set.changes {
        if change.kind == ChangeKind::ConnectionChanged {
            connection = true;
        } else if let Some(device) = &change.device {
            match devices.iter_mut().find(|(d, _)| d == device) {
                Some((_, list)) => list.push(change),
                None => devices.push((device.clone(), vec![change])),
            }
        } else if let Some(group) = &change.group {
            groups.entry(group.clone()).or_default().push(change);
        }
    }
    if connection {
        items.push("the bus connection settings change".to_string());
    }
    for (address, changes) in &groups {
        let Ok(ga) = address.parse::<GroupAddress>() else {
            continue;
        };
        items.push(group_item(&labels, ga, changes));
    }
    for (address, changes) in &devices {
        let Ok(ia) = address.parse::<IndividualAddress>() else {
            continue;
        };
        items.extend(device_items(&labels, ia, changes));
    }
    let total = items.len();
    let mut shown: Vec<String> = items.into_iter().take(SUMMARY_ITEMS).collect();
    if total > SUMMARY_ITEMS {
        shown.push(format!("{} more change(s)", total - SUMMARY_ITEMS));
    }
    let mut out = capitalize(&join_and(&shown, "; ", "; and "));
    out.push('.');
    if set.touches_protected() {
        out.push_str(
            " Part of this concerns a protected safety function, so it needs the human's \
             explicit yes.",
        );
    }
    out
}

/// One item of [`summarize`] for the changes of one group address.
fn group_item(labels: &Labels<'_>, ga: GroupAddress, changes: &[&Change]) -> String {
    let label = labels.ga(ga);
    let kinds: Vec<ChangeKind> = changes.iter().map(|c| c.kind).collect();
    if kinds.contains(&ChangeKind::GroupAdded) {
        return format!("a new function {label} is added");
    }
    if kinds.contains(&ChangeKind::GroupRemoved) {
        return format!("the function {label} is removed");
    }
    if let Some(rename) = changes.iter().find(|c| c.kind == ChangeKind::GroupRenamed) {
        let old = rename.from.as_deref().map(str::trim).unwrap_or_default();
        let new = rename.to.as_deref().map(str::trim).unwrap_or_default();
        return match (old.is_empty(), new.is_empty()) {
            (false, false) => format!("{old} is renamed to {new}"),
            (true, false) => format!("a function is now called {new}"),
            (false, true) => format!("{old} loses its name"),
            (true, true) => format!("{label} is renamed"),
        };
    }
    if kinds.contains(&ChangeKind::GroupSecurityChanged) {
        return format!("{label} changes its encryption");
    }
    format!("the details of {label} change")
}

/// The items of [`summarize`] for the changes of one device: its own
/// fields, its links and its settings.
fn device_items(labels: &Labels<'_>, ia: IndividualAddress, changes: &[&Change]) -> Vec<String> {
    let device = labels.device(ia);
    let mut out = Vec::new();
    let mut links = Vec::new();
    let mut settings = Vec::new();
    for change in changes {
        match change.kind {
            ChangeKind::LinkAdded | ChangeKind::LinkRemoved => links.push(*change),
            ChangeKind::ParameterChanged => settings.push(*change),
            ChangeKind::DeviceAdded => out.push(format!("{device} is added")),
            ChangeKind::DeviceRemoved => out.push(format!("{device} is removed")),
            ChangeKind::DeviceRenamed => {
                let old = change.from.as_deref().map(str::trim).unwrap_or_default();
                let new = change.to.as_deref().map(str::trim).unwrap_or_default();
                out.push(match (old.is_empty(), new.is_empty()) {
                    (false, false) => format!("{old} is renamed to {new}"),
                    (true, false) => format!("a device gets the name {new}"),
                    _ => format!("{device} is renamed"),
                });
            }
            ChangeKind::DeviceMoved => out.push(format!(
                "{device} moves to {}",
                change.to.as_deref().unwrap_or("another room")
            )),
            ChangeKind::DeviceProductChanged => {
                out.push(format!("{device} is recorded as another product"));
            }
            ChangeKind::ChannelRenamed => {
                let new = change.to.as_deref().map(str::trim).unwrap_or_default();
                out.push(if new.is_empty() {
                    format!("a channel of {device} loses its name")
                } else {
                    format!("a channel of {device} is renamed to {new}")
                });
            }
            ChangeKind::ObjectSecurityChanged => {
                out.push(format!("{device} changes the encryption of some functions"));
            }
            ChangeKind::InterfaceChanged => {
                out.push(format!("the network settings of {device} change"));
            }
            _ => {}
        }
    }
    if !links.is_empty() {
        if links.len() <= SUMMARY_PER_DEVICE {
            out.extend(links.iter().filter_map(|c| plain_link(labels, ia, c)));
        } else {
            out.push(format!("{} connections of {device} change", links.len()));
        }
    }
    if !settings.is_empty() {
        let names: Vec<String> = settings.iter().map(|c| setting_label(c, &device)).collect();
        out.push(if settings.len() < SUMMARY_PER_DEVICE {
            let plain: Vec<String> = settings
                .iter()
                .map(|c| first_sentence(&c.sentence))
                .collect();
            join_and(&plain, "; ", "; and ")
        } else {
            format!(
                "{} settings of {device} change ({} and more)",
                settings.len(),
                names[..2].join(", ")
            )
        });
    }
    out
}

/// A link change as a phrase of [`summarize`]: `Rocker 1 on Hallway push
/// button now switches Porch light`, named as [`link_sentence`] names it with
/// the plain labels.
fn plain_link(labels: &Labels<'_>, ia: IndividualAddress, change: &Change) -> Option<String> {
    let object = change.object?;
    let role = change.role?;
    let ga = change.group.as_deref()?.parse::<GroupAddress>().ok()?;
    let [new, old] = labels.models;
    let mut names = object_names(old, ia);
    names.extend(object_names(new, ia));
    let device = new
        .devices
        .get(&ia)
        .or_else(|| old.devices.get(&ia))
        .map(|l| &l.device);
    let sentence = link_sentence(
        labels,
        device,
        ia,
        names.get(&object).map(String::as_str),
        object,
        role,
        ga,
        change.kind == ChangeKind::LinkAdded,
    );
    Some(sentence.trim_end_matches('.').to_string())
}

/// The parameter's label in a parameter change's sentence: the text before
/// ` on <device>`.
fn setting_label(change: &Change, device: &str) -> String {
    let marker = format!(" on {device}");
    match change.sentence.find(&marker) {
        Some(at) => change.sentence[..at].to_string(),
        None => change
            .field
            .as_deref()
            .map(parameter_label)
            .unwrap_or_else(|| "a setting".to_string()),
    }
}

/// The first sentence of `text` without its final period: what a summary
/// quotes of a parameter change (the calculation note after it names an ETS
/// id).
fn first_sentence(text: &str) -> String {
    let first = text.split(". ").next().unwrap_or(text);
    first.trim_end_matches('.').to_string()
}

/// `a`, `a and b`, `a, b and c` with `sep` and `last` as the separators.
fn join_and(items: &[String], sep: &str, last: &str) -> String {
    match items.split_last() {
        None => String::new(),
        Some((only, [])) => only.clone(),
        Some((tail, rest)) => format!("{}{last}{tail}", rest.join(sep)),
    }
}

/// `text` with its first letter in upper case.
fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Labels: how a thing is named in a sentence.
// ---------------------------------------------------------------------------

/// How the sentences of one comparison name group addresses and devices
/// (issue #306): by name, with the address only for an unnamed, ambiguous or
/// protected item.
pub struct Labels<'a> {
    /// The new side, then the old.
    models: [&'a Model; 2],
    /// How many distinct group addresses carry each name (trimmed,
    /// lowercased) across both models.
    group_names: BTreeMap<String, BTreeSet<GroupAddress>>,
    /// How many distinct devices carry each name across both models.
    device_names: BTreeMap<String, BTreeSet<IndividualAddress>>,
    /// Whether a protected group address carries its address (the
    /// sentences); the plain [`summarize`] leaves it out.
    protect: bool,
}

impl<'a> Labels<'a> {
    /// The labels of a comparison of `models` (new side first).
    pub fn new(models: [&'a Model; 2]) -> Self {
        let mut group_names: BTreeMap<String, BTreeSet<GroupAddress>> = BTreeMap::new();
        let mut device_names: BTreeMap<String, BTreeSet<IndividualAddress>> = BTreeMap::new();
        for model in models {
            for (ga, group) in &model.groups.groups {
                let name = name_key(&group.name);
                if !name.is_empty() {
                    group_names.entry(name).or_default().insert(*ga);
                }
            }
            for (ia, loaded) in &model.devices {
                let name = name_key(&loaded.device.name);
                if !name.is_empty() {
                    device_names.entry(name).or_default().insert(*ia);
                }
            }
        }
        Labels {
            models,
            group_names,
            device_names,
            protect: true,
        }
    }

    /// The labels of [`summarize`]: a protected group address is called by
    /// its name alone too.
    pub fn plain(models: [&'a Model; 2]) -> Self {
        Labels {
            protect: false,
            ..Labels::new(models)
        }
    }

    /// A group address as a human reads it: `Porch light`, `Porch light
    /// (0/0/4)` when the name is not unique or the address is protected, or
    /// just the address when the model has no name for it.
    pub fn ga(&self, ga: GroupAddress) -> String {
        for model in self.models {
            if let Some(group) = model.groups.groups.get(&ga) {
                let name = group.name.trim();
                if !name.is_empty() {
                    return self.group_named(ga, name);
                }
            }
        }
        ga.to_string()
    }

    /// Group address `ga` called `name` (or its address when `name` is
    /// empty), with the address when the name is ambiguous or `ga` is
    /// protected.
    fn group_named(&self, ga: GroupAddress, name: &str) -> String {
        let name = name.trim();
        if name.is_empty() {
            return ga.to_string();
        }
        let ambiguous = self
            .group_names
            .get(&name_key(name))
            .is_some_and(|set| set.len() > 1);
        if ambiguous || (self.protect && is_protected(self.models, ga)) {
            format!("{name} ({ga})")
        } else {
            name.to_string()
        }
    }

    /// A device as a human reads it: `Hallway push button`, `Hallway push
    /// button (1.1.5)` when another device has the same name, or the bare
    /// address when it has none.
    pub fn device(&self, ia: IndividualAddress) -> String {
        for model in self.models {
            if let Some(loaded) = model.devices.get(&ia) {
                let name = loaded.device.name.trim();
                if !name.is_empty() {
                    return self.device_named(ia, name);
                }
            }
        }
        ia.to_string()
    }

    /// Device `ia` called `name` (or its address when `name` is empty), with
    /// the address when the name is ambiguous.
    fn device_named(&self, ia: IndividualAddress, name: &str) -> String {
        let name = name.trim();
        if name.is_empty() {
            return ia.to_string();
        }
        let ambiguous = self
            .device_names
            .get(&name_key(name))
            .is_some_and(|set| set.len() > 1);
        if ambiguous {
            format!("{name} ({ia})")
        } else {
            name.to_string()
        }
    }
}

/// The key two names are compared by: trimmed and lowercased.
fn name_key(name: &str) -> String {
    name.trim().to_lowercase()
}

/// What a com object is called in a sentence: the name the device file's
/// link gives it, else the vendor's object text, else its function text. A
/// vendor text that only repeats the channel's name or text is skipped for
/// the next one ("Jalousie 1" on channel "Jalousie 1" reads as its function,
/// "Langzeitbetrieb").
fn object_label(device: Option<&Device>, link_name: Option<&str>, object: u16) -> Option<String> {
    if let Some(name) = link_name.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(name.to_string());
    }
    let device = device?;
    let co = device.com_objects.get(&object)?;
    let channel: Vec<&str> = co
        .channel
        .as_deref()
        .and_then(|id| device.channels.get(id))
        .map(|ch| {
            [Some(ch.name.as_str()), ch.text.as_deref()]
                .into_iter()
                .flatten()
                .map(str::trim)
                .collect()
        })
        .unwrap_or_default();
    let texts: Vec<&str> = [co.text.as_deref(), co.function.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    texts
        .iter()
        .find(|t| !channel.contains(t))
        .or_else(|| texts.first())
        .map(|t| (*t).to_string())
}

/// The channel a com object belongs to, by the user's name, else the
/// vendor's text; `None` when the channel has neither (its handle is an id,
/// not a name).
fn channel_of_object(device: Option<&Device>, object: u16) -> Option<String> {
    let device = device?;
    let key = device.com_objects.get(&object)?.channel.as_deref()?;
    let channel = device.channels.get(key)?;
    [Some(channel.name.as_str()), channel.text.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whether a group address is protected in either model.
fn is_protected(models: [&Model; 2], ga: GroupAddress) -> bool {
    models
        .iter()
        .any(|m| m.groups.groups.get(&ga).is_some_and(|g| g.protected))
}

/// A location as prose: `Wohnzimmer, EG`, `Wohnzimmer`, `EG`, or
/// `an unknown location` when neither field is set.
fn location_label(location: Option<&Location>) -> String {
    let floor = location
        .and_then(|l| l.floor.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let room = location
        .and_then(|l| l.room.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (room, floor) {
        (Some(r), Some(f)) => format!("{r}, {f}"),
        (Some(r), None) => r.to_string(),
        (None, Some(f)) => f.to_string(),
        (None, None) => "an unknown location".to_string(),
    }
}

/// A product as prose: the order number if there is one, else the manufacturer
/// reference, else the application, else `an unnamed product`.
fn product_label(product: Option<&Product>) -> String {
    let Some(product) = product else {
        return "no product".to_string();
    };
    for field in [
        product.order_number.as_deref(),
        product.manufacturer_ref.as_deref(),
        product.application_ref.as_deref(),
        product.hardware_ref.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let field = field.trim();
        if !field.is_empty() {
            return match product.manufacturer.as_deref().map(str::trim) {
                Some(m) if !m.is_empty() => format!("{m} {field}"),
                _ => field.to_string(),
            };
        }
    }
    match product.manufacturer.as_deref().map(str::trim) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => "an unnamed product".to_string(),
    }
}

/// A parameter key rendered for a human: the slug before the `@`, with dashes
/// turned into spaces and the first letter capitalized. Falls back to the whole
/// key when it carries no slug.
pub(crate) fn parameter_label(key: &str) -> String {
    let slug = key.split('@').next().unwrap_or(key).trim();
    if slug.is_empty() {
        return key.to_string();
    }
    let words = slug.replace(['-', '_'], " ");
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => key.to_string(),
    }
}

/// The sentence of a rename: `Group address Porch light is now called "Porch
/// lamp".` An item without a name so far is called by `address`; one whose
/// name is cleared keeps its address in the sentence, the only thing that
/// names it from now on.
fn renamed_sentence(noun: &str, old: &str, address: &str, unnamed: bool, new: &str) -> String {
    let new = new.trim();
    match (unnamed, new.is_empty()) {
        (true, _) => format!("{noun} {address} is now called {new:?}."),
        (false, true) if old.contains(address) => format!("{noun} {old} no longer has a name."),
        (false, true) => format!("{noun} {old} ({address}) no longer has a name."),
        (false, false) => format!("{noun} {old} is now called {new:?}."),
    }
}

/// Quotes a value for a sentence, rendering an absent one as `nothing`.
fn value_or_nothing(value: Option<&str>) -> String {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => format!("{v:?}"),
        None => "nothing".to_string(),
    }
}

// ---------------------------------------------------------------------------
// The connection block.
// ---------------------------------------------------------------------------

/// Renders changes to `bussard.toml`'s `connection:` block.
fn describe_connection(old: &Model, new: &Model, out: &mut Vec<Change>) {
    let (a, b) = (&old.config.connection, &new.config.connection);
    if a.transport != b.transport {
        let from = transport_label(a.transport);
        let to = transport_label(b.transport);
        out.push(
            Change::new(
                ChangeKind::ConnectionChanged,
                format!("The bus connection changed from {from} to {to}."),
            )
            .with_field("transport", Some(from.to_string()), Some(to.to_string())),
        );
    }
    if a.gateway != b.gateway {
        out.push(
            Change::new(
                ChangeKind::ConnectionChanged,
                format!(
                    "The gateway changed from {} to {}.",
                    value_or_nothing(a.gateway.as_deref()),
                    value_or_nothing(b.gateway.as_deref())
                ),
            )
            .with_field("gateway", a.gateway.clone(), b.gateway.clone()),
        );
    }
    if a.multicast != b.multicast {
        out.push(
            Change::new(
                ChangeKind::ConnectionChanged,
                format!(
                    "The routing multicast address changed from {} to {}.",
                    value_or_nothing(a.multicast.as_deref()),
                    value_or_nothing(b.multicast.as_deref())
                ),
            )
            .with_field("multicast", a.multicast.clone(), b.multicast.clone()),
        );
    }
    if a.admit_tunnel_senders != b.admit_tunnel_senders {
        let state = |on: bool| if on { "on" } else { "off" };
        out.push(
            Change::new(
                ChangeKind::ConnectionChanged,
                format!(
                    "Admitting the tunnelling addresses as secure senders is now {}.",
                    state(b.admit_tunnel_senders)
                ),
            )
            .with_field(
                "admit_tunnel_senders",
                Some(state(a.admit_tunnel_senders).to_string()),
                Some(state(b.admit_tunnel_senders).to_string()),
            ),
        );
    }
}

/// The transport as a human reads it.
fn transport_label(transport: crate::schema::Transport) -> &'static str {
    match transport {
        crate::schema::Transport::Tunnel => "a tunnel",
        crate::schema::Transport::Routing => "routing (multicast)",
    }
}

// ---------------------------------------------------------------------------
// Group addresses.
// ---------------------------------------------------------------------------

/// Renders every difference in `groups.toml`, by address.
fn describe_groups(old: &Model, new: &Model, labels: &Labels<'_>, out: &mut Vec<Change>) {
    let models = [new, old];
    let addresses: BTreeSet<GroupAddress> = old
        .groups
        .groups
        .keys()
        .chain(new.groups.groups.keys())
        .copied()
        .collect();

    for ga in addresses {
        let before = old.groups.groups.get(&ga);
        let after = new.groups.groups.get(&ga);
        let protected = is_protected(models, ga);
        match (before, after) {
            (None, Some(group)) => out.push(
                Change::new(
                    ChangeKind::GroupAdded,
                    added_group_sentence(labels, ga, group),
                )
                .with_group(ga)
                .protected_if(protected),
            ),
            (Some(group), None) => out.push(
                Change::new(
                    ChangeKind::GroupRemoved,
                    removed_group_sentence(labels, ga, group),
                )
                .with_group(ga)
                .protected_if(protected),
            ),
            (Some(a), Some(b)) => group_field_changes(labels, ga, a, b, protected, out),
            (None, None) => {}
        }
    }
}

/// `Porch light` for a group we have the definition of: its name, with the
/// address when the name is ambiguous or the group is protected, or the
/// address alone when it has no name.
fn label_for_group(labels: &Labels<'_>, ga: GroupAddress, group: &Group) -> String {
    labels.group_named(ga, &group.name)
}

/// The sentence for a removed group address: `Group address Porch light
/// removed.`, or the address when it had no name.
fn removed_group_sentence(labels: &Labels<'_>, ga: GroupAddress, group: &Group) -> String {
    format!(
        "Group address {} removed.",
        label_for_group(labels, ga, group)
    )
}

/// The sentence for a newly added group address.
fn added_group_sentence(labels: &Labels<'_>, ga: GroupAddress, group: &Group) -> String {
    let label = label_for_group(labels, ga, group);
    match group.dpt {
        Some(dpt) => format!("New group address {label}, type {dpt}."),
        None => format!("New group address {label}."),
    }
}

/// Renders the per-field differences of a group address present in both models.
fn group_field_changes(
    labels: &Labels<'_>,
    ga: GroupAddress,
    a: &Group,
    b: &Group,
    protected: bool,
    out: &mut Vec<Change>,
) {
    if a.name != b.name {
        out.push(
            Change::new(
                ChangeKind::GroupRenamed,
                renamed_sentence(
                    "Group address",
                    &label_for_group(labels, ga, a),
                    &ga.to_string(),
                    a.name.trim().is_empty(),
                    &b.name,
                ),
            )
            .with_group(ga)
            .with_field("name", Some(a.name.clone()), Some(b.name.clone()))
            .protected_if(protected),
        );
    }
    if a.dpt != b.dpt {
        let label = label_for_group(labels, ga, b);
        let sentence = match (a.dpt, b.dpt) {
            (Some(from), Some(to)) => {
                format!("{label} changes type from {from} to {to}.")
            }
            (None, Some(to)) => format!("{label} now has type {to}."),
            (Some(from), None) => format!("{label} no longer has a type (was {from})."),
            (None, None) => unreachable!("dpt differs, so one side is Some"),
        };
        out.push(
            Change::new(ChangeKind::GroupDptChanged, sentence)
                .with_group(ga)
                .with_field(
                    "dpt",
                    a.dpt.map(|d| d.to_string()),
                    b.dpt.map(|d| d.to_string()),
                )
                .protected_if(protected),
        );
    }
    if a.description != b.description {
        let label = label_for_group(labels, ga, b);
        let sentence = match b
            .description
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(to) => format!("The note on {label} is now {to:?}."),
            None => format!("The note on {label} was removed."),
        };
        out.push(
            Change::new(ChangeKind::GroupDescriptionChanged, sentence)
                .with_group(ga)
                .with_field("description", a.description.clone(), b.description.clone())
                .protected_if(protected),
        );
    }
    if a.secure != b.secure {
        let label = label_for_group(labels, ga, b);
        let sentence = if b.secure {
            format!("{label} now runs secured (KNX Data Secure on).")
        } else {
            format!("{label} now runs plain (KNX Data Secure off).")
        };
        out.push(
            Change::new(ChangeKind::GroupSecurityChanged, sentence)
                .with_group(ga)
                .with_field(
                    "secure",
                    Some(a.secure.to_string()),
                    Some(b.secure.to_string()),
                )
                .protected_if(protected),
        );
    }
    if a.protected != b.protected {
        let label = label_for_group(labels, ga, b);
        let sentence = if b.protected {
            format!("{label} is now protected against casual writes.")
        } else {
            format!("{label} is no longer protected against casual writes.")
        };
        out.push(
            Change::new(ChangeKind::GroupProtectionChanged, sentence)
                .with_group(ga)
                .with_field(
                    "protected",
                    Some(a.protected.to_string()),
                    Some(b.protected.to_string()),
                )
                .protected(),
        );
    }
}

// ---------------------------------------------------------------------------
// Devices.
// ---------------------------------------------------------------------------

/// Renders every difference in `devices/*.toml`, by individual address.
fn describe_devices(old: &Model, new: &Model, labels: &Labels<'_>, out: &mut Vec<Change>) {
    let addresses: BTreeSet<IndividualAddress> = old
        .devices
        .keys()
        .chain(new.devices.keys())
        .copied()
        .collect();

    for ia in addresses {
        match (old.devices.get(&ia), new.devices.get(&ia)) {
            (None, Some(loaded)) => out.push(
                Change::new(
                    ChangeKind::DeviceAdded,
                    format!(
                        "New device {} in {}.",
                        labels.device(ia),
                        location_label(loaded.device.location.as_ref())
                    ),
                )
                .with_device(ia),
            ),
            (Some(_), None) => out.push(
                Change::new(
                    ChangeKind::DeviceRemoved,
                    format!("Device {} is gone from the model.", labels.device(ia)),
                )
                .with_device(ia),
            ),
            (Some(a), Some(b)) => device_field_changes(labels, ia, a, b, out),
            (None, None) => {}
        }
    }
}

/// Renders the per-field differences of a device present in both models.
fn device_field_changes(
    labels: &Labels<'_>,
    ia: IndividualAddress,
    a: &LoadedDevice,
    b: &LoadedDevice,
    out: &mut Vec<Change>,
) {
    let (a, b) = (&a.device, &b.device);
    if a.name != b.name {
        out.push(
            Change::new(
                ChangeKind::DeviceRenamed,
                renamed_sentence(
                    "Device",
                    &labels.device_named(ia, &a.name),
                    &ia.to_string(),
                    a.name.trim().is_empty(),
                    &b.name,
                ),
            )
            .with_device(ia)
            .with_field("name", Some(a.name.clone()), Some(b.name.clone())),
        );
    }
    if a.location != b.location {
        let from = location_label(a.location.as_ref());
        let to = location_label(b.location.as_ref());
        let name = labels.device(ia);
        out.push(
            Change::new(
                ChangeKind::DeviceMoved,
                format!("{name} moved from {from} to {to}."),
            )
            .with_device(ia)
            .with_field("location", Some(from), Some(to)),
        );
    }
    if a.product != b.product {
        let from = product_label(a.product.as_ref());
        let to = product_label(b.product.as_ref());
        let name = labels.device(ia);
        out.push(
            Change::new(
                ChangeKind::DeviceProductChanged,
                format!("{name} is now a {to} (was {from})."),
            )
            .with_device(ia)
            .with_field("product", Some(from), Some(to)),
        );
    }
    let device = labels.device(ia);
    describe_channels(&device, ia, a, b, out);
    describe_parameters(&device, ia, a, b, out);
    describe_object_security(&device, ia, a, b, out);
    describe_knxnet(&device, ia, a, b, out);
}

/// Renders the differences of the `[knxnet]` table of an IP interface (issue
/// #391), one sentence each: `Interface KNX IP Interface: tunnel address
/// 1.1.30 added.` (`device` is the device's label).
fn describe_knxnet(
    device: &str,
    ia: IndividualAddress,
    a: &Device,
    b: &Device,
    out: &mut Vec<Change>,
) {
    use crate::knxnet::{KnxnetConfig, join_addresses};
    if a.knxnet == b.knxnet {
        return;
    }
    let head = format!("Interface {device}");
    let change = |field: &str, sentence: String, from: Option<String>, to: Option<String>| {
        Change::new(ChangeKind::InterfaceChanged, format!("{head}: {sentence}."))
            .with_device(ia)
            .with_field(
                if field.is_empty() {
                    "knxnet".to_string()
                } else {
                    format!("knxnet.{field}")
                },
                from,
                to,
            )
    };
    let summary = |k: &KnxnetConfig| {
        let mut parts = vec![format!("assignment {}", k.assignment.label())];
        if let Some(addr) = k.address {
            parts.push(format!("address {addr}"));
        }
        if !k.tunnels.is_empty() {
            parts.push(format!("tunnel addresses {}", join_addresses(&k.tunnels)));
        }
        parts.join(", ")
    };
    let (old, new) = match (&a.knxnet, &b.knxnet) {
        (None, Some(k)) => {
            out.push(change(
                "",
                format!("KNXnet/IP settings added ({})", summary(k)),
                None,
                Some(summary(k)),
            ));
            return;
        }
        (Some(k), None) => {
            out.push(change(
                "",
                "KNXnet/IP settings removed from the model; bussard no longer manages the \
                 interface's IP settings and tunnel addresses"
                    .to_string(),
                Some(summary(k)),
                None,
            ));
            return;
        }
        (Some(old), Some(new)) => (old, new),
        (None, None) => return,
    };
    if old.assignment != new.assignment {
        out.push(change(
            "assignment",
            format!(
                "IP assignment is now {} (was {})",
                new.assignment.label(),
                old.assignment.label()
            ),
            Some(old.assignment.label().to_string()),
            Some(new.assignment.label().to_string()),
        ));
    }
    for (field, label, before, after) in [
        ("address", "static IP address", old.address, new.address),
        ("netmask", "static netmask", old.netmask, new.netmask),
        (
            "gateway",
            "static default gateway",
            old.gateway,
            new.gateway,
        ),
    ] {
        let sentence = match (before, after) {
            (Some(x), Some(y)) if x != y => format!("{label} is now {y} (was {x})"),
            (None, Some(y)) => format!("{label} set to {y}"),
            (Some(x), None) => format!("{label} {x} cleared"),
            _ => continue,
        };
        out.push(change(
            field,
            sentence,
            before.map(|v| v.to_string()),
            after.map(|v| v.to_string()),
        ));
    }
    if old.friendly_name != new.friendly_name {
        let sentence = match (&old.friendly_name, &new.friendly_name) {
            (Some(x), Some(y)) => format!("friendly name is now {y:?} (was {x:?})"),
            (None, Some(y)) => format!("friendly name set to {y:?}"),
            (Some(x), None) => format!("friendly name {x:?} no longer managed"),
            (None, None) => String::new(),
        };
        out.push(change(
            "friendly_name",
            sentence,
            old.friendly_name.clone(),
            new.friendly_name.clone(),
        ));
    }
    for added in new.tunnels.iter().filter(|t| !old.tunnels.contains(t)) {
        out.push(change(
            "tunnels",
            format!("tunnel address {added} added"),
            None,
            Some(added.to_string()),
        ));
    }
    for removed in old.tunnels.iter().filter(|t| !new.tunnels.contains(t)) {
        out.push(change(
            "tunnels",
            format!("tunnel address {removed} removed"),
            Some(removed.to_string()),
            None,
        ));
    }
    let same_set = old.tunnels.len() == new.tunnels.len()
        && old.tunnels.iter().all(|t| new.tunnels.contains(t));
    if same_set && old.tunnels != new.tunnels {
        out.push(change(
            "tunnels",
            format!(
                "tunnel addresses reordered to {} (slot order)",
                join_addresses(&new.tunnels)
            ),
            Some(join_addresses(&old.tunnels)),
            Some(join_addresses(&new.tunnels)),
        ));
    }
}

/// Renders the com-objects whose `secure` flag changed (issue #331), one
/// sentence per direction: `Kitchen actuator: object 12 now runs plain (KNX
/// Data Secure off).` (`device` is the device's label).
fn describe_object_security(
    device: &str,
    ia: IndividualAddress,
    a: &Device,
    b: &Device,
    out: &mut Vec<Change>,
) {
    let mut on: Vec<u16> = Vec::new();
    let mut off: Vec<u16> = Vec::new();
    for (number, after) in &b.com_objects {
        let Some(before) = a.com_objects.get(number) else {
            continue;
        };
        match (before.secure, after.secure) {
            (false, true) => on.push(*number),
            (true, false) => off.push(*number),
            _ => {}
        }
    }
    for (objects, secure) in [(off, false), (on, true)] {
        if objects.is_empty() {
            continue;
        }
        let list: Vec<String> = objects.iter().map(u16::to_string).collect();
        let noun = if objects.len() == 1 {
            "object"
        } else {
            "objects"
        };
        let verb = if objects.len() == 1 { "runs" } else { "run" };
        let how = if secure {
            "secured (KNX Data Secure on)"
        } else {
            "plain (KNX Data Secure off)"
        };
        out.push(
            Change::new(
                ChangeKind::ObjectSecurityChanged,
                format!("{device}: {noun} {} now {verb} {how}.", list.join(", ")),
            )
            .with_device(ia)
            .with_field(
                format!("objects.{}.secure", list.join(",")),
                Some((!secure).to_string()),
                Some(secure.to_string()),
            ),
        );
    }
}

/// Renders channel renames (a channel added or removed comes with the
/// regenerated com-object table, which is not an edit). `device` is the
/// device's label.
fn describe_channels(
    device: &str,
    ia: IndividualAddress,
    a: &Device,
    b: &Device,
    out: &mut Vec<Change>,
) {
    for (key, after) in &b.channels {
        let Some(before) = a.channels.get(key) else {
            continue;
        };
        if before.name == after.name {
            continue;
        }
        // A channel is called by its old name, else the vendor's text, else
        // its handle (issue #306).
        let old = [Some(before.name.as_str()), before.text.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map_or_else(|| b.channel_handle(key), |s| format!("{s:?}"));
        out.push(
            Change::new(
                ChangeKind::ChannelRenamed,
                format!(
                    "Channel {old} on {device} is now called {}.",
                    value_or_nothing(Some(&after.name)),
                ),
            )
            .with_device(ia)
            .with_field(
                format!("channels.{key}"),
                Some(before.name.clone()),
                Some(after.name.clone()),
            ),
        );
    }
}

/// Renders parameter values set, changed or cleared on a device.
///
/// A parameter is identified by its ref when its key carries one
/// (`<slug>@<ref>`), by the key otherwise (issue #375): the same ref can sit
/// under two spellings on the two sides (`label@R` written by the MCP server,
/// `page-label@R` by an import, `hidden@R` from an import while the
/// configuration hid it), and that is one parameter, not a removal and an
/// addition. A ref with the same value on both sides is no change; different
/// values are one change whose `field` is the shown spelling: the after
/// side's visible key, else the before side's, else a `hidden@` one.
/// `device` is the device's label.
fn describe_parameters(
    device: &str,
    ia: IndividualAddress,
    a: &Device,
    b: &Device,
    out: &mut Vec<Change>,
) {
    let before_by_id = parameters_by_identity(&a.parameters);
    let after_by_id = parameters_by_identity(&b.parameters);
    let ids: BTreeSet<&str> = before_by_id
        .keys()
        .chain(after_by_id.keys())
        .copied()
        .collect();
    for id in ids {
        let before = before_by_id.get(id).copied();
        let after = after_by_id.get(id).copied();
        let (before_value, after_value) = (before.map(|(_, v)| v), after.map(|(_, v)| v));
        if before_value == after_value {
            continue;
        }
        let Some(key) = visible_key(after)
            .or_else(|| visible_key(before))
            .or_else(|| after.map(|(k, _)| k))
            .or_else(|| before.map(|(k, _)| k))
        else {
            continue;
        };
        let Some(sentence) = parameter_sentence(
            &parameter_label(key),
            device,
            before_value.map(String::as_str),
            after_value.map(String::as_str),
        ) else {
            continue;
        };
        out.push(
            Change::new(ChangeKind::ParameterChanged, sentence)
                .with_device(ia)
                .with_field(key.clone(), before_value.cloned(), after_value.cloned()),
        );
    }
}

/// The key of a side's value when it is a visible one (not `hidden@`).
fn visible_key<'a>(side: Option<(&'a String, &'a String)>) -> Option<&'a String> {
    side.and_then(|(k, _)| (!crate::files::is_hidden_mem_key(k)).then_some(k))
}

/// What identifies a parameter across two models: the ref of a
/// `<slug>@<ref>` key, else the key itself.
fn parameter_identity(key: &str) -> &str {
    match key.split_once('@') {
        Some((_, reference)) if !reference.is_empty() => reference,
        _ => key,
    }
}

/// A device's stored parameter values by [`parameter_identity`], each with
/// the key it sits under. Where one ref sits under two keys (a `hidden@` one
/// next to a visible one, before a save settles it), the visible key wins,
/// as it does on disk.
fn parameters_by_identity(
    parameters: &BTreeMap<String, String>,
) -> BTreeMap<&str, (&String, &String)> {
    let mut out: BTreeMap<&str, (&String, &String)> = BTreeMap::new();
    for (key, value) in parameters {
        let id = parameter_identity(key);
        match out.get(id) {
            Some((held, _)) if !crate::files::is_hidden_mem_key(held) => {}
            Some(_) if crate::files::is_hidden_mem_key(key) => {}
            _ => {
                out.insert(id, (key, value));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Links.
// ---------------------------------------------------------------------------

/// One com-object → group-address binding, the unit a link change is about.
type Binding = (u16, LinkRole, GroupAddress);

/// Flattens a device's links into the set of bindings it declares.
fn bindings(model: &Model, ia: IndividualAddress) -> BTreeSet<Binding> {
    let mut out = BTreeSet::new();
    let Some(links) = model.links.links.get(&ia) else {
        return out;
    };
    for link in links {
        if let Some(send) = link.send {
            out.insert((link.object, LinkRole::Send, send));
        }
        for ga in &link.listen {
            out.insert((link.object, LinkRole::Listen, *ga));
        }
    }
    out
}

/// The informational com-object names a device declares, by object number.
fn object_names(model: &Model, ia: IndividualAddress) -> BTreeMap<u16, String> {
    let mut out = BTreeMap::new();
    let Some(links) = model.links.links.get(&ia) else {
        return out;
    };
    for link in links {
        if let Some(name) = link
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            out.insert(link.object, name.to_string());
        }
    }
    out
}

/// Renders every link added or removed, by device, com object and GA.
fn describe_links(old: &Model, new: &Model, labels: &Labels<'_>, out: &mut Vec<Change>) {
    let models = [new, old];
    let devices: BTreeSet<IndividualAddress> = old
        .links
        .links
        .keys()
        .chain(new.links.links.keys())
        .copied()
        .collect();

    for ia in devices {
        let before = bindings(old, ia);
        let after = bindings(new, ia);
        if before == after {
            continue;
        }
        let mut names = object_names(old, ia);
        names.extend(object_names(new, ia));
        let device = new
            .devices
            .get(&ia)
            .or_else(|| old.devices.get(&ia))
            .map(|l| &l.device);

        // Additions and removals interleaved by (object, role, GA) so a send GA
        // that moved reads as one pair of adjacent sentences.
        let all: BTreeSet<&Binding> = before.iter().chain(after.iter()).collect();
        for binding in all {
            let added = after.contains(binding) && !before.contains(binding);
            let removed = before.contains(binding) && !after.contains(binding);
            if !added && !removed {
                continue;
            }
            let (object, role, ga) = *binding;
            let kind = if added {
                ChangeKind::LinkAdded
            } else {
                ChangeKind::LinkRemoved
            };
            let sentence = link_sentence(
                labels,
                device,
                ia,
                names.get(&object).map(String::as_str),
                object,
                role,
                ga,
                added,
            );
            out.push(
                Change::new(kind, sentence)
                    .with_device(ia)
                    .with_group(ga)
                    .with_link(object, role)
                    .protected_if(is_protected(models, ga)),
            );
        }
    }
}

/// Builds the sentence for one link addition or removal.
///
/// The subject is the com-object name (the link's, else the vendor's object
/// text) on the device, with the channel appended when the com object belongs
/// to a channel with a name or vendor text: "Living room blind actuator,
/// channel B, no longer listens to Central down."
#[allow(clippy::too_many_arguments)] // all of it is one sentence's worth of context
fn link_sentence(
    labels: &Labels<'_>,
    device: Option<&Device>,
    ia: IndividualAddress,
    object_name: Option<&str>,
    object: u16,
    role: LinkRole,
    ga: GroupAddress,
    added: bool,
) -> String {
    // The device's label carries its address when its name is not unique,
    // so a sentence naming only a channel still says which device it is
    // (issues #372, #306).
    let device_label = labels.device(ia);
    let object_name = object_label(device, object_name, object);
    let mut subject = match &object_name {
        Some(name) => format!("{name} on {device_label}"),
        None => device_label,
    };
    let channel = channel_of_object(device, object);
    // An object with neither a name nor a channel is identified by its number,
    // so the sentence still says which one moved.
    let object_note = if object_name.is_none() && channel.is_none() {
        format!(" (com object {object})")
    } else {
        String::new()
    };
    let separator = match channel {
        Some(channel) => {
            subject.push_str(&format!(", channel {channel}"));
            ", "
        }
        None => " ",
    };
    let verb = match (role, added) {
        (LinkRole::Send, true) => "now switches",
        (LinkRole::Send, false) => "no longer switches",
        (LinkRole::Listen, true) => "now listens to",
        (LinkRole::Listen, false) => "no longer listens to",
    };
    format!("{subject}{object_note}{separator}{verb} {}.", labels.ga(ga))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Channel, Groups, Link, Links};

    /// An empty model to build cases on.
    fn empty() -> Model {
        Model {
            config: crate::schema::BussardConfig::default(),
            groups: Groups::default(),
            links: Links::default(),
            devices: BTreeMap::new(),
        }
    }

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("test GA parses")
    }

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("test IA parses")
    }

    fn group(name: &str) -> Group {
        Group {
            name: name.to_string(),
            ..Group::default()
        }
    }

    fn device(ia_str: &str, name: &str) -> LoadedDevice {
        LoadedDevice {
            device: Device {
                address: ia(ia_str),
                name: name.to_string(),
                description: None,
                location: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: BTreeMap::new(),
                com_objects: BTreeMap::new(),
                security: None,
                replaced: None,
                application_override: None,
                knxnet: None,
                lock: Default::default(),
            },
            file_stem: format!("{ia_str}-{name}"),
        }
    }

    #[test]
    fn test_describe_identical_models_is_empty() {
        let model = empty();
        assert!(describe(&model, &model).is_empty());
    }

    #[test]
    fn test_describe_unnamed_group_degrades_to_the_address() {
        let old = empty();
        let mut new = empty();
        new.groups.groups.insert(ga("1/2/3"), Group::default());
        let set = describe(&old, &new);
        assert_eq!(set.len(), 1);
        assert_eq!(set.changes[0].sentence, "New group address 1/2/3.");
    }

    #[test]
    fn test_describe_protected_group_annotates_the_sentence() {
        let mut old = empty();
        let mut new = empty();
        let mut protected = group("Wind alarm");
        protected.protected = true;
        old.groups.groups.insert(ga("3/2/0"), protected.clone());
        new.groups.groups.insert(ga("3/2/0"), protected);
        old.links.links.insert(ia("1.1.4"), vec![]);
        new.links.links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 7,
                name: None,
                send: None,
                listen: vec![ga("3/2/0")],
            }],
        );
        new.devices.insert(ia("1.1.4"), device("1.1.4", "Blind"));
        old.devices.insert(ia("1.1.4"), device("1.1.4", "Blind"));

        let set = describe(&old, &new);
        assert_eq!(set.len(), 1);
        assert!(set.changes[0].touches_protected);
        assert!(
            set.changes[0].sentence.ends_with(PROTECTED_NOTE),
            "got {:?}",
            set.changes[0].sentence
        );
    }

    #[test]
    fn test_render_text_puts_protected_first() {
        let mut old = empty();
        let mut new = empty();
        old.groups.groups.insert(ga("0/0/1"), group("Porch"));
        new.groups.groups.insert(ga("0/0/1"), group("Porch light"));
        let mut wind = group("Wind alarm");
        wind.protected = true;
        old.groups.groups.insert(ga("3/2/0"), wind.clone());
        let mut wind2 = wind.clone();
        wind2.name = "Wind alarm north".to_string();
        new.groups.groups.insert(ga("3/2/0"), wind2);

        let set = describe(&old, &new);
        let text = render_text(&set);
        let first = text.lines().next().unwrap_or_default();
        assert!(first.contains("Wind alarm"), "got {text:?}");
    }

    #[test]
    fn test_channel_name_appears_in_a_link_sentence() {
        let mut old = empty();
        let mut new = empty();
        let mut dev = device("1.1.4", "Living room blind actuator");
        dev.device.channels.insert(
            "CH-2".to_string(),
            Channel {
                name: "B".to_string(),
                key: None,
                number: None,
                text: None,
            },
        );
        dev.device.com_objects.insert(
            12,
            crate::schema::ComObject {
                channel: Some("CH-2".to_string()),
                ..crate::schema::ComObject::default()
            },
        );
        old.devices.insert(ia("1.1.4"), dev.clone());
        new.devices.insert(ia("1.1.4"), dev);
        old.groups.groups.insert(ga("3/0/1"), group("Central down"));
        new.groups.groups.insert(ga("3/0/1"), group("Central down"));
        old.links.links.insert(
            ia("1.1.4"),
            vec![Link {
                object: 12,
                name: None,
                send: None,
                listen: vec![ga("3/0/1")],
            }],
        );
        new.links.links.insert(ia("1.1.4"), vec![]);

        let set = describe(&old, &new);
        assert_eq!(
            set.changes[0].sentence,
            "Living room blind actuator, channel B, no longer listens to Central down."
        );
    }

    #[test]
    fn test_summarize_names_without_addresses() {
        let old = empty();
        let mut new = empty();
        let mut wind = group("Wind alarm");
        wind.protected = true;
        new.groups.groups.insert(ga("3/2/0"), wind.clone());
        let mut old = old;
        old.groups.groups.insert(ga("3/2/0"), wind);
        new.groups.groups.insert(ga("0/0/4"), group("Porch light"));
        new.devices
            .insert(ia("1.1.5"), device("1.1.5", "Hallway push button"));
        old.devices
            .insert(ia("1.1.5"), device("1.1.5", "Hallway push button"));
        new.links.links.insert(
            ia("1.1.5"),
            vec![Link {
                object: 1,
                name: Some("Rocker 1".to_string()),
                send: Some(ga("0/0/4")),
                listen: vec![ga("3/2/0")],
            }],
        );
        let set = describe(&old, &new);
        let summary = summarize(&set, [&new, &old]);
        assert_eq!(
            summary,
            "A new function Porch light is added; Rocker 1 on Hallway push button now switches \
             Porch light; and Rocker 1 on Hallway push button now listens to Wind alarm. Part of \
             this concerns a protected safety function, so it needs the human's explicit yes."
        );
        // The sentence of the protected link still names the address.
        assert!(
            set.changes
                .iter()
                .any(|c| c.touches_protected && c.sentence.contains("Wind alarm (3/2/0)")),
            "{set:?}"
        );
        assert_eq!(
            summarize(&ChangeSet::default(), [&new, &old]),
            "Nothing changes."
        );
    }

    #[test]
    fn test_describe_names_carry_the_address_only_when_ambiguous() {
        let old = empty();
        let mut new = empty();
        new.groups.groups.insert(ga("0/0/4"), group("Porch light"));
        new.groups.groups.insert(ga("0/0/5"), group("Porch light"));
        new.groups.groups.insert(ga("0/0/6"), group("Garden light"));
        new.devices
            .insert(ia("1.1.4"), device("1.1.4", "Push button"));
        new.devices
            .insert(ia("1.1.5"), device("1.1.5", "push button "));
        new.devices.insert(ia("1.1.6"), device("1.1.6", "Dimmer"));
        let sentences: Vec<String> = describe(&old, &new)
            .changes
            .into_iter()
            .map(|c| c.sentence)
            .collect();
        assert!(
            sentences.contains(&"New group address Porch light (0/0/4).".to_string()),
            "{sentences:?}"
        );
        assert!(
            sentences.contains(&"New group address Garden light.".to_string()),
            "{sentences:?}"
        );
        assert!(
            sentences
                .iter()
                .any(|s| s.starts_with("New device Push button (1.1.4) in")),
            "{sentences:?}"
        );
        assert!(
            sentences
                .iter()
                .any(|s| s.starts_with("New device Dimmer in")),
            "{sentences:?}"
        );
    }

    /// Two copies of device 1.1.4 holding `before` and `after` as their
    /// parameters, described.
    fn parameter_changes(before: &[(&str, &str)], after: &[(&str, &str)]) -> ChangeSet {
        let side = |params: &[(&str, &str)]| {
            let mut model = empty();
            let mut dev = device("1.1.4", "Weather station");
            dev.device.parameters = params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            model.devices.insert(ia("1.1.4"), dev);
            model
        };
        describe(&side(before), &side(after))
    }

    /// Issue #375: one ref under the three spellings an import and the MCP
    /// server write is one parameter.
    #[test]
    fn test_describe_parameters_same_ref_under_other_spellings_is_no_change() {
        let spellings = ["a@P-7_R-7", "page-a@P-7_R-7", "hidden@P-7_R-7"];
        for before in spellings {
            for after in spellings {
                let set = parameter_changes(&[(before, "4")], &[(after, "4")]);
                assert!(set.is_empty(), "{before} vs {after}: {:?}", set.changes);
            }
        }
    }

    #[test]
    fn test_describe_parameters_same_ref_other_value_is_one_change_named_visibly() {
        let cases = [
            ("hidden@P-7_R-7", "a@P-7_R-7", "a@P-7_R-7"),
            ("a@P-7_R-7", "hidden@P-7_R-7", "a@P-7_R-7"),
            ("a@P-7_R-7", "page-a@P-7_R-7", "page-a@P-7_R-7"),
            ("hidden@P-7_R-7", "hidden@P-7_R-7", "hidden@P-7_R-7"),
        ];
        for (before, after, field) in cases {
            let set = parameter_changes(&[(before, "4")], &[(after, "5")]);
            assert_eq!(set.len(), 1, "{before} vs {after}: {:?}", set.changes);
            let change = &set.changes[0];
            assert_eq!(change.kind, ChangeKind::ParameterChanged);
            assert_eq!(change.field.as_deref(), Some(field));
            assert_eq!(change.from.as_deref(), Some("4"));
            assert_eq!(change.to.as_deref(), Some("5"));
        }
    }

    /// A side holding one ref under a hidden and a visible key (before a
    /// save settles it) compares with the visible key's value.
    #[test]
    fn test_describe_parameters_visible_key_wins_over_hidden_on_one_side() {
        let set = parameter_changes(
            &[("hidden@P-7_R-7", "1"), ("z@P-7_R-7", "4")],
            &[("a@P-7_R-7", "4")],
        );
        assert!(set.is_empty(), "{:?}", set.changes);
    }

    #[test]
    fn test_describe_parameters_key_without_ref_compares_by_key() {
        let set = parameter_changes(
            &[("odd", "1"), ("same", "2")],
            &[("other", "1"), ("same", "2")],
        );
        let fields: Vec<_> = set
            .changes
            .iter()
            .filter_map(|c| c.field.as_deref())
            .collect();
        assert_eq!(fields, ["odd", "other"]);
        let set = parameter_changes(&[("odd", "1")], &[("odd", "1")]);
        assert!(set.is_empty());
    }

    #[test]
    fn test_describe_knxnet_sentences() {
        use crate::knxnet::{IpAssignment, KnxnetConfig};
        let with = |k: Option<KnxnetConfig>| {
            let mut m = empty();
            let mut d = device("1.1.200", "KNX IP Interface");
            d.device.knxnet = k;
            m.devices.insert(ia("1.1.200"), d);
            m
        };
        let before = KnxnetConfig {
            assignment: IpAssignment::Dhcp,
            friendly_name: Some("Alpha".to_string()),
            tunnels: vec![ia("1.1.22"), ia("1.1.23")],
            ..KnxnetConfig::default()
        };
        let mut after = before.clone();
        after.tunnels = vec![ia("1.1.22"), ia("1.1.30")];
        after.assignment = IpAssignment::Static;
        after.address = Some(std::net::Ipv4Addr::new(192, 168, 1, 74));
        after.friendly_name = Some("Beta".to_string());
        let set = describe(&with(Some(before.clone())), &with(Some(after)));
        let sentences: Vec<&str> = set.changes.iter().map(|c| c.sentence.as_str()).collect();
        assert_eq!(
            sentences,
            [
                "Interface KNX IP Interface: IP assignment is now static (was dhcp).",
                "Interface KNX IP Interface: static IP address set to 192.168.1.74.",
                "Interface KNX IP Interface: friendly name is now \"Beta\" (was \"Alpha\").",
                "Interface KNX IP Interface: tunnel address 1.1.30 added.",
                "Interface KNX IP Interface: tunnel address 1.1.23 removed.",
            ]
        );
        assert!(
            set.changes
                .iter()
                .all(|c| c.kind == ChangeKind::InterfaceChanged)
        );
        assert_eq!(set.changes[3].field.as_deref(), Some("knxnet.tunnels"));

        let added = describe(&with(None), &with(Some(before.clone())));
        assert_eq!(
            added.changes[0].sentence,
            "Interface KNX IP Interface: KNXnet/IP settings added (assignment dhcp, \
             tunnel addresses 1.1.22, 1.1.23)."
        );
        let mut reordered = before.clone();
        reordered.tunnels.reverse();
        let set = describe(&with(Some(before)), &with(Some(reordered)));
        assert_eq!(set.len(), 1);
        assert!(
            set.changes[0]
                .sentence
                .contains("reordered to 1.1.23, 1.1.22")
        );
    }
}
