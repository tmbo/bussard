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
use crate::param_model::{ProductModels, key_to_param_id};
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
    describe_connection(old, new, &mut changes);
    describe_groups(old, new, &mut changes);
    describe_devices(old, new, &mut changes);
    describe_links(old, new, &mut changes);
    ChangeSet { changes }
}

/// Replaces the key-derived label of every parameter change with the
/// parameter's text from the cached product model, e.g. `Nachtabsenkung on …`
/// becomes `Night setback on …`.
///
/// `models` are the two sides the set was described from (the device is looked
/// up in each, in order, for its `application_ref`). A change whose device has
/// no cached product model, or whose parameter has no text, keeps the label
/// derived from its key: nothing degrades to silence.
pub fn name_parameters(set: &mut ChangeSet, models: [&Model; 2], products: &ProductModels) {
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

// ---------------------------------------------------------------------------
// Labels: how a thing is named in a sentence.
// ---------------------------------------------------------------------------

/// A group address as a human reads it: `Porch light (0/0/4)`, or just the
/// address when the model has no name for it.
fn ga_label(models: [&Model; 2], ga: GroupAddress) -> String {
    for model in models {
        if let Some(group) = model.groups.groups.get(&ga) {
            let name = group.name.trim();
            if !name.is_empty() {
                return format!("{name} ({ga})");
            }
        }
    }
    ga.to_string()
}

/// A device's short name for mid-sentence use: its name, or its individual
/// address when it has none.
fn device_name(models: [&Model; 2], ia: IndividualAddress) -> String {
    for model in models {
        if let Some(loaded) = model.devices.get(&ia) {
            let name = loaded.device.name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    ia.to_string()
}

/// A device's full label: `Hallway push button (1.1.5)`, or the bare address.
fn device_label(models: [&Model; 2], ia: IndividualAddress) -> String {
    for model in models {
        if let Some(loaded) = model.devices.get(&ia) {
            let name = loaded.device.name.trim();
            if !name.is_empty() {
                return format!("{name} ({ia})");
            }
        }
    }
    ia.to_string()
}

/// The channel name a com object belongs to, when both the com object and the
/// named channel are known.
fn channel_of_object(device: Option<&Device>, object: u16) -> Option<String> {
    let device = device?;
    let key = device.com_objects.get(&object)?.channel.as_deref()?;
    let name = device.channels.get(key)?.name.trim();
    if name.is_empty() {
        Some(key.to_string())
    } else {
        Some(name.to_string())
    }
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
fn parameter_label(key: &str) -> String {
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
fn describe_groups(old: &Model, new: &Model, out: &mut Vec<Change>) {
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
                Change::new(ChangeKind::GroupAdded, added_group_sentence(ga, group))
                    .with_group(ga)
                    .protected_if(protected),
            ),
            (Some(group), None) => out.push(
                Change::new(
                    ChangeKind::GroupRemoved,
                    format!("Group address {} is gone.", label_for_group(ga, group)),
                )
                .with_group(ga)
                .protected_if(protected),
            ),
            (Some(a), Some(b)) => group_field_changes(ga, a, b, protected, out),
            (None, None) => {}
        }
    }
}

/// `Porch light (0/0/4)` for a group we have the definition of.
fn label_for_group(ga: GroupAddress, group: &Group) -> String {
    let name = group.name.trim();
    if name.is_empty() {
        ga.to_string()
    } else {
        format!("{name} ({ga})")
    }
}

/// The sentence for a newly added group address.
fn added_group_sentence(ga: GroupAddress, group: &Group) -> String {
    let label = label_for_group(ga, group);
    match group.dpt {
        Some(dpt) => format!("New group address {label}, type {dpt}."),
        None => format!("New group address {label}."),
    }
}

/// Renders the per-field differences of a group address present in both models.
fn group_field_changes(
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
                format!(
                    "Group address {ga} is now called {} (was {}).",
                    value_or_nothing(Some(&b.name)),
                    value_or_nothing(Some(&a.name))
                ),
            )
            .with_group(ga)
            .with_field("name", Some(a.name.clone()), Some(b.name.clone()))
            .protected_if(protected),
        );
    }
    if a.dpt != b.dpt {
        let label = label_for_group(ga, b);
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
        let label = label_for_group(ga, b);
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
    if a.protected != b.protected {
        let label = label_for_group(ga, b);
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
fn describe_devices(old: &Model, new: &Model, out: &mut Vec<Change>) {
    let models = [new, old];
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
                        device_label(models, ia),
                        location_label(loaded.device.location.as_ref())
                    ),
                )
                .with_device(ia),
            ),
            (Some(_), None) => out.push(
                Change::new(
                    ChangeKind::DeviceRemoved,
                    format!(
                        "Device {} is gone from the model.",
                        device_label(models, ia)
                    ),
                )
                .with_device(ia),
            ),
            (Some(a), Some(b)) => device_field_changes(ia, a, b, out),
            (None, None) => {}
        }
    }
}

/// Renders the per-field differences of a device present in both models.
fn device_field_changes(
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
                format!(
                    "Device {ia} is now called {} (was {}).",
                    value_or_nothing(Some(&b.name)),
                    value_or_nothing(Some(&a.name))
                ),
            )
            .with_device(ia)
            .with_field("name", Some(a.name.clone()), Some(b.name.clone())),
        );
    }
    if a.location != b.location {
        let from = location_label(a.location.as_ref());
        let to = location_label(b.location.as_ref());
        let name = if b.name.trim().is_empty() {
            ia.to_string()
        } else {
            format!("{} ({ia})", b.name.trim())
        };
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
        let name = if b.name.trim().is_empty() {
            ia.to_string()
        } else {
            format!("{} ({ia})", b.name.trim())
        };
        out.push(
            Change::new(
                ChangeKind::DeviceProductChanged,
                format!("{name} is now a {to} (was {from})."),
            )
            .with_device(ia)
            .with_field("product", Some(from), Some(to)),
        );
    }
    describe_channels(ia, a, b, out);
    describe_parameters(ia, a, b, out);
}

/// Renders channel renames (a channel added or removed comes with the
/// regenerated com-object table, which is not an edit).
fn describe_channels(ia: IndividualAddress, a: &Device, b: &Device, out: &mut Vec<Change>) {
    for (key, after) in &b.channels {
        let Some(before) = a.channels.get(key) else {
            continue;
        };
        if before.name == after.name {
            continue;
        }
        let device = if b.name.trim().is_empty() {
            ia.to_string()
        } else {
            format!("{} ({ia})", b.name.trim())
        };
        out.push(
            Change::new(
                ChangeKind::ChannelRenamed,
                format!(
                    "Channel {} on {device} is now called {} (was {}).",
                    key,
                    value_or_nothing(Some(&after.name)),
                    value_or_nothing(Some(&before.name))
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
fn describe_parameters(ia: IndividualAddress, a: &Device, b: &Device, out: &mut Vec<Change>) {
    let keys: BTreeSet<&String> = a.parameters.keys().chain(b.parameters.keys()).collect();
    let device = if b.name.trim().is_empty() {
        ia.to_string()
    } else {
        format!("{} ({ia})", b.name.trim())
    };
    for key in keys {
        let before = a.parameters.get(key);
        let after = b.parameters.get(key);
        if before == after {
            continue;
        }
        let label = parameter_label(key);
        let sentence = match (before, after) {
            (Some(from), Some(to)) => format!("{label} on {device}: {from} to {to}."),
            (None, Some(to)) => format!("{label} on {device} is set to {to}."),
            (Some(from), None) => {
                format!("{label} on {device} goes back to the vendor default (was {from}).")
            }
            (None, None) => continue,
        };
        out.push(
            Change::new(ChangeKind::ParameterChanged, sentence)
                .with_device(ia)
                .with_field(key.clone(), before.cloned(), after.cloned()),
        );
    }
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
fn describe_links(old: &Model, new: &Model, out: &mut Vec<Change>) {
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
                models,
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
/// The subject is the com-object name (when the model has one) on the device,
/// with the channel appended when the com object belongs to a named channel:
/// "Living room blind actuator, channel B, no longer listens to Central down
/// (3/0/1)."
#[allow(clippy::too_many_arguments)] // all of it is one sentence's worth of context
fn link_sentence(
    models: [&Model; 2],
    device: Option<&Device>,
    ia: IndividualAddress,
    object_name: Option<&str>,
    object: u16,
    role: LinkRole,
    ga: GroupAddress,
    added: bool,
) -> String {
    let device_label = device_name(models, ia);
    let mut subject = match object_name {
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
    format!(
        "{subject}{object_note}{separator}{verb} {}.",
        ga_label(models, ga)
    )
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
            "Living room blind actuator, channel B, \
             no longer listens to Central down (3/0/1)."
        );
    }
}
