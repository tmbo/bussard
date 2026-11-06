//! The ETS checklist of a change set (issue #372): `bussard diff <A> <B>
//! --checklist`.
//!
//! ETS signs its project files, so bussard cannot write its changes back
//! into a `.knxproj`. The project stays in step with the house only when
//! someone redoes bussard's changes by hand in ETS. [`checklist`] turns a
//! [`ChangeSet`] into that work list, in the order it is done in ETS:
//!
//! 1. the group addresses (new, renamed, DPT, description, security,
//!    removed), since links need them;
//! 2. one section per device, finished before the next: its own fields, its
//!    parameters on the ETS page the device view puts them on (an enabling
//!    parameter before the parameter it reveals), its objects and links, and
//!    its object security;
//! 3. what ETS cannot take by hand (the gateway, admission, the `protected`
//!    flag, values ETS never shows), as plain notes.
//!
//! The module is pure: it reads the two models and the product models and
//! writes nothing. [`Checklist::render_markdown`] prints it; the struct
//! serializes as the `--checklist --json` output.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::address::{GroupAddress, IndividualAddress};
use crate::blocks::ref_param_id;
use crate::change::{Change, ChangeKind, ChangeSet, parameter_label};
use crate::device_view::{
    RefVisibility, device_view, parameter_pages, parameter_visibility, unindexed_parameters,
};
use crate::dynamic::{DynamicConfig, RefIndex, evaluate_dynamic, split_selector};
use crate::loader::Model;
use crate::param_model::{ParamDef, ProductModel, ProductModels, enum_code, enum_label};
use crate::schema::Device;

/// One line of the checklist: a checkbox item, or a plain note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// The kind of change behind it. An object line that merges several
    /// link changes carries the first one's.
    pub kind: ChangeKind,
    /// The line as printed, without the checkbox.
    pub text: String,
    /// The device's individual address, for a device item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The group address, for a group-address item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The com-object number, for an object item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<u16>,
    /// The ETS page (or channel) title a parameter sits on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// The ETS label: the parameter text, the object name, the GA name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The new value as ETS shows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The old value as ETS shows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
}

impl Item {
    /// An item of `kind` reading `text`, every other field empty.
    fn new(kind: ChangeKind, text: impl Into<String>) -> Self {
        Item {
            kind,
            text: text.into(),
            device: None,
            group: None,
            object: None,
            page: None,
            label: None,
            value: None,
            old_value: None,
        }
    }

    /// A plain note quoting `change`'s sentence.
    fn note(change: &Change) -> Self {
        let mut item = Item::new(change.kind, change.sentence.clone());
        item.device = change.device.clone();
        item.group = change.group.clone();
        item.object = change.object;
        item.value = change.to.clone();
        item.old_value = change.from.clone();
        item
    }
}

/// The work on one device, finished before the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceSection {
    /// The individual address.
    pub address: String,
    /// The device name (empty when the model has none).
    pub name: String,
    /// The room, else the floor, when the model knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// The device's own fields: added, removed, renamed, moved, product,
    /// channel names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub device: Vec<Item>,
    /// Parameters, in the device view's page order, an enabling parameter
    /// before the parameter it reveals.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Item>,
    /// One line per com-object whose links changed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<Item>,
    /// Object security changes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<Item>,
}

impl DeviceSection {
    /// How many checkbox items it holds.
    fn len(&self) -> usize {
        self.device.len() + self.parameters.len() + self.objects.len() + self.security.len()
    }
}

/// The checklist of a change set: what to redo by hand in ETS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Checklist {
    /// How many changes the set had.
    pub changes: usize,
    /// How many checkbox items the list holds.
    pub items: usize,
    /// The group-address items, first.
    pub groups: Vec<Item>,
    /// One section per device, by individual address.
    pub devices: Vec<DeviceSection>,
    /// What ETS cannot take by hand, as plain notes.
    pub notes: Vec<Item>,
}

/// The rank of a group-address change in the list: new ones first (links
/// need them), removed ones last.
fn group_rank(kind: ChangeKind) -> u8 {
    match kind {
        ChangeKind::GroupAdded => 0,
        ChangeKind::GroupRenamed => 1,
        ChangeKind::GroupDptChanged => 2,
        ChangeKind::GroupDescriptionChanged => 3,
        ChangeKind::GroupSecurityChanged => 4,
        _ => 5,
    }
}

/// Builds the checklist of `set`, the change from `old` to `new`, with the
/// parameter pages, labels and value texts from `products`.
///
/// `set` is what [`crate::change::describe`] (and, for the parameter texts,
/// [`crate::change::name_parameters`]) produced for the two models. Pure: it
/// reads the models and writes nothing.
pub fn checklist(set: &ChangeSet, old: &Model, new: &Model, products: &ProductModels) -> Checklist {
    let mut groups: Vec<(u8, String, Item)> = Vec::new();
    let mut notes: Vec<Item> = Vec::new();
    let mut sections: BTreeMap<IndividualAddress, DeviceSection> = BTreeMap::new();
    let mut params: BTreeMap<IndividualAddress, Vec<&Change>> = BTreeMap::new();
    let mut links: BTreeMap<(IndividualAddress, u16), ChangeKind> = BTreeMap::new();

    for change in &set.changes {
        let ia = change
            .device
            .as_deref()
            .and_then(|d| d.parse::<IndividualAddress>().ok());
        match change.kind {
            ChangeKind::ConnectionChanged | ChangeKind::GroupProtectionChanged => {
                notes.push(Item::note(change));
            }
            ChangeKind::GroupAdded
            | ChangeKind::GroupRemoved
            | ChangeKind::GroupRenamed
            | ChangeKind::GroupDptChanged
            | ChangeKind::GroupDescriptionChanged
            | ChangeKind::GroupSecurityChanged => {
                let item = group_item(change, old, new);
                let key = item.group.clone().unwrap_or_default();
                groups.push((group_rank(change.kind), key, item));
            }
            ChangeKind::ParameterChanged => {
                if let Some(ia) = ia {
                    params.entry(ia).or_default().push(change);
                }
            }
            ChangeKind::LinkAdded | ChangeKind::LinkRemoved => {
                if let (Some(ia), Some(object)) = (ia, change.object) {
                    links.entry((ia, object)).or_insert(change.kind);
                }
            }
            ChangeKind::ObjectSecurityChanged => {
                if let Some(ia) = ia {
                    let items = security_items(change, old, new, ia);
                    section(&mut sections, old, new, ia).security.extend(items);
                }
            }
            ChangeKind::DeviceAdded
            | ChangeKind::DeviceRemoved
            | ChangeKind::DeviceRenamed
            | ChangeKind::DeviceMoved
            | ChangeKind::DeviceProductChanged
            | ChangeKind::ChannelRenamed
            | ChangeKind::InterfaceChanged => {
                if let Some(ia) = ia {
                    let mut item = Item::note(change);
                    item.text = change.sentence.trim_end_matches('.').to_string();
                    section(&mut sections, old, new, ia).device.push(item);
                }
            }
        }
    }

    for (ia, changes) in params {
        let (items, more_notes) = parameter_items(&changes, old, new, products, ia);
        notes.extend(more_notes);
        if !items.is_empty() {
            section(&mut sections, old, new, ia).parameters = items;
        }
    }
    for ((ia, object), kind) in links {
        if let Some(item) = object_item(old, new, ia, object, kind) {
            section(&mut sections, old, new, ia).objects.push(item);
        }
    }

    // By kind, then numerically by address; the sort is stable.
    groups.sort_by_key(|g| (g.0, group_sort_key(&g.1)));
    let groups: Vec<Item> = groups.into_iter().map(|(_, _, i)| i).collect();
    let devices: Vec<DeviceSection> = sections.into_values().filter(|s| s.len() > 0).collect();
    let items = groups.len() + devices.iter().map(DeviceSection::len).sum::<usize>();
    Checklist {
        changes: set.len(),
        items,
        groups,
        devices,
        notes,
    }
}

/// Sorts group addresses numerically, a text that does not parse last.
fn group_sort_key(text: &str) -> (u16, String) {
    match text.parse::<GroupAddress>() {
        Ok(ga) => (ga.raw(), String::new()),
        Err(_) => (u16::MAX, text.to_string()),
    }
}

/// The section of device `ia`, created on first use.
fn section<'s>(
    sections: &'s mut BTreeMap<IndividualAddress, DeviceSection>,
    old: &Model,
    new: &Model,
    ia: IndividualAddress,
) -> &'s mut DeviceSection {
    sections.entry(ia).or_insert_with(|| {
        let device = new
            .devices
            .get(&ia)
            .or_else(|| old.devices.get(&ia))
            .map(|l| &l.device);
        DeviceSection {
            address: ia.to_string(),
            name: device
                .map(|d| d.name.trim().to_string())
                .unwrap_or_default(),
            room: device.and_then(room_of),
            device: Vec::new(),
            parameters: Vec::new(),
            objects: Vec::new(),
            security: Vec::new(),
        }
    })
}

/// The room of a device, else its floor.
fn room_of(device: &Device) -> Option<String> {
    let location = device.location.as_ref()?;
    [location.room.as_deref(), location.floor.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Group addresses.
// ---------------------------------------------------------------------------

/// `4/1/20 "Aussen dunkel"`, or the bare address without a name.
fn ga_head(ga: &str, name: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        ga.to_string()
    } else {
        format!("{ga} {name:?}")
    }
}

/// The named ranges a group address sits in: `main group 4 "Zentral",
/// middle group 4/1 "Wetterdaten"`, each marked new when `old` lacks it.
fn range_words(old: &Model, new: &Model, ga: GroupAddress) -> Option<String> {
    let main = ga.main().to_string();
    let middle = format!("{}/{}", ga.main(), ga.middle());
    let mut parts = Vec::new();
    for (what, key) in [("main group", main), ("middle group", middle)] {
        let Some(range) = new.groups.ranges.get(&key) else {
            continue;
        };
        let fresh = if old.groups.ranges.contains_key(&key) {
            ""
        } else {
            "new "
        };
        parts.push(format!("{fresh}{what} {key} {:?}", range.name.trim()));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// The checklist item of a group-address change.
fn group_item(change: &Change, old: &Model, new: &Model) -> Item {
    let ga_text = change.group.clone().unwrap_or_default();
    let ga = ga_text.parse::<GroupAddress>().ok();
    let group = ga.and_then(|g| {
        new.groups
            .groups
            .get(&g)
            .or_else(|| old.groups.groups.get(&g))
    });
    let name = group.map(|g| g.name.clone()).unwrap_or_default();
    let head = ga_head(&ga_text, &name);
    let or_none = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| "none".to_string(), str::to_string)
    };
    let (text, value, old_value) = match change.kind {
        ChangeKind::GroupAdded => {
            let mut text = head;
            if let Some(dpt) = group.and_then(|g| g.dpt) {
                text.push_str(&format!(", DPT {dpt}"));
            }
            text.push_str(", new");
            if let Some(words) = ga.and_then(|g| range_words(old, new, g)) {
                text.push_str(&format!(" ({words})"));
            }
            (text, None, None)
        }
        ChangeKind::GroupRemoved => (format!("{head}: delete"), None, None),
        ChangeKind::GroupRenamed => (
            format!(
                "{ga_text}: rename to {:?} (was {:?})",
                change.to.as_deref().unwrap_or_default(),
                change.from.as_deref().unwrap_or_default()
            ),
            change.to.clone(),
            change.from.clone(),
        ),
        ChangeKind::GroupDptChanged => {
            let to = or_none(change.to.as_deref());
            let from = or_none(change.from.as_deref());
            (
                format!("{head}: DPT {to} (was {from})"),
                Some(to),
                Some(from),
            )
        }
        ChangeKind::GroupDescriptionChanged => {
            let quote = |v: Option<&str>| {
                v.map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map_or_else(|| "none".to_string(), |s| format!("{s:?}"))
            };
            (
                format!(
                    "{head}: description {} (was {})",
                    quote(change.to.as_deref()),
                    quote(change.from.as_deref())
                ),
                change.to.clone(),
                change.from.clone(),
            )
        }
        ChangeKind::GroupSecurityChanged => {
            let on_off = |v: Option<&str>| if v == Some("true") { "on" } else { "off" };
            let to = on_off(change.to.as_deref());
            let from = on_off(change.from.as_deref());
            (
                format!("{head}: security {to} (was {from})"),
                Some(to.to_string()),
                Some(from.to_string()),
            )
        }
        _ => (
            change.sentence.clone(),
            change.to.clone(),
            change.from.clone(),
        ),
    };
    let mut item = Item::new(change.kind, text);
    item.group = change.group.clone();
    item.label = (!name.trim().is_empty()).then(|| name.trim().to_string());
    item.value = value;
    item.old_value = old_value;
    item
}

// ---------------------------------------------------------------------------
// Objects, links and object security.
// ---------------------------------------------------------------------------

/// `Objekt 105 "C18.1 Logikmodul" (Schalten)`: the object number with its
/// vendor text and function from either model's com-object table, else the
/// name the links give it.
fn object_head(old: &Model, new: &Model, ia: IndividualAddress, object: u16) -> (String, String) {
    let com = [new, old]
        .into_iter()
        .filter_map(|m| m.devices.get(&ia))
        .find_map(|l| l.device.com_objects.get(&object));
    let text = com
        .and_then(|c| c.text.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            [new, old].into_iter().find_map(|m| {
                m.links
                    .links
                    .get(&ia)?
                    .iter()
                    .find(|l| l.object == object)?
                    .name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
        });
    let function = com
        .and_then(|c| c.function.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut head = format!("Objekt {object}");
    if let Some(text) = &text {
        head.push_str(&format!(" {text:?}"));
    }
    if let Some(function) = function {
        head.push_str(&format!(" ({function})"));
    }
    (head, text.unwrap_or_default())
}

/// The sending and listening group addresses of one com-object.
fn object_links(
    model: &Model,
    ia: IndividualAddress,
    object: u16,
) -> (Option<String>, Vec<String>) {
    let mut send = None;
    let mut listen: BTreeSet<GroupAddress> = BTreeSet::new();
    for link in model.links.links.get(&ia).into_iter().flatten() {
        if link.object != object {
            continue;
        }
        if let Some(ga) = link.send {
            send = Some(ga.to_string());
        }
        listen.extend(link.listen.iter().copied());
    }
    (send, listen.into_iter().map(|g| g.to_string()).collect())
}

/// The object line of a com-object whose links changed: only the roles
/// that changed, `sends 1/0/4 (was nothing), listens 4/2/13, 4/2/14`.
fn object_item(
    old: &Model,
    new: &Model,
    ia: IndividualAddress,
    object: u16,
    kind: ChangeKind,
) -> Option<Item> {
    let (send_a, listen_a) = object_links(old, ia, object);
    let (send_b, listen_b) = object_links(new, ia, object);
    let mut now = Vec::new();
    let mut was = Vec::new();
    let mut parts = Vec::new();
    if send_a != send_b {
        let to = send_b.clone().unwrap_or_else(|| "nothing".to_string());
        let from = send_a.clone().unwrap_or_else(|| "nothing".to_string());
        parts.push(format!("sends {to} (was {from})"));
        now.push(format!("sends {to}"));
        was.push(format!("sends {from}"));
    }
    if listen_a != listen_b {
        let list = |l: &[String]| {
            if l.is_empty() {
                "nothing".to_string()
            } else {
                l.join(", ")
            }
        };
        let to = list(&listen_b);
        let from = list(&listen_a);
        if listen_a.is_empty() {
            parts.push(format!("listens {to}"));
        } else {
            parts.push(format!("listens {to} (was {from})"));
        }
        now.push(format!("listens {to}"));
        was.push(format!("listens {from}"));
    }
    if parts.is_empty() {
        return None;
    }
    let (head, name) = object_head(old, new, ia, object);
    let mut item = Item::new(kind, format!("{head}: {}", parts.join(", ")));
    item.device = Some(ia.to_string());
    item.object = Some(object);
    item.label = (!name.is_empty()).then_some(name);
    item.value = Some(now.join(", "));
    item.old_value = Some(was.join(", "));
    Some(item)
}

/// One item per com-object of an object-security change (its field is
/// `objects.<n>,<n>.secure`).
fn security_items(change: &Change, old: &Model, new: &Model, ia: IndividualAddress) -> Vec<Item> {
    let numbers: Vec<u16> = change
        .field
        .as_deref()
        .and_then(|f| f.strip_prefix("objects."))
        .and_then(|f| f.strip_suffix(".secure"))
        .map(|list| {
            list.split(',')
                .filter_map(|n| n.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    let on_off = |v: Option<&str>| if v == Some("true") { "on" } else { "off" };
    let to = on_off(change.to.as_deref());
    let from = on_off(change.from.as_deref());
    numbers
        .into_iter()
        .map(|object| {
            let (head, name) = object_head(old, new, ia, object);
            let mut item = Item::new(change.kind, format!("{head}: security {to} (was {from})"));
            item.device = Some(ia.to_string());
            item.object = Some(object);
            item.label = (!name.is_empty()).then_some(name);
            item.value = Some(to.to_string());
            item.old_value = Some(from.to_string());
            item
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Parameters.
// ---------------------------------------------------------------------------

/// What the device view knows about one device of the new model: its pages
/// in ETS order, the page of each parameter ref, what the configuration
/// shows, the conditions in front of each ref, and the vendor defaults.
struct DeviceContext<'a> {
    device: &'a Device,
    product: Option<&'a ProductModel>,
    config: Option<DynamicConfig>,
    /// Page handle → (ETS order, title).
    page_order: HashMap<String, (usize, String)>,
    /// Ref → page handle.
    pages: BTreeMap<String, String>,
    /// Ref → document position in the product model's pages.
    positions: HashMap<String, usize>,
    visibility: BTreeMap<String, RefVisibility>,
    index: Option<RefIndex>,
    /// The product model carries no ETS pages: one of an older format.
    pageless: bool,
}

impl<'a> DeviceContext<'a> {
    fn new(model: &'a Model, products: &'a ProductModels, ia: IndividualAddress) -> Option<Self> {
        let device = &model.devices.get(&ia)?.device;
        let product = device
            .product
            .as_ref()
            .and_then(|p| p.application_ref.as_deref())
            .and_then(|a| products.get(a));
        let mut ctx = DeviceContext {
            device,
            product,
            config: None,
            page_order: HashMap::new(),
            pages: BTreeMap::new(),
            positions: HashMap::new(),
            visibility: BTreeMap::new(),
            index: None,
            pageless: false,
        };
        let Some(product) = product else {
            return Some(ctx);
        };
        ctx.pageless = product.blocks().is_empty();
        let (overrides, _) = crate::device_view::device_overrides(device);
        ctx.config = Some(evaluate_dynamic(product, &overrides));
        if let Ok(view) = device_view(model, products, ia, None) {
            for (n, row) in view.blocks.iter().enumerate() {
                let title = row.text.clone().unwrap_or_else(|| row.handle.clone());
                ctx.page_order.insert(row.handle.clone(), (n, title));
            }
        }
        ctx.pages = parameter_pages(model, products, ia).unwrap_or_default();
        for (reference, u) in unindexed_parameters(model, products, ia).unwrap_or_default() {
            if let Some(page) = u.page {
                ctx.pages.entry(reference).or_insert(page);
            }
        }
        let mut n = 0;
        for block in product.blocks() {
            for reference in &block.parameters {
                ctx.positions.entry(reference.clone()).or_insert_with(|| {
                    n += 1;
                    n
                });
            }
        }
        ctx.visibility = parameter_visibility(model, products, ia).unwrap_or_default();
        ctx.index = Some(RefIndex::new(product));
        Some(ctx)
    }

    /// Whether the configuration shows `reference`; a ref the pages do not
    /// hold counts as shown.
    fn shown(&self, reference: &str) -> bool {
        self.visibility.get(reference).is_none_or(|v| v.shown)
    }

    /// The ref ETS shows for the parameter of `reference`: itself when the
    /// configuration shows it, else a shown sibling ref of the same
    /// parameter (a `hidden@` value ETS sets through another ref), else
    /// `None`.
    fn shown_ref(&self, reference: &str) -> Option<String> {
        if self.shown(reference) {
            return Some(reference.to_string());
        }
        let id = ref_param_id(reference);
        self.visibility
            .iter()
            .find(|(r, v)| v.shown && ref_param_id(r) == id)
            .map(|(r, _)| r.clone())
    }

    /// The page title of `reference`, with its ETS order, else the channel
    /// the lock puts the parameter in.
    fn page(&self, reference: &str) -> (Option<usize>, Option<String>) {
        if let Some((order, title)) = self
            .pages
            .get(reference)
            .and_then(|h| self.page_order.get(h))
        {
            return (Some(*order), Some(title.clone()));
        }
        let channel = self
            .device
            .lock
            .parameters
            .get(reference)
            .and_then(|p| p.channel.as_deref())
            .and_then(|id| {
                let ch = self.device.channels.get(id)?;
                [ch.name.as_str(), ch.text.as_deref().unwrap_or_default()]
                    .into_iter()
                    .map(str::trim)
                    .find(|s| !s.is_empty())
                    .map(str::to_string)
            });
        // A lone channel names the device, not a page.
        if self.device.channels.len() > 1 {
            (None, channel)
        } else {
            (None, None)
        }
    }

    /// The vendor default of the ref of in-memory key `key`.
    fn vendor_default(&self, key: &str) -> Option<String> {
        let (product, config) = (self.product?, self.config.as_ref()?);
        let (_, full) = key.split_once('@')?;
        let (instance, reference) = split_selector(full);
        let module = instance.and_then(|id| config.modules.iter().position(|m| m.id == id));
        config.vendor_default(product, module, &reference)
    }

    /// The parameter refs whose `<when>` conditions stand in front of
    /// `reference` (app-relative, the same module instance).
    fn gates(&self, reference: &str) -> BTreeSet<String> {
        let Some(index) = &self.index else {
            return BTreeSet::new();
        };
        index
            .parameter(reference)
            .iter()
            .flat_map(|o| o.gates.iter().map(|g| g.param_ref_id.clone()))
            .collect()
    }
}

/// A value as ETS shows it: an enumeration's text, else the value.
fn value_text(def: Option<&ParamDef>, value: &str) -> String {
    let shown = match def {
        Some(d) if !d.labels.is_empty() => {
            let code = enum_code(&d.labels, value)
                .map(|c| c.to_string())
                .unwrap_or_else(|| value.trim().to_string());
            enum_label(&d.labels, &code)
                .map(|l| l.trim().to_string())
                .unwrap_or_else(|| value.trim().to_string())
        }
        _ => value.trim().to_string(),
    };
    if shown.is_empty() {
        "\"\"".to_string()
    } else {
        shown
    }
}

/// Whether two values mean the same (a label and its code).
fn same_value(def: Option<&ParamDef>, a: &str, b: &str) -> bool {
    let code = |v: &str| -> String {
        def.and_then(|d| enum_code(&d.labels, v))
            .map(|c| c.to_string())
            .unwrap_or_else(|| v.trim().to_string())
    };
    code(a) == code(b)
}

/// One parameter line before ordering.
struct ParamLine {
    item: Item,
    /// Sort key: (page order, document position, key).
    order: (usize, usize, String),
    /// (module instance, app-relative ref) of the ref ETS shows.
    at: (Option<String>, String),
    /// The refs gating it.
    gates: BTreeSet<String>,
}

/// The parameter items of device `ia`, ordered, and the notes for values
/// ETS has nothing to redo for or cannot show.
fn parameter_items(
    changes: &[&Change],
    old: &Model,
    new: &Model,
    products: &ProductModels,
    ia: IndividualAddress,
) -> (Vec<Item>, Vec<Item>) {
    let mut notes = Vec::new();
    let ctx =
        DeviceContext::new(new, products, ia).or_else(|| DeviceContext::new(old, products, ia));
    if ctx.as_ref().is_some_and(|c| c.pageless) {
        let mut note = Item::new(
            ChangeKind::ParameterChanged,
            format!(
                "{ia}: the cached product model carries no ETS pages (an older model format), \
                 so its parameters above lack their pages and old values. Run `bussard device \
                 {ia}` once to regenerate it, then this checklist again."
            ),
        );
        note.device = Some(ia.to_string());
        notes.push(note);
    }
    let mut lines: Vec<ParamLine> = Vec::new();
    for change in changes {
        let Some(key) = change.field.as_deref() else {
            continue;
        };
        let full = key.split_once('@').map_or(key, |(_, r)| r);
        let (instance, reference) = split_selector(full);
        let app = ctx
            .as_ref()
            .and_then(|c| c.device.product.as_ref())
            .and_then(|p| p.application_ref.as_deref());
        let def = app.and_then(|a| products.param_def(a, key));
        let default = ctx.as_ref().and_then(|c| c.vendor_default(key));
        let to = change.to.as_deref();
        let from = change.from.as_deref();
        // A side without a value has the vendor default, which ETS shows.
        let effective_to = to.map(str::to_string).or_else(|| default.clone());
        let effective_from = from.map(str::to_string).or_else(|| default.clone());
        let label = parameter_text(ctx.as_ref().and_then(|c| c.product), &reference, def)
            .unwrap_or_else(|| parameter_label(key));
        if let (Some(a), Some(b)) = (&effective_from, &effective_to)
            && same_value(def, a, b)
        {
            let mut note = Item::note(change);
            note.text = format!(
                "{label} on {ia}: the model stores the vendor default ({}) explicitly; \
                 ETS already shows it, nothing to do.",
                value_text(def, b)
            );
            notes.push(note);
            continue;
        }
        let value = effective_to.as_deref().map(|v| value_text(def, v));
        let old_value = effective_from.as_deref().map(|v| value_text(def, v));
        let shown = ctx.as_ref().and_then(|c| c.shown_ref(&reference));
        let Some(shown) = shown else {
            let mut note = Item::note(change);
            note.text = format!(
                "{label} on {ia}: {} (was {}). ETS does not show this parameter under the new \
                 values; it should follow from the others. Check it after the export.",
                value.as_deref().unwrap_or("default"),
                old_value.as_deref().unwrap_or("default"),
            );
            notes.push(note);
            continue;
        };
        let (page_order, page) = ctx.as_ref().map(|c| c.page(&shown)).unwrap_or((None, None));
        let position = ctx
            .as_ref()
            .and_then(|c| c.positions.get(&shown).copied())
            .unwrap_or(usize::MAX);
        let gates = ctx.as_ref().map(|c| c.gates(&shown)).unwrap_or_default();
        let mut text = match &page {
            Some(p) => format!("{p} › {label}: "),
            None => format!("{label}: "),
        };
        text.push_str(value.as_deref().unwrap_or("default"));
        text.push_str(&format!(
            " (was {})",
            old_value.as_deref().unwrap_or("default")
        ));
        let mut item = Item::new(change.kind, text);
        item.device = Some(ia.to_string());
        item.page = page;
        item.label = Some(label);
        item.value = value;
        item.old_value = old_value;
        lines.push(ParamLine {
            item,
            order: (page_order.unwrap_or(usize::MAX), position, key.to_string()),
            at: (instance, shown),
            gates,
        });
    }
    lines.sort_by(|a, b| a.order.cmp(&b.order));
    let prerequisites: Vec<Vec<usize>> = lines
        .iter()
        .map(|line| {
            lines
                .iter()
                .enumerate()
                .filter(|(_, other)| {
                    other.at.0 == line.at.0
                        && other.at.1 != line.at.1
                        && line.gates.contains(&other.at.1)
                })
                .map(|(j, _)| j)
                .collect()
        })
        .collect();
    let order = enabling_first(lines.len(), &prerequisites);
    let mut slots: Vec<Option<ParamLine>> = lines.into_iter().map(Some).collect();
    let items = order
        .into_iter()
        .filter_map(|i| slots.get_mut(i).and_then(Option::take))
        .map(|l| l.item)
        .collect();
    (items, notes)
}

/// The ETS text of a parameter ref: the ref's own text, else the
/// parameter's text, else its name.
fn parameter_text(
    product: Option<&ProductModel>,
    reference: &str,
    def: Option<&ParamDef>,
) -> Option<String> {
    let model_ref = crate::param_model::key_to_model_ref(&format!("x@{reference}"));
    product
        .and_then(|p| {
            p.parameter_refs
                .get(model_ref.as_deref().unwrap_or(reference))
        })
        .and_then(|r| r.text.clone())
        .or_else(|| def.and_then(|d| d.text.clone().or_else(|| d.name.clone())))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// The order of `n` lines already sorted by page: each line after the lines
/// it needs (`prerequisites[i]`, indexes into the same list), otherwise in
/// the given order. A cycle falls back to the given order.
fn enabling_first(n: usize, prerequisites: &[Vec<usize>]) -> Vec<usize> {
    let mut done = vec![false; n];
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let ready = (0..n).find(|i| {
            !done[*i]
                && prerequisites
                    .get(*i)
                    .is_none_or(|p| p.iter().all(|j| done.get(*j).is_none_or(|d| *d) || j == i))
        });
        let Some(next) = ready.or_else(|| (0..n).find(|i| !done[*i])) else {
            break;
        };
        done[next] = true;
        out.push(next);
    }
    out
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

impl Checklist {
    /// Renders the checklist as Markdown, `a` and `b` naming the two sides
    /// (`b` is what the closing `bussard diff <export> <b>` compares with).
    pub fn render_markdown(&self, a: &str, b: &str) -> String {
        let mut out = String::new();
        out.push_str("# ETS checklist\n\n");
        if self.changes == 0 {
            out.push_str(&format!(
                "No differences between {a} and {b}: nothing to redo in ETS.\n"
            ));
            return out;
        }
        out.push_str(&format!(
            "{} change(s) from {a} to {b}, to redo by hand in ETS.\n",
            self.changes
        ));
        if !self.groups.is_empty() {
            out.push_str("\n## Group addresses\n\n");
            push_items(&mut out, &self.groups);
        }
        for section in &self.devices {
            let mut head = section.address.clone();
            if !section.name.is_empty() {
                head.push(' ');
                head.push_str(&section.name);
            }
            if let Some(room) = &section.room {
                head.push_str(&format!(" ({room})"));
            }
            out.push_str(&format!("\n## {head}\n"));
            for (title, items) in [
                ("Device", &section.device),
                ("Parameters", &section.parameters),
                ("Objects and links", &section.objects),
                ("Security", &section.security),
            ] {
                if items.is_empty() {
                    continue;
                }
                out.push_str(&format!("\n*{title}*\n\n"));
                push_items(&mut out, items);
            }
        }
        if !self.notes.is_empty() {
            out.push_str("\n## Not in ETS by hand\n\n");
            for note in &self.notes {
                out.push_str(&format!("- {}\n", note.text));
            }
        }
        let notes = match self.notes.len() {
            0 => String::new(),
            1 => ", 1 note".to_string(),
            n => format!(", {n} notes"),
        };
        out.push_str(&format!(
            "\n{} item(s){notes}. Afterwards: export the project and run \
             bussard diff <export> {b}; it should report no changes.\n",
            self.items
        ));
        out
    }
}

/// Appends `items` as Markdown checkboxes.
fn push_items(out: &mut String, items: &[Item]) {
    for item in items {
        out.push_str(&format!("- [ ] {}\n", item.text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{describe, name_parameters};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const APP: &str = "M-00FA_A-0298-10-0000";
    const PRODUCT: &str = include_str!("../tests/fixtures/blocks_app.json");

    const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.30"
product = "WS-298"
application = "M-00FA_A-0298-10-0000"
mask = "0701"
channels = [
  { key = "generic-0", id = "CH-0", number = 0 },
]
objects = [
  { number = 0, key = "brightness", channel = "generic-0", text = "Brightness", function = "Physical value", dpt = "9.004", flags = "CRT", ref = "O-0_R-0" },
  { number = 2, key = "b-universal-channel", channel = "generic-0", text = "B Universal channel", function = "Switch", dpt = "1.001", flags = "CRT", ref = "O-2_R-2" },
]
parameters = [
  { key = "universal-channel-a-enable", channel = "generic-0", ref = "P-1_R-1", param = "P-1" },
  { key = "universal-channel-b-enable", channel = "generic-0", ref = "P-2_R-2", param = "P-2" },
  { key = "channel-function", channel = "generic-0", ref = "P-11_R-11", param = "P-11" },
  { key = "channel-function-b", channel = "generic-0", ref = "P-21_R-21", param = "P-21" },
  { key = "dusk-b", channel = "generic-0", ref = "P-22_R-22", param = "P-22" },
]
"#;

    /// The device file with `extra` lines in its channel table.
    fn device_file(extra: &str) -> String {
        format!(
            "address = \"1.1.30\"\nname = \"Weather station\"\nproduct = \"WS-298\"\n\n\
             [location]\nfloor = \"Outside\"\nroom = \"Roof\"\n\n\
             [channel.generic-0]\nuniversal-channel-a-enable = \"yes\"\n\
             channel-function = \"Temperature sensor\"\nbrightness.send = \"4/1/5\"\n{extra}"
        )
    }

    fn model(
        device: &str,
        groups: &str,
        config: &str,
    ) -> Result<Model, Box<dyn std::error::Error>> {
        let files: BTreeMap<String, String> = [
            ("bussard.lock", LOCK.to_string()),
            ("devices/1.1.30.toml", device.to_string()),
            ("groups.toml", groups.to_string()),
            ("bussard.toml", config.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        Ok(Model::from_texts(&files)?)
    }

    fn products() -> Result<ProductModels, Box<dyn std::error::Error>> {
        let mut products = ProductModels::default();
        products.insert(APP.to_string(), serde_json::from_str(PRODUCT)?);
        Ok(products)
    }

    const TUNNEL: &str = "[connection]\ntransport = \"tunnel\"\n";

    const GROUPS_A: &str = "ranges = [\n  { address = \"4\", name = \"Central\" },\n]\n\
        groups = [\n  { address = \"4/1/5\", name = \"Brightness\", dpt = \"9.004\" },\n\
        { address = \"4/1/6\", name = \"Old name\" },\n\
        { address = \"4/1/7\", name = \"Wind\", dpt = \"1.001\" },\n\
        { address = \"4/1/8\", name = \"Gone\" },\n\
        { address = \"4/1/9\", name = \"Alarm\" },\n]\n";

    const GROUPS_B: &str = "ranges = [\n  { address = \"4\", name = \"Central\" },\n\
        { address = \"4/1\", name = \"Weather\" },\n]\n\
        groups = [\n  { address = \"4/1/5\", name = \"Brightness\", dpt = \"9.004\" },\n\
        { address = \"4/1/6\", name = \"New name\" },\n\
        { address = \"4/1/7\", name = \"Wind\", dpt = \"1.002\", description = \"gusts\" },\n\
        { address = \"4/1/9\", name = \"Alarm\", secure = true, protected = true },\n\
        { address = \"4/1/20\", name = \"Outside dark\", dpt = \"1.001\" },\n]\n";

    /// The pair: B enabled with its brightness function and a dusk
    /// threshold, A's function unchanged but stored at its default on one
    /// side only, links and object security changed, groups and the
    /// gateway changed.
    fn pair() -> Result<(Model, Model, ChangeSet, ProductModels), Box<dyn std::error::Error>> {
        let old = model(&device_file(""), GROUPS_A, TUNNEL)?;
        let mut new = model(
            &device_file(
                "universal-channel-b-enable = \"yes\"\n\
                 channel-function-b = \"Brightness sensor 1 .. 100 000 lx\"\n\
                 dusk-b = \"42\"\nb-universal-channel.send = \"4/1/20\"\n\
                 b-universal-channel.listen = [\"4/1/6\"]\n",
            ),
            GROUPS_B,
            "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:3671\"\n",
        )?;
        let device = &mut new
            .devices
            .get_mut(&"1.1.30".parse()?)
            .ok_or("no device")?
            .device;
        device.name = "Weather station roof".to_string();
        if let Some(o) = device.com_objects.get_mut(&0) {
            o.secure = true;
        }
        let products = products()?;
        let mut set = describe(&old, &new);
        name_parameters(&mut set, [&new, &old], &products);
        Ok((old, new, set, products))
    }

    #[test]
    fn test_checklist_covers_every_kind_of_the_pair() -> TestResult {
        let (old, new, set, products) = pair()?;
        let list = checklist(&set, &old, &new, &products);
        let groups: Vec<&str> = list.groups.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(
            groups,
            [
                "4/1/20 \"Outside dark\", DPT 1.001, new (main group 4 \"Central\", \
                 new middle group 4/1 \"Weather\")",
                "4/1/6: rename to \"New name\" (was \"Old name\")",
                "4/1/7 \"Wind\": DPT 1.002 (was 1.001)",
                "4/1/7 \"Wind\": description \"gusts\" (was none)",
                "4/1/9 \"Alarm\": security on (was off)",
                "4/1/8 \"Gone\": delete",
            ]
        );
        assert_eq!(list.devices.len(), 1);
        let dev = &list.devices[0];
        assert_eq!(
            (dev.address.as_str(), dev.room.as_deref()),
            ("1.1.30", Some("Roof"))
        );
        assert_eq!(
            dev.device[0].text,
            "Device Weather station is now called \"Weather station roof\""
        );
        let params: Vec<&str> = dev.parameters.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(
            params,
            [
                "General › Universal channel B enable: yes (was no)",
                "Universal channel B: function › Dusk threshold in lx: 42 (was 10)",
            ]
        );
        let objects: Vec<&str> = dev.objects.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(
            objects,
            [
                "Objekt 2 \"B Universal channel\" (Switch): sends 4/1/20 (was nothing), \
              listens 4/1/6"
            ]
        );
        assert_eq!(
            dev.security[0].text,
            "Objekt 0 \"Brightness\" (Physical value): security on (was off)"
        );
        let notes: Vec<ChangeKind> = list.notes.iter().map(|n| n.kind).collect();
        assert_eq!(
            notes,
            [
                ChangeKind::ConnectionChanged,
                ChangeKind::GroupProtectionChanged,
                ChangeKind::ParameterChanged,
            ]
        );
        // The channel function of B is stored at its vendor default: ETS
        // shows it already.
        assert!(
            list.notes[2].text.contains("vendor default"),
            "{}",
            list.notes[2].text
        );
        assert_eq!(list.items, 6 + 1 + 2 + 1 + 1);
        Ok(())
    }

    #[test]
    fn test_render_markdown_lists_groups_devices_notes_and_the_closing_line() -> TestResult {
        let (old, new, set, products) = pair()?;
        let text = checklist(&set, &old, &new, &products).render_markdown("a.knxproj", "knx");
        let groups = text.find("## Group addresses").ok_or("no groups")?;
        let device = text
            .find("## 1.1.30 Weather station roof (Roof)")
            .ok_or("no device section")?;
        let notes = text.find("## Not in ETS by hand").ok_or("no notes")?;
        assert!(groups < device && device < notes, "{text}");
        assert!(
            text.contains("\n*Parameters*\n\n- [ ] General › "),
            "{text}"
        );
        assert!(text.contains("- The gateway changed"), "{text}");
        assert!(
            text.ends_with(
                "11 item(s), 3 notes. Afterwards: export the project and run bussard diff \
                 <export> knx; it should report no changes.\n"
            ),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn test_render_markdown_of_no_changes_says_so() {
        let text = Checklist::default().render_markdown("a", "b");
        assert!(text.contains("nothing to redo in ETS"), "{text}");
    }

    #[test]
    fn test_checklist_json_carries_page_label_and_values() -> TestResult {
        let (old, new, set, products) = pair()?;
        let value = serde_json::to_value(checklist(&set, &old, &new, &products))?;
        let p = &value["devices"][0]["parameters"][1];
        assert_eq!(p["kind"], "parameter_changed");
        assert_eq!(p["device"], "1.1.30");
        assert_eq!(p["page"], "Universal channel B: function");
        assert_eq!(p["label"], "Dusk threshold in lx");
        assert_eq!(p["value"], "42");
        assert_eq!(p["old_value"], "10");
        Ok(())
    }

    #[test]
    fn test_device_context_puts_parameters_on_their_pages() -> TestResult {
        let (_, new, _, products) = pair()?;
        let ctx = DeviceContext::new(&new, &products, "1.1.30".parse()?).ok_or("no device")?;
        let (order_b, page_b) = ctx.page("P-22_R-22");
        let (order_g, page_g) = ctx.page("P-2_R-2");
        assert_eq!(page_b.as_deref(), Some("Universal channel B: function"));
        assert_eq!(page_g.as_deref(), Some("General"));
        assert!(order_g < order_b);
        // B's dusk threshold sits behind B's switch and its function.
        let gates = ctx.gates("P-22_R-22");
        assert!(
            gates.contains("P-2_R-2") && gates.contains("P-21_R-21"),
            "{gates:?}"
        );
        Ok(())
    }

    #[test]
    fn test_enabling_first_moves_an_enabling_line_before_what_it_reveals() {
        // Line 0 needs line 2, line 2 needs line 1.
        let order = enabling_first(3, &[vec![2], vec![], vec![1]]);
        assert_eq!(order, [1, 2, 0]);
        // A cycle keeps the given order.
        assert_eq!(enabling_first(2, &[vec![1], vec![0]]), [0, 1]);
    }

    #[test]
    fn test_parameter_items_list_the_enabling_parameter_first() -> TestResult {
        // B's dusk threshold sits on B's page, behind B's switch on the
        // general page: the switch comes first.
        let (old, new, set, products) = pair()?;
        let list = checklist(&set, &old, &new, &products);
        let labels: Vec<&str> = list.devices[0]
            .parameters
            .iter()
            .filter_map(|i| i.label.as_deref())
            .collect();
        assert_eq!(
            labels,
            ["Universal channel B enable", "Dusk threshold in lx"]
        );
        Ok(())
    }

    #[test]
    fn test_checklist_without_product_models_keeps_keys_and_values() -> TestResult {
        let (old, new, set, _) = pair()?;
        let list = checklist(&set, &old, &new, &ProductModels::default());
        let params: Vec<&str> = list.devices[0]
            .parameters
            .iter()
            .map(|i| i.text.as_str())
            .collect();
        assert!(params.contains(&"Dusk b: 42 (was default)"), "{params:?}");
        Ok(())
    }

    #[test]
    fn test_checklist_notes_a_product_model_without_pages() -> TestResult {
        let (old, new, set, _) = pair()?;
        let mut product: ProductModel = serde_json::from_str(PRODUCT)?;
        product.dynamic.clear();
        let mut products = ProductModels::default();
        products.insert(APP.to_string(), product);
        let list = checklist(&set, &old, &new, &products);
        assert!(
            list.notes
                .iter()
                .any(|n| n.text.contains("Run `bussard device 1.1.30` once")),
            "{:?}",
            list.notes
        );
        Ok(())
    }

    #[test]
    fn test_object_item_names_a_removed_send_and_listen() -> TestResult {
        let (old, new, _, _) = pair()?;
        // Reversed: the new side loses the links.
        let item = object_item(&new, &old, "1.1.30".parse()?, 2, ChangeKind::LinkRemoved)
            .ok_or("no item")?;
        assert_eq!(
            item.text,
            "Objekt 2 \"B Universal channel\" (Switch): sends nothing (was 4/1/20), \
             listens nothing (was 4/1/6)"
        );
        Ok(())
    }

    #[test]
    fn test_checklist_new_device_gets_a_device_line() -> TestResult {
        let old = model(&device_file(""), GROUPS_A, TUNNEL)?;
        let mut empty = old.clone();
        empty.devices.clear();
        empty.links.links.clear();
        let set = describe(&empty, &old);
        let list = checklist(&set, &empty, &old, &products()?);
        let dev = &list.devices[0];
        assert_eq!(dev.device[0].kind, ChangeKind::DeviceAdded);
        assert!(
            dev.device[0]
                .text
                .starts_with("New device Weather station in")
        );
        assert_eq!(dev.objects.len(), 1, "{:?}", dev.objects);
        Ok(())
    }
}
