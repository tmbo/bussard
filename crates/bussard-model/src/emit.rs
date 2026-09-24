//! Writing the model files.
//!
//! Every file is TOML 1.0 with basic strings only. A file that already exists
//! is edited in place with `toml_edit`: entries whose meaning is unchanged keep
//! their bytes (comments, alignment, inline vs dotted style), changed entries
//! are re-formatted, added entries are appended, and removed entries are
//! dropped. Without an existing file the output is rendered fresh, sorted and
//! deterministic.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::files::{
    DeviceEntries, EntryValue, LOCK_HEADER, LOCK_VERSION, LockDevice, Placement, Resolver,
    TableRef, channel_label, device_entries, existing_placements, handle_of, scope_entries,
};
use crate::loader::SaveError;
use crate::param_model::ProductModels;
use crate::schema::{BussardConfig, Device, Group, Groups, Link};
use crate::toml_io;

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// Encodes `s` as a TOML basic string (`"…"`), escaping as TOML 1.0 requires.
pub(crate) fn basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A key as TOML writes it: bare when it can be, a basic string otherwise.
pub(crate) fn toml_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        key.to_string()
    } else {
        basic_string(key)
    }
}

/// A string value that renders as a basic string.
fn string_value(s: &str) -> Value {
    basic_string(s)
        .parse::<Value>()
        .unwrap_or_else(|_| Value::from(s))
}

/// A string item.
fn string_item(s: &str) -> Item {
    Item::Value(string_value(s))
}

// ---------------------------------------------------------------------------
// Semantic comparison
// ---------------------------------------------------------------------------

/// A formatting-free view of a TOML item, for "did this entry change?".
#[derive(Debug, PartialEq)]
enum Plain {
    Scalar(String),
    Array(Vec<Plain>),
    Table(BTreeMap<String, Plain>),
}

fn plain_value(v: &Value) -> Plain {
    match v {
        Value::String(s) => Plain::Scalar(s.value().clone()),
        Value::Integer(i) => Plain::Scalar(i.value().to_string()),
        Value::Float(f) => Plain::Scalar(f.value().to_string()),
        Value::Boolean(b) => Plain::Scalar(b.value().to_string()),
        Value::Datetime(d) => Plain::Scalar(d.value().to_string()),
        Value::Array(a) => Plain::Array(a.iter().map(plain_value).collect()),
        Value::InlineTable(t) => plain_table(t),
    }
}

fn plain_table(t: &dyn TableLike) -> Plain {
    Plain::Table(
        t.iter()
            .filter_map(|(k, v)| plain_item(v).map(|p| (k.to_string(), p)))
            .collect(),
    )
}

fn plain_item(item: &Item) -> Option<Plain> {
    match item {
        Item::None => None,
        Item::Value(v) => Some(plain_value(v)),
        Item::Table(t) => Some(plain_table(t)),
        Item::ArrayOfTables(a) => Some(Plain::Array(a.iter().map(|t| plain_table(t)).collect())),
    }
}

fn same(a: &Item, b: &Item) -> bool {
    plain_item(a) == plain_item(b)
}

/// Replaces `slot` with `new`, keeping the old value's comments and spacing
/// where both are plain values, and the inline style of an inline table.
fn replace_item(slot: &mut Item, new: &Item) {
    match (slot.as_value(), new) {
        (Some(old), Item::Value(v)) => {
            let mut v = v.clone();
            *v.decor_mut() = old.decor().clone();
            *slot = Item::Value(v);
        }
        (Some(Value::InlineTable(old)), Item::Table(t)) => {
            let mut inline = t.clone().into_inline_table();
            inline.fmt();
            *inline.decor_mut() = old.decor().clone();
            *slot = Item::Value(Value::InlineTable(inline));
        }
        _ => *slot = new.clone(),
    }
}

// ---------------------------------------------------------------------------
// bussard.toml
// ---------------------------------------------------------------------------

/// The banner of a fresh `bussard.toml`.
pub(crate) const CONFIG_HEADER: &str = "\
# bussard.toml: connection settings for `bussard`, hand-editable.
# Sets the transport (\"tunnel\" or \"routing\"), the gateway, the multicast
# endpoint and, optionally, the KNX Secure keyring file (relative to this
# directory). See docs/model-format.md.
";

/// Renders a fresh `bussard.toml`.
pub(crate) fn render_config(path: &Path, config: &BussardConfig) -> Result<String, SaveError> {
    let body = toml::to_string(config).map_err(|e| SaveError::Serialize {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    Ok(format!("{CONFIG_HEADER}\n{body}"))
}

// ---------------------------------------------------------------------------
// groups.toml
// ---------------------------------------------------------------------------

/// Column widths for the aligned entry rows.
#[derive(Debug, Default, Clone, Copy)]
struct Widths {
    address: usize,
    name: usize,
}

/// `address = "…",` for an entry.
fn address_cell(address: &str) -> String {
    format!("address = {},", basic_string(address))
}

/// `name = "…"` for an entry.
fn name_cell(name: &str) -> String {
    format!("name = {}", basic_string(name))
}

/// One aligned row: `{ address = "0/0/1", name = "…",   dpt = "1.001" }`.
fn entry_row(address: &str, name: &str, rest: &[String], w: Widths) -> String {
    let a = address_cell(address);
    let n = name_cell(name);
    let mut out = format!("{{ {a}{} {n}", pad(&a, w.address));
    if !rest.is_empty() {
        let n_comma = format!("{n},");
        out.push(',');
        out.push_str(&pad(&n_comma, w.name + 1));
        out.push(' ');
        out.push_str(&rest.join(", "));
    }
    out.push_str(" }");
    out
}

/// Spaces that pad `cell` to `width` characters.
fn pad(cell: &str, width: usize) -> String {
    " ".repeat(width.saturating_sub(cell.chars().count()))
}

/// The optional fields of a group entry, in their fixed order.
fn group_rest(group: &Group) -> Vec<String> {
    let mut rest = Vec::new();
    if let Some(dpt) = &group.dpt {
        rest.push(format!("dpt = {}", basic_string(&dpt.to_string())));
    }
    if let Some(d) = &group.description {
        rest.push(format!("description = {}", basic_string(d)));
    }
    if group.protected {
        rest.push("protected = true".to_string());
    }
    if group.secure {
        rest.push("secure = true".to_string());
    }
    rest
}

/// Widths over every group row (names only matter when a field follows).
fn group_widths(groups: &Groups) -> Widths {
    let mut w = Widths::default();
    for (ga, g) in &groups.groups {
        w.address = w.address.max(address_cell(&ga.to_string()).chars().count());
        if !group_rest(g).is_empty() {
            w.name = w.name.max(name_cell(&g.name).chars().count());
        }
    }
    w
}

/// Widths over every range row.
fn range_widths(groups: &Groups) -> Widths {
    let mut w = Widths::default();
    for key in groups.ranges.keys() {
        w.address = w.address.max(address_cell(key).chars().count());
    }
    w
}

/// The desired rows, keyed by address, in file order.
fn group_rows(groups: &Groups) -> Vec<(String, String)> {
    let w = group_widths(groups);
    groups
        .groups
        .iter()
        .map(|(ga, g)| {
            let addr = ga.to_string();
            let row = entry_row(&addr, &g.name, &group_rest(g), w);
            (addr, row)
        })
        .collect()
}

fn range_rows(groups: &Groups) -> Vec<(String, String)> {
    let w = range_widths(groups);
    let mut keys: Vec<&String> = groups.ranges.keys().collect();
    keys.sort_by_key(|k| range_order(k));
    keys.into_iter()
        .filter_map(|k| {
            let r = groups.ranges.get(k)?;
            Some((k.clone(), entry_row(k, &r.name, &[], w)))
        })
        .collect()
}

/// Sort key for a range address: numeric parts first, so `"10"` follows `"9"`.
fn range_order(key: &str) -> (Vec<u32>, String) {
    let parts = key
        .split('/')
        .map(|p| p.trim().parse::<u32>().unwrap_or(u32::MAX))
        .collect();
    (parts, key.to_string())
}

/// Renders a fresh `groups.toml`.
pub(crate) fn render_groups_fresh(groups: &Groups) -> String {
    let mut out = String::new();
    if let Some(p) = &groups.project {
        out.push_str(&format!("project = {}\n", basic_string(p)));
    }
    for (name, rows) in [
        ("ranges", range_rows(groups)),
        ("groups", group_rows(groups)),
    ] {
        if rows.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("{name} = [\n"));
        for (_, row) in rows {
            out.push_str("  ");
            out.push_str(&row);
            out.push_str(",\n");
        }
        out.push_str("]\n");
    }
    out
}

/// The address an existing array element names, if it is a table with one.
fn element_address(v: &Value) -> Option<String> {
    v.as_inline_table()?
        .get("address")?
        .as_str()
        .map(str::to_string)
}

/// Canonical form of a group address string, so `"1/2/3"` spelled oddly still
/// matches.
fn canonical_ga(s: &str) -> String {
    s.parse::<crate::address::GroupAddress>()
        .map(|g| g.to_string())
        .unwrap_or_else(|_| s.to_string())
}

/// Merges desired rows into an existing array: unchanged rows keep their
/// bytes, changed rows are replaced, missing rows are removed, new rows are
/// inserted in address order.
fn merge_rows(
    array: &mut Array,
    rows: &[(String, String)],
    canonical: impl Fn(&str) -> String,
    order: impl Fn(&str) -> Vec<u32>,
) {
    let desired: BTreeMap<String, &String> = rows.iter().map(|(a, r)| (canonical(a), r)).collect();
    let mut present: BTreeSet<String> = BTreeSet::new();
    // Update or drop existing elements.
    let mut i = 0;
    while i < array.len() {
        let addr = array
            .get(i)
            .and_then(element_address)
            .map(|a| canonical(&a));
        match addr.as_ref().and_then(|a| desired.get(a).map(|r| (a, r))) {
            Some((a, row)) if !present.contains(a) => {
                present.insert(a.clone());
                if let (Some(existing), Ok(new)) = (array.get(i), row.parse::<Value>())
                    && plain_value(existing) != plain_value(&new)
                {
                    let decor = existing.decor().clone();
                    let mut new = new;
                    *new.decor_mut() = decor;
                    array.replace_formatted(i, new);
                }
                i += 1;
            }
            _ => {
                array.remove(i);
            }
        }
    }
    // Insert the new ones in order.
    let multiline = array.is_empty()
        || array.trailing().as_str().is_some_and(|t| t.contains('\n'))
        || array.iter().any(|v| {
            v.decor()
                .prefix()
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains('\n'))
        });
    for (addr, row) in rows {
        let key = canonical(addr);
        if present.contains(&key) {
            continue;
        }
        let Ok(mut value) = row.parse::<Value>() else {
            continue;
        };
        value
            .decor_mut()
            .set_prefix(if multiline { "\n  " } else { " " });
        value.decor_mut().set_suffix("");
        let at = (0..array.len())
            .find(|&j| {
                array
                    .get(j)
                    .and_then(element_address)
                    .is_some_and(|a| order(&canonical(&a)) > order(&key))
            })
            .unwrap_or(array.len());
        array.insert_formatted(at, value);
    }
    if multiline && !array.is_empty() {
        array.set_trailing_comma(true);
        if !array.trailing().as_str().is_some_and(|t| t.contains('\n')) {
            array.set_trailing("\n");
        }
    }
}

/// Numeric sort key for a group address string.
fn ga_order(s: &str) -> Vec<u32> {
    s.split('/')
        .map(|p| p.trim().parse::<u32>().unwrap_or(u32::MAX))
        .collect()
}

/// Renders `groups.toml`, editing `existing` in place when given.
pub(crate) fn render_groups(
    path: &Path,
    groups: &Groups,
    existing: Option<&str>,
) -> Result<String, SaveError> {
    let Some(existing) = existing else {
        return Ok(render_groups_fresh(groups));
    };
    let Ok(mut doc) = toml_io::parse_document_mut(path, existing) else {
        return Ok(render_groups_fresh(groups));
    };
    match (&groups.project, doc.get_mut("project")) {
        (Some(p), Some(slot)) => {
            let new = string_item(p);
            if !same(slot, &new) {
                replace_item(slot, &new);
            }
        }
        (Some(p), None) => {
            doc.insert("project", string_item(p));
        }
        (None, Some(_)) => {
            doc.remove("project");
        }
        (None, None) => {}
    }
    for (name, rows, canonical) in [
        ("ranges", range_rows(groups), false),
        ("groups", group_rows(groups), true),
    ] {
        let canon = |s: &str| {
            if canonical {
                canonical_ga(s)
            } else {
                s.trim().to_string()
            }
        };
        match doc.get_mut(name).and_then(Item::as_array_mut) {
            Some(array) => merge_rows(array, &rows, canon, ga_order),
            None => {
                if rows.is_empty() {
                    continue;
                }
                let mut array = Array::new();
                merge_rows(&mut array, &rows, canon, ga_order);
                let mut item = Item::Value(Value::Array(array));
                if let Some(v) = item.as_value_mut() {
                    v.decor_mut().set_prefix(" ");
                }
                doc.insert(name, item);
                if let Some(mut key) = doc.key_mut(name) {
                    key.leaf_decor_mut().set_prefix("\n");
                }
            }
        }
    }
    // Drop an array that is now empty.
    for name in ["ranges", "groups"] {
        if doc
            .get(name)
            .and_then(Item::as_array)
            .is_some_and(Array::is_empty)
        {
            doc.remove(name);
        }
    }
    Ok(doc.to_string())
}

// ---------------------------------------------------------------------------
// bussard.lock
// ---------------------------------------------------------------------------

/// Renders `bussard.lock`, always fresh (it is fully generated).
pub(crate) fn render_lock(source: Option<&str>, devices: &[LockDevice]) -> String {
    let mut out = format!("{LOCK_HEADER}\nversion = {LOCK_VERSION}\n");
    if let Some(s) = source {
        out.push_str(&format!("source = {}\n", basic_string(s)));
    }
    for d in devices {
        out.push_str("\n[[device]]\n");
        out.push_str(&format!(
            "address = {}\n",
            basic_string(&d.address.to_string())
        ));
        let strings = [
            ("product", &d.product),
            ("application", &d.application),
            ("manufacturer", &d.manufacturer),
            ("manufacturer_ref", &d.manufacturer_ref),
            ("hardware_ref", &d.hardware_ref),
            ("mask", &d.mask),
        ];
        for (k, v) in strings {
            if let Some(v) = v {
                out.push_str(&format!("{k} = {}\n", basic_string(v)));
            }
        }
        if d.secure_capable {
            out.push_str("secure_capable = true\n");
        }
        if d.has_fdsk_certificate {
            out.push_str("has_fdsk_certificate = true\n");
        }
        if let Some(n) = d.sequence_number {
            out.push_str(&format!("sequence_number = {n}\n"));
        }
        let channels: Vec<String> = d
            .channels
            .iter()
            .map(|c| {
                let mut f = Vec::new();
                if let Some(k) = &c.key {
                    f.push(format!("key = {}", basic_string(k)));
                }
                f.push(format!("id = {}", basic_string(&c.id)));
                if let Some(n) = c.number {
                    f.push(format!("number = {n}"));
                }
                if let Some(t) = &c.text {
                    f.push(format!("text = {}", basic_string(t)));
                }
                if let Some(l) = &c.label_ref {
                    f.push(format!("label_ref = {}", basic_string(l)));
                }
                if let Some(b) = c.base {
                    f.push(format!("base = {b}"));
                }
                f.join(", ")
            })
            .collect();
        push_array(&mut out, "channels", &channels);
        if !d.module_bases.is_empty() {
            let cells: Vec<String> = d
                .module_bases
                .iter()
                .map(|(k, v)| format!("{} = {v}", toml_key(k)))
                .collect();
            out.push_str(&format!("module_bases = {{ {} }}\n", cells.join(", ")));
        }
        let objects: Vec<String> = d
            .objects
            .iter()
            .map(|o| {
                let mut f = vec![format!("number = {}", o.number)];
                for (k, v) in [
                    ("key", &o.key),
                    ("channel", &o.channel),
                    ("text", &o.text),
                    ("function", &o.function),
                ] {
                    if let Some(v) = v {
                        f.push(format!("{k} = {}", basic_string(v)));
                    }
                }
                if let Some(dpt) = &o.dpt {
                    f.push(format!("dpt = {}", basic_string(&dpt.to_string())));
                }
                if let Some(s) = &o.size {
                    f.push(format!("size = {}", basic_string(s)));
                }
                f.push(format!("flags = {}", basic_string(&o.flags.to_string())));
                if let Some(r) = &o.reference {
                    f.push(format!("ref = {}", basic_string(r)));
                }
                if o.secure {
                    f.push("secure = true".to_string());
                }
                f.join(", ")
            })
            .collect();
        push_array(&mut out, "objects", &objects);
        let params: Vec<String> = d
            .parameters
            .iter()
            .map(|p| {
                let mut f = vec![format!("key = {}", basic_string(&p.key))];
                if let Some(c) = &p.channel {
                    f.push(format!("channel = {}", basic_string(c)));
                }
                f.push(format!("ref = {}", basic_string(&p.reference)));
                if let Some(param) = &p.param {
                    f.push(format!("param = {}", basic_string(param)));
                }
                f.join(", ")
            })
            .collect();
        push_array(&mut out, "parameters", &params);
    }
    out
}

/// Appends `name = [ { … }, … ]`, one inline table per line.
fn push_array(out: &mut String, name: &str, rows: &[String]) {
    if rows.is_empty() {
        return;
    }
    out.push_str(&format!("{name} = [\n"));
    for row in rows {
        out.push_str(&format!("  {{ {row} }},\n"));
    }
    out.push_str("]\n");
}

// ---------------------------------------------------------------------------
// devices/<address>.toml
// ---------------------------------------------------------------------------

/// The item for one device-file entry.
fn entry_item(value: &EntryValue) -> Item {
    match value {
        EntryValue::Param(v) => string_item(v),
        EntryValue::Object { send, listen, name } => {
            let mut t = Table::new();
            t.set_dotted(true);
            if let Some(send) = send {
                t.insert("send", string_item(&send.to_string()));
            }
            if !listen.is_empty() {
                let mut a = Array::new();
                for ga in listen {
                    a.push(string_value(&ga.to_string()));
                }
                t.insert("listen", Item::Value(Value::Array(a)));
            }
            if let Some(name) = name {
                t.insert("name", string_item(name));
            }
            if t.is_empty() {
                // `144 = {}`: an object entry with nothing linked yet.
                Item::Value(Value::InlineTable(InlineTable::new()))
            } else {
                Item::Table(t)
            }
        }
    }
}

/// The desired device document, built fresh.
fn desired_device(device: &Device, entries: &[(Placement, EntryValue)]) -> DocumentMut {
    let mut doc = DocumentMut::new();
    doc.insert("address", string_item(&device.address.to_string()));
    doc.insert("name", string_item(&device.name));
    if let Some(d) = &device.description {
        doc.insert("description", string_item(d));
    }
    if let Some(p) = device
        .product
        .as_ref()
        .and_then(|p| p.order_number.as_ref())
    {
        doc.insert("product", string_item(p));
    }
    if let Some(a) = &device.application_override {
        doc.insert("application", string_item(a));
    }
    if let Some(r) = &device.replaced {
        doc.insert("replaced", string_item(r));
    }
    if let Some(loc) = &device.location
        && (loc.floor.is_some() || loc.room.is_some())
    {
        let mut t = Table::new();
        if let Some(f) = &loc.floor {
            t.insert("floor", string_item(f));
        }
        if let Some(r) = &loc.room {
            t.insert("room", string_item(r));
        }
        doc.insert("location", Item::Table(t));
    }
    if let Some(sec) = &device.security
        && (sec.activated || sec.secure_commissioning)
    {
        let mut t = Table::new();
        t.insert("activated", toml_edit::value(sec.activated));
        t.insert(
            "secure_commissioning",
            toml_edit::value(sec.secure_commissioning),
        );
        doc.insert("security", Item::Table(t));
    }

    // Group the entries per table: params (sorted by key) before objects (in
    // number order, as `device_entries` produced them), pages last.
    let mut tables: BTreeMap<TableRef, Vec<&(Placement, EntryValue)>> = BTreeMap::new();
    for e in entries {
        tables.entry(e.0.table.clone()).or_default().push(e);
    }
    let fill = |t: &mut Table, list: &[&(Placement, EntryValue)]| {
        let mut params: Vec<&(Placement, EntryValue)> = list
            .iter()
            .copied()
            .filter(|(p, v)| p.page.is_none() && matches!(v, EntryValue::Param(_)))
            .collect();
        params.sort_by(|a, b| a.0.key.cmp(&b.0.key));
        for (p, v) in params {
            t.insert(&p.key, entry_item(v));
        }
        for (p, v) in list.iter().copied() {
            if p.page.is_none() && matches!(v, EntryValue::Object { .. }) {
                t.insert(&p.key, entry_item(v));
            }
        }
        let mut pages: BTreeMap<&str, Vec<&(Placement, EntryValue)>> = BTreeMap::new();
        for e in list.iter().copied() {
            if let Some(page) = &e.0.page {
                pages.entry(page).or_default().push(e);
            }
        }
        for (page, mut list) in pages {
            list.sort_by(|a, b| a.0.key.cmp(&b.0.key));
            let mut pt = Table::new();
            for (p, v) in list {
                pt.insert(&p.key, entry_item(v));
            }
            t.insert(page, Item::Table(pt));
        }
    };
    for (name, table) in [
        ("parameters", TableRef::Parameters),
        ("links", TableRef::Links),
    ] {
        if let Some(list) = tables.get(&table) {
            let mut t = Table::new();
            fill(&mut t, list);
            doc.insert(name, Item::Table(t));
        }
    }

    // Channels: the device's own (in id order), then any handle an entry names
    // that the device does not define.
    let mut order: Vec<String> = Vec::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (id, ch) in &device.channels {
        let handle = handle_of(device, id);
        // A renamed channel writes its name; a labelled one otherwise writes
        // its label parameter's value (the two agree after a load).
        let renamed = !ch.name.is_empty() && Some(&ch.name) != ch.text.as_ref();
        let label = match channel_label(device, id) {
            Some(value) if !renamed || ch.name == value => Some(value.to_string()),
            _ => renamed.then(|| ch.name.clone()),
        };
        if let Some(label) = label {
            names.insert(handle.clone(), label);
        }
        order.push(handle);
    }
    for table in tables.keys() {
        if let TableRef::Channel(h) = table
            && !order.contains(h)
        {
            order.push(h.clone());
        }
    }
    let mut channel = Table::new();
    channel.set_implicit(true);
    for handle in order {
        let list = tables.get(&TableRef::Channel(handle.clone()));
        let name = names.get(&handle);
        if list.is_none() && name.is_none() {
            continue;
        }
        let mut t = Table::new();
        if let Some(name) = name {
            t.insert("name", string_item(name));
        }
        if let Some(list) = list {
            fill(&mut t, list);
        }
        channel.insert(&handle, Item::Table(t));
    }
    if !channel.is_empty() {
        doc.insert("channel", Item::Table(channel));
    }
    doc
}

/// Renders a device file, editing `existing` in place when given.
///
/// `lock` is the lock entry this save writes for the device; it resolves the
/// keys of the existing file.
pub(crate) fn render_device(
    path: &Path,
    device: &Device,
    links: &[Link],
    lock: Option<&LockDevice>,
    existing: Option<&str>,
    models: Option<&ProductModels>,
) -> String {
    let resolver = Resolver::new(lock);
    let parsed = existing.and_then(|text| {
        let doc = toml_io::parse_document(path, text).ok()?;
        let entries = scope_entries(path, text, &doc).ok()?;
        let doc_mut = toml_io::parse_document_mut(path, text).ok()?;
        Some((entries, doc_mut))
    });
    let empty = DeviceEntries::default();
    let placements = existing_placements(parsed.as_ref().map_or(&empty, |(e, _)| e), &resolver);
    let entries = device_entries(device, links, &placements, models);
    let desired = desired_device(device, &entries);
    match parsed {
        None => desired.to_string(),
        Some((_, mut doc)) => {
            merge_device(doc.as_table_mut(), desired.as_table(), &resolver);
            doc.to_string()
        }
    }
}

/// The top-level keys of a device file whose tables hold entries.
const SCOPE_TABLES: [&str; 2] = ["parameters", "links"];

/// Merges the desired device document into the existing one.
fn merge_device(existing: &mut Table, desired: &Table, resolver: &Resolver) {
    for (key, want) in desired.iter() {
        match key {
            "parameters" | "links" => merge_scope_slot(existing, key, want, None, resolver),
            "channel" => {
                let Some(want) = want.as_table() else {
                    continue;
                };
                if existing
                    .get("channel")
                    .and_then(Item::as_table_like)
                    .is_none()
                {
                    existing.insert("channel", Item::Table(want.clone()));
                    continue;
                }
                if let Some(have) = existing
                    .get_mut("channel")
                    .and_then(Item::as_table_like_mut)
                {
                    for (handle, want_ch) in want.iter() {
                        merge_scope_like(have, handle, want_ch, Some(handle), resolver);
                    }
                    let stale: Vec<String> = have
                        .iter()
                        .map(|(k, _)| k.to_string())
                        .filter(|k| want.get(k).is_none())
                        .collect();
                    for handle in stale {
                        prune_scope_like(have, &handle, Some(&handle), resolver);
                    }
                }
            }
            _ => merge_plain_slot(existing, key, want),
        }
    }
    let stale: Vec<String> = existing
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| desired.get(k).is_none())
        .collect();
    for key in stale {
        if SCOPE_TABLES.contains(&key.as_str()) {
            let scope_empty = Table::new();
            merge_scope_slot(existing, &key, &Item::Table(scope_empty), None, resolver);
            if existing
                .get(&key)
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                existing.remove(&key);
            }
        } else if key == "channel" {
            if let Some(have) = existing
                .get_mut("channel")
                .and_then(Item::as_table_like_mut)
            {
                let handles: Vec<String> = have.iter().map(|(k, _)| k.to_string()).collect();
                for handle in handles {
                    prune_scope_like(have, &handle, Some(&handle), resolver);
                }
            }
            if existing
                .get("channel")
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                existing.remove("channel");
            }
        } else {
            existing.remove(&key);
        }
    }
}

/// Sets, keeps or replaces a plain key (or plain table such as `[location]`).
fn merge_plain_slot(existing: &mut Table, key: &str, want: &Item) {
    match existing.get_mut(key) {
        None => {
            existing.insert(key, want.clone());
        }
        Some(slot) => {
            if same(slot, want) {
                return;
            }
            if let (Some(have), Some(want_t)) = (slot.as_table_like_mut(), want.as_table_like()) {
                for (k, v) in want_t.iter() {
                    match have.get_mut(k) {
                        Some(s) => {
                            if !same(s, v) {
                                replace_item(s, v);
                            }
                        }
                        None => {
                            have.insert(k, v.clone());
                        }
                    }
                }
                let stale: Vec<String> = have
                    .iter()
                    .map(|(k, _)| k.to_string())
                    .filter(|k| want_t.get(k).is_none())
                    .collect();
                for k in stale {
                    have.remove(&k);
                }
            } else {
                replace_item(slot, want);
            }
        }
    }
}

/// Merges one scope table held under `key` in a [`Table`].
fn merge_scope_slot(
    existing: &mut Table,
    key: &str,
    want: &Item,
    scope: Option<&str>,
    resolver: &Resolver,
) {
    let t: &mut dyn TableLike = existing;
    merge_scope_like(t, key, want, scope, resolver);
}

/// Merges one scope table (a channel, `[parameters]` or `[links]`) held under
/// `key` in `parent`.
fn merge_scope_like(
    parent: &mut dyn TableLike,
    key: &str,
    want: &Item,
    scope: Option<&str>,
    resolver: &Resolver,
) {
    let Some(want_t) = want.as_table_like() else {
        return;
    };
    if parent.get(key).and_then(Item::as_table_like).is_none() {
        parent.insert(key, want.clone());
        return;
    }
    let Some(have) = parent.get_mut(key).and_then(Item::as_table_like_mut) else {
        return;
    };
    merge_entries(have, want_t, scope, resolver, false);
}

/// Merges entries of a scope table or a page.
fn merge_entries(
    have: &mut dyn TableLike,
    want: &dyn TableLike,
    scope: Option<&str>,
    resolver: &Resolver,
    in_page: bool,
) {
    for (k, v) in want.iter() {
        match have.get_mut(k) {
            None => {
                have.insert(k, v.clone());
            }
            Some(slot) => {
                if same(slot, v) {
                    continue;
                }
                let is_page = v.is_table() && !is_object_item(v);
                if is_page
                    && !in_page
                    && let Some(have_page) = slot.as_table_like_mut()
                    && let Some(want_page) = v.as_table_like()
                {
                    merge_entries(have_page, want_page, scope, resolver, true);
                    continue;
                }
                if is_object_item(v)
                    && slot.is_table()
                    && let (Some(h), Some(w)) = (slot.as_table_like_mut(), v.as_table_like())
                {
                    for (f, fv) in w.iter() {
                        match h.get_mut(f) {
                            Some(s) => {
                                if !same(s, fv) {
                                    replace_item(s, fv);
                                }
                            }
                            None => {
                                h.insert(f, fv.clone());
                            }
                        }
                    }
                    let stale: Vec<String> = h
                        .iter()
                        .map(|(f, _)| f.to_string())
                        .filter(|f| w.get(f).is_none())
                        .collect();
                    for f in stale {
                        h.remove(&f);
                    }
                    continue;
                }
                replace_item(slot, v);
            }
        }
    }
    let stale: Vec<String> = have
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| want.get(k).is_none())
        .collect();
    for k in stale {
        let Some(item) = have.get(&k) else {
            continue;
        };
        if item.is_table_like() && !is_object_item(item) && !in_page {
            // A page: drop what it no longer holds, then the page if empty.
            if let Some(page) = have.get_mut(&k).and_then(Item::as_table_like_mut) {
                let empty = Table::new();
                merge_entries(page, &empty, scope, resolver, true);
            }
            if have
                .get(&k)
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                have.remove(&k);
            }
            continue;
        }
        let removable = if is_object_item(item) {
            // An object key the lock cannot resolve stays for validation.
            resolver.object(scope, &k).is_some()
        } else {
            true
        };
        if removable {
            have.remove(&k);
        }
    }
}

/// Drops a whole channel table's resolvable entries, keeping what validation
/// must still see, and the table itself when nothing remains.
fn prune_scope_like(
    parent: &mut dyn TableLike,
    key: &str,
    scope: Option<&str>,
    resolver: &Resolver,
) {
    if let Some(have) = parent.get_mut(key).and_then(Item::as_table_like_mut) {
        let empty = Table::new();
        merge_entries(have, &empty, scope, resolver, false);
    }
    if parent
        .get(key)
        .and_then(Item::as_table_like)
        .is_some_and(TableLike::is_empty)
    {
        parent.remove(key);
    }
}

/// Whether an item is shaped like an object entry.
fn is_object_item(item: &Item) -> bool {
    item.as_table_like().is_some_and(|t| {
        let keys: Vec<&str> = t.iter().map(|(k, _)| k).collect();
        keys.iter()
            .all(|k| matches!(*k, "send" | "listen" | "name"))
            || keys.iter().any(|k| *k == "send" || *k == "listen")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_string_escapes_quotes_and_controls() {
        assert_eq!(basic_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(basic_string("x\ny"), "\"x\\ny\"");
        assert_eq!(basic_string("it's"), "\"it's\"");
    }

    #[test]
    fn test_toml_key_quotes_only_when_needed() {
        assert_eq!(toml_key("a-1_B"), "a-1_B");
        assert_eq!(toml_key("x@P-1_R-2"), "\"x@P-1_R-2\"");
        assert_eq!(toml_key("1.1"), "\"1.1\"");
    }

    #[test]
    fn test_entry_row_pads_the_name_column() {
        let w = Widths {
            address: address_cell("0/0/10").chars().count(),
            name: name_cell("Longer name").chars().count(),
        };
        let row = entry_row("0/0/1", "Short", &["dpt = \"1.001\"".to_string()], w);
        assert_eq!(
            row,
            "{ address = \"0/0/1\",  name = \"Short\",       dpt = \"1.001\" }"
        );
    }
}
