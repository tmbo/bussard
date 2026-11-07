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
    DeviceEntries, EntryValue, LOCK_HEADER, LockDevice, Placement, Resolver, TableRef,
    channel_label, device_entries, existing_placements, handle_of, ordered_channels, scope_entries,
};
use crate::loader::SaveError;
use crate::param_model::ProductModels;
use crate::schema::{BussardConfig, Device, Group, Groups, Link, ProductEntry};
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
# directory). See docs/reference/files/.
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

/// Renders `bussard.lock`, always fresh (it is fully generated): the lock
/// structs serialised, laid out with one `[[product]]`/`[[device]]` table
/// each and one inline table per line in their arrays, so a re-import
/// diffs line by line.
pub(crate) fn render_lock(
    source: Option<&str>,
    language: Option<&str>,
    products: &[ProductEntry],
    devices: &[LockDevice],
) -> String {
    let lock = crate::files::LockFile {
        version: crate::files::lock_version_for(devices),
        written_by: Some(crate::files::lock_written_by()),
        source: source.map(str::to_string),
        language: language.map(str::to_string),
        products: products.to_vec(),
        devices: devices.to_vec(),
    };
    let mut out = format!("{LOCK_HEADER}\n");
    // Every lock field is a string, an integer, a bool, an array or a table,
    // all of which TOML holds, so neither step fails.
    let Some(doc) = toml::to_string(&lock)
        .ok()
        .and_then(|text| text.parse::<DocumentMut>().ok())
    else {
        return out;
    };
    for (key, item) in doc.iter() {
        let Item::ArrayOfTables(entries) = item else {
            out.push_str(&format!("{} = {}\n", toml_key(key), lock_item(item)));
            continue;
        };
        for entry in entries.iter() {
            out.push_str(&format!("\n[[{key}]]\n"));
            // The lock's layout of an entry, whatever the serializer's:
            // strings, other scalars, tables, then plain arrays (a device's
            // `application_version` after its strings, a product's
            // `origin` before its `applications`). Stable within each.
            let mut fields: Vec<(&str, &Item)> = entry.iter().collect();
            fields.sort_by_key(|(_, item)| match item {
                Item::Value(Value::String(_)) => 0,
                Item::Value(Value::Array(_)) => 3,
                Item::Value(Value::InlineTable(_)) | Item::Table(_) | Item::ArrayOfTables(_) => 2,
                _ => 1,
            });
            for (k, v) in fields {
                out.push_str(&format!("{} = {}\n", toml_key(k), lock_item(v)));
            }
        }
    }
    out
}

/// One lock value: an array of tables one inline table per line, any other
/// array or table inline, a string as a basic string.
fn lock_item(item: &Item) -> String {
    let fields = |t: &dyn TableLike| -> String {
        let cells: Vec<String> = t
            .iter()
            .map(|(k, v)| format!("{} = {}", toml_key(k), lock_item(v)))
            .collect();
        format!("{{ {} }}", cells.join(", "))
    };
    match item {
        Item::ArrayOfTables(rows) => {
            let rows: String = rows.iter().map(|t| format!("  {},\n", fields(t))).collect();
            format!("[\n{rows}]")
        }
        Item::Table(t) => fields(t),
        Item::Value(Value::InlineTable(t)) => fields(t),
        Item::Value(Value::String(s)) => basic_string(s.value()),
        Item::Value(Value::Array(a)) if !a.is_empty() && a.iter().all(Value::is_inline_table) => {
            let rows: String = a
                .iter()
                .filter_map(Value::as_inline_table)
                .map(|t| format!("  {},\n", fields(t)))
                .collect();
            format!("[\n{rows}]")
        }
        Item::Value(Value::Array(a)) => {
            let cells: Vec<String> = a
                .iter()
                .map(|v| lock_item(&Item::Value(v.clone())))
                .collect();
            format!("[{}]", cells.join(", "))
        }
        Item::Value(v) => v.clone().decorated("", "").to_string(),
        Item::None => String::new(),
    }
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

/// The `[knxnet]` table of an IP interface (issue #391), keys in the order the
/// model format documents.
fn knxnet_table(k: &crate::knxnet::KnxnetConfig) -> Table {
    let mut t = Table::new();
    t.insert("assignment", string_item(k.assignment.label()));
    for (key, value) in [
        ("address", k.address),
        ("netmask", k.netmask),
        ("gateway", k.gateway),
    ] {
        if let Some(v) = value {
            t.insert(key, string_item(&v.to_string()));
        }
    }
    if let Some(name) = &k.friendly_name {
        t.insert("friendly_name", string_item(name));
    }
    if !k.tunnels.is_empty() {
        let mut a = Array::new();
        for ia in &k.tunnels {
            a.push(string_value(&ia.to_string()));
        }
        t.insert("tunnels", Item::Value(Value::Array(a)));
    }
    t
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
    if let Some(knxnet) = &device.knxnet {
        doc.insert("knxnet", Item::Table(knxnet_table(knxnet)));
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

    // Channels: the device's own, in file order (see `ordered_channels`), then
    // any handle an entry names that the device does not define.
    let mut order: Vec<String> = Vec::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (id, ch) in ordered_channels(device) {
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

/// The two lock entries a stale object key of an existing device file is
/// checked against before a save drops it.
///
/// A key the lock this save writes resolves is generated. So is a key the
/// lock the file was last written against (`prior`) resolved: an import put it
/// there, and a model that no longer links it (a re-import whose project
/// dropped or moved the link, issue #235) means it goes. A key neither
/// resolves was typed by hand and stays, so validation reports it (E023).
pub(crate) struct KeyLocks<'r, 'm> {
    /// The lock entry this save writes.
    current: &'r Resolver<'m>,
    /// The lock entry on disk before this save, if any.
    prior: &'r Resolver<'m>,
}

impl KeyLocks<'_, '_> {
    /// Whether `key` in `scope` names a com object under either lock.
    fn known_object(&self, scope: Option<&str>, key: &str) -> bool {
        self.current.object(scope, key).is_some() || self.prior.object(scope, key).is_some()
    }
}

/// A device's entries in the lock this save writes and in the lock on disk.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DeviceLocks<'l> {
    /// The entry this save writes.
    pub current: Option<&'l LockDevice>,
    /// The entry on disk before this save.
    pub prior: Option<&'l LockDevice>,
}

/// The order of the keys and sections of a device file a save edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyOrder {
    /// Keep the file's order; a new entry goes after the existing ones.
    Keep,
    /// The order a fresh render writes (a re-import, issue #235).
    Fresh,
}

/// Renders a device file, editing `existing` in place when given.
///
/// `locks.current` is the lock entry this save writes for the device; it
/// resolves the keys of the existing file. `locks.prior` is the device's
/// entry in the lock on disk before this save (see [`KeyLocks`]). `order` picks the order of an
/// edited file ([`KeyOrder`]).
pub(crate) fn render_device(
    path: &Path,
    device: &Device,
    links: &[Link],
    locks: DeviceLocks<'_>,
    existing: Option<&str>,
    models: Option<&ProductModels>,
    order: KeyOrder,
) -> String {
    let app_ref = device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref());
    let resolver = Resolver::with_model(
        locks.current,
        models.zip(app_ref).and_then(|(m, a)| m.get(a)),
    );
    let prior_resolver = Resolver::with_model(locks.prior, None);
    let key_locks = KeyLocks {
        current: &resolver,
        prior: &prior_resolver,
    };
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
            merge_table(
                doc.as_table_mut(),
                desired.as_table(),
                &mut Vec::new(),
                &key_locks,
            );
            if order == KeyOrder::Fresh {
                order_like(doc.as_table_mut(), desired.as_table());
                number_tables(doc.as_table_mut(), &mut 0);
            }
            doc.to_string()
        }
    }
}

/// Merges the desired document `want` into the existing `have` at `path`,
/// keeping the bytes and comments of what did not change: a key `want`
/// lacks is inserted, an unchanged one kept, a table on both sides merged
/// key by key (an object entry only when the file writes it as a dotted or
/// header table; an inline one is replaced whole), anything else replaced.
/// A key only `have` holds goes: a table after its own keys went, when
/// nothing is left; an object entry only when a lock resolves its key, so a
/// key typed by hand stays for validation to report (E023).
fn merge_table(
    have: &mut dyn TableLike,
    want: &dyn TableLike,
    path: &mut Vec<String>,
    locks: &KeyLocks,
) {
    for (k, v) in want.iter() {
        match have.get_mut(k) {
            None => {
                have.insert(k, v.clone());
            }
            Some(slot) if same(slot, v) => {}
            Some(slot) => match (
                slot.is_table() || !is_entry_object(path, v),
                v.as_table_like(),
            ) {
                (true, Some(w)) if slot.is_table_like() => {
                    if let Some(h) = slot.as_table_like_mut() {
                        path.push(k.to_string());
                        merge_table(h, w, path, locks);
                        path.pop();
                    }
                }
                _ => replace_item(slot, v),
            },
        }
    }
    let stale: Vec<String> = have
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| want.get(k).is_none())
        .collect();
    let empty = Table::new();
    for k in stale {
        let Some(item) = have.get_mut(&k) else {
            continue;
        };
        if is_entry_object(path, item) {
            // The channel a key sits in, for a channel table's entry.
            let scope = (path.first().map(String::as_str) == Some("channel"))
                .then(|| path.get(1).map(String::as_str))
                .flatten();
            if locks.known_object(scope, &k) {
                have.remove(&k);
            }
            continue;
        }
        if let Some(t) = item.as_table_like_mut() {
            path.push(k.clone());
            merge_table(t, &empty, path, locks);
            path.pop();
            if !have
                .get(&k)
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                continue;
            }
        }
        have.remove(&k);
    }
}

/// Whether `item`, held at `path`, is an object entry: an object-shaped
/// table directly in `[parameters]`, `[links]` or a `[channel.<handle>]`, or
/// in a page of one.
fn is_entry_object(path: &[String], item: &Item) -> bool {
    let depth = match path.first().map(String::as_str) {
        Some("parameters" | "links") => path.len(),
        Some("channel") => path.len().saturating_sub(1),
        _ => return false,
    };
    (1..=2).contains(&depth) && is_object_item(item)
}

/// Puts the keys of `have` in the order `want` lists them, recursively, so an
/// edited file reads in the same order a fresh render writes (issue #235).
/// Keys `want` does not list (an unresolved key kept for validation) keep
/// their relative order after the others. Each key's bytes and comments move
/// with it.
fn order_like(have: &mut Table, want: &Table) {
    let rank: BTreeMap<&str, usize> = want.iter().enumerate().map(|(i, (k, _))| (k, i)).collect();
    let pos = |k: &toml_edit::Key| rank.get(k.get()).copied().unwrap_or(usize::MAX);
    // Only this level: a dotted object entry (`schalten.send`) keeps its own
    // field order, which `merge_entries` already set.
    let keys: Vec<String> = have.iter().map(|(k, _)| k.to_string()).collect();
    let mut sorted = keys.clone();
    sorted.sort_by_key(|k| rank.get(k.as_str()).copied().unwrap_or(usize::MAX));
    if sorted != keys {
        have.sort_values_by(|a, _, b, _| pos(a).cmp(&pos(b)));
    }
    for (key, item) in have.iter_mut() {
        if let (Item::Table(h), Some(Item::Table(w))) = (item, want.get(key.get()))
            && !h.is_dotted()
        {
            order_like(h, w);
        }
    }
}

/// Numbers every header table of a document in the order its map holds them,
/// so they render in that order: a table a save added has no position and
/// would otherwise print after the last table the file already had.
fn number_tables(table: &mut Table, next: &mut isize) {
    for (_, item) in table.iter_mut() {
        if let Item::Table(t) = item
            && !t.is_dotted()
        {
            t.set_position(Some(*next));
            *next += 1;
            number_tables(t, next);
        }
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

    /// Every lock field, strings that need escapes, and each origin kind.
    const LOCK_BODY: &str = r##"source = "a \"quoted\" \\ path\twith tab"
language = "de-DE"

[[product]]
sha256 = "abc"
file = "vendor/x.knxprod"
filename = "x.knxprod"
size = 12345
origin = { kind = "index", order_number = "2173 REG", url = "https://x" }
applications = ["M-0001_A-1", "M-0001_A-2"]
order_numbers = ["2173"]

[[product]]
sha256 = "def"
origin = { kind = "knxproj", path = "p.knxproj", project_hash = "ff" }

[[product]]
sha256 = "ghi"
origin = { kind = "device" }

[[product]]
sha256 = "jkl"
origin = { kind = "file", path = "C:\\x.knxprod" }

[[device]]
address = "1.1.1"
product = "P"
application = "A"
product_sha256 = "abc"
application_id = "M-0001_A-1"
manufacturer = "Ä Ö \u0001 €"
manufacturer_ref = "M-0001"
hardware_ref = "H"
mask = "07B0"
serial_number = "0001:00000001"
application_version = 17
secure_capable = true
has_fdsk_certificate = true
sequence_number = 281474976710655
secure_senders = [
  { address = "1.1.2", sequence = 5 },
]
channels = [
  { key = "a-1", id = "CH-1", number = 1, text = "Kanal \"A\"", label_ref = "P-1_R-1", base = 4 },
  { id = "CH-2" },
]
module_bases = { "MD 2" = 5, MD-1 = 4 }
objects = [
  { number = 0, key = "sw", channel = "CH-1", text = "t", function = "f", dpt = "1.001", size = "1 Bit", flags = "CWT", ref = "O-0_R-1", secure = true },
  { number = 1, flags = "" },
]
parameters = [
  { key = "k@P-1_R-1", channel = "CH-1", ref = "P-1_R-1", param = "P-1", default = "0" },
  { key = "k2", ref = "P-2_R-2" },
]
hidden = [
  { ref = "P-3_R-3", value = "line\nbreak" },
]

[[device]]
address = "1.1.3"
"##;

    #[test]
    fn test_render_lock_writes_one_inline_table_per_line() -> Result<(), Box<dyn std::error::Error>>
    {
        let text = format!("version = 4\nwritten_by = \"x\"\n{LOCK_BODY}");
        let lock: crate::files::LockFile = toml::from_str(&text)?;
        let out = render_lock(
            lock.source.as_deref(),
            lock.language.as_deref(),
            &lock.products,
            &lock.devices,
        );
        let expected = format!(
            "{LOCK_HEADER}\nversion = 4\nwritten_by = {}\n{LOCK_BODY}",
            basic_string(&crate::files::lock_written_by())
        );
        assert_eq!(out, expected);
        Ok(())
    }
}
