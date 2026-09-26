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
//! [`DeviceView::render_table`] is the terminal rendering, and
//! [`DeviceView::render_toml`] the paste-ready device-file snippet: what the
//! file sets, plus commented lines `# key = "value"   # choice | choice` for
//! what it could set.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::address::IndividualAddress;
use crate::flags::Flags;
use crate::loader::Model;
use crate::param_model::{ParamDef, ParamKind, ProductModel, ProductModels, enum_label};
use crate::schema::Device;

/// The channel argument that selects the device-level scope (`[parameters]`
/// and `[links]` of the device file).
pub const DEVICE_SCOPE: &str = "device";

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
    let default = def.and_then(|d| d.default.as_deref());
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

    let scope = match channel {
        None => None,
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
                .map(|(number, o)| {
                    let link = links.and_then(|l| l.iter().find(|l| l.object == *number));
                    ObjectRow {
                        key: o.key.clone().unwrap_or_else(|| number.to_string()),
                        number: *number,
                        text: o.text.clone(),
                        function: o.function.clone(),
                        dpt: o.dpt.map(|d| d.to_string()),
                        flags: o.flags.to_string(),
                        send: link.and_then(|l| l.send).map(|g| g.to_string()),
                        listen: link
                            .map(|l| l.listen.iter().map(ToString::to_string).collect())
                            .unwrap_or_default(),
                    }
                })
                .collect();
            Some(ScopeView {
                handle: id.as_deref().map(|i| device.channel_handle(i)),
                text: id
                    .as_deref()
                    .and_then(|i| device.channels.get(i))
                    .and_then(|c| c.text.clone()),
                name: id.as_deref().and_then(user_name),
                parameters,
                objects,
            })
        }
    };

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
        scope,
        notes,
    })
}

/// Pads `rows` into columns under `header`.
fn table(header: &[&str], rows: &[Vec<String>]) -> String {
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
                out.push_str(&format!(
                    "`bussard device {} <channel>` lists a channel's parameters and objects \
                     (`{DEVICE_SCOPE}` for the device level); `--toml` prints them ready to \
                     paste.\n",
                    self.address
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
                    None => out.push_str("device level\n"),
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
                            let marker = match p.at_default {
                                Some(true) => "default",
                                Some(false) => "set",
                                None if p.value.is_some() => "set",
                                None => "",
                            };
                            let allowed = if !p.choices.is_empty() {
                                p.choices.join(" | ")
                            } else {
                                p.range.clone().unwrap_or_default()
                            };
                            vec![
                                p.key.clone(),
                                value,
                                marker.to_string(),
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
