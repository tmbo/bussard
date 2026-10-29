//! What the installed devices could do (issue #298): a search over the
//! parameter texts and enum choice texts of their product models, with
//! whether the page holding each match is active on the device.
//!
//! "Is there a dark bit?" is rarely a com-object the installation already
//! has: on a Theben Meteodata it is "Funktion des Kanals = Helligkeitssensor"
//! on a universal channel the project never enabled. [`capability_lookup`]
//! finds such a choice on every device whose product model offers it and
//! says, per match, whether the page or channel holding it is active and,
//! when it is not, what enables it (the [`crate::device_view`] analysis).
//!
//! Rows that differ only in the channel they sit on (a dimmer's four
//! "DA1 - Allgemein" .. "DA4 - Allgemein" pages) are one row with a
//! `channels` list, and devices of one application with identical rows are
//! one row with `also_on` (issue #311). A device whose com-objects send the
//! measured value the query names (Helligkeit: DPT 9.004) leads.
//!
//! The pages include the channels of the module instances
//! ([`crate::blocks::module_channels_of`], issue #302), so a module channel
//! the configuration does not show is a "could provide" with its enable
//! steps.
//!
//! Parsing a product model's YAML is slow next to a search; the models come
//! through [`ProductModels::load_apps`], which memoizes them and caches them
//! as JSON under [`crate::param_model::MODEL_CACHE_DIR`] (issue #339). Of each
//! device only the pages holding a match are evaluated with their enabling
//! values ([`crate::device_view::device_view_for_blocks`]).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;

use crate::address::IndividualAddress;
use crate::blocks::{def_ref, ref_param_id};
use crate::device_view::{BlockRow, EnableStep, device_view_for_blocks};
use crate::flags::Flags;
use crate::loader::Model;
use crate::param_model::{ParamDef, ParamKind, ProductModel, ProductModels};

/// One matching parameter, or one of its choices, on a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Match {
    /// The parameter's text.
    pub parameter: String,
    /// The key the device file uses, when the configuration shows the
    /// parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The matching enum choice, when the match is a choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    /// Whether the device has it now: the parameter is shown and, for a
    /// choice, set to it.
    pub selected: bool,
}

/// What one page or channel of a device could do: the parameters and
/// choices on it whose texts match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    /// The device.
    pub device_ia: String,
    /// The device name.
    pub device_name: String,
    /// The ETS page or channel holding the parameter, by its title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_or_channel: Option<String>,
    /// Its handle for `knx_show_device` / `bussard device <ia> <handle>`:
    /// the page's or inactive channel's, else the device channel's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// When the same match sits on several channels or pages of the device
    /// with nothing else different (a dimmer's DA1 .. DA4): the handle (else
    /// the title) of each, `handle` and `block_or_channel` being the first's.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<String>,
    /// Other devices of the same application with the identical row.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also_on: Vec<String>,
    /// On the first row of a device that sends the value the query names: its
    /// com-objects that do (`<number> <text> (<DPT>)`, `-> <GA>` when linked).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sends: Vec<String>,
    /// The best match's parameter text (a selected one first, then a
    /// choice).
    pub parameter: String,
    /// The best match's key, when the configuration shows the parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The best match's choice, when it is a choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    /// Whether the page or channel is active on the device.
    pub active: bool,
    /// Whether the device has the best match now.
    pub selected: bool,
    /// `provides` (active, and the device has a match now) or `could
    /// provide` (on an inactive page, or another choice is set).
    pub status: String,
    /// The other matches on the same page (at most 5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub more: Vec<Match>,
    /// For an inactive page: the parameters that enable it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enable: Vec<EnableStep>,
    /// For an inactive page: how the change reaches the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
}

/// The other matches a [`Capability`] lists.
const MORE: usize = 5;

/// Lowercased with the German umlauts spelled out, so "Dämmerung" and
/// "daemmerung" find each other.
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().flat_map(char::to_lowercase) {
        match c {
            'ä' => out.push_str("ae"),
            'ö' => out.push_str("oe"),
            'ü' => out.push_str("ue"),
            'ß' => out.push_str("ss"),
            c => out.push(c),
        }
    }
    out
}

/// The text a parameter shows as.
fn param_text(def: &ParamDef) -> Option<&str> {
    def.text
        .as_deref()
        .or(def.name.as_deref())
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// A parameter of a product model whose texts match the query.
struct Hit<'a> {
    /// The block holding it, `None` for one no app-level page holds (a
    /// module parameter).
    block: Option<&'a str>,
    reference: &'a str,
    def: &'a ParamDef,
    text: &'a str,
    /// The matching choices, `(code, label)`.
    choices: Vec<(i64, &'a str)>,
    /// The parameter text itself matches (with no choice matching).
    plain: bool,
}

/// The parameters of `product` whose texts match `words`: every word in the
/// titles of the page path, the parameter text and the choice text
/// together, at least one in the parameter or choice text.
fn product_hits<'a>(product: &'a ProductModel, words: &[String]) -> Vec<Hit<'a>> {
    let blocks = product.blocks_with_module_channels();
    let titles: HashMap<&str, (Option<&str>, String)> = blocks
        .iter()
        .map(|b| {
            (
                b.id.as_str(),
                (b.parent.as_deref(), fold(b.text.as_deref().unwrap_or(""))),
            )
        })
        .collect();
    let path_title = |block: Option<&str>| -> String {
        let mut out = String::new();
        let mut at = block;
        while let Some(id) = at {
            let Some((parent, title)) = titles.get(id) else {
                break;
            };
            out.push_str(title);
            out.push(' ');
            at = *parent;
        }
        out
    };
    let mut candidates: Vec<(Option<&str>, &str, &ParamDef)> = Vec::new();
    let mut held: HashSet<String> = HashSet::new();
    for b in blocks {
        let mut own: HashSet<String> = HashSet::new();
        for r in &b.parameters {
            // A module channel holds its refs in the instance's selector
            // form; the definition is the module definition's.
            let id = ref_param_id(&def_ref(r)).to_string();
            let Some(def) = product.parameters.get(&id) else {
                continue;
            };
            held.insert(id.clone());
            if own.insert(id) {
                candidates.push((Some(b.id.as_str()), r.as_str(), def));
            }
        }
    }
    for (id, def) in &product.parameters {
        if !held.contains(id.as_str()) {
            candidates.push((None, id.as_str(), def));
        }
    }
    let mut out = Vec::new();
    let mut page_cache: HashMap<Option<&str>, String> = HashMap::new();
    for (block, reference, def) in candidates {
        if matches!(def.kind, ParamKind::None) {
            continue;
        }
        let Some(text) = param_text(def) else {
            continue;
        };
        let pfold = fold(text);
        let page = page_cache
            .entry(block)
            .or_insert_with(|| path_title(block))
            .clone();
        let covered = |extra: &str| {
            words.iter().all(|w| {
                page.contains(w.as_str())
                    || pfold.contains(w.as_str())
                    || extra.contains(w.as_str())
            })
        };
        let choices: Vec<(i64, &str)> = def
            .labels
            .iter()
            .filter(|(_, label)| {
                let cfold = fold(label);
                covered(&cfold) && words.iter().any(|w| cfold.contains(w.as_str()))
            })
            .map(|(code, label)| (*code, label.as_str()))
            .collect();
        let plain =
            choices.is_empty() && covered("") && words.iter().any(|w| pfold.contains(w.as_str()));
        if plain || !choices.is_empty() {
            out.push(Hit {
                block,
                reference,
                def,
                text,
                choices,
                plain,
            });
        }
    }
    out
}

/// The measured values a query can name, by a folded word stem, and the
/// DPTs a com-object sends them as: the value a device that "has" the
/// function sends to the bus (issue #311).
const MEASURED: &[(&str, &[&str])] = &[
    ("helligkeit", &["9.004", "7.013"]),
    ("brightness", &["9.004", "7.013"]),
    ("lux", &["9.004", "7.013"]),
    ("daemmerung", &["9.004"]),
    ("temperatur", &["9.001"]),
    ("wind", &["9.005"]),
    ("luftdruck", &["9.006"]),
    ("pressure", &["9.006"]),
    ("feuchte", &["9.007"]),
    ("humidity", &["9.007"]),
    ("co2", &["9.008"]),
    ("luftqualitaet", &["9.008"]),
];

/// The DPTs of the measured values the folded query `words` name.
fn query_dpts(words: &[String]) -> HashSet<&'static str> {
    MEASURED
        .iter()
        .filter(|(stem, _)| words.iter().any(|w| w.contains(stem)))
        .flat_map(|(_, dpts)| dpts.iter().copied())
        .collect()
}

/// The com-objects of `device` that send one of `dpts`, as `sends` lists
/// them, and how many of them are linked to a group address.
fn sending_objects(
    model: &Model,
    ia: IndividualAddress,
    dpts: &HashSet<&str>,
) -> (Vec<String>, usize) {
    let Some(loaded) = model.devices.get(&ia) else {
        return (Vec::new(), 0);
    };
    let links = model.links.links.get(&ia);
    let mut out = Vec::new();
    let mut linked = 0;
    for (number, o) in &loaded.device.com_objects {
        let Some(dpt) = o.dpt.map(|d| d.to_string()) else {
            continue;
        };
        if !o.flags.contains(Flags::TRANSMIT) || !dpts.contains(dpt.as_str()) {
            continue;
        }
        let send = links
            .and_then(|l| l.iter().find(|l| l.object == *number))
            .and_then(|l| l.send);
        let text = o.text.as_deref().unwrap_or("").trim();
        let mut line = format!("{number} {text} ({dpt})");
        if let Some(ga) = send {
            linked += 1;
            line.push_str(&format!(" -> {ga}"));
        }
        out.push(line);
    }
    (out, linked)
}

/// What a row is apart from where it sits: `place` keeps the page or
/// channel (to merge devices), else only its title with the numbering taken
/// out (to merge a device's channels).
fn identity(c: &Capability, place: bool) -> Capability {
    let mut c = c.clone();
    c.device_ia = String::new();
    c.device_name = String::new();
    c.also_on = Vec::new();
    c.sends = Vec::new();
    if !place {
        c.block_or_channel = Some(crate::device_view::title_shape(
            c.block_or_channel.as_deref(),
        ));
        c.handle = None;
        c.channels = Vec::new();
    }
    c
}

/// One device's rows with those identical apart from their channel merged
/// into the first, which lists them all in `channels`.
fn merge_channels(rows: Vec<Capability>) -> Vec<Capability> {
    let mut out: Vec<(Capability, Capability)> = Vec::new();
    for row in rows {
        let key = identity(&row, false);
        let place = row
            .handle
            .clone()
            .or_else(|| row.block_or_channel.clone())
            .unwrap_or_default();
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some((_, first)) => {
                if first.channels.is_empty() {
                    let own = first
                        .handle
                        .clone()
                        .or_else(|| first.block_or_channel.clone())
                        .unwrap_or_default();
                    first.channels.push(own);
                }
                first.channels.push(place);
            }
            None => out.push((key, row)),
        }
    }
    out.into_iter().map(|(_, row)| row).collect()
}

/// Searches the parameter texts and enum choice texts of every device's
/// product model for `query` (every word must appear in the page titles,
/// parameter text and choice text together, at least one in the parameter
/// or choice text; case and umlaut spelling do not matter). Returns at most
/// `limit` pages or channels, each with its matches: those where a device
/// provides a match now first, then those on an inactive page (spare
/// capacity), then active pages set to something else. Within each, a
/// device whose com-objects send the measured value the query names (DPT
/// 9.004 for "Helligkeit") comes first, the one with the most such objects
/// linked to a group address leading. A device's rows that differ only in
/// their channel are one row (`channels`), and devices of one application
/// with an identical row one row (`also_on`).
pub fn capability_lookup(model: &Model, dir: &Path, query: &str, limit: usize) -> Vec<Capability> {
    let words: Vec<String> = fold(query).split_whitespace().map(str::to_string).collect();
    if words.is_empty() || limit == 0 {
        return Vec::new();
    }
    let apps: HashSet<&str> = model
        .devices
        .values()
        .filter_map(|d| d.device.product.as_ref()?.application_ref.as_deref())
        .collect();
    let products = ProductModels::load_apps(dir, apps);
    let hits: HashMap<&str, Vec<Hit<'_>>> = products
        .by_app_ref
        .iter()
        .map(|(app, m)| (app.as_str(), product_hits(m, &words)))
        .filter(|(_, h)| !h.is_empty())
        .collect();
    let dpts = query_dpts(&words);

    // (rank, the device's sending score, the app, the row).
    let mut out: Vec<(u8, usize, &str, Capability)> = Vec::new();
    let mut device_sends: HashMap<String, Vec<String>> = HashMap::new();
    for (ia, loaded) in &model.devices {
        let Some(app) = loaded
            .device
            .product
            .as_ref()
            .and_then(|p| p.application_ref.as_deref())
        else {
            continue;
        };
        let (Some(product), Some(app_hits)) = (products.get(app), hits.get(app)) else {
            continue;
        };
        let (sends, linked) = sending_objects(model, *ia, &dpts);
        let score = if sends.is_empty() { 0 } else { 1 + linked };
        if !sends.is_empty() {
            device_sends.insert(ia.to_string(), sends);
        }
        let rows = merge_channels(device_capabilities(
            model, &products, product, *ia, app_hits,
        ));
        for cap in rows {
            let base = match (cap.status.as_str(), cap.active) {
                ("provides", _) => 0,
                (_, false) => 1,
                _ => 2,
            };
            out.push((base * 2 + u8::from(score == 0), score, app, cap));
        }
    }
    // Devices of one application with an identical row: one row.
    let mut merged: Vec<(u8, usize, &str, Capability, Capability)> = Vec::new();
    for (rank, score, app, cap) in out {
        let key = identity(&cap, true);
        let same = merged
            .iter_mut()
            .find(|(r, n, a, _, k)| *r == rank && *n == score && *a == app && *k == key);
        match same {
            Some((_, _, _, first, _)) => first.also_on.push(cap.device_ia),
            None => merged.push((rank, score, app, cap, key)),
        }
    }
    merged.sort_by_key(|(rank, score, ..)| (*rank, std::cmp::Reverse(*score)));
    // `sends` goes on the first row of each device that sends.
    let mut rows: Vec<Capability> = merged
        .into_iter()
        .take(limit)
        .map(|(_, _, _, c, _)| c)
        .collect();
    for cap in &mut rows {
        if let Some(sends) = device_sends.remove(&cap.device_ia) {
            cap.sends = sends;
        }
    }
    rows
}

/// The matches on one device, grouped by the page or channel holding them.
fn device_capabilities(
    model: &Model,
    products: &ProductModels,
    product: &ProductModel,
    ia: IndividualAddress,
    hits: &[Hit<'_>],
) -> Vec<Capability> {
    let Some(loaded) = model.devices.get(&ia) else {
        return Vec::new();
    };
    let device = &loaded.device;
    let blocks = product.blocks_with_module_channels();
    let parent_of: HashMap<&str, Option<&str>> = blocks
        .iter()
        .map(|b| (b.id.as_str(), b.parent.as_deref()))
        .collect();
    let title_of: HashMap<&str, Option<&str>> = blocks
        .iter()
        .map(|b| (b.id.as_str(), b.text.as_deref()))
        .collect();
    // Only the pages holding a match (and those enclosing them) get their
    // inactive detail evaluated.
    let mut wanted: HashSet<String> = HashSet::new();
    for hit in hits {
        let mut at = hit.block;
        while let Some(id) = at {
            if !wanted.insert(id.to_string()) {
                break;
            }
            at = parent_of.get(id).copied().flatten();
        }
    }
    let Ok(view) = device_view_for_blocks(model, products, ia, wanted) else {
        return Vec::new();
    };
    // The device's shown parameters: ref -> (file key, stored value).
    let mut shown: HashMap<String, (String, Option<String>)> = HashMap::new();
    for (reference, p) in &device.lock.parameters {
        shown.insert(reference.clone(), (p.key.clone(), None));
    }
    for (mem_key, value) in &device.parameters {
        if crate::files::is_hidden_mem_key(mem_key) {
            continue;
        }
        let Some((_, reference)) = mem_key.split_once('@') else {
            continue;
        };
        let entry = shown
            .entry(reference.to_string())
            .or_insert_with(|| (mem_key.clone(), None));
        entry.1 = Some(value.clone());
    }
    // Parameter id -> the ref the lock lists for it.
    let shown_params: HashMap<&str, &str> = device
        .lock
        .parameters
        .iter()
        .filter_map(|(r, p)| Some((p.param.as_deref()?, r.as_str())))
        .collect();

    let rows: Vec<&BlockRow> = view.blocks.iter().chain(&view.inactive_channels).collect();
    let mut row_of: HashMap<&str, &BlockRow> = HashMap::new();
    for row in &rows {
        row_of.entry(row.id.as_str()).or_insert(row);
        for id in &row.includes {
            row_of.entry(id.as_str()).or_insert(row);
        }
    }
    let row_for = |block: &str| -> Option<&BlockRow> {
        let mut at = Some(block);
        while let Some(id) = at {
            if let Some(row) = row_of.get(id) {
                return Some(*row);
            }
            at = parent_of.get(id).copied().flatten();
        }
        None
    };
    let module_channel: HashSet<&str> = blocks
        .iter()
        .filter(|b| b.module.is_some())
        .map(|b| b.id.as_str())
        .collect();
    let lock_channel = |reference: &str| -> Option<String> {
        device
            .lock
            .parameters
            .get(reference)
            .and_then(|p| p.channel.as_deref())
            .map(|c| device.channel_handle(c))
    };

    let mut groups: Vec<Capability> = Vec::new();
    for hit in hits {
        let row = hit.block.and_then(row_for);
        // A module instance's ref (selector form) is its own; another ref
        // stands for the parameter, whichever ref the lock lists.
        let instance_ref = crate::dynamic::split_selector(hit.reference).0.is_some();
        let lock_ref: Option<&str> = if shown.contains_key(hit.reference) {
            Some(hit.reference)
        } else if instance_ref {
            None
        } else {
            shown_params.get(ref_param_id(hit.reference)).copied()
        };
        let shown_entry = lock_ref.and_then(|r| shown.get(r));
        let active = match row {
            Some(row) => row.active,
            None => shown_entry.is_some(),
        };
        // A module channel the device has goes by its handle.
        let device_channel = hit
            .block
            .filter(|b| device.channels.contains_key(*b))
            .map(|b| device.channel_handle(b));
        // A module channel the view does not list (an alternative of a
        // shown instance, or one only ETS enables) is no spare capacity.
        let unlisted_module = row.is_none()
            && device_channel.is_none()
            && hit.block.is_some_and(|b| module_channel.contains(b));
        if unlisted_module {
            continue;
        }
        let label = match (row, hit.block) {
            (Some(row), _) => row.text.clone(),
            (None, Some(b)) => device_channel
                .clone()
                .or_else(|| title_of.get(b).copied().flatten().map(str::to_string)),
            (None, None) => lock_ref.and_then(lock_channel),
        };
        let handle = row
            .map(|r| r.handle.clone())
            .or(device_channel)
            .or_else(|| lock_ref.and_then(lock_channel));
        let current: Option<i64> = shown_entry
            .and_then(|(_, v)| v.clone())
            .or_else(|| {
                // A parameter no page holds stands for its one ref, if one.
                let reference = match (hit.block, hit.def.refs.as_slice()) {
                    (None, [only]) => only.clone(),
                    _ => def_ref(hit.reference),
                };
                product.ref_default(&reference).map(str::to_string)
            })
            .and_then(|v| {
                let v = v.trim();
                v.parse::<i64>()
                    .ok()
                    .or_else(|| crate::param_model::enum_code(&hit.def.labels, v))
            });
        let key = shown_entry.map(|(k, _)| k.clone()).filter(|_| active);
        let parameter = hit.text.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut matches: Vec<Match> = hit
            .choices
            .iter()
            .map(|(code, choice)| Match {
                parameter: parameter.clone(),
                key: key.clone(),
                choice: Some(choice.to_string()),
                selected: active && shown_entry.is_some() && current == Some(*code),
            })
            .collect();
        if hit.plain {
            matches.push(Match {
                parameter: parameter.clone(),
                key: key.clone(),
                choice: None,
                selected: active && shown_entry.is_some(),
            });
        }
        let group = match groups
            .iter_mut()
            .find(|g| g.block_or_channel == label && g.handle == handle)
        {
            Some(g) => g,
            None => {
                let inactive = row.and_then(|r| r.inactive.as_ref());
                groups.push(Capability {
                    device_ia: ia.to_string(),
                    device_name: device.name.clone(),
                    block_or_channel: label.clone(),
                    handle: handle.clone(),
                    channels: Vec::new(),
                    also_on: Vec::new(),
                    sends: Vec::new(),
                    parameter: String::new(),
                    key: None,
                    choice: None,
                    active,
                    selected: false,
                    status: String::new(),
                    more: Vec::new(),
                    enable: inactive.map(|i| i.enable.clone()).unwrap_or_default(),
                    needs: inactive.map(|i| i.needs.clone()),
                });
                let last = groups.len() - 1;
                &mut groups[last]
            }
        };
        group.active |= active;
        group.more.extend(matches);
    }
    for g in &mut groups {
        // The best match leads: a selected one, then a choice.
        let mut all = std::mem::take(&mut g.more);
        let best = all
            .iter()
            .position(|m| m.selected)
            .or_else(|| all.iter().position(|m| m.choice.is_some()))
            .unwrap_or(0);
        if best < all.len() {
            let lead = all.remove(best);
            g.parameter = lead.parameter;
            g.key = lead.key;
            g.choice = lead.choice;
            g.selected = lead.selected;
        }
        all.truncate(MORE);
        g.more = all;
        g.status = if g.active && g.selected {
            "provides".to_string()
        } else {
            "could provide".to_string()
        };
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fold_spells_out_umlauts() {
        assert_eq!(fold("Dämmerung"), "daemmerung");
        assert_eq!(fold("Größe"), "groesse");
    }
}
