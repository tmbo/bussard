//! The homeowner's view of a tool result (issue #306).
//!
//! The reader of the assistant's replies is a homeowner unless she says
//! otherwise: she knows her rooms, her devices and what a light or a blind
//! does, not what a group address, an individual address, a com-object
//! number, a parameter key or an ETS reference is. So every result that
//! changes something, or asks her to approve a change, carries a `summary`:
//! one or two sentences in rooms, device, channel and group names, with an id
//! only for a thing that has no name. A plan also carries
//! `what_you_will_notice`: how long the device is busy, what keeps working,
//! the changes in plain words and what to test afterwards.
//!
//! Both are additive: the sentences, the structured changes, the digests and
//! every id stay in the payload for the assistant's next call and for an
//! integrator who asks. The server writes English; the assistant translates.
//!
//! The read tools (`knx_show_device`, `knx_get_group`, `knx_model_lookup`)
//! drop what only an integrator reads unless `technical` is set
//! ([`plain_view`] and friends); `technical: true` returns the payload
//! exactly as before.

use std::collections::BTreeSet;

use bussard_model::change::{ChangeKind, ChangeSet, summarize};
use bussard_model::text::join_and;
use bussard_model::{IndividualAddress, Model};
use serde_json::{Map, Value, json};

/// The tools whose result [`add_result_summary`] gives a `summary` when the
/// tool did not write one itself.
pub const SUMMARIZED_TOOLS: &[&str] = &[
    "knx_ha_plan",
    "knx_ha_apply",
    "knx_ha_automation_plan",
    "knx_ha_automation_apply",
    "knx_ha_automation_remove",
];

pub use bussard_service::report::{device_phrase, object_phrase, room_of};

/// The devices a change set needs pushed (its link, device and parameter
/// changes), by address.
pub fn devices_to_push(changes: &ChangeSet) -> BTreeSet<IndividualAddress> {
    changes
        .changes
        .iter()
        .filter(|c| {
            matches!(
                c.kind,
                ChangeKind::LinkAdded
                    | ChangeKind::LinkRemoved
                    | ChangeKind::DeviceAdded
                    | ChangeKind::DeviceProductChanged
                    | ChangeKind::ObjectSecurityChanged
                    | ChangeKind::InterfaceChanged
                    | ChangeKind::ParameterChanged
            )
        })
        .filter_map(|c| c.device.as_deref()?.parse().ok())
        .collect()
}

/// The `summary` of a model edit, an undo, a discard or a pending change:
/// what changes ([`summarize`]), then which devices still need a push.
/// `models` are the new side, then the old.
pub fn edit_summary(changes: &ChangeSet, models: [&Model; 2]) -> String {
    let mut out = summarize(changes, models);
    if changes.is_empty() {
        return out;
    }
    let devices = devices_to_push(changes);
    out.push(' ');
    if devices.is_empty() {
        out.push_str(
            "Nothing to push: this only changes names, rooms or notes in the model, which no \
             device stores.",
        );
    } else {
        let names: Vec<String> = devices
            .iter()
            .map(|ia| {
                let model = if models[0].devices.contains_key(ia) {
                    models[0]
                } else {
                    models[1]
                };
                device_phrase(model, *ia)
            })
            .collect();
        let verb = if names.len() == 1 { "needs" } else { "need" };
        out.push_str(&format!(
            "No device has it yet: {} {verb} to be written before the house behaves this way.",
            join_and(&names)
        ));
    }
    out
}

/// The one line an edit result's `validation` gains for the human: whether
/// the model has problems that stop a push, and whether the edit added notes.
pub fn for_the_human(validation: &Value) -> String {
    let errors = validation["error_count"].as_u64().unwrap_or(0);
    let new_warnings = validation["new_warnings"].as_array().map_or(0, Vec::len);
    match (errors, new_warnings) {
        (0, 0) => "No problems.".to_string(),
        (0, 1) => "One new note about the model (types or naming); harmless, it can be \
                   tidied later."
            .to_string(),
        (0, n) => format!(
            "{n} new notes about the model (types or naming); harmless, they can be tidied \
             later."
        ),
        (1, _) => "The model has one problem that has to be fixed before a device can be \
                   written."
            .to_string(),
        (n, _) => format!(
            "The model has {n} problems that have to be fixed before a device can be written."
        ),
    }
}

/// Adds `for_the_human` to an edit result's `validation` object.
pub fn put_for_the_human(result: &mut Value) {
    let line = for_the_human(&result["validation"]);
    if let Some(map) = result["validation"].as_object_mut() {
        map.insert("for_the_human".to_string(), Value::String(line));
    }
}

/// The device a result is about, by its `address` field, as a phrase; a
/// line-form result (`line`, no `address`) is about every device on that line.
fn result_device(model: &Model, value: &Value) -> String {
    match value["address"]
        .as_str()
        .and_then(|a| a.parse::<IndividualAddress>().ok())
    {
        Some(ia) => device_phrase(model, ia),
        None => match value["line"].as_str() {
            Some(line) => format!("every device on line {line}"),
            None => "the device".to_string(),
        },
    }
}

/// Adds a `summary` to the result of `tool` (one of [`SUMMARIZED_TOOLS`])
/// when the tool did not write one itself. Returns whether it did.
pub fn add_result_summary(tool: &str, value: &mut Value, model: &Model) -> bool {
    if !SUMMARIZED_TOOLS.contains(&tool) {
        return false;
    }
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.contains_key("summary") {
        return false;
    }
    let summary = result_summary(tool, value, model);
    match value.as_object_mut() {
        Some(map) => {
            map.insert("summary".to_string(), Value::String(summary));
            true
        }
        None => false,
    }
}

/// The `summary` of a programming, device-read or Home Assistant result.
pub fn result_summary(tool: &str, value: &Value, model: &Model) -> String {
    let device = result_device(model, value);
    if value["refused"] == true {
        return format!(
            "Nothing was changed: bussard refused this request (`reason` says why){}.",
            if value["address"].is_string() {
                format!("; {device} is as it was")
            } else {
                String::new()
            }
        );
    }
    match tool {
        "knx_ha_plan" => ha_plan_summary(value),
        "knx_ha_apply" => ha_apply_summary(value),
        "knx_ha_automation_plan" => automation_plan_summary(value),
        "knx_ha_automation_apply" | "knx_ha_automation_remove" => automation_apply_summary(value),
        _ => format!("The request for {device} was handled."),
    }
}

/// `knx_ha_plan`: what Home Assistant would gain, change and lose.
fn ha_plan_summary(value: &Value) -> String {
    if value["noop"] == true || value["plan_digest"].is_null() {
        return "Home Assistant already matches your project; nothing to write.".to_string();
    }
    let counts = &value["counts"];
    let n = |k: &str| counts[k].as_u64().unwrap_or(0);
    let names: Vec<String> = value["changes"]
        .as_array()
        .map(|changes| {
            changes
                .iter()
                .filter_map(|c| c["name"].as_str())
                .map(str::to_string)
                .take(3)
                .collect()
        })
        .unwrap_or_default();
    let mut out = format!(
        "Home Assistant gets {} new, {} changed and {} removed entities",
        n("added"),
        n("changed"),
        n("removed")
    );
    if !names.is_empty() {
        out.push_str(&format!(" (among them {})", join_and(&names)));
    }
    out.push_str(". Nothing is written before the human says yes.");
    out
}

/// `knx_ha_apply`: written and reloaded, or written and not reloaded.
fn ha_apply_summary(value: &Value) -> String {
    if value["reload"]["ok"] == true {
        "Home Assistant's KNX setup is updated and reloaded; the previous file is backed up."
            .to_string()
    } else {
        "Home Assistant's KNX file is updated, but the reload failed: the change takes effect \
         at the next reload or restart of Home Assistant. The previous file is backed up."
            .to_string()
    }
}

/// `knx_ha_automation_plan`: the rule in words and what happens to it.
fn automation_plan_summary(value: &Value) -> String {
    let rule = value["sentence"].as_str().unwrap_or("this rule");
    match value["op"].as_str() {
        Some("unchanged") => {
            "Home Assistant already has this automation; nothing to write.".to_string()
        }
        Some("remove") => "Removes this bussard automation from Home Assistant. Nothing is \
                           removed before the human says yes."
            .to_string(),
        Some("update") => format!(
            "Changes the Home Assistant automation to: {rule}. Nothing is written before the \
             human says yes."
        ),
        _ => format!(
            "Home Assistant would get a new automation: {rule}. Nothing is written before the \
             human says yes."
        ),
    }
}

/// `knx_ha_automation_apply` and `_remove`: what Home Assistant now does.
fn automation_apply_summary(value: &Value) -> String {
    let rule = value["sentences"]
        .as_array()
        .and_then(|s| s.first())
        .and_then(Value::as_str)
        .and_then(|s| s.split_once(": ").map(|(_, rule)| rule))
        .and_then(|rule| rule.split(" (changes ").next())
        .map(str::to_string);
    let reloaded = value["reload"]["ok"] == true;
    let mut out = match (value["op"].as_str(), rule) {
        (Some("remove"), _) => "The automation is removed from Home Assistant.".to_string(),
        (_, Some(rule)) => format!("Home Assistant now runs the automation: {rule}."),
        _ => "Home Assistant has the automation.".to_string(),
    };
    if !reloaded {
        out.push_str(" The reload failed, so it takes effect at the next reload or restart.");
    }
    out
}

/// The keys [`plain_view`] drops: ETS ids and what only an integrator reads.
const TECHNICAL_KEYS: &[&str] = &["flags", "computed_by", "application", "includes"];

/// `knx_show_device`'s default payload: the view without the ETS ids
/// (`reference` where a `key` names the parameter, a page's `id`, the
/// application id, the folded page ids, the calculation id) and without the
/// com-object flags. `key`, `number`, `dpt` and `handle` stay: the next call
/// needs them.
pub fn plain_view(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in TECHNICAL_KEYS {
                map.remove(*key);
            }
            if map.get("key").is_some_and(Value::is_string) {
                map.remove("reference");
            }
            if map.contains_key("handle") && map.contains_key("depth") {
                // A page or channel row: its handle names it, its id is ETS's.
                map.remove("id");
            }
            for child in map.values_mut() {
                plain_view(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(plain_view),
        _ => {}
    }
}

/// `knx_get_group`'s default payload: each link with the device's room and
/// the object's channel, and the last telegram without its wire detail.
pub fn plain_group(value: &mut Value, model: &Model) {
    if let Some(links) = value["links"].as_array_mut() {
        for link in links {
            let ia = link["device_ia"]
                .as_str()
                .and_then(|a| a.parse::<IndividualAddress>().ok());
            let object = link["object"].as_u64().and_then(|n| u16::try_from(n).ok());
            if let (Some(ia), Some(map)) = (ia, link.as_object_mut()) {
                if let Some(room) = room_of(model, ia) {
                    map.insert("room".to_string(), json!(room));
                }
                if let Some(object) = object {
                    map.insert("what".to_string(), json!(object_phrase(model, ia, object)));
                }
                drop_nulls(map);
            }
        }
    }
    if let Some(last) = value["last_telegram"].as_object_mut() {
        for key in [
            "apci",
            "payload",
            "dest_type",
            "secure_seq",
            "secure_raw",
            "secure_status",
        ] {
            last.remove(key);
        }
        drop_nulls(last);
    }
}

/// `knx_model_lookup`'s default payload: every match without null or empty
/// fields, the capability matches without the ETS references a key names.
pub fn plain_lookup(value: &mut Value) {
    for kind in ["groups", "devices", "objects", "channels", "capabilities"] {
        if let Some(items) = value[kind].as_array_mut() {
            for item in items {
                if let Some(map) = item.as_object_mut() {
                    drop_nulls(map);
                }
                plain_view(item);
            }
        }
    }
}

/// Removes the null, empty-string and empty-array fields of `map`.
fn drop_nulls(map: &mut Map<String, Value>) {
    map.retain(|_, v| match v {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_view_drops_ets_ids_and_keeps_keys() {
        let mut v = json!({
            "application": "M-0083_A-00B0-32-0B5C",
            "blocks": [{"handle": "c4", "id": "PB-7243", "depth": 0, "includes": ["PB-1"]}],
            "scope": {
                "parameters": [{"key": "schwelle", "reference": "P-51_R-85"}],
                "objects": [{"key": "eingang-1", "number": 22, "dpt": "1.001", "flags": "CWT"}],
            },
            "enable": [{"reference": "P-1_R-1", "set_to": "1"}],
        });
        plain_view(&mut v);
        assert_eq!(
            v,
            json!({
                "blocks": [{"handle": "c4", "depth": 0}],
                "scope": {
                    "parameters": [{"key": "schwelle"}],
                    "objects": [{"key": "eingang-1", "number": 22, "dpt": "1.001"}],
                },
                "enable": [{"reference": "P-1_R-1", "set_to": "1"}],
            })
        );
    }

    #[test]
    fn test_for_the_human_reads_the_counts() {
        assert_eq!(
            for_the_human(&json!({"error_count": 0, "new_warnings": []})),
            "No problems."
        );
        assert!(
            for_the_human(&json!({"error_count": 0, "new_warnings": [{}, {}]}))
                .starts_with("2 new notes")
        );
        assert!(
            for_the_human(&json!({"error_count": 1, "new_warnings": []})).contains("one problem")
        );
    }
}
