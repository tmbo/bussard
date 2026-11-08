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

use bussard_model::{IndividualAddress, Model};
use serde_json::{Map, Value, json};

pub use bussard_service::report::{device_phrase, object_phrase, room_of};

pub use bussard_service::model_edit::{devices_to_push, edit_summary};

/// The one line an edit result's `validation` gains for the human: whether
/// the model has problems that stop a push, and whether the edit added notes.
pub fn for_the_human(validation: &Value) -> String {
    let errors = validation["error_count"].as_u64().unwrap_or(0) as usize;
    let new_warnings = validation["new_warnings"].as_array().map_or(0, Vec::len);
    bussard_service::model_edit::for_the_human(errors, new_warnings)
}

/// Adds `for_the_human` to an edit result's `validation` object.
pub fn put_for_the_human(result: &mut Value) {
    let line = for_the_human(&result["validation"]);
    if let Some(map) = result["validation"].as_object_mut() {
        map.insert("for_the_human".to_string(), Value::String(line));
    }
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
