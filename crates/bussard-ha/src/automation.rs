//! bussard-managed Home Assistant automations (issue #280, step 2).
//!
//! A [`Rule`] is the small shape an assistant proposes: one group address
//! that triggers, an optional value it must carry, and the group values to
//! send in response. [`render`] checks it against the model and renders the
//! automation config Home Assistant's config API stores
//! (`/api/config/automation/config/<id>`):
//!
//! - the trigger is the KNX integration's `knx.telegram` trigger on the
//!   group address, for incoming GroupValueWrite telegrams;
//! - a value is matched with a template condition on `trigger.payload`, in
//!   the raw form the KNX integration reports it (an integer for a 1-, 2- or
//!   4-bit DPT, a list of octets otherwise);
//! - each send is a `knx.send` action with the raw payload, encoded with the
//!   group address's DPT by bussard's own codec (an integer for a sub-byte
//!   DPT, a list of octets otherwise), so Home Assistant needs no `type`.
//!
//! Every automation bussard writes has an id starting with [`ID_PREFIX`] and
//! a description ending in the [`MARKER`] line naming the model directory.
//! bussard only updates or removes an automation that carries both.

use bussard_model::codec::{encode, parse_value};
use bussard_model::{Dpt, GroupAddress, Model};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The id prefix of every automation bussard writes.
pub const ID_PREFIX: &str = "bussard_";

/// The start of the description line that marks an automation as bussard's.
pub const MARKER: &str = "managed by bussard (model ";

/// The trigger: a telegram on one group address, optionally with one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// The group address, e.g. `"4/3/2"`.
    pub ga: String,
    /// The value the telegram must carry, in human form (`"1"`, `"on"`,
    /// `"50%"`); omitted, any value triggers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The DPT to read the value with; must agree with `groups.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
}

/// One group value to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Send {
    /// The group address, e.g. `"4/3/10"`.
    pub ga: String,
    /// The value in human form.
    pub value: String,
    /// The DPT to encode with; must agree with `groups.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
}

/// One action of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Then {
    /// Send a group value (the `knx.send` service).
    pub send: Send,
}

/// A rule the assistant proposes: when `when`, do every `then` in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The trigger.
    pub when: When,
    /// The actions, at least one.
    pub then: Vec<Then>,
    /// A description for Home Assistant's automation list; bussard appends
    /// its marker line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An automation as bussard writes it, in Home Assistant's key order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rendered {
    /// The config id, `bussard_…`.
    pub id: String,
    /// The name Home Assistant shows.
    pub alias: String,
    /// The description, ending in the marker line.
    pub description: String,
    /// `single`: a second telegram while the actions run is ignored.
    pub mode: String,
    /// The `knx.telegram` trigger.
    pub triggers: Vec<Value>,
    /// The value match, when the rule has a value.
    pub conditions: Vec<Value>,
    /// The `knx.send` actions.
    pub actions: Vec<Value>,
}

impl Rendered {
    /// The config as JSON, the body `POST /api/config/automation/config/<id>`
    /// takes.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// A rule bussard refuses, with the reason in one sentence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RuleError(pub String);

/// Checks an automation id: [`ID_PREFIX`], then lowercase letters, digits
/// and underscores, at most 64 characters in all.
///
/// # Errors
///
/// [`RuleError`] naming what is wrong.
pub fn check_id(id: &str) -> Result<(), RuleError> {
    let rest = id.strip_prefix(ID_PREFIX).ok_or_else(|| {
        RuleError(format!(
            "{id} is not a bussard id: bussard writes and removes only automations whose id \
             starts with {ID_PREFIX}"
        ))
    })?;
    if rest.is_empty()
        || id.len() > 64
        || !rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(RuleError(format!(
            "{id} is not a valid id: after {ID_PREFIX} use lowercase letters, digits and \
             underscores, 64 characters at most"
        )));
    }
    Ok(())
}

/// The marker line for the model directory named `model_name`.
pub fn marker_line(model_name: &str) -> String {
    format!("{MARKER}{model_name})")
}

/// Whether a stored automation config is bussard's: a `bussard_` id and the
/// marker line in its description.
pub fn is_managed(id: &str, config: &Value) -> bool {
    id.starts_with(ID_PREFIX)
        && config["description"]
            .as_str()
            .is_some_and(|d| d.contains(MARKER))
}

/// A group address of the rule, resolved against the model.
struct Resolved {
    ga: GroupAddress,
    dpt: Dpt,
}

/// Resolves `ga` and its DPT against `groups.toml`.
fn resolve(model: &Model, ga: &str, dpt: Option<&str>, role: &str) -> Result<Resolved, RuleError> {
    let address: GroupAddress = ga
        .trim()
        .parse()
        .map_err(|_| RuleError(format!("{ga} is not a group address")))?;
    let group = model.groups.groups.get(&address).ok_or_else(|| {
        RuleError(format!(
            "{address} is not in groups.toml; add it (knx_set_group) before an automation \
             uses it"
        ))
    })?;
    let requested = match dpt {
        Some(text) => Some(
            text.trim()
                .parse::<Dpt>()
                .map_err(|_| RuleError(format!("{text} is not a DPT")))?,
        ),
        None => None,
    };
    let dpt = match (requested, group.dpt) {
        (Some(r), Some(g)) => {
            let agree = r.main == g.main && (r.sub.is_none() || g.sub.is_none() || r.sub == g.sub);
            if !agree {
                return Err(RuleError(format!(
                    "the {role} DPT {r} contradicts groups.toml, which types {address} as {g}"
                )));
            }
            g
        }
        (Some(r), None) => r,
        (None, Some(g)) => g,
        (None, None) => {
            return Err(RuleError(format!(
                "{address} has no DPT in groups.toml; set one (knx_set_group) or pass dpt"
            )));
        }
    };
    Ok(Resolved { ga: address, dpt })
}

/// The raw payload Home Assistant's KNX integration uses for `value` under
/// `dpt`: an integer for a sub-byte DPT, a list of octets otherwise.
///
/// # Errors
///
/// [`RuleError`] when the value does not parse or encode under the DPT.
pub fn payload(dpt: &Dpt, value: &str, address: GroupAddress) -> Result<Value, RuleError> {
    let typed = parse_value(dpt, value.trim())
        .map_err(|e| RuleError(format!("{value} is not a value for {address} ({dpt}): {e}")))?;
    let bytes = encode(dpt, &typed).map_err(|e| {
        RuleError(format!(
            "{value} cannot be encoded for {address} ({dpt}): {e}"
        ))
    })?;
    if dpt.is_packable() {
        Ok(json!(bytes.first().copied().unwrap_or(0)))
    } else {
        Ok(json!(bytes))
    }
}

/// The rule in one sentence: `when 4/3/2 receives 1, send 0 to 4/3/10`.
pub fn sentence(rule: &Rule) -> String {
    let received = match &rule.when.value {
        Some(v) => v.trim().to_string(),
        None => "any value".to_string(),
    };
    let sends: Vec<String> = rule
        .then
        .iter()
        .map(|t| format!("{} to {}", t.send.value.trim(), t.send.ga.trim()))
        .collect();
    format!(
        "when {} receives {received}, send {}",
        rule.when.ga.trim(),
        sends.join(", then ")
    )
}

/// Checks `rule` against `model` and renders the automation with `id`,
/// `alias` (default: the sentence) and the marker for `model_name`.
///
/// Refuses a group address `groups.toml` does not list, a DPT that
/// contradicts it, a value the DPT cannot carry, a send to a `protected`
/// group address, a rule without actions, and an id that is not bussard's.
///
/// # Errors
///
/// [`RuleError`] with the reason.
pub fn render(
    model: &Model,
    model_name: &str,
    id: &str,
    alias: Option<&str>,
    rule: &Rule,
) -> Result<Rendered, RuleError> {
    check_id(id)?;
    if rule.then.is_empty() {
        return Err(RuleError(
            "the rule has no action: give at least one then.send".to_string(),
        ));
    }
    let trigger = resolve(model, &rule.when.ga, rule.when.dpt.as_deref(), "trigger")?;
    let mut conditions = Vec::new();
    if let Some(value) = &rule.when.value {
        let expected = payload(&trigger.dpt, value, trigger.ga)?;
        let template = if trigger.dpt.is_packable() {
            format!("{{{{ trigger.payload == {expected} }}}}")
        } else {
            format!("{{{{ trigger.payload | list == {expected} }}}}")
        };
        conditions.push(json!({"condition": "template", "value_template": template}));
    }
    let mut actions = Vec::new();
    for then in &rule.then {
        let target = resolve(model, &then.send.ga, then.send.dpt.as_deref(), "send")?;
        if model
            .groups
            .groups
            .get(&target.ga)
            .is_some_and(|g| g.protected)
        {
            return Err(RuleError(format!(
                "{} is protected in groups.toml; an automation may not send to it",
                target.ga
            )));
        }
        let data = payload(&target.dpt, &then.send.value, target.ga)?;
        actions.push(json!({
            "action": "knx.send",
            "data": {"address": target.ga.to_string(), "payload": data},
        }));
    }
    let sentence = sentence(rule);
    let mut description = rule
        .description
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| format!("{d}\n\n"))
        .unwrap_or_default();
    description.push_str(&marker_line(model_name));
    Ok(Rendered {
        id: id.to_string(),
        alias: alias
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| sentence.clone()),
        description,
        mode: "single".to_string(),
        triggers: vec![json!({
            "trigger": "knx.telegram",
            "destination": [trigger.ga.to_string()],
            "group_value_write": true,
            "group_value_response": false,
            "group_value_read": false,
            "incoming": true,
            "outgoing": false,
        })],
        conditions,
        actions,
    })
}

/// The group addresses a stored automation config uses: the `knx.telegram`
/// destinations and the `knx.send` addresses.
pub fn addresses(config: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for trigger in config["triggers"].as_array().into_iter().flatten() {
        for d in trigger["destination"].as_array().into_iter().flatten() {
            if let Some(ga) = d.as_str() {
                out.push(ga.to_string());
            }
        }
    }
    for action in config["actions"].as_array().into_iter().flatten() {
        if let Some(ga) = action["data"]["address"].as_str() {
            out.push(ga.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::schema::{Group, Groups};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model() -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = Groups::default();
        for (ga, name, dpt, protected) in [
            ("4/3/2", "Zu Hause", "1.001", false),
            ("4/3/10", "Gastmodus", "1.001", false),
            ("4/3/20", "Licht Dimmwert", "5.001", false),
            ("4/3/30", "Szene", "17.001", false),
            ("0/0/1", "Zentral Aus", "1.001", true),
            ("4/3/40", "Untypisiert", "", false),
        ] {
            groups.groups.insert(
                ga.parse()?,
                Group {
                    name: name.to_string(),
                    dpt: if dpt.is_empty() {
                        None
                    } else {
                        Some(dpt.parse()?)
                    },
                    protected,
                    ..Default::default()
                },
            );
        }
        Ok(Model {
            config: Default::default(),
            groups,
            links: Default::default(),
            devices: Default::default(),
        })
    }

    fn guest_rule() -> Rule {
        Rule {
            when: When {
                ga: "4/3/2".into(),
                value: Some("1".into()),
                dpt: Some("1.001".into()),
            },
            then: vec![Then {
                send: Send {
                    ga: "4/3/10".into(),
                    value: "0".into(),
                    dpt: Some("1.001".into()),
                },
            }],
            description: Some("Zu Hause ends guest mode".into()),
        }
    }

    #[test]
    fn test_render_guest_mode_rule_exactly() -> TestResult {
        let rendered = render(
            &model()?,
            "knx",
            "bussard_guest_mode_end",
            None,
            &guest_rule(),
        )?;
        assert_eq!(
            rendered.to_json(),
            json!({
                "id": "bussard_guest_mode_end",
                "alias": "when 4/3/2 receives 1, send 0 to 4/3/10",
                "description": "Zu Hause ends guest mode\n\nmanaged by bussard (model knx)",
                "mode": "single",
                "triggers": [{
                    "trigger": "knx.telegram",
                    "destination": ["4/3/2"],
                    "group_value_write": true,
                    "group_value_response": false,
                    "group_value_read": false,
                    "incoming": true,
                    "outgoing": false,
                }],
                "conditions": [{
                    "condition": "template",
                    "value_template": "{{ trigger.payload == 1 }}",
                }],
                "actions": [{
                    "action": "knx.send",
                    "data": {"address": "4/3/10", "payload": 0},
                }],
            })
        );
        assert!(is_managed("bussard_guest_mode_end", &rendered.to_json()));
        Ok(())
    }

    #[test]
    fn test_render_one_byte_payloads_are_octet_lists() -> TestResult {
        let rule = Rule {
            when: When {
                ga: "4/3/20".into(),
                value: Some("100%".into()),
                dpt: None,
            },
            then: vec![
                Then {
                    send: Send {
                        ga: "4/3/20".into(),
                        value: "50%".into(),
                        dpt: None,
                    },
                },
                Then {
                    send: Send {
                        ga: "4/3/30".into(),
                        value: "3".into(),
                        dpt: None,
                    },
                },
            ],
            description: None,
        };
        let r = render(&model()?, "knx", "bussard_dim", Some("Dim"), &rule)?;
        assert_eq!(
            r.conditions[0]["value_template"],
            "{{ trigger.payload | list == [255] }}"
        );
        assert_eq!(r.actions[0]["data"]["payload"], json!([128]));
        assert!(r.actions[1]["data"]["payload"].is_array());
        assert_eq!(r.alias, "Dim");
        assert_eq!(r.description, "managed by bussard (model knx)");
        Ok(())
    }

    #[test]
    fn test_render_refusals() -> TestResult {
        let m = model()?;
        let refuse = |id: &str, rule: &Rule| render(&m, "knx", id, None, rule).err();
        assert!(
            refuse("guest_mode", &guest_rule()).is_some_and(|e| e.0.contains("not a bussard id"))
        );
        assert!(refuse("bussard_Bad-Id", &guest_rule()).is_some());
        let mut unknown = guest_rule();
        unknown.then[0].send.ga = "9/7/9".into();
        assert!(refuse("bussard_x", &unknown).is_some_and(|e| e.0.contains("not in groups.toml")));
        let mut mismatch = guest_rule();
        mismatch.when.dpt = Some("5.001".into());
        assert!(refuse("bussard_x", &mismatch).is_some_and(|e| e.0.contains("contradicts")));
        let mut protected = guest_rule();
        protected.then[0].send.ga = "0/0/1".into();
        assert!(refuse("bussard_x", &protected).is_some_and(|e| e.0.contains("protected")));
        let mut untyped = guest_rule();
        untyped.then[0].send = Send {
            ga: "4/3/40".into(),
            value: "1".into(),
            dpt: None,
        };
        assert!(refuse("bussard_x", &untyped).is_some_and(|e| e.0.contains("no DPT")));
        let mut bad_value = guest_rule();
        bad_value.then[0].send.value = "maybe".into();
        assert!(refuse("bussard_x", &bad_value).is_some());
        let mut empty = guest_rule();
        empty.then.clear();
        assert!(refuse("bussard_x", &empty).is_some_and(|e| e.0.contains("no action")));
        Ok(())
    }

    #[test]
    fn test_is_managed_needs_prefix_and_marker() {
        let marked = json!({"description": "x\n\nmanaged by bussard (model knx)"});
        assert!(is_managed("bussard_a", &marked));
        assert!(!is_managed("a", &marked));
        assert!(!is_managed(
            "bussard_a",
            &json!({"description": "hand-made"})
        ));
    }

    #[test]
    fn test_addresses_lists_trigger_and_send_gas() -> TestResult {
        let r = render(&model()?, "knx", "bussard_g", None, &guest_rule())?;
        assert_eq!(addresses(&r.to_json()), ["4/3/2", "4/3/10"]);
        Ok(())
    }
}
