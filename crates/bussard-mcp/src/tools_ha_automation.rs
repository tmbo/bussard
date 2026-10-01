//! bussard-managed Home Assistant automations (issue #280, step 2):
//! `knx_ha_automation_plan`, `knx_ha_automation_apply` and
//! `knx_ha_automation_remove`.
//!
//! Part of the Home Assistant tier ([`crate::tools_ha`]): registered with it,
//! never touching the bus. The assistant proposes a small rule (`when` a
//! group address receives a value, `then` send group values); the plan
//! checks it against `groups.toml` and renders it with
//! [`bussard_ha::automation::render`], reads the automation Home Assistant
//! stores under the same id, and returns the rendered config, the sentence,
//! whether it creates or updates, and a `plan_digest`. The apply takes that
//! digest after the human's explicit yes, renders again against the current
//! model, reads Home Assistant again, and refuses when either moved. Then it
//! keeps the previous config under `captures/backups/ha/`, writes through
//! the config API (`POST /api/config/automation/config/<id>`) and calls
//! `automation.reload`. Removal has the same two steps.
//!
//! Only ids starting with `bussard_` are written, and an existing
//! automation is updated or removed only when its description carries the
//! bussard marker line, so automations made by hand are never touched.

use std::time::{Instant, SystemTime};

use crate::args::Parameters;
use bussard_ha::api::{HaClient, HaStatus};
use bussard_ha::automation::{self, Rule};
use bussard_model::Model;
use bussard_model::schema::HomeAssistantConfig;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::BussardMcp;

/// One automation plan this session produced.
#[derive(Debug, Clone)]
pub struct PendingAutomation {
    /// When the plan was produced.
    created: Instant,
    /// What the plan does.
    op: Op,
}

/// What an automation plan does.
#[derive(Debug, Clone)]
enum Op {
    /// Create or replace `id` from `rule`.
    Save {
        id: String,
        alias: Option<String>,
        rule: Rule,
    },
    /// Delete `id`.
    Remove { id: String },
}

/// The trigger of a rule.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WhenArg {
    /// The group address that triggers, e.g. `"4/3/2"`.
    pub ga: String,
    /// The value it must receive, in human form (`"1"`, `"on"`, `"50%"`).
    /// Omit it to trigger on any value.
    #[serde(default)]
    pub value: Option<String>,
    /// The DPT, e.g. `"1.001"`; must agree with groups.toml. Optional when
    /// groups.toml types the address.
    #[serde(default)]
    pub dpt: Option<String>,
}

/// One group value to send.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendArg {
    /// The group address, e.g. `"4/3/10"`.
    pub ga: String,
    /// The value in human form.
    pub value: String,
    /// The DPT; must agree with groups.toml.
    #[serde(default)]
    pub dpt: Option<String>,
}

/// One action of a rule.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThenArg {
    /// Send a group value through Home Assistant's `knx.send` service.
    pub send: SendArg,
}

/// Arguments for `knx_ha_automation_plan`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AutomationPlanArgs {
    /// The automation id: `bussard_` then lowercase letters, digits and
    /// underscores, e.g. `"bussard_guest_mode_end"`.
    pub id: String,
    /// The name Home Assistant shows; default: the rule's sentence.
    #[serde(default)]
    pub alias: Option<String>,
    /// A description; bussard appends its marker line.
    #[serde(default)]
    pub description: Option<String>,
    /// The trigger.
    pub when: WhenArg,
    /// The actions, at least one, in order.
    pub then: Vec<ThenArg>,
}

/// Arguments for `knx_ha_automation_apply`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AutomationApplyArgs {
    /// The `plan_digest` from `knx_ha_automation_plan`.
    pub plan_digest: String,
}

/// Arguments for `knx_ha_automation_remove`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AutomationRemoveArgs {
    /// The id of a bussard-managed automation, `bussard_…`.
    pub id: String,
    /// Omit it to get the removal plan and its digest; pass that digest
    /// (after the human's yes) to delete.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

impl AutomationPlanArgs {
    /// The rule in `bussard-ha`'s shape.
    fn rule(&self) -> Rule {
        Rule {
            when: automation::When {
                ga: self.when.ga.clone(),
                value: self.when.value.clone(),
                dpt: self.when.dpt.clone(),
            },
            then: self
                .then
                .iter()
                .map(|t| automation::Then {
                    send: automation::Send {
                        ga: t.send.ga.clone(),
                        value: t.send.value.clone(),
                        dpt: t.send.dpt.clone(),
                    },
                })
                .collect(),
            description: self.description.clone(),
        }
    }
}

#[tool_router(router = ha_automation_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_ha_automation_plan` (Home Assistant tier).
    #[tool(
        description = "Plan a bussard-managed Home Assistant automation from a small rule \
        (issue #280): `when` a group address receives a value (optional; any value without \
        it), `then` send group values (each `{send: {ga, value, dpt?}}`). Use it for the logic \
        the bus cannot do alone, e.g. when 4/3/2 receives 1, send 0 to 4/3/10. Reads only: \
        checks every address and DPT against groups.toml, renders the automation (the KNX \
        integration's knx.telegram trigger, a payload condition, knx.send actions with the \
        raw payload), reads the automation Home Assistant stores under `id`, and returns \
        `sentence`, `sentences`, `op` (create or update), `automation` (the JSON written) and \
        `yaml`, `previous`, the `question` and a plan_digest. The id must start with \
        bussard_; an existing automation without bussard's marker line is refused. ALWAYS \
        show the sentences and the automation to the human and ask the question; call \
        knx_ha_automation_apply only after an explicit yes in this conversation. Refuses \
        addresses groups.toml does not list, DPTs that contradict it and sends to protected \
        addresses. Only available with --allow-home-assistant."
    )]
    async fn knx_ha_automation_plan(
        &self,
        Parameters(args): Parameters<AutomationPlanArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let op = Op::Save {
            id: args.id.trim().to_string(),
            alias: args.alias.clone(),
            rule: args.rule(),
        };
        ok(self.automation_plan(op).await)
    }

    /// `knx_ha_automation_apply` (Home Assistant tier).
    #[tool(
        description = "Write the planned bussard-managed automation to Home Assistant and \
        reload automations (issue #280). Call this ONLY after you showed the human the plan \
        from knx_ha_automation_plan and the human answered yes explicitly in this \
        conversation. Pass its plan_digest. Refuses a digest this session did not produce, an \
        expired or used one, and one a fresh plan no longer reproduces (the model or the \
        automation in Home Assistant changed). Keeps the previous automation's JSON under \
        captures/backups/ha/, writes through the config API, calls automation.reload and \
        returns the backup path and the outcome. Only available with --allow-home-assistant."
    )]
    async fn knx_ha_automation_apply(
        &self,
        Parameters(args): Parameters<AutomationApplyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        ok(self.automation_apply(args.plan_digest.trim(), None).await)
    }

    /// `knx_ha_automation_remove` (Home Assistant tier).
    #[tool(
        description = "Remove a bussard-managed Home Assistant automation (issue #280), in two \
        calls. Without plan_digest: reads the automation and returns what would be removed, \
        the question and a plan_digest; nothing changes. Show it to the human. With the \
        plan_digest, and ONLY after the human said yes explicitly in this conversation: keeps \
        its JSON under captures/backups/ha/, deletes it through the config API and reloads \
        automations. Refuses ids that do not start with bussard_ and automations without \
        bussard's marker line. Only available with --allow-home-assistant."
    )]
    async fn knx_ha_automation_remove(
        &self,
        Parameters(args): Parameters<AutomationRemoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = args.id.trim().to_string();
        match args.plan_digest.as_deref().map(str::trim) {
            None => ok(self.automation_plan(Op::Remove { id }).await),
            Some(digest) => ok(self.automation_apply(digest, Some(&id)).await),
        }
    }
}

/// A plan, rendered against the model and Home Assistant as they are now.
struct Planned {
    /// The automation id.
    id: String,
    /// The config to write (`None` for a removal).
    config: Option<Value>,
    /// What Home Assistant stores under the id now.
    previous: Option<Value>,
    /// The rule's sentence (`None` for a removal).
    sentence: Option<String>,
    /// The digest.
    digest: String,
}

impl BussardMcp {
    /// The model directory's name for the marker line.
    fn model_name(&self) -> String {
        self.state()
            .dir
            .canonicalize()
            .unwrap_or_else(|_| self.state().dir.clone())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "knx".to_string())
    }

    /// Renders `op` against the current model and reads Home Assistant.
    async fn render_op(&self, config: &HomeAssistantConfig, op: &Op) -> Result<Planned, String> {
        let model = self.state().model.reload();
        let model_name = self.model_name();
        let (id, rendered) = match op {
            Op::Save { id, alias, rule } => {
                let rendered = automation::render(&model, &model_name, id, alias.as_deref(), rule)
                    .map_err(|e| e.to_string())?;
                (
                    id.clone(),
                    Some((rendered.to_json(), automation::sentence(rule))),
                )
            }
            Op::Remove { id } => {
                automation::check_id(id).map_err(|e| e.to_string())?;
                (id.clone(), None)
            }
        };
        let previous = read_automation(config, &id).await?;
        if let Some(prev) = &previous {
            if !automation::is_managed(&id, prev) {
                return Err(format!(
                    "Home Assistant has an automation {id} that bussard did not write (its \
                     description lacks the line \"managed by bussard (model …)\"); bussard \
                     leaves it alone. Choose another id"
                ));
            }
        } else if rendered.is_none() {
            return Err(format!("Home Assistant has no automation {id}"));
        }
        let (config_json, sentence) = match rendered {
            Some((c, s)) => (Some(c), Some(s)),
            None => (None, None),
        };
        let digest = automation_digest(&id, config_json.as_ref(), previous.as_ref());
        Ok(Planned {
            id,
            config: config_json,
            previous,
            sentence,
            digest,
        })
    }

    /// The plan for `op`, as the tool result.
    async fn automation_plan(&self, op: Op) -> Value {
        let tier = match self.ha_tier() {
            Ok(t) => t,
            Err(reason) => return refusal(reason),
        };
        let planned = match self.render_op(tier.config(), &op).await {
            Ok(p) => p,
            Err(reason) => return refusal(reason),
        };
        let unchanged = planned.config.is_some() && planned.config == planned.previous;
        let (op_name, sentences, question) = describe(&planned);
        if !unchanged {
            let mut plans = tier.automation_plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl());
            plans.insert(
                planned.digest.clone(),
                PendingAutomation {
                    created: Instant::now(),
                    op,
                },
            );
        }
        let yaml = planned
            .config
            .as_ref()
            .and_then(|c| serde_norway::to_string(c).ok());
        json!({
            "ok": true,
            "id": planned.id,
            "op": if unchanged { "unchanged" } else { op_name },
            "sentence": planned.sentence,
            "sentences": sentences,
            "automation": planned.config,
            "yaml": yaml,
            "previous": planned.previous,
            "question": (!unchanged).then_some(question),
            "plan_digest": (!unchanged).then_some(planned.digest),
            "backup_dir": bussard_ha::apply::backup_dir(&self.state().dir).display().to_string(),
            "plan_ttl_minutes": tier.plan_ttl().as_secs().div_ceil(60),
        })
    }

    /// Applies the plan with `digest`; `remove_id` is set for a removal call.
    async fn automation_apply(&self, digest: &str, remove_id: Option<&str>) -> Value {
        match self.automation_apply_inner(digest, remove_id).await {
            Ok(v) => v,
            Err(reason) => refusal(reason),
        }
    }

    async fn automation_apply_inner(
        &self,
        digest: &str,
        remove_id: Option<&str>,
    ) -> Result<Value, String> {
        let tier = self.ha_tier()?;
        let _guard = tier.write_lock().lock().await;
        let pending = tier.automation_plans().get(digest).cloned();
        let Some(pending) = pending else {
            return Err(
                "this plan_digest was not produced by a plan in this server session (or \
                        was already used); plan again, show it to the human and ask again"
                    .to_string(),
            );
        };
        let is_remove = matches!(pending.op, Op::Remove { .. });
        let wrong_tool = match (&pending.op, remove_id) {
            (Op::Remove { id }, Some(asked)) => id != asked,
            (Op::Remove { .. }, None) | (Op::Save { .. }, Some(_)) => true,
            (Op::Save { .. }, None) => false,
        };
        if wrong_tool {
            return Err(if is_remove {
                "this digest is a removal plan: pass it to knx_ha_automation_remove with the \
                 same id"
                    .to_string()
            } else {
                "this digest is not a removal plan for that id: pass an automation plan's \
                 digest to knx_ha_automation_apply"
                    .to_string()
            });
        }
        if pending.created.elapsed() > tier.plan_ttl() {
            tier.automation_plans().remove(digest);
            return Err("the plan expired; plan again and ask the human again".to_string());
        }
        let config = tier.config().clone();
        let planned = match self.render_op(&config, &pending.op).await {
            Ok(p) => p,
            Err(reason) => {
                tier.automation_plans().remove(digest);
                return Err(format!("nothing was written: {reason}"));
            }
        };
        if planned.digest != digest {
            tier.automation_plans().remove(digest);
            return Err(
                "the plan is stale: the model or the automation in Home Assistant \
                        changed since the plan. Nothing was written. Plan again, show it to the \
                        human and ask again"
                    .to_string(),
            );
        }
        tier.automation_plans().remove(digest);
        let dir = self.state().dir.clone();
        let backup = match &planned.previous {
            Some(prev) => Some(
                bussard_ha::apply::write_backup(
                    &dir,
                    &format!("automation-{}-", planned.id),
                    "json",
                    serde_json::to_string_pretty(prev)
                        .unwrap_or_default()
                        .as_bytes(),
                    SystemTime::now(),
                )
                .map_err(|e| format!("nothing was written: {e}"))?,
            ),
            None => None,
        };
        let id = planned.id.clone();
        let body = planned.config.clone();
        let write = {
            let config = config.clone();
            let id = id.clone();
            tokio::task::spawn_blocking(move || -> Result<(), String> {
                let client = HaClient::from_config(&config).map_err(|e| e.to_string())?;
                match &body {
                    Some(b) => client.save_automation(&id, b),
                    None => client.delete_automation(&id),
                }
                .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r)
        };
        if let Err(reason) = write {
            return Err(format!(
                "Home Assistant refused the {}: {reason}; nothing was reloaded",
                if is_remove { "removal" } else { "write" }
            ));
        }
        let reload = {
            let config = config.clone();
            tokio::task::spawn_blocking(move || {
                HaClient::from_config(&config).and_then(|c| c.reload_automations())
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()))
        };
        let backup_path = backup.as_ref().map(|p| p.display().to_string());
        tracing::info!(
            "audit: {} {id}; backup {}; automation.reload {}",
            if is_remove {
                "knx_ha_automation_remove deleted"
            } else {
                "knx_ha_automation_apply wrote"
            },
            backup_path.as_deref().unwrap_or("(none, new automation)"),
            if reload.is_ok() { "ok" } else { "failed" }
        );
        let (_, sentences, _) = describe(&planned);
        Ok(json!({
            "ok": reload.is_ok(),
            "id": id,
            "op": if is_remove { "remove" } else if planned.previous.is_some() { "update" } else { "create" },
            "written": true,
            "sentences": sentences,
            "backup": backup_path,
            "reload": match &reload {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": e}),
            },
            "message": match (&reload, is_remove) {
                (Ok(()), true) => format!("Removed {id} from Home Assistant and reloaded automations."),
                (Ok(()), false) => format!("Wrote {id} to Home Assistant and reloaded automations."),
                (Err(_), _) => format!(
                    "Home Assistant accepted the change to {id}, but automation.reload failed; \
                     it takes effect at the next reload or restart."
                ),
            },
        }))
    }
}

/// The op name, the sentences and the question for a plan.
fn describe(p: &Planned) -> (&'static str, Vec<String>, String) {
    match (&p.config, &p.previous) {
        (None, previous) => {
            let alias = previous
                .as_ref()
                .and_then(|v| v["alias"].as_str())
                .unwrap_or_default();
            (
                "remove",
                vec![format!("- removes the automation {} (\"{alias}\")", p.id)],
                format!("Remove the automation {} from Home Assistant?", p.id),
            )
        }
        (Some(_), None) => (
            "create",
            vec![format!(
                "+ creates the automation {}: {}",
                p.id,
                p.sentence.as_deref().unwrap_or_default()
            )],
            format!(
                "Create the automation {} in Home Assistant and reload automations?",
                p.id
            ),
        ),
        (Some(config), Some(previous)) => {
            let changed: Vec<&str> = [
                "alias",
                "description",
                "mode",
                "triggers",
                "conditions",
                "actions",
            ]
            .into_iter()
            .filter(|k| config.get(*k) != previous.get(*k))
            .collect();
            (
                "update",
                vec![format!(
                    "~ updates the automation {}: {} (changes {})",
                    p.id,
                    p.sentence.as_deref().unwrap_or_default(),
                    if changed.is_empty() {
                        "nothing".to_string()
                    } else {
                        changed.join(", ")
                    }
                )],
                format!(
                    "Replace the automation {} in Home Assistant and reload automations?",
                    p.id
                ),
            )
        }
    }
}

/// Reads automation `id` from Home Assistant on a blocking thread.
async fn read_automation(config: &HomeAssistantConfig, id: &str) -> Result<Option<Value>, String> {
    let config = config.clone();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || {
        HaClient::from_config(&config)
            .and_then(|c| c.automation(&id))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// SHA-256 over the id, the config to write and the config stored now.
fn automation_digest(id: &str, config: Option<&Value>, previous: Option<&Value>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bussard-ha-automation-v1\0");
    hasher.update(id.as_bytes());
    for part in [config, previous] {
        match part {
            Some(v) => {
                let text = v.to_string();
                hasher.update([1]);
                hasher.update((text.len() as u64).to_le_bytes());
                hasher.update(text.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The bussard-managed automations Home Assistant runs, for `knx_ha_plan`:
/// id, alias, state, whether the marker is there, and the group addresses
/// they use that `groups.toml` no longer lists.
pub(crate) async fn managed_automations(
    config: &HomeAssistantConfig,
    status: &HaStatus,
    model: &Model,
) -> Value {
    let ids: Vec<(String, Option<String>, String)> = status
        .automations
        .iter()
        .filter(|a| a.id.starts_with(automation::ID_PREFIX))
        .map(|a| (a.id.clone(), a.alias.clone(), a.state.clone()))
        .collect();
    let mut out = Vec::new();
    for (id, alias, state) in ids {
        let stored = read_automation(config, &id).await;
        let (managed, problems) = match &stored {
            Ok(Some(c)) => {
                let missing: Vec<String> = automation::addresses(c)
                    .into_iter()
                    .filter(|ga| {
                        ga.parse()
                            .map(|g| !model.groups.groups.contains_key(&g))
                            .unwrap_or(true)
                    })
                    .map(|ga| format!("{ga} is no longer in groups.toml"))
                    .collect();
                (automation::is_managed(&id, c), missing)
            }
            Ok(None) => (false, vec!["the config could not be found".to_string()]),
            Err(e) => (false, vec![e.clone()]),
        };
        out.push(json!({
            "id": id,
            "alias": alias,
            "state": state,
            "managed": managed,
            "problems": problems,
        }));
    }
    Value::Array(out)
}

/// A structured result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result the caller reads out.
fn refusal(reason: String) -> Value {
    json!({"ok": false, "refused": true, "reason": reason})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_automation_digest_moves_with_every_input() {
        let a = json!({"alias": "a"});
        let b = json!({"alias": "b"});
        let base = automation_digest("bussard_x", Some(&a), None);
        assert_ne!(base, automation_digest("bussard_y", Some(&a), None));
        assert_ne!(base, automation_digest("bussard_x", Some(&b), None));
        assert_ne!(base, automation_digest("bussard_x", Some(&a), Some(&a)));
        assert_ne!(base, automation_digest("bussard_x", None, Some(&a)));
    }
}
