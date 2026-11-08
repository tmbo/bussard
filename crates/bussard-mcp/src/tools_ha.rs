//! The Home Assistant tier (issue #280): `knx_ha_status`, `knx_ha_plan` and
//! `knx_ha_apply`.
//!
//! Registered only when `bussard.toml` has a `[home_assistant]` table AND the
//! server runs with `--allow-home-assistant`. The tier never touches the KNX
//! bus; it talks to Home Assistant's REST API and writes one file.
//!
//! - `knx_ha_status` reads (`GET /api/`, `/api/config`, the config entries,
//!   `/api/states`) and changes nothing.
//! - `knx_ha_plan` generates the KNX YAML for the current model and
//!   `ha.toml` overrides with [`bussard_ha::generate`], shapes it like the file
//!   at `home_assistant.config_path` ([`bussard_ha::plan::Layout`]), and says
//!   per entity what writing it would add, change or remove. It returns a
//!   `plan_digest`: SHA-256 over the path, the layout, the text to write and
//!   the file's current bytes.
//! - `knx_ha_apply` takes that digest after the human's explicit yes. It
//!   refuses a digest this session did not produce, one older than the plan
//!   lifetime, and one a fresh plan no longer reproduces (the model, `ha.toml`
//!   or the file moved). It refuses a file that is not YAML-managed, and a
//!   Home Assistant it cannot reach (the reload would fail). Then it backs the
//!   file up under `captures/backups/ha/`, replaces it atomically
//!   ([`bussard_ha::apply`]), calls the `knx.reload` service only after the
//!   write succeeded, and reads the status again. A plan is single use.
//!
//! The token comes from the variable `home_assistant.token_env` names (the
//! process environment or the model's `.env`) and is never part of a result
//! or a log line.

use crate::reply::answer_said;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::args::Parameters;
use bussard_ha::api::{HaClient, HaStatus};
use bussard_ha::plan::{EntityDiff, FileState, Layout};
use bussard_model::Model;
use bussard_model::change::ChangeSet;
use bussard_model::schema::HomeAssistantConfig;
use bussard_service::home_assistant::{
    FileView, HaApplyReport, HaPlanReport, HaStatusReport, Reach, ReachOrStatus, Reload, Running,
    StatusAfter, UnknownFile,
};
use bussard_service::program::plan::Fingerprint;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::Value;

use crate::confirm::Store;
use crate::server::BussardMcp;

/// What `knx_ha_status` says about entities created in Home Assistant's UI.
const UI_NOTE: &str = "KNX entities created in Home Assistant's UI live in its .storage and \
    are not visible through the REST API; bussard neither lists nor touches them. bussard \
    writes only the YAML file at config_path.";

/// The Home Assistant tier's configuration and session state.
///
/// Present in [`crate::SharedState::home_assistant`] only with both the
/// `[home_assistant]` table and `--allow-home-assistant`.
pub struct HomeAssistantTier {
    /// The `[home_assistant]` table as the server started with it.
    config: HomeAssistantConfig,
    /// Plans produced in this session, by digest.
    plans: Store<()>,
    /// Serialises applies.
    lock: tokio::sync::Mutex<()>,
    /// Automation plans produced in this session, by digest.
    pub(crate) automation_plans: Store<crate::tools_ha_automation::Op>,
}

impl HomeAssistantTier {
    /// A tier for `config`, with plans valid for `plan_ttl`.
    pub fn new(config: HomeAssistantConfig, plan_ttl: Duration) -> Self {
        HomeAssistantTier {
            config,
            plans: Store::new(plan_ttl),
            lock: tokio::sync::Mutex::new(()),
            automation_plans: Store::new(plan_ttl),
        }
    }

    /// The lock every Home Assistant write holds.
    pub(crate) fn write_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.lock
    }

    /// The `[home_assistant]` table the tier runs with.
    pub fn config(&self) -> &HomeAssistantConfig {
        &self.config
    }
}

/// Arguments for `knx_ha_apply`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HaApplyArgs {
    /// The `plan_digest` returned by `knx_ha_plan`.
    pub plan_digest: String,
}

#[tool_router(router = ha_router, vis = "pub(crate)")]
impl BussardMcp {
    // `knx_ha_status` (registered only with the Home Assistant tier).
    #[doc = include_str!("../guidance/tools/knx_ha_status.md")]
    #[tool]
    async fn knx_ha_status(&self) -> Result<CallToolResult, ErrorData> {
        answer_said(self.ha_status().await, &self.model())
    }

    // `knx_ha_plan` (registered only with the Home Assistant tier).
    #[doc = include_str!("../guidance/tools/knx_ha_plan.md")]
    #[tool]
    async fn knx_ha_plan(&self) -> Result<CallToolResult, ErrorData> {
        answer_said(self.ha_plan().await, &self.model())
    }

    // `knx_ha_apply` (registered only with the Home Assistant tier).
    #[doc = include_str!("../guidance/tools/knx_ha_apply.md")]
    #[tool]
    async fn knx_ha_apply(
        &self,
        Parameters(args): Parameters<HaApplyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_said(self.ha_apply(args.plan_digest.trim()).await, &self.model())
    }
}

/// The generated text and its diff against the file, for one plan.
struct Prepared {
    /// The resolved `config_path`.
    path: PathBuf,
    /// The file's bytes, `None` when it does not exist.
    current: Option<Vec<u8>>,
    /// Whether bussard may overwrite it.
    file: FileState,
    /// The text bussard would write, shaped for the file's layout.
    desired: String,
    /// The entity diff.
    diff: EntityDiff,
    /// The digest, when the file is YAML-managed and the write changes it.
    digest: Option<String>,
}

impl BussardMcp {
    /// The tier, or the refusal naming what is missing.
    pub(crate) fn ha_tier(&self) -> Result<&HomeAssistantTier, String> {
        self.state().home_assistant.as_ref().ok_or_else(|| {
            "the Home Assistant tier is off; add [home_assistant] to bussard.toml and start \
             the server with --allow-home-assistant"
                .to_string()
        })
    }

    /// `knx_ha_status`'s body.
    async fn ha_status(&self) -> Result<Value, String> {
        let tier = self.ha_tier()?;
        let model = self.state().model.reload();
        let prepared = prepare(&self.state().dir, &model, &tier.config);
        let status = fetch_status(&tier.config).await;
        let file = match &prepared {
            Ok(p) => FileView::Read {
                config_path: p.path.display().to_string(),
                file: p.file.clone(),
                managed: if p.file.layout().is_some() {
                    "yaml"
                } else {
                    "not_yaml"
                },
                generated_entities: p.diff.generated,
                file_entities: p.diff.current,
                running: status.as_ref().ok().map(|s| Running::of(s, &p.desired)),
            },
            Err(reason) => FileView::Unknown {
                file: UnknownFile {
                    state: "unknown",
                    reason: reason.clone(),
                },
            },
        };
        let report = HaStatusReport {
            ok: status.is_ok(),
            status: match status {
                Ok(status) => ReachOrStatus::Read(status),
                Err(reason) => ReachOrStatus::Unreachable {
                    url: tier.config.url.clone(),
                    reachable: false,
                    errors: vec![reason],
                },
            },
            token_env: tier.config.token_env.clone(),
            file,
            ui_entities: UI_NOTE,
        };
        Ok(crate::reply::report(&report, &model))
    }

    /// `knx_ha_plan`'s body.
    async fn ha_plan(&self) -> Result<Value, String> {
        let tier = self.ha_tier()?;
        let dir = self.state().dir.clone();
        let model = self.state().model.reload();
        let prepared = prepare(&dir, &model, &tier.config)?;
        if let Some(digest) = &prepared.digest {
            tier.plans.insert(digest.clone(), "", ());
        }
        let status = fetch_status(&tier.config).await;
        let mut report = HaPlanReport::new(
            &prepared.path,
            prepared.file.clone(),
            prepared.current.as_deref(),
            &prepared.desired,
            &prepared.diff,
            prepared.digest.clone(),
            &bussard_ha::apply::backup_dir(&dir),
        );
        report.home_assistant = Some(Reach::of(&status, &prepared.desired));
        report.plan_ttl_minutes = Some(tier.plans.ttl_minutes());
        if let Ok(s) = &status {
            report.automations = Some(
                crate::tools_ha_automation::managed_automations(&tier.config, s, &model).await,
            );
        }
        Ok(crate::reply::report(&report, &model))
    }

    /// `knx_ha_apply`'s body.
    async fn ha_apply(&self, digest: &str) -> Result<Value, String> {
        let tier = self.ha_tier()?;
        let _guard = tier.lock.lock().await;
        let again = "call knx_ha_plan, show the sentences to the human and ask again";
        tier.plans.fresh(digest, "", "plan", again)?;
        let dir = self.state().dir.clone();
        let model = self.state().model.reload();
        let prepared = prepare(&dir, &model, &tier.config)?;
        if let FileState::NotYaml { reason } = &prepared.file {
            tier.plans.retire(digest);
            return Err(format!(
                "{} is not YAML-managed: {reason}",
                prepared.path.display()
            ));
        }
        if prepared.digest.as_deref() != Some(digest) {
            tier.plans.retire(digest);
            return Err(
                "the plan is stale: the model, ha.toml or the file changed since \
                        knx_ha_plan. Nothing was written. Run knx_ha_plan again, show the new \
                        sentences to the human and ask again"
                    .to_string(),
            );
        }
        // Reachable and authorized before the write: a write Home Assistant
        // cannot be told to reload would leave the two out of step.
        let config = tier.config.clone();
        let before = fetch_status(&config).await?;
        if !before.reachable || !before.authorized {
            return Err(format!(
                "Home Assistant at {} is not usable ({}); nothing was written",
                before.url,
                before.errors.join("; ")
            ));
        }
        tier.plans.retire(digest);
        let current = prepared.current.clone().unwrap_or_default();
        let backup = bussard_ha::apply::write_with_backup(
            &dir,
            &prepared.path,
            &current,
            &prepared.desired,
            SystemTime::now(),
        )
        .map_err(|e| format!("nothing was reloaded: {e}"))?;
        let path = prepared.path.display().to_string();
        let backup_path = backup.display().to_string();
        let reload = {
            let config = config.clone();
            tokio::task::spawn_blocking(move || {
                HaClient::from_config(&config).and_then(|c| c.reload_knx())
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()))
        };
        tracing::info!(
            "audit: knx_ha_apply wrote {path} ({} entity changes); backup {backup_path}; \
             knx.reload {}",
            prepared.diff.changes.len(),
            if reload.is_ok() { "ok" } else { "failed" }
        );
        let after = fetch_status(&config).await;
        let reload_ok = reload.is_ok();
        let report = HaApplyReport {
            ok: reload_ok,
            written: true,
            config_path: path.clone(),
            backup: backup_path.clone(),
            sentences: prepared
                .diff
                .changes
                .iter()
                .map(|c| c.sentence.clone())
                .collect(),
            reload: Reload::of(&reload),
            status_after: match after {
                Ok(s) => StatusAfter::Read {
                    running: Running::of(&s, &prepared.desired),
                    status: s,
                },
                Err(e) => StatusAfter::Unreachable {
                    reachable: false,
                    errors: vec![e],
                },
            },
            message: if reload_ok {
                format!(
                    "Wrote {path} and reloaded Home Assistant's KNX integration. The previous \
                     file is at {backup_path}."
                )
            } else {
                format!(
                    "Wrote {path}, but the knx.reload call failed, so Home Assistant still runs \
                     the old entities until it reloads (Developer tools, YAML, KNX, or a \
                     restart). The previous file is at {backup_path}."
                )
            },
        };
        Ok(crate::reply::report(&report, &model))
    }
}

/// The `next_step` line for a model edit when the Home Assistant tier is on:
/// `None` unless the edit touched a group address the Home Assistant KNX
/// config exposes (in the YAML generated now, or in the file as it is).
pub fn next_step_line(state: &crate::SharedState, changes: &ChangeSet) -> Option<String> {
    let tier = state.home_assistant.as_ref()?;
    let touched: BTreeSet<String> = changes
        .changes
        .iter()
        .filter_map(|c| c.group.clone())
        .collect();
    if touched.is_empty() {
        return None;
    }
    let model = state.model.current();
    let mut exposed = BTreeSet::new();
    let overrides = bussard_ha::Overrides::load(&state.dir).unwrap_or_default();
    if let Ok(text) = bussard_ha::generate(&model, &overrides) {
        exposed.extend(bussard_ha::plan::exposed_addresses(&text));
    }
    if let Some(text) = tier
        .config
        .config_path(&state.dir)
        .and_then(|p| std::fs::read_to_string(p).ok())
    {
        exposed.extend(bussard_ha::plan::exposed_addresses(&text));
    }
    let hit: Vec<String> = touched.intersection(&exposed).cloned().collect();
    if hit.is_empty() {
        return None;
    }
    Some(format!(
        "Home Assistant's KNX config uses {}: knx_ha_plan shows what its YAML would change, \
         and knx_ha_apply writes it after an explicit yes.",
        hit.join(", ")
    ))
}

/// Generates the YAML for `model`, reads the file and diffs the two.
fn prepare(dir: &Path, model: &Model, config: &HomeAssistantConfig) -> Result<Prepared, String> {
    let path = config.config_path(dir).ok_or_else(|| {
        "home_assistant.config_path is not set in bussard.toml; set it to the KNX YAML file \
         Home Assistant reads"
            .to_string()
    })?;
    let current = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("reading {}: {err}", path.display())),
    };
    let text = match &current {
        Some(bytes) => Some(
            String::from_utf8(bytes.clone())
                .map_err(|_| format!("{} is not UTF-8 text", path.display()))?,
        ),
        None => None,
    };
    let file = bussard_ha::plan::classify(text.as_deref());
    let overrides = bussard_ha::Overrides::load(dir).map_err(|e| e.to_string())?;
    let generated = bussard_ha::generate(model, &overrides).map_err(|e| e.to_string())?;
    let layout = file.layout().unwrap_or(Layout::Package);
    let desired = bussard_ha::plan::render_for(&generated, layout).map_err(|e| e.to_string())?;
    let readable = text
        .as_deref()
        .filter(|t| serde_norway_ok(t))
        .map(str::to_string);
    let diff = bussard_ha::plan::diff(readable.as_deref(), &desired).map_err(|e| e.to_string())?;
    let noop = text.as_deref() == Some(desired.as_str());
    let digest = (file.layout().is_some() && !noop)
        .then(|| plan_digest(&path, layout, &desired, current.as_deref()));
    Ok(Prepared {
        path,
        current,
        file,
        desired,
        diff,
        digest,
    })
}

/// Whether `text` parses as YAML (a broken file diffs as empty).
fn serde_norway_ok(text: &str) -> bool {
    bussard_ha::plan::diff(Some(text), "{}").is_ok()
}

/// SHA-256 over everything the write depends on.
fn plan_digest(path: &Path, layout: Layout, desired: &str, current: Option<&[u8]>) -> String {
    let layout = match layout {
        Layout::Package => "package",
        Layout::Included => "included",
    };
    Fingerprint::new(b"bussard-ha-plan-v1")
        .put(path.to_string_lossy().as_bytes())
        .put(layout)
        .put(desired)
        .put([u8::from(current.is_some())])
        .put(current.unwrap_or_default())
        .hex()
}

/// The status read on a blocking thread, or why the client could not be built.
pub(crate) async fn fetch_status(config: &HomeAssistantConfig) -> Result<HaStatus, String> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || HaClient::from_config(&config).map(|c| c.status()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_digest_moves_with_every_input() {
        let path = Path::new("/ha/knx.yaml");
        let base = plan_digest(path, Layout::Package, "knx:\n", Some(b"a"));
        assert_eq!(base.len(), 64);
        assert_ne!(
            base,
            plan_digest(path, Layout::Included, "knx:\n", Some(b"a"))
        );
        assert_ne!(
            base,
            plan_digest(path, Layout::Package, "knx: {}\n", Some(b"a"))
        );
        assert_ne!(
            base,
            plan_digest(path, Layout::Package, "knx:\n", Some(b"b"))
        );
        assert_ne!(base, plan_digest(path, Layout::Package, "knx:\n", None));
        assert_ne!(
            base,
            plan_digest(Path::new("/x.yaml"), Layout::Package, "knx:\n", Some(b"a"))
        );
    }
}
