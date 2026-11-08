//! The Home Assistant tier's results in one shape each (issue #904):
//! `knx_ha_status`, `knx_ha_plan`, `knx_ha_apply` and the automation tools.
//! Each is a `Serialize` struct here; the MCP result adds the chat envelope
//! from its [`Report`] methods.

use bussard_ha::api::HaStatus;
use bussard_ha::plan::{EntityChange, EntityChangeKind, EntityDiff, FileState, Layout};
use bussard_model::Model;
use bussard_model::text::join_and;
use serde::Serialize;
use serde_json::Value;

use crate::report::Report;

/// Which generated entities Home Assistant runs (by platform and name).
#[derive(Debug, Clone, Serialize)]
pub struct Running {
    /// Whether bussard could tell (the token is authorized).
    pub known: bool,
    /// Generated entities Home Assistant runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_running: Option<usize>,
    /// Generated entities it does not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_not_running: Option<usize>,
    /// The first of those, `platform "name"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_running: Option<Vec<String>>,
}

impl Running {
    /// What `status` runs of the generated text `desired`.
    pub fn of(status: &HaStatus, desired: &str) -> Running {
        if !status.authorized {
            return Running {
                known: false,
                generated_running: None,
                generated_not_running: None,
                not_running: None,
            };
        }
        let names = bussard_ha::plan::diff(None, desired)
            .map(|d| d.changes)
            .unwrap_or_default();
        let missing: Vec<String> = names
            .iter()
            .filter(|c| !status.runs(&c.platform, &c.name))
            .map(|c| format!("{} \"{}\"", c.platform, c.name))
            .collect();
        Running {
            known: true,
            generated_running: Some(names.len() - missing.len()),
            generated_not_running: Some(missing.len()),
            not_running: Some(missing.into_iter().take(20).collect()),
        }
    }
}

/// Home Assistant as a plan sees it: reachable, authorized, what it runs.
#[derive(Debug, Clone, Serialize)]
pub struct Reach {
    /// It answered.
    pub reachable: bool,
    /// The token is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    /// What went wrong.
    pub errors: Vec<String>,
    /// What it runs.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub running: Option<Running>,
}

impl Reach {
    /// `status` as read, or why it could not be.
    pub fn of(status: &Result<HaStatus, String>, desired: &str) -> Reach {
        match status {
            Ok(s) => Reach {
                reachable: s.reachable,
                authorized: Some(s.authorized),
                errors: s.errors.clone(),
                running: Some(Running::of(s, desired)),
            },
            Err(reason) => Reach {
                reachable: false,
                authorized: None,
                errors: vec![reason.clone()],
                running: None,
            },
        }
    }
}

/// A bussard-managed automation Home Assistant runs.
#[derive(Debug, Clone, Serialize)]
pub struct ManagedAutomation {
    /// Its id.
    pub id: String,
    /// Its alias.
    pub alias: Option<String>,
    /// Its state.
    pub state: String,
    /// Whether it carries bussard's marker.
    pub managed: bool,
    /// What is wrong with it.
    pub problems: Vec<String>,
}

/// The entity counts of a plan.
#[derive(Debug, Clone, Serialize)]
pub struct HaCounts {
    /// Entities added.
    pub added: usize,
    /// Entities changed.
    pub changed: usize,
    /// Entities removed.
    pub removed: usize,
    /// Entities that stay.
    pub unchanged: usize,
    /// Entities generated.
    pub generated: usize,
    /// Entities in the file now.
    pub file: usize,
}

/// `knx_ha_plan`: what writing the KNX YAML would change.
#[derive(Debug, Clone, Serialize)]
pub struct HaPlanReport {
    /// Always `true`: the plan was made.
    pub ok: bool,
    /// The KNX YAML file.
    pub config_path: String,
    /// Whether bussard may overwrite it.
    pub file: FileState,
    /// Its layout.
    pub layout: Option<Layout>,
    /// The file already holds the generated text.
    pub noop: bool,
    /// One sentence per entity change.
    pub sentences: Vec<String>,
    /// The entity changes.
    pub changes: Vec<EntityChange>,
    /// The counts.
    pub counts: HaCounts,
    /// The one question.
    pub question: Option<String>,
    /// The digest the write takes.
    pub plan_digest: Option<String>,
    /// Where the previous file is backed up.
    pub backup_dir: String,
    /// Home Assistant as it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_assistant: Option<Reach>,
    /// How long the digest stays valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_ttl_minutes: Option<u64>,
    /// The bussard-managed automations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automations: Option<Vec<ManagedAutomation>>,
}

impl HaPlanReport {
    /// The plan of writing `desired` over `current` at `path` (classified
    /// as `file`), with `diff` and `digest`; `backup_dir` is where the old
    /// file goes.
    pub fn new(
        path: &std::path::Path,
        file: FileState,
        current: Option<&[u8]>,
        desired: &str,
        diff: &EntityDiff,
        digest: Option<String>,
        backup_dir: &std::path::Path,
    ) -> HaPlanReport {
        let count = |kind| diff.changes.iter().filter(|c| c.kind == kind).count();
        let (added, changed, removed) = (
            count(EntityChangeKind::Added),
            count(EntityChangeKind::Changed),
            count(EntityChangeKind::Removed),
        );
        let path_text = path.display().to_string();
        let mut sentences: Vec<String> = diff.changes.iter().map(|c| c.sentence.clone()).collect();
        if sentences.is_empty() && digest.is_some() {
            sentences.push(
                "~ no entity changes; only the file's comments or formatting change (the \
                 generated-by header and the summary footer)"
                    .to_string(),
            );
        }
        HaPlanReport {
            ok: true,
            question: digest.as_ref().map(|_| {
                format!(
                    "Write these {} entity change(s) ({added} added, {changed} changed, \
                     {removed} removed) to {path_text} and reload Home Assistant's KNX \
                     integration?",
                    diff.changes.len()
                )
            }),
            config_path: path_text,
            layout: file.layout(),
            file,
            noop: current == Some(desired.as_bytes()),
            sentences,
            changes: diff.changes.clone(),
            counts: HaCounts {
                added,
                changed,
                removed,
                unchanged: diff.unchanged,
                generated: diff.generated,
                file: diff.current,
            },
            plan_digest: digest,
            backup_dir: backup_dir.display().to_string(),
            home_assistant: None,
            plan_ttl_minutes: None,
            automations: None,
        }
    }
}

impl Report for HaPlanReport {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        if self.noop || self.plan_digest.is_none() {
            return Some(
                "Home Assistant already matches your project; nothing to write.".to_string(),
            );
        }
        let names: Vec<String> = self
            .changes
            .iter()
            .map(|c| c.name.clone())
            .take(3)
            .collect();
        let mut out = format!(
            "Home Assistant gets {} new, {} changed and {} removed entities",
            self.counts.added, self.counts.changed, self.counts.removed
        );
        if !names.is_empty() {
            out.push_str(&format!(" (among them {})", join_and(&names)));
        }
        out.push_str(". Nothing is written before the human says yes.");
        Some(out)
    }
}

/// How a reload call ended.
#[derive(Debug, Clone, Serialize)]
pub struct Reload {
    /// It succeeded.
    pub ok: bool,
    /// Why not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reload {
    /// `result` as a reload outcome.
    pub fn of(result: &Result<(), String>) -> Reload {
        Reload {
            ok: result.is_ok(),
            error: result.as_ref().err().cloned(),
        }
    }
}

/// Home Assistant after a write.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum StatusAfter {
    /// The status, and what it runs of the written text.
    Read {
        /// The status.
        #[serde(flatten)]
        status: Box<HaStatus>,
        /// What it runs.
        running: Running,
    },
    /// It could not be read.
    Unreachable {
        /// Always `false`.
        reachable: bool,
        /// Why.
        errors: Vec<String>,
    },
}

/// `knx_ha_apply`: the KNX YAML written and Home Assistant reloaded.
#[derive(Debug, Clone, Serialize)]
pub struct HaApplyReport {
    /// The write and the reload worked.
    pub ok: bool,
    /// Always `true`: the file was written.
    pub written: bool,
    /// The file.
    pub config_path: String,
    /// Where the previous file is.
    pub backup: String,
    /// One sentence per entity change.
    pub sentences: Vec<String>,
    /// The reload.
    pub reload: Reload,
    /// Home Assistant after it.
    pub status_after: StatusAfter,
    /// The outcome in words.
    pub message: String,
}

impl Report for HaApplyReport {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        Some(if self.reload.ok {
            "Home Assistant's KNX setup is updated and reloaded; the previous file is backed up."
                .to_string()
        } else {
            "Home Assistant's KNX file is updated, but the reload failed: the change takes \
             effect at the next reload or restart of Home Assistant. The previous file is \
             backed up."
                .to_string()
        })
    }
}

/// The KNX YAML file as `knx_ha_status` reports it.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FileView {
    /// The file and the generated YAML compared.
    Read {
        /// The file.
        config_path: String,
        /// Whether bussard may overwrite it.
        file: FileState,
        /// `yaml` or `not_yaml`.
        managed: &'static str,
        /// Entities generated.
        generated_entities: usize,
        /// Entities in the file.
        file_entities: usize,
        /// What Home Assistant runs of them.
        #[serde(skip_serializing_if = "Option::is_none")]
        running: Option<Running>,
    },
    /// The file could not be read.
    Unknown {
        /// `state: unknown` and the reason.
        file: UnknownFile,
    },
}

/// A file that could not be read.
#[derive(Debug, Clone, Serialize)]
pub struct UnknownFile {
    /// Always `unknown`.
    pub state: &'static str,
    /// Why.
    pub reason: String,
}

/// `knx_ha_status`: Home Assistant's status and the KNX YAML file.
#[derive(Debug, Clone, Serialize)]
pub struct HaStatusReport {
    /// The status, or why it could not be read.
    #[serde(flatten)]
    pub status: ReachOrStatus,
    /// Whether the status could be read.
    pub ok: bool,
    /// The variable the token comes from (never the token).
    pub token_env: String,
    /// The file.
    #[serde(flatten)]
    pub file: FileView,
    /// What bussard does not see.
    pub ui_entities: &'static str,
}

/// Home Assistant's status, or why it could not be read.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ReachOrStatus {
    /// As read.
    Read(Box<HaStatus>),
    /// Not read.
    Unreachable {
        /// The URL tried.
        url: String,
        /// Always `false`.
        reachable: bool,
        /// Why.
        errors: Vec<String>,
    },
}

impl Report for HaStatusReport {
    const SCHEMA: u32 = 1;
}

/// `knx_ha_automation_plan` and `_remove` without a digest: the rule and
/// what happens to it.
#[derive(Debug, Clone, Serialize)]
pub struct AutomationPlanReport {
    /// Always `true`.
    pub ok: bool,
    /// The automation id.
    pub id: String,
    /// `create`, `update`, `remove` or `unchanged`.
    pub op: String,
    /// The rule in words.
    pub sentence: Option<String>,
    /// The plan in words.
    pub sentences: Vec<String>,
    /// The automation to write.
    pub automation: Option<Value>,
    /// The same as YAML.
    pub yaml: Option<String>,
    /// The automation Home Assistant has now.
    pub previous: Option<Value>,
    /// The question.
    pub question: Option<String>,
    /// The digest the write takes.
    pub plan_digest: Option<String>,
    /// Where the previous automation is backed up.
    pub backup_dir: String,
    /// How long the digest stays valid.
    pub plan_ttl_minutes: u64,
}

impl Report for AutomationPlanReport {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        let rule = self.sentence.as_deref().unwrap_or("this rule");
        Some(match self.op.as_str() {
            "unchanged" => {
                "Home Assistant already has this automation; nothing to write.".to_string()
            }
            "remove" => "Removes this bussard automation from Home Assistant. Nothing is removed \
                         before the human says yes."
                .to_string(),
            "update" => format!(
                "Changes the Home Assistant automation to: {rule}. Nothing is written before the \
                 human says yes."
            ),
            _ => format!(
                "Home Assistant would get a new automation: {rule}. Nothing is written before \
                 the human says yes."
            ),
        })
    }
}

/// `knx_ha_automation_apply` and `_remove` with a digest.
#[derive(Debug, Clone, Serialize)]
pub struct AutomationApplyReport {
    /// The write and the reload worked.
    pub ok: bool,
    /// The automation id.
    pub id: String,
    /// `create`, `update` or `remove`.
    pub op: String,
    /// Always `true`.
    pub written: bool,
    /// The change in words.
    pub sentences: Vec<String>,
    /// Where the previous automation is (none for a new one).
    pub backup: Option<String>,
    /// The reload.
    pub reload: Reload,
    /// The outcome in words.
    pub message: String,
    /// The rule in words, for the summary.
    #[serde(skip)]
    pub rule: Option<String>,
}

impl Report for AutomationApplyReport {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        let mut out = match (self.op.as_str(), &self.rule) {
            ("remove", _) => "The automation is removed from Home Assistant.".to_string(),
            (_, Some(rule)) => format!("Home Assistant now runs the automation: {rule}."),
            _ => "Home Assistant has the automation.".to_string(),
        };
        if !self.reload.ok {
            out.push_str(" The reload failed, so it takes effect at the next reload or restart.");
        }
        Some(out)
    }
}
