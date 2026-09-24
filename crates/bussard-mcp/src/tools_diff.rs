//! Bundle export and project diff tools (issues #111, #99).
//!
//! `knx_export_bundle` writes the model and its history as one `.bussard` file,
//! the thing a homeowner hands an integrator or keeps as a backup.
//! `knx_diff_project` explains, as plain sentences, what an integrator's new
//! `.knxproj` or bundle would change in the working model before the human
//! imports it.
//!
//! Both only read the model directory. The export writes one file outside the
//! model files (plus the `.bussard/last_export.json` record), and neither
//! touches the bus, so both are available in every tier, `--passive` and
//! `--no-model-edits` included.

use std::path::{Path, PathBuf};

use bussard_model::Model;
use bussard_model::bundle::{self, Bundle, ExportOptions};
use bussard_model::change::{describe, name_parameters};
use bussard_model::param_model::ProductModels;
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::BussardMcp;

/// The tools this module registers, present in every tier.
pub const DIFF_TOOLS: [&str; 2] = ["knx_export_bundle", "knx_diff_project"];

/// Arguments for `knx_export_bundle`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ExportBundleArgs {
    /// Where to write the `.bussard` file. Defaults to next to the model
    /// directory, named after it and today's date (e.g. `knx-2026-09-23.bussard`).
    #[serde(default)]
    pub path: Option<String>,
    /// Include the `.bussard/history` snapshots (default true).
    #[serde(default)]
    pub include_history: Option<bool>,
}

/// Arguments for `knx_diff_project`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffProjectArgs {
    /// The `.knxproj` or `.bussard` file to compare the working model against.
    /// A password-protected `.knxproj` reads its password from the server's
    /// `BUSSARD_PROJECT_PASSWORD` environment variable.
    pub path: String,
}

// `pub(crate)`: the router is combined in `BussardMcp::new` and needs no public
// face (a `pub` macro-generated fn could not carry the doc comment the crate
// requires).
#[tool_router(router = diff_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_export_bundle`.
    #[tool(
        description = "Write the whole model (bussard.toml, groups.toml, links.yaml, devices/) \
        and its history snapshots as ONE .bussard file: the handover file for an integrator, or \
        the owner's backup. It never contains vendor product data (models/, vendor/), captures, \
        keyrings, .knxproj/.knxprod files or .env. Returns the path and the manifest (counts, \
        SHA-256, what was excluded). Reads the model, writes only the bundle; touches no device. \
        Suggest it after the first working weekend and after changes the human wants to keep."
    )]
    async fn knx_export_bundle(
        &self,
        Parameters(args): Parameters<ExportBundleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let dir = self.state().dir.clone();
        let out = args
            .path
            .map(PathBuf::from)
            .unwrap_or_else(|| bundle::default_bundle_path(&dir));
        let options = ExportOptions {
            include_history: args.include_history.unwrap_or(true),
        };
        match bundle::export(&dir, &out, options) {
            Ok(manifest) => ok(json!({
                "ok": true,
                "path": out.display().to_string(),
                "manifest": manifest,
            })),
            Err(err) => refusal(format!("the export failed: {err}")),
        }
    }

    /// `knx_diff_project`.
    #[tool(
        description = "Explain what a received ETS export (.knxproj) or bussard bundle (.bussard) \
        would change compared with the working model, as plain sentences such as \"Group address \
        1/0/1 is now called \\\"Kitchen ceiling\\\" (was \\\"Light Kitchen\\\").\" A renamed \
        group address is one rename, not a removal and an addition. QUOTE THESE SENTENCES TO THE \
        HUMAN BEFORE SHE IMPORTS the file (`bussard import <file>`); a change marked \
        touches_protected concerns a safety-critical group address and needs her explicit word. \
        At import, hand-edited names, rooms and descriptions that differ stay local unless she \
        chooses --theirs. Read-only: writes nothing, touches no device."
    )]
    async fn knx_diff_project(
        &self,
        Parameters(args): Parameters<DiffProjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let dir = self.state().dir.clone();
        let path = PathBuf::from(&args.path);
        let result = tokio::task::spawn_blocking(move || diff_against(&dir, &path)).await;
        match result {
            Ok(Ok(value)) => ok(value),
            Ok(Err(reason)) => refusal(reason),
            Err(err) => refusal(format!("the diff did not finish: {err}")),
        }
    }
}

/// Diffs the working model in `dir` against the project or bundle at `path`.
fn diff_against(dir: &Path, path: &Path) -> Result<Value, String> {
    let working =
        Model::load(dir).map_err(|err| format!("the working model does not load: {err}"))?;
    let (other, source) = load_other(path)?;
    let mut changes = describe(&working, &other);
    name_parameters(&mut changes, [&other, &working], &ProductModels::load(dir));
    let sentences: Vec<&str> = changes
        .changes
        .iter()
        .map(|c| c.sentence.as_str())
        .collect();
    Ok(json!({
        "ok": true,
        "from": "the working model",
        "to": path.display().to_string(),
        "source": source,
        "count": changes.len(),
        "summary": if changes.is_empty() {
            "no differences".to_string()
        } else {
            changes.summary()
        },
        "touches_protected": changes.touches_protected(),
        "sentences": sentences,
        "changes": changes.changes,
    }))
}

/// Loads a `.bussard` bundle or a `.knxproj` into memory, with a short
/// description of what it was.
fn load_other(path: &Path) -> Result<(Model, Value), String> {
    if bundle::is_bundle_path(path) {
        let bundle = Bundle::read(path).map_err(|err| err.to_string())?;
        let model = bundle.model().map_err(|err| err.to_string())?;
        return Ok((
            model,
            json!({ "kind": "bundle", "manifest": bundle.manifest }),
        ));
    }
    let password = std::env::var("BUSSARD_PROJECT_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    match bussard_project::import(path, password.as_deref()) {
        Ok(model) => Ok((model, json!({ "kind": "knxproj" }))),
        Err(bussard_project::ImportError::PasswordRequired) => Err(format!(
            "{} is password-protected; the server needs BUSSARD_PROJECT_PASSWORD set (ask the \
             human; never guess a password)",
            path.display()
        )),
        Err(err) => Err(format!("{} could not be read: {err}", path.display())),
    }
}

/// A structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result the caller reads out.
fn refusal(reason: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    ok(json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
    }))
}
