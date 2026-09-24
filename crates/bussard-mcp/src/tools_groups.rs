//! The group-address planning tools (issue #103).
//!
//! These live in their own `#[tool_router]` block so the file stays independent
//! of [`crate::server`]; [`BussardMcp::new`] combines the two routers.
//!
//! `knx_scaffold_groups` is the MCP face of `bussard scaffold`: an assistant
//! drafts the room-and-function plan from a conversation with the homeowner or
//! integrator, calls this once the human has confirmed the room list, and gets
//! back the addresses it created plus the model's validation counts.

use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use bussard_model::history::{History, SnapshotReason};
use bussard_model::scaffold::{self, Plan, Scheme};
use bussard_model::{Model, Severity};

use crate::server::BussardMcp;

/// Arguments for `knx_scaffold_groups`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScaffoldGroupsArgs {
    /// The plan, as a JSON object:
    /// `{"rooms": [{"floor": "Ground floor", "room": "Kitchen",
    /// "functions": ["light", "light-dim", "blind", "heating", "socket"]}]}`.
    pub plan: Value,
    /// The addressing scheme: `floor-trade-block` (main = floor, middle = trade)
    /// or `function-floor` (main = trade, middle = floor). Defaults to the
    /// project's `lint.groups.scheme`, else `floor-trade-block`.
    #[serde(default)]
    pub scheme: Option<String>,
}

/// Parses the `scheme` argument.
fn parse_scheme(raw: &str) -> Result<Scheme, ErrorData> {
    match raw {
        "floor-trade-block" => Ok(Scheme::FloorTradeBlock),
        "function-floor" => Ok(Scheme::FunctionFloor),
        other => Err(ErrorData::invalid_params(
            format!("unknown scheme {other:?} (use floor-trade-block or function-floor)"),
            None,
        )),
    }
}

// The macro generates `pub fn groups_router()` without a doc comment, and
// attributes on the impl do not reach it; the router is documented in the
// module docs above.
#[allow(missing_docs)]
#[tool_router(router = groups_router, vis = "pub")]
impl BussardMcp {
    /// `knx_scaffold_groups`.
    #[tool(
        description = "Draft or extend the project's group-address plan from a list of rooms and \
                       the functions each room needs, writing groups.toml. Reserves the \
                       conventional block per function (five addresses for a light, ten for a \
                       blind or heating zone), names every address `<Floor> <Room> <Function> \
                       <Role>`, fills the DPTs, and leaves the remaining slots free for growth. \
                       Re-running with more rooms adds addresses and never renumbers or renames \
                       existing ones. ALWAYS confirm the floor and room list, and the functions \
                       per room, with the human before calling this: it writes a file that the \
                       whole installation is then addressed against. Returns the addresses added \
                       and the model's validation counts."
    )]
    async fn knx_scaffold_groups(
        &self,
        Parameters(args): Parameters<ScaffoldGroupsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let plan: Plan = serde_json::from_value(args.plan).map_err(|e| {
            ErrorData::invalid_params(format!("the plan is not a valid room list: {e}"), None)
        })?;

        let state = self.state();
        let scheme = match args.scheme.as_deref() {
            Some(raw) => parse_scheme(raw)?,
            None => state
                .model
                .current()
                .config
                .lint
                .as_ref()
                .and_then(|l| l.groups.as_ref())
                .and_then(|g| g.scheme)
                .unwrap_or(Scheme::FloorTradeBlock),
        };

        // Snapshot before writing, like every other MCP model edit, so the
        // scaffold can be undone (issue #110). An empty directory has nothing
        // to keep; a failed snapshot refuses the write.
        let history = History::open(&state.dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_scaffold_groups")
                .with_result("before scaffolding group addresses");
            Some(history.snapshot(reason).map_err(|e| {
                ErrorData::internal_error(
                    format!(
                        "refusing to scaffold: the history snapshot could not be written ({e})"
                    ),
                    None,
                )
            })?)
        } else {
            None
        };

        let groups_path = state.dir.join("groups.toml");
        let report = scaffold::scaffold_file(&groups_path, &plan, scheme)
            .map_err(|e| ErrorData::internal_error(format!("scaffolding failed: {e}"), None))?;

        let config_path = state.dir.join("bussard.toml");
        let lint_written = scaffold::ensure_lint_config(&config_path, scheme, &report.trades_used)
            .map_err(|e| {
                ErrorData::internal_error(format!("writing the lint config failed: {e}"), None)
            })?;

        let (errors, warnings) = match Model::load(&state.dir) {
            Ok(model) => {
                let diags = bussard_model::validate_in_dir(&model, &state.dir);
                (
                    diags
                        .iter()
                        .filter(|d| d.severity == Severity::Error)
                        .count(),
                    diags
                        .iter()
                        .filter(|d| d.severity == Severity::Warning)
                        .count(),
                )
            }
            Err(_) => (0, 0),
        };

        let added: Vec<Value> = report
            .added
            .iter()
            .map(|a| {
                json!({
                    "address": a.address.to_string(),
                    "name": a.name,
                    "dpt": a.dpt.to_string(),
                })
            })
            .collect();

        Ok(CallToolResult::structured(json!({
            "scheme": scheme.as_str(),
            "file": groups_path.display().to_string(),
            "added_count": added.len(),
            "added": added,
            "lint_config_written": lint_written,
            "snapshot": snapshot,
            "validation": { "errors": errors, "warnings": warnings },
        })))
    }
}
