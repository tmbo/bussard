//! The group-address planning tools (issue #103).
//!
//! These live in their own `#[tool_router]` block so the file stays independent
//! of [`crate::server`]; [`BussardMcp::new`] combines the two routers.
//!
//! `knx_reserve_groups` is the MCP face of `bussard groups reserve`: one room,
//! the functions it needs, the conventional block appended to `groups.toml`.
//! `knx_scaffold_groups` takes several rooms at once as JSON (there is no plan
//! file): an assistant drafts the room list from a conversation with the
//! homeowner or integrator, calls it once the human has confirmed the list, and
//! gets back the addresses it created plus the model's validation counts.

use crate::args::Parameters;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use bussard_model::history::{History, SnapshotReason};
use bussard_model::scaffold::{self, Plan, PlanRoom, Scheme};
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

/// Arguments for `knx_reserve_groups`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReserveGroupsArgs {
    /// The room, floor first, as one string: `"EG Küche"` (the floor is the
    /// first word, the room the rest).
    pub room: String,
    /// The functions the room needs: `light`, `light-dim`, `blind`, `heating`,
    /// `socket`.
    pub functions: Vec<String>,
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
    // `knx_scaffold_groups`.
    #[doc = include_str!("../guidance/tools/knx_scaffold_groups.md")]
    #[tool]
    async fn knx_scaffold_groups(
        &self,
        Parameters(args): Parameters<ScaffoldGroupsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let plan: Plan = serde_json::from_value(args.plan).map_err(|e| {
            ErrorData::invalid_params(format!("the plan is not a valid room list: {e}"), None)
        })?;
        let scheme = args.scheme.as_deref().map(parse_scheme).transpose()?;
        self.reserve(plan, scheme, "knx_scaffold_groups")
    }

    // `knx_reserve_groups`.
    #[doc = include_str!("../guidance/tools/knx_reserve_groups.md")]
    #[tool]
    async fn knx_reserve_groups(
        &self,
        Parameters(args): Parameters<ReserveGroupsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let room = PlanRoom::from_label(&args.room, &args.functions)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        self.reserve(Plan { rooms: vec![room] }, None, "knx_reserve_groups")
    }
}

impl BussardMcp {
    /// The shared body of the two reservation tools: snapshot, scaffold into
    /// `groups.toml`, record the scheme in `bussard.toml`, validate.
    fn reserve(
        &self,
        plan: Plan,
        scheme: Option<Scheme>,
        tool: &str,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let scheme = scheme.unwrap_or_else(|| {
            state
                .model
                .current()
                .config
                .lint
                .as_ref()
                .and_then(|l| l.groups.as_ref())
                .and_then(|g| g.scheme)
                .unwrap_or(Scheme::FloorTradeBlock)
        });

        // Snapshot before writing, like every other MCP model edit, so the
        // scaffold can be undone (issue #110). An empty directory has nothing
        // to keep; a failed snapshot refuses the write.
        let history = History::open(&state.dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new(format!("mcp {tool}"))
                .with_result("before reserving group addresses");
            Some(history.snapshot(reason).map_err(|e| {
                ErrorData::internal_error(
                    format!("refusing to reserve: the history snapshot could not be written ({e})"),
                    None,
                )
            })?)
        } else {
            None
        };

        let groups_path = state.dir.join("groups.toml");
        let report = scaffold::scaffold_file(&groups_path, &plan, scheme)
            .map_err(|e| ErrorData::internal_error(format!("reserving failed: {e}"), None))?;

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
