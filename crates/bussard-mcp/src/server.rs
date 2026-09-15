//! The rmcp server handler and its tools.
//!
//! [`BussardMcp`] holds the shared state and exposes the read-only tools (eight
//! by default, seven in `--passive` mode) plus, with `--allow-writes`, the
//! `knx_write_group` write tool (nine total) over the Model Context Protocol.
//! Each `#[tool]`
//! method is a thin adapter: it parses arguments, calls the pure logic in
//! [`crate::tools`], and boxes the JSON in a `CallToolResult::structured`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bussard_model::{Dpt, GroupAddress, IndividualAddress};
use bussard_monitor::{ApciKind, CaptureStore, Filter, QueryFilter};
use bussard_transport::cemi::CemiFrame;
use rmcp::ErrorData;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerInfo};
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::state::{ConnState, READ_RESPONSE_TIMEOUT, SharedState};
use crate::tools;

/// The bussard MCP server handler.
///
/// Cloneable: rmcp clones the handler per request, but the heavy state lives
/// behind an `Arc`, so clones are cheap and share one ring + model.
#[derive(Clone)]
pub struct BussardMcp {
    state: Arc<SharedState>,
    tool_router: ToolRouter<BussardMcp>,
}

impl BussardMcp {
    /// Builds the server over `state`. The instance router starts with every
    /// tool registered, then unregisters the ones this mode must not expose:
    /// `knx_read_group` in passive mode, and `knx_write_group` unless
    /// `--allow-writes` is set (and never in passive mode).
    pub fn new(state: Arc<SharedState>) -> Self {
        let mut tool_router = Self::tool_router();
        if state.passive {
            tool_router.remove_route("knx_read_group");
        }
        if !state.allow_writes || state.passive {
            tool_router.remove_route("knx_write_group");
        }
        BussardMcp { state, tool_router }
    }

    /// The shared state (for tests and the runner).
    pub fn state(&self) -> &Arc<SharedState> {
        &self.state
    }
}

/// Arguments for `knx_model_lookup`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LookupArgs {
    /// Case-insensitive substring to search for across GA names/addresses,
    /// device names/individual addresses, room names and com-object names.
    pub query: String,
    /// Maximum matches to return per category (default 50).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for tools that take a single group address.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GaArgs {
    /// A 3-level group address like `"3/2/0"`.
    pub ga: String,
}

/// Arguments for `knx_write_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteArgs {
    /// A 3-level group address like `"3/0/4"`.
    pub ga: String,
    /// The value to write, in human form: `on`/`off`, `up`/`down`, a number, a
    /// percentage like `75%`, a temperature like `21.5`, an HVAC mode name, etc.
    /// Interpreted according to the resolved DPT.
    pub value: String,
    /// Override the DPT to encode as (e.g. `"1.001"`). Defaults to the GA's DPT
    /// from `groups.yaml`.
    #[serde(default)]
    pub dpt: Option<String>,
}

/// Arguments for `knx_get_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeviceArgs {
    /// An individual (physical) address like `"1.1.4"`.
    pub address: String,
}

/// Arguments for `knx_recent_telegrams`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RecentArgs {
    /// Maximum telegrams to return (default 50).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Restrict to a group address or GA prefix (`"3/2/0"`, `"3/"`).
    #[serde(default)]
    pub ga: Option<String>,
    /// Restrict to a source individual address (`"1.1.30"`).
    #[serde(default)]
    pub source: Option<String>,
    /// Only telegrams at or after this RFC3339 timestamp.
    #[serde(default)]
    pub since: Option<String>,
}

/// Arguments for `knx_wait_for_telegram`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct WaitArgs {
    /// Restrict to a group address or GA prefix.
    #[serde(default)]
    pub ga: Option<String>,
    /// Restrict to a source individual address.
    #[serde(default)]
    pub source: Option<String>,
    /// How long to wait, in seconds (max 300).
    pub timeout_seconds: u32,
}

/// Turns a JSON value into a structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A bad-argument error (invalid address, etc.).
fn invalid(msg: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(msg.into(), None)
}

/// Builds a combined filter from optional ga + source terms.
fn build_filter(ga: Option<&str>, source: Option<&str>) -> Result<Filter, ErrorData> {
    let mut terms: Vec<String> = Vec::new();
    if let Some(g) = ga {
        terms.push(g.to_string());
    }
    if let Some(s) = source {
        terms.push(s.to_string());
    }
    if terms.is_empty() {
        return Ok(Filter::default());
    }
    Filter::parse(&terms.join(",")).map_err(|e| invalid(e.to_string()))
}

#[tool_router]
impl BussardMcp {
    /// `knx_project_summary`.
    #[tool(
        description = "Summarize the loaded KNX project: name, counts of devices/group-addresses/links, floors and rooms with device counts, group-address main-range names, live bus connection status, and validation error/warning counts. Call this first to orient yourself."
    )]
    async fn knx_project_summary(&self) -> Result<CallToolResult, ErrorData> {
        ok(tools::project_summary(&self.state.model, &self.state.bus))
    }

    /// `knx_model_lookup`.
    #[tool(
        description = "Search the KNX model by a case-insensitive substring. Matches group-address names and addresses, device names and individual addresses, room names, and com-object names. Returns matches grouped by kind (groups, devices, objects) with enough context to act on them."
    )]
    async fn knx_model_lookup(
        &self,
        Parameters(args): Parameters<LookupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = args.limit.unwrap_or(50).clamp(1, 500) as usize;
        ok(tools::model_lookup(&self.state.model, &args.query, limit))
    }

    /// `knx_get_group`.
    #[tool(
        description = "Look up a single group address: its definition (name, DPT, description), every link that sends to or listens on it (device IA/name, com-object number/name, send|listen), and the last telegram seen on it from the live buffer, if any."
    )]
    async fn knx_get_group(
        &self,
        Parameters(args): Parameters<GaArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;
        ok(tools::get_group(&self.state.model, &self.state.ring, ga))
    }

    /// `knx_get_device`.
    #[tool(
        description = "Get the full definition of one device by its individual address: identity, product, location, channels and generated com-object table, plus every link (com-object -> group addresses) on it."
    )]
    async fn knx_get_device(
        &self,
        Parameters(args): Parameters<DeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = args
            .address
            .parse()
            .map_err(|_| invalid(format!("invalid individual address {:?}", args.address)))?;
        ok(tools::get_device(&self.state.model, ia))
    }

    /// `knx_recent_telegrams`.
    #[tool(
        description = "Return recent decoded telegrams from the live buffer, oldest first and newest last. Optionally filter by group address (or GA prefix), source individual address, and an RFC3339 `since` cutoff. If a capture database is configured and the requested window predates the in-memory buffer, older telegrams are read from it too."
    )]
    async fn knx_recent_telegrams(
        &self,
        Parameters(args): Parameters<RecentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = args.limit.unwrap_or(50).clamp(1, 1000) as usize;
        let since = match &args.since {
            Some(s) => Some(parse_rfc3339(s)?),
            None => None,
        };
        let filter = build_filter(args.ga.as_deref(), args.source.as_deref())?;

        let mut telegrams = tools::recent_telegrams(&self.state.ring, &filter, since, limit);

        // Fall back to the capture store when the ring window is exceeded: if we
        // got fewer than asked and a DB is configured, top up from it.
        if telegrams.len() < limit {
            if let Some(db) = &self.state.capture_db {
                if let Some(extra) = self.query_capture(db, &args, since, limit - telegrams.len()) {
                    // Prepend older store rows before the newer ring rows.
                    let mut combined = extra;
                    combined.extend(telegrams);
                    // Keep the newest `limit`, chronological.
                    if combined.len() > limit {
                        let start = combined.len() - limit;
                        combined.drain(0..start);
                    }
                    telegrams = combined;
                }
            }
        }

        let items: Vec<Value> = telegrams.iter().map(tools::telegram_json).collect();
        ok(json!({
            "count": items.len(),
            "telegrams": items,
        }))
    }

    /// `knx_wait_for_telegram`.
    #[tool(
        description = "Block until the next telegram matching the given group address and/or source arrives, or the timeout elapses. This is the 'ask the human to press the button now, then call this' workflow: tell the user which switch to press, then call this and read the resulting telegram. A timeout is a normal result (not an error)."
    )]
    async fn knx_wait_for_telegram(
        &self,
        Parameters(args): Parameters<WaitArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let timeout = Duration::from_secs(args.timeout_seconds.clamp(1, 300) as u64);
        let filter = build_filter(args.ga.as_deref(), args.source.as_deref())?;

        match self.state.ring.wait_for(&filter, timeout).await {
            Some(t) => ok(json!({
                "matched": true,
                "telegram": tools::telegram_json(&t),
            })),
            None => ok(json!({
                "matched": false,
                "timed_out": true,
                "waited_seconds": timeout.as_secs(),
            })),
        }
    }

    /// `knx_validate`.
    #[tool(
        description = "Run the bussard model validator and return every diagnostic as JSON (code, severity, message, location) plus counts of errors/warnings/infos. Use this to check whether the YAML model is internally consistent."
    )]
    async fn knx_validate(&self) -> Result<CallToolResult, ErrorData> {
        ok(tools::validate_result(&self.state.model))
    }

    /// `knx_read_group` (omitted in passive mode).
    #[tool(
        description = "Transmit a GroupValueRead on the bus for a group address and return the decoded response value. Rate-limited (minimum 250ms between reads). Only available when the server is NOT in passive mode. Use sparingly: this actively sends on the KNX bus."
    )]
    async fn knx_read_group(
        &self,
        Parameters(args): Parameters<GaArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Passive mode: the tool is unregistered, but guard anyway.
        let Some(outbound) = &self.state.outbound else {
            return ok(json!({
                "ga": args.ga,
                "ok": false,
                "reason": "server is in passive mode; bus reads are disabled",
            }));
        };

        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        if self.state.bus.state() != ConnState::Connected {
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus is not connected",
                "bus": self.state.bus.to_json(),
            }));
        }

        // Rate limit + concurrency cap. Hold the permit across the whole read.
        let _permit = self.state.read_limiter.acquire().await;

        // Subscribe to the ring *before* sending so we cannot miss the response.
        let filter = Filter::parse(&ga.to_string()).map_err(|e| invalid(e.to_string()))?;
        let ring = self.state.ring.clone();
        let wait = tokio::spawn(async move { ring.wait_for(&filter, READ_RESPONSE_TIMEOUT).await });

        // Send the GroupValueRead on the shared connection.
        let frame = CemiFrame::group_read(ga, self.state.source_ia);
        if outbound.send(frame).is_err() {
            wait.abort();
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus connection is gone",
            }));
        }

        // Await the matching response (a write or response both carry a value).
        let response = wait.await.ok().flatten();
        match response {
            Some(t)
                if matches!(t.apci, ApciKind::Response | ApciKind::Write)
                    && !t.payload.is_empty() =>
            {
                let dpt = self.state.model.groups.groups.get(&ga).and_then(|g| g.dpt);
                let (display, typed) = tools::decode_for_dpt(dpt, &t.payload);
                ok(json!({
                    "ga": ga.to_string(),
                    "ok": true,
                    "value": display,
                    "typed": typed,
                    "dpt": dpt.map(|d| d.to_string()),
                    "telegram": tools::telegram_json(&t),
                }))
            }
            Some(t) => ok(json!({
                "ga": ga.to_string(),
                "ok": true,
                "telegram": tools::telegram_json(&t),
            })),
            None => ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "timed_out": true,
                "reason": "no response within timeout",
            })),
        }
    }

    /// `knx_write_group` (registered only with `--allow-writes`, never in passive
    /// mode).
    #[tool(
        description = "Write a value to a KNX group address (GroupValueWrite) on the PHYSICAL bus. \
        This has real-world effects: lights toggle, blinds and actuators MOVE, setpoints change. \
        Only available when the server was started with --allow-writes. The value is human-typed \
        (e.g. on/off, up/down, 75%, 21.5, a scene number, or an HVAC mode name) and is interpreted \
        against the group address's DPT (override with `dpt`). Rate-limited (minimum 250ms between \
        bus operations). Protected group addresses (safety-critical objects such as a wind alarm or \
        central functions) are REFUSED outright — there is no override via MCP. When you are \
        uncertain whether a write is safe or intended, ASK THE HUMAN before calling this tool."
    )]
    async fn knx_write_group(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Writes disabled: the tool is unregistered, but guard anyway.
        let Some(outbound) = &self.state.outbound else {
            return ok(json!({
                "ga": args.ga,
                "ok": false,
                "reason": "bus writes are disabled on this server",
            }));
        };

        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        // Hard-refuse protected GAs. There is no override via MCP.
        if let Some(group) = self.state.model.groups.groups.get(&ga) {
            if group.protected {
                return ok(json!({
                    "ga": ga.to_string(),
                    "ok": false,
                    "refused": true,
                    "reason": format!(
                        "GA {ga} ({:?}) is protected (safety-critical); writes are refused via MCP",
                        group.name
                    ),
                }));
            }
        }

        // Resolve the DPT: explicit `dpt` wins, else the GA's DPT.
        let dpt: Dpt = match &args.dpt {
            Some(s) => s
                .parse()
                .map_err(|e| invalid(format!("invalid dpt {s:?}: {e}")))?,
            None => match self.state.model.groups.groups.get(&ga).and_then(|g| g.dpt) {
                Some(d) => d,
                None => {
                    return ok(json!({
                        "ga": ga.to_string(),
                        "ok": false,
                        "reason": format!(
                            "GA {ga} has no DPT in the model; pass `dpt` to write it"
                        ),
                    }));
                }
            },
        };

        // Parse + encode the value. Parse/encode errors are structured refusals.
        let typed = match bussard_model::parse_value(&dpt, &args.value) {
            Ok(v) => v,
            Err(e) => {
                return ok(json!({
                    "ga": ga.to_string(),
                    "ok": false,
                    "reason": e.to_string(),
                }));
            }
        };
        let payload = match bussard_model::encode(&dpt, &typed) {
            Ok(p) => p,
            Err(e) => {
                return ok(json!({
                    "ga": ga.to_string(),
                    "ok": false,
                    "reason": e.to_string(),
                }));
            }
        };

        if self.state.bus.state() != ConnState::Connected {
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus is not connected",
                "bus": self.state.bus.to_json(),
            }));
        }

        // Share the read rate limiter (spacing + concurrency cap) with writes.
        let _permit = self.state.read_limiter.acquire().await;

        // Send the GroupValueWrite on the shared connection.
        let frame = CemiFrame::group_write(ga, self.state.source_ia, &payload);
        if outbound.send(frame).is_err() {
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus connection is gone",
            }));
        }

        let name = self
            .state
            .model
            .groups
            .groups
            .get(&ga)
            .map(|g| g.name.clone());

        ok(json!({
            "ga": ga.to_string(),
            "ok": true,
            "written": {
                "address": ga.to_string(),
                "name": name,
                "value": typed.to_string(),
                "dpt": dpt.to_string(),
            },
        }))
    }
}

impl BussardMcp {
    /// Queries the capture store for older telegrams to top up the ring window.
    fn query_capture(
        &self,
        db: &std::path::Path,
        args: &RecentArgs,
        since: Option<SystemTime>,
        limit: usize,
    ) -> Option<Vec<bussard_monitor::DecodedTelegram>> {
        let store = CaptureStore::open(db).ok()?;
        let ga = args.ga.as_deref().and_then(|s| s.parse().ok());
        let source = args.source.as_deref().and_then(|s| s.parse().ok());
        let qf = QueryFilter {
            ga,
            source,
            since,
            limit: Some(limit),
        };
        let rows = store.query(&qf).ok()?;
        // Re-decode each row against the current model; skip undecodable rows.
        let mut out: Vec<bussard_monitor::DecodedTelegram> = rows
            .iter()
            .filter_map(|r| r.redecode(Some(&self.state.model)).ok())
            .collect();
        // Store rows are newest-first; make them chronological.
        out.reverse();
        Some(out)
    }
}

/// Parses an RFC3339 timestamp, mapping failures to an invalid-params error.
///
/// `timefmt::from_rfc3339` is lenient (it returns the epoch on a bad string), so
/// we reject an epoch result that did not come from an actual `1970` timestamp.
fn parse_rfc3339(s: &str) -> Result<SystemTime, ErrorData> {
    let ts = bussard_monitor::timefmt::from_rfc3339(s);
    if ts == SystemTime::UNIX_EPOCH && !s.starts_with("1970") {
        return Err(invalid(format!(
            "invalid RFC3339 timestamp {s:?} (expected e.g. 2026-09-15T10:00:00Z)"
        )));
    }
    Ok(ts)
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BussardMcp {
    fn get_info(&self) -> ServerInfo {
        // Identify as bussard (not the SDK default "rmcp") so clients show the
        // right name/version.
        let mut server_info = rmcp::model::Implementation::from_build_env();
        server_info.name = "bussard".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        server_info.title = Some("bussard KNX MCP server".to_string());

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(
                "bussard: read-only KNX introspection over MCP. Loads a KNX-as-code model and \
                 observes the bus. Start with knx_project_summary, then knx_model_lookup / \
                 knx_get_group / knx_get_device to explore, knx_recent_telegrams and \
                 knx_wait_for_telegram to observe live traffic (the latter enables 'press the \
                 button now' debugging), knx_validate to check the model, and knx_read_group to \
                 actively read a value (unless the server is in passive mode). When started with \
                 --allow-writes the knx_write_group tool is also available; it writes to the \
                 physical bus (actuators move) and refuses protected group addresses — prefer \
                 asking the human when a write's intent or safety is unclear.",
            )
    }
}
