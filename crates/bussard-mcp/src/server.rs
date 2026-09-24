//! The rmcp server handler and its tools.
//!
//! [`BussardMcp`] holds the shared state and exposes the read tools (the
//! bus-touching `knx_read_group` and `knx_describe_device` are omitted in
//! `--passive` mode) plus, with `--allow-writes`, the `knx_write_group` and
//! `knx_run_tests` write tools over the Model Context Protocol. The per-tier
//! tool counts are listed on [`crate::tool_names`]. The model and history tools
//! live in [`crate::tools_model`], the group-planning tools in
//! [`crate::tools_groups`], the learn and acceptance tools in
//! [`crate::tools_learn`], and `knx_audit` in [`crate::tools_audit`]; each is
//! its own `#[tool_router]` block, combined in [`BussardMcp::new`].
//! Each `#[tool]`
//! method is a thin adapter: it parses arguments, calls the pure logic in
//! [`crate::tools`], and boxes the JSON in a `CallToolResult::structured`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bussard_bus::ops;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_monitor::{CaptureStore, Filter, QueryFilter};
use bussard_service::describe::walk_objects;
use bussard_service::secure::ToolKeySource;
use bussard_service::{
    DptOverridePolicy, L4Options, ServiceError, SourcePolicy, WriteCheck, WriteRefusal, WriteValue,
    group_key_for, prepare_group_write,
};
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
        // The bus tools, the model-edit tools, the group-planning tools, the
        // learn/acceptance tools, the audit tool and the bundle/diff tools live
        // in separate `#[tool_router]` impl blocks (see `crate::tools_model`,
        // `crate::tools_groups`, `crate::tools_learn`, `crate::tools_audit`
        // and `crate::tools_diff`); rmcp's `ToolRouter` implements `Add`, so
        // they combine into one instance router, then get trimmed for this tier.
        let mut tool_router = Self::tool_router()
            + Self::model_router()
            + Self::groups_router()
            + Self::learn_router()
            + Self::audit_router()
            + Self::diff_router()
            + Self::program_router();
        if state.no_model_edits {
            for name in crate::tools_model::MODEL_EDIT_TOOLS {
                tool_router.remove_route(name);
            }
        }
        if state.passive {
            tool_router.remove_route("knx_read_group");
            // Introspection actively transmits management traffic, so it is a
            // bus-touching tool: unavailable in passive (observe-only) mode.
            tool_router.remove_route("knx_describe_device");
        }
        if !state.allow_writes || state.passive {
            tool_router.remove_route("knx_write_group");
            // Running the acceptance suite writes to the bus, so it follows the
            // write tier. `knx_infer_group` stays: it only reads the ring.
            tool_router.remove_route("knx_run_tests");
        }
        if state.programming.is_none() || state.passive {
            // The programming tier writes device tables: registered only with
            // `--allow-programming`, never in passive mode (issue #118).
            for name in crate::tools_program::PROGRAMMING_TOOLS {
                tool_router.remove_route(name);
            }
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
    /// from `groups.toml`.
    #[serde(default)]
    pub dpt: Option<String>,
}

/// Arguments for `knx_get_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeviceArgs {
    /// An individual (physical) address like `"1.1.4"`.
    pub address: String,
}

/// Arguments for `knx_describe_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeArgs {
    /// The individual (physical) address of the device to introspect, e.g.
    /// `"1.1.4"`.
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
        ok(tools::project_summary(
            &self.state.model.current(),
            &self.state.bus,
        ))
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
        ok(tools::model_lookup(
            &self.state.model.current(),
            &args.query,
            limit,
        ))
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
        ok(tools::get_group(
            &self.state.model.current(),
            &self.state.ring,
            ga,
        ))
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
        ok(tools::get_device(&self.state.model.current(), ia))
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
        // got fewer than asked and a DB is configured, top up from it with OLDER
        // rows. The DB query runs on a blocking thread (rusqlite is synchronous)
        // and its rows are re-filtered against the same `Filter` (so a GA prefix
        // like "3/" is honoured, not silently dropped) and de-duplicated against
        // the ring rows we already have.
        if telegrams.len() < limit
            && let Some(db) = self.state.capture_db.clone()
        {
            let want = limit - telegrams.len();
            let state = self.state.clone();
            let filter = filter.clone();
            // Push only *exact* terms into SQL; a GA prefix stays out of the
            // query and is enforced by the `Filter` re-check post-decode.
            let exact_ga = args.ga.as_deref().and_then(|s| s.parse().ok());
            let exact_source = args.source.as_deref().and_then(|s| s.parse().ok());
            let extra = tokio::task::spawn_blocking(move || {
                query_capture(&state, &db, &filter, exact_ga, exact_source, since, want)
            })
            .await
            .ok()
            .flatten();

            if let Some(extra) = extra {
                // Drop any store row that duplicates a ring row (same
                // instant/source/dest/payload): the ring is the source of
                // truth for the recent window and the two can overlap.
                let seen: std::collections::HashSet<TelegramKey> =
                    telegrams.iter().map(telegram_key).collect();
                let mut combined: Vec<_> = extra
                    .into_iter()
                    .filter(|t| !seen.contains(&telegram_key(t)))
                    .collect();
                // Prepend older store rows before the newer ring rows.
                combined.extend(telegrams);
                // Keep the newest `limit`, chronological.
                if combined.len() > limit {
                    let start = combined.len() - limit;
                    combined.drain(0..start);
                }
                telegrams = combined;
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
        description = "Run the bussard model validator and return every diagnostic as JSON (code, severity, message, location) plus counts of errors/warnings/infos. Use this to check whether the model (bussard.toml, groups.toml, devices/*.toml, bussard.lock) is internally consistent."
    )]
    async fn knx_validate(&self) -> Result<CallToolResult, ErrorData> {
        ok(tools::validate_result(&self.state.model.current()))
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
        if self.state.passive {
            return ok(json!({
                "ga": args.ga,
                "ok": false,
                "reason": "server is in passive mode; bus reads are disabled",
            }));
        }

        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        // KNX Data Secure (issue #172): a secured GA (a group key in the
        // server's `--keyring`, or `secure: true` in the model) is read with a
        // secured GroupValueRead; a secured GA without a key is refused.
        let model = self.state.model.current();
        let keys = match crate::secure_group::group_keys(self.state.keyring.as_deref()) {
            Ok(keys) => keys,
            Err(reason) => {
                return ok(json!({ "ga": ga.to_string(), "ok": false, "reason": reason }));
            }
        };
        let key = match group_key_for(Some(&model), ga, keys.as_deref()) {
            Ok(key) => key,
            Err(err) => {
                return ok(json!({
                    "ga": ga.to_string(),
                    "ok": false,
                    "refused": true,
                    "reason": crate::secure_group::no_key_reason(&err),
                }));
            }
        };

        let Some(service) = self.state.bus.service() else {
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus is not wired",
                "bus": self.state.bus.to_json(),
            }));
        };

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

        // The shared read implementation: subscribe, send (completion-tracked),
        // skip the L_Data.con echo, decode against the GA's DPT (#32, #30).
        let dpt = model.groups.groups.get(&ga).and_then(|g| g.dpt);
        match service
            .read_group(ga, dpt, key.as_ref(), READ_RESPONSE_TIMEOUT)
            .await
        {
            Ok(Some(read)) => {
                let outcome = read.outcome;
                let (display, typed) = match &outcome.value {
                    Some(v) => (Some(v.to_string()), tools::typed_value_json(v)),
                    None => (None, Value::Null),
                };
                ok(json!({
                    "ga": ga.to_string(),
                    "ok": true,
                    "value": display,
                    "typed": typed,
                    "dpt": outcome.dpt.map(|d| d.to_string()),
                    "source": outcome.source.to_string(),
                    "secured": read.secured,
                }))
            }
            Ok(None) => ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "timed_out": true,
                "secured": key.is_some(),
                "reason": if key.is_some() {
                    "no verified secured response within timeout"
                } else {
                    "no response within timeout"
                },
            })),
            Err(err) => ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": format!("bus send failed: {err}"),
            })),
        }
    }

    /// `knx_describe_device` (omitted in passive mode).
    #[tool(
        description = "Introspect a physical device over the KNX bus (issue #72): enumerate its \
        interface objects and, for each, every property's DESCRIPTION — PID (with a name when \
        known), data type, element count and read/write access levels. This is READ-ONLY on the \
        bus (it sends A_DeviceDescriptor_Read, A_PropertyValue_Read for object discovery, and \
        A_PropertyDescription_Read; it never writes). Use it to describe an unknown device's \
        property set. Rate-limited and only available when the server is NOT in passive mode, \
        since it actively transmits management traffic on the bus."
    )]
    async fn knx_describe_device(
        &self,
        Parameters(args): Parameters<DescribeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Passive mode: the tool is unregistered, but guard anyway.
        if self.state.passive {
            return ok(json!({
                "address": args.address,
                "ok": false,
                "reason": "server is in passive mode; bus management traffic is disabled",
            }));
        }

        let target: IndividualAddress = args
            .address
            .parse()
            .map_err(|_| invalid(format!("invalid individual address {:?}", args.address)))?;

        let Some(service) = self.state.bus.service() else {
            return ok(json!({
                "address": target.to_string(),
                "ok": false,
                "reason": "bus is not wired",
                "bus": self.state.bus.to_json(),
            }));
        };
        if self.state.bus.state() != ConnState::Connected {
            return ok(json!({
                "address": target.to_string(),
                "ok": false,
                "reason": "bus is not connected",
                "bus": self.state.bus.to_json(),
            }));
        }

        // KNX Data Secure (issue #71): with `--keyring`, the target's tool key
        // wraps every management APDU, exactly as `bussard describe --keyring`.
        // A device the keyring does not list is read in the clear, unless the
        // model records it as security-activated (issue #189).
        let activated = bussard_service::secure::model_activated(
            Some(self.state.model.current().as_ref()),
            target,
        );
        let tool_key = match bussard_service::secure::resolve(
            target,
            ToolKeySource {
                keyring: self.state.keyring.as_deref(),
                tool_key: None,
            },
            activated,
        ) {
            Ok(key) => key,
            Err(err) => {
                return ok(json!({
                    "address": target.to_string(),
                    "ok": false,
                    "reason": error_chain(&err),
                }));
            }
        };

        // Rate limit + concurrency cap, shared with the group read/write tools:
        // a full introspection is a burst of management round-trips, so hold the
        // permit across the whole session.
        let _permit = self.state.read_limiter.acquire().await;

        // Authorize (free access) as ETS does before configuration access; a
        // best-effort read tolerates a device without authorize.
        let options = L4Options {
            source: SourcePolicy::Known(ops::group_source(service.handle())),
            tool_key,
            ..L4Options::default()
        };
        let mut l4 = match service.connect_l4(target, &options).await {
            Ok(l4) => l4,
            Err(ServiceError::Lease(err)) => {
                return ok(json!({
                    "address": target.to_string(),
                    "ok": false,
                    "reason": format!("could not lease the bus: {err}"),
                }));
            }
            Err(err) => {
                return ok(json!({
                    "address": target.to_string(),
                    "ok": false,
                    "reason": format!("could not connect: {err}"),
                }));
            }
        };

        let result = describe_over_l4(&mut l4).await;
        let _ = l4.disconnect().await;

        match result {
            Ok(objects) => ok(json!({
                "address": target.to_string(),
                "ok": true,
                "objects": objects,
            })),
            Err(reason) => ok(json!({
                "address": target.to_string(),
                "ok": false,
                "reason": reason,
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
        if self.state.passive || !self.state.allow_writes {
            return ok(json!({
                "ga": args.ga,
                "ok": false,
                "reason": "bus writes are disabled on this server",
            }));
        }

        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        // Read the model through the handle, so an edit made to `groups.toml`
        // during the session (a `protected:` added, a `dpt:` corrected) is in
        // force on the very next write rather than after a restart.
        let model = self.state.model.current();
        // KNX Data Secure group keys from the server's `--keyring` (issue #172).
        let keys = match crate::secure_group::group_keys(self.state.keyring.as_deref()) {
            Ok(keys) => keys,
            Err(reason) => {
                return ok(json!({ "ga": ga.to_string(), "ok": false, "reason": reason }));
            }
        };

        // The shared write policy (bussard_service::write). Protected GAs are
        // hard-refused: `force` is never set, so there is no override via MCP.
        //
        // An unchecked `dpt` override is a hole in the protected/typed model: a
        // caller could send `dpt: "5.001", value: "255"` at a 1.001 GA and put
        // an arbitrary payload byte on the bus, past every type the model
        // declares. The CLI has the same override but behind a human y/N; MCP
        // has no human in the loop, so a mismatching override is refused. The
        // override still works where it is genuinely needed: a GA the model
        // does not type.
        let check = WriteCheck {
            dpt: args.dpt.as_deref(),
            dpt_policy: DptOverridePolicy::MustMatchModel,
            force: false,
            group_keys: keys.as_deref(),
        };
        let write =
            match prepare_group_write(Some(&model), ga, WriteValue::Human(&args.value), &check) {
                Ok(write) => write,
                Err(WriteRefusal::InvalidDpt { input, reason }) => {
                    return Err(invalid(format!("invalid dpt {input:?}: {reason}")));
                }
                Err(refusal) => return ok(write_refusal_json(ga, &refusal)),
            };

        let Some(service) = self.state.bus.service() else {
            return ok(json!({
                "ga": ga.to_string(),
                "ok": false,
                "reason": "bus is not wired",
            }));
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

        // Send once (completion-tracked against the gateway ACK). A transport
        // failure surfaces as ok:false — an honest failure, not a silent success.
        match service.send_prepared(write).await {
            Ok(sent) => ok(json!({
                "ga": ga.to_string(),
                "ok": true,
                "confirmed": sent.confirmed,
                "secured": sent.write.is_secured(),
                "written": {
                    "address": ga.to_string(),
                    "name": sent.write.name,
                    "value": sent.write.value,
                    "dpt": sent.write.dpt.map(|d| d.to_string()),
                },
            })),
            Err(refusal) => ok(write_refusal_json(ga, &refusal)),
        }
    }
}

/// Renders a [`WriteRefusal`] as the `knx_write_group` result: `ok: false`, a
/// reason in MCP words, and `refused: true` for the policy refusals (protected,
/// DPT mismatch) as opposed to plain failures.
fn write_refusal_json(ga: GroupAddress, refusal: &WriteRefusal) -> Value {
    let (refused, reason) = match refusal {
        WriteRefusal::Protected { name, .. } => (
            true,
            format!(
                "GA {ga} ({name:?}) is protected (safety-critical); writes are refused via MCP"
            ),
        ),
        WriteRefusal::DptMismatch {
            declared,
            requested,
            ..
        } => (
            true,
            format!(
                "GA {ga} is declared as DPT {declared} in the model; refusing to write it \
                 as {requested}. Correct groups.toml if the model is wrong — the model \
                 is the source of truth, not the caller"
            ),
        ),
        WriteRefusal::NoDpt { .. } => (
            false,
            format!("GA {ga} has no DPT in the model; pass `dpt` to write it"),
        ),
        WriteRefusal::InvalidValue { reason, .. } | WriteRefusal::Encode { reason, .. } => {
            (false, reason.clone())
        }
        WriteRefusal::WritesDisabled => (false, "bus writes are disabled on this server".into()),
        WriteRefusal::Bus(err) => (false, format!("bus send failed: {err}")),
        WriteRefusal::SecureNoKey { ga, keyring_given } => (
            true,
            crate::secure_group::no_key_reason(&bussard_service::SecureGroupError::NoKey {
                ga: *ga,
                keyring_given: *keyring_given,
            }),
        ),
        other => (false, other.to_string()),
    };
    let mut body = json!({
        "ga": ga.to_string(),
        "ok": false,
        "reason": reason,
    });
    if refused {
        body["refused"] = json!(true);
    }
    body
}

/// Discovers a device's interface objects and enumerates each one's property
/// descriptions over the L4 session, returning the JSON array the
/// `knx_describe_device` tool reports. Read-only on the bus.
///
/// A failure to read the descriptor or discover objects is returned as a human
/// reason string (the tool surfaces it as `ok:false`), never a panic.
async fn describe_over_l4<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
) -> Result<Vec<Value>, String> {
    // Scale property reads to the device's max APDU when it exposes it.
    let _ = l4.negotiate_max_apdu().await;
    let objects = walk_objects(l4).await.map_err(|e| error_chain(&e))?;
    Ok(objects
        .iter()
        .map(|o| tools::describe_object_json(o.index, o.object_type, &o.properties))
        .collect())
}

/// Renders an error with its source chain on one line (`outer: inner: ...`),
/// the shape an MCP `reason` string wants.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

/// A dedup key for a telegram: the fields that uniquely identify one bus event.
/// Used to drop capture-store rows that duplicate rows already in the ring.
type TelegramKey = (SystemTime, String, String, Vec<u8>);

/// Builds the dedup key for a decoded telegram.
fn telegram_key(t: &bussard_monitor::DecodedTelegram) -> TelegramKey {
    (
        t.timestamp,
        t.source.to_string(),
        t.destination.to_string(),
        t.payload.clone(),
    )
}

/// Upper bound on rows scanned from the capture DB in one fallback query.
///
/// A GA *prefix* filter (e.g. `"3/"`) cannot be expressed in SQL here, so those
/// rows are re-filtered in Rust after decoding. To keep a prefix query from
/// missing matches that sit behind many non-matching rows we do not push a tight
/// SQL `LIMIT`; this cap bounds the scan instead so a huge capture cannot blow
/// up memory.
const MAX_CAPTURE_SCAN: usize = 50_000;

/// Queries the capture store for older telegrams to top up the ring window.
///
/// Runs on a blocking thread (rusqlite is synchronous). The precise SQL filters
/// (exact GA, source, `since`) narrow the scan; the full [`Filter`] is then
/// re-applied to the decoded rows so GA prefixes are honoured, and the caller
/// de-duplicates against the ring rows. Returns rows chronological (oldest
/// first), truncated to `limit` *after* filtering.
fn query_capture(
    state: &SharedState,
    db: &std::path::Path,
    filter: &Filter,
    exact_ga: Option<GroupAddress>,
    exact_source: Option<IndividualAddress>,
    since: Option<SystemTime>,
    limit: usize,
) -> Option<Vec<bussard_monitor::DecodedTelegram>> {
    let store = CaptureStore::open(db).ok()?;
    let model = state.model.current();
    let qf = QueryFilter {
        // Only an *exact* GA can be pushed into SQL; a prefix stays None here and
        // is enforced by `filter.matches` below. `build_filter` already put both
        // ga and source into `filter`, so SQL is a coarse pre-filter only.
        ga: exact_ga,
        source: exact_source,
        since,
        // Do NOT push a tight LIMIT: a prefix filter is applied post-decode, so
        // a small LIMIT could return only non-matching rows. Bound the scan
        // instead; we truncate to `limit` after filtering.
        limit: Some(MAX_CAPTURE_SCAN),
    };
    let rows = store.query(&qf).ok()?;
    // Secured group telegrams decrypt with the server's `--keyring` (issue
    // #172); without one (or on a load failure) they stay as stored.
    let mut keyring = crate::secure_group::group_keys(state.keyring.as_deref())
        .ok()
        .flatten()
        .map(|keys| bussard_monitor::GroupKeyring::new(keys.as_ref().clone()));
    // Re-decode against the current model, drop undecodable rows, and re-apply
    // the requested filter (this is what makes a GA prefix like "3/" correct).
    let mut out: Vec<bussard_monitor::DecodedTelegram> = rows
        .iter()
        .filter_map(|r| r.redecode_secured(Some(&model), keyring.as_mut()).ok())
        .filter(|t| filter.matches(t))
        .collect();
    // Rows are newest-first; keep the newest `limit`, then make chronological.
    out.truncate(limit);
    out.reverse();
    Some(out)
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
                 button now' debugging), knx_validate to check the model, knx_read_group to \
                 actively read a value, and knx_describe_device to introspect a device's interface \
                 objects and property descriptions over the bus (both unless the server is in \
                 passive mode). When started with \
                 --allow-writes the knx_write_group tool is also available; it writes to the \
                 physical bus (actuators move) and refuses protected group addresses — prefer \
                 asking the human when a write's intent or safety is unclear. When started \
                 with --allow-programming, knx_plan_device and knx_apply_device program one \
                 device's link tables: always show the plan to the human and call \
                 knx_apply_device only after an explicit yes in the conversation.",
            )
    }
}
