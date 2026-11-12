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

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use crate::args::Parameters;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_service::monitor::{CaptureStore, Filter, QueryFilter};
use bussard_service::secure::ToolKeySource;
use bussard_service::{
    DptOverridePolicy, ServiceError, WriteCheck, WriteRefusal, WriteValue, prepare_group_write,
};
use bussard_service::{describe, group};
use rmcp::ErrorData;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::reply::{invalid, ok, ok_report};
use crate::state::{ConnState, Need, READ_RESPONSE_TIMEOUT, SharedState};
use crate::tools;
use bussard_service::bus_report::{ReconnectReport, TelegramsReport, WaitReport};
use bussard_service::device_show::{KnxnetSection, UnmodelledLive};
use bussard_service::group_report::{GroupReadReport, GroupWriteReport};
use bussard_service::project_view::{DeviceInfo, ProjectSummary};

/// How long `knx_bus_reconnect` waits for its connect attempt: the secure
/// probe, the TCP connect and the session handshake each have their own
/// timeout well inside this.
const RECONNECT_WAIT: Duration = Duration::from_secs(20);

/// The bussard MCP server handler.
///
/// Cloneable: rmcp clones the handler per request, but the heavy state lives
/// behind an `Arc`, so clones are cheap and share one ring + model.
#[derive(Clone)]
pub struct BussardMcp {
    /// The state and the tools the server started with: the full set over
    /// the model, or `knx_setup` and `knx_bus_status` over an empty
    /// placeholder model when it started without one (issue #745).
    started: Live,
    /// What `knx_setup` set up: the loaded model and the full tool set,
    /// which every clone serves from then on.
    pub(crate) set_up: Arc<OnceLock<Live>>,
    /// The onboarding state, when the server started without a model.
    pub(crate) setup: Option<Arc<crate::onboarding::Setup>>,
    /// The warm management connection shared by every clone (issue #215).
    warm: crate::warm::WarmConnection,
    /// This session's model edits no device has received yet (issue #279).
    session_edits: crate::session_edits::SessionEdits,
    /// The security individual address tables (PID 54) read for a secured
    /// write or read without admission evidence, kept for the server's
    /// lifetime so each device is read once (issue #316).
    admission_tables: Arc<tokio::sync::Mutex<bussard_service::admission::LiveTables>>,
    /// The certificate enrolment session of this server, if one was started
    /// (issue #732).
    pub(crate) enroll: crate::tools_enroll::EnrollJobs,
    /// The project password form `knx_import_file` shows (#818).
    pub(crate) password_forms: crate::password_form::PasswordForms,
    /// Opens the enrolment pairing page in the human's browser (issue #809).
    pub(crate) browser: Arc<dyn crate::browser::BrowserOpener>,
}

/// The state a server serves and the tools it registers over it.
#[derive(Clone)]
pub(crate) struct Live {
    /// The shared state.
    pub(crate) state: Arc<SharedState>,
    /// The registered tools.
    pub(crate) router: ToolRouter<BussardMcp>,
}

impl BussardMcp {
    /// Builds the server over `state` with the tools of its tiers.
    pub fn new(state: Arc<SharedState>) -> Self {
        let router = Self::full_router(&state);
        Self::with_live(Live { state, router }, None)
    }

    /// The server over `started`, with `setup` when it started without a
    /// model.
    pub(crate) fn with_live(started: Live, setup: Option<Arc<crate::onboarding::Setup>>) -> Self {
        let session_edits = crate::session_edits::SessionEdits::new(&started.state.dir);
        BussardMcp {
            started,
            set_up: Arc::default(),
            setup,
            warm: crate::warm::WarmConnection::new(),
            session_edits,
            admission_tables: Arc::default(),
            enroll: crate::tools_enroll::EnrollJobs::new(),
            password_forms: crate::password_form::PasswordForms::new(),
            browser: Arc::new(crate::browser::SystemBrowser),
        }
    }

    /// The tool set over `state`: every tool registered, then the ones
    /// whose [`crate::Tier`] this mode does not allow ([`crate::TOOLS`])
    /// unregistered.
    pub(crate) fn full_router(state: &SharedState) -> ToolRouter<BussardMcp> {
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
            + Self::jobs_router()
            + Self::files_router()
            + Self::device_router()
            + Self::program_router()
            + Self::ha_router()
            + Self::ha_automation_router()
            + Self::enroll_router()
            + Self::viz_router();
        let tiers = crate::guidance::Tiers::of(state);
        for (name, tier) in crate::TOOLS {
            if !tiers.allows(*tier) {
                tool_router.remove_route(name);
            }
        }
        tool_router
    }

    /// What the server serves now: the set-up model once `knx_setup`
    /// succeeded, else what it started with.
    fn live(&self) -> &Live {
        self.set_up.get().unwrap_or(&self.started)
    }

    /// Whether the server still waits for `knx_setup` (issue #745).
    pub(crate) fn before_setup(&self) -> bool {
        self.setup.is_some() && self.set_up.get().is_none()
    }

    /// This server with `browser` opening the enrolment pairing page
    /// instead of the system browser (the tests open nothing).
    #[must_use]
    pub fn with_browser(mut self, browser: Arc<dyn crate::browser::BrowserOpener>) -> Self {
        self.browser = browser;
        self
    }

    /// This server with enrolment sessions that use `timeouts` instead of
    /// the protocol's (the tests shorten them).
    #[must_use]
    pub fn with_enroll_timeouts(
        mut self,
        timeouts: bussard_service::enroll_session::Timeouts,
    ) -> Self {
        self.enroll = crate::tools_enroll::EnrollJobs::with_timeouts(timeouts);
        self
    }

    /// The shared state (for tests and the runner).
    pub fn state(&self) -> &Arc<SharedState> {
        &self.live().state
    }

    /// How many tools this server registers.
    pub fn tool_count(&self) -> usize {
        self.live().router.list_all().len()
    }

    /// The warm management connection (issue #215). Every tool that opens a
    /// management connection holds its lock for the session.
    pub(crate) fn warm(&self) -> &crate::warm::WarmConnection {
        &self.warm
    }

    /// The project the server serves now, for a result's `summary`.
    pub(crate) fn model(&self) -> std::sync::Arc<bussard_model::Model> {
        self.state().model.current()
    }

    /// This session's unapplied model edits, by device (issue #279).
    pub(crate) fn session_edits(&self) -> &crate::session_edits::SessionEdits {
        &self.session_edits
    }
}

/// Arguments for `knx_model_lookup`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LookupArgs {
    /// Case-insensitive substring to search for across GA names/addresses,
    /// device names/addresses, room names and com-object names;
    /// for `capabilities`, the words of a function ("Helligkeit",
    /// "Dämmerung") searched in the devices' parameter and choice texts.
    pub query: String,
    /// Maximum matches to return per category (default 50).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Also return what only an integrator reads (issue #306): the empty and null fields of every match and the ETS references a capability's key already names.
    /// Off by default; `true` returns the payload as it was before the
    /// homeowner view.
    #[serde(default)]
    pub technical: bool,
}

/// Arguments for tools that take a single group address.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GaArgs {
    /// A 3-level group address like `"3/2/0"`.
    pub ga: String,
}

/// Arguments for `knx_get_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetGroupArgs {
    /// A 3-level group address like `"3/2/0"`.
    pub ga: String,
    /// Also return what only an integrator reads (issue #306): the last telegram's wire detail (APCI, raw payload, Data Secure sequence) instead of each link's `room` and `what`.
    /// Off by default; `true` returns the payload as it was before the
    /// homeowner view.
    #[serde(default)]
    pub technical: bool,
}

/// Arguments for `knx_write_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteArgs {
    /// A 3-level group address like `"3/0/4"`.
    pub ga: String,
    /// The value to write, in human form: `on`/`off`, `up`/`down`, a number, a
    /// percentage like `75%`, a temperature like `21.5`, an HVAC mode name, etc.
    /// Interpreted according to the resolved DPT; a scaled sub-type takes the
    /// scaled value (8.010 `50 %`, 7.004 `1.5 s`), never the raw count.
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
    /// Also return the ETS-internal parameter values the device file does
    /// not show (`hidden@<ref>`, `label@<ref>`) in `device.parameters`. Off
    /// by default: they are not user settable, and `hidden_parameters`
    /// counts them.
    #[serde(default)]
    pub technical: bool,
}

/// Arguments for `knx_show_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShowDeviceArgs {
    /// An individual (physical) address like `"1.1.47"`.
    pub address: String,
    /// A channel handle (`"a-1"`), channel id or vendor number, an ETS page
    /// handle from `blocks` (`"universalkanal-c4-funktion"`), or `"device"`
    /// for the device-level parameters and objects, to list in detail. Omit
    /// it to list the channels and pages only.
    #[serde(default)]
    pub channel: Option<String>,
    /// Also return `toml`: the paste-ready device-file snippet, with
    /// commented lines for what the file does not set yet.
    #[serde(default)]
    pub toml: bool,
    /// With `channel`: also return `inactive_pages`, the inactive pages and
    /// channels with what enables each (`enable`, `also_needs`) and the
    /// objects they would show. Without it a scoped call lists every page in
    /// one line.
    #[serde(default)]
    pub inactive: bool,
    /// Also read the device over the bus, as `bussard status <address>`
    /// does, and return it as `live`: its mask and identity against
    /// bussard.lock, and for a KNX IP interface its IP settings, tunnelling
    /// addresses and state. Read-only; refused in `--passive` mode.
    #[serde(default)]
    pub live: bool,
    /// Also return what only an integrator reads (issue #306): the ETS ids (a parameter's `reference`, a page's `id`, the `application`, folded page ids, `computed_by`) and each object's `flags`.
    /// Off by default; `true` returns the payload as it was before the
    /// homeowner view.
    #[serde(default)]
    pub technical: bool,
}

/// Arguments for `knx_validate`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ValidateArgs {
    /// The least severe diagnostics to return: `"error"`, `"warning"`
    /// (default: errors and warnings) or `"info"` (everything). `counts`
    /// always counts all three.
    #[serde(default)]
    pub severity: Option<String>,
    /// Only diagnostics about this device (`"1.1.4"`), or a line when it
    /// ends with a dot (`"1.1."`).
    #[serde(default)]
    pub address: Option<String>,
    /// Only diagnostics about this group address (`"3/2/0"`), or a range
    /// when it ends with a slash (`"3/"`).
    #[serde(default)]
    pub group: Option<String>,
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
    /// Restrict to a source address (`"1.1.30"`).
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
    /// Restrict to a source address.
    #[serde(default)]
    pub source: Option<String>,
    /// How long to wait, in seconds (max 300).
    pub timeout_seconds: u32,
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
    // `knx_project_summary`.
    #[doc = include_str!("../guidance/tools/knx_project_summary.md")]
    #[tool]
    async fn knx_project_summary(&self) -> Result<CallToolResult, ErrorData> {
        let model = self.state().model.current();
        let tiers = crate::guidance::Tiers::of(self.state());
        let summary = ProjectSummary {
            server: Some(tiers.summary_json()),
            capabilities: Some(tiers.capabilities()),
            ..ProjectSummary::of(&model, self.state().bus.to_json())
        };
        ok_report(&summary, &model)
    }

    // `knx_model_lookup`.
    #[doc = include_str!("../guidance/tools/knx_model_lookup.md")]
    #[tool]
    async fn knx_model_lookup(
        &self,
        Parameters(args): Parameters<LookupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = args.limit.unwrap_or(50).clamp(1, 500) as usize;
        let tiers = crate::guidance::Tiers::of(self.state());
        let model = self.state().model.current();
        let capabilities = Some((self.state().dir.as_path(), tiers));
        let report = tools::lookup_report(&model, &args.query, limit, capabilities);
        let mut value = crate::reply::report(&report, &model);
        if !args.technical {
            crate::everyday::plain_lookup(&mut value);
        }
        ok(value)
    }

    // `knx_get_group`.
    #[doc = include_str!("../guidance/tools/knx_get_group.md")]
    #[tool]
    async fn knx_get_group(
        &self,
        Parameters(args): Parameters<GetGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;
        let model = self.state().model.current();
        let mut view = tools::group_view(&model, &self.state().ring, ga);
        if !args.technical {
            view = view.plain(&model);
        }
        ok_report(&view, &model)
    }

    // `knx_get_device`.
    #[doc = include_str!("../guidance/tools/knx_get_device.md")]
    #[tool]
    async fn knx_get_device(
        &self,
        Parameters(args): Parameters<DeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = args
            .address
            .parse()
            .map_err(|_| invalid(format!("invalid individual address {:?}", args.address)))?;
        let model = self.state().model.current();
        let app = model
            .devices
            .get(&ia)
            .and_then(|d| d.device.product.as_ref())
            .and_then(|p| p.application_ref.clone());
        let products = bussard_model::param_model::ProductModels::load_apps(
            &self.state().dir,
            app.iter().map(String::as_str),
        );
        ok_report(
            &DeviceInfo::of(&model, &products, ia, args.technical),
            &model,
        )
    }

    // `knx_show_device`.
    #[doc = include_str!("../guidance/tools/knx_show_device.md")]
    #[tool]
    async fn knx_show_device(
        &self,
        Parameters(args): Parameters<ShowDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = args
            .address
            .parse()
            .map_err(|_| invalid(format!("invalid individual address {:?}", args.address)))?;
        let model = self.state().model.current();
        let app = model
            .devices
            .get(&ia)
            .and_then(|d| d.device.product.as_ref())
            .and_then(|p| p.application_ref.clone());
        let products = bussard_model::ProductModels::load_apps(
            &self.state().dir,
            app.iter().map(String::as_str),
        );
        let view = match bussard_model::device_view::device_view(
            &model,
            &products,
            ia,
            args.channel.as_deref(),
        ) {
            Ok(view) => view,
            // A live read of a device the model does not have (a scan
            // responder) still answers, with the reason in `model_view`.
            Err(e) if args.live => {
                return ok_report(
                    &UnmodelledLive {
                        address: ia.to_string(),
                        model_view: e.to_string(),
                        live: self.live_part(ia).await,
                    },
                    &model,
                );
            }
            Err(e) => return Err(invalid(e.to_string())),
        };
        let mut show = tools::show_device_result(
            view,
            args.inactive,
            args.toml,
            crate::guidance::Tiers::of(self.state()),
        );
        // An IP interface's KNXnet/IP settings and facts (issue #391).
        show.knxnet = KnxnetSection::of(&self.state().dir, &model, ia);
        let mut value = crate::reply::report(&show, &model);
        if !args.technical {
            crate::everyday::plain_view(&mut value);
        }
        // Whether bussard writes it without the override (issue #1089),
        // after the plain view: it names the application on purpose.
        value["support"] =
            serde_json::to_value(bussard_service::support::verdict_at(Some(&model), ia).view())
                .unwrap_or_default();
        if args.live {
            value["live"] = self.live_part(ia).await;
        }
        ok(value)
    }

    // `knx_recent_telegrams`.
    #[doc = include_str!("../guidance/tools/knx_recent_telegrams.md")]
    #[tool]
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

        let mut telegrams = tools::recent_telegrams(&self.state().ring, &filter, since, limit);

        // Fall back to the capture store when the ring window is exceeded: if we
        // got fewer than asked and a DB is configured, top up from it with OLDER
        // rows. The DB query runs on a blocking thread (rusqlite is synchronous)
        // and its rows are re-filtered against the same `Filter` (so a GA prefix
        // like "3/" is honoured, not silently dropped) and de-duplicated against
        // the ring rows we already have.
        if telegrams.len() < limit
            && let Some(db) = self.state().capture_db.clone()
        {
            let want = limit - telegrams.len();
            let state = Arc::clone(self.state());
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
        ok_report(
            &TelegramsReport {
                count: items.len(),
                telegrams: items,
            },
            &self.model(),
        )
    }

    // `knx_wait_for_telegram`.
    #[doc = include_str!("../guidance/tools/knx_wait_for_telegram.md")]
    #[tool]
    async fn knx_wait_for_telegram(
        &self,
        Parameters(args): Parameters<WaitArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let timeout = Duration::from_secs(args.timeout_seconds.clamp(1, 300) as u64);
        let filter = build_filter(args.ga.as_deref(), args.source.as_deref())?;

        let report = match self.state().ring.wait_for(&filter, timeout).await {
            Some(t) => WaitReport {
                matched: true,
                telegram: Some(tools::telegram_json(&t)),
                timed_out: false,
                waited_seconds: None,
            },
            None => WaitReport {
                matched: false,
                telegram: None,
                timed_out: true,
                waited_seconds: Some(timeout.as_secs()),
            },
        };
        ok_report(&report, &self.model())
    }

    // `knx_bus_status` (issue #287).
    #[doc = include_str!("../guidance/tools/knx_bus_status.md")]
    #[tool]
    async fn knx_bus_status(&self) -> Result<CallToolResult, ErrorData> {
        let mut view = self.state().bus.view();
        view.other_instances = Some(crate::instances::other_instances(&self.state().dir));
        if self.state().bus.state() != ConnState::Connected {
            view.reason = Some(self.state().bus.not_connected_reason());
        }
        ok_report(&view, &self.model())
    }

    // `knx_bus_reconnect` (issue #287; omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_bus_reconnect.md")]
    #[tool]
    async fn knx_bus_reconnect(&self) -> Result<CallToolResult, ErrorData> {
        let model = self.model();
        if self.state().passive {
            return ok_report(
                &ReconnectReport {
                    ok: false,
                    bus: None,
                    note: None,
                    reason: Some(
                        "server is in passive mode; the bus reconnects on its own".to_string(),
                    ),
                },
                &model,
            );
        }
        let Some(handle) = self.state().bus.handle() else {
            return ok_report(
                &ReconnectReport {
                    ok: false,
                    bus: Some(self.state().bus.view()),
                    note: None,
                    reason: Some("bus is not wired".to_string()),
                },
                &model,
            );
        };
        let attempt = tokio::time::timeout(RECONNECT_WAIT, handle.reconnect()).await;
        let note = match attempt {
            Ok(Ok(())) => None,
            Ok(Err(err)) => Some(format!(
                "{err}: the bus stopped (see `stopped`); restart the server after fixing the cause"
            )),
            Err(_) => Some(format!(
                "the connect attempt did not finish within {} s; it continues in the background",
                RECONNECT_WAIT.as_secs()
            )),
        };
        let connected = self.state().bus.state() == ConnState::Connected;
        let report = ReconnectReport {
            ok: connected,
            bus: Some(self.state().bus.view()),
            note,
            reason: (!connected).then(|| self.state().bus.not_connected_reason()),
        };
        ok_report(&report, &model)
    }

    // `knx_validate`.
    #[doc = include_str!("../guidance/tools/knx_validate.md")]
    #[tool]
    async fn knx_validate(
        &self,
        Parameters(args): Parameters<ValidateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let severity = match args.severity.as_deref() {
            None => None,
            Some(text) => Some(tools::parse_severity(text).ok_or_else(|| {
                invalid(format!(
                    "severity {text:?} is not one of \"error\", \"warning\", \"info\""
                ))
            })?),
        };
        let filter = tools::ValidateFilter {
            severity,
            address: args.address,
            group: args.group,
        };
        let model = self.state().model.current();
        // The keyring rules (issue #205) against the server's keyring: never
        // prompts; without BUSSARD_KEYRING_PASSWORD one info line says the
        // key checks were skipped.
        let facts = self
            .state()
            .keyring
            .as_deref()
            .map(|path| bussard_service::secure::keyring_facts(path, "the server's keyring"));
        let mut extra = bussard_model::validate_keyring(&model, facts.as_ref());
        // W034 (issue #297): secured GAs only tunnel clients can write.
        extra.extend(bussard_service::admission::tunnel_gap_diagnostics(
            &model,
            facts.as_ref(),
        ));
        // W047 (issue #391): an IP interface's [knxnet] tunnels against the
        // tunnelling addresses the key store lists for it.
        extra.extend(
            bussard_service::admission::knxnet_tunnel_keyring_diagnostics(&model, facts.as_ref()),
        );
        // W040 (issue #348): keyring exports older than the key store.
        extra.extend(bussard_model::keystore_meta::stale_export_diagnostics(
            &model,
            &self.state().dir,
        ));
        ok(tools::validate_filtered(&model, extra, &filter))
    }

    // `knx_read_group` (omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_read_group.md")]
    #[tool]
    async fn knx_read_group(
        &self,
        Parameters(args): Parameters<GaArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        // KNX Data Secure (issue #172): a secured GA (a group key in the
        // server's `--keyring`, or `secure: true` in the model) is read with a
        // secured GroupValueRead; a secured GA without a key is refused.
        let model = self.state().model.current();
        let key = match group::read_key(Some(&model), ga, self.state().keyring.as_deref()) {
            Ok(key) => key,
            Err(err) => return ok_report(&group_error(ga, &err), &model),
        };

        // Passive mode: the tool is unregistered, but guarded anyway.
        let service = match self.state().live_service(Need::Read) {
            Ok(service) => service,
            Err(reason) => return ok(self.bus_refusal("ga", &ga.to_string(), reason)),
        };

        // Sender admission (issue #297): a responder that does not admit the
        // tunnel address never answers a secured read; an unknown verdict
        // reads the responders' PID 54 first (#316). Rate limit + concurrency
        // cap across the whole read. The shared read implementation:
        // subscribe, send (completion-tracked), skip the L_Data.con echo,
        // decode against the GA's DPT (#32, #30).
        let secured = key.is_some();
        let outcome = match group::read(
            service,
            &self.group_context(&model),
            ga,
            key,
            READ_RESPONSE_TIMEOUT,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => return ok_report(&group_error(ga, &err), &model),
        };
        let name = model.groups.groups.get(&ga).map(|g| g.name.clone());
        let report = GroupReadReport::of(ga, name, secured, READ_RESPONSE_TIMEOUT, &outcome);
        crate::reply::ok_report(&report, &model)
    }

    // `knx_describe_device` (omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_describe_device.md")]
    #[tool]
    async fn knx_describe_device(
        &self,
        Parameters(args): Parameters<DescribeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let target: IndividualAddress = args
            .address
            .parse()
            .map_err(|_| invalid(format!("invalid individual address {:?}", args.address)))?;
        // Passive mode: the tool is unregistered, but guarded anyway.
        let service = match self.state().live_service(Need::Manage) {
            Ok(service) => service,
            Err(reason) => return ok(self.bus_refusal("address", &target.to_string(), reason)),
        };

        // KNX Data Secure (issue #71): with `--keyring`, the target's tool key
        // wraps every management APDU, exactly as `bussard describe --keyring`.
        // A device the keyring does not list is read in the clear, unless the
        // model records it as security-activated (issue #189). The device's
        // FDSK rides along: a device reset to default is named, not read under
        // the factory key (issue #532).
        let model = self.state().model.current();
        let keys = match describe::session_keys(
            Some(model.as_ref()),
            target,
            ToolKeySource {
                keyring: self.state().keyring.as_deref(),
                tool_key: None,
            },
        ) {
            Ok(keys) => keys,
            Err(err) => {
                let failed =
                    describe::DescribeReport::failed(target, bussard_service::program::chain(&err));
                return crate::reply::ok_report(&failed, &model);
            }
        };

        // Rate limit + concurrency cap, shared with the group read/write tools:
        // a full introspection is a burst of management round-trips, so hold the
        // permit across the whole session.
        let _permit = self.state().read_limiter.acquire().await;

        // The warm connection (issue #215): a call to the device the previous
        // call talked to, within the idle window and on the same tunnel, reuses
        // its connection. The lock is held for the whole session, so
        // management calls stay sequential.
        let request = describe::DescribeRequest {
            target,
            model: Some(model.as_ref()),
            dir: None,
            keys,
            source: service.handle().group_source().into(),
            authorize: bussard_service::Authorize::BestEffort(
                bussard_service::mgmt::apci::FREE_ACCESS_KEY,
            ),
            walk: describe::Walk::Objects,
        };
        let mut warm = self.warm.lock().await;
        let outcome = describe::run(service, &request, Some(&mut warm)).await;
        drop(warm);
        let report = match (outcome.report, outcome.walk) {
            (Some(report), _) => report,
            (None, Ok(_)) => describe::DescribeReport::failed(
                target,
                format!("{target}: the describe read nothing"),
            ),
            (None, Err(err)) => describe::DescribeReport::failed(
                target,
                match err {
                    describe::RunError::Session(ServiceError::Lease(err)) => {
                        format!("could not lease the bus: {err}")
                    }
                    describe::RunError::Session(err) => format!("could not connect: {err}"),
                    err => bussard_service::program::chain(&err),
                },
            ),
        };
        let report = describe::DescribeReport {
            factory_key: outcome.on_factory_key,
            reason: if outcome.on_factory_key {
                Some(bussard_service::identity::factory_key_message(target))
            } else {
                report.reason
            },
            ok: report.ok && !outcome.on_factory_key,
            ..report
        };
        crate::reply::ok_report(&report, &model)
    }

    // `knx_write_group` (registered only with `--allow-writes`, never in passive
    // mode).
    #[doc = include_str!("../guidance/tools/knx_write_group.md")]
    #[tool]
    async fn knx_write_group(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;

        // Read the model through the handle, so an edit made to `groups.toml`
        // during the session (a `protected:` added, a `dpt:` corrected) is in
        // force on the very next write rather than after a restart.
        let model = self.state().model.current();
        // KNX Data Secure group keys from the server's `--keyring` (issue #172).
        let keys = match group::load_keys(self.state().keyring.as_deref()) {
            Ok(keys) => keys,
            Err(err) => return ok_report(&group_error(ga, &err), &model),
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
            group_keys: keys.as_ref(),
        };
        let write =
            match prepare_group_write(Some(&model), ga, WriteValue::Human(&args.value), &check) {
                Ok(write) => write,
                Err(WriteRefusal::InvalidDpt { input, reason }) => {
                    return Err(invalid(format!("invalid dpt {input:?}: {reason}")));
                }
                Err(refusal) => {
                    let (refused, reason) = write_refusal(ga, &refusal);
                    return ok_report(&GroupWriteReport::failed(ga, reason, refused), &model);
                }
            };

        // Writes disabled: the tool is unregistered, but guarded anyway.
        let service = match self.state().live_service(Need::Write) {
            Ok(service) => service,
            Err(reason) => return ok(self.bus_refusal("ga", &ga.to_string(), reason)),
        };

        // Sender admission (issue #297): refuse a secured write the devices on
        // the GA would discard, before anything is sent. The rate limiter's
        // spacing and concurrency cap are shared with reads. Sent once,
        // completion-tracked against the gateway ACK; a transport failure
        // surfaces as ok:false, an honest failure, not a silent success.
        let outcome = match group::write(service, &self.group_context(&model), write).await {
            Ok(outcome) => outcome,
            Err(err) => return ok_report(&group_error(ga, &err), &model),
        };
        let gateway = self.state().bus.diagnostics().map(|d| d.interface);
        let report =
            GroupWriteReport::of(ga, gateway, &outcome, |refusal| write_refusal(ga, refusal));
        crate::reply::ok_report(&report, &model)
    }
}

/// What a group read or write shares with this server: the model, the
/// keyring, the lock, the PID 54 tables read in its lifetime, the warm
/// connection and the rate limiter.
impl BussardMcp {
    /// A bus tool's result when the bus cannot be used: `ok: false`, the
    /// reason and the bus status, about `key: value`.
    fn bus_refusal(&self, key: &str, value: &str, reason: String) -> Value {
        json!({ key: value, "ok": false, "reason": reason, "bus": self.state().bus.to_json() })
    }

    fn group_context<'a>(&'a self, model: &'a bussard_model::Model) -> group::GroupContext<'a> {
        group::GroupContext {
            model: Some(model),
            keyring: self.state().keyring.as_deref(),
            lock_dir: Some(self.state().dir.as_path()),
            live: &self.admission_tables,
            warm: Some(&self.warm),
            limiter: Some(&self.state().read_limiter),
        }
    }
}

/// A group read or write that could not start: the reason, and `refused`
/// for a secured GA without a group key.
fn group_error(ga: GroupAddress, err: &group::GroupError) -> GroupReadReport {
    match err {
        group::GroupError::NoKey(err) => {
            GroupReadReport::failed(ga, crate::secure_group::no_key_reason(err), true)
        }
        group::GroupError::Keys { source, .. } | group::GroupError::Evidence { source, .. } => {
            GroupReadReport::failed(ga, bussard_service::program::chain(source), false)
        }
        group::GroupError::ToolKeys(err) => {
            GroupReadReport::failed(ga, bussard_service::program::chain(err), false)
        }
    }
}

/// A [`WriteRefusal`] in MCP words: `true` for the policy refusals
/// (protected, DPT mismatch) as opposed to plain failures, and the reason.
fn write_refusal(ga: GroupAddress, refusal: &WriteRefusal) -> (bool, String) {
    let (refused, reason) = match refusal {
        WriteRefusal::Protected { name, .. } => (
            true,
            format!(
                "group address {ga} ({name:?}) is protected (safety-critical); writes are refused via MCP"
            ),
        ),
        WriteRefusal::DptMismatch {
            declared,
            requested,
            ..
        } => (
            true,
            format!(
                "group address {ga} is declared as DPT {declared} in your project; refusing to write it \
                 as {requested}. Correct groups.toml if your project is wrong — your project \
                 is the source of truth, not the caller"
            ),
        ),
        WriteRefusal::NoDpt { .. } => (
            false,
            format!("group address {ga} has no DPT in your project; pass `dpt` to write it"),
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
    (refused, reason)
}

/// A dedup key for a telegram: the fields that uniquely identify one bus event.
/// Used to drop capture-store rows that duplicate rows already in the ring.
type TelegramKey = (SystemTime, String, String, Vec<u8>);

/// Builds the dedup key for a decoded telegram.
fn telegram_key(t: &bussard_service::monitor::DecodedTelegram) -> TelegramKey {
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
) -> Option<Vec<bussard_service::monitor::DecodedTelegram>> {
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
    let mut keyring = crate::secure_group::key_store(state.keyring.as_deref())
        .ok()
        .flatten()
        .map(bussard_service::monitor::GroupKeyring::new);
    // Re-decode against the current model, drop undecodable rows, and re-apply
    // the requested filter (this is what makes a GA prefix like "3/" correct).
    let mut out: Vec<bussard_service::monitor::DecodedTelegram> = rows
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
    let ts = bussard_service::monitor::timefmt::from_rfc3339(s);
    if ts == SystemTime::UNIX_EPOCH && !s.starts_with("1970") {
        return Err(invalid(format!(
            "invalid RFC3339 timestamp {s:?} (expected e.g. 2026-09-15T10:00:00Z)"
        )));
    }
    Ok(ts)
}

#[tool_handler(router = self.live().router)]
impl ServerHandler for BussardMcp {
    /// Logs the shape of every `tools/call` (issue #269), then dispatches it
    /// through the tool router exactly as the `#[tool_handler]` default does.
    ///
    /// Info: the tool name, whether `arguments` was present and the received
    /// field names, never values. Debug (`-vv`): the raw request with every
    /// string value redacted. An argument error comes back as a tool result
    /// with `isError` set (see [`crate::args::argument_error_as_tool_result`]).
    /// The call that ends the onboarding state sends
    /// `notifications/tools/list_changed` (issue #745).
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        tracing::info!(
            tool = %request.name,
            arguments_present = request.arguments.is_some(),
            fields = ?crate::args::field_names(request.arguments.as_ref()),
            "tools/call"
        );
        if tracing::enabled!(tracing::Level::DEBUG) {
            let arguments = request.arguments.as_ref().map(|object| {
                crate::args::redact_strings(&serde_json::Value::Object(object.clone()))
            });
            tracing::debug!(
                tool = %request.name,
                raw = %serde_json::json!({ "name": request.name, "arguments": arguments }),
                "tools/call request (string values redacted)"
            );
        }
        let before_setup = self.before_setup();
        let peer = context.peer.clone();
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let response =
            crate::args::argument_error_as_tool_result(self.live().router.call(tcc).await);
        if before_setup
            && !self.before_setup()
            && let Err(err) = peer.notify_tool_list_changed().await
        {
            tracing::warn!("failed to send tools/list_changed: {err}");
        }
        response
    }

    fn get_info(&self) -> ServerConfig {
        // Identify as bussard (not the SDK default "rmcp") so clients show the
        // right name/version.
        let mut server_info = rmcp::model::Implementation::from_build_env();
        server_info.name = "bussard".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        server_info.title = Some("bussard KNX MCP server".to_string());
        // A server that starts without a model changes its tool list once.
        let capabilities = if self.setup.is_some() {
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build()
        } else {
            ServerCapabilities::builder().enable_tools().build()
        };
        let instructions = match &self.setup {
            Some(setup) if self.before_setup() => setup.instructions(),
            _ => crate::guidance::Tiers::of(self.state()).instructions(),
        };
        ServerConfig::new(capabilities)
            .with_server_info(server_info)
            .with_instructions(instructions)
    }
}
