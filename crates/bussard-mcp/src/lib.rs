//! MCP stdio server for bussard: read-only KNX model and bus introspection.
//!
//! This crate implements the phase-0 Model Context Protocol server described in
//! the design document (§5.5). It loads a KNX-as-code [`Model`] from a directory,
//! spawns the reconnecting bus monitor pipeline feeding a shared
//! [`TelegramRing`](bussard_monitor::TelegramRing), and exposes read-only tools
//! over MCP so an LLM (e.g. Claude Code) can explore the installation and debug
//! live traffic.
//!
//! It is built on the official Rust MCP SDK [`rmcp`] (3.x) using the
//! `#[tool_router]` / `#[tool]` / `#[tool_handler]` macro API and the stdio
//! transport. All logging goes to **stderr**; stdout carries only the MCP JSON-
//! RPC wire, nothing else.
//!
//! # Tools
//!
//! | Tool | Purpose |
//! |------|---------|
//! | `knx_project_summary` | Project name, counts, rooms, GA ranges, bus status, validation counts. |
//! | `knx_model_lookup` | Case-insensitive substring search over the model. |
//! | `knx_get_group` | A GA's definition, links touching it, and its last telegram. |
//! | `knx_get_device` | A device's full definition plus its links. |
//! | `knx_show_device` | A device's channels, and one channel's parameters (choices, defaults) and objects, in its device file's words; optionally as paste-ready TOML. |
//! | `knx_recent_telegrams` | Recent telegrams from the ring (and capture DB). |
//! | `knx_wait_for_telegram` | Block for the next matching telegram ("press the button now"). |
//! | `knx_validate` | Model validation diagnostics as JSON. |
//! | `knx_audit` | Installation audit: model gaps, one-sided links, mask capabilities, Secure devices; with `live`, tunnel slots and a traffic sample (live refused in `--passive`). |
//! | `knx_scaffold_groups` | Draft or extend `groups.toml` from a room and function list (JSON). |
//! | `knx_reserve_groups` | Reserve the conventional addresses for one room in `groups.toml`. |
//! | `knx_read_group` | Send a GroupValueRead and return the value (omitted in `--passive`). |
//! | `knx_describe_device` | Introspect a device: enumerate its interface objects and each property's description (omitted in `--passive`). |
//! | `knx_infer_group` | Infer a GA's DPT and a proposed name from the traffic seen on it (issue #95). |
//! | `knx_write_group` | Send a GroupValueWrite (registered only with `--allow-writes`). |
//! | `knx_run_tests` | Run the model directory's `tests.toml` against the bus (registered only with `--allow-writes`). |
//! | `knx_describe_change` | Pending or between-snapshot model changes, as plain sentences. |
//! | `knx_history` | The model's history snapshots with a one-line summary each. |
//! | `knx_set_group` | Create or update a group address (refuses to rename or retype a protected one). |
//! | `knx_add_link` / `knx_remove_link` | Bind or unbind a com object and a GA (refuses protected GAs). |
//! | `knx_set_device` | Rename a device or change its floor/room. |
//! | `knx_set_parameter` | Set one device parameter, checked against the product model. |
//! | `knx_undo` | Restore the model files to a history snapshot. |
//! | `knx_export_bundle` | Write the model and history as one `.bussard` handover file. |
//! | `knx_diff_project` | What a received `.knxproj` or bundle would change, as sentences. |
//! | `knx_plan_device` | Read one device's live tables and return the plan `bussard plan` prints, plus a `plan_digest` (registered only with `--allow-programming`). |
//! | `knx_apply_device` | Write the planned tables to one device, backup first and verify after, only with a fresh matching `plan_digest` (registered only with `--allow-programming`). |
//!
//! The eight from `knx_describe_change` to `knx_undo` are model tools: they
//! read and write the model files (TOML) under the model directory and never touch the bus,
//! so they are available in every tier including `--passive`. The six that
//! edit, and `knx_scaffold_groups` and `knx_reserve_groups`, which write
//! `groups.toml`, are withheld by
//! `--no-model-edits`. Every edit snapshots first, validates after, and returns
//! the change as sentences for the caller to quote to the human. The last two
//! only read the model (the export writes one file outside it) and are
//! available in every tier.
//!
//! In `--passive` mode the two bus-touching read tools (`knx_read_group` and
//! `knx_describe_device`) are unregistered and the server never transmits;
//! `knx_infer_group` stays, because it only reads the telegram ring, and
//! `knx_audit` stays but refuses `live: true`.
//! `knx_write_group` and `knx_run_tests` are registered only when the server is
//! started with `--allow-writes` (which conflicts with `--passive`); both write
//! to the physical bus, and both hard-refuse `protected` GAs.
//!
//! Tool counts per tier: `--passive` 22, default 24, `--allow-writes` 26. With
//! `--no-model-edits` the eight model-edit tools (the six above plus the two
//! reservation tools) are withheld, giving 14, 16 and 18.
//!
//! `--allow-programming` (issue #118) adds the two programming tools
//! ([`tools_program::PROGRAMMING_TOOLS`]) to any non-passive tier. They write
//! device tables, so they pass the non-loopback write gate on every call, run
//! the source-address probe, and apply only a plan whose digest this session
//! produced minutes ago and which a fresh read still reproduces. See
//! [`tools_program`].
//!
//! # Connecting this to Claude Code
//!
//! Register the server with the Claude Code CLI (stdio transport):
//!
//! ```bash
//! claude mcp add bussard -- bussard mcp --dir knx/
//! ```
//!
//! or add it to a project `.mcp.json`:
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "bussard": {
//!       "command": "bussard",
//!       "args": ["mcp", "--dir", "knx/"]
//!     }
//!   }
//! }
//! ```
//!
//! Add `--passive` to the `args` to forbid any bus transmission (read-only
//! observation only), or `--allow-writes` to additionally expose
//! `knx_write_group` for value writes (the two flags are mutually exclusive).
//! Because the server talks MCP on stdout and logs on stderr, it plugs directly
//! into any MCP client that speaks stdio.

#![warn(missing_docs)]

pub mod model_handle;
pub mod run;
mod secure_group;
pub mod server;
pub mod state;
pub mod tools;
pub mod tools_audit;
pub mod tools_diff;
pub mod tools_groups;
pub mod tools_learn;
pub mod tools_model;
pub mod tools_program;
pub mod warm;

use std::path::PathBuf;
use std::sync::Arc;

use bussard_model::Model;
use bussard_service::{BusService, WritePolicy};
use bussard_transport::{ConnectionConfig, TransportKind};

pub use server::BussardMcp;
pub use state::{READ_MAX_CONCURRENT, READ_MIN_INTERVAL, SharedState};

/// The default source individual address for outgoing `GroupValueRead` frames.
///
/// A high device number in area/line 0 that is unlikely to collide with a real
/// device (bussard acts as a tool, like ETS's `0.0.255`).
pub const DEFAULT_SOURCE_IA: &str = "0.0.255";

/// Configuration for building the MCP server state.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// The directory containing the KNX-as-code model (required).
    pub dir: PathBuf,
    /// The resolved bus connection.
    pub connection: ConnectionConfig,
    /// Passive mode: no `knx_read_group`, no outbound channel.
    pub passive: bool,
    /// Allow bus writes: registers `knx_write_group`. Mutually exclusive with
    /// `passive` (enforced by the CLI).
    pub allow_writes: bool,
    /// Withhold the model-edit tools (`--no-model-edits`). They only write model
    /// files, behind a history snapshot, so they are registered by default in
    /// every tier including `--passive`.
    pub no_model_edits: bool,
    /// Optional capture database to extend `knx_recent_telegrams` history.
    pub capture_db: Option<PathBuf>,
    /// Register the programming tier (`knx_plan_device`, `knx_apply_device`;
    /// issue #118). The CLI refuses it together with `--passive` and applies
    /// the non-loopback write gate before starting.
    pub allow_programming: bool,
    /// The operator passed `--allow-remote-gateway`: the programming tools'
    /// own write-gate check accepts a real gateway.
    pub allow_remote_gateway: bool,
    /// How long a `knx_plan_device` digest stays valid for `knx_apply_device`.
    pub plan_ttl: std::time::Duration,
    /// An ETS `.knxkeys` keyring for KNX Data Secure management (issue #71);
    /// the password comes from `BUSSARD_KEYRING_PASSWORD`.
    pub keyring: Option<PathBuf>,
}

impl McpConfig {
    /// The write policy the server's bus is opened under: transmitting when
    /// `--allow-writes` or `--allow-programming` is set (and the server is not
    /// passive), read-only otherwise. A transmitting policy applies the
    /// non-loopback write gate when the bus is opened (issue #74).
    pub fn write_policy(&self) -> WritePolicy {
        if !self.passive && (self.allow_writes || self.allow_programming) {
            WritePolicy::transmit(self.allow_remote_gateway)
        } else {
            WritePolicy::ReadOnly
        }
    }
}

/// Builds the shared state and the outbound receiver from a config.
///
/// The model must load from `config.dir`; a missing directory or a load error is
/// a hard failure (the server is useless without a model). The bus connection is
/// *not* opened here — that happens in the stream task, which reconnects, so a
/// bus that is down at startup does not stop the server.
///
/// Returns the built state (with no bus handle wired yet — [`run::serve_stdio`]
/// spawns the actor and wires it in).
pub fn build_state(config: &McpConfig) -> anyhow::Result<Arc<SharedState>> {
    if !config.dir.exists() {
        anyhow::bail!(
            "model directory {} not found; the MCP server needs a loaded model (pass --dir)",
            config.dir.display()
        );
    }
    bussard_service::complete_product_models(&config.dir);
    let model = Model::load(&config.dir)
        .map_err(|e| anyhow::anyhow!("failed to load model from {}: {e}", config.dir.display()))?;

    build_state_from_model(model, config)
}

/// Builds state from an already-loaded model (used by tests with an in-code
/// model, and by [`build_state`] after loading from disk).
///
/// The bus handle is not wired here (the actor is spawned by
/// [`run::serve_stdio`]); the status starts as `connecting`.
pub fn build_state_from_model(
    model: Model,
    config: &McpConfig,
) -> anyhow::Result<Arc<SharedState>> {
    let source_ia = DEFAULT_SOURCE_IA
        .parse()
        .expect("DEFAULT_SOURCE_IA is a valid individual address");

    let bus = state::BusStatus::new(config.connection.transport.clone())
        .with_gateway(config.connection.gateway);
    let ring = bussard_monitor::TelegramRing::new();

    let state = Arc::new(SharedState {
        model: model_handle::ModelHandle::new(config.dir.clone(), model),
        dir: config.dir.clone(),
        ring,
        bus,
        passive: config.passive,
        allow_writes: config.allow_writes,
        no_model_edits: config.no_model_edits,
        read_limiter: state::ReadLimiter::new(READ_MIN_INTERVAL, READ_MAX_CONCURRENT),
        capture_db: config.capture_db.clone(),
        source_ia,
        programming: (config.allow_programming && !config.passive).then(|| {
            tools_program::ProgrammingTier::new(
                config.connection.clone(),
                config.allow_remote_gateway,
                config.plan_ttl,
            )
        }),
        keyring: config.keyring.clone(),
    });

    Ok(state)
}

/// Convenience: the transport kind as a stable tag (used in docs/tests).
pub fn transport_tag(kind: &TransportKind) -> &'static str {
    match kind {
        TransportKind::Tunnel => "tunnel",
        TransportKind::Routing => "routing",
    }
}

/// Loads and serves the MCP server over stdio from a [`McpConfig`], blocking
/// until the client disconnects.
///
/// The bus is opened as a [`BusService`] under [`McpConfig::write_policy`], so a
/// write-enabled server against a non-loopback gateway refuses to start without
/// the operator's opt-in, before any bus contact.
pub async fn run(config: &McpConfig) -> anyhow::Result<()> {
    let state = build_state(config)?;
    let service = BusService::open(config.connection.clone(), config.write_policy())?;
    if service.gate() == Some(bussard_transport::write_gate::WriteGate::OptedIn) {
        tracing::warn!(
            "{}",
            bussard_service::guidance::opt_in_warning(&service.gateway_display())
        );
    }
    run::serve_stdio(state, service).await
}

/// The set of tool names exposed, in registration order. Used by tests and docs.
///
/// - passive mode: 22 tools (no bus-touching tools: no `knx_read_group`, no
///   `knx_describe_device`, no `knx_write_group`, no `knx_run_tests`).
///   `knx_infer_group` is there: it only reads the telegram ring. `knx_audit`
///   is there too, but refuses `live: true`.
/// - default mode: 24 tools (adds `knx_read_group` and `knx_describe_device`).
/// - `--allow-writes`: 26 tools (adds `knx_write_group` and `knx_run_tests`).
/// - `--no-model-edits` removes the eight model-edit tools
///   ([`tools_model::MODEL_EDIT_TOOLS`], including the two reservation tools) from
///   any of those (14, 16 and 18 tools).
///
/// The two model/history read tools (`knx_describe_change`, `knx_history`),
/// the two bundle/diff tools (`knx_export_bundle`, `knx_diff_project`) and the
/// eight model-edit tools touch files only, so they are present in every tier
/// including `--passive`.
pub fn tool_names(passive: bool, allow_writes: bool, no_model_edits: bool) -> Vec<&'static str> {
    tool_names_for(passive, allow_writes, no_model_edits, false)
}

/// [`tool_names`] with the programming tier: `allow_programming` appends
/// [`tools_program::PROGRAMMING_TOOLS`] unless the server is passive.
pub fn tool_names_for(
    passive: bool,
    allow_writes: bool,
    no_model_edits: bool,
    allow_programming: bool,
) -> Vec<&'static str> {
    let mut names = vec![
        "knx_project_summary",
        "knx_model_lookup",
        "knx_get_group",
        "knx_get_device",
        "knx_show_device",
        "knx_recent_telegrams",
        "knx_wait_for_telegram",
        "knx_validate",
        "knx_audit",
        "knx_infer_group",
    ];
    if !passive {
        names.push("knx_read_group");
        names.push("knx_describe_device");
    }
    if allow_writes && !passive {
        names.push("knx_write_group");
        names.push("knx_run_tests");
    }
    names.extend(tools_model::MODEL_READ_TOOLS);
    names.extend(tools_diff::DIFF_TOOLS);
    if !no_model_edits {
        names.extend(tools_model::MODEL_EDIT_TOOLS);
    }
    if allow_programming && !passive {
        names.extend(tools_program::PROGRAMMING_TOOLS);
    }
    names
}
