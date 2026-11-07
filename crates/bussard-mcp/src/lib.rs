//! MCP server for bussard (stdio, or streamable HTTP with `--listen`): KNX
//! model and bus tools, tier-gated.
//!
//! This crate implements the phase-0 Model Context Protocol server described in
//! the design document (§5.5). It loads a KNX-as-code [`Model`] from a directory,
//! spawns the reconnecting bus monitor pipeline feeding a shared
//! `TelegramRing`, and exposes read-only tools
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
//! | `knx_setup` | Onboarding state only: find the gateway, write the model directory and import the ETS export, as `bussard init` does; then the full tool set registers (issue #745). |
//! | `knx_project_summary` | Project name, counts, rooms, GA ranges, bus status, validation counts. |
//! | `knx_model_lookup` | Case-insensitive substring search over the model. |
//! | `knx_get_group` | A GA's definition, links touching it, and its last telegram. |
//! | `knx_get_device` | A device's full definition plus its links. |
//! | `knx_show_device` | A device's channels, and one channel's parameters (choices, defaults) and objects, in its device file's words; optionally as paste-ready TOML; with `live: true` also what `bussard status <ia>` reads over the bus (refused in `--passive`, issue #747). |
//! | `knx_recent_telegrams` | Recent telegrams from the ring (and capture DB). |
//! | `knx_wait_for_telegram` | Block for the next matching telegram ("press the button now"). |
//! | `knx_validate` | Model validation diagnostics as JSON: errors and warnings by default, infos on request, filtered by device or group. |
//! | `knx_audit` | Installation audit: model gaps, one-sided links, mask capabilities, Secure devices; with `live`, tunnel slots and a traffic sample (live refused in `--passive`). |
//! | `knx_scaffold_groups` | Draft or extend `groups.toml` from a room and function list (JSON). |
//! | `knx_reserve_groups` | Reserve the conventional addresses for one room in `groups.toml`. |
//! | `knx_read_group` | Send a GroupValueRead and return the value (omitted in `--passive`). |
//! | `knx_describe_device` | Introspect a device: enumerate its interface objects and each property's description (omitted in `--passive`). |
//! | `knx_infer_group` | Infer a GA's DPT and a proposed name from the traffic seen on it (issue #95). |
//! | `knx_bus_status` | The bus connection in detail: interface, tunnelling user, the last transport error and when, attempts, seconds to the next retry, other `bussard mcp` processes for the model (issue #287). |
//! | `knx_bus_reconnect` | Drop the bus connection and connect afresh now, backoff reset; not a write (omitted in `--passive`, issue #287). |
//! | `knx_write_group` | Send a GroupValueWrite (registered only with `--allow-writes`). |
//! | `knx_run_tests` | Run the model directory's `tests.toml` against the bus (registered only with `--allow-writes`). |
//! | `knx_describe_change` | Pending or between-snapshot model changes, as plain sentences. |
//! | `knx_history` | The model's history snapshots with a one-line summary each. |
//! | `knx_set_group` | Create or update a group address (refuses to rename or retype a protected one). |
//! | `knx_remove_group` | Remove a group address (refuses while linked, and protected ones). |
//! | `knx_add_link` / `knx_remove_link` | Bind or unbind a com object and a GA (refuses protected GAs). |
//! | `knx_set_device` | Rename a device or change its floor/room. |
//! | `knx_set_parameter` | Set one device parameter, checked against the product model. |
//! | `knx_set_interface` | Edit a KNX IP interface's `[knxnet]` table (IP assignment, static settings, friendly name, tunnels), validated before it is saved. |
//! | `knx_undo` | Restore the model files to a history snapshot. |
//! | `knx_discard_edits` | Drop one device's or group address's unapplied edits, leaving the rest. |
//! | `knx_import_file` | Import a `.knxproj`, `.bussard` bundle, `.json` dump, `.knxprod` (or product data by order number, with `download`) or `.knxkeys`, as `bussard import`, `import-product` and `keys import` do (withheld by `--no-model-edits`). |
//! | `knx_export` | Write the bundle, the group plan for ETS, the keyring or the handover documentation, as `bussard export`, `export-groups`, `keys export` and `doc` do. |
//! | `knx_export_bundle` | The bundle form of `knx_export` under its earlier name: the model and history as one `.bussard` handover file. |
//! | `knx_diff_project` | What a received `.knxproj` or bundle would change, as sentences. |
//! | `knx_job_status` | One job of the server's job table, of any tier: `step`, `question`, `done`, `result` (issue #746; registered in every tier). |
//! | `knx_viz` | Start the `bussard viz` page inside the server and return its URL: read-only, fed from the server's own model and bus connection, the same URL on every call ([`tools_viz`]; registered in every tier). |
//! | `knx_backup_device` | Back one device or every device up (tables, bounded parameter memory) under `captures/backups/<timestamp>/`, as `bussard backup` (read-only on the bus; not in `--passive`). |
//! | `knx_reconstruct_device` | Read one device's tables back and diff them against the model, as `bussard reconstruct`; with `line`, sweep a line into a fresh model directory, as `bussard reconstruct --line` (read-only on the bus; not in `--passive`). |
//! | `knx_plan_device` | Read one device's live tables and return the plan `bussard plan` prints, plus a `plan_digest`; with `line`, every device on a line under one digest, as `bussard plan --line` (registered only with `--allow-programming`). |
//! | `knx_find_devices` | Scan one line for devices as `bussard scan`, run as a job: mask, manufacturer and order number per responder, names first (read-only on the bus; not in `--passive`, issue #747). |
//! | `knx_ha_status` | Home Assistant's version, KNX integration, entity counts and the state of the KNX YAML file (registered only with the Home Assistant tier). |
//! | `knx_ha_plan` | What writing the generated KNX YAML would change, per entity, plus a `plan_digest` (Home Assistant tier). |
//! | `knx_ha_apply` | Write the planned KNX YAML (backup first) and reload Home Assistant's KNX integration, only with a fresh matching `plan_digest` (Home Assistant tier). |
//! | `knx_ha_automation_plan` | Render a small rule (when a GA receives a value, send group values) into a bussard-managed Home Assistant automation, plus a `plan_digest` (Home Assistant tier). |
//! | `knx_ha_automation_apply` | Write the planned automation through the config API (previous JSON backed up) and reload automations, only with a fresh matching `plan_digest` (Home Assistant tier). |
//! | `knx_ha_automation_remove` | Plan, then with the digest delete, a bussard-managed automation (Home Assistant tier). |
//! | `knx_apply_device` | Write the planned tables to one device, backup first and verify after, only with a fresh matching `plan_digest`; with `line`, a line plan as one job, as `bussard apply --line` (registered only with `--allow-programming`). |
//! | `knx_apply_status` | One apply job's step, progress and final result (issue #289; registered only with `--allow-programming`). |
//! | `knx_last_apply` | The latest apply job for a device, from the session or its record under `.bussard/history/` (registered only with `--allow-programming`). |
//! | `knx_restore_parameters` | Plan, then with the digest write, the replay of a parameter backup from `captures/backups/parameters/` onto one device: refused on a device, application or mask mismatch, only placed octets, device-managed ones kept, verified by read-back, run as a job (issue #290; registered only with `--allow-programming`). |
//! | `knx_restart_device` | Name the restart form, then with the digest restart one device and wait until it answers, as `bussard restart`, run as a job (issue #717; registered only with `--allow-programming`). |
//! | `knx_restore_tables` | Plan, then with the digest write, a backup's link tables onto one device with `knx_apply_device`'s write and read-back, run as a job (issue #717; registered only with `--allow-programming`). |
//!
//! The ten from `knx_describe_change` to `knx_discard_edits` are model tools: they
//! read and write the model files (TOML) under the model directory and never touch the bus,
//! so they are available in every tier including `--passive`. The eight that
//! edit, `knx_scaffold_groups` and `knx_reserve_groups`, which write
//! `groups.toml`, and `knx_import_file` are withheld by
//! `--no-model-edits`. Every edit snapshots first, validates after, and returns
//! the change as sentences for the caller to quote to the human. The three
//! export tools and `knx_diff_project` only read the model (an export writes
//! one file outside it) and are available in every tier.
//!
//! In `--passive` mode the bus-touching read tools (`knx_read_group`,
//! `knx_describe_device`, `knx_backup_device`, `knx_reconstruct_device` and
//! `knx_find_devices`) are unregistered and the server never transmits;
//! `knx_infer_group` stays, because it only reads the telegram ring, and
//! `knx_audit` and `knx_show_device` stay but refuse `live: true`.
//! `knx_write_group` and `knx_run_tests` are registered only when the server is
//! started with `--allow-writes` (which conflicts with `--passive`); both write
//! to the physical bus, and both hard-refuse `protected` GAs.
//!
//! Started on a missing or empty directory, the server is in its onboarding
//! state ([`onboarding`], issue #745): it registers only `knx_setup`, which
//! runs the setup of `bussard init` (gateway, skeleton, the ETS import), and
//! `knx_bus_status`. After a successful `knx_setup` it registers the full
//! set of the tiers it was started with and sends
//! `notifications/tools/list_changed`.
//!
//! `knx_job_status` reads the server's one job table ([`jobs`], issue #746)
//! and never touches the bus, so it is registered in every tier.
//!
//! `knx_viz` serves the `bussard viz` page from the server's model and its one
//! bus connection, read-only, so it is registered in every tier ([`tools_viz`]).
//!
//! Tool counts per tier: `--passive` 32, default 38, `--allow-writes` 40. With
//! `--no-model-edits` the model-edit and enrolment tools are withheld, giving
//! 18, 24 and 26. [`tier_help::tier_counts`] computes them from this table.
//!
//! `--allow-programming` (issue #118) adds the twelve programming tools
//! ([`Tier::Programming`] in [`TOOLS`]) to any non-passive tier. They write
//! device tables, so they pass the non-loopback write gate on every call, run
//! the source-address probe, and apply only a plan whose digest this session
//! produced minutes ago and which a fresh read still reproduces. The write
//! runs as a job (issue #289) of the server's job table ([`jobs`]):
//! `knx_job_status`, `knx_apply_status` and
//! `knx_last_apply` report it. `knx_restore_parameters` (issue #290) replays
//! a parameter backup with the same plan, digest and job flow, and
//! `knx_restore_tables` and `knx_restart_device` (issue #717) the link tables
//! of a backup and a device restart. `knx_add_device` (issue #749) adds a
//! new device: the wait for the programming button and the identification
//! as a job that pauses for the human's yes, then the address write, the
//! read-back and the device file. `knx_commission_line` (issue #753) runs
//! `bussard commission`'s line walk as one job: per device the button, the
//! order-number check against the model and the address write with its
//! read-back, after one yes for the line.
//! `knx_replace_device` (issue #751) replaces
//! a dead device in the same job shape: the backup snapshot, the wait for the
//! replacement's button and the identification, then after one yes the
//! address, the application, the parameters and links (the plan and apply
//! of `knx_plan_device` and `knx_apply_device`) and the record. See
//! [`tools_program`].
//!
//! `--allow-home-assistant` (issue #280) adds the six Home Assistant tools
//! ([`Tier::HomeAssistant`]) when `bussard.toml` has a `[home_assistant]`
//! table: `knx_ha_status` reads Home Assistant's REST API, `knx_ha_plan`
//! diffs the KNX YAML generated from the model against the file Home
//! Assistant reads, and `knx_ha_apply` writes it (backup first) and reloads
//! the KNX integration, only with a fresh digest from this session. The
//! automation tools ([`tools_ha_automation`]) create, update and remove
//! bussard-managed automations through Home Assistant's config API with the
//! same plan, digest and explicit-yes flow. See [`tools_ha`].
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

pub mod args;
pub mod browser;
pub mod confirm;
pub mod elicit;
pub mod everyday;
pub mod guidance;
pub mod http;
pub mod instances;
pub mod jobs;
pub mod model_handle;
pub mod onboarding;
pub mod param_keys;
pub mod password_form;
pub mod reply;
pub mod run;
mod secure_group;
pub mod server;
pub mod session_edits;
pub mod state;
pub mod tier_help;
pub mod tools;
pub mod tools_audit;
pub mod tools_device;
pub mod tools_diff;
pub mod tools_enroll;
pub mod tools_files;
mod tools_find;
pub mod tools_groups;
pub mod tools_ha;
pub mod tools_ha_automation;
pub mod tools_jobs;
pub mod tools_learn;
pub mod tools_model;
pub mod tools_program;
pub mod tools_viz;
/// The warm management connection (issue #215), kept by the service layer.
pub use bussard_service::warm;

use std::path::PathBuf;
use std::sync::Arc;

use bussard_model::Model;
use bussard_service::transport::{ConnectionConfig, TransportKind};
use bussard_service::{BusService, WritePolicy};

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
    /// Register the Home Assistant tier (`--allow-home-assistant`, issue
    /// #280). It takes effect only when `bussard.toml` also has a
    /// `[home_assistant]` table.
    pub allow_home_assistant: bool,
    /// Where `knx_viz` binds the browser page (`--viz-listen`); `None` binds
    /// `127.0.0.1:0`, a free loopback port.
    pub viz_listen: Option<std::net::SocketAddr>,
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
    let home_assistant = match (
        config.allow_home_assistant,
        model.config.home_assistant.clone(),
    ) {
        (true, Some(table)) => Some(tools_ha::HomeAssistantTier::new(table, config.plan_ttl)),
        (true, None) => {
            tracing::warn!(
                "--allow-home-assistant without a [home_assistant] table in bussard.toml: the \
                 Home Assistant tools stay off"
            );
            None
        }
        (false, _) => None,
    };
    let source_ia = DEFAULT_SOURCE_IA
        .parse()
        .expect("DEFAULT_SOURCE_IA is a valid individual address");

    let bus = state::BusStatus::new(config.connection.transport.clone())
        .with_gateway(config.connection.gateway);
    let ring = bussard_service::monitor::TelegramRing::new();
    let jobs = Arc::new(jobs::JobTable::new());

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
                Arc::clone(&jobs),
            )
        }),
        keyring: config.keyring.clone(),
        home_assistant,
        jobs,
        viz: tools_viz::VizPage::new(config.viz_listen),
    });

    Ok(state)
}

/// Convenience: the transport kind as a stable tag (used in docs/tests).
pub fn transport_tag(kind: &TransportKind) -> &'static str {
    match kind {
        TransportKind::Tunnel => "tunnel",
        TransportKind::Routing => "routing",
        TransportKind::DeviceManagement => "device-management",
    }
}

/// Loads and serves the MCP server over stdio from a [`McpConfig`], blocking
/// until the client disconnects.
///
/// The bus is opened as a [`BusService`] under [`McpConfig::write_policy`], so a
/// write-enabled server against a non-loopback gateway refuses to start without
/// the operator's opt-in, before any bus contact.
pub async fn run(config: &McpConfig) -> anyhow::Result<()> {
    run_with_ready(config, || {}).await
}

/// [`run`], calling `on_ready` once the server has started and is about to
/// wait for a client on stdio (after the model loaded and the bus service
/// opened, so a refused start never reaches it). The CLI uses it to print how
/// to register the server with a client.
pub async fn run_with_ready(config: &McpConfig, on_ready: impl FnOnce()) -> anyhow::Result<()> {
    let state = build_state(config)?;
    // Instance awareness (issue #287): mark this server and warn about another
    // one for the same model directory. Held until the server exits.
    let _instance = instances::register(&config.dir);
    let service = BusService::open(config.connection.clone(), config.write_policy())?;
    if service.gate() == Some(bussard_service::transport::write_gate::WriteGate::OptedIn) {
        tracing::warn!(
            "{}",
            bussard_service::guidance::opt_in_warning(&service.gateway_display())
        );
    }
    run::serve_stdio_with_ready(state, service, on_ready).await
}

/// [`run_with_ready`] over streamable HTTP instead of stdio (issue #265):
/// the same model, tools, tiers and real-gateway write gate, served at
/// [`http::url`] of the bound address until Ctrl-C.
///
/// The listen address is checked first ([`http::HttpOptions::check`]: a
/// non-loopback bind needs `--allow-remote-clients` and a bearer token), so a
/// refused bind never loads the model or touches the bus. `on_ready` gets the
/// bound address once the listener is up.
pub async fn run_http_with_ready(
    config: &McpConfig,
    options: &http::HttpOptions,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> anyhow::Result<()> {
    options.check()?;
    let state = build_state(config)?;
    let _instance = instances::register(&config.dir);
    let service = BusService::open(config.connection.clone(), config.write_policy())?;
    if service.gate() == Some(bussard_service::transport::write_gate::WriteGate::OptedIn) {
        tracing::warn!(
            "{}",
            bussard_service::guidance::opt_in_warning(&service.gateway_display())
        );
    }
    run::serve_http_with_ready(state, service, options, on_ready).await
}

/// Serves the onboarding server (issue #745) over stdio: `--dir` names a
/// missing or empty directory ([`onboarding::is_onboarding_dir`]), so only
/// `knx_setup` and `knx_bus_status` are registered until `knx_setup` has
/// written the model; then the full tool set of `onboarding.config`'s tiers.
/// `on_ready` runs once the server is about to wait for a client.
pub async fn run_onboarding_with_ready(
    onboarding: onboarding::Onboarding,
    on_ready: impl FnOnce(),
) -> anyhow::Result<()> {
    run::serve_onboarding_stdio(onboarding::SetupMcp::new(onboarding), on_ready).await
}

/// [`run_onboarding_with_ready`] over streamable HTTP (issue #265). The
/// listen address is checked first, as in [`run_http_with_ready`].
pub async fn run_onboarding_http_with_ready(
    onboarding: onboarding::Onboarding,
    options: &http::HttpOptions,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> anyhow::Result<()> {
    options.check()?;
    run::serve_onboarding_http(onboarding::SetupMcp::new(onboarding), options, on_ready).await
}

/// The tier a tool belongs to (issue #905): which server flags register it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Every tier, `--passive` included: the model, the ring, the job table.
    Read,
    /// The default tier: transmits read or management traffic, so not in
    /// `--passive`.
    Bus,
    /// `--allow-writes`, never with `--passive`.
    Writes,
    /// Writes the model files or the key store; withheld by
    /// `--no-model-edits`.
    ModelEdit,
    /// `--allow-programming`, never with `--passive`.
    Programming,
    /// `--allow-home-assistant` with a `[home_assistant]` table; never
    /// touches the bus, so `--passive` keeps it.
    HomeAssistant,
}

/// Every tool of the server with its tier, in registration order: the one
/// table [`tool_names`], [`server::BussardMcp::new`] and [`tier_help`] read.
pub const TOOLS: &[(&str, Tier)] = &[
    ("knx_project_summary", Tier::Read),
    ("knx_model_lookup", Tier::Read),
    ("knx_get_group", Tier::Read),
    ("knx_get_device", Tier::Read),
    ("knx_show_device", Tier::Read),
    ("knx_recent_telegrams", Tier::Read),
    ("knx_wait_for_telegram", Tier::Read),
    ("knx_validate", Tier::Read),
    // `knx_audit` refuses `live: true` in passive mode.
    ("knx_audit", Tier::Read),
    // Only reads the telegram ring.
    ("knx_infer_group", Tier::Read),
    ("knx_bus_status", Tier::Read),
    ("knx_read_group", Tier::Bus),
    // Introspection, backups, reconstruction and scans transmit management
    // traffic (issue #717); passive mode leaves the connection to the actor.
    ("knx_describe_device", Tier::Bus),
    ("knx_bus_reconnect", Tier::Bus),
    ("knx_backup_device", Tier::Bus),
    ("knx_reconstruct_device", Tier::Bus),
    ("knx_find_devices", Tier::Bus),
    ("knx_write_group", Tier::Writes),
    // The acceptance suite writes to the bus.
    ("knx_run_tests", Tier::Writes),
    ("knx_describe_change", Tier::Read),
    ("knx_history", Tier::Read),
    ("knx_export_bundle", Tier::Read),
    ("knx_diff_project", Tier::Read),
    ("knx_export", Tier::Read),
    ("knx_job_status", Tier::Read),
    ("knx_viz", Tier::Read),
    ("knx_scaffold_groups", Tier::ModelEdit),
    ("knx_reserve_groups", Tier::ModelEdit),
    ("knx_set_group", Tier::ModelEdit),
    ("knx_remove_group", Tier::ModelEdit),
    ("knx_add_link", Tier::ModelEdit),
    ("knx_remove_link", Tier::ModelEdit),
    ("knx_set_device", Tier::ModelEdit),
    ("knx_set_parameter", Tier::ModelEdit),
    ("knx_set_interface", Tier::ModelEdit),
    ("knx_undo", Tier::ModelEdit),
    ("knx_discard_edits", Tier::ModelEdit),
    // Imports write the model files too (issue #743).
    ("knx_import_file", Tier::ModelEdit),
    // Certificate enrolment writes the key store (issue #732).
    ("knx_enroll_certificates", Tier::ModelEdit),
    ("knx_enroll_status", Tier::ModelEdit),
    ("knx_plan_device", Tier::Programming),
    ("knx_apply_device", Tier::Programming),
    ("knx_add_device", Tier::Programming),
    ("knx_commission_line", Tier::Programming),
    ("knx_replace_device", Tier::Programming),
    ("knx_interface_secure", Tier::Programming),
    ("knx_clear_security_log", Tier::Programming),
    ("knx_apply_status", Tier::Programming),
    ("knx_last_apply", Tier::Programming),
    ("knx_restore_parameters", Tier::Programming),
    ("knx_restart_device", Tier::Programming),
    ("knx_restore_tables", Tier::Programming),
    ("knx_ha_status", Tier::HomeAssistant),
    ("knx_ha_plan", Tier::HomeAssistant),
    ("knx_ha_apply", Tier::HomeAssistant),
    ("knx_ha_automation_plan", Tier::HomeAssistant),
    ("knx_ha_automation_apply", Tier::HomeAssistant),
    ("knx_ha_automation_remove", Tier::HomeAssistant),
];

/// The tools of `tier`, in registration order.
pub fn tools_of(tier: Tier) -> Vec<&'static str> {
    TOOLS
        .iter()
        .filter(|(_, t)| *t == tier)
        .map(|(name, _)| *name)
        .collect()
}

/// The set of tool names exposed, in registration order. Used by tests and docs.
///
/// - passive mode: 32 tools (no [`Tier::Bus`] or [`Tier::Writes`] tools).
///   `knx_infer_group` is there: it only reads the telegram ring.
///   `knx_bus_status` reads the connection state. `knx_audit` is there too,
///   but refuses `live: true`.
/// - default mode: 38 tools (adds the [`Tier::Bus`] tools).
/// - `--allow-writes`: 40 tools (adds `knx_write_group` and `knx_run_tests`).
/// - `--no-model-edits` removes the [`Tier::ModelEdit`] tools from any of
///   those (18, 24 and 26 tools).
pub fn tool_names(passive: bool, allow_writes: bool, no_model_edits: bool) -> Vec<&'static str> {
    tool_names_for(passive, allow_writes, no_model_edits, false)
}

/// [`tool_names`] with the programming tier: `allow_programming` adds the
/// [`Tier::Programming`] tools unless the server is passive.
pub fn tool_names_for(
    passive: bool,
    allow_writes: bool,
    no_model_edits: bool,
    allow_programming: bool,
) -> Vec<&'static str> {
    tool_names_with_ha(
        passive,
        allow_writes,
        no_model_edits,
        allow_programming,
        false,
    )
}

/// [`tool_names_for`] with the Home Assistant tier: `home_assistant` (the
/// `[home_assistant]` table and `--allow-home-assistant` together) adds the
/// [`Tier::HomeAssistant`] tools, also in passive mode.
pub fn tool_names_with_ha(
    passive: bool,
    allow_writes: bool,
    no_model_edits: bool,
    allow_programming: bool,
    home_assistant: bool,
) -> Vec<&'static str> {
    let tiers = guidance::Tiers {
        passive,
        writes: allow_writes && !passive,
        programming: allow_programming && !passive,
        model_edits: !no_model_edits,
        home_assistant,
    };
    TOOLS
        .iter()
        .filter(|(_, tier)| tiers.allows(*tier))
        .map(|(name, _)| *name)
        .collect()
}
