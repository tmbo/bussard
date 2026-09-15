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
//! | `knx_recent_telegrams` | Recent telegrams from the ring (and capture DB). |
//! | `knx_wait_for_telegram` | Block for the next matching telegram ("press the button now"). |
//! | `knx_validate` | Model validation diagnostics as JSON. |
//! | `knx_read_group` | Send a GroupValueRead and return the value (omitted in `--passive`). |
//! | `knx_write_group` | Send a GroupValueWrite (registered only with `--allow-writes`). |
//!
//! In `--passive` mode `knx_read_group` is unregistered, so `tools/list`
//! contains seven tools instead of eight and the server never transmits.
//! `knx_write_group` is registered only when the server is started with
//! `--allow-writes` (which conflicts with `--passive`), making nine tools; it
//! writes to the physical bus and hard-refuses `protected` GAs.
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

pub mod run;
pub mod server;
pub mod state;
pub mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use bussard_model::Model;
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{ConnectionConfig, TransportKind};
use tokio::sync::mpsc;

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
    /// Optional capture database to extend `knx_recent_telegrams` history.
    pub capture_db: Option<PathBuf>,
}

/// Builds the shared state and the outbound receiver from a config.
///
/// The model must load from `config.dir`; a missing directory or a load error is
/// a hard failure (the server is useless without a model). The bus connection is
/// *not* opened here — that happens in the stream task, which reconnects, so a
/// bus that is down at startup does not stop the server.
///
/// Returns the state plus the outbound receiver (`None` in passive mode) to hand
/// to [`run::serve_stdio`].
pub fn build_state(
    config: &McpConfig,
) -> anyhow::Result<(Arc<SharedState>, Option<mpsc::UnboundedReceiver<CemiFrame>>)> {
    if !config.dir.exists() {
        anyhow::bail!(
            "model directory {} not found; the MCP server needs a loaded model (pass --dir)",
            config.dir.display()
        );
    }
    let model = Model::load(&config.dir)
        .map_err(|e| anyhow::anyhow!("failed to load model from {}: {e}", config.dir.display()))?;

    build_state_from_model(model, config)
}

/// Builds state from an already-loaded model (used by tests with an in-code
/// model, and by [`build_state`] after loading from disk).
pub fn build_state_from_model(
    model: Model,
    config: &McpConfig,
) -> anyhow::Result<(Arc<SharedState>, Option<mpsc::UnboundedReceiver<CemiFrame>>)> {
    let source_ia = DEFAULT_SOURCE_IA
        .parse()
        .expect("DEFAULT_SOURCE_IA is a valid individual address");

    let bus = state::BusStatus::new(config.connection.transport.clone());
    let ring = bussard_monitor::TelegramRing::new();

    // In passive mode there is no outbound channel at all.
    let (outbound, outbound_rx) = if config.passive {
        (None, None)
    } else {
        let (tx, rx) = mpsc::unbounded_channel();
        (Some(tx), Some(rx))
    };

    let state = Arc::new(SharedState {
        model,
        dir: config.dir.clone(),
        ring,
        bus,
        outbound,
        passive: config.passive,
        allow_writes: config.allow_writes,
        read_limiter: state::ReadLimiter::new(READ_MIN_INTERVAL, READ_MAX_CONCURRENT),
        capture_db: config.capture_db.clone(),
        source_ia,
    });

    Ok((state, outbound_rx))
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
pub async fn run(config: &McpConfig) -> anyhow::Result<()> {
    let (state, outbound_rx) = build_state(config)?;
    run::serve_stdio(state, config.connection.clone(), outbound_rx).await
}

/// The set of tool names exposed, in registration order. Used by tests and docs.
///
/// - passive mode: 7 tools (no `knx_read_group`, no `knx_write_group`).
/// - default mode: 8 tools (adds `knx_read_group`).
/// - `--allow-writes`: 9 tools (adds `knx_write_group`).
pub fn tool_names(passive: bool, allow_writes: bool) -> Vec<&'static str> {
    let mut names = vec![
        "knx_project_summary",
        "knx_model_lookup",
        "knx_get_group",
        "knx_get_device",
        "knx_recent_telegrams",
        "knx_wait_for_telegram",
        "knx_validate",
    ];
    if !passive {
        names.push("knx_read_group");
    }
    if allow_writes && !passive {
        names.push("knx_write_group");
    }
    names
}
