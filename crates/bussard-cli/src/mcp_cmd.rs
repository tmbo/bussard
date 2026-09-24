//! The `bussard mcp` subcommand: run the read-only MCP server over stdio.
//!
//! The model is required (the server is useless without one). The bus
//! connection is resolved from the model's `bussard.yaml` plus overrides, but is
//! opened lazily by the server's stream task, which reconnects — so a bus that
//! is down at startup does not stop the server. All logging is on stderr
//! (configured in `main`); stdout carries only the MCP wire.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_mcp::McpConfig;
use bussard_model::Model;

use crate::conn_cmd::{ConnOverrides, resolve_config};

/// Runs `bussard mcp`.
///
/// The model-edit tools (`knx_set_group`, `knx_add_link`, …) are registered
/// unless `--no-model-edits` is passed: they write YAML files behind a history
/// snapshot and never touch the bus, so they are safe in every tier.
///
/// With `--allow-writes` the server registers `knx_write_group`, so an LLM can
/// put telegrams on the bus for the whole session. That goes through the same
/// non-loopback gate as `bussard write` (issue #74), applied when the server
/// opens its [`bussard_service::BusService`]: against a real gateway the server
/// refuses to start unless the operator passed `--allow-remote-gateway` or set
/// `BUSSARD_ALLOW_REAL_GATEWAY=1`. `--allow-programming` (issue #118) hands
/// the LLM the table write of `bussard apply`, so it passes the same gate here,
/// and the programming tools check it again on every call. A read-only or
/// `--passive` server never writes, so it is allowed against any gateway.
/// The server's tier flags, bundled so the subcommand's five booleans do not
/// become five positional arguments.
#[derive(Debug, Clone, Copy)]
pub struct McpModes {
    /// Never transmit on the bus.
    pub passive: bool,
    /// Register `knx_write_group`.
    pub allow_writes: bool,
    /// Register the programming tier (`knx_plan_device`, `knx_apply_device`).
    pub allow_programming: bool,
    /// How long a plan digest stays valid.
    pub plan_ttl: std::time::Duration,
    /// Permit `--allow-writes` against a non-loopback gateway.
    pub allow_remote_gateway: bool,
    /// Omit the model-edit tools.
    pub no_model_edits: bool,
}

pub fn run(
    dir: &Path,
    overrides: ConnOverrides,
    modes: McpModes,
    capture_db: Option<PathBuf>,
    keyring: Option<PathBuf>,
) -> anyhow::Result<ExitCode> {
    let McpModes {
        passive,
        allow_writes,
        allow_programming,
        plan_ttl,
        allow_remote_gateway,
        no_model_edits,
    } = modes;
    if !dir.exists() {
        anyhow::bail!(
            "model directory {} not found; the MCP server needs a loaded model (pass --dir)",
            dir.display()
        );
    }
    // Load the model here to resolve the connection config; the server reloads
    // it from the same directory (cheap, and keeps the API uniform).
    let model = Model::load(dir)
        .map_err(|e| anyhow::anyhow!("failed to load model from {}: {e}", dir.display()))?;
    let connection = resolve_config(Some(&model), &overrides)?;

    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection,
        passive,
        allow_writes,
        no_model_edits,
        capture_db,
        allow_programming,
        allow_remote_gateway,
        plan_ttl,
        keyring,
    };

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { bussard_mcp::run(&config).await })?;

    Ok(ExitCode::SUCCESS)
}
