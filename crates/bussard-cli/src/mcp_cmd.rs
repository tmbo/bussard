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
pub fn run(
    dir: &Path,
    overrides: ConnOverrides,
    passive: bool,
    allow_writes: bool,
    capture_db: Option<PathBuf>,
) -> anyhow::Result<ExitCode> {
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
        capture_db,
    };

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { bussard_mcp::run(&config).await })?;

    Ok(ExitCode::SUCCESS)
}
