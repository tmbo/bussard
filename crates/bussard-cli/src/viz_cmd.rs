//! The `bussard viz` subcommand: serve the KNX visualization website.
//!
//! The model is required (the site is useless without one, and the protected-GA
//! write gate must never fail open). The bus connection is resolved from the
//! model's `bussard.yaml` plus overrides; if resolution fails the server
//! degrades to model-only mode (a warning, `connection: None`) so the plan and
//! debug views still work — group writes then return `503`. Shutdown is graceful
//! on Ctrl-C, closing the bus to free the gateway tunnel slot.

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use bussard_model::Model;
use bussard_viz::VizConfig;

use crate::conn_cmd::{ConnOverrides, resolve_config};

/// Runs `bussard viz`.
pub fn run(listen: SocketAddr, dir: &Path, overrides: ConnOverrides) -> anyhow::Result<ExitCode> {
    if !dir.exists() {
        anyhow::bail!(
            "model directory {} not found; the viz server needs a loaded model (pass --dir)",
            dir.display()
        );
    }
    // Load the model here to resolve the connection config. A present-but-broken
    // model is a hard error: the write gate must not fail open.
    let model = Model::load(dir)
        .map_err(|e| anyhow::anyhow!("failed to load model from {}: {e}", dir.display()))?;

    // Resolve the connection; on failure degrade to model-only mode.
    let connection = match resolve_config(Some(&model), &overrides) {
        Ok(conn) => Some(conn),
        Err(e) => {
            tracing::warn!(
                "no bus connection ({e}); serving model-only (group writes will return 503)"
            );
            None
        }
    };

    let config = VizConfig {
        dir: dir.to_path_buf(),
        listen,
        connection,
    };

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { serve_with_ctrl_c(config).await })?;

    Ok(ExitCode::SUCCESS)
}

/// Serves the viz site until Ctrl-C, then shuts down gracefully and closes the
/// bus (freeing the gateway tunnel slot).
async fn serve_with_ctrl_c(config: VizConfig) -> anyhow::Result<()> {
    let (state, handle) = bussard_viz::build_state(&config)?;
    let app = bussard_viz::router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {e}", config.listen))?;
    let addr = listener.local_addr().unwrap_or(config.listen);
    tracing::info!("bussard viz serving on http://{addr}");
    eprintln!("bussard viz serving on http://{addr} (Ctrl-C to stop)");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown requested");
    };

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("http server error: {e}"));

    // Free the tunnel slot on the way out.
    if let Some(h) = handle {
        let _ = h.close().await;
    }
    result
}
