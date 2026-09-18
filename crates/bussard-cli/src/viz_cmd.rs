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
///
/// Shutdown has two layers: on the first Ctrl-C the hub broadcasts
/// [`HubEvent::Shutdown`] so every open SSE stream ends (otherwise those
/// never-ending in-flight requests hold axum's graceful shutdown open
/// forever), and a backstop force-exits if a second Ctrl-C arrives or the
/// grace period elapses before the graceful path completes.
async fn serve_with_ctrl_c(config: VizConfig) -> anyhow::Result<()> {
    /// How long the graceful path gets before the backstop gives up on it.
    const GRACE: std::time::Duration = std::time::Duration::from_secs(3);

    let (state, handle) = bussard_viz::build_state(&config)?;
    let hub = state.hub.clone();
    let app = bussard_viz::router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {e}", config.listen))?;
    let addr = listener.local_addr().unwrap_or(config.listen);
    tracing::info!("bussard viz serving on http://{addr}");
    eprintln!("bussard viz serving on http://{addr} (Ctrl-C to stop)");

    let shutdown = {
        let hub = hub.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown requested");
            eprintln!("\nshutting down (Ctrl-C again to force)");
            // End every open SSE stream so graceful shutdown can complete.
            hub.shutdown();
        }
    };

    // Backstop: every concurrent `ctrl_c()` listener fires on each SIGINT, so
    // this future observes the FIRST Ctrl-C alongside the graceful path, then
    // force-exits on a SECOND Ctrl-C or when the grace period elapses.
    let force = async {
        let _ = tokio::signal::ctrl_c().await;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => eprintln!("second Ctrl-C, forcing exit"),
            _ = tokio::time::sleep(GRACE) => eprintln!("grace period elapsed, forcing exit"),
        }
    };

    let serve = axum::serve(listener, app).with_graceful_shutdown(shutdown);
    let result = tokio::select! {
        r = serve => r.map_err(|e| anyhow::anyhow!("http server error: {e}")),
        // Dropping the serve future closes the listener and all connections.
        _ = force => Ok(()),
    };

    // Free the tunnel slot on the way out.
    if let Some(h) = handle {
        let _ = h.close().await;
    }
    result
}
