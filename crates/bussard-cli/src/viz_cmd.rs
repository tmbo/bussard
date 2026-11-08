//! The `bussard viz` subcommand: serve the KNX visualization website.
//!
//! The model is required (the site is useless without one, and the protected-GA
//! write gate must never fail open). The bus connection is resolved from the
//! model's `bussard.toml` plus overrides; if resolution fails the server
//! degrades to model-only mode (a warning, `connection: None`) so the plan and
//! debug views still work — group writes then return `503`. Shutdown is graceful
//! on Ctrl-C, closing the bus to free the gateway tunnel slot.

use std::net::SocketAddr;
use std::process::ExitCode;

use anyhow::Context as _;
use bussard_model::Model;
use bussard_viz::VizConfig;

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::resolve_config;

/// `bussard viz`.
#[derive(Debug, clap::Args)]
pub(crate) struct VizArgs {
    /// The address to bind the HTTP server to.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Watch for devices in KNX programming mode and highlight them in the
    /// UI. This periodically broadcasts `A_IndividualAddress_Read` on the
    /// bus (active traffic), so it is off by default and must be enabled
    /// explicitly — never point it at a real installation unattended.
    #[arg(long)]
    watch_prog: bool,
    /// Arm `POST /api/group-write`, so the page can send test writes. Off
    /// by default: a bare `bussard viz` is a viewer and the endpoint
    /// answers 403.
    #[arg(long)]
    allow_writes: bool,
    /// Also answer requests whose `Host` is this name. Repeatable. Loopback
    /// names and bare IP literals are always accepted; any other name is
    /// refused because it is how DNS rebinding reaches this port.
    #[arg(long, value_name = "HOST")]
    allow_host: Vec<String>,
}

impl Run for VizArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self, g)
    }
}

/// Runs `bussard viz`.
///
/// Two options put traffic on the bus, and both go through the same
/// non-loopback write gate as `bussard write` (issue #74):
///
/// * `--allow-writes` arms `POST /api/group-write`;
/// * `--watch-prog` runs the programming-mode watch, a
///   background task that puts a broadcast `A_IndividualAddress_Read` on the
///   bus periodically and surfaces responders in `/api/state` and the `prog`
///   SSE event.
///
/// Both default off, so a bare `bussard viz` never transmits and is allowed
/// against any gateway. With either set and a non-loopback gateway resolved,
/// the server refuses to start without `--allow-remote-gateway` (or
/// `BUSSARD_ALLOW_REAL_GATEWAY=1`).
fn run(options: VizArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (listen, dir, overrides) = (options.listen, g.dir(), g.group());
    if !dir.exists() {
        anyhow::bail!(
            "project folder {} not found; the viz server needs a loaded project (pass --dir)",
            dir.display()
        );
    }
    // Load the model here to resolve the connection config. A present-but-broken
    // model is a hard error: the write gate must not fail open.
    let model = Model::load(dir)
        .map_err(|e| anyhow::anyhow!("failed to load the project from {}: {e}", dir.display()))?;

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

    // The non-loopback write gate is applied when the server opens its
    // `BusService` (`bussard_viz::build_state`): if this server can transmit at
    // all, the operator must have opted in to a non-loopback gateway. Loopback
    // (the simulator, the test suite) is exempt, and a read-only viz is never
    // gated.

    // Say plainly what this server may do; a read-only viewer is the default.
    if options.allow_writes {
        eprintln!("group writes are ENABLED (POST /api/group-write)");
    } else {
        eprintln!("read-only: group writes return 403 (pass --allow-writes to enable them)");
    }

    // A non-loopback bind puts an unauthenticated port on the network. The
    // browser guard still blocks DNS rebinding and cross-origin writes, but
    // anything that can reach the port can read the whole model, so say so.
    if !listen.ip().is_loopback() {
        eprintln!(
            "warning: binding {listen}, which is reachable from the network. \
             The port is unauthenticated: anyone who can reach it can read the \
             whole project{}.",
            if options.allow_writes {
                " and write to the bus"
            } else {
                ""
            }
        );
    }

    let group_keys = g
        .keyring()
        .map(|path| {
            bussard_service::secure::load_keys(path)
                .with_context(|| format!("loading group keys from {}", path.display()))
        })
        .transpose()?;
    if let Some(keys) = &group_keys {
        eprintln!(
            "keyring: {} group key(s) for secured group telegrams",
            keys.group_keys.len()
        );
    }

    let config = VizConfig {
        dir: dir.to_path_buf(),
        listen,
        connection,
        watch_prog: options.watch_prog,
        allow_writes: options.allow_writes,
        allow_remote_gateway: g.allow_remote_gateway,
        allowed_hosts: options.allow_host,
        group_keys,
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

    let (state, handle, watch) = bussard_viz::build_state(&config)?;
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

    // Stop the programming-mode watch task (like the feeder, it is torn down on
    // shutdown), then free the tunnel slot on the way out.
    if let Some(w) = watch {
        w.abort();
    }
    if let Some(service) = handle {
        service.close().await;
    }
    result
}
