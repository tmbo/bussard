//! Shared entrypoint for the simulator binaries.
//!
//! Both the `knx-sim` and `serve` binaries are thin wrappers around
//! [`run_from_first_arg`], which loads an installation config and serves a
//! KNXnet/IP tunnelling gateway backed by the virtual bus. Keeping the logic
//! here (rather than duplicated in two `main.rs` files) lets the two binary
//! names share one implementation without Cargo warning about a source file
//! bound to multiple targets.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::bus::event::{EventSink, FanoutSink, TracingSink};
use crate::config::SimConfig;
use crate::net::KnxnetIpServer;

/// Initialize the process-wide tracing subscriber for the simulator binaries.
///
/// The `TracingSink` publishes every telegram and device state change at
/// `info` level; without a subscriber that stream is invisible. The filter is
/// taken from `RUST_LOG` (env-filter), defaulting to `info` so the read-only
/// bus view is on by default. Safe to call once at process start.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

/// Load the config named by the process's first CLI argument and serve the
/// KNXnet/IP tunnelling gateway forever. Initializes tracing first.
pub fn run_from_first_arg() -> Result<()> {
    init_tracing();
    let config_path = std::env::args()
        .nth(1)
        .context("usage: knx-sim <config.yaml>")?;
    serve_config(Path::new(&config_path))
}

/// Load `config_path`, build the virtual bus, and serve until a socket error.
pub fn serve_config(config_path: &Path) -> Result<()> {
    let base_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

    let cfg = SimConfig::from_file(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;

    // The observable event stream: log every telegram + state change to stdout.
    // A future HTML visualization is just another EventSink added to this fan-out.
    let events: Arc<dyn EventSink> = Arc::new(FanoutSink::new(vec![Arc::new(TracingSink)]));

    let bus = cfg
        .build_bus(base_dir, events.clone())
        .context("building virtual bus")?;
    tracing::info!(devices = bus.device_count(), "virtual bus ready");

    let addr: SocketAddr = format!("{}:{}", cfg.gateway.host, cfg.gateway.port)
        .parse()
        .context("parsing gateway host:port")?;
    let mut server = KnxnetIpServer::bind(addr, bus).context("binding KNXnet/IP server")?;
    if let Some(secure) = &cfg.gateway.secure {
        server
            .enable_secure(secure)
            .context("enabling KNXnet/IP Secure")?;
        tracing::info!(
            %addr,
            users = secure.users.len(),
            secure_only = secure.secure_only,
            tcp = secure.tcp,
            udp = secure.udp,
            "KNXnet/IP Secure tunnelling"
        );
    }
    tracing::info!(%addr, "KNXnet/IP tunnelling gateway listening");
    server.serve().context("serving")?;
    Ok(())
}
