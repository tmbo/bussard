//! `knx-sim` binary: load an installation config and serve a KNXnet/IP
//! tunnelling gateway backed by the virtual bus.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use knx_sim::bus::event::{EventSink, FanoutSink, TracingSink};
use knx_sim::config::SimConfig;
use knx_sim::net::KnxnetIpServer;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .context("usage: knx-sim <config.yaml>")?;
    let config_path = Path::new(&config_path);
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
    tracing::info!(%addr, "KNXnet/IP tunnelling gateway listening");
    server.serve().context("serving")?;
    Ok(())
}
