//! `knx-sim serve <config.yaml>` — run the simulated KNX bus as a KNXnet/IP
//! tunnelling gateway so an external tool (e.g. bussard) can scan/flash the
//! simulated devices exactly as it would a real gateway.
//!
//! The [`TracingSink`] prints every telegram and device state change to stdout,
//! giving a live read-only view of the bus (the placeholder for the future HTML
//! visualization).

use std::path::Path;
use std::sync::Arc;

use knx_sim::bus::event::{EventSink, TracingSink};
use knx_sim::config::SimConfig;
use knx_sim::net::KnxnetIpServer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .ok_or("usage: serve <config.yaml>")?;
    let config = SimConfig::from_file(&config_path)?;
    let base_dir = Path::new(&config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let events: Arc<dyn EventSink> = Arc::new(TracingSink);
    let device_count = config.devices.len();
    let bus = config.build_bus(base_dir, events)?;

    let addr: std::net::SocketAddr =
        format!("{}:{}", config.gateway.host, config.gateway.port).parse()?;
    let mut server = KnxnetIpServer::bind(addr, bus)?;
    eprintln!(
        "knx-sim listening on {} with {device_count} device(s)",
        server.local_addr()?
    );
    server.serve()?;
    Ok(())
}
