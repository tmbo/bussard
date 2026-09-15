//! Wiring the server to a live bus and the stdio transport.
//!
//! [`serve_stdio`] loads nothing itself — it takes an already-built
//! [`SharedState`] — spawns the reconnecting monitor pipeline feeding the shared
//! ring (and applying outbound reads), and serves the MCP protocol over stdin/
//! stdout until the client disconnects.

use std::sync::Arc;
use std::time::Duration;

use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{DecodedTelegram, run_stream_with_outbound};
use bussard_transport::{ConnectionConfig, TimestampedFrame, TransportError};
use rmcp::ServiceExt;
use rmcp::transport::io::stdio;
use tokio::sync::mpsc;

use crate::server::BussardMcp;
use crate::state::{BusStatus, ConnState, SharedState};

/// A sink that pushes every decoded telegram into the shared ring and updates
/// the bus status on connect/disconnect. It never stops the stream itself — the
/// stream lives as long as the server does.
struct RingSink {
    ring: bussard_monitor::TelegramRing,
    bus: BusStatus,
}

impl TelegramSink for RingSink {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, _frame: &TimestampedFrame) -> Flow {
        self.ring.push(telegram.clone());
        Flow::Continue
    }

    fn on_connect(&mut self, reconnect: bool) -> Flow {
        self.bus.set(ConnState::Connected);
        if reconnect {
            tracing::info!("reconnected to the bus");
        } else {
            tracing::info!("connected to the bus");
        }
        Flow::Continue
    }

    fn on_disconnect(&mut self, error: &TransportError, backoff: Duration) -> Flow {
        self.bus.set(ConnState::Reconnecting);
        tracing::warn!(
            "bus connection lost: {error}; retrying in {}s",
            backoff.as_secs()
        );
        // Keep retrying: the MCP server stays up and serves model-only tools.
        Flow::Continue
    }
}

/// Runs the bus stream task and the MCP stdio server concurrently until the MCP
/// client disconnects, then shuts the stream task down.
///
/// `config` is the resolved bus connection. `outbound_rx` is the receiver half
/// of the state's outbound channel (created by the caller alongside the state);
/// pass `None` in passive mode. The bus stream reconnects on its own, so a bus
/// that is down at startup does not prevent the server from serving.
pub async fn serve_stdio(
    state: Arc<SharedState>,
    config: ConnectionConfig,
    outbound_rx: Option<mpsc::UnboundedReceiver<bussard_transport::cemi::CemiFrame>>,
) -> anyhow::Result<()> {
    let model = state.model.clone();
    let ring = state.ring.clone();
    let bus = state.bus.clone();

    // Spawn the reconnecting stream feeding the shared ring.
    let stream_handle = tokio::spawn(async move {
        let mut sink = RingSink { ring, bus };
        // This future only returns if the sink stops it, which it never does, so
        // it runs until the task is aborted at shutdown.
        let _ = run_stream_with_outbound(&config, Some(&model), &mut sink, outbound_rx).await;
    });

    // Serve MCP over stdio. `stdio()` returns (stdin, stdout).
    let server = BussardMcp::new(state);
    tracing::info!("bussard MCP server ready on stdio");
    let running = server
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("failed to start MCP stdio service: {e}"))?;

    // Block until the client disconnects or the transport closes.
    let quit_reason = running
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP service error: {e}"))?;
    tracing::info!("MCP client disconnected: {quit_reason:?}");

    stream_handle.abort();
    Ok(())
}
