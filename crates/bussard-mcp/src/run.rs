//! Wiring the server to a live bus and the stdio transport.
//!
//! [`serve_stdio`] wires an opened [`BusService`] into the shared state (so tools can read status and call
//! [`ops`](bussard_bus::ops)), feeds the shared ring from a frame subscription,
//! and serves the MCP protocol over stdin/stdout until the client disconnects.

use std::sync::Arc;

use bussard_monitor::DecodedTelegram;
use bussard_service::BusService;
use rmcp::ServiceExt;
use rmcp::transport::io::stdio;

use crate::server::BussardMcp;
use crate::state::SharedState;

/// Wires the bus service into the state, feeds the shared ring from a
/// subscription, and serves the MCP protocol over stdio until the client
/// disconnects, then closes the bus cleanly.
///
/// The service is opened by the caller ([`crate::run`]) under the server's
/// write policy. Its actor reconnects on its own, so a bus that is down at
/// startup does not prevent the server from serving model-only tools.
pub async fn serve_stdio(state: Arc<SharedState>, service: BusService) -> anyhow::Result<()> {
    let handle = service.handle().clone();
    state.bus.wire(service);

    // Feed the shared ring from a frame subscription. Every inbound frame is
    // decoded against the model and pushed with its message code, so
    // `knx_read_group`'s waiter can skip the gateway's L_Data.con echo (#32).
    let ring = state.ring.clone();
    let model = state.model.clone();
    let feeder_handle = handle.clone();
    let feeder = tokio::spawn(async move {
        let mut sub = feeder_handle.subscribe();
        while let Some(inbound) = sub.recv().await {
            let current = model.current();
            let decoded = DecodedTelegram::from_frame(&inbound.frame, Some(&current));
            ring.push_with_code(decoded, inbound.message_code);
        }
    });

    // Serve MCP over stdio. `stdio()` returns (stdin, stdout).
    let server = BussardMcp::new(state);
    tracing::info!("bussard MCP server ready on stdio");
    let running = server
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("failed to start MCP stdio service: {e}"))?;

    let quit_reason = running
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP service error: {e}"))?;
    tracing::info!("MCP client disconnected: {quit_reason:?}");

    // Close the bus cleanly (releasing the gateway tunnel slot) before exit.
    let _ = handle.close().await;
    feeder.abort();
    Ok(())
}
