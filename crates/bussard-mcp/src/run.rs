//! Wiring the server to a live bus and the stdio transport.
//!
//! [`serve_stdio`] wires an opened [`BusService`] into the shared state (so tools can read status and call
//! [`ops`](bussard_bus::ops)), feeds the shared ring from a frame subscription,
//! and serves the MCP protocol over stdin/stdout until the client disconnects.
//!
//! Secured group telegrams (KNX Data Secure) are unwrapped with the server's
//! keyring on the way into the ring (issue #205 item 5), through the same
//! [`DecodedTelegram::from_frame_secured`] path `bussard learn`, `monitor`
//! and `viz` use, so `knx_wait_for_telegram`, `knx_recent_telegrams` and
//! `knx_infer_group` see the decrypted value and the `secured` fields.

use std::sync::Arc;

use bussard_bus::BusHandle;
use bussard_monitor::{DecodedTelegram, GroupKeyring};
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
    serve_stdio_with_ready(state, service, || {}).await
}

/// [`serve_stdio`], calling `on_ready` right after the "serving on stdio" log
/// line, before the server blocks waiting for the client's `initialize`.
pub async fn serve_stdio_with_ready(
    state: Arc<SharedState>,
    service: BusService,
    on_ready: impl FnOnce(),
) -> anyhow::Result<()> {
    let handle = service.handle().clone();
    state.bus.wire(service);

    let feeder = spawn_ring_feeder(&state, &handle, server_group_keyring(&state));

    // Serve MCP over stdio. `stdio()` returns (stdin, stdout).
    let server = BussardMcp::new(state);
    tracing::info!("mcp: serving on stdio");
    on_ready();
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

/// The server keyring's group keys as a [`GroupKeyring`] for the ring feeder,
/// or `None` without a keyring. A keyring that does not load (no
/// `BUSSARD_KEYRING_PASSWORD`, a wrong password, a missing file) is logged
/// once and the ring keeps secured telegrams encrypted; the tools that need
/// the keys report the same reason on their own.
pub fn server_group_keyring(state: &SharedState) -> Option<GroupKeyring> {
    match crate::secure_group::group_keys(state.keyring.as_deref()) {
        Ok(Some(keys)) => {
            tracing::info!(
                "keyring: {} group key(s) for secured group telegrams",
                keys.len()
            );
            Some(GroupKeyring::new(keys.as_ref().clone()))
        }
        Ok(None) => None,
        Err(reason) => {
            tracing::warn!("secured group telegrams stay encrypted: {reason}");
            None
        }
    }
}

/// Feeds the shared ring from a frame subscription on `handle`.
///
/// Every inbound frame is decoded against the current model, a secured group
/// telegram unwrapped with `keyring` first, and pushed with its message code,
/// so `knx_read_group`'s waiter can skip the gateway's `L_Data.con` echo
/// (#32). The task ends when the bus actor stops; abort it to stop earlier.
pub fn spawn_ring_feeder(
    state: &SharedState,
    handle: &BusHandle,
    keyring: Option<GroupKeyring>,
) -> tokio::task::JoinHandle<()> {
    let ring = state.ring.clone();
    let model = state.model.clone();
    let feeder_handle = handle.clone();
    let mut keyring = keyring;
    tokio::spawn(async move {
        let mut sub = feeder_handle.subscribe();
        while let Some(inbound) = sub.recv().await {
            let current = model.current();
            let decoded = DecodedTelegram::from_frame_secured(
                &inbound.frame,
                Some(&current),
                keyring.as_mut(),
            );
            ring.push_with_code(decoded, inbound.message_code);
        }
    })
}
