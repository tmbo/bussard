//! `knx_viz`: the `bussard viz` page, served from inside the MCP server, in
//! every tier including `--passive`.
//!
//! The page is the same axum router `bussard viz` serves
//! ([`bussard_viz::router`]), built by the same state builder
//! ([`bussard_viz::state_with_feed`]) over what this server already holds:
//!
//! * the server's watched model handle, so an edit through a model tool shows
//!   on the page's next request without a second load;
//! * the server's one bus service, whose actor the page's traffic feeder
//!   subscribes to. The page never opens a connection of its own, so it costs
//!   no tunnel slot. A server without a bus serves the page model-only.
//!
//! The page is read-only: `POST /api/group-write` answers `403`, the
//! programming-mode watch never runs, and the `Host` guard accepts loopback
//! names and IP literals only, exactly as a bare `bussard viz`. The first call
//! binds `127.0.0.1:0` (or `bussard mcp --viz-listen`); every later call
//! returns the same URL. The server stops the page when it exits
//! ([`VizPage::stop`]).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use serde_json::json;
use tokio::sync::Mutex;

use crate::server::BussardMcp;
use crate::state::SharedState;

/// The tools this module registers, present in every tier.
pub const VIZ_TOOLS: [&str; 1] = ["knx_viz"];

/// How long a stopping page gets to finish open requests before it is cut.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// The page of one server: where it binds, and the running page once
/// `knx_viz` has started it.
#[derive(Default)]
pub struct VizPage {
    /// `bussard mcp --viz-listen`; `None` binds `127.0.0.1:0`.
    listen: Option<SocketAddr>,
    /// The running page, started by the first `knx_viz`.
    running: Mutex<Option<Running>>,
}

/// A running page and what stops it.
struct Running {
    /// The bound address.
    addr: SocketAddr,
    /// The page's traffic hub; shut down to end open SSE streams.
    hub: bussard_viz::traffic::TrafficHub,
    /// Starts the graceful shutdown of the HTTP server.
    stop: tokio::sync::oneshot::Sender<()>,
    /// The HTTP server task.
    server: tokio::task::JoinHandle<()>,
    /// The traffic feeder, `None` without a bus.
    feeder: Option<tokio::task::JoinHandle<()>>,
}

impl VizPage {
    /// A page that binds `listen` when started, or `127.0.0.1:0` for `None`.
    pub fn new(listen: Option<SocketAddr>) -> Self {
        VizPage {
            listen,
            running: Mutex::new(None),
        }
    }

    /// The address the page binds when started.
    pub fn listen(&self) -> SocketAddr {
        self.listen
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    }

    /// The page's address, starting it over `state` on the first call.
    ///
    /// A page whose server task has ended is started afresh.
    ///
    /// # Errors
    ///
    /// A human reason when the listen address cannot be bound.
    pub async fn start(&self, state: &SharedState) -> Result<SocketAddr, String> {
        let mut running = self.running.lock().await;
        if let Some(page) = running.as_ref()
            && !page.server.is_finished()
        {
            return Ok(page.addr);
        }
        let listen = self.listen();
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("could not bind {listen} for the browser page: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("could not read the browser page's address: {e}"))?;
        if !addr.ip().is_loopback() {
            tracing::warn!(
                "viz: the browser page binds {addr}, which is reachable from the network; \
                 anyone who can reach it can read the whole project"
            );
        }

        let model = bussard_viz::state::ModelHandle::from_shared(
            state.model.clone(),
            Some(state.dir.clone()),
        );
        // A keyring that does not load leaves secured telegrams encrypted on
        // the page, as in the ring (`run::server_group_keyring` logs why).
        let group_keys = crate::secure_group::group_keys(state.keyring.as_deref())
            .ok()
            .flatten();
        let security = bussard_viz::state::Security {
            allow_writes: false,
            allowed_hosts: std::sync::Arc::new(Vec::new()),
            group_keys,
        };
        let (page_state, feeder) = bussard_viz::state_with_feed(
            model,
            state.dir.clone(),
            state.bus.service().cloned(),
            security,
        );
        let hub = page_state.hub.clone();
        let app = bussard_viz::router(page_state);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = stopped.await;
            });
            if let Err(e) = serve.await {
                tracing::warn!("viz: the browser page stopped: {e}");
            }
        });
        tracing::info!("viz: browser page on http://{addr}");
        *running = Some(Running {
            addr,
            hub,
            stop,
            server,
            feeder,
        });
        Ok(addr)
    }

    /// Stops the page, if it runs: ends the open event streams, lets open
    /// requests finish for a moment, then cuts the server and its feeder.
    pub async fn stop(&self) {
        let Some(page) = self.running.lock().await.take() else {
            return;
        };
        let _ = page.stop.send(());
        page.hub.shutdown();
        if let Some(feeder) = &page.feeder {
            feeder.abort();
        }
        let abort = page.server.abort_handle();
        if tokio::time::timeout(STOP_GRACE, page.server).await.is_err() {
            abort.abort();
        }
    }
}

/// The page's URL for `addr`. An unspecified bind (`0.0.0.0`) is named by
/// its loopback address, which the browser on this host can open.
pub fn page_url(addr: SocketAddr) -> String {
    let addr = if addr.ip().is_unspecified() {
        match addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port())),
        }
    } else {
        addr
    };
    format!("http://{addr}")
}

// `pub(crate)`: the router is combined in `BussardMcp::new`.
#[tool_router(router = viz_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_viz`.
    #[tool(
        description = "Open the project in a web browser: starts the page `bussard viz` serves \
        (devices, group addresses, links and live telegrams) inside this server and returns \
        its `url`. Give the human the url to open; it works only in a browser on this \
        computer. The page is read-only: it never writes to the bus, and its live telegrams \
        are the ones this server already receives, without a second bus connection. A second \
        call returns the same url; the page stops when the server stops."
    )]
    async fn knx_viz(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let value = match state.viz.start(state).await {
            Ok(addr) => json!({
                "ok": true,
                "url": page_url(addr),
                "read_only": true,
                "live_traffic": state.bus.service().is_some(),
            }),
            Err(reason) => json!({
                "ok": false,
                "reason": reason,
            }),
        };
        Ok(CallToolResult::structured(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_url_names_loopback_for_unspecified() {
        assert_eq!(
            page_url(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080))),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            page_url(SocketAddr::from((Ipv4Addr::LOCALHOST, 52133))),
            "http://127.0.0.1:52133"
        );
    }

    #[test]
    fn test_viz_page_listen_defaults_to_loopback_any_port() {
        let page = VizPage::default();
        assert_eq!(page.listen(), SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let fixed = SocketAddr::from((Ipv4Addr::LOCALHOST, 8099));
        assert_eq!(VizPage::new(Some(fixed)).listen(), fixed);
    }
}
