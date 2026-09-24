//! The `bussard viz` web server: a self-contained KNX installation viewer.
//!
//! [`serve`] loads nothing itself — it takes a [`VizConfig`] (a model directory,
//! a listen address, and an optional resolved [`ConnectionConfig`]) and:
//!
//! 1. loads the [`Model`](bussard_model::Model) and precomputes the `/api/model`
//!    projection ([`project`]),
//! 2. optionally spawns the [`Bus`](bussard_bus::Bus) actor and a feeder that
//!    fills the [`TrafficHub`](traffic::TrafficHub) from the live bus,
//! 3. builds the axum [`router`] and serves it until the listener closes.
//!
//! When the connection config is `None` (resolution failed, or the caller chose
//! model-only mode) the server still serves every read-only view; group writes
//! return `503`. The frontend is embedded ([`assets`]) so the binary is
//! self-contained and works offline.
//!
//! ## Who may write
//!
//! The port is unauthenticated, so two things stand between a browser and the
//! bus:
//!
//! * `POST /api/group-write` answers `403 writes_disabled` unless
//!   [`VizConfig::allow_writes`] is set (`bussard viz --allow-writes`). The CLI
//!   runs the non-loopback write gate before setting it, so the viz write path
//!   is gated exactly like `bussard write`.
//! * [`guard`] rejects requests whose `Host` this server does not answer to
//!   (DNS rebinding) and state-changing requests from a foreign `Origin`
//!   (CSRF), both with `403 forbidden`.
//!
//! ## HTTP routes
//!
//! | Method | Path | Purpose |
//! |--------|------|---------|
//! | GET | `/` | the `index.html` shell |
//! | GET | `/assets/{file}` | an embedded JS/CSS/HTML/JSON asset |
//! | GET | `/api/model` | the precomputed model projection |
//! | GET | `/api/state` | bus status + last value per GA |
//! | GET | `/api/traffic` | the SSE telegram/bus/gap stream |
//! | POST | `/api/group-write` | encode + send a `GroupValueWrite` |
//! | POST | `/api/reload` | reload the model from disk and swap it atomically |

pub mod api;
pub mod assets;
pub mod error;
pub mod guard;
pub mod project;
pub mod state;
pub mod traffic;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use bussard_model::Model;
use bussard_service::{BusService, WritePolicy};
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::WriteGate;

use crate::state::{AppState, BusStatus, ModelHandle, Security};
use crate::traffic::TrafficHub;

/// Configuration for the viz server.
pub struct VizConfig {
    /// The model directory to load (`bussard.toml`, `groups.toml`, …).
    pub dir: PathBuf,
    /// The address to bind the HTTP listener to.
    pub listen: SocketAddr,
    /// The resolved bus connection, or `None` for model-only (degraded) mode.
    pub connection: Option<ConnectionConfig>,
    /// Whether to run the programming-mode watch: a background probe that puts a
    /// broadcast `A_IndividualAddress_Read` on the bus every few seconds and
    /// surfaces responders in `/api/state`'s `prog` field and the `prog` SSE
    /// event. DEFAULT OFF — the probe generates active bus traffic and must never
    /// run unnoticed against a real installation. Only takes effect when a bus is
    /// configured.
    pub watch_prog: bool,
    /// Whether `POST /api/group-write` may put telegrams on the bus. DEFAULT
    /// OFF: a bare `bussard viz` is a viewer, and the write endpoint answers
    /// `403` until `--allow-writes` is passed. With this or
    /// [`watch_prog`](Self::watch_prog) set, the bus is opened as a
    /// transmitting [`BusService`], which applies the non-loopback write gate,
    /// so the viz write path is gated exactly like `bussard write`.
    pub allow_writes: bool,
    /// The operator's opt-in to a non-loopback gateway for a transmitting
    /// server (`--allow-remote-gateway`); `BUSSARD_ALLOW_REAL_GATEWAY=1` also
    /// opts in.
    pub allow_remote_gateway: bool,
    /// Extra `Host` header values to accept beyond loopback names and IP
    /// literals. Empty in the normal case; see [`guard`] for why this matters.
    pub allowed_hosts: Vec<String>,
    /// The keyring's group keys for KNX Data Secure group communication
    /// (`--keyring`, issue #172): secured writes and decrypted live traffic.
    pub group_keys: Option<bussard_service::GroupKeys>,
}

/// Errors surfaced while starting the viz server.
#[derive(Debug, thiserror::Error)]
pub enum VizError {
    /// The bus could not be opened: the non-loopback write gate refused a
    /// transmitting server (issue #74).
    #[error(transparent)]
    Bus(#[from] bussard_service::ServiceError),

    /// The model failed to load. The server must not start without one: the
    /// protected-GA gate would otherwise fail open.
    #[error("failed to load model from {dir}: {source}")]
    ModelLoad {
        /// The directory that failed to load.
        dir: String,
        /// The underlying load error.
        source: bussard_model::LoadError,
    },

    /// Binding the TCP listener failed.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The HTTP server exited with an error.
    #[error("http server error: {0}")]
    Serve(#[source] std::io::Error),
}

/// Builds the axum router over a ready [`AppState`].
///
/// Exposed for tests so a handler can be driven with `tower::ServiceExt::oneshot`
/// without binding a socket. Production code goes through [`serve`].
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{file}", get(serve_asset))
        .route("/api/model", get(api::get_model))
        .route("/api/state", get(api::get_state))
        .route("/api/traffic", get(api::get_traffic))
        .route("/api/group-write", post(api::post_group_write))
        .route("/api/reload", post(api::post_reload))
        // The browser guard runs before every handler: a `Host` allow-list on
        // all requests, an `Origin` check on the state-changing ones. See
        // [`guard`] for the threat model it closes.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            guard::guard,
        ))
        .with_state(state)
}

/// `GET /` — the `index.html` shell.
async fn index() -> Html<&'static str> {
    Html(assets::INDEX_HTML)
}

/// `GET /assets/{file}` — an embedded asset, or `404` for an unknown name.
async fn serve_asset(Path(file): Path<String>, State(_): State<AppState>) -> Response {
    match assets::asset(&file) {
        Some(a) => {
            let mut resp = a.body.into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(a.content_type),
            );
            resp
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// What [`build_state`] returns: the shared [`AppState`], the optional bus handle
/// (the caller closes it on shutdown to free the tunnel slot), and the optional
/// [`JoinHandle`](tokio::task::JoinHandle) for the programming-mode watch task
/// (the caller aborts it on shutdown, like the feeder is torn down). Both
/// optionals are `None` in model-only mode.
pub type BuiltState = (
    AppState,
    Option<BusService>,
    Option<tokio::task::JoinHandle<()>>,
);

/// Loads the model and builds the shared [`AppState`], spawning the bus feeder
/// (and, when `watch_prog` is set, the programming-mode watch) when a connection
/// is configured. See [`BuiltState`] for the returned handles.
///
/// The model load is a hard error: the server must never run without one. The
/// model is watched, so an edit on disk (a `protected: true` added) is in force
/// on the next write even without `POST /api/reload`.
///
/// The bus is opened as a [`BusService`]: transmitting (and so behind the
/// non-loopback write gate) when `allow_writes` or `watch_prog` is set,
/// read-only otherwise. A refused gate is [`VizError::Bus`], before any bus
/// contact and before the listener binds.
///
/// Must be called from within a tokio runtime (it spawns the bus actor).
pub fn build_state(config: &VizConfig) -> Result<BuiltState, VizError> {
    let model = Model::load(&config.dir).map_err(|source| VizError::ModelLoad {
        dir: config.dir.display().to_string(),
        source,
    })?;
    let model = ModelHandle::watching(config.dir.clone(), model);
    let hub = TrafficHub::new();
    let group_keys = config.group_keys.clone().map(std::sync::Arc::new);

    let (bus, handle, watch) = match &config.connection {
        Some(conn) => {
            let policy = if config.allow_writes || config.watch_prog {
                WritePolicy::transmit(config.allow_remote_gateway)
            } else {
                WritePolicy::ReadOnly
            };
            let service = BusService::open(conn.clone(), policy)?;
            if service.gate() == Some(WriteGate::OptedIn) {
                tracing::warn!(
                    "writing to non-loopback gateway {} (opt-in acknowledged)",
                    service.gateway_display()
                );
            }
            let handle = service.handle().clone();
            let bus = BusStatus::connected(service.clone());
            // Spawn the feeder: it fills the hub from the live bus and emits
            // `bus` events on state changes. It resolves names through the
            // `ModelHandle`, so a reload swap is reflected on the next telegram.
            tokio::spawn(traffic::feed_secured(
                hub.clone(),
                handle.clone(),
                model.clone(),
                bus.clone(),
                group_keys
                    .as_deref()
                    .map(|keys| bussard_monitor::GroupKeyring::new(keys.clone())),
            ));
            // Spawn the programming-mode watch only when explicitly enabled: it
            // puts active broadcast reads on the bus, so it is opt-in via
            // `--watch-prog` and must never run unnoticed against a real
            // installation.
            let watch = if config.watch_prog {
                Some(tokio::spawn(traffic::watch_prog(
                    hub.clone(),
                    handle.clone(),
                )))
            } else {
                None
            };
            (bus, Some(service), watch)
        }
        None => (BusStatus::none(), None, None),
    };

    let state = AppState {
        model,
        dir: config.dir.clone(),
        hub,
        bus,
        security: Security {
            allow_writes: config.allow_writes,
            allowed_hosts: std::sync::Arc::new(
                config
                    .allowed_hosts
                    .iter()
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect(),
            ),
            group_keys,
        },
    };
    Ok((state, handle, watch))
}

/// Loads the model, wires the bus, and serves the HTTP API until the process is
/// asked to shut down (the caller drives shutdown via `serve_with_shutdown`).
///
/// This is the simple path with no shutdown signal: it serves until the
/// listener closes. Binaries that need a Ctrl-C hook use [`build_state`] +
/// [`router`] and axum's `serve` directly.
pub async fn serve(config: VizConfig) -> Result<(), VizError> {
    let (state, handle, watch) = build_state(&config)?;
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|source| VizError::Bind {
            addr: config.listen,
            source,
        })?;

    let result = axum::serve(listener, app).await.map_err(VizError::Serve);

    // Stop the programming-mode watch, then free the tunnel slot on the way out.
    if let Some(w) = watch {
        w.abort();
    }
    if let Some(service) = handle {
        service.close().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Groups, Links};
    use serde_json::Value;

    /// A minimal empty-model state for router tests.
    fn empty_state() -> AppState {
        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups: BTreeMap::new(),
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };
        AppState {
            model: ModelHandle::new(model),
            dir: std::path::PathBuf::from("."),
            hub: TrafficHub::new(),
            bus: BusStatus::none(),
            // Tests drive the handlers directly; writes are enabled so the
            // write-path assertions below reach the gate they are about.
            security: Security {
                allow_writes: true,
                allowed_hosts: std::sync::Arc::new(Vec::new()),
                group_keys: None,
            },
        }
    }

    #[test]
    fn test_router_builds() {
        // Building the router must not panic (route table is well-formed).
        let _ = router(empty_state());
    }

    #[test]
    fn test_empty_model_projection_shape() {
        let state = empty_state();
        let snapshot = state.model.current();
        let v: &Value = snapshot.json.as_ref();
        assert_eq!(v["stats"]["devices"], 0);
        assert_eq!(v["stats"]["groups"], 0);
        assert!(v["devices"].as_array().expect("devices").is_empty());
    }

    // --- oneshot handler tests (drive the router without binding a socket) ---

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Sends a request through the router and returns the (status, body-bytes).
    async fn call(state: AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = router(state)
            .oneshot(req)
            .await
            .expect("router responds infallibly");
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
            .to_vec();
        (status, bytes)
    }

    /// Parses a JSON body, failing the test on malformed JSON.
    fn json(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("valid JSON body")
    }

    #[tokio::test]
    async fn test_index_serves_html() {
        let (status, body) = call(
            empty_state(),
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The embedded index is HTML (real or placeholder).
        assert!(
            String::from_utf8_lossy(&body).contains('<'),
            "index looks like HTML"
        );
    }

    #[tokio::test]
    async fn test_model_endpoint_has_contract_keys() {
        let (status, body) = call(
            empty_state(),
            Request::builder()
                .uri("/api/model")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v = json(&body);
        for key in ["project", "stats", "ranges", "devices", "groups"] {
            assert!(v.get(key).is_some(), "model missing key {key}");
        }
    }

    #[tokio::test]
    async fn test_state_endpoint_reports_disconnected() {
        let (status, body) = call(
            empty_state(),
            Request::builder()
                .uri("/api/state")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v = json(&body);
        assert_eq!(v["bus"]["state"], "disconnected");
        assert_eq!(v["bus"]["connected"], false);
        assert_eq!(v["seq"], 0);
        // With no watch running the prog set is an empty array (never absent).
        assert_eq!(v["prog"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_state_endpoint_reports_prog_set() {
        // With devices observed in programming mode, /api/state.prog carries
        // their individual addresses (sorted, BTreeSet order).
        use bussard_model::IndividualAddress;
        let state = empty_state();
        let set: std::collections::BTreeSet<IndividualAddress> = ["1.1.7", "1.1.2"]
            .iter()
            .map(|s| s.parse().expect("ia"))
            .collect();
        assert!(state.hub.set_prog_if_changed(set));

        let (status, body) = call(
            state,
            Request::builder()
                .uri("/api/state")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v = json(&body);
        assert_eq!(v["prog"], serde_json::json!(["1.1.2", "1.1.7"]));
    }

    /// Builds a POST /api/group-write request from a JSON body.
    fn write_req(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/group-write")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    /// A single-GA state: `3/0/4` with a DPT, optionally protected.
    fn state_with_ga(protected: bool, dpt: Option<&str>) -> AppState {
        use bussard_model::GroupAddress;
        use bussard_model::schema::Group;
        let mut groups = BTreeMap::new();
        let ga: GroupAddress = "3/0/4".parse().expect("ga");
        groups.insert(
            ga,
            Group {
                name: "Living Room Blind".to_string(),
                dpt: dpt.map(|d| d.parse().expect("dpt")),
                description: None,
                protected,
                secure: false,
            },
        );
        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };
        AppState {
            model: ModelHandle::new(model),
            dir: std::path::PathBuf::from("."),
            hub: TrafficHub::new(),
            bus: BusStatus::none(),
            // Tests drive the handlers directly; writes are enabled so the
            // write-path assertions below reach the gate they are about.
            security: Security {
                allow_writes: true,
                allowed_hosts: std::sync::Arc::new(Vec::new()),
                group_keys: None,
            },
        }
    }

    // --- the browser guard (Host allow-list + Origin check) ------------------

    /// The same single-GA state, but read-only (no `--allow-writes`).
    fn read_only_state() -> AppState {
        let mut state = state_with_ga(false, Some("1.008"));
        state.security = Security {
            allow_writes: false,
            allowed_hosts: std::sync::Arc::new(Vec::new()),
            group_keys: None,
        };
        state
    }

    #[tokio::test]
    async fn test_group_write_without_allow_writes_is_403() {
        let (status, body) = call(
            read_only_state(),
            write_req(serde_json::json!({"address": "3/0/4", "value": "down"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "writes_disabled");
    }

    #[tokio::test]
    async fn test_foreign_host_is_refused() {
        // A DNS-rebinding request carries the attacker's name in Host.
        let req = Request::builder()
            .uri("/api/model")
            .header("host", "evil.example:8080")
            .body(Body::empty())
            .expect("request");
        let (status, body) = call(empty_state(), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn test_loopback_hosts_are_accepted() {
        for host in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
            let req = Request::builder()
                .uri("/api/model")
                .header("host", host)
                .body(Body::empty())
                .expect("request");
            let (status, _) = call(empty_state(), req).await;
            assert_eq!(status, StatusCode::OK, "Host {host} must be accepted");
        }
    }

    #[tokio::test]
    async fn test_cross_origin_group_write_is_refused() {
        let req = Request::builder()
            .method("POST")
            .uri("/api/group-write")
            .header("host", "127.0.0.1:8080")
            .header("origin", "https://evil.example")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"address": "3/0/4", "value": "down"}).to_string(),
            ))
            .expect("request");
        let (status, body) = call(state_with_ga(false, Some("1.008")), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn test_cross_origin_reload_is_refused() {
        // `post_reload` takes no body, so it is reachable by a plain form POST
        // from any page unless the Origin check stops it.
        let req = Request::builder()
            .method("POST")
            .uri("/api/reload")
            .header("host", "127.0.0.1:8080")
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .expect("request");
        let (status, body) = call(empty_state(), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn test_same_origin_post_is_allowed_through_the_guard() {
        let req = Request::builder()
            .method("POST")
            .uri("/api/group-write")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"address": "3/0/4", "value": "down"}).to_string(),
            ))
            .expect("request");
        let (status, _) = call(state_with_ga(false, Some("1.008")), req).await;
        // The guard lets it through; the write itself fails on the absent bus.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_state_names_the_gateway() {
        let (status, body) = call(
            empty_state(),
            Request::builder()
                .uri("/api/state")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Model-only mode: no bus, so the gateway is explicitly null rather
        // than absent (the field is part of the contract either way).
        let v = json(&body);
        assert!(v["bus"].get("gateway").is_some(), "gateway key present");
        assert!(v["bus"]["gateway"].is_null());
    }

    #[tokio::test]
    async fn test_group_write_protected_403() {
        let (status, body) = call(
            state_with_ga(true, Some("1.008")),
            write_req(serde_json::json!({"address": "3/0/4", "value": "down"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "protected");
    }

    #[tokio::test]
    async fn test_group_write_no_dpt_422() {
        let (status, body) = call(
            state_with_ga(false, None),
            write_req(serde_json::json!({"address": "3/0/4", "value": "down"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json(&body)["error"]["code"], "no_dpt");
    }

    #[tokio::test]
    async fn test_group_write_bus_unavailable_503() {
        // Unprotected, DPT present, value valid — but there is no bus.
        let (status, body) = call(
            state_with_ga(false, Some("1.008")),
            write_req(serde_json::json!({"address": "3/0/4", "value": "down"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json(&body)["error"]["code"], "bus_unavailable");
    }

    #[tokio::test]
    async fn test_group_write_bad_address_400() {
        let (status, body) = call(
            state_with_ga(false, Some("1.008")),
            write_req(serde_json::json!({"address": "not-a-ga", "value": "down"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_bad_value_400() {
        // Valid GA + DPT, but the value cannot be parsed for DPT 1.008.
        let (status, body) = call(
            state_with_ga(false, Some("1.008")),
            write_req(serde_json::json!({"address": "3/0/4", "value": "not-up-or-down"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_value_and_payload_both_400() {
        // Providing both value and payload is a mutual-exclusivity 400.
        let (status, body) = call(
            state_with_ga(false, Some("1.001")),
            write_req(serde_json::json!({"address": "3/0/4", "value": "on", "payload": "01"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_neither_value_nor_payload_400() {
        let (status, body) = call(
            state_with_ga(false, Some("1.001")),
            write_req(serde_json::json!({"address": "3/0/4"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_payload_bad_hex_400() {
        let (status, body) = call(
            state_with_ga(false, Some("1.001")),
            write_req(serde_json::json!({"address": "3/0/4", "payload": "zz"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_payload_size_mismatch_400() {
        // DPT 1.001 is 1 bit / 1 byte; a 2-byte payload is rejected.
        let (status, body) = call(
            state_with_ga(false, Some("1.001")),
            write_req(serde_json::json!({"address": "3/0/4", "payload": "0001"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"]["code"], "bad_request");
    }

    #[tokio::test]
    async fn test_group_write_payload_protected_403() {
        // The protected gate applies to raw writes identically.
        let (status, body) = call(
            state_with_ga(true, Some("1.001")),
            write_req(serde_json::json!({"address": "3/0/4", "payload": "01"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"]["code"], "protected");
    }

    #[tokio::test]
    async fn test_group_write_payload_no_dpt_reaches_bus() {
        // A raw write with no DPT anywhere is ALLOWED (not a 422): it passes
        // validation and only fails at the send step with 503 (no bus here).
        let (status, body) = call(
            state_with_ga(false, None),
            write_req(serde_json::json!({"address": "3/0/4", "payload": "abcd"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json(&body)["error"]["code"], "bus_unavailable");
    }

    #[tokio::test]
    async fn test_group_write_payload_known_dpt_valid_reaches_bus() {
        // A raw write whose length matches the known DPT passes validation and
        // reaches the send step (503 without a bus). This is the raw happy path.
        let (status, body) = call(
            state_with_ga(false, Some("9.001")),
            write_req(serde_json::json!({"address": "3/0/4", "payload": "0c1a"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json(&body)["error"]["code"], "bus_unavailable");
    }

    #[tokio::test]
    async fn test_unknown_asset_404() {
        let (status, _) = call(
            empty_state(),
            Request::builder()
                .uri("/assets/secret.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_asset_served_with_content_type() {
        let resp = router(empty_state())
            .oneshot(
                Request::builder()
                    .uri("/assets/main.js")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("responds");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .expect("content-type")
            .to_str()
            .expect("ascii");
        assert!(ct.contains("javascript"), "got {ct}");
    }

    #[tokio::test]
    async fn test_sse_stream_framing() {
        // Publish two telegrams, then open the SSE stream and read the opening
        // frames: a `bus` event, then the replayed `telegram` events with ids.
        use bussard_model::IndividualAddress;
        use bussard_model::codec::TypedValue;
        use bussard_monitor::DecodedTelegram;
        use bussard_monitor::decode::{ApciKind, DestinationRef};
        use std::time::SystemTime;

        let state = empty_state();
        let ia: IndividualAddress = "1.1.30".parse().expect("ia");
        let ga: bussard_model::GroupAddress = "3/2/0".parse().expect("ga");
        let telegram = DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia,
            source_name: None,
            destination: DestinationRef::Group(ga),
            destination_name: None,
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(TypedValue::Bool {
                value: true,
                label: "On",
            }),
            dpt: Some("1.001".parse().expect("dpt")),
            object_name: None,
            decode_note: None,
            secure: None,
        };
        state.hub.publish(&telegram);
        state.hub.publish(&telegram);

        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/traffic?backlog=50")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("responds");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .expect("content-type")
            .to_str()
            .expect("ascii");
        assert!(ct.contains("text/event-stream"), "got {ct}");

        // Read just the first data frame from the streaming body (the opening
        // `bus` event and the replay are already buffered; we don't drain the
        // never-ending live tail).
        let mut body = resp.into_body().into_data_stream();
        let mut raw = String::new();
        use futures_util::StreamExt as _;
        while let Some(chunk) = body.next().await {
            let bytes = chunk.expect("chunk");
            raw.push_str(&String::from_utf8_lossy(&bytes));
            // Stop once we've seen both replayed telegrams (avoid the live tail).
            if raw.matches("telegram").count() >= 2 {
                break;
            }
        }
        // Normalize `field: value` / `field:value` spacing before asserting.
        let collected = raw.replace(": ", ":");
        assert!(
            collected.contains("event:bus"),
            "SSE has a bus event: {raw}"
        );
        assert!(
            collected.contains("event:telegram"),
            "SSE has telegram events: {raw}"
        );
        assert!(collected.contains("id:1"), "first telegram has id 1: {raw}");
        assert!(
            collected.contains("id:2"),
            "second telegram has id 2: {raw}"
        );
    }

    #[tokio::test]
    async fn test_sse_stream_ends_on_hub_shutdown() {
        // An open SSE connection must END when the hub broadcasts Shutdown;
        // otherwise it is a never-ending in-flight request that holds axum's
        // graceful shutdown open forever (the Ctrl-C hang).
        let state = empty_state();
        let hub = state.hub.clone();

        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/traffic?backlog=0")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("responds");
        assert_eq!(resp.status(), StatusCode::OK);

        hub.shutdown();

        // Drain the body: it must reach the end (next() -> None) promptly
        // instead of pending forever on the live tail.
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            use futures_util::StreamExt as _;
            let mut body = resp.into_body().into_data_stream();
            while let Some(chunk) = body.next().await {
                let _ = chunk.expect("chunk");
            }
        })
        .await;
        assert!(drained.is_ok(), "SSE stream did not end on hub shutdown");
    }

    // --- POST /api/reload ----------------------------------------------------

    use std::io::Write as _;
    use std::path::Path;

    /// Builds an AppState whose model is loaded from an on-disk directory, so a
    /// reload re-reads that same directory (empty dirs load fine).
    fn state_from_dir(dir: &Path) -> AppState {
        let model = Model::load(dir).expect("model loads from dir");
        AppState {
            model: ModelHandle::new(model),
            dir: dir.to_path_buf(),
            hub: TrafficHub::new(),
            bus: BusStatus::none(),
            // Tests drive the handlers directly; writes are enabled so the
            // write-path assertions below reach the gate they are about.
            security: Security {
                allow_writes: true,
                allowed_hosts: std::sync::Arc::new(Vec::new()),
                group_keys: None,
            },
        }
    }

    /// Writes a valid one-group `groups.toml` into `dir`.
    fn write_valid_groups(dir: &Path) {
        let mut f = std::fs::File::create(dir.join("groups.toml")).expect("create groups.toml");
        // A single declared group with a DPT and a name.
        writeln!(
            f,
            "groups:\n  3/0/4:\n    name: Living Room Blind\n    dpt: \"1.008\""
        )
        .expect("write groups.toml");
    }

    /// A POST request with no body to `uri`.
    fn empty_post(uri: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn test_reload_success_200_shape_and_version() -> Result<(), Box<dyn std::error::Error>> {
        // Start from an empty dir (version 1, zero groups), then add a group on
        // disk and reload: the swap must report the new stats and version 2.
        let tmp = tempfile::tempdir()?;
        let state = state_from_dir(tmp.path());
        assert_eq!(state.model.current().version, 1);
        assert_eq!(state.model.current().json["stats"]["groups"], 0);

        write_valid_groups(tmp.path());

        let handle = state.model.clone();
        let (status, body) = call(state, empty_post("/api/reload")).await;
        assert_eq!(status, StatusCode::OK);
        let v = json(&body);
        assert_eq!(v["ok"], true);
        assert_eq!(v["model_version"], 2);
        assert_eq!(v["stats"]["groups"], 1);

        // The swap is visible through the shared handle.
        assert_eq!(handle.current().version, 2);
        assert_eq!(handle.current().json["stats"]["groups"], 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_reload_broken_yaml_422_keeps_old_model() -> Result<(), Box<dyn std::error::Error>>
    {
        // Load a good one-group model, then corrupt groups.toml on disk and
        // reload: the response is 422 model_invalid and the old model survives.
        let tmp = tempfile::tempdir()?;
        write_valid_groups(tmp.path());
        let state = state_from_dir(tmp.path());
        assert_eq!(state.model.current().version, 1);
        assert_eq!(state.model.current().json["stats"]["groups"], 1);

        // Corrupt the file: not valid YAML for the Groups schema.
        std::fs::write(tmp.path().join("groups.toml"), b": : not yaml : :\n")?;

        let handle = state.model.clone();
        let (status, body) = call(state, empty_post("/api/reload")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json(&body)["error"]["code"], "model_invalid");
        assert!(
            json(&body)["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("groups.toml"),
            "the rich LoadError names the offending file: {}",
            String::from_utf8_lossy(&body)
        );

        // The good model is untouched: still version 1, still one group.
        assert_eq!(handle.current().version, 1);
        assert_eq!(handle.current().json["stats"]["groups"], 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_reload_emits_model_sse_event() -> Result<(), Box<dyn std::error::Error>> {
        // A successful reload publishes a `model` event on the hub carrying the
        // new model_version and stats. Subscribe first, then reload.
        use crate::traffic::HubEvent;

        let tmp = tempfile::tempdir()?;
        let state = state_from_dir(tmp.path());
        let mut rx = state.hub.subscribe();
        write_valid_groups(tmp.path());

        let (status, _) = call(state, empty_post("/api/reload")).await;
        assert_eq!(status, StatusCode::OK);

        // Drain until the model event arrives (nothing else is published here).
        let mut found = None;
        while let Ok(ev) = rx.try_recv() {
            if let HubEvent::Model(v) = ev {
                found = Some(v);
                break;
            }
        }
        let v = found.ok_or("no model event published")?;
        assert_eq!(v["model_version"], 2);
        assert_eq!(v["stats"]["groups"], 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_sse_model_event_framing() -> Result<(), Box<dyn std::error::Error>> {
        // A `model` HubEvent frames on the SSE stream as `event: model` with a
        // JSON data line carrying model_version + stats. The model event is a
        // live broadcast (not backlogged), so publish it AFTER the handler has
        // subscribed: open the stream first, then publish on the shared hub.
        let state = empty_state();
        let hub = state.hub.clone();

        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/traffic?backlog=50")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("responds");
        assert_eq!(resp.status(), StatusCode::OK);

        // The handler has subscribed by the time the response is produced; the
        // model event now lands in the live tail.
        hub.publish_model(serde_json::json!({"model_version": 7, "stats": {"groups": 2}}));

        let mut body = resp.into_body().into_data_stream();
        let mut raw = String::new();
        use futures_util::StreamExt as _;
        while let Some(chunk) = body.next().await {
            let bytes = chunk.expect("chunk");
            raw.push_str(&String::from_utf8_lossy(&bytes));
            if raw.contains("model_version") {
                break;
            }
        }
        let collected = raw.replace(": ", ":");
        assert!(
            collected.contains("event:model"),
            "SSE has a model event: {raw}"
        );
        assert!(
            raw.contains("\"model_version\":7"),
            "model event carries model_version: {raw}"
        );
        Ok(())
    }
}
