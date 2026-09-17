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

pub mod api;
pub mod assets;
pub mod error;
pub mod project;
pub mod state;
pub mod traffic;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use bussard_bus::Bus;
use bussard_model::Model;
use bussard_transport::ConnectionConfig;

use crate::state::{AppState, BusStatus};
use crate::traffic::TrafficHub;

/// Configuration for the viz server.
pub struct VizConfig {
    /// The model directory to load (`bussard.yaml`, `groups.yaml`, …).
    pub dir: PathBuf,
    /// The address to bind the HTTP listener to.
    pub listen: SocketAddr,
    /// The resolved bus connection, or `None` for model-only (degraded) mode.
    pub connection: Option<ConnectionConfig>,
}

/// Errors surfaced while starting the viz server.
#[derive(Debug, thiserror::Error)]
pub enum VizError {
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

/// Loads the model and builds the shared [`AppState`], spawning the bus feeder
/// when a connection is configured. Returns the state plus an optional bus
/// handle (the caller closes it on shutdown to free the tunnel slot).
///
/// The model load is a hard error: the server must never run without one.
pub fn build_state(
    config: &VizConfig,
) -> Result<(AppState, Option<bussard_bus::BusHandle>), VizError> {
    let model = Model::load(&config.dir).map_err(|source| VizError::ModelLoad {
        dir: config.dir.display().to_string(),
        source,
    })?;
    let model = Arc::new(model);
    let model_json = Arc::new(project::project_model(&model));
    let hub = TrafficHub::new();

    let (bus, handle) = match &config.connection {
        Some(conn) => {
            let (handle, _task) = Bus::connect(conn.clone());
            let bus = BusStatus::connected(conn.transport.clone(), handle.clone());
            // Spawn the feeder: it fills the hub from the live bus and emits
            // `bus` events on state changes.
            tokio::spawn(traffic::feed(
                hub.clone(),
                handle.clone(),
                model.clone(),
                bus.clone(),
            ));
            (bus, Some(handle))
        }
        None => (BusStatus::none(), None),
    };

    let state = AppState {
        model,
        model_json,
        hub,
        bus,
    };
    Ok((state, handle))
}

/// Loads the model, wires the bus, and serves the HTTP API until the process is
/// asked to shut down (the caller drives shutdown via `serve_with_shutdown`).
///
/// This is the simple path with no shutdown signal: it serves until the
/// listener closes. Binaries that need a Ctrl-C hook use [`build_state`] +
/// [`router`] and axum's `serve` directly.
pub async fn serve(config: VizConfig) -> Result<(), VizError> {
    let (state, handle) = build_state(&config)?;
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|source| VizError::Bind {
            addr: config.listen,
            source,
        })?;

    let result = axum::serve(listener, app).await.map_err(VizError::Serve);

    // Free the tunnel slot on the way out.
    if let Some(h) = handle {
        let _ = h.close().await;
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
        let model = Arc::new(Model {
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
        });
        let model_json = Arc::new(project::project_model(&model));
        AppState {
            model,
            model_json,
            hub: TrafficHub::new(),
            bus: BusStatus::none(),
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
        let v: &Value = state.model_json.as_ref();
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
                name: "Jalousie".to_string(),
                dpt: dpt.map(|d| d.parse().expect("dpt")),
                description: None,
                protected,
            },
        );
        let model = Arc::new(Model {
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
        });
        let model_json = Arc::new(project::project_model(&model));
        AppState {
            model,
            model_json,
            hub: TrafficHub::new(),
            bus: BusStatus::none(),
        }
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
}
