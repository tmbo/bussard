//! The shared application state held behind the axum router.
//!
//! [`AppState`] bundles everything a handler needs: the loaded model (behind a
//! swappable [`ModelHandle`]) and its memoised projection, the [`TrafficHub`],
//! and the optional bus
//! connection ([`BusStatus`]) used for status reporting and group writes. The
//! whole thing is cloneable (`Arc` inside) so axum can share it across handlers.
//!
//! The model lives behind the shared [`ModelHandle`] (the same one the MCP
//! server uses, issue #86): it reloads by itself when the files on disk change, and
//! `POST /api/reload` (issue #65) installs a freshly loaded model explicitly.
//! Every reader (the model/state endpoints, the write gate, the decode feeder)
//! reads through the handle, so a new model is picked up without a restart.

use std::path::Path;
use std::sync::{Arc, Mutex};

use bussard_service::transport::TransportKind;
use bussard_service::transport::bus::{BusHandle, BusState};
use bussard_service::transport::write_gate::is_loopback_gateway;
use bussard_service::{BusService, ModelHandle};
use serde_json::{Value, json};

use crate::project;
use crate::traffic::TrafficHub;

/// The bus connection state as reported over the API, a stable re-projection of
/// the actor's [`BusState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Never yet connected (startup, before the first successful connect).
    Connecting,
    /// Connected and streaming.
    Connected,
    /// Dropped; reconnecting with backoff, or closed.
    Reconnecting,
}

impl ConnState {
    /// Maps the actor's [`BusState`] to the API-facing state.
    fn from_bus(state: BusState) -> Self {
        match state {
            BusState::Connected => ConnState::Connected,
            BusState::Reconnecting | BusState::Closed => ConnState::Reconnecting,
            BusState::Connecting => ConnState::Connecting,
        }
    }

    /// A short, stable lowercase tag for the API.
    pub fn tag(self) -> &'static str {
        match self {
            ConnState::Connecting => "connecting",
            ConnState::Connected => "connected",
            ConnState::Reconnecting => "reconnecting",
        }
    }
}

/// The bus status view for the API.
///
/// Wraps an optional [`BusService`] (opened under the server's write policy, so
/// the non-loopback gate has already been applied) and the configured transport
/// kind. When there is no service (model-only degraded mode, where connection
/// resolution failed) it reports `disconnected` and rejects group writes with
/// `503`.
#[derive(Clone)]
pub struct BusStatus {
    service: Option<BusService>,
    transport: Option<TransportKind>,
    gateway: Option<String>,
    loopback: bool,
}

impl BusStatus {
    /// A status with a live bus service (normal connected/reconnecting mode).
    ///
    /// The gateway is reported as the operator would read it
    /// (`192.0.2.10:3671`, or `multicast 224.0.23.12:3671` for routing) together
    /// with whether it is a loopback address, in `/api/state`, so the page can
    /// name the bus it is about to write to, which `docs/explanation/safety.md` promises of
    /// every write path.
    pub fn connected(service: BusService) -> Self {
        BusStatus {
            transport: Some(service.config().transport.clone()),
            gateway: Some(service.gateway_display()),
            loopback: is_loopback_gateway(service.config()),
            service: Some(service),
        }
    }

    /// A status with no bus (model-only degraded mode). Reports `disconnected`.
    pub fn none() -> Self {
        BusStatus {
            service: None,
            transport: None,
            gateway: None,
            loopback: false,
        }
    }

    /// The current connection state, or `None` when there is no bus at all.
    pub fn state(&self) -> Option<ConnState> {
        self.service
            .as_ref()
            .map(|s| ConnState::from_bus(s.handle().status()))
    }

    /// The bus handle, if a bus is configured.
    pub fn handle(&self) -> Option<&BusHandle> {
        self.service.as_ref().map(BusService::handle)
    }

    /// The bus service, if a bus is configured: group writes go through it.
    pub fn service(&self) -> Option<&BusService> {
        self.service.as_ref()
    }

    /// The transport tag (`tunnel`/`routing`), or `null` with no bus.
    fn transport_tag(&self) -> Option<&'static str> {
        self.transport.as_ref().map(|t| match t {
            TransportKind::Tunnel => "tunnel",
            TransportKind::Routing => "routing",
            TransportKind::DeviceManagement => "device-management",
        })
    }

    /// A JSON object describing the bus status, matching the `state` endpoint's
    /// `bus` block. With no bus the state is `disconnected`, `connected` is
    /// false and `gateway` is `null`.
    pub fn to_json(&self) -> Value {
        let state = match self.state() {
            Some(s) => s.tag(),
            None => "disconnected",
        };
        json!({
            "state": state,
            "transport": self.transport_tag(),
            "connected": self.state() == Some(ConnState::Connected),
            "gateway": self.gateway,
            "loopback": self.loopback,
        })
    }
}

/// The memoised `/api/model` projection of a [`ModelHandle`]: recomputed only
/// when the model's version changes. Cloning shares the cache.
///
/// A `std::sync::Mutex` is deliberate: the lock is held only to compare a
/// version and clone an `Arc`, never across an `await`.
#[derive(Clone, Default)]
pub struct Projection(Arc<Mutex<Option<Versioned>>>);

/// A projection and the model version it was made from.
type Versioned = (u64, Arc<Value>);

impl Projection {
    /// The projection of `model`'s current version, joining the product
    /// models under `dir` (vendor texts, choice labels, defaults) onto the
    /// parameter values, and that version.
    ///
    /// A poisoned lock (a panicking writer) is recovered so a single panic
    /// cannot wedge every reader.
    pub fn get(&self, model: &ModelHandle, dir: &Path) -> (u64, Arc<Value>) {
        let (model, version) = model.snapshot();
        if let Some((cached, json)) = &*self.0.lock().unwrap_or_else(|p| p.into_inner())
            && *cached == version
        {
            return (version, json.clone());
        }
        let products = project::product_models_for(&model, dir);
        let json = Arc::new(project::project_model_with(&model, &products));
        let mut guard = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if guard.as_ref().is_none_or(|(cached, _)| *cached < version) {
            *guard = Some((version, json.clone()));
        }
        (version, json)
    }
}

/// The browser-facing security policy of one viz server.
///
/// The viz server binds an unauthenticated HTTP port that can put telegrams on
/// a real KNX bus, so two things guard it (see [`crate::guard`]):
///
/// * [`allow_writes`](Self::allow_writes) — `POST /api/group-write` answers
///   `403` unless `bussard viz --allow-writes` was passed. A bare `bussard viz`
///   is a viewer, not a controller.
/// * [`allowed_hosts`](Self::allowed_hosts) — extra `Host` header values to
///   accept beyond the always-allowed loopback names and bare IP literals. This
///   is what stops DNS rebinding from making an attacker's page same-origin
///   with `127.0.0.1:8080`.
#[derive(Clone, Debug, Default)]
pub struct Security {
    /// Whether `POST /api/group-write` may put telegrams on the bus.
    pub allow_writes: bool,
    /// Extra `Host` values to accept, lowercased and without a port.
    pub allowed_hosts: Arc<Vec<String>>,
    /// The keyring or key store (`bussard viz --keyring`, issue #172): a
    /// write to a secured GA is sealed under its group key, and secured
    /// telegrams in the live traffic are decrypted. `None` without a keyring.
    /// `Debug` redacts the keys.
    pub group_keys: Option<Arc<bussard_service::keys::KeyStore>>,
}

/// The shared application state, cloned into every handler by axum.
#[derive(Clone)]
pub struct AppState {
    /// The current model, swappable via `POST /api/reload`.
    pub model: ModelHandle,
    /// The memoised `/api/model` projection of [`model`](Self::model).
    pub projection: Projection,
    /// The model directory, re-read by the reload endpoint.
    pub dir: std::path::PathBuf,
    /// The sequenced telegram hub feeding the SSE stream and state endpoint.
    pub hub: TrafficHub,
    /// The bus status (present in connected mode, `none` when degraded).
    pub bus: BusStatus,
    /// The browser-facing security policy (write permission, `Host` allow-list).
    pub security: Security,
}

impl AppState {
    /// The `/api/model` projection of the current model, and its version.
    pub fn model_json(&self) -> (u64, Arc<Value>) {
        self.projection.get(&self.model, &self.dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_state_from_bus() {
        assert_eq!(
            ConnState::from_bus(BusState::Connecting),
            ConnState::Connecting
        );
        assert_eq!(
            ConnState::from_bus(BusState::Connected),
            ConnState::Connected
        );
        assert_eq!(
            ConnState::from_bus(BusState::Reconnecting),
            ConnState::Reconnecting
        );
        assert_eq!(
            ConnState::from_bus(BusState::Closed),
            ConnState::Reconnecting
        );
    }

    #[test]
    fn test_bus_status_none_is_disconnected() {
        let bus = BusStatus::none();
        assert_eq!(bus.state(), None);
        let j = bus.to_json();
        assert_eq!(j["state"], "disconnected");
        assert_eq!(j["connected"], false);
        assert_eq!(j["transport"], Value::Null);
    }

    // --- Projection memo ---------------------------------------------------------

    use std::collections::BTreeMap;

    use bussard_model::Model;
    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A single-GA model: `3/0/4` named `name`.
    fn model_with(name: &str) -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "3/0/4".parse()?,
            Group {
                name: name.to_string(),
                dpt: Some("1.001".parse()?),
                description: None,
                protected: false,
                secure: false,
            },
        );
        Ok(Model {
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
        })
    }

    #[test]
    fn test_projection_get_follows_the_installed_version() -> TestResult {
        let handle = ModelHandle::fixed(model_with("Old")?);
        let projection = Projection::default();
        let dir = Path::new("/nonexistent");
        let (version, before) = projection.get(&handle, dir);
        assert_eq!(version, 1);
        assert_eq!(before["groups"][0]["name"], "Old");
        // Unchanged version: the cached projection itself.
        assert!(Arc::ptr_eq(&before, &projection.get(&handle, dir).1));

        handle.install(model_with("New")?);
        let (version, after) = projection.get(&handle, dir);
        assert_eq!(version, 2);
        assert_eq!(after["groups"][0]["name"], "New");
        // A reader holding the old projection is unaffected by the swap.
        assert_eq!(before["groups"][0]["name"], "Old");
        Ok(())
    }
}
