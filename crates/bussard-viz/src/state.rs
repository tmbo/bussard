//! The shared application state held behind the axum router.
//!
//! [`AppState`] bundles everything a handler needs: the loaded model (behind a
//! swappable [`ModelHandle`]), the [`TrafficHub`], and the optional bus
//! connection ([`BusStatus`]) used for status reporting and group writes. The
//! whole thing is cloneable (`Arc` inside) so axum can share it across handlers.
//!
//! The model was originally immutable for the process lifetime. To support
//! `POST /api/reload` (issue #65) it now lives behind a [`ModelHandle`]: an
//! `Arc<RwLock<Arc<ModelSnapshot>>>` whose reloads swap atomically. Every reader
//! (the model/state endpoints, the write gate, the decode feeder) reads through
//! the handle, so a swap is picked up immediately without restarting the server.

use std::sync::{Arc, RwLock};

use bussard_bus::{BusHandle, BusState};
use bussard_model::Model;
use bussard_transport::TransportKind;
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
/// Wraps an optional bus [`BusHandle`] and the configured transport kind. When
/// there is no handle (model-only degraded mode, where connection resolution
/// failed) it reports `disconnected` and rejects group writes with `503`.
#[derive(Clone)]
pub struct BusStatus {
    handle: Option<BusHandle>,
    transport: Option<TransportKind>,
    gateway: Option<String>,
    loopback: bool,
}

impl BusStatus {
    /// A status with a live bus handle (normal connected/reconnecting mode).
    ///
    /// `gateway` is the resolved endpoint as the operator would read it
    /// (`192.0.2.10:3671`, or `multicast 224.0.23.12:3671` for routing) and
    /// `loopback` says whether that endpoint is a loopback address. Both are
    /// reported in `/api/state` so the page can name the bus it is about to
    /// write to, which `docs/SAFETY.md` promises of every write path.
    pub fn connected(
        transport: TransportKind,
        gateway: String,
        loopback: bool,
        handle: BusHandle,
    ) -> Self {
        BusStatus {
            handle: Some(handle),
            transport: Some(transport),
            gateway: Some(gateway),
            loopback,
        }
    }

    /// A status with no bus (model-only degraded mode). Reports `disconnected`.
    pub fn none() -> Self {
        BusStatus {
            handle: None,
            transport: None,
            gateway: None,
            loopback: false,
        }
    }

    /// The current connection state, or `None` when there is no bus at all.
    pub fn state(&self) -> Option<ConnState> {
        self.handle
            .as_ref()
            .map(|h| ConnState::from_bus(h.status()))
    }

    /// The bus handle, if a bus is configured.
    pub fn handle(&self) -> Option<&BusHandle> {
        self.handle.as_ref()
    }

    /// The transport tag (`tunnel`/`routing`), or `null` with no bus.
    fn transport_tag(&self) -> Option<&'static str> {
        self.transport.as_ref().map(|t| match t {
            TransportKind::Tunnel => "tunnel",
            TransportKind::Routing => "routing",
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

/// An immutable, versioned snapshot of the loaded model and its projection.
///
/// A reload builds a fresh snapshot (bumping [`version`](ModelSnapshot::version))
/// and swaps it into the [`ModelHandle`] in one move, so a reader never sees a
/// half-updated model or a projection that disagrees with its model.
pub struct ModelSnapshot {
    /// The loaded model, shared for on-demand decoding and write resolution.
    pub model: Arc<Model>,
    /// The precomputed `/api/model` JSON projection of [`model`](Self::model).
    pub json: Arc<Value>,
    /// A monotonically increasing version, bumped on every successful reload.
    /// The initial snapshot is version 1.
    pub version: u64,
}

impl ModelSnapshot {
    /// Builds a snapshot from a model, precomputing its `/api/model` projection.
    pub fn new(model: Model, version: u64) -> Self {
        let model = Arc::new(model);
        let json = Arc::new(project::project_model(&model));
        ModelSnapshot {
            model,
            json,
            version,
        }
    }
}

/// A swappable handle to the current [`ModelSnapshot`].
///
/// Cloning is cheap (an `Arc`). Readers call [`current`](Self::current) to grab
/// the live snapshot (an `Arc` clone under a short read lock, never held across
/// an `.await`); a reload calls [`swap`](Self::swap) to install a new snapshot.
///
/// A `std::sync::RwLock` is deliberate: every access is synchronous and holds
/// the lock only long enough to clone one `Arc`, so it never blocks the async
/// runtime. This mirrors [`TrafficHub`]'s own `std::sync::RwLock` for its GA
/// state map and avoids pulling in `arc-swap` (not in the dependency tree).
#[derive(Clone)]
pub struct ModelHandle {
    inner: Arc<RwLock<Arc<ModelSnapshot>>>,
}

impl ModelHandle {
    /// Creates a handle wrapping an initial model snapshot (version 1).
    pub fn new(model: Model) -> Self {
        ModelHandle {
            inner: Arc::new(RwLock::new(Arc::new(ModelSnapshot::new(model, 1)))),
        }
    }

    /// Returns the current snapshot, cloning the inner `Arc` under a read lock.
    ///
    /// The lock is poisoned only if a writer panicked mid-swap; we recover the
    /// guard so a single panic cannot wedge every reader.
    pub fn current(&self) -> Arc<ModelSnapshot> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Atomically replaces the current snapshot with `next`.
    ///
    /// Only ever called after `Model::load` succeeds, so a broken model never
    /// reaches this method (the reload handler keeps serving the old one).
    pub fn swap(&self, next: Arc<ModelSnapshot>) {
        let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
        *guard = next;
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
}

/// The shared application state, cloned into every handler by axum.
#[derive(Clone)]
pub struct AppState {
    /// The current model snapshot, swappable via `POST /api/reload`.
    pub model: ModelHandle,
    /// The model directory, re-read by the reload endpoint.
    pub dir: std::path::PathBuf,
    /// The sequenced telegram hub feeding the SSE stream and state endpoint.
    pub hub: TrafficHub,
    /// The bus status (present in connected mode, `none` when degraded).
    pub bus: BusStatus,
    /// The browser-facing security policy (write permission, `Host` allow-list).
    pub security: Security,
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

    // --- ModelHandle swap semantics -----------------------------------------

    use std::collections::BTreeMap;

    use bussard_model::GroupAddress;
    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    /// A single-GA model: `3/0/4` named `name`, optionally `protected`.
    fn model_with(name: &str, protected: bool) -> Model {
        let ga: GroupAddress = "3/0/4".parse().expect("ga");
        let mut groups = BTreeMap::new();
        groups.insert(
            ga,
            Group {
                name: name.to_string(),
                dpt: Some("1.001".parse().expect("dpt")),
                description: None,
                protected,
                secure: false,
            },
        );
        Model {
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
        }
    }

    #[test]
    fn test_model_handle_initial_version_is_one() {
        let handle = ModelHandle::new(model_with("A", false));
        assert_eq!(handle.current().version, 1);
    }

    #[test]
    fn test_model_handle_swap_installs_new_snapshot_and_version() {
        let handle = ModelHandle::new(model_with("Old", false));
        let before = handle.current();
        assert_eq!(before.version, 1);
        assert_eq!(before.json["stats"]["groups"], 1);

        // A reload builds the next snapshot at version 2 and swaps it in.
        let next = Arc::new(ModelSnapshot::new(model_with("New", false), 2));
        handle.swap(next);

        let after = handle.current();
        assert_eq!(after.version, 2);
        // The precomputed projection tracks the new model.
        assert_eq!(after.json["groups"][0]["name"], "New");
        // The old snapshot Arc still points at the old model (readers holding it
        // are unaffected by the swap).
        assert_eq!(before.json["groups"][0]["name"], "Old");
    }

    #[test]
    fn test_model_handle_swap_reflects_new_protected_flag() {
        // The protected-GA gate reads through the handle, so a newly protected
        // GA must be visible immediately after a swap.
        let ga: GroupAddress = "3/0/4".parse().expect("ga");
        let handle = ModelHandle::new(model_with("Living Room Blind", false));
        assert!(
            !handle
                .current()
                .model
                .groups
                .groups
                .get(&ga)
                .expect("ga")
                .protected
        );

        handle.swap(Arc::new(ModelSnapshot::new(
            model_with("Living Room Blind", true),
            2,
        )));

        assert!(
            handle
                .current()
                .model
                .groups
                .groups
                .get(&ga)
                .expect("ga")
                .protected,
            "the swapped-in model's protected flag must be visible"
        );
    }
}
