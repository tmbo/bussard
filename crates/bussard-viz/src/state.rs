//! The shared application state held behind the axum router.
//!
//! [`AppState`] bundles everything a handler needs: the loaded model, the
//! precomputed `/api/model` projection, the [`TrafficHub`], and the optional bus
//! connection ([`BusStatus`]) used for status reporting and group writes. The
//! whole thing is cloneable (`Arc` inside) so axum can share it across handlers.

use std::sync::Arc;

use bussard_bus::{BusHandle, BusState};
use bussard_model::Model;
use bussard_transport::TransportKind;
use serde_json::{Value, json};

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
}

impl BusStatus {
    /// A status with a live bus handle (normal connected/reconnecting mode).
    pub fn connected(transport: TransportKind, handle: BusHandle) -> Self {
        BusStatus {
            handle: Some(handle),
            transport: Some(transport),
        }
    }

    /// A status with no bus (model-only degraded mode). Reports `disconnected`.
    pub fn none() -> Self {
        BusStatus {
            handle: None,
            transport: None,
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
    /// `bus` block. With no bus the state is `disconnected` and `connected` is
    /// false.
    pub fn to_json(&self) -> Value {
        let state = match self.state() {
            Some(s) => s.tag(),
            None => "disconnected",
        };
        json!({
            "state": state,
            "transport": self.transport_tag(),
            "connected": self.state() == Some(ConnState::Connected),
        })
    }
}

/// The shared application state, cloned into every handler by axum.
#[derive(Clone)]
pub struct AppState {
    /// The loaded model, shared for on-demand decoding and write resolution.
    pub model: Arc<Model>,
    /// The precomputed `/api/model` JSON projection (the model is immutable).
    pub model_json: Arc<Value>,
    /// The sequenced telegram hub feeding the SSE stream and state endpoint.
    pub hub: TrafficHub,
    /// The bus status (present in connected mode, `none` when degraded).
    pub bus: BusStatus,
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
}
