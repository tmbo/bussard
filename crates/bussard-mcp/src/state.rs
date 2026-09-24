//! Shared server state: the loaded model, the live telegram ring, the bus
//! handle (actor), and the read rate limiter.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bussard_bus::{BusHandle, BusState};
use bussard_monitor::TelegramRing;
use bussard_service::BusService;
use bussard_transport::TransportKind;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::model_handle::ModelHandle;

/// Minimum spacing between bus reads (rate limit for `knx_read_group`).
pub const READ_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// Timeout awaiting a `GroupValueResponse` after a `GroupValueRead`.
pub const READ_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Concurrency cap on in-flight bus reads.
pub const READ_MAX_CONCURRENT: usize = 2;

/// The live bus connection state as reported to tools. A thin re-projection of
/// the actor's [`BusState`], kept as a distinct enum so the JSON tags stay
/// stable across the MCP surface.
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
    fn from_bus(state: BusState) -> Self {
        match state {
            BusState::Connected => ConnState::Connected,
            BusState::Reconnecting | BusState::Closed => ConnState::Reconnecting,
            BusState::Connecting => ConnState::Connecting,
        }
    }

    /// A short, stable lowercase tag for tool output.
    pub fn tag(self) -> &'static str {
        match self {
            ConnState::Connecting => "connecting",
            ConnState::Connected => "connected",
            ConnState::Reconnecting => "reconnecting",
        }
    }
}

/// Bus status: a view onto the bus service for tool output.
///
/// Wraps the [`BusService`] (present once the server has wired the bus; opened
/// under the server's write policy, so the non-loopback gate has already been
/// applied) and the configured transport kind. When there is no service (a test
/// that never spawned the actor, or before wiring) it reports `connecting`.
#[derive(Clone)]
pub struct BusStatus {
    /// Wired once by the runner after the service is opened. Cheap to share.
    service: Arc<OnceLock<BusService>>,
    transport: TransportKind,
    /// The tunnelling gateway's control endpoint, when the transport is a
    /// tunnel. Used by `knx_audit` to ask the interface for its tunnel slots.
    gateway: Option<std::net::SocketAddrV4>,
}

impl BusStatus {
    /// Creates a status with no handle yet (reports `connecting`).
    pub fn new(transport: TransportKind) -> Self {
        BusStatus {
            service: Arc::new(OnceLock::new()),
            transport,
            gateway: None,
        }
    }

    /// Creates a status already backed by a live bus service.
    pub fn with_service(transport: TransportKind, service: BusService) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(service);
        BusStatus {
            service: Arc::new(cell),
            transport,
            gateway: None,
        }
    }

    /// Records the tunnelling gateway endpoint (builder style).
    pub fn with_gateway(mut self, gateway: Option<std::net::SocketAddrV4>) -> Self {
        self.gateway = gateway;
        self
    }

    /// The tunnelling gateway endpoint, if one is configured.
    pub fn gateway(&self) -> Option<std::net::SocketAddrV4> {
        self.gateway
    }

    /// Wires the bus service once (called by the runner after opening it). A
    /// second call is a no-op.
    pub fn wire(&self, service: BusService) {
        let _ = self.service.set(service);
    }

    /// The current connection state (from the handle, or `connecting`).
    pub fn state(&self) -> ConnState {
        match self.service.get() {
            Some(s) => ConnState::from_bus(s.handle().status()),
            None => ConnState::Connecting,
        }
    }

    /// The transport kind (tunnel or routing) as a stable tag.
    pub fn transport_tag(&self) -> &'static str {
        match self.transport {
            TransportKind::Tunnel => "tunnel",
            TransportKind::Routing => "routing",
        }
    }

    /// The bus handle, if wired.
    pub fn handle(&self) -> Option<&BusHandle> {
        self.service.get().map(BusService::handle)
    }

    /// The bus service, if wired: the checked group write and management
    /// sessions go through it.
    pub fn service(&self) -> Option<&BusService> {
        self.service.get()
    }

    /// A JSON object describing the bus status.
    pub fn to_json(&self) -> Value {
        json!({
            "state": self.state().tag(),
            "transport": self.transport_tag(),
            "connected": self.state() == ConnState::Connected,
        })
    }
}

/// The read rate limiter: enforces a minimum spacing between bus reads and a
/// concurrency cap.
///
/// `last` is a tokio mutex holding the [`Instant`](tokio::time::Instant) of the
/// last read; `permits` is a semaphore bounding concurrent reads.
pub struct ReadLimiter {
    last: Mutex<Option<tokio::time::Instant>>,
    permits: tokio::sync::Semaphore,
    min_interval: Duration,
}

impl ReadLimiter {
    /// Creates a limiter with the given spacing and concurrency cap.
    pub fn new(min_interval: Duration, max_concurrent: usize) -> Self {
        ReadLimiter {
            last: Mutex::new(None),
            permits: tokio::sync::Semaphore::new(max_concurrent.max(1)),
            min_interval,
        }
    }

    /// Acquires the right to perform one bus read, sleeping until the minimum
    /// interval since the previous read has elapsed. The returned permit must be
    /// held for the duration of the read.
    pub async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
        // Semaphore first (concurrency cap), then spacing (rate).
        let permit = self
            .permits
            .acquire()
            .await
            .expect("read semaphore is never closed");
        let mut last = self.last.lock().await;
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
        }
        *last = Some(tokio::time::Instant::now());
        permit
    }
}

/// All shared state, held behind an `Arc` inside the rmcp server handler.
pub struct SharedState {
    /// The loaded KNX model, behind a handle that reloads it when the files on
    /// disk change. An MCP session outlives many edits of `knx/`, and the
    /// protected-GA gate must follow the source of truth rather than whatever
    /// the directory held at startup. See [`crate::model_handle`].
    pub model: ModelHandle,
    /// The directory the model was loaded from (for diagnostics).
    pub dir: PathBuf,
    /// The live telegram ring buffer, shared with the stream task.
    pub ring: TelegramRing,
    /// The bus connection status (wraps the actor handle when wired).
    pub bus: BusStatus,
    /// Whether the server is in passive mode (no `knx_read_group`, no writes).
    pub passive: bool,
    /// Whether bus writes are allowed (registers `knx_write_group`). Mutually
    /// exclusive with `passive`.
    pub allow_writes: bool,
    /// Whether the model-edit tools are withheld (`--no-model-edits`). They
    /// write model files behind a history snapshot and never touch the bus, so
    /// they are registered by default.
    pub no_model_edits: bool,
    /// The read rate limiter (shared by reads and writes).
    pub read_limiter: ReadLimiter,
    /// Optional capture database path, used to extend `knx_recent_telegrams`
    /// beyond the in-memory ring window.
    pub capture_db: Option<PathBuf>,
    /// The source IA to use for outgoing `GroupValueRead` requests.
    pub source_ia: bussard_model::IndividualAddress,
    /// The programming tier (`--allow-programming`, issue #118): its gate
    /// configuration and the plans produced this session. `None` keeps
    /// `knx_plan_device` and `knx_apply_device` unregistered.
    pub programming: Option<crate::tools_program::ProgrammingTier>,
    /// The ETS `.knxkeys` keyring for KNX Data Secure management
    /// (`bussard mcp --keyring`, issue #71). `knx_describe_device` looks the
    /// target's tool key up in it; the password comes from
    /// `BUSSARD_KEYRING_PASSWORD`. `None` is plain management.
    pub keyring: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_state_maps_from_bus_state() {
        use bussard_bus::BusState;
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
        // A closed actor reads as reconnecting (the server stays up).
        assert_eq!(
            ConnState::from_bus(BusState::Closed),
            ConnState::Reconnecting
        );
    }

    #[test]
    fn bus_status_without_handle_is_connecting() {
        let bus = BusStatus::new(TransportKind::Routing);
        assert_eq!(bus.state(), ConnState::Connecting);
        assert_eq!(bus.transport_tag(), "routing");
        assert_eq!(bus.to_json()["connected"], false);
        assert_eq!(bus.to_json()["state"], "connecting");
    }

    #[tokio::test]
    async fn read_limiter_spaces_reads() {
        // A small real interval keeps the test fast while still measurable.
        let limiter = ReadLimiter::new(Duration::from_millis(60), 2);
        let start = std::time::Instant::now();

        // First acquire: no wait.
        {
            let _p = limiter.acquire().await;
        }
        // Second acquire: must wait ~60ms since the first.
        {
            let _p = limiter.acquire().await;
        }
        // Third acquire: another ~60ms.
        {
            let _p = limiter.acquire().await;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(120),
            "three spaced reads should take >= 120ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn read_limiter_caps_concurrency() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let limiter = Arc::new(ReadLimiter::new(Duration::from_millis(0), 2));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..6 {
            let limiter = limiter.clone();
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            handles.push(tokio::spawn(async move {
                let _p = limiter.acquire().await;
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await?;
        }
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "never more than 2 concurrent reads"
        );
        Ok(())
    }
}
