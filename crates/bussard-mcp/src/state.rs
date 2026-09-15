//! Shared server state: the loaded model, the live telegram ring, the bus
//! connection status, the outbound-frame channel and the read rate limiter.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use bussard_model::Model;
use bussard_monitor::TelegramRing;
use bussard_transport::TransportKind;
use bussard_transport::cemi::CemiFrame;
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};

/// Minimum spacing between bus reads (rate limit for `knx_read_group`).
pub const READ_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// Timeout awaiting a `GroupValueResponse` after a `GroupValueRead`.
pub const READ_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Concurrency cap on in-flight bus reads.
pub const READ_MAX_CONCURRENT: usize = 2;

/// The live bus connection state, updated by the stream task and read by tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Never yet connected (startup, before the first successful connect).
    Connecting,
    /// Connected and streaming.
    Connected,
    /// Dropped; reconnecting with backoff.
    Reconnecting,
}

impl ConnState {
    fn as_u8(self) -> u8 {
        match self {
            ConnState::Connecting => 0,
            ConnState::Connected => 1,
            ConnState::Reconnecting => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => ConnState::Connected,
            2 => ConnState::Reconnecting,
            _ => ConnState::Connecting,
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

/// Bus status shared between the stream task and the tools, cheaply cloneable.
#[derive(Clone)]
pub struct BusStatus {
    state: Arc<AtomicU8>,
    transport: TransportKind,
}

impl BusStatus {
    /// Creates a status starting in [`ConnState::Connecting`].
    pub fn new(transport: TransportKind) -> Self {
        BusStatus {
            state: Arc::new(AtomicU8::new(ConnState::Connecting.as_u8())),
            transport,
        }
    }

    /// Records a new connection state (called from the stream task).
    pub fn set(&self, state: ConnState) {
        self.state.store(state.as_u8(), Ordering::Relaxed);
    }

    /// The current connection state.
    pub fn state(&self) -> ConnState {
        ConnState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// The transport kind (tunnel or routing) as a stable tag.
    pub fn transport_tag(&self) -> &'static str {
        match self.transport {
            TransportKind::Tunnel => "tunnel",
            TransportKind::Routing => "routing",
        }
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
    /// The loaded KNX model.
    pub model: Model,
    /// The directory the model was loaded from (for diagnostics).
    pub dir: PathBuf,
    /// The live telegram ring buffer, shared with the stream task.
    pub ring: TelegramRing,
    /// The bus connection status.
    pub bus: BusStatus,
    /// Sender for outbound frames (a `GroupValueRead`), or `None` in passive
    /// mode (no writes to the bus at all).
    pub outbound: Option<mpsc::UnboundedSender<CemiFrame>>,
    /// Whether the server is in passive mode (no `knx_read_group`).
    pub passive: bool,
    /// Whether bus writes are allowed (registers `knx_write_group`). Mutually
    /// exclusive with `passive`.
    pub allow_writes: bool,
    /// The read rate limiter (shared by reads and writes).
    pub read_limiter: ReadLimiter,
    /// Optional capture database path, used to extend `knx_recent_telegrams`
    /// beyond the in-memory ring window.
    pub capture_db: Option<PathBuf>,
    /// The source IA to use for outgoing `GroupValueRead` requests.
    pub source_ia: bussard_model::IndividualAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_state_tags_roundtrip() {
        for s in [
            ConnState::Connecting,
            ConnState::Connected,
            ConnState::Reconnecting,
        ] {
            assert_eq!(ConnState::from_u8(s.as_u8()), s);
        }
    }

    #[test]
    fn bus_status_transitions() {
        let bus = BusStatus::new(TransportKind::Routing);
        assert_eq!(bus.state(), ConnState::Connecting);
        assert_eq!(bus.transport_tag(), "routing");
        bus.set(ConnState::Connected);
        assert_eq!(bus.to_json()["connected"], true);
        bus.set(ConnState::Reconnecting);
        assert_eq!(bus.to_json()["state"], "reconnecting");
        assert_eq!(bus.to_json()["connected"], false);
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
    async fn read_limiter_caps_concurrency() {
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
            h.await.unwrap();
        }
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "never more than 2 concurrent reads"
        );
    }
}
