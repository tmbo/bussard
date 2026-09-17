//! The bus-service actor: a single owner of the [`bussard_transport::Transport`]
//! providing frame subscriptions, sends with completion, and exclusive leases
//! for connection-oriented management sessions.
//!
//! # Why an actor
//!
//! `bussard_transport`'s [`BusConnection::recv`](bussard_transport::BusConnection::recv)
//! is single-consumer: whoever calls it takes the frame. That destroys group
//! traffic for everyone else during a connection-oriented management (layer-4)
//! session, and forces every frontend (monitor, MCP, `scan`/`assign`) to open
//! its own tunnel — colliding on slot-limited gateways. This crate owns *one*
//! [`Transport`](bussard_transport::Transport) inside a task and fans inbound
//! frames out over a broadcast channel, so a monitor, an MCP ring, and an active
//! L4 session can all observe the bus at once.
//!
//! # The handle API
//!
//! [`Bus::connect`] spawns the actor and returns a cloneable [`BusHandle`]:
//!
//! - [`subscribe`](BusHandle::subscribe) — a broadcast of every inbound
//!   `(TimestampedFrame, MessageCode)`; multiple concurrent consumers.
//! - [`send`](BusHandle::send) — completes against the tunnel's `TUNNELING_ACK`
//!   (returning a [`SendReceipt`]), with a **staleness cutoff**: a frame queued
//!   while the actor is reconnecting is dropped with [`BusError::Stale`] after
//!   [`STALE_CUTOFF`] rather than firing seconds late.
//! - [`lease`](BusHandle::lease) — an exclusive [`BusLease`] for one L4 session
//!   at a time. Leases serialize only against *other leases*; independent group
//!   [`send`](BusHandle::send)s and [`subscribe`](BusHandle::subscribe)rs are
//!   unaffected.
//! - [`assigned_individual_address`](BusHandle::assigned_individual_address) and
//!   [`status`](BusHandle::status) — the tunnel-assigned IA and connected /
//!   reconnecting state.
//! - [`close`](BusHandle::close) — awaits the transport `DISCONNECT` on a single
//!   close path (the #31 tunnel-slot guarantee), so a graceful shutdown never
//!   opens a fresh tunnel just to close it.
//!
//! The [`ops`] module holds the shared `read_group` / `write_group`
//! implementations the CLI and MCP both call (echo-skip, rate-limit hooks);
//! policy (protected / `--force` / passive) stays at the edges.

#![warn(missing_docs)]

pub mod ops;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bussard_transport::cemi::{CemiFrame, MessageCode};
use bussard_transport::{
    BusConnection, ConnectionConfig, TimestampedFrame, Transport, TransportError,
};
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// How long a frame may sit queued (waiting for a live connection) before the
/// actor drops it rather than transmitting it stale. Keeps a write queued during
/// a reconnect from firing an actuator seconds after the caller gave up.
pub const STALE_CUTOFF: Duration = Duration::from_secs(2);

/// The initial reconnect backoff.
const BACKOFF_START: Duration = Duration::from_secs(1);
/// The maximum reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Depth of the inbound broadcast channel. Subscribers that fall behind this far
/// lag (older frames dropped) rather than blocking the actor.
const BROADCAST_DEPTH: usize = 1024;

/// An inbound frame as fanned out to subscribers: the timestamped cEMI frame
/// plus its cEMI message code.
///
/// The message code distinguishes a real bus indication (`L_Data.ind`) from the
/// gateway's local confirmation echo of our own request (`L_Data.con`) — a
/// consumer waiting on a GA must skip the echo (issue #32).
#[derive(Debug, Clone)]
pub struct InboundFrame {
    /// The timestamped cEMI frame.
    pub frame: TimestampedFrame,
    /// The cEMI message code the frame arrived with.
    pub message_code: MessageCode,
}

/// The live connection status, as observed on a [`BusHandle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusState {
    /// Never yet connected (startup, before the first successful connect).
    Connecting,
    /// Connected and streaming.
    Connected,
    /// Dropped; reconnecting with backoff.
    Reconnecting,
    /// Closed for good (after [`BusHandle::close`] or actor shutdown).
    Closed,
}

impl BusState {
    fn as_u8(self) -> u8 {
        match self {
            BusState::Connecting => 0,
            BusState::Connected => 1,
            BusState::Reconnecting => 2,
            BusState::Closed => 3,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => BusState::Connected,
            2 => BusState::Reconnecting,
            3 => BusState::Closed,
            _ => BusState::Connecting,
        }
    }

    /// A short, stable lowercase tag for tool/CLI output.
    pub fn tag(self) -> &'static str {
        match self {
            BusState::Connecting => "connecting",
            BusState::Connected => "connected",
            BusState::Reconnecting => "reconnecting",
            BusState::Closed => "closed",
        }
    }
}

/// Errors surfaced by [`BusHandle`] operations.
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    /// The actor task is gone (closed or panicked); the bus is unusable.
    #[error("bus actor is gone")]
    ActorGone,

    /// A queued frame was dropped without transmitting because the connection
    /// did not come up within [`STALE_CUTOFF`].
    #[error("frame dropped: bus was not connected within the staleness cutoff")]
    Stale,

    /// The send reached the connection but the transport reported an error
    /// (e.g. TUNNELING_ACK exhaustion, a socket error, a server disconnect).
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// A receipt that a [`send`](BusHandle::send) completed against the transport.
///
/// For a tunnel this means the gateway returned a matching `TUNNELING_ACK`
/// (after any retransmit); for routing it means the multicast datagram left the
/// socket. It carries no further payload — its existence *is* the confirmation.
#[derive(Debug, Clone, Copy)]
pub struct SendReceipt {
    _priv: (),
}

impl SendReceipt {
    fn new() -> Self {
        SendReceipt { _priv: () }
    }
}

/// A command from a [`BusHandle`] to the actor task.
enum Command {
    /// Transmit a frame; reply once it is ACKed (or on error / staleness).
    Send {
        frame: Box<CemiFrame>,
        queued_at: Instant,
        reply: oneshot::Sender<Result<SendReceipt, BusError>>,
    },
    /// Cleanly close the connection; reply when the DISCONNECT has been awaited.
    Close { reply: oneshot::Sender<()> },
}

/// Shared, cheaply-cloneable status published by the actor and read by handles.
struct Shared {
    /// The current [`BusState`], as a `u8`.
    state: AtomicU8,
    /// The tunnel-assigned individual address (raw), or 0 if none / routing.
    assigned_ia: AtomicU16,
    /// Notified on every state transition so waiters wake immediately instead of
    /// polling. Carries the new [`BusState`] as a `u8`; the atomic above stays
    /// the source of truth for cheap synchronous reads.
    state_tx: watch::Sender<u8>,
}

impl Shared {
    fn set_state(&self, state: BusState) {
        self.state.store(state.as_u8(), Ordering::Relaxed);
        // Wake any `wait_connected` waiters. `send` never fails here: `Shared`
        // owns the sender for its whole lifetime, so a receiver can always be
        // borrowed from it, and `send` errors only when all receivers are gone.
        let _ = self.state_tx.send(state.as_u8());
    }

    fn state(&self) -> BusState {
        BusState::from_u8(self.state.load(Ordering::Relaxed))
    }
}

/// A running bus actor. Use [`Bus::connect`] to start one.
pub struct Bus;

impl Bus {
    /// Spawns the actor task owning a [`Transport`] opened from `config`, and
    /// returns a [`BusHandle`] plus the task's [`JoinHandle`].
    ///
    /// The actor connects (and reconnects, with exponential backoff) on its own,
    /// so a bus that is down at startup does not fail here — the handle simply
    /// reports [`BusState::Connecting`] until the first connect. Surfacing
    /// connect/disconnect to subscribers happens through [`BusHandle::status`].
    pub fn connect(config: ConnectionConfig) -> (BusHandle, JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (frame_tx, _frame_rx) = broadcast::channel(BROADCAST_DEPTH);
        let (state_tx, _state_rx) = watch::channel(BusState::Connecting.as_u8());
        let shared = Arc::new(Shared {
            state: AtomicU8::new(BusState::Connecting.as_u8()),
            assigned_ia: AtomicU16::new(0),
            state_tx,
        });

        let actor = Actor {
            config,
            commands: cmd_rx,
            frames: frame_tx.clone(),
            shared: shared.clone(),
        };
        let task = tokio::spawn(actor.run());

        let handle = BusHandle {
            commands: cmd_tx,
            frames: frame_tx,
            shared,
            lease_gate: Arc::new(Semaphore::new(1)),
        };
        (handle, task)
    }
}

/// A cloneable handle to the bus actor.
///
/// Every clone shares the same underlying [`Transport`]: sends are serialized
/// through the actor, subscriptions all see the same inbound stream, and there
/// is one lease slot across all clones.
#[derive(Clone)]
pub struct BusHandle {
    commands: mpsc::Sender<Command>,
    frames: broadcast::Sender<InboundFrame>,
    shared: Arc<Shared>,
    /// A one-permit semaphore serializing leases (see [`BusHandle::lease`]).
    lease_gate: Arc<Semaphore>,
}

impl BusHandle {
    /// Subscribes to the inbound frame broadcast.
    ///
    /// The subscription is live from the moment this returns, so a caller can
    /// subscribe *before* transmitting a request and then await the response
    /// without a race (issue #32). Multiple subscribers coexist.
    pub fn subscribe(&self) -> FrameSubscription {
        FrameSubscription {
            rx: self.frames.subscribe(),
        }
    }

    /// Transmits `frame`, resolving once the transport confirms it.
    ///
    /// For a tunnel the returned [`SendReceipt`] means the gateway ACKed the
    /// frame; an ACK exhaustion or socket error surfaces as
    /// [`BusError::Transport`]. A frame queued while the actor is reconnecting is
    /// dropped with [`BusError::Stale`] once [`STALE_CUTOFF`] elapses, so a write
    /// never fires an actuator seconds after the caller gave up.
    pub async fn send(&self, frame: CemiFrame) -> Result<SendReceipt, BusError> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Send {
                frame: Box::new(frame),
                queued_at: Instant::now(),
                reply,
            })
            .await
            .map_err(|_| BusError::ActorGone)?;
        rx.await.map_err(|_| BusError::ActorGone)?
    }

    /// Acquires the exclusive lease for a connection-oriented (layer-4) session.
    ///
    /// Only one [`BusLease`] exists at a time: a second `lease()` call waits
    /// until the first is dropped. This is deliberately the *simplest correct*
    /// exclusivity — it serializes only other leases (the TP1 etiquette of one
    /// open connection at a time). Independent group [`send`](Self::send)s and
    /// [`subscribe`](Self::subscribe)rs are unaffected and proceed concurrently.
    pub async fn lease(&self) -> Result<BusLease, BusError> {
        let permit = self
            .lease_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BusError::ActorGone)?;
        Ok(BusLease {
            handle: self.clone(),
            _permit: permit,
        })
    }

    /// The tunnel-assigned individual address (raw 16-bit), or `None` on a
    /// routing transport or when the gateway assigned none.
    ///
    /// Group traffic should present this as its source address (falling back to
    /// `0.0.255` on routing) — the deferred #30 item.
    pub fn assigned_individual_address(&self) -> Option<u16> {
        match self.shared.assigned_ia.load(Ordering::Relaxed) {
            0 => None,
            raw => Some(raw),
        }
    }

    /// The current connection status.
    pub fn status(&self) -> BusState {
        self.shared.state()
    }

    /// Waits until the actor reports [`BusState::Connected`] (or `Closed`),
    /// up to `timeout`. Returns `true` when connected.
    ///
    /// Callers that derive the management source address from
    /// [`assigned_individual_address`](Self::assigned_individual_address) MUST
    /// wait first: the actor connects asynchronously, and reading the source
    /// before the tunnel handshake completes silently yields the `0.0.255`
    /// fallback — which real devices ignore for connection-oriented traffic
    /// (issue #30's failure mode, as a startup race).
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        // Subscribe before the first status read so no transition can slip
        // through between the check and the await (the actor may set the state
        // concurrently). `borrow_and_update` on a fresh receiver marks the
        // current value seen; `changed()` then wakes only on a *new* transition.
        let mut rx = self.shared.state_tx.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match BusState::from_u8(*rx.borrow_and_update()) {
                BusState::Connected => return true,
                BusState::Closed => return false,
                _ => {}
            }
            // Await the next transition, bounded by the deadline. A timeout or a
            // dropped sender (actor gone) both end the wait as not-connected.
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => continue,
                Ok(Err(_)) | Err(_) => return false,
            }
        }
    }

    /// Closes the connection cleanly, awaiting the transport `DISCONNECT`.
    ///
    /// This is the single close path: it never opens a fresh tunnel just to
    /// close it (a close requested during reconnect backoff simply stops the
    /// actor), preserving the #31 tunnel-slot guarantee. Idempotent — closing an
    /// already-gone actor is `Ok`.
    pub async fn close(&self) -> Result<(), BusError> {
        let (reply, rx) = oneshot::channel();
        if self.commands.send(Command::Close { reply }).await.is_err() {
            // Actor already gone: treat as already-closed.
            return Ok(());
        }
        let _ = rx.await;
        Ok(())
    }
}

/// An exclusive lease on the bus for a connection-oriented session.
///
/// Holds the lease slot until dropped. It derefs to the underlying
/// [`BusHandle`] so the L4 state machine can [`subscribe`](BusHandle::subscribe)
/// and [`send`](BusHandle::send) through it. Dropping the lease releases the slot
/// for the next waiter.
pub struct BusLease {
    handle: BusHandle,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl BusLease {
    /// The underlying handle (subscribe / send / status all go through it).
    pub fn handle(&self) -> &BusHandle {
        &self.handle
    }
}

impl std::ops::Deref for BusLease {
    type Target = BusHandle;

    fn deref(&self) -> &BusHandle {
        &self.handle
    }
}

/// A live subscription to the inbound frame broadcast.
pub struct FrameSubscription {
    rx: broadcast::Receiver<InboundFrame>,
}

impl FrameSubscription {
    /// Receives the next inbound frame, skipping nothing.
    ///
    /// Returns `None` when the actor has shut down. A lagged receiver (missed
    /// frames under burst) transparently resumes on the next fresh frame.
    pub async fn recv(&mut self) -> Option<InboundFrame> {
        loop {
            match self.rx.recv().await {
                Ok(f) => return Some(f),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Waits for the next inbound frame for which `matches(frame, message_code)`
    /// is `true`, up to `timeout`. Returns `None` on timeout or shutdown.
    ///
    /// This is the shared "subscribe, send, await the answer" primitive: the
    /// predicate typically skips the gateway's `L_Data.con` echo of our own
    /// request (issue #32).
    pub async fn wait_for_matching(
        &mut self,
        timeout: Duration,
        matches: impl Fn(&TimestampedFrame, MessageCode) -> bool,
    ) -> Option<TimestampedFrame> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Ok(f)) if matches(&f.frame, f.message_code) => return Some(f.frame),
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                Err(_) => return None,
            }
        }
    }
}

/// State owned by the actor task.
struct Actor {
    config: ConnectionConfig,
    commands: mpsc::Receiver<Command>,
    frames: broadcast::Sender<InboundFrame>,
    shared: Arc<Shared>,
}

impl Actor {
    /// The actor's top-level reconnecting loop.
    ///
    /// Mirrors `bussard_monitor::stream`'s former loop: connect (with backoff),
    /// consume until the connection drops, reconnect. It exits only on a
    /// [`Command::Close`] or when every handle has been dropped.
    async fn run(mut self) {
        let mut backoff = BACKOFF_START;

        loop {
            match Transport::connect(&self.config).await {
                Ok(conn) => {
                    backoff = BACKOFF_START;
                    // Publish the assigned IA and connected state.
                    let ia = conn.assigned_individual_address().unwrap_or(0);
                    self.shared.assigned_ia.store(ia, Ordering::Relaxed);
                    self.shared.set_state(BusState::Connected);

                    match self.consume(conn).await {
                        ActorOutcome::Closed => {
                            self.shared.set_state(BusState::Closed);
                            return;
                        }
                        ActorOutcome::HandlesDropped => {
                            self.shared.set_state(BusState::Closed);
                            return;
                        }
                        ActorOutcome::Dropped => {
                            self.shared.set_state(BusState::Reconnecting);
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("bus connect failed: {err}; retrying in {backoff:?}");
                    self.shared.set_state(BusState::Reconnecting);
                }
            }

            // Backoff before the next connect attempt, but end promptly on a
            // Close command or when all handles are dropped (so we never open a
            // fresh tunnel just to close it — issue #31).
            match self.wait_backoff(backoff).await {
                BackoffOutcome::Elapsed => backoff = next_backoff(backoff),
                BackoffOutcome::Close => {
                    self.shared.set_state(BusState::Closed);
                    return;
                }
                BackoffOutcome::HandlesDropped => {
                    self.shared.set_state(BusState::Closed);
                    return;
                }
            }
        }
    }

    /// Consumes one live connection: fans inbound frames out to subscribers and
    /// services commands, until the connection drops or the actor is closed.
    ///
    /// A `Send` is dispatched onto a spawned task via a cheap
    /// [`TransportSender`](bussard_transport::TransportSender) so `conn.recv()`
    /// keeps being polled while the send awaits its (up to ~2 s) tunnel ACK.
    /// Without this, subscriber delivery stalled for the whole ACK window while
    /// the inline `conn.send().await` held the select (issue #57). Only one send
    /// is ever in flight at a time — while a send is outstanding the command
    /// channel is not polled, preserving the "sends serialize" invariant.
    async fn consume(&mut self, mut conn: Transport) -> ActorOutcome {
        // The outcome of a spawned send: its transport result plus the reply
        // channel to answer the originating handle on the actor thread.
        type SendResult = (
            Result<(), TransportError>,
            oneshot::Sender<Result<SendReceipt, BusError>>,
        );
        let mut in_flight: Option<tokio::task::JoinHandle<SendResult>> = None;

        loop {
            tokio::select! {
                // An inbound frame from the bus. Polled unconditionally, so it
                // keeps draining even while a send is outstanding.
                received = conn.recv() => match received {
                    Ok(stamped) => {
                        let message_code = stamped.frame.message_code;
                        // Ignore send errors: no subscribers is fine.
                        let _ = self.frames.send(InboundFrame {
                            frame: stamped,
                            message_code,
                        });
                    }
                    Err(_err) => return ActorOutcome::Dropped,
                },

                // The in-flight send finished. Only armed when a send is running,
                // so the branch is inert otherwise.
                joined = async { in_flight.as_mut().unwrap().await }, if in_flight.is_some() => {
                    in_flight = None;
                    match joined {
                        Ok((Ok(()), reply)) => {
                            let _ = reply.send(Ok(SendReceipt::new()));
                        }
                        Ok((Err(err), reply)) => {
                            let _ = reply.send(Err(BusError::Transport(err)));
                            // A send error is a connection problem: reconnect.
                            return ActorOutcome::Dropped;
                        }
                        Err(_join_err) => {
                            // The send task panicked; treat as a dropped connection.
                            return ActorOutcome::Dropped;
                        }
                    }
                },

                // A command from a handle. Not polled while a send is in flight,
                // so at most one send runs at a time and ordering is preserved.
                cmd = self.commands.recv(), if in_flight.is_none() => match cmd {
                    Some(Command::Send { frame, queued_at, reply }) => {
                        // Connected here, so the only staleness is a very old
                        // queued frame; still enforce the cutoff.
                        if queued_at.elapsed() >= STALE_CUTOFF {
                            let _ = reply.send(Err(BusError::Stale));
                            continue;
                        }
                        // Spawn the send so its (slow) ACK wait does not block the
                        // recv arm above. The sender shares the transport's
                        // channel, so the ACK is still awaited normally.
                        let sender = conn.sender();
                        in_flight = Some(tokio::spawn(async move {
                            let result = sender.send(*frame).await;
                            (result, reply)
                        }));
                    }
                    Some(Command::Close { reply }) => {
                        let _ = conn.close().await;
                        let _ = reply.send(());
                        return ActorOutcome::Closed;
                    }
                    None => return ActorOutcome::HandlesDropped,
                },
            }
        }
    }

    /// Waits out the reconnect backoff, or returns early on a Close command / all
    /// handles dropped. While disconnected, Send commands are answered with
    /// [`BusError::Stale`] once they exceed the cutoff (so a queued write never
    /// fires late), and fresh ones wait out the remaining budget.
    async fn wait_backoff(&mut self, backoff: Duration) -> BackoffOutcome {
        let deadline = tokio::time::Instant::now() + backoff;
        loop {
            let sleep = tokio::time::sleep_until(deadline);
            tokio::select! {
                _ = sleep => return BackoffOutcome::Elapsed,
                cmd = self.commands.recv() => match cmd {
                    Some(Command::Send { queued_at, reply, .. }) => {
                        // Disconnected: hold the frame until it goes stale, then
                        // drop it. We do not buffer across the reconnect — a late
                        // actuator write is worse than a clear failure (review A3).
                        let age = queued_at.elapsed();
                        if age >= STALE_CUTOFF {
                            let _ = reply.send(Err(BusError::Stale));
                        } else {
                            // Wait the remainder of the cutoff (or until the
                            // backoff deadline, whichever is first), then fail
                            // stale — a reconnect that completes will happen on
                            // the next loop iteration, not here.
                            let stale_at = tokio::time::Instant::now() + (STALE_CUTOFF - age);
                            tokio::select! {
                                _ = tokio::time::sleep_until(stale_at) => {
                                    let _ = reply.send(Err(BusError::Stale));
                                }
                                _ = tokio::time::sleep_until(deadline) => {
                                    let _ = reply.send(Err(BusError::Stale));
                                    return BackoffOutcome::Elapsed;
                                }
                            }
                        }
                    }
                    Some(Command::Close { reply }) => {
                        // Nothing open to disconnect; just acknowledge.
                        let _ = reply.send(());
                        return BackoffOutcome::Close;
                    }
                    None => return BackoffOutcome::HandlesDropped,
                },
            }
        }
    }
}

/// The result of consuming one connection.
enum ActorOutcome {
    /// A `Close` command was serviced; the connection was closed cleanly.
    Closed,
    /// Every handle was dropped; nothing more can command the actor.
    HandlesDropped,
    /// The connection dropped; the actor should reconnect.
    Dropped,
}

/// The result of waiting out a reconnect backoff.
enum BackoffOutcome {
    /// The backoff elapsed; try to connect again.
    Elapsed,
    /// A `Close` command arrived.
    Close,
    /// Every handle was dropped.
    HandlesDropped,
}

/// Doubles the backoff, capped at [`BACKOFF_MAX`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(
            next_backoff(Duration::from_secs(16)),
            Duration::from_secs(30)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn bus_state_tags_roundtrip() {
        for s in [
            BusState::Connecting,
            BusState::Connected,
            BusState::Reconnecting,
            BusState::Closed,
        ] {
            assert_eq!(BusState::from_u8(s.as_u8()), s);
        }
    }
}
