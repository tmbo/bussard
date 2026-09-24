//! The connect-and-consume adapter over the bus actor.
//!
//! Since issue #37 this is a thin adapter: the reconnecting connect loop moved
//! into the [`bussard_bus`] actor (one `Transport` owner, fanning inbound frames
//! out to every subscriber). [`run_stream`] spawns a [`Bus`] from a
//! [`ConnectionConfig`], subscribes, decodes every inbound frame against an
//! optional model, and hands each [`DecodedTelegram`] to a [`TelegramSink`] —
//! while the actor handles reconnect/backoff underneath and other consumers
//! (an MCP ring, an L4 session) see the same frames.
//!
//! The public sink / cancel API is unchanged, so `monitor`, `capture` and the
//! MCP server keep their decode / format / store code exactly as before.

use std::time::Duration;

use bussard_bus::{Bus, BusState};
use bussard_model::Model;
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{ConnectionConfig, TransportError};
use tokio::sync::{mpsc, watch};

use crate::decode::DecodedTelegram;
use crate::secure::GroupKeyring;

/// A cooperative cancellation signal for a running stream loop.
///
/// Create a [`CancelToken`] with [`CancelToken::new`], pass the paired
/// [`CancelWatch`] into a `run_stream*` entry point, and call
/// [`CancelToken::cancel`] to ask the loop to stop and **cleanly close** the bus
/// (the actor sends DISCONNECT_REQUEST) before returning — rather than leaking
/// the gateway's tunnel slot (issue #31).
///
/// Backed by a `tokio::sync::watch` channel, so it is dependency-free and can be
/// observed from inside `tokio::select!` without racing.
#[derive(Debug, Clone)]
pub struct CancelToken {
    tx: watch::Sender<bool>,
}

/// The receiving half of a [`CancelToken`], handed to the stream loop.
#[derive(Debug, Clone)]
pub struct CancelWatch {
    rx: watch::Receiver<bool>,
}

impl CancelToken {
    /// Creates a fresh, not-yet-cancelled token and its paired watch.
    pub fn new() -> (CancelToken, CancelWatch) {
        let (tx, rx) = watch::channel(false);
        (CancelToken { tx }, CancelWatch { rx })
    }

    /// Signals cancellation. The stream loop stops and the bus is closed cleanly
    /// before it returns `Ok(())`.
    pub fn cancel(&self) {
        // Ignore the error if all watchers are gone: nothing to cancel.
        let _ = self.tx.send(true);
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        CancelToken::new().0
    }
}

impl CancelWatch {
    /// Whether cancellation has already been requested.
    fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves as soon as cancellation is requested (or immediately if it has
    /// already been requested). Suitable for use inside `tokio::select!`.
    async fn cancelled(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        while self.rx.changed().await.is_ok() {
            if *self.rx.borrow() {
                return;
            }
        }
    }
}

/// A stand-in backoff reported to sinks on a disconnect. The actor now owns the
/// real (exponential) reconnect schedule; sinks only log this, so a single
/// representative value keeps the callback contract without leaking internals.
const REPORTED_BACKOFF: Duration = Duration::from_secs(1);

/// An error that stops the stream loop for good (as opposed to a recoverable
/// connection drop, which the actor handles by reconnecting).
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The stream was asked to stop by the sink or an external signal.
    #[error("stream stopped")]
    Stopped,
    /// The gateway refused the connection in a way retrying cannot fix (a
    /// KNXnet/IP Secure interface without credentials, a refused password;
    /// issue #182). The bus actor has stopped.
    #[error("{0}")]
    ConnectRefused(String),
}

/// A consumer of decoded telegrams.
///
/// Implementors receive each telegram and connection lifecycle events. Returning
/// [`Flow::Stop`] from any callback ends the stream loop cleanly.
pub trait TelegramSink: Send {
    /// Handles one decoded telegram (and the frame it came from, for callers
    /// that need the raw bytes, e.g. the capture store).
    fn on_telegram(&mut self, telegram: &DecodedTelegram, frame: &TimestampedFrame) -> Flow;

    /// Called when a connection has been established. `reconnect` is true for
    /// every attempt after the first. Default: keep going.
    fn on_connect(&mut self, _reconnect: bool) -> Flow {
        Flow::Continue
    }

    /// Called when the connection dropped and the actor is reconnecting.
    /// Default: keep going.
    fn on_disconnect(&mut self, _error: &TransportError, _backoff: Duration) -> Flow {
        Flow::Continue
    }
}

/// The timestamped frame type, re-exported so sinks need only this crate.
pub use bussard_transport::TimestampedFrame;

/// Whether the stream loop should continue or stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep streaming.
    Continue,
    /// Stop the loop cleanly.
    Stop,
}

impl Flow {
    fn is_stop(self) -> bool {
        self == Flow::Stop
    }
}

/// Runs the connect-and-consume loop until the sink stops it.
///
/// `model` is resolved into each telegram (pass `None` to keep addresses
/// numeric). The loop only returns `Ok(())` when a sink returns [`Flow::Stop`]
/// (or on cancellation); connection drops are handled by the actor reconnecting.
pub async fn run_stream(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, None, None, None).await
}

/// Like [`run_stream`], but cancellable through a [`CancelWatch`].
///
/// On cancellation the bus is closed cleanly (DISCONNECT on a tunnel) before
/// returning `Ok(())`.
pub async fn run_stream_cancellable(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    cancel: CancelWatch,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, None, Some(cancel), None).await
}

/// Like [`run_stream`], but also drains an optional outbound channel, sending
/// each queued [`CemiFrame`] onto the bus.
///
/// This is the injection point the MCP server and one-shot commands use to
/// transmit on the *same* bus that feeds the telegram stream. Passing `None` for
/// `outbound` is equivalent to [`run_stream`].
pub async fn run_stream_with_outbound(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, outbound, None, None).await
}

/// Like [`run_stream_with_outbound`], but cancellable through a [`CancelWatch`].
pub async fn run_stream_with_outbound_cancellable(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
    cancel: CancelWatch,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, outbound, Some(cancel), None).await
}

/// Like [`run_stream_cancellable`], but unwraps KNX Data Secure group
/// telegrams with the keyring's group keys before decoding (issue #172; see
/// [`DecodedTelegram::from_frame_secured`]). `None` is exactly
/// [`run_stream_cancellable`].
pub async fn run_stream_secured_cancellable(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    keyring: Option<GroupKeyring>,
    cancel: CancelWatch,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, None, Some(cancel), keyring).await
}

/// The shared implementation behind every `run_stream*` entry point.
async fn run_stream_inner(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    mut outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
    mut cancel: Option<CancelWatch>,
    mut keyring: Option<GroupKeyring>,
) -> Result<(), StreamError> {
    // If cancellation was requested before we start, do nothing (never open a
    // tunnel just to close it — issue #31).
    if cancel.as_ref().is_some_and(CancelWatch::is_cancelled) {
        return Ok(());
    }

    let (handle, _task) = Bus::connect(config.clone());
    let mut sub = handle.subscribe();

    // Track connection transitions so the sink still sees on_connect /
    // on_disconnect. The actor owns the real backoff; we report a placeholder.
    let mut announced_connected = false;
    let mut was_connected = false;

    loop {
        // Surface any connection-state transition to the sink.
        let state = handle.status();
        match state {
            BusState::Connected if !was_connected => {
                was_connected = true;
                let reconnect = announced_connected;
                announced_connected = true;
                if sink.on_connect(reconnect).is_stop() {
                    let _ = handle.close().await;
                    return Ok(());
                }
            }
            // The actor stopped on a refusal retrying cannot fix (#182): end
            // the stream with it instead of waiting forever.
            BusState::Closed => {
                if let Some(fatal) = handle.fatal_error() {
                    return Err(StreamError::ConnectRefused(fatal));
                }
            }
            BusState::Reconnecting if was_connected => {
                was_connected = false;
                let err = TransportError::Closed;
                if sink.on_disconnect(&err, REPORTED_BACKOFF).is_stop() {
                    let _ = handle.close().await;
                    return Ok(());
                }
            }
            _ => {}
        }

        let out_recv = async {
            match outbound.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        let cancelled = async {
            match cancel.as_mut() {
                Some(c) => c.cancelled().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            inbound = sub.recv() => match inbound {
                Some(frame) => {
                    let stamped = frame.frame;
                    let decoded =
                        DecodedTelegram::from_frame_secured(&stamped, model, keyring.as_mut());
                    if sink.on_telegram(&decoded, &stamped).is_stop() {
                        let _ = handle.close().await;
                        return Ok(());
                    }
                }
                // The actor shut down: close (idempotent) and stop.
                None => {
                    let _ = handle.close().await;
                    return Ok(());
                }
            },
            frame = out_recv => match frame {
                Some(frame) => {
                    // A frame to transmit. Completion-tracked by the actor; a
                    // failure (staleness / ACK exhaustion) is logged and the
                    // stream continues, matching fire-and-forget KNX semantics.
                    if let Err(err) = handle.send(frame).await {
                        tracing::warn!("outbound send failed: {err}");
                    }
                }
                None => {
                    // The outbound sender was dropped: stop selecting on it.
                    outbound = None;
                }
            },
            _ = cancelled => {
                let _ = handle.close().await;
                return Ok(());
            }
            // Poll the connection state periodically so transitions are noticed
            // even when no frames are flowing.
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_stop() {
        assert!(Flow::Stop.is_stop());
        assert!(!Flow::Continue.is_stop());
    }
}
