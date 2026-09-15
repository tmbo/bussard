//! The reconnecting connect-and-consume loop.
//!
//! [`run_stream`] opens a [`Transport`] from a [`ConnectionConfig`], decodes
//! every received frame against an optional model, and hands each
//! [`DecodedTelegram`] to a [`TelegramSink`]. On a connection error
//! (heartbeat lost, gateway disconnect, socket error) it retries with
//! exponential backoff (1s, 2s, 4s… capped at 30s), logging each attempt and
//! resuming the stream — so a monitor survives a gateway reboot.
//!
//! The loop runs until the sink asks it to stop (e.g. on Ctrl-C) or a
//! non-recoverable setup error occurs.

use std::time::Duration;

use bussard_model::Model;
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{
    BusConnection, ConnectionConfig, TimestampedFrame, Transport, TransportError,
};
use tokio::sync::{mpsc, watch};

use crate::decode::DecodedTelegram;

/// A cooperative cancellation signal for a running stream loop.
///
/// Create a [`CancelToken`] with [`CancelToken::new`], pass the paired
/// [`CancelWatch`] into [`run_stream_with_outbound`], and call
/// [`CancelToken::cancel`] to ask the loop to break out of its consume loop and
/// **cleanly close** the live connection (sending DISCONNECT_REQUEST) before
/// returning — rather than aborting the task and leaking the gateway's tunnel
/// slot (issue #31).
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

    /// Signals cancellation. The stream loop breaks its consume loop and closes
    /// the connection cleanly before returning `Ok(())`.
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
        // Wait for a change to `true`. If the sender is dropped, treat that as
        // cancellation too (the owner is gone).
        while self.rx.changed().await.is_ok() {
            if *self.rx.borrow() {
                return;
            }
        }
    }
}

/// The initial reconnect backoff.
const BACKOFF_START: Duration = Duration::from_secs(1);
/// The maximum reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// An error that stops the stream loop for good (as opposed to a recoverable
/// connection drop, which triggers a reconnect).
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The stream was asked to stop by the sink or an external signal.
    #[error("stream stopped")]
    Stopped,
}

/// A consumer of decoded telegrams.
///
/// Implementors receive each telegram and connection lifecycle events. Returning
/// [`Flow::Stop`] from any callback ends the stream loop cleanly.
pub trait TelegramSink: Send {
    /// Handles one decoded telegram (and the frame it came from, for callers
    /// that need the raw bytes, e.g. the capture store).
    fn on_telegram(&mut self, telegram: &DecodedTelegram, frame: &TimestampedFrame) -> Flow;

    /// Called when a fresh connection has been established. `reconnect` is true
    /// for every attempt after the first. Default: keep going.
    fn on_connect(&mut self, _reconnect: bool) -> Flow {
        Flow::Continue
    }

    /// Called when the connection dropped and a retry is scheduled after
    /// `backoff`. Default: keep going (retry).
    fn on_disconnect(&mut self, _error: &TransportError, _backoff: Duration) -> Flow {
        Flow::Continue
    }
}

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

/// Runs the reconnecting stream loop until the sink stops it.
///
/// `model` is resolved into each telegram (pass `None` to keep addresses
/// numeric). The loop only returns `Ok(())` when a sink returns [`Flow::Stop`];
/// connection errors are handled internally by reconnecting.
pub async fn run_stream(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
) -> Result<(), StreamError> {
    run_stream_with_outbound(config, model, sink, None).await
}

/// Like [`run_stream`], but cancellable through a [`CancelWatch`].
///
/// On cancellation the loop breaks and cleanly closes any live connection
/// (sending DISCONNECT_REQUEST on a tunnel) before returning `Ok(())`.
pub async fn run_stream_cancellable(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    cancel: CancelWatch,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, None, Some(cancel)).await
}

/// Like [`run_stream`], but also drains an optional outbound channel, sending
/// each queued [`CemiFrame`] onto the live connection.
///
/// This is the injection point the MCP server (and the `bussard read` command)
/// use to transmit a `GroupValueRead` on the *same* connection that feeds the
/// telegram stream, so a request and its response share one bus session.
/// Passing `None` for `outbound` is byte-for-byte equivalent to [`run_stream`]
/// — existing callers are unaffected.
///
/// Frames queued while the connection is down (during reconnect backoff) stay
/// in the channel and are sent once a fresh connection is up. A send error on
/// the bus is treated like any other connection drop: it triggers a reconnect,
/// not a permanent failure.
pub async fn run_stream_with_outbound(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, outbound, None).await
}

/// Like [`run_stream_with_outbound`], but cancellable through a [`CancelWatch`].
///
/// This is the injection point one-shot commands (`bussard read`/`write`) and
/// the MCP server use: they queue a frame on `outbound`, await the response, and
/// then [`cancel`](CancelToken::cancel) so the connection is closed cleanly
/// (releasing the gateway tunnel slot) instead of being aborted — issue #31.
pub async fn run_stream_with_outbound_cancellable(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
    cancel: CancelWatch,
) -> Result<(), StreamError> {
    run_stream_inner(config, model, sink, outbound, Some(cancel)).await
}

/// The shared implementation behind every `run_stream*` entry point.
async fn run_stream_inner(
    config: &ConnectionConfig,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    mut outbound: Option<mpsc::UnboundedReceiver<CemiFrame>>,
    mut cancel: Option<CancelWatch>,
) -> Result<(), StreamError> {
    let mut backoff = BACKOFF_START;
    let mut first = true;

    loop {
        // If cancellation was requested before/between connections, stop now so
        // we never open a fresh tunnel just to close it.
        if cancel.as_ref().is_some_and(CancelWatch::is_cancelled) {
            return Ok(());
        }

        match Transport::connect(config).await {
            Ok(conn) => {
                // A successful connect resets the backoff schedule.
                backoff = BACKOFF_START;
                if sink.on_connect(!first).is_stop() {
                    let _ = conn.close().await;
                    return Ok(());
                }
                first = false;

                match consume(conn, model, sink, outbound.as_mut(), cancel.as_mut()).await {
                    ConsumeOutcome::Stopped => return Ok(()),
                    ConsumeOutcome::Cancelled => return Ok(()),
                    ConsumeOutcome::Dropped(err) => {
                        if sink.on_disconnect(&err, backoff).is_stop() {
                            return Ok(());
                        }
                        // A cancel during the sleep should end promptly.
                        if let Some(c) = cancel.as_mut() {
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                _ = c.cancelled() => return Ok(()),
                            }
                        } else {
                            tokio::time::sleep(backoff).await;
                        }
                        backoff = next_backoff(backoff);
                    }
                }
            }
            Err(err) => {
                // Could not connect: back off and retry (unless the sink stops).
                if sink.on_disconnect(&err, backoff).is_stop() {
                    return Ok(());
                }
                if let Some(c) = cancel.as_mut() {
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = c.cancelled() => return Ok(()),
                    }
                } else {
                    tokio::time::sleep(backoff).await;
                }
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// The result of consuming from one connection.
enum ConsumeOutcome {
    /// The sink asked to stop.
    Stopped,
    /// Cancellation was requested; the connection was closed cleanly.
    Cancelled,
    /// The connection dropped with this error; caller should reconnect.
    Dropped(TransportError),
}

/// Receives and dispatches frames from a single live connection until it drops,
/// the sink stops, or cancellation is requested — while also forwarding any
/// queued outbound frames onto it.
///
/// On cancellation the connection is **closed cleanly** (`conn.close().await`,
/// which sends DISCONNECT_REQUEST on a tunnel) before returning, so the gateway
/// releases its tunnel slot instead of holding it for its ~2-minute timeout.
async fn consume(
    mut conn: Transport,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
    mut outbound: Option<&mut mpsc::UnboundedReceiver<CemiFrame>>,
    mut cancel: Option<&mut CancelWatch>,
) -> ConsumeOutcome {
    // If cancellation was already requested before we got here, close and stop.
    if cancel.as_deref().is_some_and(|c| c.is_cancelled()) {
        let _ = conn.close().await;
        return ConsumeOutcome::Cancelled;
    }

    loop {
        // When no outbound channel is present, this collapses to a plain
        // `conn.recv().await` (the disabled branch is never polled), so the
        // classic monitor/capture path is unchanged.
        let out_recv = async {
            match outbound.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        // When no cancel watch is present, this branch never resolves.
        let cancelled = async {
            match cancel.as_mut() {
                Some(c) => c.cancelled().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            received = conn.recv() => match received {
                Ok(stamped) => {
                    let decoded = DecodedTelegram::from_frame(&stamped, model);
                    if sink.on_telegram(&decoded, &stamped).is_stop() {
                        let _ = conn.close().await;
                        return ConsumeOutcome::Stopped;
                    }
                }
                Err(err) => return ConsumeOutcome::Dropped(err),
            },
            frame = out_recv => match frame {
                // A frame to transmit. A send failure is a connection problem:
                // drop and reconnect (the frame is lost, matching fire-and-forget
                // KNX semantics; the caller times out waiting for a response).
                Some(frame) => {
                    if let Err(err) = conn.send(frame).await {
                        return ConsumeOutcome::Dropped(err);
                    }
                }
                // The outbound sender was dropped: stop selecting on it but keep
                // serving the stream (rebuild the async each loop, so just clear).
                None => {
                    outbound = None;
                }
            },
            _ = cancelled => {
                // Cancellation requested: close the connection cleanly so the
                // gateway releases the tunnel slot, then stop.
                let _ = conn.close().await;
                return ConsumeOutcome::Cancelled;
            }
        }
    }
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
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
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
    fn flow_stop() {
        assert!(Flow::Stop.is_stop());
        assert!(!Flow::Continue.is_stop());
    }
}
