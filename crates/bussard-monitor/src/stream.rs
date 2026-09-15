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
use bussard_transport::{
    BusConnection, ConnectionConfig, TimestampedFrame, Transport, TransportError,
};

use crate::decode::DecodedTelegram;

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
    let mut backoff = BACKOFF_START;
    let mut first = true;

    loop {
        match Transport::connect(config).await {
            Ok(conn) => {
                // A successful connect resets the backoff schedule.
                backoff = BACKOFF_START;
                if sink.on_connect(!first).is_stop() {
                    let _ = conn.close().await;
                    return Ok(());
                }
                first = false;

                match consume(conn, model, sink).await {
                    ConsumeOutcome::Stopped => return Ok(()),
                    ConsumeOutcome::Dropped(err) => {
                        if sink.on_disconnect(&err, backoff).is_stop() {
                            return Ok(());
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = next_backoff(backoff);
                    }
                }
            }
            Err(err) => {
                // Could not connect: back off and retry (unless the sink stops).
                if sink.on_disconnect(&err, backoff).is_stop() {
                    return Ok(());
                }
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// The result of consuming from one connection.
enum ConsumeOutcome {
    /// The sink asked to stop.
    Stopped,
    /// The connection dropped with this error; caller should reconnect.
    Dropped(TransportError),
}

/// Receives and dispatches frames from a single live connection until it drops
/// or the sink stops.
async fn consume(
    mut conn: Transport,
    model: Option<&Model>,
    sink: &mut dyn TelegramSink,
) -> ConsumeOutcome {
    loop {
        match conn.recv().await {
            Ok(stamped) => {
                let decoded = DecodedTelegram::from_frame(&stamped, model);
                if sink.on_telegram(&decoded, &stamped).is_stop() {
                    let _ = conn.close().await;
                    return ConsumeOutcome::Stopped;
                }
            }
            Err(err) => return ConsumeOutcome::Dropped(err),
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
