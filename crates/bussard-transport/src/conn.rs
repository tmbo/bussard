//! The [`BusConnection`] trait and shared event types.

use std::time::SystemTime;

use crate::cemi::CemiFrame;
use crate::error::Result;

/// A received cEMI frame stamped with the local time it arrived.
/// `bussard-monitor` consumes a stream of these.
///
/// Out-of-band router conditions (ROUTING_BUSY / ROUTING_LOST_MESSAGE) are not
/// carried here: the actor that owns a connection only awaits
/// [`recv`](BusConnection::recv), so nothing would read a side channel. The
/// [`Router`](crate::Router) logs those conditions via `tracing::warn` and
/// honours ROUTING_BUSY's pause internally. A former `BusEvent` enum plus a
/// `Router::last_event` poll existed for this but were never read by any caller,
/// so they were removed rather than left as unreachable API.
#[derive(Debug, Clone)]
pub struct TimestampedFrame {
    /// Local time the frame was received.
    pub received_at: SystemTime,
    /// The decoded cEMI frame.
    pub frame: CemiFrame,
}

/// A KNX bus connection: send and receive cEMI frames.
///
/// Both [`Tunnel`](crate::Tunnel) and [`Router`](crate::Router) implement this.
/// Received frames are delivered through [`recv`](BusConnection::recv), which
/// yields the next frame or an error. Connect/bind happens in the constructors;
/// [`close`](BusConnection::close) performs a clean shutdown.
#[allow(async_fn_in_trait)]
pub trait BusConnection: Send {
    /// Sends a cEMI frame onto the bus. For tunneling this awaits the gateway's
    /// TUNNELING_ACK (with retransmit); for routing it is fire-and-forget on the
    /// multicast group.
    async fn send(&mut self, frame: CemiFrame) -> Result<()>;

    /// Receives the next timestamped frame from the bus.
    async fn recv(&mut self) -> Result<TimestampedFrame>;

    /// Closes the connection, releasing any gateway channel.
    async fn close(self) -> Result<()>;
}
