//! The [`BusConnection`] trait and shared event types.

use std::time::SystemTime;

use crate::cemi::CemiFrame;
use crate::error::Result;

/// A received cEMI frame stamped with the local time it arrived, plus any
/// out-of-band router events. `bussard-monitor` consumes a stream of these.
#[derive(Debug, Clone)]
pub struct TimestampedFrame {
    /// Local time the frame was received.
    pub received_at: SystemTime,
    /// The decoded cEMI frame.
    pub frame: CemiFrame,
}

/// An out-of-band event surfaced by a connection, alongside normal frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusEvent {
    /// A router reported dropped messages (ROUTING_LOST_MESSAGE).
    RoutingLost {
        /// Number of frames the router dropped.
        lost: u16,
    },
    /// A router asked senders to back off (ROUTING_BUSY).
    RoutingBusy {
        /// Milliseconds to wait before sending again.
        wait_ms: u16,
    },
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
