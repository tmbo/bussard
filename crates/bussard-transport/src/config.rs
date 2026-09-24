//! Connection configuration and the timing/retry constants.
//!
//! [`ConnectionConfig`] deliberately mirrors the *shape* of the model's
//! `bussard.yaml` connection section but does **not** import
//! `bussard-model`'s schema type. Keeping transport's config independent lets
//! the crate be used and tested standalone; the CLI maps between the model's
//! deserialized config and this struct.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// The default KNXnet/IP UDP port (unicast and multicast).
pub const DEFAULT_PORT: u16 = 3671;

/// The KNX routing multicast group (`224.0.23.12`).
pub const DEFAULT_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

// --- Timing and retry constants (all in one place, per the design brief) ---

/// Heartbeat interval: send a CONNECTIONSTATE_REQUEST this often. The KNXnet/IP
/// spec mandates a heartbeat at least every 60 s to keep the tunnel alive.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Per-attempt timeout waiting for a CONNECTIONSTATE_RESPONSE (spec: 10 s).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// Number of heartbeat attempts before the connection is declared dead (spec: 3).
pub const HEARTBEAT_RETRIES: u32 = 3;

/// Timeout waiting for a TUNNELING_ACK to one of our requests (spec: 1 s).
pub const TUNNELING_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Number of times a tunneling request is retransmitted on ACK timeout before
/// erroring. The spec allows one retransmit, i.e. two sends total.
pub const TUNNELING_RETRANSMITS: u32 = 1;

/// Timeout waiting for a CONNECT_RESPONSE during the handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout waiting for a DISCONNECT_RESPONSE during a clean close.
pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default total time a lost tunnel is re-established for before the pending
/// send fails (issue #177). Long enough to ride out a pulled and re-plugged LAN
/// cable or a switch reboot, short enough that a dead interface fails clearly.
pub const TUNNEL_RECONNECT_BUDGET: Duration = Duration::from_secs(60);

/// Default pause before the second re-establish attempt; it doubles per attempt.
pub const TUNNEL_RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Default cap on the pause between two re-establish attempts, so a cable that
/// comes back is noticed within this long.
pub const TUNNEL_RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Default timeout for one CONNECT_RESPONSE during a re-establish attempt. A
/// reachable gateway answers in milliseconds; a short wait keeps the attempts
/// frequent while the link is down.
pub const TUNNEL_RECONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// How a [`Tunnel`](crate::Tunnel) re-establishes itself after the gateway
/// link is lost (issue #177).
///
/// The link counts as lost when a TUNNELING_REQUEST stays unacknowledged after
/// its retransmit, when the CONNECTIONSTATE heartbeat fails, or when the socket
/// reports an error. The tunnel then sends a best-effort DISCONNECT for the old
/// channel, opens a new one with CONNECT_REQUEST (sequence counters reset to
/// zero) and re-sends the frame that was pending. Attempts are spaced by a
/// doubling backoff (`initial_backoff`, 2x, 4x ... capped at `max_backoff`)
/// until `budget` has passed since the loss; then the pending send fails with
/// [`TransportError::TunnelLost`](crate::TransportError::TunnelLost).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelReconnect {
    /// Total time to keep trying, measured from the moment the loss was
    /// detected. [`Duration::ZERO`] disables re-establishing: the first loss
    /// fails the send (the behaviour before issue #177).
    pub budget: Duration,
    /// The pause before the second attempt (the first runs immediately).
    pub initial_backoff: Duration,
    /// The cap the doubling pause never exceeds.
    pub max_backoff: Duration,
    /// How long one attempt waits for the CONNECT_RESPONSE.
    pub attempt_timeout: Duration,
}

impl Default for TunnelReconnect {
    fn default() -> Self {
        TunnelReconnect {
            budget: TUNNEL_RECONNECT_BUDGET,
            initial_backoff: TUNNEL_RECONNECT_INITIAL_BACKOFF,
            max_backoff: TUNNEL_RECONNECT_MAX_BACKOFF,
            attempt_timeout: TUNNEL_RECONNECT_ATTEMPT_TIMEOUT,
        }
    }
}

impl TunnelReconnect {
    /// A policy that never re-establishes: the first link loss fails the send.
    pub fn disabled() -> Self {
        TunnelReconnect {
            budget: Duration::ZERO,
            ..TunnelReconnect::default()
        }
    }

    /// The default policy with a different total `budget`.
    pub fn with_budget(budget: Duration) -> Self {
        TunnelReconnect {
            budget,
            ..TunnelReconnect::default()
        }
    }

    /// Whether this policy re-establishes a lost tunnel at all.
    pub fn enabled(&self) -> bool {
        !self.budget.is_zero()
    }
}

/// Which transport to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    /// KNXnet/IP tunneling (unicast to a specific gateway).
    Tunnel,
    /// KNXnet/IP routing (multicast).
    Routing,
}

/// Configuration for opening a bus connection.
///
/// This mirrors the `connection:` block of `bussard.yaml` but is defined here
/// so the transport crate stays decoupled from the model's YAML schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Which transport to open.
    pub transport: TransportKind,
    /// For tunneling: the gateway's control endpoint (host + port).
    pub gateway: Option<SocketAddrV4>,
    /// For routing: the multicast group and port. Defaults to `224.0.23.12:3671`.
    pub multicast: SocketAddrV4,
    /// The local IPv4 interface to bind / join the group on. `0.0.0.0` lets the
    /// OS choose.
    pub local_interface: Ipv4Addr,
    /// How a tunnel re-establishes itself after the gateway link is lost.
    /// Ignored for routing.
    pub reconnect: TunnelReconnect,
}

impl ConnectionConfig {
    /// Convenience constructor for a tunneling connection to `gateway`.
    pub fn tunnel(gateway: SocketAddrV4) -> Self {
        ConnectionConfig {
            transport: TransportKind::Tunnel,
            gateway: Some(gateway),
            multicast: SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT),
            local_interface: Ipv4Addr::UNSPECIFIED,
            reconnect: TunnelReconnect::default(),
        }
    }

    /// Convenience constructor for a routing (multicast) connection using the
    /// default group.
    pub fn routing() -> Self {
        ConnectionConfig {
            transport: TransportKind::Routing,
            gateway: None,
            multicast: SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT),
            local_interface: Ipv4Addr::UNSPECIFIED,
            reconnect: TunnelReconnect::default(),
        }
    }

    /// This configuration with a different tunnel re-establish policy.
    pub fn with_reconnect(mut self, reconnect: TunnelReconnect) -> Self {
        self.reconnect = reconnect;
        self
    }
}
