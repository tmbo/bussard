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
}

impl ConnectionConfig {
    /// Convenience constructor for a tunneling connection to `gateway`.
    pub fn tunnel(gateway: SocketAddrV4) -> Self {
        ConnectionConfig {
            transport: TransportKind::Tunnel,
            gateway: Some(gateway),
            multicast: SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT),
            local_interface: Ipv4Addr::UNSPECIFIED,
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
        }
    }
}
