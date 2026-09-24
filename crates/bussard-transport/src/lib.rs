//! KNXnet/IP transport for bussard.
//!
//! This crate speaks KNXnet/IP over UDP and exposes a single [`BusConnection`]
//! trait with two implementations:
//!
//! - [`Tunnel`] — a unicast **tunneling** client to a KNXnet/IP gateway, with
//!   the full CONNECT / heartbeat / TUNNELING_REQUEST+ACK / DISCONNECT state
//!   machine and sequence counters. With KNXnet/IP Secure credentials
//!   ([`SecureTunnelConfig`]) the same state machine runs inside an
//!   authenticated secure session over TCP (issue #71 Phase B).
//! - [`Router`] — a **routing** (multicast) participant on `224.0.23.12:3671`.
//!
//! Underneath sits a pure, heavily-tested [`cemi`] codec for the KNX link-layer
//! `L_Data` telegrams (including the 6-bit "small APDU" packing) and a
//! [`knxnet`] module for the framing of every service.
//!
//! It is written from scratch under the crate's MIT license, from the published
//! KNXnet/IP protocol structure — no GPL KNX stacks were used.
//!
//! # Example
//!
//! ```no_run
//! use bussard_transport::{BusConnection, ConnectionConfig, Transport};
//! use bussard_transport::cemi::CemiFrame;
//! use bussard_model::{GroupAddress, IndividualAddress};
//!
//! # async fn run() -> bussard_transport::Result<()> {
//! // Open a tunnel to a gateway at 192.0.2.10:3671.
//! let gateway = "192.0.2.10:3671".parse().unwrap();
//! let config = ConnectionConfig::tunnel(gateway);
//! let mut conn = Transport::connect(&config).await?;
//!
//! // Write the 1-bit value `1` to group address 3/0/4.
//! let ga: GroupAddress = "3/0/4".parse().unwrap();
//! let ia: IndividualAddress = "1.1.255".parse().unwrap();
//! // A 1-bit DPT packs into the 6-bit APDU; the write path uses the DPT-aware
//! // `CemiFrame::group_write(.., dpt.is_packable())` so byte-sized DPTs don't.
//! conn.send(CemiFrame::group_write_packed(ga, ia, &[1])).await?;
//!
//! // Observe the bus.
//! let stamped = conn.recv().await?;
//! println!("{:?} from {}", stamped.frame.apdu, stamped.frame.source);
//!
//! conn.close().await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod cemi;
pub mod config;
mod conn;
pub mod discovery;
mod error;
pub mod knxnet;
mod router;
mod secure;
pub mod tpci;
mod tunnel;
pub mod wire_trace;
pub mod write_gate;

pub use config::{
    ConnectionConfig, SecureSource, SecureTunnelConfig, SecureUser, TransportKind, TunnelReconnect,
};
pub use conn::{BusConnection, TimestampedFrame};
pub use discovery::{
    describe_gateway, describe_gateway_extended, discover, discover_all, local_ipv4_interfaces,
};
pub use error::{E_NO_MORE_CONNECTIONS, Result, TransportError};
pub use router::Router;
pub use tunnel::{LinkState, Tunnel};

use crate::cemi::CemiFrame;

/// A config-driven bus connection, dispatching to [`Tunnel`] or [`Router`].
///
/// Use [`Transport::connect`] as the single entry point when the transport is
/// chosen at runtime from configuration.
pub enum Transport {
    /// A tunneling connection.
    Tunnel(Tunnel),
    /// A routing (multicast) connection.
    Router(Router),
}

impl Transport {
    /// Opens the connection described by `config`.
    pub async fn connect(config: &ConnectionConfig) -> Result<Transport> {
        match config.transport {
            TransportKind::Tunnel => Ok(Transport::Tunnel(Tunnel::connect(config).await?)),
            TransportKind::Routing => Ok(Transport::Router(Router::connect(config).await?)),
        }
    }

    /// The raw individual address the gateway assigned to this connection's
    /// tunnel, if any.
    ///
    /// Connection-oriented management traffic should present this as its
    /// source address — many devices ignore frames from an address that is not
    /// the tunnel's. Routing connections have no assigned address (`None`);
    /// gateways that assign none report `0.0.0`, which is also `None` here.
    pub fn assigned_individual_address(&self) -> Option<u16> {
        match self {
            Transport::Tunnel(t) => t.assigned_individual_address().filter(|&ia| ia != 0),
            Transport::Router(_) => None,
        }
    }

    /// The tunnel's [`LinkState`] receiver, so a caller can surface a gateway
    /// link loss and its re-establishment (issue #177). `None` for routing,
    /// which has no connection to lose.
    pub fn link_state(&self) -> Option<tokio::sync::watch::Receiver<LinkState>> {
        match self {
            Transport::Tunnel(t) => Some(t.link_state()),
            Transport::Router(_) => None,
        }
    }
}

impl BusConnection for Transport {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        match self {
            Transport::Tunnel(t) => t.send(frame).await,
            Transport::Router(r) => r.send(frame).await,
        }
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        match self {
            Transport::Tunnel(t) => t.recv().await,
            Transport::Router(r) => r.recv().await,
        }
    }

    async fn close(self) -> Result<()> {
        match self {
            Transport::Tunnel(t) => t.close().await,
            Transport::Router(r) => r.close().await,
        }
    }
}
