//! KNXnet/IP gateway discovery via SEARCH_REQUEST / SEARCH_RESPONSE.
//!
//! [`discover`] sends a SEARCH_REQUEST to the discovery multicast group and
//! collects every SEARCH_RESPONSE that arrives within a timeout, returning the
//! gateways found (name, individual address, control endpoint).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::config::{DEFAULT_MULTICAST, DEFAULT_PORT};
use crate::error::Result;
use crate::knxnet::{self, GatewayInfo, Hpai, ServiceType};

/// Discovers KNXnet/IP gateways on the local network.
///
/// Broadcasts a SEARCH_REQUEST on the discovery multicast group and returns all
/// distinct gateways that respond within `timeout`. `interface` selects the
/// local IPv4 interface (`0.0.0.0` lets the OS choose).
pub async fn discover(timeout: Duration, interface: Ipv4Addr) -> Result<Vec<GatewayInfo>> {
    // A short-lived unicast socket bound to an ephemeral port; the gateway
    // replies to the discovery-endpoint HPAI we send.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_if_v4(&interface)?;
    let bind: SocketAddr = SocketAddr::from(SocketAddrV4::new(interface, 0));
    socket.bind(&bind.into())?;
    let socket = UdpSocket::from_std(socket.into())?;

    let local = match socket.local_addr()? {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => SocketAddrV4::new(interface, 0),
    };

    // Send the SEARCH_REQUEST advertising our discovery endpoint. If we bound to
    // the wildcard we can't put a useful IP in the HPAI, so use route-back.
    let hpai = if local.ip().is_unspecified() {
        Hpai::wildcard()
    } else {
        Hpai::new(local)
    };
    let req = knxnet::search_request(hpai);
    let group = SocketAddr::from(SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT));
    socket.send_to(&req, group).await?;

    let deadline = Instant::now() + timeout;
    let mut found: Vec<GatewayInfo> = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                if let Ok(parsed) = knxnet::parse(&buf[..n]) {
                    if parsed.service == ServiceType::SearchResponse {
                        if let Ok(info) = knxnet::parse_search_response(parsed.body) {
                            if !found.iter().any(|g| g.endpoint == info.endpoint) {
                                found.push(info);
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break, // overall timeout elapsed
        }
    }

    Ok(found)
}
