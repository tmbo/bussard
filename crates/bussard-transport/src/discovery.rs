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
use crate::error::{Result, TransportError};
use crate::knxnet::{self, GatewayDescription, GatewayInfo, Hpai, ServiceType};

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
                if let Ok(parsed) = knxnet::parse(&buf[..n])
                    && parsed.service == ServiceType::SearchResponse
                    && let Ok(info) = knxnet::parse_search_response(parsed.body)
                    && !found.iter().any(|g| g.endpoint == info.endpoint)
                {
                    found.push(info);
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break, // overall timeout elapsed
        }
    }

    Ok(found)
}

/// Asks one gateway's control endpoint to describe itself
/// (DESCRIPTION_REQUEST / DESCRIPTION_RESPONSE).
///
/// Unicast, so unlike [`discover`] it works across subnets. The answer carries
/// the device-info DIB (name, individual address, serial) and, on a KNXnet/IP
/// Core v2 interface, the tunnelling-info DIB with one entry per tunnelling
/// slot — which is how bussard reports "N tunnels, M in use" (issue #105).
///
/// Read-only: nothing is put on the KNX bus, only a UDP exchange with the
/// interface itself.
pub async fn describe_gateway(
    endpoint: SocketAddrV4,
    timeout: Duration,
) -> Result<GatewayDescription> {
    let socket = UdpSocket::bind(SocketAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        0,
    )))
    .await?;
    socket.connect(endpoint).await?;
    let local = match socket.local_addr()? {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => {
            return Err(TransportError::InvalidField {
                field: "local socket is IPv6, KNXnet/IP requires IPv4",
                value: 0,
            });
        }
    };
    socket
        .send(&knxnet::description_request(Hpai::new(local)))
        .await?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Timeout("DESCRIPTION_RESPONSE"));
        }
        match tokio::time::timeout(remaining, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(parsed) = knxnet::parse(&buf[..n])
                    && parsed.service == ServiceType::DescriptionResponse
                {
                    return knxnet::parse_description_response(parsed.body);
                }
                // Anything else on this ephemeral port is not ours; keep waiting.
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(TransportError::Timeout("DESCRIPTION_RESPONSE")),
        }
    }
}

/// Enumerates the machine's usable local IPv4 interfaces.
///
/// Loopback is excluded (a gateway is never reachable there) and the wildcard
/// `0.0.0.0` is skipped. The result feeds [`discover_all`], which searches on
/// each interface because KNXnet/IP discovery is multicast and multicast does
/// not route between subnets — the SEARCH_REQUEST must egress the interface on
/// the gateway's own network.
pub fn local_ipv4_interfaces() -> Vec<Ipv4Addr> {
    let mut addrs: Vec<Ipv4Addr> = match if_addrs::get_if_addrs() {
        Ok(ifaces) => ifaces
            .into_iter()
            .filter_map(|iface| match iface.addr.ip() {
                std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
                _ => None,
            })
            .collect(),
        Err(err) => {
            tracing::warn!("could not enumerate local interfaces: {err}");
            Vec::new()
        }
    };
    addrs.sort();
    addrs.dedup();
    addrs
}

/// Discovers gateways across every local IPv4 interface concurrently.
///
/// Runs [`discover`] on each interface returned by [`local_ipv4_interfaces`]
/// (each with its own `timeout`) and merges the results, de-duplicating by
/// control endpoint. If no interfaces can be enumerated, falls back to a single
/// wildcard search so discovery still works in constrained environments.
pub async fn discover_all(timeout: Duration) -> Result<Vec<GatewayInfo>> {
    let mut interfaces = local_ipv4_interfaces();
    if interfaces.is_empty() {
        // Fall back to a single wildcard search so discovery still works when
        // interface enumeration is unavailable.
        interfaces.push(Ipv4Addr::UNSPECIFIED);
    }

    let mut set = tokio::task::JoinSet::new();
    for iface in interfaces {
        set.spawn(async move { discover(timeout, iface).await });
    }

    let mut merged: Vec<GatewayInfo> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(gateways)) => {
                for gw in gateways {
                    if !merged.iter().any(|g| g.endpoint == gw.endpoint) {
                        merged.push(gw);
                    }
                }
            }
            // A failure on one interface (e.g. no route) must not sink the rest.
            Ok(Err(err)) => tracing::debug!("discovery on one interface failed: {err}"),
            Err(err) => tracing::debug!("discovery task join error: {err}"),
        }
    }
    Ok(merged)
}
