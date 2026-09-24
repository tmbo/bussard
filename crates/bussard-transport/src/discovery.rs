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
    // The extended search as well: only its answer carries the KNXnet/IP
    // Secure DIBs (issue #182). Interfaces without Core v2 ignore it.
    socket
        .send_to(&knxnet::search_request_extended(hpai), group)
        .await?;

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
                let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                    continue;
                };
                let extended = parsed.service == ServiceType::SearchResponseExtended;
                if (parsed.service == ServiceType::SearchResponse || extended)
                    && let Ok(info) = knxnet::parse_search_response(parsed.body)
                {
                    match found.iter_mut().find(|g| g.endpoint == info.endpoint) {
                        // The extended answer knows more (security, slots).
                        Some(existing) if extended => *existing = info,
                        Some(_) => {}
                        None => found.push(info),
                    }
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

/// Asks one gateway for its extended description (SEARCH_REQUEST_EXTENDED /
/// SEARCH_RESPONSE_EXTENDED), which, unlike a DESCRIPTION_RESPONSE, carries
/// the KNXnet/IP Secure DIBs: the security service family and the secured
/// service families (issue #182).
///
/// Tries, in order, and returns the first answer:
///
/// 1. TCP to the control endpoint, exactly as ETS does (issue #90 S4 capture:
///    TCP route-back HPAI + SRP `08 04 01 08 02 06 07 00`); an interface
///    without TCP refuses the connection at once;
/// 2. unicast UDP: the extended search and a plain DESCRIPTION_REQUEST side by
///    side; the plain description (no security information) is the answer
///    only when no extended one follows it shortly.
///
/// Each step waits up to `timeout`. Read-only: nothing reaches the KNX bus.
pub async fn describe_gateway_extended(
    endpoint: SocketAddrV4,
    timeout: Duration,
) -> Result<GatewayDescription> {
    match search_extended_tcp(endpoint, timeout).await {
        Ok(d) => return Ok(d),
        Err(err) => tracing::debug!(%err, "extended search over TCP to {endpoint} failed"),
    }
    search_extended_udp(endpoint, timeout).await
}

/// SEARCH_REQUEST_EXTENDED over a short-lived TCP connection.
async fn search_extended_tcp(
    endpoint: SocketAddrV4,
    timeout: Duration,
) -> Result<GatewayDescription> {
    use tokio::io::AsyncWriteExt;
    let mut stream = crate::secure::tcp_connect(endpoint, Ipv4Addr::UNSPECIFIED, timeout).await?;
    stream
        .write_all(&knxnet::search_request_extended(Hpai::tcp_route_back()))
        .await?;
    let mut reader = crate::secure::FrameReader::new();
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = match tokio::time::timeout(remaining, reader.read_frame(&mut stream)).await {
            Ok(frame) => frame?,
            Err(_) => return Err(TransportError::Timeout("SEARCH_RESPONSE_EXTENDED")),
        };
        if let Ok(parsed) = knxnet::parse(&frame)
            && parsed.service == ServiceType::SearchResponseExtended
        {
            let _ = stream.shutdown().await;
            return Ok(knxnet::parse_search_response(parsed.body)?.description);
        }
    }
}

/// How long a UDP probe keeps waiting for the extended answer after a plain
/// DESCRIPTION_RESPONSE already arrived (an older interface never sends one).
const EXTENDED_GRACE: Duration = Duration::from_millis(250);

/// SEARCH_REQUEST_EXTENDED and DESCRIPTION_REQUEST as unicast UDP datagrams
/// on one socket. Returns the extended answer when it comes, else the plain
/// description once [`EXTENDED_GRACE`] has passed after it.
async fn search_extended_udp(
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
        .send(&knxnet::search_request_extended(Hpai::new(local)))
        .await?;
    socket
        .send(&knxnet::description_request(Hpai::new(local)))
        .await?;
    let mut deadline = Instant::now() + timeout;
    let mut plain: Option<GatewayDescription> = None;
    let mut buf = [0u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return plain.ok_or(TransportError::Timeout("SEARCH_RESPONSE_EXTENDED"));
        }
        match tokio::time::timeout(remaining, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => match knxnet::parse(&buf[..n]) {
                Ok(parsed) if parsed.service == ServiceType::SearchResponseExtended => {
                    return Ok(knxnet::parse_search_response(parsed.body)?.description);
                }
                Ok(parsed)
                    if parsed.service == ServiceType::DescriptionResponse && plain.is_none() =>
                {
                    plain = Some(knxnet::parse_description_response(parsed.body)?);
                    deadline = deadline.min(Instant::now() + EXTENDED_GRACE);
                }
                _ => {}
            },
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return plain.ok_or(TransportError::Timeout("SEARCH_RESPONSE_EXTENDED"));
            }
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
