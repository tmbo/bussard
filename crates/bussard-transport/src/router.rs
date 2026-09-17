//! KNXnet/IP routing (multicast) transport.
//!
//! A [`Router`] joins the KNX routing multicast group (default
//! `224.0.23.12:3671`) and exchanges ROUTING_INDICATION frames. Unlike
//! tunneling there is no connection, sequence counter or ACK: sending is
//! fire-and-forget onto the group. ROUTING_LOST_MESSAGE and ROUTING_BUSY are
//! decoded and surfaced as `tracing::warn` log records; on ROUTING_BUSY the
//! sender additionally pauses for the requested wait time.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::cemi::CemiFrame;
use crate::config::ConnectionConfig;
use crate::conn::{BusConnection, TimestampedFrame};
use crate::error::Result;
use crate::knxnet::{self, ServiceType};

/// A KNXnet/IP routing (multicast) connection.
pub struct Router {
    /// The multicast socket. Wrapped in an `Arc` so a cheap [`RouterSender`] can
    /// share it for fire-and-forget sends while the actor keeps receiving.
    socket: Arc<UdpSocket>,
    group: SocketAddrV4,
    /// Instant (as millis since an epoch) until which sending is paused because
    /// of a ROUTING_BUSY. Shared so it survives across `send`/`recv` calls.
    pause_until: Arc<PauseClock>,
}

/// A cheap, cloneable send-only handle for a [`Router`].
///
/// It shares the router's multicast socket and ROUTING_BUSY pause clock, so a
/// send issued through it honours the same back-off the receiving half observes.
/// This lets the bus actor spawn a send without giving up its `&mut` borrow of
/// the receiving `Router` (issue #57).
pub struct RouterSender {
    socket: Arc<UdpSocket>,
    group: SocketAddrV4,
    pause_until: Arc<PauseClock>,
}

impl RouterSender {
    /// Waits out any ROUTING_BUSY-imposed pause, then sends `frame` on the group.
    pub async fn send(&self, frame: CemiFrame) -> Result<()> {
        let wait = self.pause_until.remaining();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let datagram = knxnet::routing_indication(&frame);
        let target = SocketAddr::from(self.group);
        self.socket.send_to(&datagram, target).await?;
        Ok(())
    }
}

/// A monotonic pause deadline stored as milliseconds since process start.
struct PauseClock {
    origin: Instant,
    until_ms: AtomicU64,
}

impl PauseClock {
    fn new() -> Self {
        PauseClock {
            origin: Instant::now(),
            until_ms: AtomicU64::new(0),
        }
    }

    fn set_pause(&self, wait: Duration) {
        let now_ms = self.origin.elapsed().as_millis() as u64;
        let target = now_ms + wait.as_millis() as u64;
        // Only extend, never shorten.
        let mut cur = self.until_ms.load(Ordering::Relaxed);
        while target > cur {
            match self.until_ms.compare_exchange_weak(
                cur,
                target,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    fn remaining(&self) -> Duration {
        let now_ms = self.origin.elapsed().as_millis() as u64;
        let until = self.until_ms.load(Ordering::Relaxed);
        if until > now_ms {
            Duration::from_millis(until - now_ms)
        } else {
            Duration::ZERO
        }
    }
}

impl Router {
    /// Joins the routing multicast group described by `config` and returns a
    /// ready-to-use router.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self> {
        let group = config.multicast;
        let interface = config.local_interface;
        let socket = Self::bind_multicast(*group.ip(), group.port(), interface)?;
        let socket = UdpSocket::from_std(socket)?;
        Ok(Router {
            socket: Arc::new(socket),
            group,
            pause_until: Arc::new(PauseClock::new()),
        })
    }

    /// Returns a cheap, cloneable send-only handle sharing this router's socket
    /// and pause clock.
    pub fn sender(&self) -> RouterSender {
        RouterSender {
            socket: Arc::clone(&self.socket),
            group: self.group,
            pause_until: Arc::clone(&self.pause_until),
        }
    }

    /// Builds a UDP socket bound for multicast reception with the appropriate
    /// address-reuse options, joined to `group` on `interface`.
    fn bind_multicast(
        group: Ipv4Addr,
        port: u16,
        interface: Ipv4Addr,
    ) -> Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Allow multiple listeners on the same group/port (e.g. bussard plus a
        // home-automation controller on the same host).
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;

        // Bind to the group port. Binding to the wildcard address is the most
        // portable choice for receiving multicast across platforms.
        let bind_addr: SocketAddr =
            SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        socket.bind(&bind_addr.into())?;

        // Join the multicast group on the requested interface.
        socket.join_multicast_v4(&group, &interface)?;
        // Send multicast out of the same interface.
        socket.set_multicast_if_v4(&interface)?;
        // Keep our own multicast sends off our receive path unless explicitly
        // wanted; loopback stays on so loopback tests work.
        socket.set_multicast_loop_v4(true)?;

        Ok(socket.into())
    }

    /// Waits out any ROUTING_BUSY-imposed pause before sending.
    async fn honor_pause(&self) {
        let wait = self.pause_until.remaining();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

impl BusConnection for Router {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        self.honor_pause().await;
        let datagram = knxnet::routing_indication(&frame);
        let target = SocketAddr::from(self.group);
        self.socket.send_to(&datagram, target).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        let mut buf = [0u8; 1024];
        loop {
            let (n, _from) = self.socket.recv_from(&mut buf).await?;
            let parsed = match knxnet::parse(&buf[..n]) {
                Ok(p) => p,
                Err(_) => continue, // ignore malformed datagrams on the group
            };
            match parsed.service {
                ServiceType::RoutingIndication => {
                    match knxnet::parse_routing_indication(parsed.body) {
                        Ok(frame) => {
                            return Ok(TimestampedFrame {
                                received_at: SystemTime::now(),
                                frame,
                            });
                        }
                        Err(_) => continue,
                    }
                }
                ServiceType::RoutingBusy => {
                    if let Ok(busy) = knxnet::parse_routing_busy(parsed.body) {
                        // Surface the back-off request and honour it. No waiter is
                        // notified out-of-band: the actor that owns this Router
                        // only awaits `recv`, so a `tracing::warn` is the honest
                        // surfacing (see conn.rs BusEvent removal).
                        tracing::warn!(wait_ms = busy.wait_time_ms, "ROUTING_BUSY: pausing sends");
                        self.pause_until
                            .set_pause(Duration::from_millis(busy.wait_time_ms as u64));
                    }
                    continue;
                }
                ServiceType::RoutingLostMessage => {
                    if let Ok(lost) = knxnet::parse_routing_lost(parsed.body) {
                        // Same rationale as ROUTING_BUSY: warn, since no consumer
                        // reads router events out of band.
                        tracing::warn!(lost = lost.lost, "ROUTING_LOST_MESSAGE");
                    }
                    continue;
                }
                _ => continue, // discovery etc. not relevant on the data path
            }
        }
    }

    async fn close(self) -> Result<()> {
        // Dropping the socket leaves the multicast group. Nothing to negotiate.
        drop(self);
        Ok(())
    }
}
