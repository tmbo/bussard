//! KNXnet/IP routing (multicast) transport.
//!
//! A [`Router`] joins the KNX routing multicast group (default
//! `224.0.23.12:3671`) and exchanges ROUTING_INDICATION frames. Unlike
//! tunneling there is no connection, sequence counter or ACK: sending is
//! fire-and-forget onto the group, paced by the rules of the standard
//! (issue #519):
//!
//! - at most 50 ROUTING_INDICATIONs per second, and at least 5 ms between two
//!   on the group (KNX IP 3/2/6 §2.1, §4.2);
//! - on ROUTING_BUSY, no send for the wait time `tw` (a second BUSY extends it
//!   to the larger of the remaining and the new time), then for a random
//!   `trandom` in `[0, N x 50 ms]`, where `N` counts BUSY frames received
//!   more than 10 ms apart and drops by one every 5 ms once `N x 100 ms` have
//!   passed since the last one (Routing 3/8/5 §2.3.5);
//! - datagrams leave with the multicast TTL of the connection config, 16 by
//!   default as PID_TTL (Device Management 3/8/3 §2.5.18), so they cross IP
//!   routers like those of every KNXnet/IP router in the installation.
//!
//! ROUTING_LOST_MESSAGE is informational (3/8/5 §2.3.4) and logged.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::cemi::CemiFrame;
use crate::config::ConnectionConfig;
use crate::conn::{BusConnection, TimestampedFrame};
use crate::error::Result;
use crate::knxnet::{self, ServiceType};

/// Most ROUTING_INDICATIONs sent in any one second (3/2/6 §2.1).
const MAX_PER_SECOND: usize = 50;
/// The least pause after a ROUTING_INDICATION on the group (3/2/6 §2.1).
const MIN_SPACING: Duration = Duration::from_millis(5);
/// BUSY frames closer than this to the previous one do not raise `N`
/// (3/8/5 §2.3.5): several routers may report the same congestion at once.
const BUSY_COUNT_GAP: Duration = Duration::from_millis(10);
/// The random wait per unit of `N` (3/8/5 §2.3.5).
const RANDOM_PER_BUSY: Duration = Duration::from_millis(50);
/// The quiet time per unit of `N` before `N` starts to fall (3/8/5 §2.3.5).
const SLOW_PER_BUSY: Duration = Duration::from_millis(100);
/// How often `N` falls by one once the quiet time has passed (3/8/5 §2.3.5).
const BUSY_DECREMENT: Duration = Duration::from_millis(5);

/// A KNXnet/IP routing (multicast) connection.
pub struct Router {
    socket: UdpSocket,
    group: SocketAddrV4,
    /// When the next ROUTING_INDICATION may leave.
    pacer: Pacer,
}

/// The send pacing of a router: the rate limit, the spacing, and the
/// ROUTING_BUSY flow control (module docs). Pure bookkeeping over the instants
/// it is given, so it is testable without a socket or a clock.
#[derive(Debug, Default)]
pub(crate) struct Pacer {
    /// When the last datagrams of the past second left, oldest first.
    sent: VecDeque<Instant>,
    /// The end of the BUSY wait `tw`, if one is running or ran.
    busy_until: Option<Instant>,
    /// The random wait `trandom` after `busy_until`.
    busy_random: Duration,
    /// `N`, as of `last_busy`.
    busy_count: u32,
    /// When the last ROUTING_BUSY arrived.
    last_busy: Option<Instant>,
}

impl Pacer {
    /// `N` at `now`: the count as of the last BUSY, less one per 5 ms past
    /// the quiet time of `N x 100 ms`.
    pub(crate) fn busy_count(&self, now: Instant) -> u32 {
        let Some(last) = self.last_busy else {
            return 0;
        };
        let slow = SLOW_PER_BUSY * self.busy_count;
        let quiet = now.saturating_duration_since(last);
        match quiet.checked_sub(slow) {
            None => self.busy_count,
            Some(past) => {
                let steps = past.as_micros() / BUSY_DECREMENT.as_micros();
                let steps = u32::try_from(steps).unwrap_or(u32::MAX);
                self.busy_count.saturating_sub(steps)
            }
        }
    }

    /// Takes a ROUTING_BUSY with wait time `wait` received at `now`.
    /// `random` is a uniform draw from `[0, 1]` for `trandom`.
    pub(crate) fn on_busy(&mut self, now: Instant, wait: Duration, random: f64) {
        let counts = self
            .last_busy
            .is_none_or(|last| now.saturating_duration_since(last) > BUSY_COUNT_GAP);
        let mut n = self.busy_count(now);
        if counts {
            n = n.saturating_add(1);
        }
        self.busy_count = n;
        self.last_busy = Some(now);
        let until = now + wait;
        self.busy_until = Some(match self.busy_until {
            Some(current) if current > until => current,
            _ => until,
        });
        self.busy_random = RANDOM_PER_BUSY.mul_f64(random.clamp(0.0, 1.0) * f64::from(n));
    }

    /// The earliest instant at or after `now` the next datagram may leave.
    pub(crate) fn next_send(&mut self, now: Instant) -> Instant {
        let window = Duration::from_secs(1);
        while self
            .sent
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= window)
        {
            self.sent.pop_front();
        }
        let mut at = now;
        if let Some(&last) = self.sent.back() {
            at = at.max(last + MIN_SPACING);
        }
        if self.sent.len() >= MAX_PER_SECOND
            && let Some(&oldest) = self.sent.front()
        {
            at = at.max(oldest + window);
        }
        if let Some(until) = self.busy_until {
            at = at.max(until + self.busy_random);
        }
        at
    }

    /// Records a datagram sent at `now`.
    pub(crate) fn sent(&mut self, now: Instant) {
        self.sent.push_back(now);
        while self.sent.len() > MAX_PER_SECOND {
            self.sent.pop_front();
        }
    }
}

/// A uniform draw from `[0, 1]` for the BUSY random wait. Jitter only, so
/// the standard library's randomly seeded hasher is enough.
fn jitter() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

impl Router {
    /// Joins the routing multicast group described by `config` and returns a
    /// ready-to-use router.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self> {
        let group = config.multicast;
        let interface = config.local_interface;
        let socket =
            Self::bind_multicast(*group.ip(), group.port(), interface, config.multicast_ttl)?;
        let socket = UdpSocket::from_std(socket)?;
        Ok(Router {
            socket,
            group,
            pacer: Pacer::default(),
        })
    }

    /// Builds a UDP socket bound for multicast reception with the appropriate
    /// address-reuse options, joined to `group` on `interface`.
    fn bind_multicast(
        group: Ipv4Addr,
        port: u16,
        interface: Ipv4Addr,
        ttl: u32,
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
        // The OS default (1 on most systems) never crosses an IP router; the
        // standard's PID_TTL defaults to 16 (3/8/3 §2.5.18, issue #519).
        socket.set_multicast_ttl_v4(ttl)?;

        Ok(socket.into())
    }

    /// Waits until the pacing rules let the next datagram leave.
    async fn honor_pause(&mut self) {
        let at = self.pacer.next_send(Instant::now());
        tokio::time::sleep_until(at).await;
    }
}

impl BusConnection for Router {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        self.honor_pause().await;
        let datagram = knxnet::routing_indication(&frame);
        let target = SocketAddr::from(self.group);
        self.socket.send_to(&datagram, target).await?;
        self.pacer.sent(Instant::now());
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
                        let now = Instant::now();
                        self.pacer.on_busy(
                            now,
                            Duration::from_millis(u64::from(busy.wait_time_ms)),
                            jitter(),
                        );
                        tracing::warn!(
                            wait_ms = busy.wait_time_ms,
                            busy_count = self.pacer.busy_count(now),
                            "ROUTING_BUSY: pausing sends"
                        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn test_next_send_spaces_datagrams_by_5_ms() {
        let mut pacer = Pacer::default();
        let t0 = Instant::now();
        assert_eq!(pacer.next_send(t0), t0);
        pacer.sent(t0);
        assert_eq!(pacer.next_send(t0 + ms(1)), t0 + ms(5));
        assert_eq!(pacer.next_send(t0 + ms(7)), t0 + ms(7));
    }

    #[test]
    fn test_next_send_caps_50_per_second() {
        let mut pacer = Pacer::default();
        let t0 = Instant::now();
        for i in 0..50 {
            pacer.sent(t0 + ms(5 * i));
        }
        // The 51st waits until the first leaves the one-second window.
        let now = t0 + ms(250);
        assert_eq!(pacer.next_send(now), t0 + ms(1000));
        pacer.sent(t0 + ms(1000));
        assert_eq!(pacer.next_send(t0 + ms(1001)), t0 + ms(1005));
    }

    #[test]
    fn test_on_busy_waits_tw_plus_random_and_keeps_the_longer_wait() {
        let mut pacer = Pacer::default();
        let t0 = Instant::now();
        pacer.on_busy(t0, ms(100), 0.0);
        assert_eq!(pacer.next_send(t0), t0 + ms(100));
        // A shorter BUSY 20 ms later keeps the remaining 80 ms; N is 2 now
        // and the full random draw adds 2 x 50 ms.
        pacer.on_busy(t0 + ms(20), ms(30), 1.0);
        assert_eq!(pacer.busy_count(t0 + ms(20)), 2);
        assert_eq!(pacer.next_send(t0 + ms(20)), t0 + ms(200));
    }

    #[test]
    fn test_on_busy_counts_frames_more_than_10_ms_apart() {
        let mut pacer = Pacer::default();
        let t0 = Instant::now();
        pacer.on_busy(t0, ms(20), 0.0);
        pacer.on_busy(t0 + ms(5), ms(20), 0.0);
        assert_eq!(pacer.busy_count(t0 + ms(5)), 1, "within 10 ms: same event");
        pacer.on_busy(t0 + ms(20), ms(20), 0.0);
        assert_eq!(pacer.busy_count(t0 + ms(20)), 2);
    }

    #[test]
    fn test_busy_count_decays_after_the_slow_duration() {
        let mut pacer = Pacer::default();
        let t0 = Instant::now();
        pacer.on_busy(t0, ms(20), 0.0);
        pacer.on_busy(t0 + ms(20), ms(20), 0.0);
        let last = t0 + ms(20);
        // N = 2: no decrement for 200 ms, then one per 5 ms.
        assert_eq!(pacer.busy_count(last + ms(200)), 2);
        assert_eq!(pacer.busy_count(last + ms(205)), 1);
        assert_eq!(pacer.busy_count(last + ms(210)), 0);
        assert_eq!(pacer.busy_count(last + ms(500)), 0);
    }

    #[test]
    fn test_jitter_is_in_the_unit_interval() {
        for _ in 0..100 {
            let r = jitter();
            assert!((0.0..=1.0).contains(&r), "{r}");
        }
    }
}
