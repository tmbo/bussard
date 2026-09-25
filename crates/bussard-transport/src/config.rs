//! Connection configuration and the timing/retry constants.
//!
//! [`ConnectionConfig`] deliberately mirrors the *shape* of the model's
//! `bussard.toml` connection section but does **not** import
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

/// Default read deadline of a KNXnet/IP Secure tunnel over TCP (issue #192).
///
/// TCP carries no TUNNELING_ACK, so a pulled LAN cable is otherwise noticed
/// only when the kernel gives up retransmitting (about 37 s on macOS, longer on
/// Linux). When nothing has arrived for this long the tunnel sends a
/// CONNECTIONSTATE_REQUEST as a liveness probe; an answer (or any other frame)
/// keeps the link, silence for another [`TCP_LINK_PROBE_TIMEOUT`] declares it
/// lost and re-establishes it. A busy tunnel never probes: every tunnelled
/// frame is confirmed by an `L_Data.con`, which counts as traffic.
pub const TCP_READ_DEADLINE: Duration = Duration::from_secs(5);

/// The longest a TCP liveness probe (see [`TCP_READ_DEADLINE`]) waits for its
/// answer. A reachable interface answers in milliseconds; the probe waits the
/// shorter of this and the configured read deadline.
pub const TCP_LINK_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
///
/// Over TCP (KNXnet/IP Secure) there is no ACK to time out, so
/// `tcp_read_deadline` bounds how long the link may stay silent before a
/// liveness probe decides whether it is lost (issue #192).
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
    /// How long a TCP tunnel may receive nothing before it probes the link
    /// with a CONNECTIONSTATE_REQUEST (see [`TCP_READ_DEADLINE`]). An
    /// unanswered probe counts as a lost link. [`Duration::ZERO`] turns the
    /// check off, leaving detection to the 60 s heartbeat and the kernel's
    /// TCP timeout. Ignored on a plain UDP tunnel, whose ACK timeout already
    /// detects a loss within about 2 s.
    pub tcp_read_deadline: Duration,
}

impl Default for TunnelReconnect {
    fn default() -> Self {
        TunnelReconnect {
            budget: TUNNEL_RECONNECT_BUDGET,
            initial_backoff: TUNNEL_RECONNECT_INITIAL_BACKOFF,
            max_backoff: TUNNEL_RECONNECT_MAX_BACKOFF,
            attempt_timeout: TUNNEL_RECONNECT_ATTEMPT_TIMEOUT,
            tcp_read_deadline: TCP_READ_DEADLINE,
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

    /// This policy with a different TCP read deadline (`Duration::ZERO` turns
    /// the check off).
    pub fn with_tcp_read_deadline(mut self, deadline: Duration) -> Self {
        self.tcp_read_deadline = deadline;
        self
    }

    /// How long a TCP liveness probe waits for its answer: the shorter of the
    /// read deadline and [`TCP_LINK_PROBE_TIMEOUT`].
    pub fn tcp_probe_timeout(&self) -> Duration {
        self.tcp_read_deadline.min(TCP_LINK_PROBE_TIMEOUT)
    }

    /// Whether this policy re-establishes a lost tunnel at all.
    pub fn enabled(&self) -> bool {
        !self.budget.is_zero()
    }
}

/// Default interval of the KNXnet/IP Secure session keepalive (a wrapped
/// SESSION_STATUS `STATUS_KEEPALIVE`). The server drops an idle session after
/// its session timeout (60 s in the KNX specification); every 30 s keeps well
/// inside that with one lost keepalive to spare. INFERRED (the XKNX rate);
/// [`SecureTunnelConfig::keepalive`] overrides it (issue #197).
pub const SECURE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for the KNXnet/IP Secure probe (SEARCH_REQUEST_EXTENDED) that
/// decides between a plain and a secure tunnel.
pub const SECURE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The credentials of one KNXnet/IP Secure tunnelling user (issue #71 Phase
/// B): the user id and password, plus what the keyring says about the
/// interface.
///
/// The passwords stay passwords until the transport has picked the user it
/// will present: each PBKDF2 derivation costs tens of milliseconds and a
/// keyring lists every tunnelling user of the interface.
///
/// `Debug` redacts the secrets; the type is not serializable.
#[derive(Clone, PartialEq, Eq)]
pub struct SecureUser {
    /// The user id presented in SESSION_AUTHENTICATE (1 = management, 2..
    /// tunnelling users).
    pub user_id: u8,
    /// The user password (key = PBKDF2 with `user-password.1.secure.ip.knx.org`).
    pub password: bussard_secure::Password,
    /// The interface's device authentication code (key = PBKDF2 with
    /// `device-authentication-code.1.secure.ip.knx.org`). With it the client
    /// verifies the SESSION_RESPONSE MAC (the interface proves its identity);
    /// without it the check is skipped with a warning.
    pub device_authentication_code: Option<bussard_secure::Password>,
    /// The tunnel individual address the keyring binds this user to (the
    /// interface assigns it on CONNECT), if known.
    pub tunnel_ia: Option<u16>,
    /// The individual address of the interface (the keyring's `Host`), if
    /// known. Used to pick the user for the gateway actually reached.
    pub host_ia: Option<u16>,
}

impl std::fmt::Debug for SecureUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureUser")
            .field("user_id", &self.user_id)
            .field("password", &"<redacted>")
            .field(
                "device_authentication_code",
                &self
                    .device_authentication_code
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("tunnel_ia", &self.tunnel_ia)
            .field("host_ia", &self.host_ia)
            .finish()
    }
}

/// Where the KNXnet/IP Secure credentials came from, which decides when the
/// tunnel goes secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureSource {
    /// From a keyring: go secure only when the gateway's own individual
    /// address matches a keyring interface (`Host`) and the gateway advertises
    /// KNXnet/IP Secure; otherwise stay plain.
    Keyring,
    /// From explicit flags (`--secure-user`/`--secure-password-env`): always
    /// open a secure session with the single given user.
    Explicit,
}

/// Which carrier a KNXnet/IP Secure session runs over (issue #197).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecureTransport {
    /// TCP, the carrier ETS uses with the tested interface and the only one
    /// verified against a real interface. When the TCP connect is refused and
    /// the interface's extended search advertises KNXnet/IP Secure, the
    /// connect fails with [`TransportError::SecureTcpRefused`] naming
    /// `--secure-transport udp`; it never switches to UDP on its own
    /// (issue #197).
    ///
    /// [`TransportError::SecureTcpRefused`]: crate::TransportError::SecureTcpRefused
    #[default]
    Auto,
    /// TCP only: no TUNNELING_ACK, route-back HPAIs (CONFIRMED against the
    /// Jung interface).
    Tcp,
    /// UDP only, an explicit opt-in: the session and the tunnel on one UDP
    /// socket, TUNNELING_ACK inside SECURE_WRAPPERs, the real local endpoint
    /// in every HPAI. INFERRED from the KNX specification, verified against
    /// knx-sim and the testkit mock only; no real interface has been tested.
    Udp,
}

impl std::fmt::Display for SecureTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SecureTransport::Auto => "auto",
            SecureTransport::Tcp => "tcp",
            SecureTransport::Udp => "udp",
        })
    }
}

/// KNXnet/IP Secure tunnelling configuration: the candidate users, how they
/// were supplied, the carrier and the session keepalive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureTunnelConfig {
    /// The candidate users. With [`SecureSource::Keyring`] the transport picks
    /// one whose `host_ia` is the gateway and whose tunnel slot is free.
    pub users: Vec<SecureUser>,
    /// Where the users came from.
    pub source: SecureSource,
    /// TCP (the default, `Auto`), or UDP when explicitly asked for.
    pub transport: SecureTransport,
    /// How often the tunnel sends a wrapped `STATUS_KEEPALIVE`
    /// ([`SECURE_KEEPALIVE_INTERVAL`] by default). [`Duration::ZERO`] sends
    /// none, leaving the session to the tunnel's own traffic and heartbeats.
    pub keepalive: Duration,
}

impl SecureTunnelConfig {
    /// `users` from `source`, with the default carrier ([`SecureTransport::Auto`])
    /// and keepalive ([`SECURE_KEEPALIVE_INTERVAL`]).
    pub fn new(users: Vec<SecureUser>, source: SecureSource) -> Self {
        SecureTunnelConfig {
            users,
            source,
            transport: SecureTransport::Auto,
            keepalive: SECURE_KEEPALIVE_INTERVAL,
        }
    }

    /// This configuration over `transport`.
    pub fn with_transport(mut self, transport: SecureTransport) -> Self {
        self.transport = transport;
        self
    }

    /// This configuration with a different keepalive interval
    /// (`Duration::ZERO` turns the keepalive off).
    pub fn with_keepalive(mut self, keepalive: Duration) -> Self {
        self.keepalive = keepalive;
        self
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
/// This mirrors the `connection:` block of `bussard.toml` but is defined here
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
    /// KNXnet/IP Secure tunnelling credentials, if any (issue #71 Phase B).
    /// `None` keeps the plain UDP tunnel; a secure-only interface then fails
    /// fast with [`TransportError::SecureRequired`](crate::TransportError::SecureRequired).
    pub secure: Option<SecureTunnelConfig>,
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
            secure: None,
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
            secure: None,
        }
    }

    /// This configuration with KNXnet/IP Secure tunnelling credentials.
    pub fn with_secure(mut self, secure: Option<SecureTunnelConfig>) -> Self {
        self.secure = secure;
        self
    }

    /// This configuration with a different tunnel re-establish policy.
    pub fn with_reconnect(mut self, reconnect: TunnelReconnect) -> Self {
        self.reconnect = reconnect;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_tunnel_config_new_defaults_and_overrides() {
        let config = SecureTunnelConfig::new(Vec::new(), SecureSource::Explicit);
        assert_eq!(config.transport, SecureTransport::Auto);
        assert_eq!(config.keepalive, SECURE_KEEPALIVE_INTERVAL);
        let config = config
            .with_transport(SecureTransport::Udp)
            .with_keepalive(Duration::from_secs(10));
        assert_eq!(config.transport, SecureTransport::Udp);
        assert_eq!(config.keepalive, Duration::from_secs(10));
        assert_eq!(SecureTransport::Udp.to_string(), "udp");
    }
}
