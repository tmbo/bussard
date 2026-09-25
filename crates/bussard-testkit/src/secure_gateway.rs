//! [`MockSecureGateway`]: a loopback KNXnet/IP **Secure** tunnelling interface
//! (issue #71 Phase B).
//!
//! It models a secure-only interface the way the Jung IP interface behaved in
//! the issue #90 S4 capture:
//!
//! - UDP on the port: a plain CONNECT_REQUEST is refused with status `0x22`;
//!   SEARCH_REQUEST_EXTENDED and DESCRIPTION_REQUEST are answered (the
//!   extended answer lists the security family and the secured-families DIB
//!   `06 06 03 01 04 01`).
//! - TCP on the same port: SEARCH_REQUEST_EXTENDED answered in the clear;
//!   SESSION_REQUEST -> SESSION_RESPONSE (MAC under the device authentication
//!   key); a wrapped SESSION_AUTHENTICATE checked against the configured
//!   users; a wrapped SESSION_STATUS; then CONNECT, CONNECTIONSTATE,
//!   DISCONNECT and TUNNELLING_REQUEST inside SECURE_WRAPPERs, no ACKs. Each
//!   client L_Data.req is confirmed with an L_Data.con, then answered by the
//!   [`MockDevice`]s on the line behind the interface, if any.
//!
//! - Optionally ([`SecureGatewayBuilder::udp_sessions`], issue #197) the same
//!   secure session over UDP, keyed by the client's endpoint, with
//!   TUNNELING_ACKs inside the wrappers in both directions; and
//!   ([`SecureGatewayBuilder::without_tcp`]) no TCP endpoint at all, so a TCP
//!   connect is refused as on a UDP-only interface.
//! - Optionally ([`SecureGatewayBuilder::session_timeout`]) an idle session
//!   timeout: a TCP session gets a wrapped `STATUS_TIMEOUT` and is closed, a
//!   UDP session is forgotten silently.
//!
//! The crypto comes from `bussard_secure::ipsecure`, so this mock checks the
//! client's state machine, not the byte layout; the independent peer for the
//! bytes is knx-sim's secure server.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_secure::Key16;
use bussard_secure::ipsecure::{self, EphemeralKeyPair, IpSecureSession, SessionStatus};
use bussard_transport::cemi::{CemiFrame, MessageCode};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::MockDevice;
use crate::MockError;

/// The interface's own individual address (1.1.200, as in the capture).
pub const SECURE_GATEWAY_IA: u16 = 0x11C8;

/// One tunnelling user the mock accepts.
#[derive(Clone)]
pub struct MockSecureUser {
    /// The user id.
    pub user_id: u8,
    /// PBKDF2 of the user password.
    pub user_key: Key16,
    /// The tunnel individual address handed out on CONNECT.
    pub tunnel_ia: u16,
}

/// What the mock has seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecureGatewayStats {
    /// Plain UDP CONNECT_REQUESTs refused with `0x22`.
    pub plain_refusals: usize,
    /// SEARCH_REQUEST_EXTENDED answered (UDP or TCP).
    pub extended_searches: usize,
    /// Secure sessions that authenticated.
    pub sessions: usize,
    /// SESSION_AUTHENTICATEs refused.
    pub auth_failures: usize,
    /// The user ids that authenticated, in order.
    pub users: Vec<u8>,
    /// CONNECT_REQUESTs granted over secure sessions.
    pub connects: usize,
    /// CONNECTIONSTATE_REQUESTs answered.
    pub heartbeats: usize,
    /// SESSION_STATUS keepalives received.
    pub keepalives: usize,
    /// SESSION_STATUS closes received.
    pub closes: usize,
    /// DISCONNECT_REQUESTs answered.
    pub disconnects: usize,
    /// TUNNELING_ACKs the client sent (must stay 0 over TCP).
    pub client_acks: usize,
    /// Every cEMI frame the client tunnelled.
    pub requests: Vec<CemiFrame>,
    /// Wrappers that failed to verify.
    pub bad_wrappers: usize,
    /// Frames read and ignored on a stalled connection (see
    /// [`SecureGatewayBuilder::stall_after_requests`]).
    pub stalled_frames: usize,
    /// Secure sessions that authenticated over UDP (a subset of `sessions`).
    pub udp_sessions: usize,
    /// Sessions ended by the idle timeout (see
    /// [`SecureGatewayBuilder::session_timeout`]).
    pub timeouts: usize,
}

/// Configures a [`MockSecureGateway`].
pub struct SecureGatewayBuilder {
    device_auth: Key16,
    individual_address: u16,
    devices: Vec<MockDevice>,
    users: Vec<MockSecureUser>,
    drop_after_requests: Option<usize>,
    stall_after_requests: Option<usize>,
    push_after_connect: Vec<CemiFrame>,
    udp_sessions: bool,
    tcp: bool,
    session_timeout: Option<Duration>,
    feature_info_first: bool,
}

impl SecureGatewayBuilder {
    /// Sends a wrapped TUNNELLING_FEATURE_INFO before each CONNECT_RESPONSE,
    /// so the client's handshake must skip an unrelated authenticated frame
    /// (issue #197: over TCP and UDP alike).
    pub fn feature_info_before_connect_response(mut self) -> Self {
        self.feature_info_first = true;
        self
    }

    /// Also accepts KNXnet/IP Secure sessions over UDP on the port
    /// (issue #197): SESSION_REQUEST with the client's UDP HPAI, then the
    /// wrapped tunnel with TUNNELING_ACKs.
    pub fn udp_sessions(mut self) -> Self {
        self.udp_sessions = true;
        self
    }

    /// Serves no TCP: a TCP connect to the port is refused, as on an
    /// interface without a TCP endpoint. Implies nothing about UDP; combine
    /// with [`udp_sessions`](Self::udp_sessions).
    pub fn without_tcp(mut self) -> Self {
        self.tcp = false;
        self
    }

    /// Ends a secure session after `timeout` without a frame from the client:
    /// a wrapped `STATUS_TIMEOUT` and a close over TCP, silence over UDP.
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = Some(timeout);
        self
    }

    /// Adds an accepted tunnelling user.
    pub fn user(mut self, user_id: u8, user_key: Key16, tunnel_ia: u16) -> Self {
        self.users.push(MockSecureUser {
            user_id,
            user_key,
            tunnel_ia,
        });
        self
    }

    /// Sets the device authentication key the SESSION_RESPONSE MAC uses.
    pub fn device_auth(mut self, key: Key16) -> Self {
        self.device_auth = key;
        self
    }

    /// Sets the interface's own individual address (default
    /// [`SECURE_GATEWAY_IA`]), reported in the search/description answers: a
    /// keyring tunnelling user is matched to the interface by it.
    pub fn individual_address(mut self, ia: u16) -> Self {
        self.individual_address = ia;
        self
    }

    /// Puts a [`MockDevice`] on the line behind the interface: it answers the
    /// management frames tunnelled to it (issue #189: a plain device reached
    /// through the secure tunnel).
    pub fn device(mut self, device: MockDevice) -> Self {
        self.devices.push(device);
        self
    }

    /// Closes the first secure TCP connection after it carried `n`
    /// TUNNELLING_REQUESTs (a link loss the client must re-establish).
    pub fn drop_after_requests(mut self, n: usize) -> Self {
        self.drop_after_requests = Some(n);
        self
    }

    /// Stalls the first secure TCP connection after it carried `n`
    /// TUNNELLING_REQUESTs: the connection stays open but nothing is answered
    /// any more, which is what a pulled LAN cable looks like to the client
    /// (no FIN, no RST, just silence; issue #192).
    pub fn stall_after_requests(mut self, n: usize) -> Self {
        self.stall_after_requests = Some(n);
        self
    }

    /// Pushes this indication to the client right after each CONNECT.
    pub fn push_after_connect(mut self, frame: CemiFrame) -> Self {
        self.push_after_connect.push(frame);
        self
    }

    /// Binds UDP and TCP on one loopback port and starts serving.
    ///
    /// # Errors
    /// A socket error, or no port free for both protocols after a few tries.
    pub async fn start(self) -> Result<MockSecureGateway, MockError> {
        // The sockets of failed attempts are held until a pair binds, so the
        // OS cannot hand the same ephemeral port back on the next try. On
        // Windows a TCP bind inside an excluded port range fails with
        // WSAEACCES, and consecutive ephemeral UDP ports often all fall in one
        // such range, so the attempts alternate between UDP-first and
        // TCP-first.
        let mut held_udp = Vec::new();
        let mut held_tcp = Vec::new();
        let mut last_err = None;
        for attempt in 0..32 {
            if attempt % 2 == 0 {
                let udp = UdpSocket::bind("127.0.0.1:0").await?;
                let port = udp.local_addr()?.port();
                match TcpListener::bind(("127.0.0.1", port)).await {
                    Ok(tcp) => return Ok(MockSecureGateway::spawn(self, udp, tcp, port)),
                    Err(err) => {
                        last_err = Some(err);
                        held_udp.push(udp);
                    }
                }
            } else {
                let tcp = TcpListener::bind("127.0.0.1:0").await?;
                let port = tcp.local_addr()?.port();
                match UdpSocket::bind(("127.0.0.1", port)).await {
                    Ok(udp) => return Ok(MockSecureGateway::spawn(self, udp, tcp, port)),
                    Err(err) => {
                        last_err = Some(err);
                        held_tcp.push(tcp);
                    }
                }
            }
        }
        Err(MockError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::other("no free port for UDP and TCP")
        })))
    }
}

/// Shared configuration of the serving tasks.
struct Config {
    device_auth: Key16,
    individual_address: u16,
    line: Mutex<Vec<MockDevice>>,
    users: Vec<MockSecureUser>,
    drop_after_requests: Option<usize>,
    stall_after_requests: Option<usize>,
    push_after_connect: Vec<CemiFrame>,
    udp_sessions: bool,
    session_timeout: Option<Duration>,
    feature_info_first: bool,
}

/// A running mock secure interface. Dropping it stops the tasks.
pub struct MockSecureGateway {
    port: u16,
    stats: Arc<Mutex<SecureGatewayStats>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MockSecureGateway {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MockSecureGateway {
    /// A builder with no users and an all-`0x11` device authentication key.
    pub fn builder() -> SecureGatewayBuilder {
        SecureGatewayBuilder {
            device_auth: Key16::new([0x11; 16]),
            individual_address: SECURE_GATEWAY_IA,
            devices: Vec::new(),
            users: Vec::new(),
            drop_after_requests: None,
            stall_after_requests: None,
            push_after_connect: Vec::new(),
            udp_sessions: false,
            tcp: true,
            session_timeout: None,
            feature_info_first: false,
        }
    }

    /// The control endpoint (UDP and TCP share the port).
    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, self.port)
    }

    /// A snapshot of what the mock has seen.
    ///
    /// # Errors
    /// A poisoned state lock.
    pub fn stats(&self) -> Result<SecureGatewayStats, MockError> {
        self.stats
            .lock()
            .map(|s| s.clone())
            .map_err(|_| MockError::Poisoned)
    }

    fn spawn(builder: SecureGatewayBuilder, udp: UdpSocket, tcp: TcpListener, port: u16) -> Self {
        let stats = Arc::new(Mutex::new(SecureGatewayStats::default()));
        let serve_tcp_side = builder.tcp;
        let config = Arc::new(Config {
            device_auth: builder.device_auth,
            individual_address: builder.individual_address,
            line: Mutex::new(builder.devices),
            users: builder.users,
            drop_after_requests: builder.drop_after_requests,
            stall_after_requests: builder.stall_after_requests,
            push_after_connect: builder.push_after_connect,
            udp_sessions: builder.udp_sessions,
            session_timeout: builder.session_timeout,
            feature_info_first: builder.feature_info_first,
        });
        let udp_task = tokio::spawn(serve_udp(udp, stats.clone(), config.clone()));
        if !serve_tcp_side {
            // Closing the listener frees the TCP port: a connect is refused.
            drop(tcp);
            return MockSecureGateway {
                port,
                stats,
                tasks: vec![udp_task],
            };
        }
        let tcp_stats = stats.clone();
        let tcp_task = tokio::spawn(async move {
            let mut first = true;
            let mut channel = 0x40u8;
            while let Ok((stream, _)) = tcp.accept().await {
                let faults = if first {
                    Faults {
                        drop_after: config.drop_after_requests,
                        stall_after: config.stall_after_requests,
                    }
                } else {
                    Faults::default()
                };
                first = false;
                channel = channel.wrapping_add(1);
                let stats = tcp_stats.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = serve_tcp(stream, config, stats, faults, channel).await;
                });
            }
        });
        MockSecureGateway {
            port,
            stats,
            tasks: vec![udp_task, tcp_task],
        }
    }
}

fn bump(stats: &Mutex<SecureGatewayStats>, f: impl FnOnce(&mut SecureGatewayStats)) {
    if let Ok(mut s) = stats.lock() {
        f(&mut s);
    }
}

/// The DIBs of the extended description: device info (IA 1.1.200), service
/// families incl. security, secured families (device management, tunnelling),
/// tunnelling info with two slots 1.1.22 (free) and 1.1.23 (free).
pub fn extended_description_dibs() -> Vec<u8> {
    extended_description_dibs_for(SECURE_GATEWAY_IA)
}

/// [`extended_description_dibs`] with the interface at individual address `ia`.
pub fn extended_description_dibs_for(ia: u16) -> Vec<u8> {
    let mut dibs = vec![0u8; 54];
    dibs[0] = 54;
    dibs[1] = knxnet::DIB_DEVICE_INFO;
    dibs[2] = 0x02;
    dibs[4..6].copy_from_slice(&ia.to_be_bytes());
    dibs[24..34].copy_from_slice(b"MockSecure");
    dibs.extend_from_slice(&[0x0A, 0x02, 0x02, 0x02, 0x03, 0x02, 0x04, 0x02, 0x09, 0x01]);
    dibs.extend_from_slice(&[0x06, 0x06, 0x03, 0x01, 0x04, 0x01]);
    dibs.extend_from_slice(&[0x0C, 0x07, 0x00, 0xF8]);
    dibs.extend_from_slice(&[0x11, 0x16, 0x00, 0x05, 0x11, 0x17, 0x00, 0x05]);
    dibs
}

/// A secure session over UDP, keyed by the client's endpoint.
enum UdpSession {
    /// SESSION_RESPONSE sent, waiting for the wrapped SESSION_AUTHENTICATE.
    Pending(Pending, tokio::time::Instant),
    /// Authenticated.
    Established {
        session: IpSecureSession,
        side: TunnelSide,
        last_rx: tokio::time::Instant,
    },
}

/// The UDP side: refuse a plain CONNECT with 0x22, answer the searches, and
/// (with [`SecureGatewayBuilder::udp_sessions`]) serve secure sessions.
async fn serve_udp(socket: UdpSocket, stats: Arc<Mutex<SecureGatewayStats>>, config: Arc<Config>) {
    let ia = config.individual_address;
    let mut buf = [0u8; 1024];
    let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
    let mut next_channel = 0x60u8;
    loop {
        let received =
            tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await;
        if let Some(timeout) = config.session_timeout {
            // Forget idle sessions silently, as a UDP server has no
            // connection to close.
            let before = sessions.len();
            sessions.retain(|_, s| match s {
                UdpSession::Pending(_, at) => at.elapsed() < timeout,
                UdpSession::Established { last_rx, .. } => last_rx.elapsed() < timeout,
            });
            let expired = before - sessions.len();
            if expired > 0 {
                bump(&stats, |s| s.timeouts += expired);
            }
        }
        let (n, peer) = match received {
            Err(_) => continue,
            Ok(Ok(r)) => r,
            // A client that went away (ICMP refusal): keep serving.
            Ok(Err(_)) => continue,
        };
        let frame = buf[..n].to_vec();
        let Ok(parsed) = knxnet::parse(&frame) else {
            continue;
        };
        if config.udp_sessions {
            match parsed.service {
                ServiceType::SessionRequest => {
                    if let Ok((response, pending)) = accept_session_request(&config, &frame) {
                        let _ = socket.send_to(&response, peer).await;
                        sessions.insert(
                            peer,
                            UdpSession::Pending(pending, tokio::time::Instant::now()),
                        );
                    }
                    continue;
                }
                ServiceType::SecureWrapper => {
                    let replies = match sessions.remove(&peer) {
                        Some(UdpSession::Pending(pending, _)) => {
                            match finish_authentication(&config, pending, &frame, &stats) {
                                Ok((session, reply, Some(user))) => {
                                    bump(&stats, |s| s.udp_sessions += 1);
                                    next_channel = next_channel.wrapping_add(1);
                                    sessions.insert(
                                        peer,
                                        UdpSession::Established {
                                            session,
                                            side: TunnelSide::new(next_channel, user.tunnel_ia),
                                            last_rx: tokio::time::Instant::now(),
                                        },
                                    );
                                    vec![reply]
                                }
                                Ok((_, reply, None)) => vec![reply],
                                Err(_) => Vec::new(),
                            }
                        }
                        Some(UdpSession::Established {
                            mut session,
                            mut side,
                            ..
                        }) => {
                            let inner = match session.open(&frame) {
                                Ok(inner) => inner,
                                Err(_) => {
                                    bump(&stats, |s| s.bad_wrappers += 1);
                                    sessions.insert(
                                        peer,
                                        UdpSession::Established {
                                            session,
                                            side,
                                            last_rx: tokio::time::Instant::now(),
                                        },
                                    );
                                    continue;
                                }
                            };
                            let step = tunnel_step(&inner, &mut side, &config, &stats, true);
                            let mut sealed = Vec::new();
                            for reply in step.replies {
                                if let Ok(w) = session.seal(&reply) {
                                    sealed.push(w);
                                }
                            }
                            if !step.close {
                                sessions.insert(
                                    peer,
                                    UdpSession::Established {
                                        session,
                                        side,
                                        last_rx: tokio::time::Instant::now(),
                                    },
                                );
                            }
                            sealed
                        }
                        // A wrapper for no (or a forgotten) session: silence.
                        None => Vec::new(),
                    };
                    for reply in replies {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                    continue;
                }
                _ => {}
            }
        }
        let reply = match parsed.service {
            ServiceType::ConnectRequest => {
                bump(&stats, |s| s.plain_refusals += 1);
                knxnet::frame(ServiceType::ConnectResponse, &[0x00, 0x22])
            }
            ServiceType::SearchRequestExtended => {
                bump(&stats, |s| s.extended_searches += 1);
                let mut body = udp_hpai(peer);
                body.extend_from_slice(&extended_description_dibs_for(ia));
                knxnet::frame(ServiceType::SearchResponseExtended, &body)
            }
            ServiceType::DescriptionRequest => {
                // A DESCRIPTION_RESPONSE carries no secure DIBs (CONFIRMED on
                // the Jung interface).
                knxnet::frame(
                    ServiceType::DescriptionResponse,
                    &extended_description_dibs_for(ia)[..54],
                )
            }
            _ => continue,
        };
        let _ = socket.send_to(&reply, peer).await;
    }
}

fn udp_hpai(peer: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x08, 0x01];
    match peer {
        SocketAddr::V4(v4) => {
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(_) => out.extend_from_slice(&[0; 6]),
    }
    out
}

/// Reads one KNXnet/IP frame from a TCP stream.
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, MockError> {
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await?;
    let total = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let mut frame = header.to_vec();
    if total > 6 {
        let mut rest = vec![0u8; total - 6];
        stream.read_exact(&mut rest).await?;
        frame.extend_from_slice(&rest);
    }
    Ok(frame)
}

/// The link faults one TCP connection models.
#[derive(Default, Clone, Copy)]
struct Faults {
    /// Close the connection after this many TUNNELLING_REQUESTs.
    drop_after: Option<usize>,
    /// Stop answering (but keep the connection open) after this many.
    stall_after: Option<usize>,
}

/// A session between SESSION_RESPONSE and SESSION_AUTHENTICATE.
struct Pending {
    session: IpSecureSession,
    client_public: [u8; ipsecure::PUBLIC_KEY_LEN],
    server_public: [u8; ipsecure::PUBLIC_KEY_LEN],
}

/// Answers a SESSION_REQUEST: the SESSION_RESPONSE and the pending session.
fn accept_session_request(config: &Config, frame: &[u8]) -> Result<(Vec<u8>, Pending), MockError> {
    let request = ipsecure::parse_session_request(frame).map_err(secure_err)?;
    let server = EphemeralKeyPair::from_secret_bytes([0x5C; 32]);
    let session_id = 0x0001;
    let response = ipsecure::session_response(
        &config.device_auth,
        session_id,
        &request.client_public,
        server.public(),
    )
    .map_err(secure_err)?;
    let key = server.session_key(&request.client_public);
    Ok((
        response,
        Pending {
            session: IpSecureSession::new(key, session_id, [0x00, 0xA6, 0, 0, 0, 1]),
            client_public: request.client_public,
            server_public: *server.public(),
        },
    ))
}

/// Checks the wrapped SESSION_AUTHENTICATE: the session, the wrapped
/// SESSION_STATUS reply and the user, if one matched.
fn finish_authentication(
    config: &Config,
    pending: Pending,
    wrapped: &[u8],
    stats: &Mutex<SecureGatewayStats>,
) -> Result<(IpSecureSession, Vec<u8>, Option<MockSecureUser>), MockError> {
    let mut session = pending.session;
    let inner = session.open(wrapped).map_err(secure_err)?;
    let auth = ipsecure::parse_session_authenticate(&inner).map_err(secure_err)?;
    let user = config
        .users
        .iter()
        .find(|u| {
            u.user_id == auth.user_id
                && ipsecure::authenticate_mac(
                    &u.user_key,
                    u.user_id,
                    &pending.client_public,
                    &pending.server_public,
                )
                .is_ok_and(|mac| mac == auth.mac)
        })
        .cloned();
    let status = if user.is_some() {
        SessionStatus::Success
    } else {
        SessionStatus::AuthenticationFailed
    };
    let reply = session
        .seal(&ipsecure::session_status(status))
        .map_err(secure_err)?;
    match &user {
        Some(user) => bump(stats, |s| {
            s.sessions += 1;
            s.users.push(user.user_id);
        }),
        None => bump(stats, |s| s.auth_failures += 1),
    }
    Ok((session, reply, user))
}

/// The tunnelling state of one authenticated session.
struct TunnelSide {
    channel: u8,
    tunnel_ia: u16,
    tx_seq: u8,
    requests: usize,
}

impl TunnelSide {
    fn new(channel: u8, tunnel_ia: u16) -> Self {
        TunnelSide {
            channel,
            tunnel_ia,
            tx_seq: 0,
            requests: 0,
        }
    }
}

/// What one inner frame produced.
struct Step {
    /// Plain frames to wrap and send back.
    replies: Vec<Vec<u8>>,
    /// The client closed the session.
    close: bool,
}

/// Serves one plain inner frame of an authenticated session. `acks`: the
/// session runs over UDP, so client TUNNELLING_REQUESTs are acknowledged.
fn tunnel_step(
    inner: &[u8],
    side: &mut TunnelSide,
    config: &Config,
    stats: &Mutex<SecureGatewayStats>,
    acks: bool,
) -> Step {
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let Ok(parsed) = knxnet::parse(inner) else {
        return Step {
            replies,
            close: false,
        };
    };
    let channel = side.channel;
    match parsed.service {
        ServiceType::SessionStatus => match ipsecure::parse_session_status(inner) {
            Ok(SessionStatus::KeepAlive) => bump(stats, |s| s.keepalives += 1),
            Ok(SessionStatus::Close) => {
                bump(stats, |s| s.closes += 1);
                return Step {
                    replies,
                    close: true,
                };
            }
            _ => {}
        },
        ServiceType::ConnectRequest => {
            bump(stats, |s| s.connects += 1);
            if config.feature_info_first {
                // Connection header (4 octets), feature id 0x03 (bus
                // connection status), reserved, value 1 (connected).
                replies.push(knxnet::frame(
                    ServiceType::TunnelingFeatureInfo,
                    &[0x04, channel, side.tx_seq, 0x00, 0x03, 0x00, 0x01],
                ));
            }
            let mut body = vec![channel, 0x00, 0x08, 0x02, 0, 0, 0, 0, 0, 0, 0x04, 0x04];
            body.extend_from_slice(&side.tunnel_ia.to_be_bytes());
            replies.push(knxnet::frame(ServiceType::ConnectResponse, &body));
            for push in &config.push_after_connect {
                replies.push(knxnet::tunneling_request(
                    ConnectionHeader {
                        channel_id: channel,
                        seq: side.tx_seq,
                    },
                    push,
                ));
                side.tx_seq = side.tx_seq.wrapping_add(1);
            }
        }
        ServiceType::ConnectionstateRequest => {
            bump(stats, |s| s.heartbeats += 1);
            let asked = parsed.body.first().copied().unwrap_or(channel);
            // E_CONNECTION_ID for a channel this session does not hold.
            let status = if asked == channel { 0x00 } else { 0x21 };
            replies.push(knxnet::connectionstate_response(asked, status));
        }
        ServiceType::DisconnectRequest => {
            bump(stats, |s| s.disconnects += 1);
            replies.push(knxnet::disconnect_response(channel, 0));
        }
        ServiceType::TunnelingAck => bump(stats, |s| s.client_acks += 1),
        ServiceType::TunnelingRequest => {
            if let Ok(req) = knxnet::parse_tunneling_request(parsed.body) {
                side.requests += 1;
                if acks {
                    replies.push(knxnet::tunneling_ack(channel, req.header.seq, 0));
                }
                let mut con = req.cemi.clone();
                con.message_code = MessageCode::LDataCon;
                let answers = match config.line.lock() {
                    Ok(mut line) => crate::gateway::line_replies(&mut line, &req.cemi),
                    Err(_) => Vec::new(),
                };
                bump(stats, |s| s.requests.push(req.cemi));
                for frame in std::iter::once(con).chain(answers) {
                    replies.push(knxnet::tunneling_request(
                        ConnectionHeader {
                            channel_id: channel,
                            seq: side.tx_seq,
                        },
                        &frame,
                    ));
                    side.tx_seq = side.tx_seq.wrapping_add(1);
                }
            }
        }
        _ => {}
    }
    Step {
        replies,
        close: false,
    }
}

/// Reads the next frame of a secure TCP session, honouring the idle timeout:
/// `Ok(None)` when the session timed out.
async fn read_session_frame(
    stream: &mut TcpStream,
    timeout: Option<Duration>,
) -> Result<Option<Vec<u8>>, MockError> {
    match timeout {
        None => read_frame(stream).await.map(Some),
        Some(t) => match tokio::time::timeout(t, read_frame(stream)).await {
            Ok(frame) => frame.map(Some),
            Err(_) => Ok(None),
        },
    }
}

/// One TCP connection: plain searches, or a secure session.
async fn serve_tcp(
    mut stream: TcpStream,
    config: Arc<Config>,
    stats: Arc<Mutex<SecureGatewayStats>>,
    faults: Faults,
    channel: u8,
) -> Result<(), MockError> {
    // Handshake.
    let (mut session, user) = loop {
        let frame = read_frame(&mut stream).await?;
        let parsed = knxnet::parse(&frame)?;
        match parsed.service {
            ServiceType::SearchRequestExtended => {
                bump(&stats, |s| s.extended_searches += 1);
                let mut body = vec![0x08, 0x02, 0, 0, 0, 0, 0, 0];
                body.extend_from_slice(&extended_description_dibs_for(config.individual_address));
                let reply = knxnet::frame(ServiceType::SearchResponseExtended, &body);
                stream.write_all(&reply).await?;
            }
            ServiceType::SessionRequest => {
                let (response, pending) = accept_session_request(&config, &frame)?;
                stream.write_all(&response).await?;
                let wrapped = read_frame(&mut stream).await?;
                let (session, reply, user) =
                    finish_authentication(&config, pending, &wrapped, &stats)?;
                stream.write_all(&reply).await?;
                match user {
                    Some(user) => break (session, user),
                    None => return Ok(()),
                }
            }
            _ => {}
        }
    };

    // Tunnelling inside the session.
    let mut side = TunnelSide::new(channel, user.tunnel_ia);
    loop {
        let Some(frame) = read_session_frame(&mut stream, config.session_timeout).await? else {
            bump(&stats, |s| s.timeouts += 1);
            let notice = session
                .seal(&ipsecure::session_status(SessionStatus::Timeout))
                .map_err(secure_err)?;
            stream.write_all(&notice).await?;
            return Ok(());
        };
        let Ok(inner) = session.open(&frame) else {
            bump(&stats, |s| s.bad_wrappers += 1);
            continue;
        };
        let step = tunnel_step(&inner, &mut side, &config, &stats, false);
        for reply in step.replies {
            let wrapped = session.seal(&reply).map_err(secure_err)?;
            stream.write_all(&wrapped).await?;
        }
        if step.close {
            return Ok(());
        }
        if faults.drop_after.is_some_and(|n| side.requests >= n) {
            // Model a link loss: close the TCP connection abruptly.
            tokio::time::sleep(Duration::from_millis(10)).await;
            return Ok(());
        }
        if faults.stall_after.is_some_and(|n| side.requests >= n) {
            // Model a pulled cable: keep the connection open, read what the
            // client sends so its writes never block, answer nothing.
            loop {
                read_frame(&mut stream).await?;
                bump(&stats, |s| s.stalled_frames += 1);
            }
        }
    }
}

fn secure_err(err: ipsecure::IpSecureError) -> MockError {
    MockError::Io(std::io::Error::other(err.to_string()))
}
