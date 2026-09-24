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
//!   client L_Data.req is confirmed with an L_Data.con.
//!
//! The crypto comes from `bussard_secure::ipsecure`, so this mock checks the
//! client's state machine, not the byte layout; the independent peer for the
//! bytes is knx-sim's secure server.

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
}

/// Configures a [`MockSecureGateway`].
pub struct SecureGatewayBuilder {
    device_auth: Key16,
    users: Vec<MockSecureUser>,
    drop_after_requests: Option<usize>,
    push_after_connect: Vec<CemiFrame>,
}

impl SecureGatewayBuilder {
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

    /// Closes the first secure TCP connection after it carried `n`
    /// TUNNELLING_REQUESTs (a link loss the client must re-establish).
    pub fn drop_after_requests(mut self, n: usize) -> Self {
        self.drop_after_requests = Some(n);
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
        let mut last_err = None;
        for _ in 0..16 {
            let udp = UdpSocket::bind("127.0.0.1:0").await?;
            let port = udp.local_addr()?.port();
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(tcp) => return Ok(MockSecureGateway::spawn(self, udp, tcp, port)),
                Err(err) => last_err = Some(err),
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
    users: Vec<MockSecureUser>,
    drop_after_requests: Option<usize>,
    push_after_connect: Vec<CemiFrame>,
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
            users: Vec::new(),
            drop_after_requests: None,
            push_after_connect: Vec::new(),
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
        let config = Arc::new(Config {
            device_auth: builder.device_auth,
            users: builder.users,
            drop_after_requests: builder.drop_after_requests,
            push_after_connect: builder.push_after_connect,
        });
        let udp_task = tokio::spawn(serve_udp(udp, stats.clone()));
        let tcp_stats = stats.clone();
        let tcp_task = tokio::spawn(async move {
            let mut first = true;
            let mut channel = 0x40u8;
            while let Ok((stream, _)) = tcp.accept().await {
                let drop_after = if first {
                    config.drop_after_requests
                } else {
                    None
                };
                first = false;
                channel = channel.wrapping_add(1);
                let stats = tcp_stats.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = serve_tcp(stream, config, stats, drop_after, channel).await;
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
    let mut dibs = vec![0u8; 54];
    dibs[0] = 54;
    dibs[1] = knxnet::DIB_DEVICE_INFO;
    dibs[2] = 0x02;
    dibs[4..6].copy_from_slice(&SECURE_GATEWAY_IA.to_be_bytes());
    dibs[24..34].copy_from_slice(b"MockSecure");
    dibs.extend_from_slice(&[0x0A, 0x02, 0x02, 0x02, 0x03, 0x02, 0x04, 0x02, 0x09, 0x01]);
    dibs.extend_from_slice(&[0x06, 0x06, 0x03, 0x01, 0x04, 0x01]);
    dibs.extend_from_slice(&[0x0C, 0x07, 0x00, 0xF8]);
    dibs.extend_from_slice(&[0x11, 0x16, 0x00, 0x05, 0x11, 0x17, 0x00, 0x05]);
    dibs
}

/// The plain side: refuse CONNECT with 0x22, answer the searches.
async fn serve_udp(socket: UdpSocket, stats: Arc<Mutex<SecureGatewayStats>>) {
    let mut buf = [0u8; 1024];
    while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        let reply = match parsed.service {
            ServiceType::ConnectRequest => {
                bump(&stats, |s| s.plain_refusals += 1);
                knxnet::frame(ServiceType::ConnectResponse, &[0x00, 0x22])
            }
            ServiceType::SearchRequestExtended => {
                bump(&stats, |s| s.extended_searches += 1);
                let mut body = udp_hpai(peer);
                body.extend_from_slice(&extended_description_dibs());
                knxnet::frame(ServiceType::SearchResponseExtended, &body)
            }
            ServiceType::DescriptionRequest => {
                // A DESCRIPTION_RESPONSE carries no secure DIBs (CONFIRMED on
                // the Jung interface).
                knxnet::frame(
                    ServiceType::DescriptionResponse,
                    &extended_description_dibs()[..54],
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

/// One TCP connection: plain searches, or a secure session.
async fn serve_tcp(
    mut stream: TcpStream,
    config: Arc<Config>,
    stats: Arc<Mutex<SecureGatewayStats>>,
    drop_after: Option<usize>,
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
                body.extend_from_slice(&extended_description_dibs());
                let reply = knxnet::frame(ServiceType::SearchResponseExtended, &body);
                stream.write_all(&reply).await?;
            }
            ServiceType::SessionRequest => {
                let request = ipsecure::parse_session_request(&frame).map_err(secure_err)?;
                let server = EphemeralKeyPair::from_secret_bytes([0x5C; 32]);
                let session_id = 0x0001;
                let response = ipsecure::session_response(
                    &config.device_auth,
                    session_id,
                    &request.client_public,
                    server.public(),
                )
                .map_err(secure_err)?;
                stream.write_all(&response).await?;
                let key = server.session_key(&request.client_public);
                let mut session = IpSecureSession::new(key, session_id, [0x00, 0xA6, 0, 0, 0, 1]);
                let wrapped = read_frame(&mut stream).await?;
                let inner = session.open(&wrapped).map_err(secure_err)?;
                let auth = ipsecure::parse_session_authenticate(&inner).map_err(secure_err)?;
                let user = config.users.iter().find(|u| {
                    u.user_id == auth.user_id
                        && ipsecure::authenticate_mac(
                            &u.user_key,
                            u.user_id,
                            &request.client_public,
                            server.public(),
                        )
                        .is_ok_and(|mac| mac == auth.mac)
                });
                let status = if user.is_some() {
                    SessionStatus::Success
                } else {
                    SessionStatus::AuthenticationFailed
                };
                let reply = session
                    .seal(&ipsecure::session_status(status))
                    .map_err(secure_err)?;
                stream.write_all(&reply).await?;
                match user {
                    Some(user) => {
                        bump(&stats, |s| {
                            s.sessions += 1;
                            s.users.push(user.user_id);
                        });
                        break (session, user.clone());
                    }
                    None => {
                        bump(&stats, |s| s.auth_failures += 1);
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    };

    // Tunnelling inside the session.
    let mut tx_seq = 0u8;
    let mut requests = 0usize;
    loop {
        let frame = read_frame(&mut stream).await?;
        let Ok(inner) = session.open(&frame) else {
            bump(&stats, |s| s.bad_wrappers += 1);
            continue;
        };
        let Ok(parsed) = knxnet::parse(&inner) else {
            continue;
        };
        let mut replies: Vec<Vec<u8>> = Vec::new();
        match parsed.service {
            ServiceType::SessionStatus => match ipsecure::parse_session_status(&inner) {
                Ok(SessionStatus::KeepAlive) => bump(&stats, |s| s.keepalives += 1),
                Ok(SessionStatus::Close) => {
                    bump(&stats, |s| s.closes += 1);
                    return Ok(());
                }
                _ => {}
            },
            ServiceType::ConnectRequest => {
                bump(&stats, |s| s.connects += 1);
                let mut body = vec![channel, 0x00, 0x08, 0x02, 0, 0, 0, 0, 0, 0, 0x04, 0x04];
                body.extend_from_slice(&user.tunnel_ia.to_be_bytes());
                replies.push(knxnet::frame(ServiceType::ConnectResponse, &body));
                for push in &config.push_after_connect {
                    replies.push(knxnet::tunneling_request(
                        ConnectionHeader {
                            channel_id: channel,
                            seq: tx_seq,
                        },
                        push,
                    ));
                    tx_seq = tx_seq.wrapping_add(1);
                }
            }
            ServiceType::ConnectionstateRequest => {
                bump(&stats, |s| s.heartbeats += 1);
                replies.push(knxnet::connectionstate_response(channel, 0));
            }
            ServiceType::DisconnectRequest => {
                bump(&stats, |s| s.disconnects += 1);
                replies.push(knxnet::disconnect_response(channel, 0));
            }
            ServiceType::TunnelingAck => bump(&stats, |s| s.client_acks += 1),
            ServiceType::TunnelingRequest => {
                if let Ok(req) = knxnet::parse_tunneling_request(parsed.body) {
                    requests += 1;
                    let mut con = req.cemi.clone();
                    con.message_code = MessageCode::LDataCon;
                    bump(&stats, |s| s.requests.push(req.cemi));
                    replies.push(knxnet::tunneling_request(
                        ConnectionHeader {
                            channel_id: channel,
                            seq: tx_seq,
                        },
                        &con,
                    ));
                    tx_seq = tx_seq.wrapping_add(1);
                }
            }
            _ => {}
        }
        for reply in replies {
            let wrapped = session.seal(&reply).map_err(secure_err)?;
            stream.write_all(&wrapped).await?;
        }
        if drop_after.is_some_and(|n| requests >= n) {
            // Model a link loss: close the TCP connection abruptly.
            tokio::time::sleep(Duration::from_millis(10)).await;
            return Ok(());
        }
    }
}

fn secure_err(err: ipsecure::IpSecureError) -> MockError {
    MockError::Io(std::io::Error::other(err.to_string()))
}
