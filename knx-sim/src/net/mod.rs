//! KNXnet/IP tunnelling server frontend.
//!
//! Presents a UDP tunnelling gateway so a tool connects exactly as it would to
//! a real KNXnet/IP interface. It terminates the tunnel, unwraps cEMI, hands it
//! to the [`Bus`], and wraps device responses back into `TUNNELLING_REQUEST`
//! frames toward the tool.
//!
//! Routing/multicast is a later addition; this frontend is deliberately kept
//! behind a thin boundary so a `RoutingServer` can be added alongside it and
//! feed the same bus.
//!
//! # KNXnet/IP Secure (issue #71 Phase B)
//!
//! With [`KnxnetIpServer::enable_secure`] the gateway also listens on TCP on
//! the same port and behaves like the Jung IP interface of bussard issue #90
//! S4: a KNXnet/IP Secure session (SESSION_REQUEST / RESPONSE, a wrapped
//! SESSION_AUTHENTICATE / STATUS) and then CONNECT, heartbeats, tunnelling
//! and DISCONNECT inside SECURE_WRAPPERs, with no TUNNELLING_ACK (TCP). In
//! secure-only mode a plain UDP CONNECT_REQUEST is refused with `0x22`, and
//! the extended search answer lists tunnelling as a secured service family.
//! See [`crate::secure::ipsecure`] for the crypto.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::bus::Bus;
use crate::config::IpSecureConfig;
use crate::secure::ipsecure::{self, Handshake, SecureSession};
use crate::wire::IndividualAddress;
use crate::wire::cemi::CemiLData;
use crate::wire::knxnetip::{
    ConnectionHeader, E_CONNECTION_ID, E_CONNECTION_TYPE, KnxnetIpFrame, service,
};

/// Who a frame came from: a UDP endpoint or a secure TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Peer {
    /// A plain UDP client.
    Udp(SocketAddr),
    /// A TCP connection (its id), whose traffic is wrapped once the secure
    /// session is authenticated.
    Tcp(usize),
}

/// The secure-gateway settings, with the password keys derived once.
struct SecureGateway {
    individual_address: u16,
    device_key: [u8; 16],
    secure_only: bool,
    /// (user id, password key, tunnel individual address).
    users: Vec<(u8, [u8; 16], u16)>,
    listener: TcpListener,
    next_id: usize,
    conns: BTreeMap<usize, TcpConn>,
}

/// One TCP connection's state.
struct TcpConn {
    stream: TcpStream,
    buf: Vec<u8>,
    state: TcpState,
    /// The tunnelling channel this connection's CONNECT was granted.
    channel: u8,
}

enum TcpState {
    /// No secure session yet: only searches and SESSION_REQUEST.
    Plain,
    /// SESSION_RESPONSE sent; waiting for the wrapped SESSION_AUTHENTICATE.
    Authenticating(Handshake),
    /// Authenticated as `user`.
    Established {
        session: SecureSession,
        user: u8,
        tunnel_ia: u16,
    },
}

/// A blocking KNXnet/IP tunnelling gateway over UDP.
pub struct KnxnetIpServer {
    socket: UdpSocket,
    bus: Bus,
    channel: u8,
    /// Per-client sequence counters for TUNNELLING_REQUESTs we send toward each
    /// tool, keyed by the client's UDP endpoint and reset to 0 on its
    /// CONNECT_REQUEST. The KNXnet/IP tunnelling sequence counter is **per
    /// connection** (a client silently discards an out-of-window sequence, per
    /// the spec's discard rule), so a single global counter would desync every
    /// other client whenever two tunnels are open at once — e.g. a `viz`
    /// session watching the bus while a second tool toggles programming mode.
    tx_seqs: BTreeMap<Peer, u8>,
    /// The currently-connected tunnel client, if any. Device-originated
    /// telegrams (scripted stimulus, group responses fanned to the tool) are
    /// forwarded here so the connected monitor/read sees them.
    peer: Option<Peer>,
    /// A monotonic clock origin for scheduling stimulus.
    started: Instant,
    /// KNXnet/IP Secure, when enabled.
    secure: Option<SecureGateway>,
}

/// Errors from running the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A socket I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A secure-gateway setting did not parse.
    #[error("config: {0}")]
    Config(String),
}

impl KnxnetIpServer {
    /// Bind a server on `addr`, serving the given bus.
    pub fn bind(addr: SocketAddr, bus: Bus) -> Result<Self, ServerError> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            bus,
            channel: 1,
            tx_seqs: BTreeMap::new(),
            peer: None,
            started: Instant::now(),
            secure: None,
        })
    }

    /// Enables KNXnet/IP Secure: binds TCP on the gateway's own address and
    /// port and derives the configured users' keys (PBKDF2, once).
    pub fn enable_secure(&mut self, cfg: &IpSecureConfig) -> Result<(), ServerError> {
        let parse_ia = |s: &str| -> Result<u16, ServerError> {
            s.parse::<IndividualAddress>()
                .map(|ia| ia.0)
                .map_err(|e| ServerError::Config(format!("bad individual address {s:?}: {e}")))
        };
        let listener = TcpListener::bind(self.socket.local_addr()?)?;
        listener.set_nonblocking(true)?;
        let mut users = Vec::new();
        for u in &cfg.users {
            users.push((
                u.id,
                ipsecure::user_password_key(&u.password),
                parse_ia(&u.tunnel_address)?,
            ));
        }
        self.secure = Some(SecureGateway {
            individual_address: parse_ia(&cfg.individual_address)?,
            device_key: ipsecure::device_authentication_key(&cfg.device_authentication_code),
            secure_only: cfg.secure_only,
            users,
            listener,
            next_id: 0,
            conns: BTreeMap::new(),
        });
        Ok(())
    }

    /// The local address the server bound to (useful when binding to port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Borrow the bus (for observation).
    pub fn bus(&self) -> &Bus {
        &self.bus
    }

    /// Serve forever. Returns only on a socket error.
    ///
    /// The socket has a short read timeout so the loop wakes periodically even
    /// when the client is idle, letting it drive scripted stimulus. Each wake
    /// ticks the bus's stimulus schedule and forwards any device-originated
    /// telegrams to the connected tunnel client.
    pub fn serve(&mut self) -> Result<(), ServerError> {
        // A 100 ms wakeup is fine-grained enough for the example's multi-second
        // stimulus periods while keeping the loop responsive to client traffic.
        // With a TCP side the loop also polls the secure connections, so it
        // wakes every few milliseconds instead.
        let wake = if self.secure.is_some() { 5 } else { 100 };
        self.socket
            .set_read_timeout(Some(Duration::from_millis(wake)))?;
        let mut buf = [0u8; 1024];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, peer)) => self.handle_datagram(&buf[..n], peer)?,
                // Idle wakeups (read timeout) drive the stimulus below.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                // A client that closed its socket (e.g. mid-flash across a device
                // reboot) can trigger an ICMP port-unreachable, surfaced on the
                // next recv as ConnectionRefused/ConnectionReset. A real gateway
                // keeps serving — it does not fall over because one datagram could
                // not be delivered — so treat it as transient and forget the peer.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    if matches!(self.peer, Some(Peer::Udp(_))) {
                        self.peer = None;
                    }
                }
                Err(e) => return Err(ServerError::Io(e)),
            }
            self.poll_tcp();
            self.pump_stimulus();
        }
    }

    /// Tick the stimulus schedule and forward any produced telegrams to the
    /// connected tunnel client. A send failure (the client went away) is
    /// non-fatal: a real gateway does not crash because a datagram could not be
    /// delivered — it forgets the peer and keeps serving.
    ///
    /// [`serve`](Self::serve) calls this on every loop iteration; it is also
    /// public so a test harness driving the server via [`serve_n`](Self::serve_n)
    /// can advance the stimulus deterministically.
    pub fn pump_stimulus(&mut self) {
        let Some(peer) = self.peer else {
            return;
        };
        let now_ms = self.started.elapsed().as_millis();
        let telegrams = self.bus.tick_stimulus(now_ms);
        for cemi in telegrams {
            if self.send_tunnelling(&cemi, peer).is_err() {
                // The client is gone; stop forwarding until it reconnects.
                self.peer = None;
                break;
            }
        }
    }

    /// Serve exactly `count` datagrams then return (used by tests to bound the
    /// loop).
    pub fn serve_n(&mut self, count: usize) -> Result<(), ServerError> {
        let mut buf = [0u8; 1024];
        for _ in 0..count {
            let (n, peer) = self.socket.recv_from(&mut buf)?;
            self.handle_datagram(&buf[..n], peer)?;
        }
        Ok(())
    }

    /// Process one inbound KNXnet/IP datagram from `peer`, emitting the
    /// appropriate replies. Public so a test harness can drive it directly.
    pub fn handle_datagram(&mut self, data: &[u8], peer: SocketAddr) -> Result<(), ServerError> {
        self.handle_frame(data, Peer::Udp(peer))
    }

    /// Process one plain KNXnet/IP frame from `peer` (a UDP datagram, or the
    /// inner frame of an authenticated secure TCP session).
    fn handle_frame(&mut self, data: &[u8], peer: Peer) -> Result<(), ServerError> {
        let frame = match KnxnetIpFrame::decode(data) {
            Ok(f) => f,
            // Strict: a malformed datagram is logged and dropped, never fatal.
            // The decoder is total (it returns an error for every truncated,
            // oversized or garbage input), so no peer can take the loop down.
            Err(e) => {
                tracing::debug!(
                    ?peer,
                    len = data.len(),
                    "dropping malformed KNXnet/IP datagram: {e}"
                );
                return Ok(());
            }
        };
        match frame.service {
            service::CONNECT_REQUEST => self.on_connect_request(&frame.body, peer),
            service::CONNECTIONSTATE_REQUEST => self.on_connectionstate_request(&frame.body, peer),
            service::DISCONNECT_REQUEST => self.on_disconnect_request(&frame.body, peer),
            service::TUNNELLING_REQUEST => self.on_tunnelling_request(&frame.body, peer),
            service::DESCRIPTION_REQUEST => {
                let out = KnxnetIpFrame::encode(service::DESCRIPTION_RESPONSE, &self.dibs(false));
                self.send_frame(&out, peer)
            }
            service::SEARCH_REQUEST_EXTENDED => {
                // HPAI of the answer: the UDP endpoint, or TCP route-back.
                let mut body = match (peer, self.socket.local_addr()?) {
                    (Peer::Udp(_), local) => hpai(local).to_vec(),
                    (Peer::Tcp(_), _) => vec![0x08, 0x02, 0, 0, 0, 0, 0, 0],
                };
                body.extend_from_slice(&self.dibs(true));
                let out = KnxnetIpFrame::encode(service::SEARCH_RESPONSE_EXTENDED, &body);
                self.send_frame(&out, peer)
            }
            _ => Ok(()),
        }
    }

    /// The description DIBs: device info, supported service families and,
    /// when `extended` (a SEARCH_RESPONSE_EXTENDED), the secured service
    /// families and the tunnelling slots. A real Jung interface lists the
    /// security family only in the extended answer (bussard issue #182).
    fn dibs(&self, extended: bool) -> Vec<u8> {
        let ia = self
            .secure
            .as_ref()
            .map(|s| s.individual_address)
            .unwrap_or(0x1000);
        let mut out = vec![0u8; 54];
        out[0] = 54;
        out[1] = 0x01; // DEVICE_INFO
        out[2] = 0x02; // TP1
        out[4..6].copy_from_slice(&ia.to_be_bytes());
        out[24..31].copy_from_slice(b"knx-sim");
        let mut families = vec![0x02, 0x02, 0x03, 0x02, 0x04, 0x02];
        if extended && self.secure.is_some() {
            families.extend_from_slice(&[0x09, 0x01]);
        }
        out.push((2 + families.len()) as u8);
        out.push(0x02); // SUPP_SVC_FAMILIES
        out.extend_from_slice(&families);
        if let (true, Some(secure)) = (extended, &self.secure) {
            if secure.secure_only {
                // SECURED_SERVICE_FAMILIES: device management v1, tunnelling
                // v1, exactly as the Jung interface sends it.
                out.extend_from_slice(&[0x06, 0x06, 0x03, 0x01, 0x04, 0x01]);
            }
            let in_use: Vec<u16> = secure
                .conns
                .values()
                .filter_map(|c| match c.state {
                    TcpState::Established { tunnel_ia, .. } => Some(tunnel_ia),
                    _ => None,
                })
                .collect();
            out.push((4 + 4 * secure.users.len()) as u8);
            out.push(0x07); // TUNNELLING_INFO
            out.extend_from_slice(&248u16.to_be_bytes());
            for (_, _, tunnel_ia) in &secure.users {
                // usable (0x04) | free (0x01); a secure slot is not
                // pre-authorized (0x02), as on the real interface.
                let status: u16 = if in_use.contains(tunnel_ia) {
                    0x04
                } else {
                    0x05
                };
                out.extend_from_slice(&tunnel_ia.to_be_bytes());
                out.extend_from_slice(&status.to_be_bytes());
            }
        }
        out
    }

    /// The tunnelling channel `peer` uses.
    fn channel_of(&self, peer: Peer) -> u8 {
        match peer {
            Peer::Udp(_) => self.channel,
            Peer::Tcp(id) => self
                .secure
                .as_ref()
                .and_then(|s| s.conns.get(&id))
                .map(|c| c.channel)
                .unwrap_or(self.channel),
        }
    }

    /// Sends a plain KNXnet/IP frame to `peer` (wrapped on a secure session).
    fn send_frame(&mut self, frame: &[u8], peer: Peer) -> Result<(), ServerError> {
        match peer {
            Peer::Udp(addr) => {
                self.socket.send_to(frame, addr)?;
                Ok(())
            }
            Peer::Tcp(id) => {
                let Some(conn) = self.secure.as_mut().and_then(|s| s.conns.get_mut(&id)) else {
                    return Ok(());
                };
                let bytes = match &mut conn.state {
                    TcpState::Established { session, .. } => session.seal(frame),
                    // Before authentication only plain answers leave.
                    _ => frame.to_vec(),
                };
                write_all_nonblocking(&mut conn.stream, &bytes)?;
                Ok(())
            }
        }
    }

    /// Accepts new TCP connections and serves every complete frame that
    /// arrived on the existing ones.
    fn poll_tcp(&mut self) {
        let Some(secure) = self.secure.as_mut() else {
            return;
        };
        while let Ok((stream, from)) = secure.listener.accept() {
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            let _ = stream.set_nodelay(true);
            let id = secure.next_id;
            secure.next_id += 1;
            tracing::info!(%from, conn = id, "KNXnet/IP TCP connection accepted");
            secure.conns.insert(
                id,
                TcpConn {
                    stream,
                    buf: Vec::new(),
                    state: TcpState::Plain,
                    channel: 0x40u8.wrapping_add(id as u8),
                },
            );
        }
        let ids: Vec<usize> = secure.conns.keys().copied().collect();
        for id in ids {
            let (frames, closed) = match self.secure.as_mut().and_then(|s| s.conns.get_mut(&id)) {
                Some(conn) => read_frames(conn),
                None => continue,
            };
            for frame in frames {
                if !self.on_tcp_frame(id, &frame) {
                    self.drop_tcp(id);
                    break;
                }
            }
            if closed {
                self.drop_tcp(id);
            }
        }
    }

    /// Forgets a TCP connection (closed by either side).
    fn drop_tcp(&mut self, id: usize) {
        if let Some(secure) = self.secure.as_mut()
            && secure.conns.remove(&id).is_some()
        {
            tracing::info!(conn = id, "KNXnet/IP TCP connection closed");
        }
        self.tx_seqs.remove(&Peer::Tcp(id));
        if self.peer == Some(Peer::Tcp(id)) {
            self.peer = None;
        }
    }

    /// One frame from TCP connection `id`. Returns `false` to close it.
    fn on_tcp_frame(&mut self, id: usize, frame: &[u8]) -> bool {
        let Ok(parsed) = KnxnetIpFrame::decode(frame) else {
            return true;
        };
        let Some(secure) = self.secure.as_mut() else {
            return false;
        };
        let device_key = secure.device_key;
        let users: Vec<(u8, [u8; 16])> = secure.users.iter().map(|(i, k, _)| (*i, *k)).collect();
        let tunnel_of = |user: u8, users: &[(u8, [u8; 16], u16)]| {
            users
                .iter()
                .find(|(i, _, _)| *i == user)
                .map(|(_, _, t)| *t)
        };
        let all_users = secure.users.clone();
        let Some(conn) = secure.conns.get_mut(&id) else {
            return false;
        };
        match (&mut conn.state, parsed.service) {
            (TcpState::Plain, ipsecure::SESSION_REQUEST) => {
                match Handshake::respond(&parsed.body, 0x0001, &device_key) {
                    Ok((hs, response)) => {
                        tracing::info!(conn = id, "SECURE session request answered");
                        let ok = write_all_nonblocking(&mut conn.stream, &response).is_ok();
                        conn.state = TcpState::Authenticating(hs);
                        ok
                    }
                    Err(e) => {
                        tracing::warn!(conn = id, "SECURE session request refused: {e}");
                        false
                    }
                }
            }
            (TcpState::Plain, _) => {
                // Searches over TCP (ETS does this) are answered in the clear.
                let _ = self.handle_frame(frame, Peer::Tcp(id));
                true
            }
            (TcpState::Authenticating(hs), ipsecure::SECURE_WRAPPER) => {
                let mut session = hs.session([0x00, 0xFA, 0x5E, 0xC0, 0x00, 0x01]);
                let inner = match session.open(frame) {
                    Ok(inner) => inner,
                    Err(e) => {
                        tracing::warn!(conn = id, "SECURE authenticate wrapper refused: {e}");
                        return false;
                    }
                };
                match hs.authenticate(&inner, &users) {
                    Ok(user) => {
                        let status =
                            session.seal(&ipsecure::session_status(ipsecure::STATUS_SUCCESS));
                        let ok = write_all_nonblocking(&mut conn.stream, &status).is_ok();
                        tracing::info!(conn = id, user, "SECURE session authenticated");
                        conn.state = TcpState::Established {
                            session,
                            user,
                            tunnel_ia: tunnel_of(user, &all_users).unwrap_or(0),
                        };
                        ok
                    }
                    Err(e) => {
                        let status =
                            session.seal(&ipsecure::session_status(ipsecure::STATUS_AUTH_FAILED));
                        let _ = write_all_nonblocking(&mut conn.stream, &status);
                        tracing::warn!(conn = id, "SECURE authentication refused: {e}");
                        false
                    }
                }
            }
            (TcpState::Established { session, user, .. }, ipsecure::SECURE_WRAPPER) => {
                let user = *user;
                let inner = match session.open(frame) {
                    Ok(inner) => inner,
                    Err(e) => {
                        tracing::warn!(conn = id, user, "SECURE wrapper refused: {e}");
                        return true;
                    }
                };
                if inner.len() >= 8
                    && u16::from_be_bytes([inner[2], inner[3]]) == ipsecure::SESSION_STATUS
                {
                    return match inner[6] {
                        ipsecure::STATUS_KEEPALIVE => {
                            tracing::debug!(conn = id, "SECURE keepalive");
                            true
                        }
                        ipsecure::STATUS_CLOSE => {
                            tracing::info!(conn = id, "SECURE session closed by the client");
                            false
                        }
                        _ => true,
                    };
                }
                let _ = self.handle_frame(&inner, Peer::Tcp(id));
                true
            }
            _ => true,
        }
    }

    fn on_connect_request(&mut self, _body: &[u8], peer: Peer) -> Result<(), ServerError> {
        if let (Peer::Udp(_), Some(secure)) = (peer, &self.secure)
            && secure.secure_only
        {
            // A secure-only interface has no plain tunnel (bussard #182).
            tracing::info!(?peer, "plain CONNECT refused: tunnelling is secure-only");
            let out = KnxnetIpFrame::encode(service::CONNECT_RESPONSE, &[0x00, E_CONNECTION_TYPE]);
            return self.send_frame(&out, peer);
        }
        // Remember the client so device-originated telegrams (stimulus, fanned
        // group responses) are forwarded to it.
        self.peer = Some(peer);
        // A fresh connection starts its tunnelling sequence counter at 0, as the
        // spec requires (the counter is per connection, not per gateway).
        self.tx_seqs.insert(peer, 0);
        // CONNECT_RESPONSE body: channel, status, data-endpoint HPAI (8),
        // connection-response data block (CRD): len(1), type(1) + KNX addr(2).
        let mut body = Vec::new();
        body.push(self.channel_of(peer));
        body.push(0x00); // E_NO_ERROR
        // Data endpoint HPAI: length 8, protocol UDP (0x01), IP:port of the
        // server's own local address (echo the peer's addressing family is not
        // required; a real gateway returns its own endpoint). Over TCP it is
        // the route-back HPAI, as on the real interface.
        let (hpai_bytes, tunnel_ia) = match peer {
            Peer::Udp(_) => (hpai(self.socket.local_addr()?), 0x1000u16),
            Peer::Tcp(id) => {
                let ia = self
                    .secure
                    .as_ref()
                    .and_then(|s| s.conns.get(&id))
                    .and_then(|c| match c.state {
                        TcpState::Established { tunnel_ia, .. } => Some(tunnel_ia),
                        _ => None,
                    })
                    .unwrap_or(0x1000);
                ([0x08, 0x02, 0, 0, 0, 0, 0, 0], ia)
            }
        };
        body.extend_from_slice(&hpai_bytes);
        // CRD for tunnelling: length 4, TUNNEL_CONNECTION, KNX individual addr
        // (1.0.0 on the plain gateway, the user's tunnel address on a secure
        // session).
        body.push(0x04);
        body.push(0x04); // TUNNEL_CONNECTION
        body.extend_from_slice(&tunnel_ia.to_be_bytes());
        let out = KnxnetIpFrame::encode(service::CONNECT_RESPONSE, &body);
        self.send_frame(&out, peer)
    }

    fn on_connectionstate_request(&mut self, body: &[u8], peer: Peer) -> Result<(), ServerError> {
        let own = self.channel_of(peer);
        let channel = body.first().copied().unwrap_or(own);
        let status = if channel == own { 0x00 } else { 0x21 };
        let resp = KnxnetIpFrame::encode(service::CONNECTIONSTATE_RESPONSE, &[channel, status]);
        self.send_frame(&resp, peer)
    }

    fn on_disconnect_request(&mut self, body: &[u8], peer: Peer) -> Result<(), ServerError> {
        let channel = body.first().copied().unwrap_or(self.channel_of(peer));
        let resp = KnxnetIpFrame::encode(service::DISCONNECT_RESPONSE, &[channel, 0x00]);
        self.send_frame(&resp, peer)?;
        // The connection is over; drop its per-connection sequence counter and
        // stop forwarding device-originated telegrams to it.
        self.tx_seqs.remove(&peer);
        if self.peer == Some(peer) {
            self.peer = None;
        }
        Ok(())
    }

    fn on_tunnelling_request(&mut self, body: &[u8], peer: Peer) -> Result<(), ServerError> {
        let Some(hdr) = ConnectionHeader::parse(body) else {
            return Ok(());
        };
        if let (Peer::Udp(_), Some(secure)) = (peer, &self.secure)
            && secure.secure_only
        {
            // No plain tunnel exists on a secure-only interface.
            return Ok(());
        }
        let own_channel = self.channel_of(peer);
        // Over TCP the tunnelling layer has no TUNNELLING_ACK.
        let acks = matches!(peer, Peer::Udp(_));
        // Strict: only frames naming the channel this gateway handed out at
        // CONNECT are served. A frame for any other channel is answered with a
        // TUNNELLING_ACK carrying E_CONNECTION_ID and is neither delivered to
        // the bus nor allowed to re-point the forwarding peer — otherwise any
        // peer that can reach the socket hijacks the single-client path.
        if hdr.channel != own_channel {
            let nak = KnxnetIpFrame::encode(
                service::TUNNELLING_ACK,
                &ConnectionHeader {
                    channel: hdr.channel,
                    seq: hdr.seq,
                    status: E_CONNECTION_ID,
                }
                .to_bytes(),
            );
            self.send_frame(&nak, peer)?;
            return Ok(());
        }
        // Track the active client for device-originated forwarding.
        self.peer = Some(peer);
        // ACK the request first (UDP only).
        if acks {
            let ack = KnxnetIpFrame::encode(
                service::TUNNELLING_ACK,
                &ConnectionHeader {
                    channel: hdr.channel,
                    seq: hdr.seq,
                    status: 0x00,
                }
                .to_bytes(),
            );
            self.send_frame(&ack, peer)?;
        }

        // The cEMI payload follows the 4-byte connection header.
        let cemi_bytes = &body[4..];
        let cemi = match CemiLData::decode(cemi_bytes) {
            Ok(c) => c,
            // Strict: drop malformed cEMI (already ACKed at the tunnel layer).
            Err(e) => {
                tracing::debug!(?peer, "dropping malformed cEMI payload: {e}");
                return Ok(());
            }
        };

        let responses = self.bus.deliver_from_tool(&cemi);
        for resp in responses {
            self.send_tunnelling(&resp, peer)?;
        }
        Ok(())
    }

    fn send_tunnelling(&mut self, cemi: &CemiLData, peer: Peer) -> Result<(), ServerError> {
        let channel = self.channel_of(peer);
        // Use (and advance) THIS client's sequence counter. A client that never
        // sent a CONNECT_REQUEST (drove tunnelling directly, as some tests do)
        // starts at 0.
        let counter = self.tx_seqs.entry(peer).or_insert(0);
        let seq = *counter;
        *counter = counter.wrapping_add(1);
        let mut body = ConnectionHeader {
            channel,
            seq,
            status: 0x00,
        }
        .to_bytes()
        .to_vec();
        body.extend_from_slice(&cemi.encode());
        let frame = KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body);
        self.send_frame(&frame, peer)
    }
}

/// Reads everything available on a non-blocking TCP connection and splits
/// it into KNXnet/IP frames. Returns the frames and whether the peer closed.
fn read_frames(conn: &mut TcpConn) -> (Vec<Vec<u8>>, bool) {
    let mut closed = false;
    let mut chunk = [0u8; 2048];
    loop {
        match conn.stream.read(&mut chunk) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => conn.buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    let mut frames = Vec::new();
    while conn.buf.len() >= 6 {
        if conn.buf[0] != 0x06 || conn.buf[1] != 0x10 {
            // Strict: a stream that lost its framing is closed.
            return (frames, true);
        }
        let total = usize::from(u16::from_be_bytes([conn.buf[4], conn.buf[5]]));
        if total < 6 {
            return (frames, true);
        }
        if conn.buf.len() < total {
            break;
        }
        frames.push(conn.buf.drain(..total).collect());
    }
    (frames, closed)
}

/// `write_all` on a non-blocking stream: retries briefly on `WouldBlock`.
fn write_all_nonblocking(stream: &mut TcpStream, mut bytes: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Serialize a HPAI (Host Protocol Address Information) block for a UDP
/// endpoint: length(1), protocol(1=UDP), IPv4(4), port(2).
fn hpai(addr: SocketAddr) -> [u8; 8] {
    let ip = match addr {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(_) => [0, 0, 0, 0], // IPv6 not modelled; report 0.0.0.0
    };
    let port = addr.port().to_be_bytes();
    [0x08, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1]]
}
