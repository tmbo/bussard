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
//!
//! With `udp: true` (bussard issue #197) the same session runs over UDP,
//! keyed by the client's endpoint: SESSION_REQUEST carries the client's UDP
//! HPAI, and inside the session the tunnel uses TUNNELLING_ACK as a plain UDP
//! tunnel does. `tcp: false` removes the TCP endpoint (a UDP-only interface).
//! With `session_timeout_ms` an idle session ends with a wrapped
//! `STATUS_TIMEOUT`. The UDP mode is INFERRED from the KNX specification; no
//! real UDP-only interface has been captured.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::bus::Bus;
use crate::config::IpSecureConfig;
use crate::secure::ipsecure::{self, Handshake, SecureSession};
use crate::wire::IndividualAddress;
use crate::wire::cemi::{CemiLData, MessageCode};
use crate::wire::knxnetip::{
    ConnectionHeader, DEVICE_MGMT_CONNECTION, E_CONNECTION_ID, E_CONNECTION_TYPE, KnxnetIpFrame,
    service,
};

/// Who a frame came from: a UDP endpoint, a secure TCP connection, or a
/// secure session over UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Peer {
    /// A plain UDP client.
    Udp(SocketAddr),
    /// A TCP connection (its id), whose traffic is wrapped once the secure
    /// session is authenticated.
    Tcp(usize),
    /// A secure session over UDP with this client endpoint.
    SecureUdp(SocketAddr),
}

/// The secure-gateway settings, with the password keys derived once.
struct SecureGateway {
    individual_address: u16,
    device_key: [u8; 16],
    secure_only: bool,
    /// (user id, password key, tunnel individual address).
    users: Vec<(u8, [u8; 16], u16)>,
    /// The TCP endpoint (`None` with `tcp: false`).
    listener: Option<TcpListener>,
    next_id: usize,
    conns: BTreeMap<usize, TcpConn>,
    /// Serve secure sessions over UDP too.
    udp: bool,
    /// The secure sessions over UDP, by client endpoint.
    udp_sessions: BTreeMap<SocketAddr, UdpSession>,
    /// The idle timeout of a secure session.
    session_timeout: Option<Duration>,
}

/// One secure session over UDP.
struct UdpSession {
    state: SessionState,
    /// The tunnelling channel granted on this session.
    channel: u8,
    /// When the client last sent a frame.
    last_rx: Instant,
}

/// One TCP connection's state.
struct TcpConn {
    stream: TcpStream,
    buf: Vec<u8>,
    state: SessionState,
    /// The tunnelling channel this connection's CONNECT was granted.
    channel: u8,
    /// When the client last sent a frame.
    last_rx: Instant,
}

enum SessionState {
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
    /// The distinct data endpoint of plain UDP tunnels, when
    /// [`enable_data_port`](Self::enable_data_port) opened one (bussard issue
    /// #512). Non-blocking; [`serve`](Self::serve) drains it every wake.
    data_socket: Option<UdpSocket>,
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
    /// The bus device this gateway is the management server of (bussard
    /// issue #398): its KNXnet/IP Secure properties decide, after each of its
    /// master resets, whether the gateway serves plain or secure tunnelling.
    interface_device: Option<u16>,
    /// The individual address a plain (non-secure, no interface device)
    /// gateway reports in its DEVICE_INFO DIB and assigns to the tunnel.
    /// 1.0.0 unless `gateway.tunnel_address` says otherwise.
    plain_ia: u16,
    /// When a pending interface-secure switch (after the interface device's
    /// master reset) takes effect; see `sync_interface_secure`.
    interface_switch_due: Option<std::time::Instant>,
    /// Every UDP datagram in and out, as a pcap file (`gateway.pcap`): the
    /// capture of an ETS run without a sniffer on the host.
    pcap: Option<PcapWriter>,
    /// The master-reset epoch of [`interface_device`](Self::interface_device)
    /// last applied.
    interface_epoch: u64,
    /// Open device management connections (bussard issue #398): the channel
    /// and the next sequence of the requests the server sends, per peer.
    mgmt: BTreeMap<Peer, (u8, u8)>,
    /// The transport connection the server holds to the interface device for
    /// each device management peer's `T_Data_Connected` traffic: the next
    /// numbered-data sequence it sends.
    mgmt_transport: BTreeMap<Peer, u8>,
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
            data_socket: None,
            bus,
            channel: 1,
            tx_seqs: BTreeMap::new(),
            peer: None,
            started: Instant::now(),
            secure: None,
            interface_device: None,
            plain_ia: 0x1000,
            interface_switch_due: None,
            pcap: None,
            interface_epoch: 0,
            mgmt: BTreeMap::new(),
            mgmt_transport: BTreeMap::new(),
        })
    }

    /// Serves the data connection of plain UDP tunnels on a second socket bound
    /// to `addr` (port 0 picks one) and returns its address (bussard issue
    /// #512). KNXnet/IP Core 3/8/2 §8.6.3.1 lets a server return any port as
    /// the data endpoint of a CONNECT_RESPONSE; a conforming client then
    /// sends its TUNNELLING_REQUESTs and ACKs there (§8.6.3.4) and keeps
    /// CONNECTIONSTATE and DISCONNECT on the control endpoint (§8.6.3.3).
    /// The server is strict about it: a TUNNELLING_REQUEST/ACK on the
    /// control port, or any other plain frame on the data port, is dropped.
    /// Secure sessions and device management connections are unaffected.
    pub fn enable_data_port(&mut self, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let local = socket.local_addr()?;
        self.data_socket = Some(socket);
        Ok(local)
    }

    /// The address of the distinct data port, if one is enabled.
    pub fn data_addr(&self) -> Option<SocketAddr> {
        self.data_socket.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Makes the gateway the KNXnet/IP server of the bus device `address`
    /// (bussard issue #398): the description names it, and after each of its
    /// master resets the gateway switches to secure-only tunnelling with the
    /// credentials of its KNXnet/IP Secure properties, or back to plain.
    pub fn set_interface_device(&mut self, address: u16) {
        self.interface_device = Some(address);
    }

    /// The address the plain gateway reports and hands out on CONNECT
    /// (`gateway.tunnel_address`). ETS compares the line of this address with
    /// the project's line medium, so a sweep project puts it on a TP line.
    pub fn set_plain_address(&mut self, address: u16) {
        self.plain_ia = address;
    }

    /// Record every UDP datagram the gateway receives or sends to `path`
    /// (classic pcap, raw IPv4 link type, flushed per packet so a killed sim
    /// loses nothing). `tools/knxtrace` reads it like a sniffer capture.
    pub fn set_pcap(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        self.pcap = Some(PcapWriter::create(path)?);
        Ok(())
    }

    fn record(&mut self, data: &[u8], peer: Peer, inbound: bool) {
        let Peer::Udp(remote) = peer else {
            return;
        };
        let Ok(local) = self.socket.local_addr() else {
            return;
        };
        if let Some(w) = self.pcap.as_mut() {
            let (src, dst) = if inbound {
                (remote, local)
            } else {
                (local, remote)
            };
            if let Err(e) = w.write_udp(src, dst, data) {
                tracing::warn!("pcap write failed: {e}");
                self.pcap = None;
            }
        }
    }

    /// Applies the interface device's KNXnet/IP Secure state after a master
    /// reset (bussard issue #398). A restart ends every tunnel and session.
    fn sync_interface_secure(&mut self) {
        let Some(address) = self.interface_device else {
            return;
        };
        let Some(ip) = self
            .bus
            .device(IndividualAddress(address))
            .and_then(|d| d.ip_secure())
        else {
            return;
        };
        if ip.epoch() == self.interface_epoch {
            return;
        }
        // A real interface answers the master reset and keeps serving its
        // tunnel for the moment it takes to reboot; the tool's T_ACK of that
        // answer lands in it. Apply the switch after that moment, not in the
        // same loop turn, or the T_ACK finds a secure-only gateway and the
        // tool's TUNNELLING_ACK wait times out (bussard-cli
        // sim_interface_secure, after the device started answering under the
        // request's sequence number, 2026-10-27).
        let due = *self
            .interface_switch_due
            .get_or_insert_with(|| std::time::Instant::now() + Duration::from_millis(300));
        if std::time::Instant::now() < due {
            return;
        }
        self.interface_switch_due = None;
        self.interface_epoch = ip.epoch();
        let state = ip.applied().cloned();
        self.peer = None;
        self.tx_seqs.clear();
        let old_listener = self.secure.take().and_then(|s| s.listener);
        let Some(state) = state else {
            tracing::info!("interface {address:#06x}: KNXnet/IP Secure off, plain tunnelling");
            return;
        };
        let listener = match old_listener {
            Some(l) => Some(l),
            None => self
                .socket
                .local_addr()
                .and_then(TcpListener::bind)
                .and_then(|l| l.set_nonblocking(true).map(|()| l))
                .ok(),
        };
        tracing::info!(
            users = state.users.len(),
            "interface {address:#06x}: KNXnet/IP Secure on, secure-only tunnelling"
        );
        self.secure = Some(SecureGateway {
            individual_address: address,
            device_key: state.device_key,
            secure_only: true,
            users: state.users,
            listener,
            next_id: 0,
            conns: BTreeMap::new(),
            udp: false,
            udp_sessions: BTreeMap::new(),
            session_timeout: None,
        });
    }

    /// Enables KNXnet/IP Secure: binds TCP on the gateway's own address and
    /// port and derives the configured users' keys (PBKDF2, once).
    pub fn enable_secure(&mut self, cfg: &IpSecureConfig) -> Result<(), ServerError> {
        let parse_ia = |s: &str| -> Result<u16, ServerError> {
            s.parse::<IndividualAddress>()
                .map(|ia| ia.0)
                .map_err(|e| ServerError::Config(format!("bad individual address {s:?}: {e}")))
        };
        let listener = if cfg.tcp {
            let listener = TcpListener::bind(self.socket.local_addr()?)?;
            listener.set_nonblocking(true)?;
            Some(listener)
        } else {
            None
        };
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
            udp: cfg.udp,
            udp_sessions: BTreeMap::new(),
            session_timeout: cfg.session_timeout_ms.map(Duration::from_millis),
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
        let wake = if self.secure.is_some()
            || self.interface_device.is_some()
            || self.data_socket.is_some()
        {
            5
        } else {
            100
        };
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
            self.poll_data()?;
            self.poll_tcp();
            self.pump_stimulus();
            self.pump_transport();
            self.sync_interface_secure();
        }
    }

    /// Handles every datagram waiting on the data port, if one is enabled.
    /// A refused datagram (ICMP from a client that went away) is transient,
    /// as on the control port.
    pub fn poll_data(&mut self) -> Result<(), ServerError> {
        let mut buf = [0u8; 1024];
        loop {
            let Some(socket) = &self.data_socket else {
                return Ok(());
            };
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => self.handle_data_datagram(&buf[..n], peer)?,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                    ) => {}
                Err(e) => return Err(ServerError::Io(e)),
            }
        }
    }

    /// Process one datagram that arrived on the data port: only a plain
    /// TUNNELLING_REQUEST or TUNNELLING_ACK belongs there.
    pub fn handle_data_datagram(
        &mut self,
        data: &[u8],
        peer: SocketAddr,
    ) -> Result<(), ServerError> {
        self.record(data, Peer::Udp(peer), true);
        if !is_data_service(data) {
            tracing::debug!(?peer, "dropping a non-tunnelling frame on the data port");
            return Ok(());
        }
        self.handle_frame(data, Peer::Udp(peer))
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

    /// Runs the devices' transport timers (the 3 s response repetition and the
    /// 6 s connection timeout of 03_03_04 §5.4.3) and forwards what they send
    /// to the connected tunnel client. Without a client the timers still run,
    /// so a connection nobody uses closes; the frames have nowhere to go.
    pub fn pump_transport(&mut self) {
        let telegrams = self.bus.tick_transport(std::time::Instant::now());
        let Some(peer) = self.peer else {
            return;
        };
        for cemi in telegrams {
            if self.send_tunnelling(&cemi, peer).is_err() {
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
        self.record(data, Peer::Udp(peer), true);
        let udp_secure = self.secure.as_ref().is_some_and(|s| s.udp);
        if udp_secure && data.len() >= 4 {
            let svc = u16::from_be_bytes([data[2], data[3]]);
            if svc == ipsecure::SESSION_REQUEST || svc == ipsecure::SECURE_WRAPPER {
                if svc == ipsecure::SESSION_REQUEST
                    && let Some(secure) = self.secure.as_mut()
                {
                    // A new session request replaces any older session of
                    // this endpoint.
                    secure.udp_sessions.insert(
                        peer,
                        UdpSession {
                            state: SessionState::Plain,
                            channel: 0x60u8.wrapping_add(secure.next_id as u8),
                            last_rx: Instant::now(),
                        },
                    );
                    secure.next_id += 1;
                }
                let key = Peer::SecureUdp(peer);
                if !self.on_session_frame(key, data) {
                    self.drop_session(key);
                }
                return Ok(());
            }
        }
        if self.data_socket.is_some() && is_data_service(data) {
            tracing::debug!(?peer, "dropping a tunnelling frame on the control port");
            return Ok(());
        }
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
        // After the interface device's master reset only the old tunnel keeps
        // being served for the reboot grace (the tool's T_ACK of the restart
        // answer, its DISCONNECT). Anything else, a new CONNECT, a SEARCH or a
        // DESCRIPTION request, sees the new state at once.
        let old_channel_traffic = matches!(
            frame.service,
            service::TUNNELLING_REQUEST
                | service::TUNNELLING_ACK
                | service::TUNNELLING_FEATURE_GET
                | service::TUNNELLING_FEATURE_SET
                | service::CONNECTIONSTATE_REQUEST
                | service::DISCONNECT_REQUEST
        );
        if self.interface_switch_due.is_some() && !old_channel_traffic {
            self.interface_switch_due = Some(std::time::Instant::now());
            self.sync_interface_secure();
        }
        match frame.service {
            service::CONNECT_REQUEST => self.on_connect_request(&frame.body, peer),
            service::CONNECTIONSTATE_REQUEST => self.on_connectionstate_request(&frame.body, peer),
            service::DISCONNECT_REQUEST => self.on_disconnect_request(&frame.body, peer),
            service::TUNNELLING_REQUEST => self.on_tunnelling_request(&frame.body, peer),
            service::TUNNELLING_FEATURE_GET => self.on_tunnelling_feature(&frame.body, peer, false),
            service::TUNNELLING_FEATURE_SET => self.on_tunnelling_feature(&frame.body, peer, true),
            service::DEVICE_CONFIGURATION_REQUEST => {
                self.on_device_configuration(&frame.body, peer)
            }
            service::DESCRIPTION_REQUEST => {
                let out = KnxnetIpFrame::encode(service::DESCRIPTION_RESPONSE, &self.dibs(false));
                self.send_frame(&out, peer)
            }
            service::SEARCH_REQUEST => {
                // Plain discovery: ETS 6 sends it (unicast) to a configured
                // tunnelling connection before listing it, and the house
                // interface answers with HPAI + device info + service families.
                let mut body = match (peer, self.socket.local_addr()?) {
                    (Peer::Udp(_) | Peer::SecureUdp(_), local) => hpai(local).to_vec(),
                    (Peer::Tcp(_), _) => vec![0x08, 0x02, 0, 0, 0, 0, 0, 0],
                };
                body.extend_from_slice(&self.dibs(false));
                let out = KnxnetIpFrame::encode(service::SEARCH_RESPONSE, &body);
                self.send_frame(&out, peer)
            }
            service::SEARCH_REQUEST_EXTENDED => {
                // HPAI of the answer: the UDP endpoint, or TCP route-back.
                let mut body = match (peer, self.socket.local_addr()?) {
                    (Peer::Udp(_) | Peer::SecureUdp(_), local) => hpai(local).to_vec(),
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
            .or(self.interface_device)
            .unwrap_or(self.plain_ia);
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
                    SessionState::Established { tunnel_ia, .. } => Some(tunnel_ia),
                    _ => None,
                })
                .chain(secure.udp_sessions.values().filter_map(|u| match u.state {
                    SessionState::Established { tunnel_ia, .. } => Some(tunnel_ia),
                    _ => None,
                }))
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
            Peer::SecureUdp(addr) => self
                .secure
                .as_ref()
                .and_then(|s| s.udp_sessions.get(&addr))
                .map(|u| u.channel)
                .unwrap_or(self.channel),
        }
    }

    /// The session state of a secure peer, if it has one.
    fn session_state(&mut self, peer: Peer) -> Option<&mut SessionState> {
        let secure = self.secure.as_mut()?;
        match peer {
            Peer::Udp(_) => None,
            Peer::Tcp(id) => secure.conns.get_mut(&id).map(|c| &mut c.state),
            Peer::SecureUdp(addr) => secure.udp_sessions.get_mut(&addr).map(|u| &mut u.state),
        }
    }

    /// Writes raw bytes (already wrapped, or a plain handshake frame) to a
    /// secure peer.
    fn write_raw(&mut self, peer: Peer, bytes: &[u8]) -> std::io::Result<()> {
        match peer {
            Peer::Udp(addr) | Peer::SecureUdp(addr) => self.socket.send_to(bytes, addr).map(|_| ()),
            Peer::Tcp(id) => match self.secure.as_mut().and_then(|s| s.conns.get_mut(&id)) {
                Some(conn) => write_all_nonblocking(&mut conn.stream, bytes),
                None => Ok(()),
            },
        }
    }

    /// Sends a plain KNXnet/IP frame to `peer` (wrapped on a secure session).
    fn send_frame(&mut self, frame: &[u8], peer: Peer) -> Result<(), ServerError> {
        match peer {
            Peer::Udp(addr) => {
                // Tunnelling frames leave from the data port when one is
                // enabled (Core §8.6.3.4).
                let socket = match &self.data_socket {
                    Some(data) if is_data_service(frame) => data,
                    _ => &self.socket,
                };
                socket.send_to(frame, addr)?;
                self.record(frame, peer, false);
                Ok(())
            }
            Peer::Tcp(_) | Peer::SecureUdp(_) => {
                let Some(state) = self.session_state(peer) else {
                    return Ok(());
                };
                let bytes = match state {
                    SessionState::Established { session, .. } => session.seal(frame),
                    // Before authentication only plain answers leave.
                    _ => frame.to_vec(),
                };
                self.write_raw(peer, &bytes)?;
                Ok(())
            }
        }
    }

    /// Accepts new TCP connections and serves every complete frame that
    /// arrived on the existing ones.
    fn poll_tcp(&mut self) {
        self.expire_sessions();
        let Some(secure) = self.secure.as_mut() else {
            return;
        };
        while let Some(Ok((stream, from))) = secure.listener.as_ref().map(TcpListener::accept) {
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
                    state: SessionState::Plain,
                    channel: 0x40u8.wrapping_add(id as u8),
                    last_rx: Instant::now(),
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
                if !self.on_session_frame(Peer::Tcp(id), &frame) {
                    self.drop_session(Peer::Tcp(id));
                    break;
                }
            }
            if closed {
                self.drop_session(Peer::Tcp(id));
            }
        }
    }

    /// Ends every secure session idle for longer than the session timeout
    /// with a wrapped `STATUS_TIMEOUT`.
    fn expire_sessions(&mut self) {
        let Some(secure) = self.secure.as_ref() else {
            return;
        };
        let Some(timeout) = secure.session_timeout else {
            return;
        };
        let expired: Vec<Peer> = secure
            .conns
            .iter()
            .filter(|(_, c)| c.last_rx.elapsed() >= timeout)
            .map(|(id, _)| Peer::Tcp(*id))
            .chain(
                secure
                    .udp_sessions
                    .iter()
                    .filter(|(_, u)| u.last_rx.elapsed() >= timeout)
                    .map(|(addr, _)| Peer::SecureUdp(*addr)),
            )
            .collect();
        for peer in expired {
            tracing::info!(?peer, "SECURE session timed out");
            if let Some(SessionState::Established { session, .. }) = self.session_state(peer) {
                let notice = session.seal(&ipsecure::session_status(ipsecure::STATUS_TIMEOUT));
                let _ = self.write_raw(peer, &notice);
            }
            self.drop_session(peer);
        }
    }

    /// Forgets a secure peer: a TCP connection (closed by either side) or a
    /// UDP session.
    fn drop_session(&mut self, peer: Peer) {
        if let Some(secure) = self.secure.as_mut() {
            match peer {
                Peer::Tcp(id) => {
                    if secure.conns.remove(&id).is_some() {
                        tracing::info!(conn = id, "KNXnet/IP TCP connection closed");
                    }
                }
                Peer::SecureUdp(addr) => {
                    if secure.udp_sessions.remove(&addr).is_some() {
                        tracing::info!(%addr, "KNXnet/IP Secure UDP session ended");
                    }
                }
                Peer::Udp(_) => {}
            }
        }
        self.tx_seqs.remove(&peer);
        self.mgmt.remove(&peer);
        self.mgmt_transport.remove(&peer);
        if self.peer == Some(peer) {
            self.peer = None;
        }
    }

    /// One frame from a secure peer (a TCP connection, or a UDP session).
    /// Returns `false` to end it.
    fn on_session_frame(&mut self, peer: Peer, frame: &[u8]) -> bool {
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
        let now = Instant::now();
        let state = match peer {
            Peer::Udp(_) => None,
            Peer::Tcp(id) => secure.conns.get_mut(&id).map(|c| {
                c.last_rx = now;
                &mut c.state
            }),
            Peer::SecureUdp(addr) => secure.udp_sessions.get_mut(&addr).map(|u| {
                u.last_rx = now;
                &mut u.state
            }),
        };
        let Some(state) = state else {
            return false;
        };
        // What to write back (raw) once the state is no longer borrowed.
        let mut reply: Option<Vec<u8>> = None;
        let keep = match (&mut *state, parsed.service) {
            (SessionState::Plain, ipsecure::SESSION_REQUEST) => {
                match Handshake::respond(&parsed.body, 0x0001, &device_key) {
                    Ok((hs, response)) => {
                        tracing::info!(?peer, "SECURE session request answered");
                        reply = Some(response);
                        *state = SessionState::Authenticating(hs);
                        true
                    }
                    Err(e) => {
                        tracing::warn!(?peer, "SECURE session request refused: {e}");
                        false
                    }
                }
            }
            (SessionState::Plain, _) => {
                // Searches over TCP (ETS does this) are answered in the clear.
                let _ = self.handle_frame(frame, peer);
                return true;
            }
            (SessionState::Authenticating(hs), ipsecure::SECURE_WRAPPER) => {
                let mut session = hs.session([0x00, 0xFA, 0x5E, 0xC0, 0x00, 0x01]);
                let inner = match session.open(frame) {
                    Ok(inner) => inner,
                    Err(e) => {
                        tracing::warn!(?peer, "SECURE authenticate wrapper refused: {e}");
                        return false;
                    }
                };
                match hs.authenticate(&inner, &users) {
                    Ok(user) => {
                        reply =
                            Some(session.seal(&ipsecure::session_status(ipsecure::STATUS_SUCCESS)));
                        tracing::info!(?peer, user, "SECURE session authenticated");
                        *state = SessionState::Established {
                            session,
                            user,
                            tunnel_ia: tunnel_of(user, &all_users).unwrap_or(0),
                        };
                        true
                    }
                    Err(e) => {
                        let status =
                            session.seal(&ipsecure::session_status(ipsecure::STATUS_AUTH_FAILED));
                        tracing::warn!(?peer, "SECURE authentication refused: {e}");
                        let _ = self.write_raw(peer, &status);
                        return false;
                    }
                }
            }
            (SessionState::Established { session, user, .. }, ipsecure::SECURE_WRAPPER) => {
                let user = *user;
                let inner = match session.open(frame) {
                    Ok(inner) => inner,
                    Err(e) => {
                        tracing::warn!(?peer, user, "SECURE wrapper refused: {e}");
                        return true;
                    }
                };
                if inner.len() >= 8
                    && u16::from_be_bytes([inner[2], inner[3]]) == ipsecure::SESSION_STATUS
                {
                    return match inner[6] {
                        ipsecure::STATUS_KEEPALIVE => {
                            tracing::debug!(?peer, "SECURE keepalive");
                            true
                        }
                        ipsecure::STATUS_CLOSE => {
                            tracing::info!(?peer, "SECURE session closed by the client");
                            false
                        }
                        _ => true,
                    };
                }
                let _ = self.handle_frame(&inner, peer);
                return true;
            }
            _ => true,
        };
        match reply {
            Some(bytes) => self.write_raw(peer, &bytes).is_ok() && keep,
            None => keep,
        }
    }

    fn on_connect_request(&mut self, body: &[u8], peer: Peer) -> Result<(), ServerError> {
        // The CRI after the two HPAIs: a device management connection (type
        // 3, bussard issue #398) is served by the interface device itself.
        if body.get(17) == Some(&DEVICE_MGMT_CONNECTION) && self.interface_device.is_some() {
            return self.on_mgmt_connect(peer);
        }
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
        let plain = self.plain_ia;
        let session_ia = |state: Option<&mut SessionState>| match state {
            Some(SessionState::Established { tunnel_ia, .. }) => *tunnel_ia,
            _ => plain,
        };
        let control = self.socket.local_addr()?;
        let data = self
            .data_socket
            .as_ref()
            .map(UdpSocket::local_addr)
            .transpose()?
            .unwrap_or(control);
        let (hpai_bytes, tunnel_ia) = match peer {
            // The data endpoint: the distinct data port when one is enabled.
            Peer::Udp(_) => (hpai(data), plain),
            Peer::Tcp(_) => (
                [0x08, 0x02, 0, 0, 0, 0, 0, 0],
                session_ia(self.session_state(peer)),
            ),
            // A secure session over UDP: the gateway's UDP endpoint, as on a
            // plain UDP tunnel.
            Peer::SecureUdp(_) => {
                let local = hpai(self.socket.local_addr()?);
                (local, session_ia(self.session_state(peer)))
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

    /// A device management CONNECT_REQUEST: refused on a secure-only
    /// interface over plain UDP (device management is a secured family
    /// there), else answered with a device management CRD.
    fn on_mgmt_connect(&mut self, peer: Peer) -> Result<(), ServerError> {
        if let (Peer::Udp(_), Some(secure)) = (peer, &self.secure)
            && secure.secure_only
        {
            let out = KnxnetIpFrame::encode(service::CONNECT_RESPONSE, &[0x00, E_CONNECTION_TYPE]);
            return self.send_frame(&out, peer);
        }
        let channel = 0x80u8.wrapping_add(self.mgmt.len() as u8);
        self.mgmt.insert(peer, (channel, 0));
        let mut body = vec![channel, 0x00];
        match peer {
            Peer::Tcp(_) => body.extend_from_slice(&[0x08, 0x02, 0, 0, 0, 0, 0, 0]),
            _ => body.extend_from_slice(&hpai(self.socket.local_addr()?)),
        }
        body.extend_from_slice(&[0x02, DEVICE_MGMT_CONNECTION]);
        let out = KnxnetIpFrame::encode(service::CONNECT_RESPONSE, &body);
        self.send_frame(&out, peer)
    }

    /// A DEVICE_CONFIGURATION_REQUEST on a device management connection
    /// (bussard issue #398), as ETS sends them to the Jung interface: cEMI
    /// `T_Data_Connected.req` / `T_Data_Individual.req` (reserved addresses,
    /// then a TPDU) reach the interface device as `L_Data` from `0.0.0` and
    /// its answers come back as `.ind`; `M_PropRead.req`, `M_PropWrite.req`
    /// and `M_Reset.req` are the device's local management.
    fn on_device_configuration(&mut self, body: &[u8], peer: Peer) -> Result<(), ServerError> {
        let (Some(hdr), Some(&(channel, _)), Some(device)) = (
            ConnectionHeader::parse(body),
            self.mgmt.get(&peer),
            self.interface_device,
        ) else {
            return Ok(());
        };
        if matches!(peer, Peer::Udp(_) | Peer::SecureUdp(_)) {
            let ack = KnxnetIpFrame::encode(
                service::DEVICE_CONFIGURATION_ACK,
                &ConnectionHeader {
                    channel: hdr.channel,
                    seq: hdr.seq,
                    status: if hdr.channel == channel {
                        0x00
                    } else {
                        E_CONNECTION_ID
                    },
                }
                .to_bytes(),
            );
            self.send_frame(&ack, peer)?;
        }
        if hdr.channel != channel {
            return Ok(());
        }
        let cemi = body.get(4..).unwrap_or_default();
        let mut answers: Vec<Vec<u8>> = Vec::new();
        match cemi.first() {
            Some(&mc @ (0x41 | 0x4A)) => {
                let add = usize::from(cemi.get(1).copied().unwrap_or(0));
                let off = 2 + add + 6;
                let Some(tpdu) = cemi.get(off + 1..).filter(|t| !t.is_empty()) else {
                    return Ok(());
                };
                let ind = if mc == 0x41 { 0x89 } else { 0x94 };
                for resp in self.mgmt_deliver(peer, device, tpdu, mc == 0x41) {
                    let mut out = vec![ind, 0x00, 0, 0, 0, 0, 0, 0];
                    out.push((resp.len() - 1) as u8);
                    out.extend_from_slice(&resp);
                    answers.push(out);
                }
            }
            Some(_) => {
                if let Some(con) = self
                    .bus
                    .device_mut(IndividualAddress(device))
                    .and_then(|d| d.local_management(cemi))
                {
                    answers.push(con);
                }
            }
            None => {}
        }
        for cemi in answers {
            let seq = match self.mgmt.get_mut(&peer) {
                Some((_, seq)) => {
                    let s = *seq;
                    *seq = seq.wrapping_add(1);
                    s
                }
                None => 0,
            };
            let mut out = ConnectionHeader {
                channel,
                seq,
                status: 0x00,
            }
            .to_bytes()
            .to_vec();
            out.extend_from_slice(&cemi);
            let frame = KnxnetIpFrame::encode(service::DEVICE_CONFIGURATION_REQUEST, &out);
            self.send_frame(&frame, peer)?;
        }
        Ok(())
    }

    /// Delivers one transport-layer service of a device management peer to
    /// the interface device and returns the application answers as
    /// unnumbered TPDUs. A connected service rides the transport connection
    /// the server holds to the device (opened with `T_Connect` on first use):
    /// the request goes as numbered data, the device's numbered answers are
    /// acknowledged here, as the cEMI server of a real interface does.
    fn mgmt_deliver(
        &mut self,
        peer: Peer,
        device: u16,
        tpdu: &[u8],
        connected: bool,
    ) -> Vec<Vec<u8>> {
        let frame = |tpdu: Vec<u8>| CemiLData {
            message_code: crate::wire::cemi::MessageCode::LDataReq,
            ctrl1: 0xBC,
            ctrl2: 0x60,
            source: IndividualAddress(0),
            dest: device,
            tpdu,
        };
        let mut request = tpdu.to_vec();
        if connected {
            // A Style 3 device closes a connection idle for 6 s (03_03_04
            // §5.4.3 E16): open a fresh one when it did.
            let open = self
                .bus
                .device(IndividualAddress(device))
                .is_some_and(|d| d.l4_connected_to(IndividualAddress(0)));
            if !open || !self.mgmt_transport.contains_key(&peer) {
                self.bus.deliver_from_tool(&frame(vec![0x80]));
                self.mgmt_transport.insert(peer, 0);
            }
            let seq = self.mgmt_transport.get(&peer).copied().unwrap_or(0);
            request[0] = 0x40 | ((seq & 0x0F) << 2) | (request[0] & 0x03);
            self.mgmt_transport.insert(peer, seq.wrapping_add(1) & 0x0F);
        }
        let mut out = Vec::new();
        for resp in self.bus.deliver_from_tool(&frame(request)) {
            let Some(&first) = resp.tpdu.first() else {
                continue;
            };
            if resp.tpdu.len() < 2 {
                continue; // a transport ACK or control frame
            }
            if first & 0xC0 == 0x40 {
                // Numbered data from the device: acknowledge it.
                let ack = 0xC2 | (first & 0x3C);
                self.bus.deliver_from_tool(&frame(vec![ack]));
            }
            let mut plain = resp.tpdu.clone();
            plain[0] &= 0x03;
            out.push(plain);
        }
        out
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

    /// Tunnelling v2 feature services (03_08_04 §2.3.x): GET answers the
    /// feature's value, SET accepts and echoes it. ETS 6 reads feature 0x07
    /// (max APDU length) right after CONNECT and gives up without an answer.
    fn on_tunnelling_feature(
        &mut self,
        body: &[u8],
        peer: Peer,
        set: bool,
    ) -> Result<(), ServerError> {
        let Some(hdr) = ConnectionHeader::parse(body) else {
            return Ok(());
        };
        if hdr.channel != self.channel_of(peer) || body.len() < 6 {
            return Ok(());
        }
        let feature = body[4];
        let ia = self
            .secure
            .as_ref()
            .map(|s| s.individual_address)
            .or(self.interface_device)
            .unwrap_or(self.plain_ia);
        let (code, value): (u8, Vec<u8>) = if set {
            (0x00, body[6..].to_vec())
        } else {
            match feature {
                0x01 => (0x00, vec![0x00, 0x04]), // supported EMI types: cEMI
                0x02 => (0x00, vec![0x57, 0xB0]), // device descriptor type 0 of an IP interface
                0x03 => (0x00, vec![0x01]),       // bus connection status: connected
                0x04 => (0x00, vec![0x00, 0x00]), // KNX manufacturer code
                0x05 => (0x00, vec![0x00, 0x04]), // active EMI type: cEMI
                0x06 => (0x00, ia.to_be_bytes().to_vec()), // individual address of the tunnel
                0x07 => (0x00, vec![0x00, 0xFE]), // max APDU length 254
                0x08 => (0x00, vec![0x00]),       // info service disabled
                _ => (0x01, vec![]),              // unknown feature
            }
        };
        tracing::info!(
            feature = format!("0x{feature:02x}"),
            set,
            "tunnelling feature"
        );
        // Feature frames ride the tunnelling sequence machinery (03_08_04 v2):
        // the GET/SET is acknowledged with TUNNELLING_ACK under the client's
        // sequence, and the RESPONSE carries the server's own send sequence,
        // which the client acknowledges in turn. ETS 6 re-sends the GET after
        // one second and disconnects after two unacknowledged attempts.
        if matches!(peer, Peer::Udp(_) | Peer::SecureUdp(_)) {
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
        let counter = self.tx_seqs.entry(peer).or_insert(0);
        let seq = *counter;
        *counter = counter.wrapping_add(1);
        let mut out = ConnectionHeader {
            channel: hdr.channel,
            seq,
            status: 0x00,
        }
        .to_bytes()
        .to_vec();
        out.push(feature);
        out.push(code);
        out.extend_from_slice(&value);
        let frame = KnxnetIpFrame::encode(service::TUNNELLING_FEATURE_RESPONSE, &out);
        self.send_frame(&frame, peer)
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
        // Over TCP the tunnelling layer has no TUNNELLING_ACK; over UDP,
        // plain or secure, it has.
        let acks = matches!(peer, Peer::Udp(_) | Peer::SecureUdp(_));
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

        let mut cemi = cemi;
        // As a real interface: a request sent with source 0.0.0 goes out under
        // the tunnel's address.
        if cemi.message_code == MessageCode::LDataReq && cemi.source.0 == 0 {
            cemi.source = IndividualAddress(self.tunnel_ia_of(peer));
        }
        let responses = self.bus.deliver_from_tool(&cemi);
        // Every L_Data.req is confirmed with exactly one L_Data.con before any
        // answer from the bus (the bus echoes group writes as a con itself;
        // the gateway adds one for every other request). ETS 6 waits for that
        // confirmation and drops the tunnel after 3 s without it
        // (ETS-against-sim capture, 2026-10-27).
        if cemi.message_code == MessageCode::LDataReq
            && !responses
                .iter()
                .any(|r| r.message_code == MessageCode::LDataCon)
        {
            let con = CemiLData {
                message_code: MessageCode::LDataCon,
                ..cemi.clone()
            };
            self.send_tunnelling(&con, peer)?;
        }
        for resp in responses {
            self.send_tunnelling(&resp, peer)?;
        }
        Ok(())
    }

    /// The individual address the tunnel of `peer` was given at CONNECT.
    fn tunnel_ia_of(&mut self, peer: Peer) -> u16 {
        let plain = self.plain_ia;
        if matches!(peer, Peer::Udp(_)) {
            return plain;
        }
        match self.session_state(peer) {
            Some(SessionState::Established { tunnel_ia, .. }) => *tunnel_ia,
            _ => plain,
        }
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

/// Whether a plain KNXnet/IP frame belongs to a tunnel's data connection
/// (TUNNELLING_REQUEST or TUNNELLING_ACK) rather than its control endpoint.
fn is_data_service(frame: &[u8]) -> bool {
    frame.len() >= 4
        && matches!(
            u16::from_be_bytes([frame[2], frame[3]]),
            service::TUNNELLING_REQUEST | service::TUNNELLING_ACK
        )
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

/// A classic pcap file of raw IPv4 packets (link type 101), one UDP datagram
/// per record with synthesised IP and UDP headers. Flushed after every packet.
struct PcapWriter {
    out: std::io::BufWriter<std::fs::File>,
    start: std::time::Instant,
    epoch: std::time::SystemTime,
}

impl PcapWriter {
    fn create(path: &std::path::Path) -> std::io::Result<Self> {
        use std::io::Write;
        let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
        // magic, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 101 (RAW)
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&65535u32.to_le_bytes())?;
        out.write_all(&101u32.to_le_bytes())?;
        out.flush()?;
        Ok(Self {
            out,
            start: std::time::Instant::now(),
            epoch: std::time::SystemTime::now(),
        })
    }

    fn write_udp(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
    ) -> std::io::Result<()> {
        use std::io::Write;
        let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) else {
            return Ok(());
        };
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // id, flags, ttl, proto UDP, checksum 0
        pkt.extend_from_slice(&s.ip().octets());
        pkt.extend_from_slice(&d.ip().octets());
        pkt.extend_from_slice(&s.port().to_be_bytes());
        pkt.extend_from_slice(&d.port().to_be_bytes());
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(payload);
        let since = (self.epoch + self.start.elapsed())
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.out
            .write_all(&(since.as_secs() as u32).to_le_bytes())?;
        self.out.write_all(&since.subsec_micros().to_le_bytes())?;
        self.out.write_all(&(pkt.len() as u32).to_le_bytes())?;
        self.out.write_all(&(pkt.len() as u32).to_le_bytes())?;
        self.out.write_all(&pkt)?;
        self.out.flush()
    }
}
