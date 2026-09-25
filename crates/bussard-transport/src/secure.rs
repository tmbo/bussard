//! The KNXnet/IP Secure tunnelling link (issue #71 Phase B, #197, spec §7-§9).
//!
//! A [`SecureLink`] is one authenticated secure session with the interface's
//! control endpoint, over TCP or UDP. The tunnel task talks plain KNXnet/IP
//! frames to it; the link wraps every outbound frame in a SECURE_WRAPPER and
//! unwraps every inbound one.
//!
//! # TCP (CONFIRMED)
//!
//! ETS talks to the Jung IP interface over TCP only, for the description, the
//! extended search, the session and all tunnelling (issue #90 S4 capture), and
//! the XKNX reference supports secure tunnelling only over TCP. Over TCP the
//! KNXnet/IP tunnelling layer sends no TUNNELING_ACK (CONFIRMED: the capture's
//! plain TCP tunnel carries 177 TUNNELING_REQUESTs and no ACK), every HPAI is
//! the TCP route-back HPAI, and a closed TCP connection ends the session.
//!
//! # UDP (INFERRED, verified against knx-sim only; issue #197)
//!
//! The KNX specification also allows a unicast secure session over UDP, for an
//! interface without a TCP endpoint. The session and the tunnel share one
//! connected UDP socket: SESSION_REQUEST carries that socket's real endpoint
//! as its HPAI, the CONNECT_REQUEST names it as control and data endpoint (as
//! the plain UDP tunnel does), and TUNNELING_ACK is back in the loop, wrapped
//! like every other frame. Every frame goes to the control endpoint; the data
//! endpoint of the CONNECT_RESPONSE is not used, as on the plain UDP tunnel.
//! No real UDP-only interface has been captured or tested, so UDP is an
//! explicit opt-in (`--secure-transport udp`): the default `auto` stays on TCP
//! and reports an interface that refuses TCP but advertises Secure with
//! [`TransportError::SecureTcpRefused`] instead of switching.
//!
//! # Handshake (as implemented)
//!
//! 1. TCP connect to the gateway's control endpoint, or bind a UDP socket
//!    connected to it.
//! 2. SESSION_REQUEST: the carrier's HPAI + fresh X25519 public key.
//! 3. SESSION_RESPONSE: session id + server public key + MAC. With the
//!    device authentication code (keyring) the MAC is verified, so the client
//!    authenticates the interface before it reveals anything derived from the
//!    user password.
//! 4. Session key = SHA-256(X25519 shared secret)[..16].
//! 5. SESSION_AUTHENTICATE (user id + MAC under the user password key), sent
//!    inside a SECURE_WRAPPER.
//! 6. SESSION_STATUS inside a SECURE_WRAPPER: `STATUS_AUTHENTICATION_SUCCESS`,
//!    or the handshake fails with [`TransportError::SecureAuthFailed`].
//!
//! Every later frame (CONNECT_REQUEST, heartbeats, tunnelling, DISCONNECT) is
//! wrapped. The tunnel sends a wrapped SESSION_STATUS keepalive every
//! [`SecureTunnelConfig::keepalive`](crate::SecureTunnelConfig::keepalive)
//! and a wrapped `STATUS_CLOSE` before it closes. TIMER_NOTIFY belongs to
//! secure routing (the multicast timer); on a unicast session it is ignored
//! (CONFIRMED absent over TCP; over UDP ignored the same way).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use bussard_secure::ipsecure::{
    self, EphemeralKeyPair, IpSecureSession, SessionStatus, verify_session_response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::{self, Instant};

use crate::config::{SecureTransport, SecureUser};
use crate::error::{Result, TransportError};
use crate::knxnet::{self, HEADER_LEN, Hpai, ServiceType};

/// Largest KNXnet/IP frame the link accepts (the header's 16-bit length).
const MAX_FRAME: usize = u16::MAX as usize;

/// A buffered reader of whole KNXnet/IP frames from a TCP stream.
///
/// Cancel-safe: bytes read so far live in `buf`, so dropping a pending
/// [`read_frame`](FrameReader::read_frame) (the tunnel task does that in its
/// `select!`) loses nothing.
pub(crate) struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// An empty reader.
    pub(crate) fn new() -> Self {
        FrameReader { buf: Vec::new() }
    }

    /// Takes one complete frame out of the buffer, if there is one.
    fn pop(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        if self.buf[0] != knxnet::HEADER_SIZE_10 || self.buf[1] != knxnet::KNXNETIP_VERSION_10 {
            return Err(TransportError::BadHeader(self.buf[0], self.buf[1]));
        }
        let total = usize::from(u16::from_be_bytes([self.buf[4], self.buf[5]]));
        if total < HEADER_LEN {
            return Err(TransportError::Truncated {
                needed: HEADER_LEN,
                had: total,
                context: "KNXnet/IP total length over TCP",
            });
        }
        if self.buf.len() < total {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buf.drain(..total).collect();
        Ok(Some(frame))
    }

    /// Reads the next whole frame from `stream`.
    pub(crate) async fn read_frame(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut chunk = [0u8; 2048];
        loop {
            if let Some(frame) = self.pop()? {
                return Ok(frame);
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(TransportError::Io {
                    peer: stream.peer_addr().ok(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the gateway closed the TCP connection",
                    ),
                });
            }
            if self.buf.len() + n > MAX_FRAME * 2 {
                return Err(TransportError::Truncated {
                    needed: MAX_FRAME,
                    had: self.buf.len() + n,
                    context: "KNXnet/IP TCP receive buffer overflow",
                });
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Opens a TCP connection to `gateway`, bound to `local` unless unspecified.
pub(crate) async fn tcp_connect(
    gateway: SocketAddrV4,
    local: Ipv4Addr,
    timeout: Duration,
) -> Result<TcpStream> {
    let connect = async {
        let socket = TcpSocket::new_v4()?;
        if !local.is_unspecified() {
            socket.bind(SocketAddr::from(SocketAddrV4::new(local, 0)))?;
        }
        let stream = socket.connect(SocketAddr::from(gateway)).await?;
        stream.set_nodelay(true)?;
        Ok::<TcpStream, std::io::Error>(stream)
    };
    match time::timeout(timeout, connect).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(source)) => Err(TransportError::Io {
            peer: Some(SocketAddr::from(gateway)),
            source,
        }),
        Err(_) => Err(TransportError::Timeout("TCP connect to the gateway")),
    }
}

/// The derived keys of the one [`SecureUser`] a tunnel presents.
#[derive(Clone)]
pub(crate) struct UserKeys {
    /// The user id.
    pub(crate) user_id: u8,
    /// PBKDF2 of the user password.
    pub(crate) user_key: bussard_secure::Key16,
    /// PBKDF2 of the device authentication code, if known.
    pub(crate) device_auth: Option<bussard_secure::Key16>,
}

impl UserKeys {
    /// Derives the keys of `user` (two PBKDF2 runs at most).
    pub(crate) fn derive(user: &SecureUser) -> Self {
        UserKeys {
            user_id: user.user_id,
            user_key: user.password.derive(bussard_secure::salt::USER_PASSWORD),
            device_auth: user
                .device_authentication_code
                .as_ref()
                .map(|code| code.derive(bussard_secure::salt::DEVICE_AUTHENTICATION_CODE)),
        }
    }
}

/// The socket a secure session runs over.
enum Carrier {
    /// A TCP connection, split into whole frames by `reader`.
    Tcp {
        /// The stream.
        stream: TcpStream,
        /// Buffered bytes of a partly received frame.
        reader: FrameReader,
    },
    /// A UDP socket connected to the gateway; one datagram is one frame.
    Udp {
        /// The socket.
        socket: UdpSocket,
        /// The socket's real local endpoint, advertised in every HPAI.
        hpai: Hpai,
    },
}

impl Carrier {
    /// Opens the carrier `transport` names (`Auto` is resolved by the caller
    /// and treated as TCP here).
    async fn open(
        transport: SecureTransport,
        gateway: SocketAddrV4,
        local: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Carrier> {
        match transport {
            SecureTransport::Udp => {
                let (socket, hpai) = crate::tunnel::udp_socket(gateway, local).await?;
                Ok(Carrier::Udp { socket, hpai })
            }
            SecureTransport::Tcp | SecureTransport::Auto => Ok(Carrier::Tcp {
                stream: tcp_connect(gateway, local, timeout).await?,
                reader: FrameReader::new(),
            }),
        }
    }

    /// The HPAI this carrier advertises: TCP route-back, or the UDP socket's
    /// real endpoint.
    fn hpai(&self) -> Hpai {
        match self {
            Carrier::Tcp { .. } => Hpai::tcp_route_back(),
            Carrier::Udp { hpai, .. } => *hpai,
        }
    }

    /// Sends raw bytes (one frame).
    async fn send(&mut self, bytes: &[u8], gateway: SocketAddrV4) -> Result<()> {
        let result = match self {
            Carrier::Tcp { stream, .. } => stream.write_all(bytes).await,
            Carrier::Udp { socket, .. } => socket.send(bytes).await.map(|_| ()),
        };
        result.map_err(|source| TransportError::Io {
            peer: Some(SocketAddr::from(gateway)),
            source,
        })
    }

    /// Receives the next raw frame. Cancel-safe.
    async fn recv(&mut self) -> Result<Vec<u8>> {
        match self {
            Carrier::Tcp { stream, reader } => reader.read_frame(stream).await,
            Carrier::Udp { socket, .. } => {
                let mut buf = vec![0u8; 2048];
                let n = socket.recv(&mut buf).await?;
                buf.truncate(n);
                Ok(buf)
            }
        }
    }

    /// Reads the next frame before `deadline`, naming `what` on timeout.
    async fn recv_until(&mut self, deadline: Instant, what: &'static str) -> Result<Vec<u8>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match time::timeout(remaining, self.recv()).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout(what)),
        }
    }

    /// Best effort: shuts a TCP stream (a UDP socket has nothing to shut).
    async fn shutdown(&mut self) {
        if let Carrier::Tcp { stream, .. } = self {
            let _ = stream.shutdown().await;
        }
    }
}

/// One authenticated KNXnet/IP Secure session over TCP or UDP.
pub(crate) struct SecureLink {
    carrier: Carrier,
    session: IpSecureSession,
    gateway: SocketAddrV4,
}

impl SecureLink {
    /// Opens the carrier and runs the session handshake for `user` (module
    /// docs), bounded by `timeout` overall. `transport` must be `Tcp` or
    /// `Udp`; `Auto` means TCP here (the refusal check lives in the tunnel).
    pub(crate) async fn open(
        gateway: SocketAddrV4,
        local: Ipv4Addr,
        user: &UserKeys,
        transport: SecureTransport,
        timeout: Duration,
    ) -> Result<SecureLink> {
        let deadline = Instant::now() + timeout;
        let mut carrier = Carrier::open(transport, gateway, local, timeout).await?;

        let keys = EphemeralKeyPair::generate()?;
        let request = ipsecure::session_request(&carrier.hpai().to_bytes(), keys.public());
        carrier.send(&request, gateway).await?;

        // SESSION_RESPONSE.
        let response = loop {
            let frame = carrier.recv_until(deadline, "SESSION_RESPONSE").await?;
            match knxnet::parse(&frame) {
                Ok(p) if p.service == ServiceType::SessionResponse => {
                    break ipsecure::parse_session_response(&frame)?;
                }
                Ok(p) if p.service == ServiceType::SessionStatus => {
                    let status = ipsecure::parse_session_status(&frame)?;
                    return Err(TransportError::SecureAuthFailed {
                        gateway,
                        user_id: user.user_id,
                        status,
                    });
                }
                _ => continue,
            }
        };
        match &user.device_auth {
            Some(device_auth) => {
                if verify_session_response(&response, device_auth, keys.public()).is_err() {
                    return Err(TransportError::SecureServerUnverified { gateway });
                }
            }
            None => tracing::warn!(
                "KNXnet/IP Secure: no device authentication code for {gateway}; \
                 not verifying the interface's identity (pass a keyring to check it)"
            ),
        }
        let session_key = keys.session_key(&response.server_public);
        let client_public = *keys.public();
        drop(keys);
        let serial = ipsecure::client_serial()?;
        let mut session = IpSecureSession::new(session_key, response.session_id, serial);

        // SESSION_AUTHENTICATE, wrapped (CONFIRMED against the capture).
        let authenticate = ipsecure::session_authenticate(
            &user.user_key,
            user.user_id,
            &client_public,
            &response.server_public,
        )?;
        let wrapped = session.seal(&authenticate)?;
        carrier.send(&wrapped, gateway).await?;

        // SESSION_STATUS, wrapped.
        loop {
            let frame = carrier.recv_until(deadline, "SESSION_STATUS").await?;
            let inner = match knxnet::parse(&frame) {
                Ok(p) if p.service == ServiceType::SecureWrapper => match session.open(&frame) {
                    Ok(inner) => inner,
                    Err(err) => {
                        tracing::debug!(%err, "dropping an unverifiable wrapper during the handshake");
                        continue;
                    }
                },
                // A plain SESSION_STATUS: some servers answer an unknown user
                // this way before any wrapper exists.
                Ok(p) if p.service == ServiceType::SessionStatus => frame.clone(),
                _ => continue,
            };
            match ipsecure::parse_session_status(&inner) {
                Ok(SessionStatus::Success) => break,
                Ok(SessionStatus::KeepAlive) => continue,
                Ok(status) => {
                    return Err(TransportError::SecureAuthFailed {
                        gateway,
                        user_id: user.user_id,
                        status,
                    });
                }
                Err(_) => continue,
            }
        }
        tracing::debug!(
            session = response.session_id,
            user = user.user_id,
            udp = matches!(carrier, Carrier::Udp { .. }),
            "KNXnet/IP Secure session authenticated with {gateway}"
        );
        Ok(SecureLink {
            carrier,
            session,
            gateway,
        })
    }

    /// Whether the session runs over UDP (so the tunnelling layer uses
    /// TUNNELING_ACK and a deferred ICMP refusal is transient).
    pub(crate) fn is_udp(&self) -> bool {
        matches!(self.carrier, Carrier::Udp { .. })
    }

    /// The carrier this session runs over (`Tcp` or `Udp`).
    pub(crate) fn transport(&self) -> SecureTransport {
        if self.is_udp() {
            SecureTransport::Udp
        } else {
            SecureTransport::Tcp
        }
    }

    /// The HPAI the tunnel advertises in CONNECT, CONNECTIONSTATE and
    /// DISCONNECT on this session.
    pub(crate) fn hpai(&self) -> Hpai {
        self.carrier.hpai()
    }

    /// Wraps and sends one plain KNXnet/IP frame.
    pub(crate) async fn send(&mut self, frame: &[u8]) -> Result<()> {
        let wrapped = self.session.seal(frame)?;
        self.carrier.send(&wrapped, self.gateway).await
    }

    /// Receives the next plain inbound frame into `out`, returning its length.
    ///
    /// Unwraps SECURE_WRAPPERs; drops frames that fail verification or replay
    /// checks (logged); swallows keepalives and TIMER_NOTIFY; turns a session
    /// close/timeout from the gateway into
    /// [`TransportError::SecureSessionEnded`]. Cancel-safe.
    pub(crate) async fn recv(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            let frame = self.carrier.recv().await?;
            let service = match knxnet::parse(&frame) {
                Ok(p) => p.service,
                Err(_) => continue,
            };
            let inner = match service {
                ServiceType::SecureWrapper => match self.session.open(&frame) {
                    Ok(inner) => inner,
                    Err(err) => {
                        tracing::warn!(%err, "dropping an inbound SECURE_WRAPPER");
                        continue;
                    }
                },
                // Plain SESSION_STATUS from the server (e.g. a timeout notice
                // after our session was already dropped) ends the session too.
                ServiceType::SessionStatus => frame,
                // Secure routing's timer sync; meaningless on a unicast session.
                ServiceType::TimerNotify => {
                    tracing::debug!("ignoring a TIMER_NOTIFY on a unicast secure session");
                    continue;
                }
                other => {
                    tracing::debug!(?other, "ignoring a plain frame on the secure session");
                    continue;
                }
            };
            if let Ok(p) = knxnet::parse(&inner) {
                match p.service {
                    ServiceType::SessionStatus => match ipsecure::parse_session_status(&inner) {
                        Ok(SessionStatus::KeepAlive) | Ok(SessionStatus::Success) => continue,
                        Ok(status) => return Err(TransportError::SecureSessionEnded(status)),
                        Err(_) => continue,
                    },
                    ServiceType::TimerNotify => continue,
                    _ => {}
                }
            }
            if inner.len() > out.len() {
                tracing::warn!(len = inner.len(), "dropping an oversized inner frame");
                continue;
            }
            out[..inner.len()].copy_from_slice(&inner);
            return Ok(inner.len());
        }
    }

    /// Sends a wrapped `STATUS_KEEPALIVE`.
    pub(crate) async fn keepalive(&mut self) -> Result<()> {
        self.send(&ipsecure::session_status(SessionStatus::KeepAlive))
            .await
    }

    /// Best effort: sends a wrapped `STATUS_CLOSE` and shuts a TCP stream.
    pub(crate) async fn close(&mut self) {
        let _ = self
            .send(&ipsecure::session_status(SessionStatus::Close))
            .await;
        self.carrier.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_reader_splits_concatenated_frames() -> Result<()> {
        let mut reader = FrameReader::new();
        let a = knxnet::frame(ServiceType::ConnectionstateResponse, &[1, 0]);
        let b = knxnet::frame(ServiceType::DisconnectResponse, &[1, 0]);
        reader.buf.extend_from_slice(&a);
        reader.buf.extend_from_slice(&b[..3]);
        assert_eq!(reader.pop()?, Some(a));
        assert_eq!(reader.pop()?, None);
        reader.buf.extend_from_slice(&b[3..]);
        assert_eq!(reader.pop()?, Some(b));
        Ok(())
    }

    #[test]
    fn test_frame_reader_rejects_garbage() {
        let mut reader = FrameReader::new();
        reader.buf.extend_from_slice(&[0xFF; 8]);
        assert!(matches!(
            reader.pop(),
            Err(TransportError::BadHeader(0xFF, 0xFF))
        ));
    }
}
