//! Raw KNXnet/IP primitives for tests that script each datagram themselves.
//!
//! [`RawGateway`] owns a loopback UDP socket and has one helper per protocol
//! step: receive and parse, expect a service, accept a CONNECT, push an
//! indication, ACK. The protocol-probe suites (sequence windows, retransmits,
//! heartbeats, HPAIs) use it directly. The higher-level
//! [`MockGateway`](crate::MockGateway) is built on the same frame builders.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use bussard_transport::cemi::CemiFrame;
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType, TunnelingRequest};
use tokio::net::UdpSocket;

use crate::MockError;
use crate::consts::TUNNEL_IA_RAW;

/// Largest datagram the mocks accept.
const MAX_DATAGRAM: usize = 1024;

/// Binds a UDP socket on `127.0.0.1:0` and returns its address with it.
///
/// # Errors
/// Fails when the socket cannot be bound or reports a non-IPv4 address.
pub async fn bind() -> Result<(SocketAddrV4, UdpSocket), MockError> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    match sock.local_addr()? {
        SocketAddr::V4(v4) => Ok((v4, sock)),
        SocketAddr::V6(_) => Err(MockError::NotIpv4),
    }
}

/// Wraps `body` in a KNXnet/IP header for `service`.
pub fn frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    knxnet::frame(service, body)
}

/// A successful CONNECT_RESPONSE body: `channel`, status 0, data HPAI
/// `127.0.0.1:port`, and a tunnel CRD that assigns IA 1.1.255.
pub fn connect_response_body(channel: u8, port: u16) -> Vec<u8> {
    let mut body = vec![channel, 0x00, 0x08, 0x01, 127, 0, 0, 1];
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04]);
    body.extend_from_slice(&TUNNEL_IA_RAW.to_be_bytes());
    body
}

/// A refused CONNECT_RESPONSE body: channel 0 and `status`, with no HPAI or CRD.
/// For example, `0x24` is E_NO_MORE_CONNECTIONS.
pub fn connect_refusal_body(status: u8) -> Vec<u8> {
    vec![0x00, status]
}

/// Whether an 8-octet HPAI (`[0x08, 0x01, ip(4), port(2)]`) encodes exactly `peer`.
pub fn hpai_matches(hpai: &[u8], peer: SocketAddr) -> bool {
    let SocketAddr::V4(v4) = peer else {
        return false;
    };
    hpai.len() == 8
        && hpai[0] == 0x08
        && hpai[1] == 0x01
        && hpai[2..6] == v4.ip().octets()
        && hpai[6..8] == v4.port().to_be_bytes()
}

/// A DESCRIPTION_RESPONSE body: a 54-octet device-info DIB named `name` (IA
/// 1.0.0, TP1), followed by a tunnelling-info DIB with `slots` slots, of which
/// the first `in_use` are occupied. Slot IAs start at 1.0.241. Every slot is
/// usable and authorized. With `slots == 0` the tunnelling DIB is still
/// appended (4 octets); slice `[..54]` to model an interface without one.
pub fn description_response_body(name: &str, slots: usize, in_use: usize) -> Vec<u8> {
    let mut body = vec![0u8; 54];
    body[0] = 54;
    body[1] = 0x01; // DIB_DEVICE_INFO
    body[2] = 0x02; // medium: TP1
    body[4..6].copy_from_slice(&0x1000u16.to_be_bytes());
    let name = name.as_bytes();
    let len = name.len().min(30);
    body[24..24 + len].copy_from_slice(&name[..len]);

    body.push((4 + 4 * slots) as u8);
    body.push(0x07); // DIB_TUNNELING_INFO
    body.extend_from_slice(&248u16.to_be_bytes()); // max APDU
    for slot in 0..slots {
        body.extend_from_slice(&(0x10F1u16 + slot as u16).to_be_bytes());
        // Status bits: free = 0x01, authorized = 0x02, usable = 0x04.
        let mut status = 0x0006u16;
        if slot >= in_use {
            status |= 0x0001;
        }
        body.extend_from_slice(&status.to_be_bytes());
    }
    body
}

/// One received, header-parsed KNXnet/IP datagram.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Who sent it.
    pub peer: SocketAddr,
    /// Its service type.
    pub service: ServiceType,
    /// The body after the 6-octet header.
    pub body: Vec<u8>,
}

impl Datagram {
    /// Parses the body as a TUNNELLING_REQUEST.
    ///
    /// # Errors
    /// Fails when the body is not a well-formed tunnelling request.
    pub fn tunneling_request(&self) -> Result<TunnelingRequest, MockError> {
        Ok(knxnet::parse_tunneling_request(&self.body)?)
    }

    /// Parses the body as a TUNNELLING_ACK: `(header, status)`.
    ///
    /// # Errors
    /// Fails when the body is not a well-formed tunnelling ACK.
    pub fn tunneling_ack(&self) -> Result<(ConnectionHeader, u8), MockError> {
        Ok(knxnet::parse_tunneling_ack(&self.body)?)
    }
}

/// A loopback KNXnet/IP endpoint driven step by step from a test.
#[derive(Debug)]
pub struct RawGateway {
    sock: UdpSocket,
    addr: SocketAddrV4,
}

impl RawGateway {
    /// Binds `127.0.0.1:0`.
    ///
    /// # Errors
    /// Fails when the socket cannot be bound.
    pub async fn bind() -> Result<Self, MockError> {
        let (addr, sock) = bind().await?;
        Ok(Self { sock, addr })
    }

    /// The address to hand to the client under test.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The underlying socket, for anything the helpers do not cover.
    pub fn socket(&self) -> &UdpSocket {
        &self.sock
    }

    /// Receives and parses one datagram. There is no deadline, so this also
    /// works under a paused tokio clock.
    ///
    /// # Errors
    /// Fails on a socket error or a datagram that is not KNXnet/IP.
    pub async fn recv(&self) -> Result<Datagram, MockError> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, peer) = self.sock.recv_from(&mut buf).await?;
        let parsed = knxnet::parse(&buf[..n])?;
        Ok(Datagram {
            peer,
            service: parsed.service,
            body: parsed.body.to_vec(),
        })
    }

    /// Like [`RawGateway::recv`], but gives up after `within` and returns
    /// `None`.
    ///
    /// # Errors
    /// Fails on a socket error or a datagram that is not KNXnet/IP.
    pub async fn recv_within(&self, within: Duration) -> Result<Option<Datagram>, MockError> {
        match tokio::time::timeout(within, self.recv()).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Receives one datagram and requires it to be `service`.
    ///
    /// # Errors
    /// Fails when a different service arrives, or as [`RawGateway::recv`].
    pub async fn expect(&self, service: ServiceType) -> Result<Datagram, MockError> {
        let dgram = self.recv().await?;
        if dgram.service != service {
            return Err(MockError::UnexpectedService {
                expected: service,
                got: dgram.service,
            });
        }
        Ok(dgram)
    }

    /// Sends raw bytes to `peer`.
    ///
    /// # Errors
    /// Fails on a socket error.
    pub async fn send(&self, bytes: &[u8], peer: SocketAddr) -> Result<(), MockError> {
        self.sock.send_to(bytes, peer).await?;
        Ok(())
    }

    /// Frames `body` as `service` and sends it to `peer`.
    ///
    /// # Errors
    /// Fails on a socket error.
    pub async fn send_frame(
        &self,
        service: ServiceType,
        body: &[u8],
        peer: SocketAddr,
    ) -> Result<(), MockError> {
        self.send(&frame(service, body), peer).await
    }

    /// Waits for a CONNECT_REQUEST, grants `channel`, and returns the client's
    /// address.
    ///
    /// # Errors
    /// Fails when anything other than a CONNECT_REQUEST arrives first.
    pub async fn accept_connect(&self, channel: u8) -> Result<SocketAddr, MockError> {
        let req = self.expect(ServiceType::ConnectRequest).await?;
        self.send_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, self.port()),
            req.peer,
        )
        .await?;
        Ok(req.peer)
    }

    /// Pushes `cemi` to `peer` as a TUNNELLING_REQUEST on `channel` with `seq`.
    ///
    /// # Errors
    /// Fails on a socket error.
    pub async fn push(
        &self,
        peer: SocketAddr,
        channel: u8,
        seq: u8,
        cemi: &CemiFrame,
    ) -> Result<(), MockError> {
        let header = ConnectionHeader {
            channel_id: channel,
            seq,
        };
        self.send(&knxnet::tunneling_request(header, cemi), peer)
            .await
    }

    /// Sends a TUNNELLING_ACK for `seq` with `status`.
    ///
    /// # Errors
    /// Fails on a socket error.
    pub async fn ack(
        &self,
        peer: SocketAddr,
        channel: u8,
        seq: u8,
        status: u8,
    ) -> Result<(), MockError> {
        self.send(&knxnet::tunneling_ack(channel, seq, status), peer)
            .await
    }

    /// Receives until the client's TUNNELLING_ACK for `seq` arrives, skipping
    /// anything else, such as a retransmit of the client's own request. Returns
    /// the ACK status. Gives up after `within`.
    ///
    /// # Errors
    /// Fails with [`MockError::Timeout`] when the ACK does not arrive in time.
    pub async fn await_client_ack(&self, seq: u8, within: Duration) -> Result<u8, MockError> {
        let wait = async {
            loop {
                let dgram = self.recv().await?;
                if dgram.service == ServiceType::TunnelingAck {
                    let (header, status) = dgram.tunneling_ack()?;
                    if header.seq == seq {
                        return Ok(status);
                    }
                }
            }
        };
        tokio::time::timeout(within, wait)
            .await
            .map_err(|_| MockError::Timeout("the client's TUNNELING_ACK"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_response_body_parses_back() -> Result<(), MockError> {
        let parsed = knxnet::parse_connect_response(&connect_response_body(7, 3671))?;
        assert_eq!(parsed.channel_id, 7);
        assert_eq!(parsed.status, 0);
        Ok(())
    }

    #[test]
    fn test_description_response_body_reports_slots() -> Result<(), MockError> {
        let desc = knxnet::parse_description_response(&description_response_body("Mock", 4, 3))?;
        assert_eq!(desc.name.as_deref(), Some("Mock"));
        let capacity = desc
            .tunnel_capacity()
            .ok_or(MockError::Timeout("capacity"))?;
        assert_eq!((capacity.total, capacity.in_use), (4, 3));
        Ok(())
    }

    #[test]
    fn test_hpai_matches_only_the_exact_endpoint() {
        let peer: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0x0E57));
        assert!(hpai_matches(&[0x08, 0x01, 127, 0, 0, 1, 0x0E, 0x57], peer));
        assert!(!hpai_matches(&[0x08, 0x01, 0, 0, 0, 0, 0, 0], peer));
    }
}
