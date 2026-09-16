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

use std::net::{SocketAddr, UdpSocket};

use crate::bus::Bus;
use crate::wire::cemi::CemiLData;
use crate::wire::knxnetip::{ConnectionHeader, KnxnetIpFrame, service};

/// A blocking KNXnet/IP tunnelling gateway over UDP.
pub struct KnxnetIpServer {
    socket: UdpSocket,
    bus: Bus,
    channel: u8,
    /// Sequence counter for TUNNELLING_REQUESTs we send toward the tool.
    tx_seq: u8,
}

/// Errors from running the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A socket I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl KnxnetIpServer {
    /// Bind a server on `addr`, serving the given bus.
    pub fn bind(addr: SocketAddr, bus: Bus) -> Result<Self, ServerError> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self {
            socket,
            bus,
            channel: 1,
            tx_seq: 0,
        })
    }

    /// The local address the server bound to (useful when binding to port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Borrow the bus (for observation).
    pub fn bus(&self) -> &Bus {
        &self.bus
    }

    /// Serve forever, one datagram at a time. Returns only on socket error.
    pub fn serve(&mut self) -> Result<(), ServerError> {
        let mut buf = [0u8; 1024];
        loop {
            let (n, peer) = self.socket.recv_from(&mut buf)?;
            self.handle_datagram(&buf[..n], peer)?;
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
        let frame = match KnxnetIpFrame::decode(data) {
            Ok(f) => f,
            Err(_) => return Ok(()), // strict: ignore malformed framing
        };
        match frame.service {
            service::CONNECT_REQUEST => self.on_connect_request(&frame.body, peer),
            service::CONNECTIONSTATE_REQUEST => self.on_connectionstate_request(&frame.body, peer),
            service::DISCONNECT_REQUEST => self.on_disconnect_request(&frame.body, peer),
            service::TUNNELLING_REQUEST => self.on_tunnelling_request(&frame.body, peer),
            _ => Ok(()),
        }
    }

    fn on_connect_request(&mut self, _body: &[u8], peer: SocketAddr) -> Result<(), ServerError> {
        // CONNECT_RESPONSE body: channel, status, data-endpoint HPAI (8),
        // connection-response data block (CRD): len(1), type(1) + KNX addr(2).
        let mut body = Vec::new();
        body.push(self.channel);
        body.push(0x00); // E_NO_ERROR
        // Data endpoint HPAI: length 8, protocol UDP (0x01), IP:port of the
        // server's own local address (echo the peer's addressing family is not
        // required; a real gateway returns its own endpoint).
        let local = self.socket.local_addr()?;
        body.extend_from_slice(&hpai(local));
        // CRD for tunnelling: length 4, TUNNEL_CONNECTION, KNX individual addr.
        body.push(0x04);
        body.push(0x04); // TUNNEL_CONNECTION
        body.extend_from_slice(&0x1000u16.to_be_bytes()); // gateway IA 1.0.0
        let out = KnxnetIpFrame::encode(service::CONNECT_RESPONSE, &body);
        self.socket.send_to(&out, peer)?;
        Ok(())
    }

    fn on_connectionstate_request(
        &mut self,
        body: &[u8],
        peer: SocketAddr,
    ) -> Result<(), ServerError> {
        let channel = body.first().copied().unwrap_or(self.channel);
        let status = if channel == self.channel { 0x00 } else { 0x21 };
        let resp = KnxnetIpFrame::encode(service::CONNECTIONSTATE_RESPONSE, &[channel, status]);
        self.socket.send_to(&resp, peer)?;
        Ok(())
    }

    fn on_disconnect_request(&mut self, body: &[u8], peer: SocketAddr) -> Result<(), ServerError> {
        let channel = body.first().copied().unwrap_or(self.channel);
        let resp = KnxnetIpFrame::encode(service::DISCONNECT_RESPONSE, &[channel, 0x00]);
        self.socket.send_to(&resp, peer)?;
        Ok(())
    }

    fn on_tunnelling_request(&mut self, body: &[u8], peer: SocketAddr) -> Result<(), ServerError> {
        let Some(hdr) = ConnectionHeader::parse(body) else {
            return Ok(());
        };
        // ACK the request first.
        let ack = KnxnetIpFrame::encode(
            service::TUNNELLING_ACK,
            &ConnectionHeader {
                channel: hdr.channel,
                seq: hdr.seq,
                status: 0x00,
            }
            .to_bytes(),
        );
        self.socket.send_to(&ack, peer)?;

        // The cEMI payload follows the 4-byte connection header.
        let cemi_bytes = &body[4..];
        let cemi = match CemiLData::decode(cemi_bytes) {
            Ok(c) => c,
            Err(_) => return Ok(()), // strict: drop malformed cEMI
        };

        let responses = self.bus.deliver_from_tool(&cemi);
        for resp in responses {
            self.send_tunnelling(&resp, hdr.channel, peer)?;
        }
        Ok(())
    }

    fn send_tunnelling(
        &mut self,
        cemi: &CemiLData,
        channel: u8,
        peer: SocketAddr,
    ) -> Result<(), ServerError> {
        let seq = self.tx_seq;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut body = ConnectionHeader {
            channel,
            seq,
            status: 0x00,
        }
        .to_bytes()
        .to_vec();
        body.extend_from_slice(&cemi.encode());
        let frame = KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body);
        self.socket.send_to(&frame, peer)?;
        Ok(())
    }
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
