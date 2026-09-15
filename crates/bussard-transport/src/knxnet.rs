//! KNXnet/IP framing: header, HPAI, and the service PDUs used by tunneling,
//! routing and discovery.
//!
//! Every KNXnet/IP frame starts with a 6-byte header:
//!
//! ```text
//! +------+------+--------------+--------------+
//! | 0x06 | 0x10 | service type | total length |
//! | hdr  | ver  |    u16 BE    |   u16 BE     |
//! +------+------+--------------+--------------+
//! ```
//!
//! `total length` covers the header plus the body. This module encodes/decodes
//! the header and each service body against the published layouts; all decoders
//! return [`TransportError`] rather than panicking.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::cemi::{CemiFrame, Cursor};
use crate::error::{Result, TransportError};

/// KNXnet/IP header size in bytes.
pub const HEADER_LEN: usize = 6;
/// Header byte 0.
pub const HEADER_SIZE_10: u8 = 0x06;
/// Header byte 1 (protocol version 1.0).
pub const KNXNETIP_VERSION_10: u8 = 0x10;

/// KNXnet/IP service type identifiers (the header's `service type` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ServiceType {
    /// SEARCH_REQUEST — gateway discovery (multicast).
    SearchRequest = 0x0201,
    /// SEARCH_RESPONSE — a gateway's answer to a search.
    SearchResponse = 0x0202,
    /// CONNECT_REQUEST — open a tunneling connection.
    ConnectRequest = 0x0205,
    /// CONNECT_RESPONSE — the gateway's channel id + status.
    ConnectResponse = 0x0206,
    /// CONNECTIONSTATE_REQUEST — heartbeat request.
    ConnectionstateRequest = 0x0207,
    /// CONNECTIONSTATE_RESPONSE — heartbeat reply.
    ConnectionstateResponse = 0x0208,
    /// DISCONNECT_REQUEST — tear down a connection.
    DisconnectRequest = 0x0209,
    /// DISCONNECT_RESPONSE — acknowledge a disconnect.
    DisconnectResponse = 0x020A,
    /// TUNNELING_REQUEST — a cEMI frame over a tunnel.
    TunnelingRequest = 0x0420,
    /// TUNNELING_ACK — acknowledge a tunneling request.
    TunnelingAck = 0x0421,
    /// ROUTING_INDICATION — a cEMI frame on the multicast group.
    RoutingIndication = 0x0530,
    /// ROUTING_LOST_MESSAGE — the router dropped frames.
    RoutingLostMessage = 0x0531,
    /// ROUTING_BUSY — the router is congested; back off.
    RoutingBusy = 0x0532,
}

impl ServiceType {
    fn from_u16(v: u16) -> Result<Self> {
        use ServiceType::*;
        Ok(match v {
            0x0201 => SearchRequest,
            0x0202 => SearchResponse,
            0x0205 => ConnectRequest,
            0x0206 => ConnectResponse,
            0x0207 => ConnectionstateRequest,
            0x0208 => ConnectionstateResponse,
            0x0209 => DisconnectRequest,
            0x020A => DisconnectResponse,
            0x0420 => TunnelingRequest,
            0x0421 => TunnelingAck,
            0x0530 => RoutingIndication,
            0x0531 => RoutingLostMessage,
            0x0532 => RoutingBusy,
            other => {
                return Err(TransportError::InvalidField {
                    field: "KNXnet/IP service type",
                    value: other,
                })
            }
        })
    }
}

/// Wraps a service body in a KNXnet/IP header and returns the full datagram.
pub fn frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (HEADER_LEN + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(HEADER_SIZE_10);
    out.push(KNXNETIP_VERSION_10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A parsed KNXnet/IP header plus the body slice that follows it.
#[derive(Debug)]
pub struct ParsedFrame<'a> {
    /// The decoded service type.
    pub service: ServiceType,
    /// The body bytes (everything after the 6-byte header).
    pub body: &'a [u8],
}

/// Parses the KNXnet/IP header and returns the service type and body slice.
pub fn parse(buf: &[u8]) -> Result<ParsedFrame<'_>> {
    if buf.len() < HEADER_LEN {
        return Err(TransportError::Truncated {
            needed: HEADER_LEN,
            had: buf.len(),
            context: "KNXnet/IP header",
        });
    }
    if buf[0] != HEADER_SIZE_10 || buf[1] != KNXNETIP_VERSION_10 {
        return Err(TransportError::BadHeader(buf[0], buf[1]));
    }
    let service = ServiceType::from_u16(u16::from_be_bytes([buf[2], buf[3]]))?;
    let total = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if total > buf.len() || total < HEADER_LEN {
        return Err(TransportError::Truncated {
            needed: total,
            had: buf.len(),
            context: "KNXnet/IP total length",
        });
    }
    Ok(ParsedFrame {
        service,
        body: &buf[HEADER_LEN..total],
    })
}

/// Host Protocol Address Information: an 8-byte structure carrying an IPv4
/// endpoint over which the gateway should reach us (or vice versa).
///
/// ```text
/// +------+---------+---------------+------+
/// | 0x08 | 0x01    |  IPv4 (4 B)   | port |
/// | len  | UDP=01  |               | u16  |
/// +------+---------+---------------+------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hpai {
    /// The IPv4 socket address (host + UDP port).
    pub addr: SocketAddrV4,
}

/// HPAI host-protocol code for UDP over IPv4.
pub const HPAI_UDP_IPV4: u8 = 0x01;
/// HPAI structure length.
pub const HPAI_LEN: u8 = 0x08;

impl Hpai {
    /// Builds an HPAI for a UDP/IPv4 endpoint.
    pub fn new(addr: SocketAddrV4) -> Self {
        Hpai { addr }
    }

    /// A wildcard HPAI (`0.0.0.0:0`), asking the gateway to reply on the same
    /// socket it received the request from (route-back / NAT-friendly).
    pub fn wildcard() -> Self {
        Hpai {
            addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(HPAI_LEN);
        out.push(HPAI_UDP_IPV4);
        out.extend_from_slice(&self.addr.ip().octets());
        out.extend_from_slice(&self.addr.port().to_be_bytes());
    }

    fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let len = cur.u8("HPAI length")?;
        if len != HPAI_LEN {
            return Err(TransportError::InvalidField {
                field: "HPAI length",
                value: len as u16,
            });
        }
        let _proto = cur.u8("HPAI host protocol")?;
        let ip = cur.take(4, "HPAI IPv4")?;
        let ip = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
        let port = cur.u16("HPAI port")?;
        Ok(Hpai {
            addr: SocketAddrV4::new(ip, port),
        })
    }
}

/// Connection type code for a tunneling connection.
pub const CONNECTION_TYPE_TUNNEL: u8 = 0x04;
/// KNX layer code: link-layer tunneling (the mode bussard uses).
pub const TUNNEL_LINK_LAYER: u8 = 0x02;

/// Builds a CONNECT_REQUEST body: control HPAI, data HPAI, and a CRI (Connection
/// Request Information) requesting a link-layer tunnel.
pub fn connect_request(control: Hpai, data: Hpai) -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    control.encode(&mut body);
    data.encode(&mut body);
    // CRI: length (4), tunnel connection type, KNX layer, reserved.
    body.push(0x04);
    body.push(CONNECTION_TYPE_TUNNEL);
    body.push(TUNNEL_LINK_LAYER);
    body.push(0x00);
    frame(ServiceType::ConnectRequest, &body)
}

/// The parsed result of a CONNECT_RESPONSE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResponse {
    /// Channel id assigned by the gateway.
    pub channel_id: u8,
    /// Status byte (0 = OK).
    pub status: u8,
    /// The gateway's data endpoint (from the response HPAI), if the status is OK.
    pub data_endpoint: Option<SocketAddrV4>,
    /// The individual address assigned to this tunnel, if present in the CRD.
    pub assigned_ia: Option<u16>,
}

/// Decodes a CONNECT_RESPONSE body.
pub fn parse_connect_response(body: &[u8]) -> Result<ConnectResponse> {
    let mut cur = Cursor::new(body);
    let channel_id = cur.u8("connect-response channel id")?;
    let status = cur.u8("connect-response status")?;
    if status != 0 {
        return Ok(ConnectResponse {
            channel_id,
            status,
            data_endpoint: None,
            assigned_ia: None,
        });
    }
    let data_hpai = Hpai::decode(&mut cur)?;
    // CRD: length, connection type, then (for tunnel) the assigned IA (2 bytes).
    let mut assigned_ia = None;
    if cur.remaining() >= 2 {
        let crd_len = cur.u8("CRD length")? as usize;
        let conn_type = cur.u8("CRD connection type")?;
        if conn_type == CONNECTION_TYPE_TUNNEL && crd_len >= 4 && cur.remaining() >= 2 {
            assigned_ia = Some(cur.u16("CRD assigned IA")?);
        }
    }
    Ok(ConnectResponse {
        channel_id,
        status,
        data_endpoint: Some(data_hpai.addr),
        assigned_ia,
    })
}

/// Builds a CONNECTIONSTATE_REQUEST body (heartbeat).
pub fn connectionstate_request(channel_id: u8, control: Hpai) -> Vec<u8> {
    let mut body = Vec::with_capacity(10);
    body.push(channel_id);
    body.push(0x00); // reserved
    control.encode(&mut body);
    frame(ServiceType::ConnectionstateRequest, &body)
}

/// Builds a CONNECTIONSTATE_RESPONSE body.
pub fn connectionstate_response(channel_id: u8, status: u8) -> Vec<u8> {
    frame(ServiceType::ConnectionstateResponse, &[channel_id, status])
}

/// A channel id + status pair, used by several small service bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelStatus {
    /// The connection channel id.
    pub channel_id: u8,
    /// The status byte (0 = OK).
    pub status: u8,
}

/// Decodes a body whose first two bytes are channel id + status
/// (CONNECTIONSTATE_RESPONSE, DISCONNECT_RESPONSE).
pub fn parse_channel_status(body: &[u8]) -> Result<ChannelStatus> {
    if body.len() < 2 {
        return Err(TransportError::Truncated {
            needed: 2,
            had: body.len(),
            context: "channel id + status",
        });
    }
    Ok(ChannelStatus {
        channel_id: body[0],
        status: body[1],
    })
}

/// Builds a DISCONNECT_REQUEST body.
pub fn disconnect_request(channel_id: u8, control: Hpai) -> Vec<u8> {
    let mut body = Vec::with_capacity(10);
    body.push(channel_id);
    body.push(0x00); // reserved
    control.encode(&mut body);
    frame(ServiceType::DisconnectRequest, &body)
}

/// Builds a DISCONNECT_RESPONSE body.
pub fn disconnect_response(channel_id: u8, status: u8) -> Vec<u8> {
    frame(ServiceType::DisconnectResponse, &[channel_id, status])
}

/// Decodes the channel id from a DISCONNECT_REQUEST body.
pub fn parse_disconnect_request(body: &[u8]) -> Result<u8> {
    if body.is_empty() {
        return Err(TransportError::Truncated {
            needed: 1,
            had: 0,
            context: "disconnect-request channel id",
        });
    }
    Ok(body[0])
}

/// The 4-byte connection header carried by TUNNELING_REQUEST and TUNNELING_ACK.
///
/// ```text
/// +------+---------+-----+----------+
/// | 0x04 | channel | seq | reserved |
/// | len  |   u8    | u8  |   0x00   |
/// +------+---------+-----+----------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionHeader {
    /// The connection channel id.
    pub channel_id: u8,
    /// The sequence counter.
    pub seq: u8,
}

/// Connection-header structure length.
pub const CONNECTION_HEADER_LEN: u8 = 0x04;

impl ConnectionHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(CONNECTION_HEADER_LEN);
        out.push(self.channel_id);
        out.push(self.seq);
        out.push(0x00); // reserved
    }

    fn decode(cur: &mut Cursor<'_>) -> Result<Self> {
        let len = cur.u8("connection-header length")?;
        if len != CONNECTION_HEADER_LEN {
            return Err(TransportError::InvalidField {
                field: "connection-header length",
                value: len as u16,
            });
        }
        let channel_id = cur.u8("connection-header channel")?;
        let seq = cur.u8("connection-header seq")?;
        let _reserved = cur.u8("connection-header reserved")?;
        Ok(ConnectionHeader { channel_id, seq })
    }
}

/// Builds a TUNNELING_REQUEST: connection header + cEMI.
pub fn tunneling_request(header: ConnectionHeader, cemi: &CemiFrame) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 16);
    header.encode(&mut body);
    body.extend_from_slice(&cemi.encode());
    frame(ServiceType::TunnelingRequest, &body)
}

/// Builds a TUNNELING_ACK: connection header only, with a status byte in place
/// of the reserved byte.
pub fn tunneling_ack(channel_id: u8, seq: u8, status: u8) -> Vec<u8> {
    let body = [CONNECTION_HEADER_LEN, channel_id, seq, status];
    frame(ServiceType::TunnelingAck, &body)
}

/// A decoded TUNNELING_REQUEST: its connection header and the carried cEMI frame.
#[derive(Debug)]
pub struct TunnelingRequest {
    /// The connection header (channel + seq).
    pub header: ConnectionHeader,
    /// The decoded cEMI frame.
    pub cemi: CemiFrame,
}

/// Decodes a TUNNELING_REQUEST body.
pub fn parse_tunneling_request(body: &[u8]) -> Result<TunnelingRequest> {
    let mut cur = Cursor::new(body);
    let header = ConnectionHeader::decode(&mut cur)?;
    let cemi_bytes = cur.take(cur.remaining(), "tunneling cEMI")?;
    let cemi = CemiFrame::decode(cemi_bytes)?;
    Ok(TunnelingRequest { header, cemi })
}

/// Decodes a TUNNELING_ACK body: connection header with status in the last byte.
pub fn parse_tunneling_ack(body: &[u8]) -> Result<(ConnectionHeader, u8)> {
    if body.len() < 4 {
        return Err(TransportError::Truncated {
            needed: 4,
            had: body.len(),
            context: "tunneling ack",
        });
    }
    Ok((
        ConnectionHeader {
            channel_id: body[1],
            seq: body[2],
        },
        body[3],
    ))
}

/// Builds a ROUTING_INDICATION: header + cEMI (no connection header).
pub fn routing_indication(cemi: &CemiFrame) -> Vec<u8> {
    frame(ServiceType::RoutingIndication, &cemi.encode())
}

/// Decodes a ROUTING_INDICATION body into its cEMI frame.
pub fn parse_routing_indication(body: &[u8]) -> Result<CemiFrame> {
    CemiFrame::decode(body)
}

/// A decoded ROUTING_BUSY: the wait time tells senders how long to pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingBusy {
    /// Device state flags.
    pub device_state: u8,
    /// Milliseconds the router asks senders to wait.
    pub wait_time_ms: u16,
    /// Control field used to scope the busy request.
    pub control: u16,
}

/// Decodes a ROUTING_BUSY body.
///
/// Layout: structure length (0x06), device state, wait time (u16 ms), control (u16).
pub fn parse_routing_busy(body: &[u8]) -> Result<RoutingBusy> {
    let mut cur = Cursor::new(body);
    let _len = cur.u8("routing-busy length")?;
    let device_state = cur.u8("routing-busy device state")?;
    let wait_time_ms = cur.u16("routing-busy wait time")?;
    let control = cur.u16("routing-busy control")?;
    Ok(RoutingBusy {
        device_state,
        wait_time_ms,
        control,
    })
}

/// A decoded ROUTING_LOST_MESSAGE: how many frames the router dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingLost {
    /// Device state flags.
    pub device_state: u8,
    /// Number of lost messages.
    pub lost: u16,
}

/// Decodes a ROUTING_LOST_MESSAGE body.
///
/// Layout: structure length (0x04), device state, lost-message count (u16).
pub fn parse_routing_lost(body: &[u8]) -> Result<RoutingLost> {
    let mut cur = Cursor::new(body);
    let _len = cur.u8("routing-lost length")?;
    let device_state = cur.u8("routing-lost device state")?;
    let lost = cur.u16("routing-lost count")?;
    Ok(RoutingLost { device_state, lost })
}

/// Builds a SEARCH_REQUEST body: a single discovery-endpoint HPAI.
pub fn search_request(discovery: Hpai) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    discovery.encode(&mut body);
    frame(ServiceType::SearchRequest, &body)
}

/// Information about a discovered gateway, parsed from a SEARCH_RESPONSE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayInfo {
    /// The control endpoint (host + UDP port) to connect to.
    pub endpoint: SocketAddrV4,
    /// The gateway's KNX individual address (from the device-info DIB), if present.
    pub individual_address: Option<u16>,
    /// The friendly name (from the device-info DIB), if present.
    pub name: Option<String>,
}

/// DIB type: device information.
const DIB_DEVICE_INFO: u8 = 0x01;

/// Decodes a SEARCH_RESPONSE body into a [`GatewayInfo`].
///
/// Layout: an HPAI (the control endpoint) followed by one or more DIBs. We parse
/// the device-info DIB for the IA and friendly name; other DIBs are skipped.
pub fn parse_search_response(body: &[u8]) -> Result<GatewayInfo> {
    let mut cur = Cursor::new(body);
    let endpoint = Hpai::decode(&mut cur)?.addr;
    let mut individual_address = None;
    let mut name = None;

    // Walk the DIBs. Each begins with a length byte and a type byte.
    while cur.remaining() >= 2 {
        let dib_len = cur.u8("DIB length")? as usize;
        if dib_len < 2 {
            break;
        }
        let dib_type = cur.u8("DIB type")?;
        // The DIB body is dib_len - 2 bytes (len + type already consumed).
        let body_len = dib_len - 2;
        if cur.remaining() < body_len {
            break;
        }
        let dib_body = cur.take(body_len, "DIB body")?;
        if dib_type == DIB_DEVICE_INFO && dib_body.len() >= 52 {
            // Device-info DIB: [medium, status, KNX IA (2), project id (2),
            // serial (6), multicast (4), mac (6), friendly name (30)].
            individual_address = Some(u16::from_be_bytes([dib_body[2], dib_body[3]]));
            let name_bytes = &dib_body[22..52];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(30);
            let n = String::from_utf8_lossy(&name_bytes[..end])
                .trim()
                .to_string();
            if !n.is_empty() {
                name = Some(n);
            }
        }
    }

    Ok(GatewayInfo {
        endpoint,
        individual_address,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cemi::CemiFrame;
    use bussard_model::{GroupAddress, IndividualAddress};

    fn ip(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    #[test]
    fn header_roundtrip() {
        let body = [0xAA, 0xBB];
        let f = frame(ServiceType::TunnelingAck, &body);
        // 06 10 04 21 00 08 AA BB
        assert_eq!(&f[..6], &[0x06, 0x10, 0x04, 0x21, 0x00, 0x08]);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::TunnelingAck);
        assert_eq!(parsed.body, &body);
    }

    #[test]
    fn bad_header_rejected() {
        assert!(parse(&[0x07, 0x10, 0x02, 0x05, 0x00, 0x06]).is_err());
        assert!(parse(&[0x06]).is_err());
    }

    #[test]
    fn connect_request_layout() {
        let control = Hpai::new(ip(192, 168, 1, 10, 3672));
        let data = Hpai::new(ip(192, 168, 1, 10, 3672));
        let f = connect_request(control, data);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        // Two HPAIs (8 each) + 4-byte CRI = 20 bytes body.
        assert_eq!(parsed.body.len(), 20);
        // CRI trailer: 04 04 02 00.
        assert_eq!(&parsed.body[16..], &[0x04, 0x04, 0x02, 0x00]);
        // First HPAI: 08 01 C0 A8 01 0A 0E 58.
        assert_eq!(
            &parsed.body[..8],
            &[0x08, 0x01, 192, 168, 1, 10, 0x0E, 0x58]
        );
    }

    #[test]
    fn connect_response_ok() {
        // channel 0x15, status 0x00, data HPAI 192.168.1.10:3671, CRD tunnel IA 1.1.255.
        let hex: &[u8] = &[
            0x15, 0x00, // channel, status
            0x08, 0x01, 192, 168, 1, 10, 0x0E, 0x57, // data HPAI :3671
            0x04, 0x04, 0x11, 0xFF, // CRD: len 4, tunnel, IA 1.1.255
        ];
        let r = parse_connect_response(hex).unwrap();
        assert_eq!(r.channel_id, 0x15);
        assert_eq!(r.status, 0);
        assert_eq!(r.data_endpoint, Some(ip(192, 168, 1, 10, 3671)));
        assert_eq!(r.assigned_ia, Some(0x11FF));
    }

    #[test]
    fn connect_response_error_status() {
        let hex: &[u8] = &[0x00, 0x24]; // E_NO_MORE_CONNECTIONS-ish
        let r = parse_connect_response(hex).unwrap();
        assert_eq!(r.status, 0x24);
        assert_eq!(r.data_endpoint, None);
    }

    #[test]
    fn connectionstate_roundtrip() {
        let control = Hpai::wildcard();
        let f = connectionstate_request(0x15, control);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectionstateRequest);
        assert_eq!(parsed.body[0], 0x15);

        let resp = connectionstate_response(0x15, 0x00);
        let rp = parse(&resp).unwrap();
        let cs = parse_channel_status(rp.body).unwrap();
        assert_eq!(cs.channel_id, 0x15);
        assert_eq!(cs.status, 0);
    }

    #[test]
    fn tunneling_request_carries_group_write() {
        let ga: GroupAddress = "3/0/4".parse().unwrap();
        let ia: IndividualAddress = "1.1.255".parse().unwrap();
        let cemi = CemiFrame::group_write(ga, ia, &[1]);
        let header = ConnectionHeader {
            channel_id: 0x15,
            seq: 0,
        };
        let f = tunneling_request(header, &cemi);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::TunnelingRequest);
        // Connection header: 04 15 00 00.
        assert_eq!(&parsed.body[..4], &[0x04, 0x15, 0x00, 0x00]);
        let tr = parse_tunneling_request(parsed.body).unwrap();
        assert_eq!(tr.header.channel_id, 0x15);
        assert_eq!(tr.header.seq, 0);
        assert_eq!(tr.cemi, cemi);
    }

    #[test]
    fn tunneling_ack_roundtrip() {
        let f = tunneling_ack(0x15, 0x07, 0x00);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::TunnelingAck);
        let (hdr, status) = parse_tunneling_ack(parsed.body).unwrap();
        assert_eq!(hdr.channel_id, 0x15);
        assert_eq!(hdr.seq, 0x07);
        assert_eq!(status, 0);
    }

    #[test]
    fn routing_indication_roundtrip() {
        let ga: GroupAddress = "1/2/3".parse().unwrap();
        let ia: IndividualAddress = "1.1.1".parse().unwrap();
        let cemi = CemiFrame::group_write(ga, ia, &[0]);
        let f = routing_indication(&cemi);
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::RoutingIndication);
        let back = parse_routing_indication(parsed.body).unwrap();
        assert_eq!(back, cemi);
    }

    #[test]
    fn routing_busy_and_lost_decode() {
        // ROUTING_BUSY: len 06, state 00, wait 100ms (0x0064), control 0000.
        let busy = parse_routing_busy(&[0x06, 0x00, 0x00, 0x64, 0x00, 0x00]).unwrap();
        assert_eq!(busy.wait_time_ms, 100);

        // ROUTING_LOST_MESSAGE: len 04, state 00, lost 5.
        let lost = parse_routing_lost(&[0x04, 0x00, 0x00, 0x05]).unwrap();
        assert_eq!(lost.lost, 5);
    }

    #[test]
    fn disconnect_roundtrip() {
        let f = disconnect_request(0x15, Hpai::wildcard());
        let parsed = parse(&f).unwrap();
        assert_eq!(parsed.service, ServiceType::DisconnectRequest);
        assert_eq!(parse_disconnect_request(parsed.body).unwrap(), 0x15);

        let resp = disconnect_response(0x15, 0);
        let rp = parse(&resp).unwrap();
        let cs = parse_channel_status(rp.body).unwrap();
        assert_eq!(cs.channel_id, 0x15);
    }

    #[test]
    fn search_response_parses_device_info() {
        // Control HPAI + one device-info DIB with IA 1.1.0 and name "GW".
        let mut body = Vec::new();
        Hpai::new(ip(192, 168, 1, 20, 3671)).encode(&mut body);
        // DIB: len 54, type 01, medium, status, IA (2), project (2), serial(6),
        // multicast(4), mac(6), name(30).
        let mut dib = vec![54u8, DIB_DEVICE_INFO, 0x02, 0x00, 0x11, 0x00];
        dib.extend_from_slice(&[0, 0]); // project id
        dib.extend_from_slice(&[0u8; 6]); // serial
        dib.extend_from_slice(&[224, 0, 23, 12]); // multicast
        dib.extend_from_slice(&[0u8; 6]); // mac
        let mut name = vec![0u8; 30];
        name[..2].copy_from_slice(b"GW");
        dib.extend_from_slice(&name);
        body.extend_from_slice(&dib);

        let info = parse_search_response(&body).unwrap();
        assert_eq!(info.endpoint, ip(192, 168, 1, 20, 3671));
        assert_eq!(info.individual_address, Some(0x1100));
        assert_eq!(info.name.as_deref(), Some("GW"));
    }
}
