//! KNXnet/IP framing for the tunnelling connection.
//!
//! Every KNXnet/IP frame starts with a 6-byte header:
//!
//! ```text
//!   06 10  <service:2>  <total_len:2>
//! ```
//!
//! - `06` header length, `10` protocol version 1.0.
//! - `service` the 16-bit service-type identifier.
//! - `total_len` header + body length.
//!
//! The services needed to present a tunnelling gateway are:
//! CONNECT_REQUEST/RESPONSE, CONNECTIONSTATE_REQUEST/RESPONSE,
//! TUNNELLING_REQUEST/ACK and DISCONNECT_REQUEST/RESPONSE. Values are from the
//! KNXnet/IP core + tunnelling specs (cross-checked with the Wireshark
//! `packet-knxnetip.c` dissector).

/// KNXnet/IP service-type identifiers.
pub mod service {
    /// CONNECT_REQUEST.
    pub const CONNECT_REQUEST: u16 = 0x0205;
    /// CONNECT_RESPONSE.
    pub const CONNECT_RESPONSE: u16 = 0x0206;
    /// CONNECTIONSTATE_REQUEST.
    pub const CONNECTIONSTATE_REQUEST: u16 = 0x0207;
    /// CONNECTIONSTATE_RESPONSE.
    pub const CONNECTIONSTATE_RESPONSE: u16 = 0x0208;
    /// DISCONNECT_REQUEST.
    pub const DISCONNECT_REQUEST: u16 = 0x0209;
    /// DISCONNECT_RESPONSE.
    pub const DISCONNECT_RESPONSE: u16 = 0x020A;
    /// TUNNELLING_REQUEST.
    pub const TUNNELLING_REQUEST: u16 = 0x0420;
    /// TUNNELLING_ACK.
    pub const TUNNELLING_ACK: u16 = 0x0421;
}

/// The tunnelling connection type identifier used in CONNECT_REQUEST.
pub const TUNNEL_CONNECTION: u8 = 0x04;
/// KNXnet/IP header length constant.
pub const HEADER_LEN: u8 = 0x06;
/// KNXnet/IP protocol version 1.0.
pub const PROTOCOL_V10: u8 = 0x10;
/// KNXnet/IP error status `E_CONNECTION_ID`: the frame named a communication
/// channel that is not open on this gateway.
pub const E_CONNECTION_ID: u8 = 0x21;

/// A minimally-parsed KNXnet/IP frame: service type + body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxnetIpFrame {
    /// The 16-bit service-type identifier.
    pub service: u16,
    /// Body bytes (everything after the 6-byte header).
    pub body: Vec<u8>,
}

/// Errors from decoding a KNXnet/IP frame.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than 6 bytes, or body shorter than the header claims.
    #[error("KNXnet/IP frame truncated: need {need}, have {have}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// Header length / version bytes were not `06 10`.
    #[error("bad KNXnet/IP header: {0:02x?}")]
    BadHeader([u8; 2]),
    /// The header's `total_len` field is smaller than the 6-byte header it
    /// counts, so the body length would be negative.
    #[error("bad KNXnet/IP total length: {total_len} < 6")]
    BadLength {
        /// The bogus total-length field.
        total_len: usize,
    },
}

impl KnxnetIpFrame {
    /// Decode a KNXnet/IP frame.
    pub fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < 6 {
            return Err(FrameError::Truncated {
                need: 6,
                have: buf.len(),
            });
        }
        if buf[0] != HEADER_LEN || buf[1] != PROTOCOL_V10 {
            return Err(FrameError::BadHeader([buf[0], buf[1]]));
        }
        let service = u16::from_be_bytes([buf[2], buf[3]]);
        let total_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        // `total_len` counts the header too, so anything below 6 is malformed.
        // Without this check the `buf[6..total_len]` slice below panics on a
        // frame that claims a shorter-than-header length — a remote panic
        // reachable from any peer that can put a datagram on the socket.
        if total_len < usize::from(HEADER_LEN) {
            return Err(FrameError::BadLength { total_len });
        }
        if buf.len() < total_len {
            return Err(FrameError::Truncated {
                need: total_len,
                have: buf.len(),
            });
        }
        Ok(Self {
            service,
            body: buf[6..total_len].to_vec(),
        })
    }

    /// Encode a service + body into a full KNXnet/IP frame.
    pub fn encode(service: u16, body: &[u8]) -> Vec<u8> {
        let total = 6 + body.len();
        let mut out = Vec::with_capacity(total);
        out.push(HEADER_LEN);
        out.push(PROTOCOL_V10);
        out.extend_from_slice(&service.to_be_bytes());
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
}

/// The connection-header of a TUNNELLING_REQUEST / TUNNELLING_ACK.
///
/// ```text
///   04  <channel>  <seq>  <reserved/status>
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionHeader {
    /// Communication-channel id assigned at CONNECT.
    pub channel: u8,
    /// Sequence counter for this direction.
    pub seq: u8,
    /// Reserved (request) / status (ack).
    pub status: u8,
}

impl ConnectionHeader {
    /// Structure length byte for a tunnelling connection header (4).
    pub const LEN: u8 = 0x04;

    /// Parse a 4-byte connection header from the start of a body.
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() < 4 || body[0] != Self::LEN {
            return None;
        }
        Some(Self {
            channel: body[1],
            seq: body[2],
            status: body[3],
        })
    }

    /// Serialize this 4-byte connection header.
    pub fn to_bytes(self) -> [u8; 4] {
        [Self::LEN, self.channel, self.seq, self.status]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() -> Result<(), FrameError> {
        let body = [0x04, 0x01, 0x00, 0x00, 0xAB, 0xCD];
        let bytes = KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body);
        assert_eq!(&bytes[0..2], &[0x06, 0x10]);
        let f = KnxnetIpFrame::decode(&bytes)?;
        assert_eq!(f.service, service::TUNNELLING_REQUEST);
        assert_eq!(f.body, body);
        Ok(())
    }

    #[test]
    fn test_frame_bad_header() {
        assert!(matches!(
            KnxnetIpFrame::decode(&[0x07, 0x10, 0, 0, 0, 6]),
            Err(FrameError::BadHeader(_))
        ));
    }

    #[test]
    fn test_decode_total_len_below_header_is_rejected() {
        // A 6-byte datagram claiming total_len = 0 used to slice `buf[6..0]`
        // and panic, killing the single-threaded server loop.
        for total_len in 0u16..6 {
            let mut buf = vec![0x06, 0x10, 0x04, 0x20, 0, 0];
            buf[4..6].copy_from_slice(&total_len.to_be_bytes());
            assert_eq!(
                KnxnetIpFrame::decode(&buf),
                Err(FrameError::BadLength {
                    total_len: usize::from(total_len)
                })
            );
        }
    }

    #[test]
    fn test_decode_truncated_body_is_rejected() {
        // `total_len` claims more than the datagram actually carries.
        assert!(matches!(
            KnxnetIpFrame::decode(&[0x06, 0x10, 0x04, 0x20, 0x00, 0x20]),
            Err(FrameError::Truncated { need: 32, have: 6 })
        ));
    }

    #[test]
    fn test_decode_never_panics_on_arbitrary_input() {
        // Sweep short datagrams over every interesting header byte: decoding
        // must always terminate with Ok or Err, never panic.
        for len in 0usize..12 {
            for a in [0x00u8, 0x06, 0xff] {
                for b in [0x00u8, 0x10, 0xff] {
                    for tail in [0x00u8, 0x01, 0xff] {
                        let mut buf = vec![tail; len];
                        if len > 0 {
                            buf[0] = a;
                        }
                        if len > 1 {
                            buf[1] = b;
                        }
                        let _ = KnxnetIpFrame::decode(&buf);
                        let _ = ConnectionHeader::parse(&buf);
                    }
                }
            }
        }
    }

    #[test]
    fn test_connection_header_roundtrip() {
        let h = ConnectionHeader {
            channel: 7,
            seq: 3,
            status: 0,
        };
        assert_eq!(ConnectionHeader::parse(&h.to_bytes()), Some(h));
    }
}
