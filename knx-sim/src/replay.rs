//! Start the bus from a recorded download: replay the tool's requests of a
//! capture into the devices before the gateway opens.
//!
//! The partial-download oracle (bussard issues #469 and #478) compares what
//! ETS and bussard write to a device that is *already loaded*: ETS's state
//! after a full download with links, then a partial download after a link
//! change. The sim has no memory dump, and a dump would miss the load states,
//! the table references and the properties a download sets. Replaying the
//! tool's side of the capture through the same device code puts every one of
//! them where ETS left them, by construction.
//!
//! A capture is a classic pcap (the sim's own `gateway.pcap`, raw IPv4) or a
//! pcapng (Wireshark), with raw IPv4, Ethernet, Linux cooked or BSD loopback
//! framing. Every KNXnet/IP `TUNNELLING_REQUEST` that carries a cEMI
//! `L_Data.req` is a tool request, whichever port it came from; confirmations
//! and indications (the gateway's answers) are not. A request repeated with
//! the same channel, sequence number and bytes (a tunnelling retransmission)
//! is delivered once. A request with source 0.0.0 goes out under the
//! gateway's tunnel address, as the live gateway does. The devices' answers
//! are dropped.

use std::path::Path;

use crate::bus::Bus;
use crate::wire::knxnetip::{ConnectionHeader, KnxnetIpFrame, service};
use crate::wire::{CemiLData, IndividualAddress, MessageCode};

/// Errors from reading a capture to replay.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The capture file could not be read.
    #[error("reading capture {path}: {source}")]
    Io {
        /// The capture path.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Neither a classic pcap nor a pcapng.
    #[error("not a pcap or pcapng capture (magic {0:08x})")]
    NotACapture(u32),
    /// A record or block ran past the end of the file.
    #[error("capture truncated at offset {0}")]
    Truncated(usize),
}

/// UDP payloads of a capture, in order.
pub fn udp_payloads(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ReplayError> {
    let magic = read_u32(bytes, 0, true).ok_or(ReplayError::Truncated(0))?;
    match magic {
        0xa1b2_c3d4 | 0xa1b2_3c4d => classic(bytes, true),
        0xd4c3_b2a1 | 0x4d3c_b2a1 => classic(bytes, false),
        0x0a0d_0d0a => pcapng(bytes),
        other => Err(ReplayError::NotACapture(other)),
    }
}

/// The tool's requests in a capture: every tunnelled cEMI `L_Data.req`, a
/// retransmission delivered once (see the module doc).
pub fn requests_from_capture(bytes: &[u8]) -> Result<Vec<CemiLData>, ReplayError> {
    let mut out = Vec::new();
    // The last request per channel: (sequence, bytes).
    let mut last: std::collections::HashMap<u8, (u8, Vec<u8>)> = std::collections::HashMap::new();
    for datagram in udp_payloads(bytes)? {
        let Ok(frame) = KnxnetIpFrame::decode(&datagram) else {
            continue;
        };
        if frame.service == service::CONNECT_REQUEST {
            // A new connection starts its sequence again at 0.
            last.clear();
            continue;
        }
        if frame.service != service::TUNNELLING_REQUEST {
            continue;
        }
        let Some(hdr) = ConnectionHeader::parse(&frame.body) else {
            continue;
        };
        let Ok(cemi) = CemiLData::decode(&frame.body[4..]) else {
            continue;
        };
        if cemi.message_code != MessageCode::LDataReq {
            continue;
        }
        let key = (hdr.seq, frame.body[4..].to_vec());
        if last.get(&hdr.channel) == Some(&key) {
            continue;
        }
        last.insert(hdr.channel, key);
        out.push(cemi);
    }
    Ok(out)
}

/// Delivers `requests` to the bus in order, a request with source 0.0.0 under
/// `tunnel_address`. Returns how many were delivered.
pub fn replay(bus: &mut Bus, requests: &[CemiLData], tunnel_address: u16) -> usize {
    for request in requests {
        let mut cemi = request.clone();
        if cemi.source.0 == 0 {
            cemi.source = IndividualAddress(tunnel_address);
        }
        let _ = bus.deliver_from_tool(&cemi);
    }
    requests.len()
}

/// Replays every capture in `paths`, in order. Returns the request count per file.
pub fn replay_files(
    bus: &mut Bus,
    paths: &[impl AsRef<Path>],
    tunnel_address: u16,
) -> Result<Vec<usize>, ReplayError> {
    let mut counts = Vec::new();
    for path in paths {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| ReplayError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let requests = requests_from_capture(&bytes)?;
        counts.push(replay(bus, &requests, tunnel_address));
    }
    Ok(counts)
}

fn read_u32(b: &[u8], at: usize, le: bool) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(s)
    } else {
        u32::from_be_bytes(s)
    })
}

fn read_u16(b: &[u8], at: usize, le: bool) -> Option<u16> {
    let s: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(s)
    } else {
        u16::from_be_bytes(s)
    })
}

fn classic(b: &[u8], le: bool) -> Result<Vec<Vec<u8>>, ReplayError> {
    let link = read_u32(b, 20, le).ok_or(ReplayError::Truncated(20))?;
    let mut out = Vec::new();
    let mut pos = 24;
    while pos < b.len() {
        let incl = read_u32(b, pos + 8, le).ok_or(ReplayError::Truncated(pos))? as usize;
        let data = b
            .get(pos + 16..pos + 16 + incl)
            .ok_or(ReplayError::Truncated(pos))?;
        if let Some(p) = udp_payload(link, data) {
            out.push(p.to_vec());
        }
        pos += 16 + incl;
    }
    Ok(out)
}

fn pcapng(b: &[u8]) -> Result<Vec<Vec<u8>>, ReplayError> {
    let mut out = Vec::new();
    let mut links: Vec<u32> = Vec::new();
    let mut le = true;
    let mut pos = 0;
    while pos + 12 <= b.len() {
        let kind = read_u32(b, pos, true).ok_or(ReplayError::Truncated(pos))?;
        if kind == 0x0a0d_0d0a {
            // Section header: the byte-order magic decides the endianness.
            le = read_u32(b, pos + 8, true) == Some(0x1a2b_3c4d);
            links.clear();
        }
        let len = read_u32(b, pos + 4, le).ok_or(ReplayError::Truncated(pos))? as usize;
        if len < 12 || pos + len > b.len() {
            return Err(ReplayError::Truncated(pos));
        }
        let body = &b[pos + 8..pos + len - 4];
        match read_u32(b, pos, le) {
            // Interface description: the link type of the next interface.
            Some(1) => links.push(u32::from(read_u16(body, 0, le).unwrap_or(0))),
            // Enhanced packet: interface, timestamp, captured length, data.
            Some(6) => {
                let iface = read_u32(body, 0, le).unwrap_or(0) as usize;
                let cap = read_u32(body, 12, le).unwrap_or(0) as usize;
                if let (Some(data), Some(link)) = (body.get(20..20 + cap), links.get(iface))
                    && let Some(p) = udp_payload(*link, data)
                {
                    out.push(p.to_vec());
                }
            }
            // Simple packet: original length, data (interface 0).
            Some(3) => {
                if let (Some(data), Some(link)) = (body.get(4..), links.first())
                    && let Some(p) = udp_payload(*link, data)
                {
                    out.push(p.to_vec());
                }
            }
            _ => {}
        }
        pos += len;
    }
    Ok(out)
}

/// The UDP payload of one link-layer frame, or None (not IPv4 UDP).
fn udp_payload(link: u32, frame: &[u8]) -> Option<&[u8]> {
    let ip = match link {
        // DLT_RAW (101) and LINKTYPE_IPV4 (228): the IP packet itself.
        101 | 228 => frame,
        // Ethernet: IPv4 ethertype only.
        1 => {
            if frame.get(12..14)? != [0x08, 0x00] {
                return None;
            }
            frame.get(14..)?
        }
        // Linux cooked capture: protocol at 14.
        113 => {
            if frame.get(14..16)? != [0x08, 0x00] {
                return None;
            }
            frame.get(16..)?
        }
        // BSD loopback: a 4-octet address family.
        0 => frame.get(4..)?,
        _ => return None,
    };
    if ip.first()? >> 4 != 4 || *ip.get(9)? != 17 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(read_u16(ip, 2, false)?);
    let udp = ip.get(ihl..total.min(ip.len()))?;
    let udp_len = usize::from(read_u16(udp, 4, false)?);
    udp.get(8..udp_len.min(udp.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnelling request datagram carrying `cemi` on `channel`/`seq`.
    fn tunnelling(channel: u8, seq: u8, cemi: &CemiLData) -> Vec<u8> {
        let mut body = ConnectionHeader {
            channel,
            seq,
            status: 0,
        }
        .to_bytes()
        .to_vec();
        body.extend_from_slice(&cemi.encode());
        KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body)
    }

    fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]);
        p.extend_from_slice(&[0x0e, 0x57, 0x0e, 0x57]);
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn classic_pcap(datagrams: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        for v in [0u32, 0, 65535, 101] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for d in datagrams {
            let pkt = ipv4_udp(d);
            for v in [0u32, 0, pkt.len() as u32, pkt.len() as u32] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&pkt);
        }
        out
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut padded = body.to_vec();
        while !padded.len().is_multiple_of(4) {
            padded.push(0);
        }
        let len = (12 + padded.len()) as u32;
        let mut out = kind.to_le_bytes().to_vec();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&padded);
        out.extend_from_slice(&len.to_le_bytes());
        out
    }

    fn pcapng_capture(datagrams: &[Vec<u8>]) -> Vec<u8> {
        let mut shb = 0x1a2b_3c4du32.to_le_bytes().to_vec();
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&u64::MAX.to_le_bytes());
        let mut out = block(0x0a0d_0d0a, &shb);
        let mut idb = 1u16.to_le_bytes().to_vec(); // Ethernet
        idb.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        out.extend(block(1, &idb));
        for d in datagrams {
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x08, 0x00]);
            eth.extend(ipv4_udp(d));
            let mut epb = 0u32.to_le_bytes().to_vec();
            for v in [0u32, 0, eth.len() as u32, eth.len() as u32] {
                epb.extend_from_slice(&v.to_le_bytes());
            }
            epb.extend_from_slice(&eth);
            out.extend(block(6, &epb));
        }
        out
    }

    fn req(tpdu: Vec<u8>, code: MessageCode) -> CemiLData {
        CemiLData {
            message_code: code,
            ctrl1: 0xb0,
            ctrl2: 0x60,
            source: IndividualAddress(0),
            dest: 0x1101,
            tpdu,
        }
    }

    fn sample() -> Vec<Vec<u8>> {
        let connect = KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0; 20]);
        let a = req(vec![0x80], MessageCode::LDataReq); // T_CONNECT
        let b = req(vec![0x43, 0x00], MessageCode::LDataReq); // A_DeviceDescriptor_Read
        let con = req(vec![0x80], MessageCode::LDataCon);
        vec![
            connect.clone(),
            tunnelling(1, 0, &a),
            tunnelling(1, 0, &con), // the gateway's confirmation: not a request
            tunnelling(1, 1, &b),
            tunnelling(1, 1, &b), // a retransmission: delivered once
            connect,
            tunnelling(1, 0, &a), // a new connection: seq 0 again, delivered
        ]
    }

    #[test]
    fn test_requests_from_capture_classic_pcap_dedups_and_skips_answers() -> Result<(), ReplayError>
    {
        let requests = requests_from_capture(&classic_pcap(&sample()))?;
        let tpdus: Vec<Vec<u8>> = requests.iter().map(|r| r.tpdu.clone()).collect();
        assert_eq!(tpdus, vec![vec![0x80], vec![0x43, 0x00], vec![0x80]]);
        Ok(())
    }

    #[test]
    fn test_requests_from_capture_pcapng_ethernet() -> Result<(), ReplayError> {
        let requests = requests_from_capture(&pcapng_capture(&sample()))?;
        assert_eq!(requests.len(), 3);
        Ok(())
    }

    #[test]
    fn test_udp_payloads_rejects_other_files() {
        assert!(matches!(
            udp_payloads(b"not a capture"),
            Err(ReplayError::NotACapture(_))
        ));
    }

    #[test]
    fn test_udp_payloads_truncated_record() {
        let mut cap = classic_pcap(&sample());
        cap.truncate(cap.len() - 3);
        assert!(matches!(udp_payloads(&cap), Err(ReplayError::Truncated(_))));
    }
}
