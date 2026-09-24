//! Offline oracle: the KNXnet/IP Secure frame shapes bussard builds and parses,
//! checked against a real ETS capture of a Jung IP interface with Secure
//! enabled (issue #90 S4.1, #71 Phase B).
//!
//! Ignored by default: the capture and the keyring are private and never
//! committed. Run it with
//!
//! ```text
//! BUSSARD_IPSECURE_PCAP=shared-with-windows/ipsecure-1-1-200.pcapng \
//! BUSSARD_KEYRING=shared-with-windows/<project>.knxkeys BUSSARD_KEYRING_PASSWORD=... \
//! cargo nextest run -p bussard-service --run-ignored only ipsecure_capture
//! ```
//!
//! The wrapped payloads cannot be decrypted (ETS's X25519 private key is
//! unknown), so this checks what can be checked:
//!
//! - the extended search: our SRP is byte-identical to one of ETS's, and the
//!   secure-only interface's answer parses to "tunnelling secure-only";
//! - ETS's plain TCP CONNECT_REQUEST is byte-identical to ours;
//! - SESSION_REQUEST / SESSION_RESPONSE layouts, and (with the keyring) the
//!   SESSION_RESPONSE MAC verifies under the interface's device
//!   authentication code: spec §7.4 end to end against the real device;
//! - SECURE_WRAPPER headers: session id, per-direction sequence from 0 in
//!   steps of 1, message tag 0, ETS's `00 FA` client serial, and the first
//!   wrappers of each session being SESSION_AUTHENTICATE (24 octets) and
//!   SESSION_STATUS (8 octets);
//! - no TUNNELING_ACK and no TIMER_NOTIFY on the TCP connections.
//!
//! Nothing here prints key material: only counts, lengths and pass/fail.

use std::collections::HashMap;

use bussard_secure::ipsecure;
use bussard_transport::knxnet::{self, ServiceType};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One TCP/UDP payload from the capture.
struct Segment {
    tcp: bool,
    src: Endpoint,
    dst: Endpoint,
    seq: u32,
    syn: bool,
    payload: Vec<u8>,
}

/// Reads the Enhanced/Simple Packet Blocks of a little-endian pcapng file
/// with Ethernet link type and returns the IPv4 TCP/UDP payloads.
fn read_pcapng(bytes: &[u8]) -> Result<Vec<Segment>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let u32le = |b: &[u8], o: usize| -> Result<u32, Box<dyn std::error::Error>> {
        let s = b.get(o..o + 4).ok_or("truncated pcapng")?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    while off + 12 <= bytes.len() {
        let btype = u32le(bytes, off)?;
        let blen = u32le(bytes, off + 4)? as usize;
        if blen < 12 || off + blen > bytes.len() {
            break;
        }
        let body = &bytes[off + 8..off + blen - 4];
        if btype == 0x0000_0006 && body.len() >= 20 {
            let cap = u32le(body, 12)? as usize;
            if let Some(frame) = body.get(20..20 + cap)
                && let Some(seg) = parse_ethernet(frame)
            {
                out.push(seg);
            }
        }
        off += blen;
    }
    Ok(out)
}

fn parse_ethernet(frame: &[u8]) -> Option<Segment> {
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype == 0x8100 {
        off += 4;
        ethertype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
    }
    if ethertype != 0x0800 {
        return None;
    }
    let ip = frame.get(off + 2..)?;
    let ihl = usize::from(ip.first()? & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    let proto = *ip.get(9)?;
    let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
    let l4 = ip.get(ihl..total.min(ip.len()))?;
    let port = |o: usize| Some(u16::from_be_bytes([*l4.get(o)?, *l4.get(o + 1)?]));
    match proto {
        6 => {
            let data_off = usize::from(l4.get(12)? >> 4) * 4;
            let flags = *l4.get(13)?;
            Some(Segment {
                tcp: true,
                src: (src, port(0)?),
                dst: (dst, port(2)?),
                seq: u32::from_be_bytes(l4.get(4..8)?.try_into().ok()?),
                syn: flags & 0x02 != 0,
                payload: l4.get(data_off..)?.to_vec(),
            })
        }
        17 => Some(Segment {
            tcp: false,
            src: (src, port(0)?),
            dst: (dst, port(2)?),
            seq: 0,
            syn: false,
            payload: l4.get(8..)?.to_vec(),
        }),
        _ => None,
    }
}

/// An IPv4 endpoint: address and port.
type Endpoint = ([u8; 4], u16);
/// A directional TCP flow: source and destination endpoints.
type Flow = (Endpoint, Endpoint);

/// One KNXnet/IP frame and the flow it travelled on.
struct Frame {
    tcp: bool,
    /// The client-side TCP/UDP port (the one that is not 3671).
    client_port: u16,
    from_client: bool,
    bytes: Vec<u8>,
}

/// Reassembles TCP per direction (dropping retransmitted bytes) and splits
/// every stream and datagram into KNXnet/IP frames.
fn frames(segments: &[Segment]) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut next_seq: HashMap<Flow, u32> = HashMap::new();
    let mut bufs: HashMap<Flow, Vec<u8>> = HashMap::new();
    for seg in segments {
        let from_client = seg.dst.1 == 3671;
        let client_port = if from_client { seg.src.1 } else { seg.dst.1 };
        if !seg.tcp {
            split(&seg.payload, false, client_port, from_client, &mut out);
            continue;
        }
        let key = (seg.src, seg.dst);
        if seg.syn {
            next_seq.insert(key, seg.seq.wrapping_add(1));
            continue;
        }
        if seg.payload.is_empty() {
            continue;
        }
        let expected = *next_seq.entry(key).or_insert(seg.seq);
        let skip = expected.wrapping_sub(seg.seq) as usize;
        if skip >= seg.payload.len() && expected != seg.seq {
            continue; // a pure retransmission
        }
        let fresh = if skip < seg.payload.len() {
            &seg.payload[skip..]
        } else {
            &seg.payload[..]
        };
        next_seq.insert(key, seg.seq.wrapping_add(seg.payload.len() as u32));
        let buf = bufs.entry(key).or_default();
        buf.extend_from_slice(fresh);
        while buf.len() >= 6 {
            let total = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
            if total < 6 || buf.len() < total {
                break;
            }
            let frame: Vec<u8> = buf.drain(..total).collect();
            out.push(Frame {
                tcp: true,
                client_port,
                from_client,
                bytes: frame,
            });
        }
    }
    out
}

fn split(data: &[u8], tcp: bool, client_port: u16, from_client: bool, out: &mut Vec<Frame>) {
    let mut off = 0;
    while off + 6 <= data.len() {
        let total = usize::from(u16::from_be_bytes([data[off + 4], data[off + 5]]));
        if total < 6 || off + total > data.len() {
            return;
        }
        out.push(Frame {
            tcp,
            client_port,
            from_client,
            bytes: data[off..off + total].to_vec(),
        });
        off += total;
    }
}

fn service(frame: &Frame) -> Option<ServiceType> {
    knxnet::parse(&frame.bytes).ok().map(|p| p.service)
}

/// The device authentication codes the keyring holds for interface 1.1.200,
/// if a keyring is configured.
fn device_auth_keys() -> Result<Vec<bussard_secure::Key16>, Box<dyn std::error::Error>> {
    let Ok(path) = std::env::var("BUSSARD_KEYRING") else {
        return Ok(Vec::new());
    };
    let password = std::env::var("BUSSARD_KEYRING_PASSWORD")?;
    let keyring = bussard_project::parse_keyring(&std::fs::read_to_string(path)?, &password)?;
    let host: bussard_model::IndividualAddress = "1.1.200".parse()?;
    let mut keys = Vec::new();
    for iface in keyring.interfaces.iter().filter(|i| i.host == Some(host)) {
        if let Some(k) = iface.device_auth_key() {
            keys.push(k);
            break; // every tunnelling user carries the same code
        }
    }
    if let Some(device) = keyring.devices.iter().find(|d| d.ia == host)
        && let Some(k) = device.device_auth_key()
    {
        keys.push(k);
    }
    Ok(keys)
}

#[test]
#[ignore = "needs the private ETS capture (BUSSARD_IPSECURE_PCAP)"]
fn test_ipsecure_capture_frame_shapes_match_bussard() -> TestResult {
    let Ok(path) = std::env::var("BUSSARD_IPSECURE_PCAP") else {
        eprintln!("BUSSARD_IPSECURE_PCAP not set; skipping");
        return Ok(());
    };
    let frames = frames(&read_pcapng(&std::fs::read(path)?)?);
    assert!(!frames.is_empty(), "no KNXnet/IP frames in the capture");

    // 1. Extended search: our SRP is one ETS sends; the secure-only answer.
    let our_search = knxnet::search_request_extended(knxnet::Hpai::tcp_route_back());
    assert!(
        frames.iter().any(|f| f.bytes == our_search),
        "ETS never sent our exact SEARCH_REQUEST_EXTENDED over TCP"
    );
    let mut secure_only = 0;
    for f in frames
        .iter()
        .filter(|f| service(f) == Some(ServiceType::SearchResponseExtended))
    {
        let parsed = knxnet::parse(&f.bytes)?;
        let desc = knxnet::parse_search_response(parsed.body)?.description;
        assert!(desc.secure_capable(), "every extended answer lists 09 01");
        if desc.tunnelling_secure_only() {
            secure_only += 1;
            assert_eq!(
                desc.secured_service_families,
                Some(vec![(0x03, 0x01), (0x04, 0x01)])
            );
            assert_eq!(desc.individual_address, Some(0x11C8));
        }
    }
    assert!(secure_only > 0, "no secure-only extended answer");
    // A DESCRIPTION_RESPONSE never carries the secure DIBs.
    for f in frames
        .iter()
        .filter(|f| service(f) == Some(ServiceType::DescriptionResponse))
    {
        let parsed = knxnet::parse(&f.bytes)?;
        let desc = knxnet::parse_description_response(parsed.body)?;
        assert!(!desc.tunnelling_secure_only());
    }

    // 2. ETS's plain TCP CONNECT_REQUEST is ours byte for byte.
    let connects: Vec<&Frame> = frames
        .iter()
        .filter(|f| f.tcp && service(f) == Some(ServiceType::ConnectRequest))
        .collect();
    assert!(
        connects
            .iter()
            .all(|f| f.bytes == knxnet::connect_request_tcp()),
        "TCP CONNECT_REQUEST differs from bussard's"
    );

    // 3. Sessions: request, response (MAC), wrappers.
    let auth_keys = device_auth_keys()?;
    let mut sessions = 0;
    let mut macs_verified = 0;
    let mut client_publics: HashMap<u16, [u8; 32]> = HashMap::new();
    let mut session_ids: HashMap<u16, u16> = HashMap::new();
    let mut next_wrapper: HashMap<(u16, bool), u64> = HashMap::new();
    let mut wrappers = 0;
    for f in &frames {
        match service(f) {
            Some(ServiceType::SessionRequest) => {
                assert_eq!(f.bytes.len(), 46, "SESSION_REQUEST is 46 octets");
                let req = ipsecure::parse_session_request(&f.bytes)?;
                assert_eq!(req.hpai, knxnet::Hpai::tcp_route_back().to_bytes());
                client_publics.insert(f.client_port, req.client_public);
            }
            Some(ServiceType::SessionResponse) => {
                sessions += 1;
                assert_eq!(f.bytes.len(), 56, "SESSION_RESPONSE is 56 octets");
                let resp = ipsecure::parse_session_response(&f.bytes)?;
                session_ids.insert(f.client_port, resp.session_id);
                let client = client_publics
                    .get(&f.client_port)
                    .ok_or("SESSION_RESPONSE without a request")?;
                if let Some(first) = auth_keys.first() {
                    // The transport uses the tunnelling interface's
                    // `Authentication` (the first key), so that one must verify.
                    assert!(
                        ipsecure::verify_session_response(&resp, first, client).is_ok(),
                        "SESSION_RESPONSE MAC does not verify under Interface@Authentication"
                    );
                    for other in &auth_keys[1..] {
                        assert!(
                            ipsecure::verify_session_response(&resp, other, client).is_ok(),
                            "SESSION_RESPONSE MAC does not verify under Device@Authentication"
                        );
                    }
                    macs_verified += 1;
                }
            }
            Some(ServiceType::SecureWrapper) => {
                wrappers += 1;
                let hdr = ipsecure::peek_wrapper(&f.bytes)?;
                assert_eq!(Some(&hdr.session_id), session_ids.get(&f.client_port));
                assert_eq!(hdr.tag, 0, "unicast message tag is 0");
                let next = next_wrapper
                    .entry((f.client_port, f.from_client))
                    .or_insert(0);
                assert_eq!(hdr.sequence, *next, "sequence runs 0, 1, 2 ...");
                if *next == 0 {
                    let expected = if f.from_client { 24 } else { 8 };
                    assert_eq!(
                        hdr.payload_len, expected,
                        "first wrapper: AUTHENTICATE / STATUS"
                    );
                }
                *next += 1;
                if f.from_client {
                    assert_eq!(&hdr.serial[..2], &ipsecure::CLIENT_SERIAL_PREFIX);
                }
            }
            Some(ServiceType::TimerNotify) => return Err("unexpected TIMER_NOTIFY".into()),
            Some(ServiceType::TunnelingAck) if f.tcp => {
                return Err("TUNNELING_ACK on a TCP connection".into());
            }
            _ => {}
        }
    }
    assert!(sessions >= 1, "no secure session in the capture");
    eprintln!(
        "capture oracle: {} frames, {sessions} sessions, {wrappers} wrappers, \
         {macs_verified} SESSION_RESPONSE MACs verified with {} keyring code(s)",
        frames.len(),
        auth_keys.len()
    );
    if std::env::var("BUSSARD_KEYRING").is_ok() {
        assert_eq!(macs_verified, sessions);
    }
    Ok(())
}
