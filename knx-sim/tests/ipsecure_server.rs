//! The simulator's KNXnet/IP Secure gateway (issue #71 Phase B) driven by a
//! client written here from docs/knx-secure-spec.md §7-§8, over real sockets.
//!
//! Checks the secure-only behaviour bussard issue #182 describes (plain UDP
//! CONNECT refused with 0x22, secured families in the extended search), the
//! handshake (server MAC under the device authentication code, wrapped
//! authenticate/status), wrapped tunnelling to a device without ACKs, and the
//! refusal of a wrong password.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use knx_sim::bus::Bus;
use knx_sim::bus::event::TracingSink;
use knx_sim::config::{IpSecureConfig, IpSecureUserConfig};
use knx_sim::device::{Device, LoadState};
use knx_sim::net::KnxnetIpServer;
use knx_sim::prod::{LoadableObject, ProductData};
use knx_sim::secure::crypto::{cbc_mac, decrypt_data_ctr, encrypt_data_ctr};
use knx_sim::secure::ipsecure::{device_authentication_key, user_password_key};
use knx_sim::wire::knxnetip::{KnxnetIpFrame, service};
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DEVICE_CODE: &str = "sim-device-auth-code";
const USER_PASSWORD: &str = "sim-tunnel-user-2";

/// Starts a secure-only sim with one synthetic device at 1.1.2, serving on a
/// background thread.
fn start() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let sink = Arc::new(TracingSink);
    let pd = synthetic_system_b_product();
    let dev = Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        sink.clone(),
    );
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    let mut server = KnxnetIpServer::bind("127.0.0.1:0".parse()?, bus)?;
    server.enable_secure(&IpSecureConfig {
        individual_address: "1.1.200".into(),
        device_authentication_code: DEVICE_CODE.into(),
        secure_only: true,
        users: vec![IpSecureUserConfig {
            id: 2,
            password: USER_PASSWORD.into(),
            tunnel_address: "1.1.22".into(),
        }],
    })?;
    let addr = server.local_addr()?;
    std::thread::spawn(move || {
        let _ = server.serve();
    });
    Ok(addr)
}

/// A synthetic System B product (as in `knxnetip_server.rs`): no vendor file.
fn synthetic_system_b_product() -> ProductData {
    ProductData {
        application_id: "M-0083_A-0001-01-0000".into(),
        application_number: 1,
        application_version: 1,
        mask_version: "MV-07B0".into(),
        objects: vec![LoadableObject {
            lsm_index: 4,
            name: "application program".into(),
            max_size: None,
            image: Vec::new(),
        }],
        load_procedures: Vec::new(),
        segments: Vec::new(),
        hardware_type_marker: None,
    }
}

fn frame(svc: u16, body: &[u8]) -> Vec<u8> {
    KnxnetIpFrame::encode(svc, body)
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 6];
    stream.read_exact(&mut head)?;
    let total = usize::from(u16::from_be_bytes([head[4], head[5]]));
    let mut rest = vec![0u8; total.saturating_sub(6)];
    stream.read_exact(&mut rest)?;
    let mut out = head.to_vec();
    out.extend_from_slice(&rest);
    Ok(out)
}

const CTR_HANDSHAKE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0];

/// A spec-§8 client session.
struct Client {
    key: [u8; 16],
    session_id: u16,
    tx: u64,
}

impl Client {
    fn seal(&mut self, inner: &[u8]) -> Vec<u8> {
        let total = (38 + inner.len()) as u16;
        let mut head = vec![0x06, 0x10, 0x09, 0x50];
        head.extend_from_slice(&total.to_be_bytes());
        head.extend_from_slice(&self.session_id.to_be_bytes());
        let mut prefix = self.tx.to_be_bytes()[2..].to_vec();
        prefix.extend_from_slice(&[0x00, 0xFA, 9, 9, 9, 9, 0, 0]);
        let mut b0 = [0u8; 16];
        b0[..14].copy_from_slice(&prefix);
        b0[14..].copy_from_slice(&(inner.len() as u16).to_be_bytes());
        let mut c0 = [0u8; 16];
        c0[..14].copy_from_slice(&prefix);
        c0[14] = 0xFF;
        let tag = cbc_mac(&self.key, &head, inner, &b0);
        let (enc, mac) = encrypt_data_ctr(&self.key, &c0, &tag, inner);
        self.tx += 1;
        let mut out = head;
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&mac);
        out
    }

    fn open(&self, wrapper: &[u8]) -> Result<Vec<u8>, String> {
        let prefix = &wrapper[8..22];
        let mut c0 = [0u8; 16];
        c0[..14].copy_from_slice(prefix);
        c0[14] = 0xFF;
        let (inner, tag_rx) = decrypt_data_ctr(
            &self.key,
            &c0,
            &wrapper[wrapper.len() - 16..],
            &wrapper[22..wrapper.len() - 16],
        );
        let mut b0 = [0u8; 16];
        b0[..14].copy_from_slice(prefix);
        b0[14..].copy_from_slice(&(inner.len() as u16).to_be_bytes());
        if cbc_mac(&self.key, &wrapper[..8], &inner, &b0).as_slice() != tag_rx.as_slice() {
            return Err("server wrapper MAC mismatch".into());
        }
        Ok(inner)
    }
}

/// Runs the handshake as user 2 with `password`; returns the stream, the
/// client session and the plain SESSION_STATUS the server answered.
fn handshake(
    addr: SocketAddr,
    password: &str,
) -> Result<(TcpStream, Client, Vec<u8>), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let secret = x25519_dalek::StaticSecret::from([0x21u8; 32]);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let mut body = vec![0x08, 0x02, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&public);
    stream.write_all(&frame(0x0951, &body))?;

    let response = read_frame(&mut stream)?;
    assert_eq!(response.len(), 56, "SESSION_RESPONSE is 56 octets");
    assert_eq!(&response[2..4], &[0x09, 0x52]);
    let session_id = u16::from_be_bytes([response[6], response[7]]);
    let server: [u8; 32] = response[8..40].try_into()?;
    let xor: Vec<u8> = public
        .iter()
        .zip(server.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    // The server proves the device authentication code.
    let device = device_authentication_key(DEVICE_CODE);
    let mut ad = response[..6].to_vec();
    ad.extend_from_slice(&session_id.to_be_bytes());
    ad.extend_from_slice(&xor);
    let (_, mac) = encrypt_data_ctr(
        &device,
        &CTR_HANDSHAKE,
        &cbc_mac(&device, &ad, &[], &[0; 16]),
        &[],
    );
    assert_eq!(&response[40..56], mac.as_slice(), "server MAC");

    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(server));
    let digest = <sha2::Sha256 as sha2::Digest>::digest(shared.as_bytes());
    let mut client = Client {
        key: digest[..16].try_into()?,
        session_id,
        tx: 0,
    };
    let user = user_password_key(password);
    let mut auth = vec![0x06, 0x10, 0x09, 0x53, 0x00, 0x18, 0x00, 0x02];
    let mut auth_ad = auth.clone();
    auth_ad.extend_from_slice(&xor);
    let (_, auth_mac) = encrypt_data_ctr(
        &user,
        &CTR_HANDSHAKE,
        &cbc_mac(&user, &auth_ad, &[], &[0; 16]),
        &[],
    );
    auth.extend_from_slice(&auth_mac);
    let wrapped = client.seal(&auth);
    stream.write_all(&wrapped)?;
    let status = client.open(&read_frame(&mut stream)?)?;
    Ok((stream, client, status))
}

#[test]
fn test_plain_udp_connect_is_refused_and_search_names_secure_tunnelling() -> TestResult {
    let addr = start()?;
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    udp.set_read_timeout(Some(Duration::from_secs(2)))?;
    udp.send_to(&frame(service::CONNECT_REQUEST, &[0; 20]), addr)?;
    let mut buf = [0u8; 512];
    let (n, _) = udp.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(
        resp.body,
        vec![0x00, 0x22],
        "secure-only: E_CONNECTION_TYPE"
    );

    let mut search = vec![0x08, 0x01, 127, 0, 0, 1, 0, 0];
    search.extend_from_slice(&[0x08, 0x04, 0x01, 0x08, 0x02, 0x06, 0x07, 0x00]);
    udp.send_to(&frame(service::SEARCH_REQUEST_EXTENDED, &search), addr)?;
    let (n, _) = udp.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(resp.service, service::SEARCH_RESPONSE_EXTENDED);
    let has = |needle: &[u8]| resp.body.windows(needle.len()).any(|w| w == needle);
    assert!(
        has(&[0x06, 0x06, 0x03, 0x01, 0x04, 0x01]),
        "secured families DIB"
    );
    assert!(has(&[0x09, 0x01]), "security service family");
    assert!(
        has(&[0x11, 0x16, 0x00, 0x05]),
        "tunnel slot 1.1.22 free, usable"
    );
    Ok(())
}

#[test]
fn test_secure_session_tunnels_to_a_device_without_acks() -> TestResult {
    let addr = start()?;
    let (mut stream, mut client, status) = handshake(addr, USER_PASSWORD)?;
    assert_eq!(status, vec![0x06, 0x10, 0x09, 0x54, 0x00, 0x08, 0x00, 0x00]);

    // CONNECT (TCP route-back HPAIs) inside the session.
    let mut connect = vec![0x08, 0x02, 0, 0, 0, 0, 0, 0, 0x08, 0x02, 0, 0, 0, 0, 0, 0];
    connect.extend_from_slice(&[0x04, 0x04, 0x02, 0x00]);
    stream.write_all(&client.seal(&frame(service::CONNECT_REQUEST, &connect)))?;
    let resp = client.open(&read_frame(&mut stream)?)?;
    let resp = KnxnetIpFrame::decode(&resp)?;
    assert_eq!(resp.service, service::CONNECT_RESPONSE);
    assert_eq!(resp.body[1], 0x00, "granted");
    assert_eq!(&resp.body[2..4], &[0x08, 0x02], "TCP route-back data HPAI");
    assert_eq!(&resp.body[12..14], &[0x11, 0x16], "user 2's tunnel address");
    let channel = resp.body[0];

    // T_Connect then A_DeviceDescriptor_Read (connected, seq 0) to 1.1.2.
    let src = IndividualAddress::new(1, 1, 22);
    let t_connect = CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xB0,
        ctrl2: 0x60,
        source: src,
        dest: IndividualAddress::new(1, 1, 2).raw(),
        tpdu: vec![0x80],
    };
    let read = CemiLData {
        tpdu: vec![0x43, 0x00],
        ..t_connect.clone()
    };
    for (seq, cemi) in [(0u8, &t_connect), (1u8, &read)] {
        let mut body = vec![0x04, channel, seq, 0x00];
        body.extend_from_slice(&cemi.encode());
        stream.write_all(&client.seal(&frame(service::TUNNELLING_REQUEST, &body)))?;
    }
    // Every inbound frame is a wrapped TUNNELLING_REQUEST (no TUNNELLING_ACK
    // over TCP); one carries the A_DeviceDescriptor_Response.
    let mut saw_response = false;
    for _ in 0..4 {
        let Ok(raw) = read_frame(&mut stream) else {
            break;
        };
        let inner = KnxnetIpFrame::decode(&client.open(&raw)?)?;
        assert_eq!(
            inner.service,
            service::TUNNELLING_REQUEST,
            "no ACKs over TCP"
        );
        let cemi = CemiLData::decode(&inner.body[4..])?;
        if cemi.tpdu.len() >= 2 && (cemi.tpdu[0] & 0x03) == 0x03 && cemi.tpdu[1] & 0xC0 == 0x40 {
            saw_response = true;
            break;
        }
    }
    assert!(saw_response, "the device answered through the session");

    // Close the session.
    stream.write_all(&client.seal(&frame(0x0954, &[0x05, 0x00])))?;
    Ok(())
}

#[test]
fn test_wrong_password_is_refused_with_auth_failed() -> TestResult {
    let addr = start()?;
    let (mut stream, _client, status) = handshake(addr, "not-the-password")?;
    assert_eq!(status[6], 0x01, "STATUS_AUTHENTICATION_FAILED");
    // The server closes the connection.
    let mut buf = [0u8; 16];
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    assert!(matches!(stream.read(&mut buf), Ok(0) | Err(_)));
    Ok(())
}
