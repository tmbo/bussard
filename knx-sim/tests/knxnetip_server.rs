//! End-to-end test of the KNXnet/IP tunnelling frontend over a real UDP socket.
//!
//! A client socket drives the server exactly as a tool would: CONNECT_REQUEST →
//! CONNECT_RESPONSE, then a TUNNELLING_REQUEST wrapping a cEMI management
//! telegram → TUNNELLING_ACK, and (for a request that produces a device reply)
//! a TUNNELLING_REQUEST back carrying the response cEMI.

use std::net::UdpSocket;
use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::TracingSink;
use knx_sim::device::{Device, LoadState};
use knx_sim::net::KnxnetIpServer;
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::knxnetip::{ConnectionHeader, KnxnetIpFrame, service};
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

// The DA.tp `.knxprod` is a vendor file that is NOT committed; loaded at runtime.
fn build_server() -> Option<KnxnetIpServer> {
    let sink = Arc::new(TracingSink);
    let fixture = knx_sim::testfixtures::da_tp_knxprod()?;
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB")).expect("prod");
    let dev = Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        sink.clone(),
    );
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    // Bind to an ephemeral loopback port for test isolation (nextest runs each
    // test in its own process, but 127.0.0.1:0 keeps it robust regardless).
    Some(KnxnetIpServer::bind("127.0.0.1:0".parse().expect("addr"), bus).expect("bind"))
}

#[test]
fn test_connect_and_authorize_over_udp() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut server) = build_server() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let server_addr = server.local_addr()?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    // Drive the server on a background thread: 1 CONNECT + 2 TUNNELLING = 3
    // inbound datagrams to process.
    let handle = std::thread::spawn(move || {
        server.serve_n(3).expect("serve");
        server
    });

    // 1. CONNECT_REQUEST (a minimal one; the server ignores the body detail).
    let connect = KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0x00; 10]);
    client.send_to(&connect, server_addr)?;
    let mut buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(resp.service, service::CONNECT_RESPONSE);
    let channel = resp.body[0];
    assert_eq!(resp.body[1], 0x00, "connect should succeed");

    // 2. TUNNELLING_REQUEST: T_Connect.
    send_tunnel(&client, server_addr, channel, 0, &tconnect())?;
    expect_ack(&client)?;

    // 3. TUNNELLING_REQUEST: A_Authorize, which yields a response tunnelling req.
    send_tunnel(&client, server_addr, channel, 1, &authorize())?;
    // The server sends an ACK and then a TUNNELLING_REQUEST carrying the
    // A_Authorize_Response. Order: ACK first.
    expect_ack(&client)?;
    let (n, _) = client.recv_from(&mut buf)?;
    let reply = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(reply.service, service::TUNNELLING_REQUEST);
    // The reply body is [connheader(4)][cEMI...]; decode the cEMI and check it is
    // an L_Data.ind from the device.
    let cemi = CemiLData::decode(&reply.body[4..])?;
    assert_eq!(cemi.message_code, MessageCode::LDataInd);
    assert_eq!(cemi.source, IndividualAddress::new(1, 1, 2));

    let _server = handle.join().expect("join");
    Ok(())
}

fn tconnect() -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: IndividualAddress::new(1, 1, 2).raw(),
        tpdu: vec![0x80],
    }
}

fn authorize() -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: IndividualAddress::new(1, 1, 2).raw(),
        // A_Authorize_Request FF FF FF FF (TPCI 0x43 carries APCI hi bits).
        tpdu: vec![0x43, 0xd1, 0x00, 0xff, 0xff, 0xff, 0xff],
    }
}

fn send_tunnel(
    client: &UdpSocket,
    to: std::net::SocketAddr,
    channel: u8,
    seq: u8,
    cemi: &CemiLData,
) -> std::io::Result<()> {
    let mut body = ConnectionHeader {
        channel,
        seq,
        status: 0,
    }
    .to_bytes()
    .to_vec();
    body.extend_from_slice(&cemi.encode());
    let frame = KnxnetIpFrame::encode(service::TUNNELLING_REQUEST, &body);
    client.send_to(&frame, to)?;
    Ok(())
}

fn expect_ack(client: &UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut buf)?;
    let f = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(f.service, service::TUNNELLING_ACK);
    Ok(())
}
