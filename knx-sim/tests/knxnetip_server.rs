//! End-to-end test of the KNXnet/IP tunnelling frontend over a real UDP socket.
//!
//! A client socket drives the server exactly as a tool would: CONNECT_REQUEST →
//! CONNECT_RESPONSE, then a TUNNELLING_REQUEST wrapping a cEMI management
//! telegram → TUNNELLING_ACK, and (for a request that produces a device reply)
//! a TUNNELLING_REQUEST back carrying the response cEMI.

use std::net::UdpSocket;
use std::sync::Arc;

use knx_sim::bus::event::TracingSink;
use knx_sim::bus::{Bus, StimulusJob};
use knx_sim::device::{Device, LoadState, flag};
use knx_sim::net::KnxnetIpServer;
use knx_sim::prod::{LoadableObject, ProductData, read_knxprod_bytes};
use knx_sim::wire::knxnetip::{ConnectionHeader, KnxnetIpFrame, service};
use knx_sim::wire::{Apci, CemiLData, GroupAddress, IndividualAddress, MessageCode, Tpci};

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

/// A synthetic System B `ProductData` with a single application-program object,
/// so an end-to-end test needs no (un-committed) vendor `.knxprod` fixture. The
/// mask is `MV-07B0` (System B), which is all the property-description path
/// depends on.
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

/// Build a sim server around one synthetic System B device at `1.1.2` — no
/// vendor fixture required, so this always runs in CI.
fn build_synthetic_server() -> KnxnetIpServer {
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
    KnxnetIpServer::bind("127.0.0.1:0".parse().expect("addr"), bus).expect("bind")
}

/// An `A_PropertyDescription_Read` for object `obj`, PID `pid`, property index
/// `index` toward `1.1.2` at connected sequence 1 (following the T_Connect at 0).
fn property_description_read(seq: u8, obj: u8, pid: u8, index: u8) -> CemiLData {
    // TPCI: connected-data with `seq`, plus the APCI high bits (0x3D8 → hi 0x03).
    let apci10: u16 = 0x3D8;
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: IndividualAddress::new(1, 1, 2).raw(),
        tpdu: vec![
            0x40 | ((seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
            (apci10 & 0xFF) as u8,
            obj,
            pid,
            index,
        ],
    }
}

#[test]
fn test_property_description_read_over_udp() -> Result<(), Box<dyn std::error::Error>> {
    // End-to-end (issue #72): a tunnel client sends A_PropertyDescription_Read by
    // index on the device object and gets back a well-formed descriptor over the
    // wire — the same path `bussard describe` drives.
    let mut server = build_synthetic_server();
    let server_addr = server.local_addr()?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    // CONNECT + T_Connect + the description read = 3 inbound datagrams.
    let handle = std::thread::spawn(move || {
        server.serve_n(3).expect("serve");
        server
    });

    let connect = KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0x00; 10]);
    client.send_to(&connect, server_addr)?;
    let mut buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    let channel = resp.body[0];

    // T_Connect, then the property-description read at connected seq 0.
    send_tunnel(&client, server_addr, channel, 0, &tconnect())?;
    expect_ack(&client)?;
    send_tunnel(
        &client,
        server_addr,
        channel,
        1,
        &property_description_read(0, 0, 0, 1),
    )?;
    expect_ack(&client)?;

    // The device answers with a TUNNELLING_REQUEST carrying the response cEMI.
    let (n, _) = client.recv_from(&mut buf)?;
    let reply = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(reply.service, service::TUNNELLING_REQUEST);
    let cemi = CemiLData::decode(&reply.body[4..])?;
    let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
    assert_eq!(
        Apci::from_u10(apci10),
        Apci::PropertyDescriptionResponse,
        "device answered with A_PropertyDescription_Response"
    );
    // Response payload: [obj][pid][index][type][max_hi][max_lo][access].
    let payload = &cemi.tpdu[2..];
    assert_eq!(payload[0], 0x00, "device object echoed");
    assert_eq!(payload[2], 0x01, "property index 1 echoed");
    let max = u16::from_be_bytes([payload[4], payload[5]]);
    assert_eq!(max, 1, "one element for the object-type property");
    // A real PID is reported for index 1 (the object object-type PID is 1).
    assert_eq!(payload[1], 0x01, "index 1 is PID_OBJECT_TYPE");

    let _server = handle.join().expect("join");
    Ok(())
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

#[test]
fn test_group_write_is_echoed_to_the_tunnel_client() -> Result<(), Box<dyn std::error::Error>> {
    // A tunnel client (like `bussard viz`) that sends a GroupValueWrite must see
    // it come back over the tunnel as an L_Data.con echo — the whole point of
    // issue #64. A plain Loaded device suffices: the echo does not depend on any
    // device listening to the GA.
    let Some(mut server) = build_server() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let server_addr = server.local_addr()?;
    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    // CONNECT + one TUNNELLING (the group write) = 2 inbound datagrams.
    let handle = std::thread::spawn(move || {
        server.serve_n(2).expect("serve");
        server
    });

    let connect = KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0x00; 10]);
    client.send_to(&connect, server_addr)?;
    let mut buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    let channel = resp.body[0];

    // Send a GroupValueWrite of value 1 to 1/0/5 (0x0805).
    let write = group_write(GroupAddress(0x0805), 0x01);
    send_tunnel(&client, server_addr, channel, 0, &write)?;
    expect_ack(&client)?;

    // The client receives its own write back as a TUNNELLING_REQUEST carrying an
    // L_Data.con of the same GA and value.
    let (n, _) = client.recv_from(&mut buf)?;
    let frame = KnxnetIpFrame::decode(&buf[..n])?;
    assert_eq!(frame.service, service::TUNNELLING_REQUEST);
    let cemi = CemiLData::decode(&frame.body[4..])?;
    assert_eq!(cemi.message_code, MessageCode::LDataCon, "echo is a con");
    assert_eq!(cemi.dest_group(), GroupAddress(0x0805));
    let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
    assert_eq!(Apci::from_u10(apci10), Apci::GroupValueWrite);
    assert_eq!((apci10 & 0x3f) as u8, 0x01);

    let _server = handle.join().expect("join");
    Ok(())
}

#[test]
fn test_device_reply_and_stimulus_reach_the_tunnel_client() -> Result<(), Box<dyn std::error::Error>>
{
    // With a flashed, group-linked device, the tunnel client must observe a
    // device's A_GroupValue_Response (reply to a read) AND a scripted stimulus
    // telegram — all the traffic classes issue #64 asks the viz to render.
    let sink = Arc::new(TracingSink);
    let Some(fixture) = knx_sim::testfixtures::da_tp_knxprod() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB")).expect("prod");
    let addr = IndividualAddress::new(1, 0, 1);
    let dev = Device::from_product(addr, &pd, LoadState::Unloaded, sink.clone());
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    // Flash so the device reconstructs its group routing from its own memory.
    flash_two_object_device(&mut bus, addr)?;
    // Seed the readable object's value so a read has something to answer with.
    let seed = group_write(GroupAddress(0x0802), 0x01);
    bus.deliver_from_tool(&seed);
    // Script a stimulus on the transmitting object (asap 3), due immediately.
    bus.set_stimulus(vec![StimulusJob {
        device: addr,
        object: 3,
        period_ms: 100_000,
        values: vec![vec![0x01]],
        next_due_ms: 0,
        cursor: 0,
    }]);

    let mut server = KnxnetIpServer::bind("127.0.0.1:0".parse().expect("addr"), bus).expect("bind");
    let server_addr = server.local_addr()?;
    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    // Drive the server on a background thread. CONNECT + one TUNNELLING (a read)
    // = 2 datagrams; the read draws a device Response, and the idle stimulus pump
    // (run each loop iteration) delivers the scripted telegram.
    let handle = std::thread::spawn(move || {
        server.serve_n(2).expect("serve");
        // Pump the stimulus once so the due telegram is forwarded to the client.
        server.pump_stimulus();
        server
    });

    let connect = KnxnetIpFrame::encode(service::CONNECT_REQUEST, &[0x00; 10]);
    client.send_to(&connect, server_addr)?;
    let mut buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut buf)?;
    let resp = KnxnetIpFrame::decode(&buf[..n])?;
    let channel = resp.body[0];

    // A_GroupValue_Read on 1/0/2: expect ACK, the write-echo of the read is
    // suppressed, and a device Response comes back over the tunnel.
    let read = group_read(GroupAddress(0x0802));
    send_tunnel(&client, server_addr, channel, 0, &read)?;
    expect_ack(&client)?;

    // Collect the frames the client receives: the device Response and the
    // stimulus write. Both are GroupValueWrite/Response L_Data.ind telegrams.
    let mut saw_response = false;
    let mut saw_stimulus = false;
    for _ in 0..4 {
        let (n, _) = match client.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => break,
        };
        let frame = KnxnetIpFrame::decode(&buf[..n])?;
        if frame.service != service::TUNNELLING_REQUEST {
            continue;
        }
        let cemi = CemiLData::decode(&frame.body[4..])?;
        if !cemi.is_group() {
            continue;
        }
        let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
        match Apci::from_u10(apci10) {
            Apci::GroupValueResponse if cemi.source == addr => saw_response = true,
            Apci::GroupValueWrite if cemi.source == addr => saw_stimulus = true,
            _ => {}
        }
        if saw_response && saw_stimulus {
            break;
        }
    }
    assert!(
        saw_response,
        "the device's read Response reached the client"
    );
    assert!(saw_stimulus, "the scripted stimulus reached the client");

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

/// A group `L_Data.req` write of a single small value (packed into the APCI).
fn group_write(ga: GroupAddress, value: u8) -> CemiLData {
    let apci10 = Apci::GroupValueWrite.to_u10();
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0xe0, // group destination
        source: IndividualAddress::new(0, 0, 15),
        dest: ga.raw(),
        tpdu: vec![
            (apci10 >> 8) as u8 & 0x03,
            ((apci10 & 0xc0) as u8) | (value & 0x3f),
        ],
    }
}

/// A group `L_Data.req` read (no payload).
fn group_read(ga: GroupAddress) -> CemiLData {
    let apci10 = Apci::GroupValueRead.to_u10();
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0xe0,
        source: IndividualAddress::new(0, 0, 15),
        dest: ga.raw(),
        tpdu: vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xff) as u8],
    }
}

/// A bare T_Connect toward `addr`.
fn tconnect_to(addr: IndividualAddress) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: addr.raw(),
        tpdu: vec![0x80],
    }
}

/// Encode a table image the way the download engine does: a big-endian count
/// word followed by the raw element bytes.
fn table_image(count: u16, elements: &[u8]) -> Vec<u8> {
    let mut v = count.to_be_bytes().to_vec();
    v.extend_from_slice(elements);
    v
}

/// Build a connected NDT toward `addr` and advance the shared sequence counter.
fn ndt(addr: IndividualAddress, seq: &mut u8, apci10: u16, payload: &[u8]) -> CemiLData {
    let mut tpdu = vec![
        Tpci::data_connected_byte(*seq) | ((apci10 >> 8) as u8 & 0x03),
        (apci10 & 0xFF) as u8,
    ];
    tpdu.extend_from_slice(payload);
    *seq = (*seq + 1) & 0x0F;
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: addr.raw(),
        tpdu,
    }
}

/// Drive one loadable object through a flash: StartLoading, allocate, write the
/// image at the object's base, LoadCompleted (mirrors `bussard flash`).
fn flash_object(
    bus: &mut Bus,
    addr: IndividualAddress,
    obj: u8,
    seq: &mut u8,
    image: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let pid5 = |event: &[u8]| -> Vec<u8> {
        let mut v = vec![obj, 5, 0x10, 0x01];
        v.extend_from_slice(event);
        v.resize(4 + 10, 0x00);
        v
    };
    let size = image.len() as u32;
    bus.deliver_from_tool(&ndt(addr, seq, 0x3D7, &pid5(&[0x01])));
    let mut alloc = vec![0x03u8, 0x0b];
    alloc.extend_from_slice(&size.to_be_bytes());
    bus.deliver_from_tool(&ndt(addr, seq, 0x3D7, &pid5(&alloc)));
    let base = {
        let r = bus.deliver_from_tool(&ndt(addr, seq, 0x3D5, &[obj, 7, 0x10, 0x01]));
        let tpdu = &r[0].tpdu;
        let n = tpdu.len();
        u16::from_be_bytes([tpdu[n - 2], tpdu[n - 1]])
    };
    let mut off = 0usize;
    while off < image.len() {
        let chunk = &image[off..(off + 12).min(image.len())];
        let addr16 = base.wrapping_add(off as u16);
        let mut payload = addr16.to_be_bytes().to_vec();
        payload.extend_from_slice(chunk);
        bus.deliver_from_tool(&ndt(
            addr,
            seq,
            0x280 | (chunk.len() as u16 & 0x3F),
            &payload,
        ));
        off += chunk.len();
    }
    bus.deliver_from_tool(&ndt(addr, seq, 0x3D7, &pid5(&[0x02])));
    Ok(())
}

/// Authorize + flash `addr` so it holds tables wiring a writable object (asap 1)
/// to 1/0/1 and a readable/transmitting status object (asap 3) to 1/0/2.
fn flash_two_object_device(
    bus: &mut Bus,
    addr: IndividualAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seq = 0u8;
    bus.deliver_from_tool(&tconnect_to(addr));
    bus.deliver_from_tool(&ndt(addr, &mut seq, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]));

    let addr_tbl = table_image(2, &[0x08, 0x01, 0x08, 0x02]);
    let assoc_tbl = table_image(2, &[0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
    let w1 = flag::COMMUNICATION | flag::WRITE;
    let w3 = flag::COMMUNICATION | flag::READ | flag::WRITE | flag::TRANSMIT;
    let go_tbl = table_image(
        3,
        &[
            (w1 >> 8) as u8,
            (w1 & 0xff) as u8,
            0x00,
            0x00,
            (w3 >> 8) as u8,
            (w3 & 0xff) as u8,
        ],
    );

    flash_object(bus, addr, 1, &mut seq, &addr_tbl)?;
    flash_object(bus, addr, 2, &mut seq, &assoc_tbl)?;
    flash_object(bus, addr, 3, &mut seq, &go_tbl)?;
    Ok(())
}
