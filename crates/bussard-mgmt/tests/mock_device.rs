//! Integration tests: the management layer against an in-process **mock KNX
//! device** reached through the existing mock-gateway (tunneling) pattern.
//!
//! A mock gateway task speaks just enough KNXnet/IP tunneling to relay cEMI
//! frames, and behind it a device simulator implements the KNX device side:
//! accept `T_Connect`, `T_ACK` our numbered data telegrams, and answer
//! `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` and `A_Memory_Read` with
//! response NDTs (which the client must in turn acknowledge). One simulated
//! device NAKs; one goes silent (models an absent address).
//!
//! These exercise the full [`DeviceConnection`] procedure surface plus the
//! sequence state machine end-to-end over UDP localhost.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_mgmt::apci;
use bussard_mgmt::{DeviceConnection, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

/// How a simulated device reacts to a connection.
#[derive(Clone)]
enum Behavior {
    /// Answers management reads normally.
    Responds {
        mask: u16,
        manufacturer: u16,
        serial: Vec<u8>,
        order: Vec<u8>,
        memory: HashMap<u16, Vec<u8>>,
    },
    /// Accepts the connection but `T_NAK`s the first numbered data telegram.
    Nak,
    /// Never reacts at all (an absent address).
    Silent,
    /// Answers management reads normally, but **folds the ACK**: it emits the
    /// response NDT *before* (in fact instead of) a separate `T_ACK`. This models
    /// the real device behaviour that used to desync the connection.
    FoldsAck {
        /// The mask version reported by the device descriptor read.
        mask: u16,
    },
}

/// One simulated device at an individual address.
#[derive(Clone)]
struct MockDevice {
    address: IndividualAddress,
    behavior: Behavior,
}

/// The channel id the mock gateway hands out.
const CHANNEL: u8 = 0x15;

/// Binds a mock gateway socket on an ephemeral localhost port.
async fn bind_mock() -> (SocketAddrV4, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = match sock.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected v4"),
    };
    (addr, sock)
}

fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Runs the mock gateway + device simulator until the client disconnects the
/// KNXnet/IP channel or the socket goes quiet.
///
/// The gateway's own outbound tunneling sequence (for pushing indications back
/// to the client) is tracked in `gw_seq`. Each device tracks its own KNX TPCI
/// receive/send sequence numbers.
async fn run_mock(gw: UdpSocket, devices: Vec<MockDevice>) {
    let mut gw_seq: u8 = 0;
    // Per-device KNX send sequence (for the response NDTs the device emits).
    let mut dev_send_seq: HashMap<u16, u8> = HashMap::new();

    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(5), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let parsed = match knxnet::parse(&buf[..n]) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, &gw),
                );
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::ConnectionstateRequest => {
                let resp = knxnet::connectionstate_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::DisconnectRequest => {
                let resp = knxnet::disconnect_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
                return;
            }
            ServiceType::TunnelingAck => {
                // The client acknowledging one of our pushed indications. Nothing
                // to do — we push the next telegram only after this arrives, so
                // ordering is naturally serialised by the request flow.
            }
            ServiceType::TunnelingRequest => {
                let tr = match knxnet::parse_tunneling_request(parsed.body) {
                    Ok(tr) => tr,
                    Err(_) => continue,
                };
                // ACK the client's tunneling request at the KNXnet layer.
                let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                gw.send_to(&ack, from).await.unwrap();

                handle_device_frame(
                    &gw,
                    from,
                    &devices,
                    &tr.cemi,
                    &mut gw_seq,
                    &mut dev_send_seq,
                )
                .await;
            }
            _ => {}
        }
    }
}

/// Pushes a cEMI frame from the device back to the client as a tunneling
/// indication. Does not wait inline for the client's KNXnet ACK — the single
/// `run_mock` loop is the only reader of the socket and drains those ACKs as
/// they arrive, so waiting here would deadlock against the client's own
/// outgoing telegrams.
async fn push_indication(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    gw_seq: &mut u8,
    cemi: &CemiFrame,
) {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    let frame = knxnet::tunneling_request(hdr, cemi);
    gw.send_to(&frame, peer).await.unwrap();
    *gw_seq = gw_seq.wrapping_add(1);
}

/// The device-side reaction to one management cEMI frame from the client.
async fn handle_device_frame(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    devices: &[MockDevice],
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_send_seq: &mut HashMap<u16, u8>,
) {
    let dest = match cemi.destination {
        Destination::Individual(ia) => ia,
        Destination::Group(_) => return,
    };
    let device = match devices.iter().find(|d| d.address == dest) {
        Some(d) => d,
        None => return, // absent address: no reaction
    };
    let source = cemi.source; // the tool's address — becomes our reply destination
    let dev_ia = device.address;

    match tpci::classify(cemi.tpci_octet()) {
        TpciKind::Connect => {
            // Reset this device's send sequence on a fresh connection.
            dev_send_seq.insert(dev_ia.raw(), 0);
        }
        TpciKind::Disconnect => {
            dev_send_seq.remove(&dev_ia.raw());
        }
        TpciKind::Ack(_) => {}
        TpciKind::NumberedData(client_seq) => {
            match &device.behavior {
                Behavior::Silent => {
                    // Absent/silent: no ACK, no response.
                }
                Behavior::Nak => {
                    // Present but refusing: NAK the numbered data telegram.
                    let nak = CemiFrame::t_control(source, dev_ia, tpci::t_nak(client_seq));
                    push_indication(gw, peer, gw_seq, &nak).await;
                }
                Behavior::FoldsAck { mask } => {
                    // Fold the ACK: send the response NDT *before* / instead of a
                    // separate T_ACK. The client's await_ack must treat the folded
                    // NDT as the acknowledgement, stash it and deliver it.
                    let seq = *dev_send_seq.get(&dev_ia.raw()).unwrap_or(&0);
                    let resp = CemiFrame::t_data_connected(
                        source,
                        dev_ia,
                        tpci::ndt(seq),
                        apci::A_DEVICE_DESCRIPTOR_RESPONSE,
                        &mask.to_be_bytes(),
                    );
                    push_indication(gw, peer, gw_seq, &resp).await;
                    dev_send_seq.insert(dev_ia.raw(), (seq + 1) & 0x0f);
                }
                Behavior::Responds { .. } => {
                    // 1. ACK the client's request NDT.
                    let ack = CemiFrame::t_control(source, dev_ia, tpci::t_ack(client_seq));
                    push_indication(gw, peer, gw_seq, &ack).await;

                    // 2. Build and push the response NDT with our own seq.
                    if let Some((resp_apci, resp_data)) = device_response(&device.behavior, cemi) {
                        let seq = *dev_send_seq.get(&dev_ia.raw()).unwrap_or(&0);
                        let resp = CemiFrame::t_data_connected(
                            source,
                            dev_ia,
                            tpci::ndt(seq),
                            resp_apci,
                            &resp_data,
                        );
                        push_indication(gw, peer, gw_seq, &resp).await;
                        dev_send_seq.insert(dev_ia.raw(), (seq + 1) & 0x0f);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Computes the response APCI + payload for a management request.
fn device_response(behavior: &Behavior, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let Behavior::Responds {
        mask,
        manufacturer,
        serial,
        order,
        memory,
    } = behavior
    else {
        return None;
    };
    let (req_apci, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };

    // Strict, spec-independent framing (implemented from the KNX standard, not
    // mirrored from the client): the descriptor type and memory octet count live
    // in the low 6 APCI bits, so the request selector is masked with 0x3C0 and a
    // strict device refuses the over-long forms.
    const APCI_SELECTOR: u16 = 0x3C0;

    if req_apci & APCI_SELECTOR == apci::A_DEVICE_DESCRIPTOR_READ {
        if !data.is_empty() {
            return None; // over-long descriptor read: a strict device refuses
        }
        return Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            mask.to_be_bytes().to_vec(),
        ));
    }

    if req_apci & APCI_SELECTOR == apci::A_MEMORY_READ {
        let count = (req_apci & 0x3f) as u8;
        if data.len() != 2 {
            return None; // strict: the payload is exactly the 2 address octets
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mem = memory
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| vec![0; count as usize]);
        // Response: count in the APCI low bits, payload = addr + data.
        let (resp_apci, payload) = apci::encode_memory_response(addr, &mem);
        return Some((resp_apci, payload));
    }

    match req_apci {
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => serial.clone(),
                apci::PID_ORDER_INFO => order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0 } else { 1 };
            let mut resp = vec![
                pv.object_index,
                pv.property_id,
                (count << 4) | ((pv.start >> 8) as u8 & 0x0f),
                (pv.start & 0xff) as u8,
            ];
            resp.extend_from_slice(&value);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => None,
    }
}

/// A fully-responsive device fixture.
fn responder(addr: &str, mask: u16, manufacturer: u16) -> MockDevice {
    let mut memory = HashMap::new();
    memory.insert(0x0060u16, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    MockDevice {
        address: addr.parse().unwrap(),
        behavior: Behavior::Responds {
            mask,
            manufacturer,
            serial: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            order: b"MDT-JAL0410".to_vec(),
            memory,
        },
    }
}

async fn open_bus(addr: SocketAddrV4) -> Transport {
    let config = ConnectionConfig::tunnel(addr);
    Transport::connect(&config).await.unwrap()
}

/// The lease path: an L4 session driven over a [`LeaseChannel`] on the bus actor
/// must read the device correctly, *and* a concurrent group subscriber on the
/// same bus must still see the device's response frames (the single-consumer
/// fix — the old `recv` would have stolen them).
#[tokio::test]
async fn device_read_over_a_lease_and_group_subscriber_both_see_frames() {
    use bussard_bus::Bus;
    use bussard_mgmt::LeaseChannel;

    let (addr, gw) = bind_mock().await;
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    // Wait for the actor to connect.
    for _ in 0..300 {
        if handle.status() == bussard_bus::BusState::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // A concurrent group subscriber: it must observe the device's response
    // frames flowing over the shared bus while the L4 session is active.
    let mut sub = handle.subscribe();
    let observer = tokio::spawn(async move {
        // Collect whatever arrives within a short window.
        let mut seen = 0usize;
        while (tokio::time::timeout(Duration::from_secs(2), sub.recv()).await)
            .is_ok_and(|f| f.is_some())
        {
            seen += 1;
            if seen >= 1 {
                break;
            }
        }
        seen
    });

    let lease = handle.lease().await.unwrap();
    let channel = LeaseChannel::new(lease);
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(channel, target, source)
        .await
        .unwrap();

    let mask = dev.device_descriptor().await.unwrap();
    assert_eq!(mask, 0x07B0, "the L4 session over a lease reads correctly");
    dev.disconnect().await.unwrap();

    let seen = observer.await.unwrap();
    assert!(
        seen >= 1,
        "a concurrent group subscriber must see the device's response frames"
    );

    let _ = handle.close().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn device_descriptor_property_and_memory() {
    let (addr, gw) = bind_mock().await;
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let mut bus = open_bus(addr).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    let mask = dev.device_descriptor().await.unwrap();
    assert_eq!(mask, 0x07B0);

    let manu = dev
        .read_device_property(apci::PID_MANUFACTURER_ID)
        .await
        .unwrap();
    assert_eq!(manu, vec![0x00, 0x83]);

    let serial = dev
        .read_device_property(apci::PID_SERIAL_NUMBER)
        .await
        .unwrap();
    assert_eq!(serial, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

    let order = dev
        .read_device_property(apci::PID_ORDER_INFO)
        .await
        .unwrap();
    assert_eq!(order, b"MDT-JAL0410");

    let mem = dev.read_memory(0x0060, 4).await.unwrap();
    assert_eq!(mem, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    dev.disconnect().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn wraparound_across_many_requests() {
    // Issue > 16 property reads on one connection to exercise TPCI sequence
    // wraparound at 15 in both directions.
    let (addr, gw) = bind_mock().await;
    let devices = vec![responder("1.1.4", 0x07B0, 0x0083)];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let mut bus = open_bus(addr).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    for _ in 0..20 {
        let manu = dev
            .read_device_property(apci::PID_MANUFACTURER_ID)
            .await
            .unwrap();
        assert_eq!(manu, vec![0x00, 0x83]);
    }
    dev.disconnect().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn folded_ack_device_still_delivers_response() {
    // A device that folds its ACK (answers with the response NDT before/instead
    // of a separate T_ACK) must still yield the descriptor, and the connection
    // must stay in sync for a following request.
    let (addr, gw) = bind_mock().await;
    let devices = vec![MockDevice {
        address: "1.1.4".parse().unwrap(),
        behavior: Behavior::FoldsAck { mask: 0x07B0 },
    }];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let mut bus = open_bus(addr).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    let mask = dev.device_descriptor().await.unwrap();
    assert_eq!(mask, 0x07B0, "folded-ACK response must still decode");

    // A second request must also succeed: the receive sequence advanced exactly
    // once for the folded response, so nothing is dropped as a duplicate.
    let mask2 = dev.device_descriptor().await.unwrap();
    assert_eq!(
        mask2, 0x07B0,
        "connection stayed in sync after a folded ACK"
    );

    dev.disconnect().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn nak_device_is_present_but_refuses() {
    let (addr, gw) = bind_mock().await;
    let devices = vec![MockDevice {
        address: "1.1.7".parse().unwrap(),
        behavior: Behavior::Nak,
    }];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let mut bus = open_bus(addr).await;
    let target: IndividualAddress = "1.1.7".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    let err = dev.device_descriptor().await.unwrap_err();
    assert!(matches!(err, MgmtError::Nak { .. }), "got {err:?}");
    assert!(err.device_present(), "a NAK means the device is present");
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn silent_device_is_absent() {
    let (addr, gw) = bind_mock().await;
    let devices = vec![MockDevice {
        address: "1.1.9".parse().unwrap(),
        behavior: Behavior::Silent,
    }];
    let gw_task = tokio::spawn(run_mock(gw, devices));

    let mut bus = open_bus(addr).await;
    let target: IndividualAddress = "1.1.9".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    // A silent address costs `2 × ack_timeout` to rule out; the real discovery()
    // budget is 1500ms per attempt (~3s wasted here). Nothing about this test
    // depends on that duration, so use a tight budget that keeps the wall low.
    let fast = Timeouts {
        ack_timeout: Duration::from_millis(50),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(50),
    };
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast)
        .await
        .unwrap();

    let err = dev.device_descriptor().await.unwrap_err();
    assert!(matches!(err, MgmtError::NoResponse { .. }), "got {err:?}");
    assert!(!err.device_present(), "silence means the device is absent");
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}
