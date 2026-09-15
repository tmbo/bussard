//! Integration tests for the `bussard assign` primitives against an in-process
//! mock KNX device reached through the mock-gateway (tunneling) pattern.
//!
//! The mock here understands the **broadcast** management services assign uses:
//! a device in programming mode answers `A_IndividualAddress_Read` (source = its
//! current address), applies an `A_IndividualAddress_Write` (adopting the new
//! address and leaving programming mode), and afterwards answers a connected
//! `A_DeviceDescriptor_Read` on the NEW address. A serial-number variant answers
//! `A_IndividualAddressSerialNumber_Read` and applies the serial-number write.
//!
//! This exercises the full round trip: discover → write → verify.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_mgmt::apci;
use bussard_mgmt::{
    DeviceConnection, broadcast, read_individual_address_by_serial, write_individual_address,
    write_individual_address_by_serial,
};
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x15;

/// Shared mutable state for one simulated device: its current address (which the
/// address-write mutates) and whether it is in programming mode.
#[derive(Clone)]
struct DeviceState {
    address: IndividualAddress,
    programming: bool,
    mask: u16,
    manufacturer: u16,
    serial: [u8; 6],
    order: Vec<u8>,
}

type Shared = Arc<Mutex<Vec<DeviceState>>>;

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

async fn run_mock(gw: UdpSocket, devices: Shared) {
    let mut gw_seq: u8 = 0;
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
            ServiceType::TunnelingAck => {}
            ServiceType::TunnelingRequest => {
                let tr = match knxnet::parse_tunneling_request(parsed.body) {
                    Ok(tr) => tr,
                    Err(_) => continue,
                };
                let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                gw.send_to(&ack, from).await.unwrap();

                handle_frame(
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

async fn handle_frame(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    devices: &Shared,
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_send_seq: &mut HashMap<u16, u8>,
) {
    let source = cemi.source; // the tool's address — our reply destination

    match &cemi.destination {
        // A broadcast (group 0/0/0) management service.
        Destination::Group(_) => {
            let (apci, data) = match (&cemi.tpci, &cemi.apdu) {
                (Tpci::DataGroup, Apdu::Other { apci, data }) => (*apci, data.clone()),
                _ => return,
            };
            handle_broadcast(gw, peer, devices, apci, &data, source, gw_seq).await;
        }
        // A connected management service to a specific individual address.
        Destination::Individual(dest) => {
            let dest = *dest;
            handle_connected(gw, peer, devices, cemi, dest, source, gw_seq, dev_send_seq).await;
        }
    }
}

async fn handle_broadcast(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    devices: &Shared,
    apci_val: u16,
    data: &[u8],
    source: IndividualAddress,
    gw_seq: &mut u8,
) {
    match apci_val {
        apci::A_INDIVIDUAL_ADDRESS_READ => {
            // Every device in programming mode answers with its own address.
            let responders: Vec<IndividualAddress> = {
                let devs = devices.lock().unwrap();
                devs.iter()
                    .filter(|d| d.programming)
                    .map(|d| d.address)
                    .collect()
            };
            for addr in responders {
                let resp = CemiFrame::t_broadcast(addr, apci::A_INDIVIDUAL_ADDRESS_RESPONSE, &[]);
                push_indication(gw, peer, gw_seq, &resp).await;
            }
        }
        apci::A_INDIVIDUAL_ADDRESS_WRITE => {
            if data.len() >= 2 {
                let new_addr = IndividualAddress::from_raw(u16::from_be_bytes([data[0], data[1]]));
                let mut devs = devices.lock().unwrap();
                for d in devs.iter_mut() {
                    if d.programming {
                        d.address = new_addr;
                        d.programming = false; // adopting the address exits programming mode
                    }
                }
            }
        }
        apci::A_INDIVIDUAL_ADDRESS_SERIAL_READ => {
            if data.len() >= 6 {
                let responder = {
                    let devs = devices.lock().unwrap();
                    devs.iter()
                        .find(|d| d.serial == data[..6])
                        .map(|d| d.address)
                };
                if let Some(addr) = responder {
                    let mut payload = data[..6].to_vec();
                    payload.extend_from_slice(&[0, 0]); // reserved domain-address octets
                    let resp = CemiFrame::t_broadcast(
                        addr,
                        apci::A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE,
                        &payload,
                    );
                    push_indication(gw, peer, gw_seq, &resp).await;
                }
            }
        }
        apci::A_INDIVIDUAL_ADDRESS_SERIAL_WRITE => {
            if data.len() >= 8 {
                let new_addr = IndividualAddress::from_raw(u16::from_be_bytes([data[6], data[7]]));
                let mut devs = devices.lock().unwrap();
                if let Some(d) = devs.iter_mut().find(|d| d.serial == data[..6]) {
                    d.address = new_addr;
                }
            }
        }
        _ => {
            let _ = source;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connected(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    devices: &Shared,
    cemi: &CemiFrame,
    dest: IndividualAddress,
    source: IndividualAddress,
    gw_seq: &mut u8,
    dev_send_seq: &mut HashMap<u16, u8>,
) {
    // Snapshot the device's read-only descriptor data if it exists at this addr.
    let device = {
        let devs = devices.lock().unwrap();
        devs.iter().find(|d| d.address == dest).cloned()
    };
    let Some(device) = device else {
        return; // absent address: no reaction
    };
    let dev_ia = device.address;

    match tpci::classify(cemi.tpci_octet()) {
        TpciKind::Connect => {
            dev_send_seq.insert(dev_ia.raw(), 0);
        }
        TpciKind::Disconnect => {
            dev_send_seq.remove(&dev_ia.raw());
        }
        TpciKind::Ack(_) => {}
        TpciKind::NumberedData(client_seq) => {
            let ack = CemiFrame::t_control(source, dev_ia, tpci::t_ack(client_seq));
            push_indication(gw, peer, gw_seq, &ack).await;

            if let Some((resp_apci, resp_data)) = connected_response(&device, cemi) {
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
        _ => {}
    }
}

fn connected_response(device: &DeviceState, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (apci_val, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    match apci_val {
        apci::A_DEVICE_DESCRIPTOR_READ => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            device.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => device.manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => device.serial.to_vec(),
                apci::PID_ORDER_INFO => device.order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0u8 } else { 1 };
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

async fn open_bus(addr: SocketAddrV4) -> Transport {
    let config = ConnectionConfig::tunnel(addr);
    Transport::connect(&config).await.unwrap()
}

fn device(addr: &str, programming: bool) -> DeviceState {
    DeviceState {
        address: addr.parse().unwrap(),
        programming,
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: b"MDT-JAL0410".to_vec(),
    }
}

#[tokio::test]
async fn discover_write_and_verify_round_trip() {
    let (addr, gw) = bind_mock().await;
    // A factory device in programming mode at 15.15.255.
    let shared: Shared = Arc::new(Mutex::new(vec![device("15.15.255", true)]));
    let gw_task = tokio::spawn(run_mock(gw, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();

    // 1. Discover exactly one device in programming mode.
    let found = broadcast::devices_in_programming_mode(&mut bus, source)
        .await
        .unwrap();
    assert_eq!(found, vec!["15.15.255".parse().unwrap()]);

    // 2. Write the new address.
    let target: IndividualAddress = "1.1.7".parse().unwrap();
    write_individual_address(&mut bus, source, target)
        .await
        .unwrap();

    // 3. Verify: connect to the NEW address and read the descriptor.
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mask = dev.device_descriptor().await.unwrap();
    assert_eq!(mask, 0x07B0);
    let order = dev
        .read_device_property(apci::PID_ORDER_INFO)
        .await
        .unwrap();
    assert_eq!(order, b"MDT-JAL0410");
    dev.disconnect().await.unwrap();

    // The device left programming mode and now lives at the new address.
    {
        let devs = shared.lock().unwrap();
        assert_eq!(devs[0].address, target);
        assert!(!devs[0].programming);
    }

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn zero_devices_in_programming_mode_is_empty() {
    let (addr, gw) = bind_mock().await;
    let shared: Shared = Arc::new(Mutex::new(vec![device("1.1.4", false)]));
    let gw_task = tokio::spawn(run_mock(gw, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let found = broadcast::devices_in_programming_mode(&mut bus, source)
        .await
        .unwrap();
    assert!(found.is_empty());
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn two_devices_in_programming_mode_both_reported() {
    let (addr, gw) = bind_mock().await;
    let shared: Shared = Arc::new(Mutex::new(vec![
        device("15.15.255", true),
        device("15.15.254", true),
    ]));
    let gw_task = tokio::spawn(run_mock(gw, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let found = broadcast::devices_in_programming_mode(&mut bus, source)
        .await
        .unwrap();
    assert_eq!(found.len(), 2, "both responders surface: {found:?}");
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn verify_fails_when_address_not_applied() {
    // The device stays at its old address (models a write that did not land):
    // it is NOT in programming mode and lives at 15.15.255, so a connect to the
    // intended new address 1.1.7 finds nobody.
    let (addr, gw) = bind_mock().await;
    let shared: Shared = Arc::new(Mutex::new(vec![device("15.15.255", false)]));
    let gw_task = tokio::spawn(run_mock(gw, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let target: IndividualAddress = "1.1.7".parse().unwrap();

    let mut dev = DeviceConnection::connect_with(
        &mut bus,
        target,
        source,
        bussard_mgmt::Timeouts::discovery(),
    )
    .await
    .unwrap();
    let err = dev.device_descriptor().await.unwrap_err();
    assert!(
        !err.device_present(),
        "no device at the new address: {err:?}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn serial_number_read_and_write_round_trip() {
    let (addr, gw) = bind_mock().await;
    // A device NOT in programming mode, addressed by its serial number instead.
    let shared: Shared = Arc::new(Mutex::new(vec![device("15.15.255", false)]));
    let gw_task = tokio::spawn(run_mock(gw, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let serial = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    // Read the current address by serial number (no button press).
    let current = read_individual_address_by_serial(&mut bus, source, serial)
        .await
        .unwrap();
    assert_eq!(current, Some("15.15.255".parse().unwrap()));

    // Write a new address by serial number.
    let target: IndividualAddress = "1.1.9".parse().unwrap();
    write_individual_address_by_serial(&mut bus, source, serial, target)
        .await
        .unwrap();

    // Verify on the new address.
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();
    assert_eq!(dev.device_descriptor().await.unwrap(), 0x07B0);
    dev.disconnect().await.unwrap();

    {
        let devs = shared.lock().unwrap();
        assert_eq!(devs[0].address, target);
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn serial_read_unknown_serial_is_none() {
    let (addr, gw) = bind_mock().await;
    let shared: Shared = Arc::new(Mutex::new(vec![device("15.15.255", false)]));
    let gw_task = tokio::spawn(run_mock(gw, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let unknown = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let found = read_individual_address_by_serial(&mut bus, source, unknown)
        .await
        .unwrap();
    assert_eq!(found, None);
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}
