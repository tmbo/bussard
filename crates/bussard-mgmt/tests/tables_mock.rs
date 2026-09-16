//! Integration tests for [`bussard_mgmt::tables`]: System B table read-back
//! against an in-process **mock KNX device** behind a mock KNXnet/IP gateway
//! (the same UDP-loopback pattern as `mock_device.rs`).
//!
//! The scripted device serves object-index discovery (`PID_OBJECT_TYPE`),
//! `PID_TABLE` property arrays with real element counts and chunked reads,
//! `PID_TABLE_REFERENCE` and raw memory — enough to exercise the property
//! path, the memory-fallback path, the unsupported-mask refusal and the
//! nothing-readable error.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    self, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE, PID_TABLE, PID_TABLE_REFERENCE, TableSource,
    TablesError,
};
use bussard_mgmt::{Layer4Connection, Timeouts};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

/// The channel id the mock gateway hands out.
const CHANNEL: u8 = 0x16;

/// A scripted System B device: interface objects with property arrays plus a
/// sparse byte-addressable memory.
#[derive(Clone, Default)]
struct TableDevice {
    mask: u16,
    /// `object index → PID_OBJECT_TYPE` (contiguous indexes from 0).
    object_types: Vec<u16>,
    /// `(object index, pid) → property array` (element 0 of the array is the
    /// first *element*, i.e. property start index 1).
    props: HashMap<(u8, u8), Vec<Vec<u8>>>,
    /// Byte-addressable memory for `A_Memory_Read`.
    memory: HashMap<u16, u8>,
    /// If set, cap the number of elements answered per property read to
    /// simulate a device that returns fewer elements than requested.
    max_elems_per_read: Option<usize>,
}

impl TableDevice {
    fn put_memory(&mut self, base: u16, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.memory.insert(base + i as u16, *b);
        }
    }
}

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn assoc_elem(tsap: u16, asap: u16) -> Vec<u8> {
    let mut v = tsap.to_be_bytes().to_vec();
    v.extend_from_slice(&asap.to_be_bytes());
    v
}

// --- Mock gateway plumbing (same shape as tests/mock_device.rs) ---

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

/// Runs the mock gateway + scripted device until the client disconnects.
async fn run_mock(gw: UdpSocket, address: IndividualAddress, device: TableDevice) {
    let mut gw_seq: u8 = 0;
    let mut dev_send_seq: u8 = 0;

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

                let cemi = &tr.cemi;
                let dest = match cemi.destination {
                    Destination::Individual(ia) => ia,
                    Destination::Group(_) => continue,
                };
                if dest != address {
                    continue; // absent address
                }
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => dev_send_seq = 0,
                    TpciKind::NumberedData(client_seq) => {
                        let ack = CemiFrame::t_control(tool, address, tpci::t_ack(client_seq));
                        push_indication(&gw, from, &mut gw_seq, &ack).await;
                        if let Some((rapci, rdata)) = device_response(&device, cemi) {
                            let resp = CemiFrame::t_data_connected(
                                tool,
                                address,
                                tpci::ndt(dev_send_seq),
                                rapci,
                                &rdata,
                            );
                            push_indication(&gw, from, &mut gw_seq, &resp).await;
                            dev_send_seq = (dev_send_seq + 1) & 0x0f;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Builds an `A_PropertyValue_Response` payload with an explicit element count.
fn property_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

/// The scripted device's reaction to one management request.
fn device_response(dev: &TableDevice, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (req_apci, data) = match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
        _ => return None,
    };
    // Strict wire encodings, like a real System B device (verified live against
    // a Jung 23024): the descriptor type / memory octet count live in the low
    // 6 APCI bits, so the request APCI is masked with 0x3C0 and the payload
    // must be exactly the size the standard says.
    const APCI_SELECTOR: u16 = 0x3C0;
    if req_apci & APCI_SELECTOR == apci::A_DEVICE_DESCRIPTOR_READ {
        if !data.is_empty() {
            return None; // over-long descriptor read: a strict device refuses
        }
        return Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        ));
    }
    if req_apci & APCI_SELECTOR == apci::A_MEMORY_READ {
        let count = (req_apci & 0x3F) as u8;
        if data.len() != 2 {
            return None; // strict: the payload is exactly the 2 address octets
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let bytes: Vec<u8> = (0..count)
            .map(|i| dev.memory.get(&(addr + u16::from(i))).copied().unwrap_or(0))
            .collect();
        let mut resp = addr.to_be_bytes().to_vec();
        resp.extend_from_slice(&bytes);
        return Some((apci::A_MEMORY_RESPONSE | u16::from(count), resp));
    }
    match req_apci {
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(&data)?;
            let empty = || property_response(pv.object_index, pv.property_id, 0, pv.start, &[]);

            // Object discovery: PID_OBJECT_TYPE, element 1.
            if pv.property_id == PID_OBJECT_TYPE {
                let resp = match dev.object_types.get(usize::from(pv.object_index)) {
                    Some(ot) => {
                        property_response(pv.object_index, pv.property_id, 1, pv.start, &be16(*ot))
                    }
                    None => empty(),
                };
                return Some((apci::A_PROPERTY_VALUE_RESPONSE, resp));
            }

            // Property arrays: element 0 = count, elements 1.. = data.
            let Some(elems) = dev.props.get(&(pv.object_index, pv.property_id)) else {
                return Some((apci::A_PROPERTY_VALUE_RESPONSE, empty()));
            };
            let resp = if pv.start == 0 {
                property_response(
                    pv.object_index,
                    pv.property_id,
                    1,
                    0,
                    &be16(elems.len() as u16),
                )
            } else {
                let start = usize::from(pv.start);
                if start > elems.len() {
                    empty()
                } else {
                    let mut want = usize::from(pv.count).min(elems.len() - start + 1);
                    if let Some(cap) = dev.max_elems_per_read {
                        want = want.min(cap);
                    }
                    let bytes: Vec<u8> = elems[start - 1..start - 1 + want]
                        .iter()
                        .flatten()
                        .copied()
                        .collect();
                    property_response(
                        pv.object_index,
                        pv.property_id,
                        want as u8,
                        pv.start,
                        &bytes,
                    )
                }
            };
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => None,
    }
}

async fn open_bus(addr: SocketAddrV4) -> Transport {
    let config = ConnectionConfig::tunnel(addr);
    Transport::connect(&config).await.unwrap()
}

/// A System B device whose tables are exposed as PID_TABLE property arrays.
fn property_device() -> TableDevice {
    let mut dev = TableDevice {
        mask: 0x07B0,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ],
        ..TableDevice::default()
    };
    // Address table (object index 1): three GAs. TSAP 1 = 1/2/0.
    dev.props.insert(
        (1, PID_TABLE),
        vec![
            be16(ga("1/2/0").raw()),
            be16(ga("1/2/1").raw()),
            be16(ga("1/3/0").raw()),
        ],
    );
    // Association table (object index 2): (TSAP, ASAP) pairs. The ASAP is the
    // ETS com-object number itself (verified live — see tables.rs docs).
    dev.props.insert(
        (2, PID_TABLE),
        vec![
            assoc_elem(1, 21),
            assoc_elem(2, 22),
            assoc_elem(3, 21),
            assoc_elem(3, 22),
        ],
    );
    // Group object table (object index 3): 22 descriptor words (content unused).
    dev.props
        .insert((3, PID_TABLE), (0..22u16).map(|_| be16(0x079C)).collect());
    dev
}

async fn read_tables_from(
    addr: SocketAddrV4,
    target: IndividualAddress,
) -> Result<tables::DeviceTables, TablesError> {
    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut l4 = Layer4Connection::connect_with(&mut bus, target, source, Timeouts::discovery())
        .await
        .unwrap();
    let result = tables::read_tables(&mut l4).await;
    let _ = l4.disconnect().await;
    result
}

#[tokio::test]
async fn reads_tables_via_property_path() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let gw_task = tokio::spawn(run_mock(gw, target, property_device()));

    let read = read_tables_from(addr, target).await.unwrap();

    assert_eq!(read.mask, 0x07B0);
    assert_eq!(read.addresses, vec![ga("1/2/0"), ga("1/2/1"), ga("1/3/0")]);
    assert_eq!(read.associations, vec![(1, 21), (2, 22), (3, 21), (3, 22)]);
    // object = asap; TSAP is 1-based into the GA table.
    let resolved: Vec<(u16, GroupAddress)> =
        read.resolved.iter().map(|l| (l.object, l.ga)).collect();
    assert_eq!(
        resolved,
        vec![
            (21, ga("1/2/0")),
            (22, ga("1/2/1")),
            (21, ga("1/3/0")),
            (22, ga("1/3/0")),
        ]
    );
    assert!(
        read.sources
            .iter()
            .all(|(_, s)| *s == TableSource::Property),
        "both tables should come from the property path: {:?}",
        read.sources
    );
    assert!(
        read.notes.iter().any(|n| n.contains("22 entries")),
        "the group object table count should be noted: {:?}",
        read.notes
    );

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn chunk_capped_device_still_reads_full_table() {
    // A device that answers at most one element per read must still yield the
    // complete table (the reader advances by what actually arrived).
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let mut dev = property_device();
    dev.max_elems_per_read = Some(1);
    let gw_task = tokio::spawn(run_mock(gw, target, dev));

    let read = read_tables_from(addr, target).await.unwrap();
    assert_eq!(read.addresses.len(), 3);
    assert_eq!(read.associations.len(), 4);

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn non_system_b_mask_is_refused() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.7".parse().unwrap();
    let dev = TableDevice {
        mask: 0x0705,
        object_types: vec![OT_DEVICE],
        ..TableDevice::default()
    };
    let gw_task = tokio::spawn(run_mock(gw, target, dev));

    let err = read_tables_from(addr, target).await.unwrap_err();
    match err {
        TablesError::UnsupportedMask { mask, .. } => assert_eq!(mask, 0x0705),
        other => panic!("expected UnsupportedMask, got {other:?}"),
    }

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn falls_back_to_memory_when_pid_table_is_unreadable() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.9".parse().unwrap();

    // Tables live only in memory; PID_TABLE is not served by this mock.
    let mut dev = TableDevice {
        mask: 0x07B0,
        object_types: vec![OT_DEVICE, OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE],
        ..TableDevice::default()
    };
    // Address table at 0x4000: count 2, then 1/2/0 and 4/0/7.
    dev.props
        .insert((1, PID_TABLE_REFERENCE), vec![be16(0x4000)]);
    let mut addr_blob = be16(2);
    addr_blob.extend_from_slice(&be16(ga("1/2/0").raw()));
    addr_blob.extend_from_slice(&be16(ga("4/0/7").raw()));
    dev.put_memory(0x4000, &addr_blob);
    // Association table at 0x4100 with a 4-octet PID_TABLE_REFERENCE value:
    // count 2, entries (1, 1) and (2, 5).
    dev.props.insert(
        (2, PID_TABLE_REFERENCE),
        vec![0x0000_4100u32.to_be_bytes().to_vec()],
    );
    let mut assoc_blob = be16(2);
    assoc_blob.extend_from_slice(&assoc_elem(1, 1));
    assoc_blob.extend_from_slice(&assoc_elem(2, 5));
    dev.put_memory(0x4100, &assoc_blob);

    let gw_task = tokio::spawn(run_mock(gw, target, dev));

    let read = read_tables_from(addr, target).await.unwrap();
    assert_eq!(read.addresses, vec![ga("1/2/0"), ga("4/0/7")]);
    assert_eq!(read.associations, vec![(1, 1), (2, 5)]);
    let resolved: Vec<(u16, GroupAddress)> =
        read.resolved.iter().map(|l| (l.object, l.ga)).collect();
    assert_eq!(resolved, vec![(1, ga("1/2/0")), (5, ga("4/0/7"))]);
    assert!(
        read.sources.iter().all(|(_, s)| *s == TableSource::Memory),
        "both tables should come from the memory path: {:?}",
        read.sources
    );
    assert!(
        read.notes
            .iter()
            .any(|n| n.contains("no group object table")),
        "the missing group object table should be noted: {:?}",
        read.notes
    );

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn device_with_no_readable_table_is_a_clean_error() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.11".parse().unwrap();
    // Interface objects exist, but neither PID_TABLE nor PID_TABLE_REFERENCE
    // answers.
    let dev = TableDevice {
        mask: 0x07B0,
        object_types: vec![OT_DEVICE, OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE],
        ..TableDevice::default()
    };
    let gw_task = tokio::spawn(run_mock(gw, target, dev));

    let err = read_tables_from(addr, target).await.unwrap_err();
    match err {
        TablesError::TableUnreadable { reason, .. } => {
            assert!(
                reason.contains("neither PID_TABLE nor PID_TABLE_REFERENCE"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected TableUnreadable, got {other:?}"),
    }

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn device_without_address_table_object_is_a_clean_error() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.12".parse().unwrap();
    let dev = TableDevice {
        mask: 0x07B0,
        object_types: vec![OT_DEVICE, OT_APPLICATION_PROGRAM],
        ..TableDevice::default()
    };
    let gw_task = tokio::spawn(run_mock(gw, target, dev));

    let err = read_tables_from(addr, target).await.unwrap_err();
    match err {
        TablesError::TableUnreadable { reason, .. } => {
            assert!(
                reason.contains("no group address table object"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected TableUnreadable, got {other:?}"),
    }

    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}
