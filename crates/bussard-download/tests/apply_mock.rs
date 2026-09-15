//! Mock-device integration tests for the write path.
//!
//! A scripted System B device implements the load-state machine and writable
//! `PID_TABLE` arrays **from the KNX spec semantics**, not from bussard's own
//! encoder (de-mirrored): the mock decodes `A_PropertyValue_Write` requests,
//! mutates its own in-memory tables and load states, and answers with an
//! `A_PropertyValue_Response` that echoes the stored value — exactly what a real
//! device does. The client drives it through [`bussard_download::apply_tables`].
//!
//! Cases:
//! - happy path: write → both Loaded → verify byte-equal;
//! - a device that flips to load Error on `LoadCompleted` → clear failure;
//! - a property-write NAK mid-table → abort with the underlying error;
//! - plan-only (a bare `read_tables`) touches no load state (asserted by the
//!   mock recording zero control writes).
//!
//! **The write path is only ever exercised here — never against a live bus.**

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{apply_tables, compute_tables, discover_table_objects};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::{LoadState, WriteError};
use bussard_model::schema::Link;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x33;

// --- KNX identifiers, redeclared here from the spec (de-mirrored) ---
const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const A_DEVICE_DESCRIPTOR_READ_SEL: u16 = 0x300;
const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
const APCI_SELECTOR: u16 = 0x3C0;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE: u8 = 23;

const OT_DEVICE: u16 = 0;
const OT_ADDRESS_TABLE: u16 = 1;
const OT_ASSOCIATION_TABLE: u16 = 2;
const OT_GROUP_OBJECT_TABLE: u16 = 9;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;
const LS_ERROR: u8 = 3;

const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_UNLOAD: u8 = 4;

/// How the device misbehaves, if at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Enter the load Error state when the association table's LoadCompleted is
    /// written (models a device rejecting the written content).
    ErrorOnAssocComplete,
    /// NAK the first `PID_TABLE` element write to the association table (models
    /// a refused property write mid-table).
    NakAssocTableWrite,
}

/// One loadable table object's state.
#[derive(Clone, Default)]
struct TableObject {
    load_state: u8,
    /// Table elements as raw octets (excludes the count word). 2 octets per
    /// address element, 4 per association element.
    elements: Vec<u8>,
    elem_size: usize,
}

/// The mutable mock-device state, shared with the gateway task.
struct DeviceState {
    object_types: Vec<u16>,
    /// Keyed by object index.
    tables: HashMap<u8, TableObject>,
    fault: Fault,
    /// Count of load-control writes seen (plan-only must be zero).
    control_writes: usize,
    /// The group object table element count (nice-to-have; read side counts it).
    go_count: u16,
}

type Shared = Arc<Mutex<DeviceState>>;

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
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

fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

async fn push(gw: &UdpSocket, peer: SocketAddr, gw_seq: &mut u8, cemi: &CemiFrame) {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    gw.send_to(&knxnet::tunneling_request(hdr, cemi), peer)
        .await
        .unwrap();
    *gw_seq = gw_seq.wrapping_add(1);
}

/// Builds a property-value response payload (4-octet header + data), from the
/// spec, not from bussard's encoder.
fn prop_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

/// Decodes a property-value read/write header from a request payload.
fn decode_prop_header(payload: &[u8]) -> Option<(u8, u8, u8, u16)> {
    if payload.len() < 4 {
        return None;
    }
    let object_index = payload[0];
    let pid = payload[1];
    let count = (payload[2] >> 4) & 0x0f;
    let start = (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16;
    Some((object_index, pid, count, start))
}

/// The device's reaction to one management request. Returns `Some((apci, data))`
/// to answer, `None` to NAK (models a refused write), or `Some` with the read.
enum Reaction {
    Answer(u16, Vec<u8>),
    Nak,
}

fn handle_request(state: &Shared, req_apci: u16, data: &[u8]) -> Reaction {
    let mut s = state.lock().unwrap();

    // Device descriptor read (empty payload, strict).
    if req_apci & APCI_SELECTOR == A_DEVICE_DESCRIPTOR_READ_SEL && data.is_empty() {
        return Reaction::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]);
    }

    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        // Object type discovery.
        if pid == PID_OBJECT_TYPE {
            return match s.object_types.get(usize::from(oi)) {
                Some(ot) => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &ot.to_be_bytes()),
                ),
                None => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                ),
            };
        }
        // Load state read: single octet at element 1.
        if pid == PID_LOAD_STATE_CONTROL {
            let st = s
                .tables
                .get(&oi)
                .map(|t| t.load_state)
                .unwrap_or(LS_UNLOADED);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[st]),
            );
        }
        // PID_TABLE read: element 0 = count, elements 1.. = data.
        if pid == PID_TABLE {
            // Group object table: report a fixed count at element 0.
            if s.object_types.get(usize::from(oi)) == Some(&OT_GROUP_OBJECT_TABLE) {
                if start == 0 {
                    let c = s.go_count;
                    return Reaction::Answer(
                        A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, 0, &c.to_be_bytes()),
                    );
                }
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            }
            let Some(t) = s.tables.get(&oi) else {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            };
            let elem_size = t.elem_size.max(1);
            let count = (t.elements.len() / elem_size) as u16;
            if start == 0 {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, 0, &count.to_be_bytes()),
                );
            }
            let idx = usize::from(start);
            if idx == 0 || idx > count as usize {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            }
            let want = (_count as usize).clamp(1, count as usize - idx + 1);
            let byte_start = (idx - 1) * elem_size;
            let byte_end = byte_start + want * elem_size;
            let chunk = t.elements[byte_start..byte_end].to_vec();
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, want as u8, start, &chunk),
            );
        }
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, 0, start, &[]),
        );
    }

    if req_apci == A_PROPERTY_VALUE_WRITE {
        let Some((oi, pid, count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = &data[4..];

        if pid == PID_LOAD_STATE_CONTROL {
            s.control_writes += 1;
            let event = value.first().copied().unwrap_or(0);
            let is_assoc = s.object_types.get(usize::from(oi)) == Some(&OT_ASSOCIATION_TABLE);
            let fault = s.fault;
            let new_state = {
                let t = s.tables.entry(oi).or_default();
                match event {
                    LE_START_LOADING => {
                        t.load_state = LS_LOADING;
                        LS_LOADING
                    }
                    LE_LOAD_COMPLETED => {
                        if is_assoc && fault == Fault::ErrorOnAssocComplete {
                            t.load_state = LS_ERROR;
                            LS_ERROR
                        } else {
                            t.load_state = LS_LOADED;
                            LS_LOADED
                        }
                    }
                    LE_UNLOAD => {
                        t.load_state = LS_UNLOADED;
                        LS_UNLOADED
                    }
                    _ => t.load_state,
                }
            };
            // Echo the resulting load state (what a real device returns).
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[new_state]),
            );
        }

        if pid == PID_TABLE {
            let is_assoc = s.object_types.get(usize::from(oi)) == Some(&OT_ASSOCIATION_TABLE);
            // A persistently-refused write: NAK every association-table element
            // write, so retransmission cannot recover it (style-1 treats a lone
            // NAK as "repeat"; a real refusal NAKs every attempt).
            if is_assoc && s.fault == Fault::NakAssocTableWrite {
                return Reaction::Nak;
            }
            let elem_size = if is_assoc { 4 } else { 2 };
            let t = s.tables.entry(oi).or_default();
            t.elem_size = elem_size;
            if start == 0 {
                // Writing element 0 sets the count: (re)size the element buffer.
                let new_count = if value.len() >= 2 {
                    u16::from_be_bytes([value[0], value[1]]) as usize
                } else {
                    0
                };
                t.elements = vec![0u8; new_count * elem_size];
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, count, start, value),
                );
            }
            // Element write at 1-based `start`.
            let byte_start = (usize::from(start) - 1) * elem_size;
            let byte_end = byte_start + value.len();
            if byte_end > t.elements.len() {
                t.elements.resize(byte_end, 0);
            }
            t.elements[byte_start..byte_end].copy_from_slice(value);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, count, start, value),
            );
        }
        return Reaction::Nak;
    }

    Reaction::Nak
}

async fn run_gateway(gw: UdpSocket, address: IndividualAddress, state: Shared) {
    let mut gw_seq = 0u8;
    let mut dev_seq = 0u8;
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(30), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
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
                gw.send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await
                    .unwrap();
            }
            ServiceType::DisconnectRequest => {
                gw.send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await
                    .unwrap();
                return;
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                gw.send_to(
                    &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                    from,
                )
                .await
                .unwrap();

                let cemi = &tr.cemi;
                let dest = match cemi.destination {
                    Destination::Individual(ia) => ia,
                    Destination::Group(_) => continue,
                };
                if dest != address {
                    continue;
                }
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => dev_seq = 0,
                    TpciKind::NumberedData(client_seq) => {
                        let (req_apci, payload) = match (&cemi.tpci, &cemi.apdu) {
                            (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
                            _ => continue,
                        };
                        match handle_request(&state, req_apci, &payload) {
                            Reaction::Nak => {
                                let nak =
                                    CemiFrame::t_control(tool, address, tpci::t_nak(client_seq));
                                push(&gw, from, &mut gw_seq, &nak).await;
                            }
                            Reaction::Answer(rapci, rdata) => {
                                let ack =
                                    CemiFrame::t_control(tool, address, tpci::t_ack(client_seq));
                                push(&gw, from, &mut gw_seq, &ack).await;
                                let resp = CemiFrame::t_data_connected(
                                    tool,
                                    address,
                                    tpci::ndt(dev_seq),
                                    rapci,
                                    &rdata,
                                );
                                push(&gw, from, &mut gw_seq, &resp).await;
                                dev_seq = (dev_seq + 1) & 0x0f;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

fn fresh_device(fault: Fault) -> Shared {
    let mut tables = HashMap::new();
    // Objects: 0 device, 1 address table, 2 association table, 3 group object.
    tables.insert(
        1u8,
        TableObject {
            load_state: LS_LOADED,
            elements: Vec::new(),
            elem_size: 2,
        },
    );
    tables.insert(
        2u8,
        TableObject {
            load_state: LS_LOADED,
            elements: Vec::new(),
            elem_size: 4,
        },
    );
    Arc::new(Mutex::new(DeviceState {
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        tables,
        fault,
        control_writes: 0,
        go_count: 22,
    }))
}

fn model_links() -> Vec<Link> {
    // object 20 → 1/2/0 (send); object 21 → 1/2/1, 1/3/2 (listen).
    vec![
        Link {
            object: 20,
            name: None,
            send: Some(ga("1/2/0")),
            listen: vec![],
        },
        Link {
            object: 21,
            name: None,
            send: None,
            listen: vec![ga("1/2/1"), ga("1/3/2")],
        },
    ]
}

/// Spins up the gateway and returns a connected [`Transport`] plus the port.
async fn setup(fault: Fault) -> (Transport, Shared, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let state = fresh_device(fault);
    let addr: IndividualAddress = "1.1.4".parse().unwrap();
    let handle = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let bus = Transport::connect(&ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ))
    .await
    .unwrap();
    (bus, state, handle)
}

#[tokio::test]
async fn apply_happy_path_writes_verifies_and_loads() {
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();

    let desired = compute_tables(&model_links());
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let objects = discover_table_objects(&mut l4).await.unwrap();
    let outcome = apply_tables(&mut l4, objects, &desired).await.unwrap();
    let _ = l4.disconnect().await;

    assert!(outcome.ok(), "apply must verify: {outcome:?}");
    assert_eq!(outcome.address_state, LoadState::Loaded);
    assert_eq!(outcome.association_state, LoadState::Loaded);
    assert!(outcome.addresses_match);
    assert!(outcome.associations_match);

    // The device's stored tables match the desired serialisation.
    {
        let s = state.lock().unwrap();
        assert_eq!(s.tables[&1].elements, desired.address_elements());
        assert_eq!(s.tables[&2].elements, desired.association_elements());
    }

    handle.abort();
}

#[tokio::test]
async fn apply_reports_load_error_after_completed() {
    let (mut bus, _state, handle) = setup(Fault::ErrorOnAssocComplete).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();

    let desired = compute_tables(&model_links());
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let objects = discover_table_objects(&mut l4).await.unwrap();
    let err = apply_tables(&mut l4, objects, &desired)
        .await
        .expect_err("a load Error must surface");
    let _ = l4.disconnect().await;

    assert!(
        matches!(err, WriteError::LoadError { .. }),
        "expected LoadError, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn apply_aborts_on_property_write_nak() {
    let (mut bus, _state, handle) = setup(Fault::NakAssocTableWrite).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();

    let desired = compute_tables(&model_links());
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let objects = discover_table_objects(&mut l4).await.unwrap();
    let err = apply_tables(&mut l4, objects, &desired)
        .await
        .expect_err("a NAK mid-table must abort");
    let _ = l4.disconnect().await;

    // A NAK tears the connection down → a Mgmt(Nak/Disconnected) error.
    assert!(
        matches!(err, WriteError::Mgmt(_)),
        "expected a Mgmt error from the NAK, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn plan_only_read_touches_no_load_state() {
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let source: IndividualAddress = "0.0.255".parse().unwrap();

    // A plan is a read-only `read_tables` — it must never write a load control.
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let _ = bussard_mgmt::tables::read_tables(&mut l4).await.unwrap();
    let _ = l4.disconnect().await;

    let s = state.lock().unwrap();
    assert_eq!(
        s.control_writes, 0,
        "a plan-only read must not write any load-state control"
    );
    handle.abort();
}
