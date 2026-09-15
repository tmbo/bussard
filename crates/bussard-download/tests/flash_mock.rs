//! Mock-device integration tests for the application-download (flash) path.
//!
//! Extends the de-mirrored System B mock (see `apply_mock.rs`) with the pieces a
//! first application download needs, all **from KNX spec semantics** rather than
//! bussard's own encoders:
//!
//! - an **application-program interface object** (type 3) carrying the load
//!   machine (`PID_LOAD_STATE_CONTROL`);
//! - **relative segment allocation** via the 10-octet `AdditionalLoadControls`
//!   `LdCtrlRelSegment` (sub-command `0x0B`): the device picks a base address,
//!   reports it through `PID_TABLE_REFERENCE`, and backs it with sparse memory;
//! - **`A_Memory_Write`/`A_Memory_Read`** over that sparse memory, so the
//!   client's read-back verification sees exactly what it wrote.
//!
//! Cases mirror the acceptance ladder for #43:
//! - full happy flash (2 segments: code + params over a base image) → `Loaded`
//!   and every spot check matches;
//! - a device that flips to load `Error` on `LoadCompleted` → surfaced;
//! - a mid-write memory NAK → aborts with the underlying error;
//! - zero-touch: a plan-only pre-flight writes no load control.
//!
//! **The flash path is only ever exercised here — never against a live bus.**

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{FlashStep, flash, plan_flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::LoadState;
use bussard_prod::application::{ApplicationProgram, parse_application_program};
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
const A_MEMORY_READ_SEL: u16 = 0x200;
const A_MEMORY_RESPONSE: u16 = 0x240;
const A_MEMORY_WRITE_SEL: u16 = 0x280;
const A_DEVICE_DESCRIPTOR_READ_SEL: u16 = 0x300;
const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
const A_RESTART_SEL: u16 = 0x380;
const APCI_SELECTOR: u16 = 0x3C0;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;

const OT_DEVICE: u16 = 0;
const OT_ADDRESS_TABLE: u16 = 1;
const OT_ASSOCIATION_TABLE: u16 = 2;
const OT_APPLICATION_PROGRAM: u16 = 3;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;
const LS_ERROR: u8 = 3;

const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;
const SUB_REL_SEGMENT: u8 = 0x0B;

/// How the device misbehaves, if at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Enter load `Error` when the application object's `LoadCompleted` is written.
    ErrorOnLoadCompleted,
    /// NAK every `A_Memory_Write` (models a refused write mid-flash).
    NakMemoryWrite,
}

/// The mutable mock-device state, shared with the gateway task.
struct DeviceState {
    object_types: Vec<u16>,
    /// The application object's load state (object index resolved via type 3).
    app_load_state: u8,
    /// Device-placed segment base address, chosen on the first RelSegment.
    next_segment_base: u16,
    /// The base of the most-recently allocated segment (reported via
    /// `PID_TABLE_REFERENCE`).
    last_segment_base: u16,
    /// Sparse device memory: address → octet.
    memory: HashMap<u16, u8>,
    fault: Fault,
    /// Count of load-control writes seen (plan-only must be zero).
    control_writes: usize,
}

type Shared = Arc<Mutex<DeviceState>>;

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

/// Builds a property-value response payload (4-octet header + data), from spec.
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

/// The application-program object's index (first type-3 object).
fn app_object_index(s: &DeviceState) -> Option<u8> {
    s.object_types
        .iter()
        .position(|&t| t == OT_APPLICATION_PROGRAM)
        .map(|i| i as u8)
}

enum Reaction {
    Answer(u16, Vec<u8>),
    /// No response (a bare T_ACK) — for A_Memory_Write, which is not answered.
    Ack,
    Nak,
}

fn handle_request(state: &Shared, req_apci: u16, data: &[u8]) -> Reaction {
    let mut s = state.lock().unwrap();

    // Device descriptor read (empty payload, strict).
    if req_apci & APCI_SELECTOR == A_DEVICE_DESCRIPTOR_READ_SEL && data.is_empty() {
        return Reaction::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]);
    }

    // Restart: fire-and-forget, just ACK.
    if req_apci & APCI_SELECTOR == A_RESTART_SEL {
        return Reaction::Ack;
    }

    // Memory read: [addr_hi, addr_lo], count in APCI low bits.
    if req_apci & APCI_SELECTOR == A_MEMORY_READ_SEL {
        let count = (req_apci & 0x3f) as usize;
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let a = addr.wrapping_add(i as u16);
            out.push(*s.memory.get(&a).unwrap_or(&0));
        }
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&out);
        return Reaction::Answer(A_MEMORY_RESPONSE | (count as u16 & 0x3f), payload);
    }

    // Memory write: [addr_hi, addr_lo, data…], count in APCI low bits.
    if req_apci & APCI_SELECTOR == A_MEMORY_WRITE_SEL {
        if s.fault == Fault::NakMemoryWrite {
            return Reaction::Nak;
        }
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        for (i, b) in data[2..].iter().enumerate() {
            s.memory.insert(addr.wrapping_add(i as u16), *b);
        }
        // A_Memory_Write is acknowledged (T_ACK) but not answered.
        return Reaction::Ack;
    }

    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
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
        if pid == PID_LOAD_STATE_CONTROL {
            let st = if app_object_index(&s) == Some(oi) {
                s.app_load_state
            } else {
                LS_UNLOADED
            };
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[st]),
            );
        }
        if pid == PID_TABLE_REFERENCE {
            // Report the last-allocated segment base as a big-endian u32.
            let base = s.last_segment_base as u32;
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &base.to_be_bytes()),
            );
        }
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, 0, start, &[]),
        );
    }

    if req_apci == A_PROPERTY_VALUE_WRITE {
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = &data[4..];

        if pid == PID_LOAD_STATE_CONTROL {
            s.control_writes += 1;
            let event = value.first().copied().unwrap_or(0);
            let is_app = app_object_index(&s) == Some(oi);
            let fault = s.fault;

            // A 10-octet AdditionalLoadControls write is a segment allocation.
            if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                // Allocate: pick the next base, advance the cursor by the
                // requested size (data[2..6] big-endian u32).
                let size = if value.len() >= 6 {
                    u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                } else {
                    0
                };
                let base = s.next_segment_base;
                s.last_segment_base = base;
                s.next_segment_base = base.wrapping_add(size.max(1) as u16);
                // Stays in Loading; echo the resulting state.
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[s.app_load_state]),
                );
            }

            let new_state = if is_app {
                match event {
                    LE_START_LOADING => {
                        s.app_load_state = LS_LOADING;
                        LS_LOADING
                    }
                    LE_LOAD_COMPLETED => {
                        if fault == Fault::ErrorOnLoadCompleted {
                            s.app_load_state = LS_ERROR;
                            LS_ERROR
                        } else {
                            s.app_load_state = LS_LOADED;
                            LS_LOADED
                        }
                    }
                    LE_UNLOAD => {
                        s.app_load_state = LS_UNLOADED;
                        LS_UNLOADED
                    }
                    _ => s.app_load_state,
                }
            } else {
                LS_UNLOADED
            };
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[new_state]),
            );
        }

        // Any other property write: echo it (confirm).
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, _count, start, value),
        );
    }

    Reaction::Nak
}

async fn run_gateway(gw: UdpSocket, address: bussard_model::IndividualAddress, state: Shared) {
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
                            Reaction::Ack => {
                                let ack =
                                    CemiFrame::t_control(tool, address, tpci::t_ack(client_seq));
                                push(&gw, from, &mut gw_seq, &ack).await;
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

/// A factory-fresh System B device: objects 0..3, application object Unloaded.
fn fresh_device(fault: Fault) -> Shared {
    Arc::new(Mutex::new(DeviceState {
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_APPLICATION_PROGRAM,
        ],
        app_load_state: LS_UNLOADED,
        next_segment_base: 0x4000,
        last_segment_base: 0,
        memory: HashMap::new(),
        fault,
        control_writes: 0,
    }))
}

/// A minimal single-application System B app: code segment (6 bytes) + parameter
/// segment (1 byte, default 7 over a zero base).
fn fabricated_app() -> ApplicationProgram {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-1_A-1_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
        <RelativeSegment Id="M-1_A-1_RS-2" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
       </Code>
       <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
       <Parameters><Parameter Id="M-1_A-1_P-0" Name="thr" ParameterType="M-1_A-1_PT-0" Value="7"><Memory CodeSegment="M-1_A-1_RS-2" Offset="0" BitOffset="0" /></Parameter></Parameters>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
         <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    parse_application_program("M-1_A-1", xml.as_bytes()).unwrap()
}

async fn setup(fault: Fault) -> (Transport, Shared, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let state = fresh_device(fault);
    let addr: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let handle = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let bus = Transport::connect(&ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ))
    .await
    .unwrap();
    (bus, state, handle)
}

fn no_overrides() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[tokio::test]
async fn flash_happy_path_loads_and_verifies() {
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();

    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let outcome = flash(&mut l4, &plan, |_| {}).await.unwrap();
    let _ = l4.disconnect().await;

    assert!(outcome.ok(), "flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    assert!(outcome.spot_checks_match);

    // The code image landed at the first segment base 0x4000; the parameter
    // image at the second base (0x4000 + 6 = 0x4006).
    let s = state.lock().unwrap();
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&a).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(*s.memory.get(&0x4006).unwrap_or(&0), 7); // parameter default 7

    handle.abort();
}

#[tokio::test]
async fn flash_surfaces_load_error_on_completed() {
    let (mut bus, _state, handle) = setup(Fault::ErrorOnLoadCompleted).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();

    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let err = flash(&mut l4, &plan, |_| {})
        .await
        .expect_err("a load Error on completion must surface");
    let _ = l4.disconnect().await;

    assert!(
        matches!(err, bussard_mgmt::load::WriteError::LoadError { .. }),
        "expected LoadError, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_aborts_on_memory_write_nak() {
    let (mut bus, _state, handle) = setup(Fault::NakMemoryWrite).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();

    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let err = flash(&mut l4, &plan, |_| {})
        .await
        .expect_err("a memory-write NAK mid-flash must abort");
    let _ = l4.disconnect().await;

    assert!(
        matches!(err, bussard_mgmt::load::WriteError::Mgmt(_)),
        "expected a Mgmt error from the NAK, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn plan_only_touches_no_load_state() {
    let (_bus, state, handle) = setup(Fault::None).await;

    // Building a plan is a pure, offline operation: it must never write a load
    // control (or anything) to the device.
    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();
    assert!(!plan.steps.is_empty());
    // The first supported device step is the unload of the application object.
    assert_eq!(plan.steps[0], FlashStep::Unload);

    let s = state.lock().unwrap();
    assert_eq!(
        s.control_writes, 0,
        "a plan-only pre-flight must not write any load-state control"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_reports_progress_for_every_step() {
    let (mut bus, _state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides()).unwrap();
    let total = plan.steps.len();

    let steps_seen = Arc::new(Mutex::new(0usize));
    let seen = Arc::clone(&steps_seen);

    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let outcome = flash(&mut l4, &plan, move |p| {
        if let bussard_download::Progress::Step { .. } = p {
            *seen.lock().unwrap() += 1;
        }
    })
    .await
    .unwrap();
    let _ = l4.disconnect().await;

    assert!(outcome.ok());
    assert_eq!(
        *steps_seen.lock().unwrap(),
        total,
        "one Step event per step"
    );
    handle.abort();
}
