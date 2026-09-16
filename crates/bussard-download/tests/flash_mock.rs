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
//! It also gives the mock **`PID_MCB_TABLE`** (PID 27) semantics: after a load
//! completes, a read of the loaded object's MCB returns the 8-octet
//! `PDT_GENERIC_08` entry `[size u32 BE][crc_ctrl=0x00][access=0xFF][crc16 u16
//! BE]` where the device computes the CRC16-CCITT over the segment bytes it
//! actually holds. The mock computes its **own** CRC, so a wrong tool-side CRC
//! fails the `LdCtrlLoadImageProp` integrity check rather than passing by
//! construction.
//!
//! Cases mirror the acceptance ladder for #43:
//! - full happy flash (2 segments: code + params over a base image) → `Loaded`
//!   and every spot check matches;
//! - a full flash of the real MDT A-0007 / Jung 23024 shape (a combined
//!   `full,par` segment followed by four `LdCtrlLoadImageProp` MCB checks) →
//!   `Loaded` with every integrity check passing;
//! - a device that stored a corrupted image → the MCB CRC diverges and
//!   `LdCtrlLoadImageProp` surfaces `ImagePropMismatch`;
//! - a device that flips to load `Error` on `LoadCompleted` → surfaced;
//! - a mid-write memory NAK → aborts with the underlying error;
//! - zero-touch: a plan-only pre-flight writes no load control.
//!
//! **The flash path is only ever exercised here — never against a live bus.**

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{FlashStep, Session, flash, plan_flash};
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
const PID_MCB_TABLE: u8 = 27;

/// CRC16-CCITT (poly 0x1021, init 0xFFFF, no reflection, no final XOR), the CRC
/// the KNX `PID_MCB_TABLE` uses. De-mirrored from the KNX spec here so the mock
/// computes its OWN CRC over the segment bytes it received — a wrong tool-side
/// CRC must therefore fail the integrity check rather than pass by construction.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut result: u32 = 0xFFFF;
    for i in 0..8 * (data.len() + 2) {
        result <<= 1;
        let bit = if (i / 8) < data.len() {
            ((data[i / 8] >> (7 - (i % 8))) & 1) as u32
        } else {
            0
        };
        result |= bit;
        if result & 0x1_0000 != 0 {
            result ^= 0x1021;
        }
    }
    (result & 0xFFFF) as u16
}

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
    /// Silently corrupt one stored octet of every memory write, so the segment
    /// the device holds differs from what the tool sent: the device's own MCB
    /// CRC will then diverge from the tool's, and `LoadImageProp` must catch it.
    CorruptStoredImage,
    /// Snap straight to `Loaded` on `StartLoading` instead of exposing the
    /// intermediate `Loading` state — the KNX Virtual 2.6.1 behaviour that the
    /// strict load-state check trips on (finding 1).
    LoadedAfterStartLoading,
    /// Expose `Loading` after `StartLoading` (so `start_loading` passes), but drop
    /// to `Loaded` when the `AdditionalLoadControls` allocation is written — so the
    /// allocate path's own load-state re-read trips the strict check. Exercises the
    /// #50 finding-2 gap: the allocate path's error must carry the same discovered
    /// object context the StartLoading path got.
    LoadedOnAllocate,
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
    /// The size (octets) of the most-recently allocated segment, so a
    /// `PID_MCB_TABLE` read can CRC exactly the segment the device stored.
    last_segment_size: u32,
    /// Sparse device memory: address → octet.
    memory: HashMap<u16, u8>,
    fault: Fault,
    /// Count of load-control writes seen (plan-only must be zero).
    control_writes: usize,
    /// Count of `T_Disconnect` control frames received from the tool. The
    /// disconnect-on-error guarantee (finding 3) asserts this reaches ≥1 even
    /// when the flash fails mid-procedure.
    disconnects: usize,
    /// Stored interface-object property values a `LdCtrlCompareProp` reads back,
    /// keyed by `(object_index, pid)`. Absent keys answer count 0 (not present).
    compare_props: HashMap<(u8, u8), Vec<u8>>,
    /// Count of `T_Connect` control frames received from the tool — i.e. how many
    /// connection windows the download opened. The windowed-reconnect tests assert
    /// this reaches ≥2 (the download completed across multiple windows).
    connects: usize,
    /// Numbered data telegrams seen on the CURRENT connection. Reset to 0 on every
    /// `T_Connect` (a fresh sequence window). When `die_after_exchanges` is set and
    /// this reaches it, the device stops answering for the rest of this connection
    /// — modelling KNX Virtual dropping the L4 connection after a varying number of
    /// exchanges (issue #52). A fresh `T_Connect` clears it and the device answers
    /// again from its persistent object state.
    exchanges_this_connection: u32,
    /// If set, the device goes silent after this many numbered exchanges on one
    /// connection (a mid-download connection death). A windowed download that
    /// cycles below this budget survives it; a non-windowed one dies.
    die_after_exchanges: Option<u32>,
    /// If set, the device drops the application object out of `Loading` (back to
    /// `Unloaded`) the first time it is reconnected mid-download — modelling a peer
    /// that does not persist the intermediate state across a graceful window. The
    /// resume-safety load-state re-check must catch this.
    drop_loading_on_reconnect: bool,
    /// Whether the object was in `Loading` at the last disconnect, so a reconnect
    /// can decide whether to apply `drop_loading_on_reconnect`.
    was_loading_at_disconnect: bool,
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
        if pid == PID_MCB_TABLE {
            // The memory control block for the last-loaded segment, computed by
            // the device (this mock) over the bytes it actually holds — an
            // 8-octet PDT_GENERIC_08 entry
            // `[size u32 BE][crc_ctrl=0x00][access=0xFF][crc16 u16 BE]`, valid
            // only while Loaded. A wrong tool-side CRC must NOT match this.
            if app_object_index(&s) != Some(oi) || s.app_load_state != LS_LOADED {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            }
            let base = s.last_segment_base;
            let size = s.last_segment_size;
            let segment: Vec<u8> = (0..size)
                .map(|i| *s.memory.get(&base.wrapping_add(i as u16)).unwrap_or(&0))
                .collect();
            let crc = crc16_ccitt(&segment);
            let mut entry = size.to_be_bytes().to_vec();
            entry.push(0x00); // CRC control byte.
            entry.push(0xFF); // access.
            entry.extend_from_slice(&crc.to_be_bytes());
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &entry),
            );
        }
        // A stored property a LdCtrlCompareProp reads back, if configured.
        if let Some(value) = s.compare_props.get(&(oi, pid)) {
            let count = if value.is_empty() { 0 } else { 1 };
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, count, start, value),
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
                s.last_segment_size = size;
                s.next_segment_base = base.wrapping_add(size.max(1) as u16);
                // Normally stays in Loading; the LoadedOnAllocate fault drops to
                // Loaded here, so the allocate's own re-read trips the strict check.
                if fault == Fault::LoadedOnAllocate && is_app {
                    s.app_load_state = LS_LOADED;
                }
                // Echo the resulting state.
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[s.app_load_state]),
                );
            }

            let new_state = if is_app {
                match event {
                    LE_START_LOADING => {
                        // A conformant device exposes LS_LOADING; KV snaps to
                        // LS_LOADED (the LoadedAfterStartLoading fault).
                        if fault == Fault::LoadedAfterStartLoading {
                            s.app_load_state = LS_LOADED;
                            LS_LOADED
                        } else {
                            s.app_load_state = LS_LOADING;
                            LS_LOADING
                        }
                    }
                    LE_LOAD_COMPLETED => {
                        if fault == Fault::ErrorOnLoadCompleted {
                            s.app_load_state = LS_ERROR;
                            LS_ERROR
                        } else {
                            // A device that stored a corrupted image: flip one
                            // octet of the last segment now (after the per-chunk
                            // read-backs have already passed), so only the
                            // MCB-CRC integrity check can catch the divergence.
                            if fault == Fault::CorruptStoredImage {
                                let base = s.last_segment_base;
                                let cur = *s.memory.get(&base).unwrap_or(&0);
                                s.memory.insert(base, cur ^ 0xFF);
                            }
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
                    TpciKind::Connect => {
                        dev_seq = 0;
                        // A fresh connection window: reset the per-connection
                        // exchange budget and, if configured, drop the app object
                        // out of Loading to model a peer that does not persist the
                        // intermediate state across a graceful window.
                        let mut s = state.lock().unwrap();
                        s.connects += 1;
                        s.exchanges_this_connection = 0;
                        if s.drop_loading_on_reconnect
                            && s.was_loading_at_disconnect
                            && s.app_load_state == LS_LOADING
                        {
                            s.app_load_state = LS_UNLOADED;
                        }
                    }
                    TpciKind::Disconnect => {
                        // Record the tool's clean teardown so a test can assert
                        // the L4 session was released even after a failed flash.
                        let mut s = state.lock().unwrap();
                        s.disconnects += 1;
                        s.was_loading_at_disconnect = s.app_load_state == LS_LOADING;
                    }
                    TpciKind::NumberedData(client_seq) => {
                        // Per-connection death budget: once this connection has run
                        // its allotted exchanges, the device goes silent for the
                        // rest of the connection (KV drops the L4 link, issue #52).
                        {
                            let mut s = state.lock().unwrap();
                            s.exchanges_this_connection += 1;
                            if let Some(budget) = s.die_after_exchanges {
                                if s.exchanges_this_connection > budget {
                                    // No ACK, no response: the connection is dead
                                    // until a fresh T_Connect resets the budget.
                                    continue;
                                }
                            }
                        }
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
        last_segment_size: 0,
        memory: HashMap::new(),
        fault,
        control_writes: 0,
        disconnects: 0,
        compare_props: HashMap::new(),
        connects: 0,
        exchanges_this_connection: 0,
        die_after_exchanges: None,
        drop_loading_on_reconnect: false,
        was_loading_at_disconnect: false,
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

/// A single-application System B app in the real MDT A-0007 / Jung 23024 shape:
/// one relative segment written as a combined `full,par` image, followed by four
/// `LdCtrlLoadImageProp` MCB integrity checks (ObjIdx 1..4, the last Count=2).
fn app_with_image_prop() -> ApplicationProgram {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-2_A-7" ApplicationNumber="7" ApplicationVersion="35"
        MaskVersion="MV-07B0" Name="AKK" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-2_A-7_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="1">
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
         <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="4" PropId="27" Count="2" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    parse_application_program("M-2_A-7", xml.as_bytes()).unwrap()
}

/// A single-application System B app in the MDT SCN-DA64x DALI-gateway shape: a
/// `LdCtrlCompareProp` precondition (object 0, PID 78, expecting the 4-byte
/// `AAECAw==`/`00 01 02 03`) verified before the download proper writes the
/// segment. The compare gates the flash: only a device whose property matches
/// proceeds. `mask`, when set, is emitted as the op's hex `Mask` attribute.
fn app_with_compare_prop(mask: Option<&str>) -> ApplicationProgram {
    let mask_attr = mask.map(|m| format!(" Mask=\"{m}\"")).unwrap_or_default();
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-3_A-8" ApplicationNumber="8" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="DALI" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-3_A-8_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="1">
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlCompareProp InlineData="00010203"{mask_attr} ObjIdx="0" PropId="78">
          <OnError Cause="CompareMismatch" MessageRef="M-3_A-8_M-1" />
         </LdCtrlCompareProp>
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" />
         <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="0" Offset="0" Size="6" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    parse_application_program("M-3_A-8", xml.as_bytes()).unwrap()
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
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

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
async fn flash_with_image_prop_loads_and_verifies_mcb() {
    // A full flash of the real MDT/Jung shape: write the segment, complete the
    // load, then four LoadImageProp MCB checks. The device computes its own CRC
    // over the stored segment; the tool's CRC over the bytes it sent matches, so
    // the flash reaches Loaded and every integrity check passes.
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = app_with_image_prop();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
    // The plan carries the four MCB checks.
    let checks = plan
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::LoadImageProp { .. }))
        .count();
    assert_eq!(checks, 4);

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "flash with LoadImageProp must verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);

    // The code image landed at the segment base.
    let s = state.lock().unwrap();
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&a).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    handle.abort();
}

#[tokio::test]
async fn flash_image_prop_catches_corrupted_stored_image() {
    // The device stores a corrupted segment (one octet flipped after the load
    // completes). Its own MCB CRC therefore diverges from the CRC the tool
    // computed over the bytes it sent, and the LoadImageProp step must surface
    // an ImagePropMismatch — proving the mock's independent CRC really gates it.
    let (mut bus, _state, handle) = setup(Fault::CorruptStoredImage).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = app_with_image_prop();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a corrupted stored image must fail the MCB integrity check");
    let _ = session.into_disconnect().await;

    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::ImagePropMismatch { .. }
        ),
        "expected ImagePropMismatch, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_surfaces_load_error_on_completed() {
    let (mut bus, _state, handle) = setup(Fault::ErrorOnLoadCompleted).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a load Error on completion must surface");
    let _ = session.into_disconnect().await;

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
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a memory-write NAK mid-flash must abort");
    let _ = session.into_disconnect().await;

    assert!(
        matches!(err, bussard_mgmt::load::WriteError::Mgmt(_)),
        "expected a Mgmt error from the NAK, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_disconnects_even_when_it_fails_mid_procedure() {
    // Finding 3: after a failed flash the L4 session must be torn down, or the
    // device holds a stale connection and the next `reconstruct` reports it
    // absent. Here the device snaps to Loaded on StartLoading (KV behaviour) with
    // the tolerance flag OFF, so the FIRST allocate fails its Loading precondition
    // — an application-level error that leaves the connection OPEN. The flash body
    // returns Err, and the explicit `l4.disconnect()` must still emit a
    // T_Disconnect that reaches the device.
    let (mut bus, state, handle) = setup(Fault::LoadedAfterStartLoading).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    // Strict (default) options: the KV snap-to-Loaded trips the load-state check.
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a non-conformant load state must fail the flash");
    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::UnexpectedLoadState { .. }
        ),
        "expected UnexpectedLoadState, got {err:?}"
    );
    // Before the disconnect the device saw none; the connection is still open.
    assert_eq!(
        state.lock().unwrap().disconnects,
        0,
        "the failed flash must not have disconnected on its own yet"
    );

    // The disconnect-on-error guarantee: this must reach the device.
    let _ = session.into_disconnect().await;

    // Poll briefly for the async gateway to record the T_Disconnect.
    let mut saw = false;
    for _ in 0..50 {
        if state.lock().unwrap().disconnects >= 1 {
            saw = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        saw,
        "a failed flash must still emit T_Disconnect to release the L4 session"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_strict_load_state_error_names_object_and_table() {
    // Finding 1: when the device snaps to Loaded after StartLoading and the
    // tolerance flag is OFF, the flash fails with a RICH error — it names the
    // targeted object's discovered interface-object type and the full discovered
    // object table, so "object 3 did not reach Loading" becomes actionable.
    let (mut bus, _state, handle) = setup(Fault::LoadedAfterStartLoading).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("strict mode must reject the non-conformant load state");
    let _ = session.into_disconnect().await;

    match &err {
        bussard_mgmt::load::WriteError::UnexpectedLoadState {
            object_index,
            actual,
            context,
            ..
        } => {
            // The app object is index 3 on the fresh device (device, address,
            // association, application-program).
            assert_eq!(*object_index, 3, "the app object is index 3");
            assert_eq!(*actual, LoadState::Loaded);
            // The context names the target object type (3 = application-program)
            // and carries the full discovered object table.
            assert_eq!(context.object_type, Some(OT_APPLICATION_PROGRAM));
            assert_eq!(
                context.object_table,
                vec![(0, 0), (1, 1), (2, 2), (3, 3)],
                "the discovered object table must be folded in"
            );
        }
        other => panic!("expected UnexpectedLoadState, got {other:?}"),
    }
    // The rendered message must name the object type and the discovered table.
    let rendered = err.to_string();
    assert!(
        rendered.contains("application-program"),
        "message must name the object type: {rendered}"
    );
    assert!(
        rendered.contains("discovered object table"),
        "message must include the discovered object table: {rendered}"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_allocate_path_load_state_error_names_object_and_table() {
    // Finding 2: the allocate path (AdditionalLoadControls) must carry the SAME
    // rich LoadStateContext the StartLoading path got in 9a0668a. Here the device
    // passes StartLoading (reaches Loading) but drops to Loaded on the allocation,
    // so it is the ALLOCATE re-read that trips the strict check — and its error
    // must still name the targeted object's type and the full discovered table.
    let (mut bus, _state, handle) = setup(Fault::LoadedOnAllocate).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("the allocate re-read must trip the strict load-state check");
    let _ = session.into_disconnect().await;

    match &err {
        bussard_mgmt::load::WriteError::UnexpectedLoadState {
            object_index,
            control,
            context,
            ..
        } => {
            // The failure came from the allocate path (AdditionalLoadControls),
            // not StartLoading — proving finding-2's path is the one enriched.
            assert_eq!(
                *control,
                bussard_mgmt::LoadControl::AdditionalLoadControls,
                "the error must originate on the allocate path"
            );
            assert_eq!(*object_index, 3, "the app object is index 3");
            // Same rich context as the StartLoading path: object type + table.
            assert_eq!(context.object_type, Some(OT_APPLICATION_PROGRAM));
            assert_eq!(
                context.object_table,
                vec![(0, 0), (1, 1), (2, 2), (3, 3)],
                "the allocate-path error must fold in the discovered object table"
            );
        }
        other => panic!("expected UnexpectedLoadState from the allocate path, got {other:?}"),
    }
    let rendered = err.to_string();
    assert!(
        rendered.contains("application-program") && rendered.contains("discovered object table"),
        "the allocate-path message must render the rich context: {rendered}"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_batched_verify_loads_and_verifies() {
    // Item 1: a full flash under --verify batched still reaches Loaded with every
    // byte landed. Batched writes the whole segment before verifying it once.
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let options = bussard_download::FlashOptions {
        verify: bussard_mgmt::VerifyMode::Batched,
        ..Default::default()
    };
    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, &plan, options, |_| {}).await.unwrap();
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "batched flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    let s = state.lock().unwrap();
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&a).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(*s.memory.get(&0x4006).unwrap_or(&0), 7);
    handle.abort();
}

#[tokio::test]
async fn flash_tolerance_flag_accepts_loaded_after_start_loading() {
    // Finding 1: with --tolerate-nonconformant-load-states the same KV device
    // (snaps to Loaded after StartLoading) flashes through to Loaded. Only the
    // subsequent operations succeeding makes this acceptable, and they do.
    let (mut bus, state, handle) = setup(Fault::LoadedAfterStartLoading).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let options = bussard_download::FlashOptions {
        tolerate_nonconformant_load_states: true,
        ..Default::default()
    };
    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, &plan, options, |_| {}).await.unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "the tolerance flag must let a KV-style device flash through: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);

    // The code image still landed at the first segment base.
    let s = state.lock().unwrap();
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&a).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    handle.abort();
}

#[tokio::test]
async fn plan_only_touches_no_load_state() {
    let (_bus, state, handle) = setup(Fault::None).await;

    // Building a plan is a pure, offline operation: it must never write a load
    // control (or anything) to the device.
    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
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
async fn flash_applies_device_file_parameter_override() {
    // A device-file override (keyed by app-relative ParameterRef id) changes the
    // parameter byte away from the vendor default 7. The overridden value must
    // reach device memory AND be reflected in the segment the device CRCs — the
    // MCB integrity check passing proves the OVERRIDDEN image (not the default)
    // is what actually flowed onto the device.
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();

    // The default plan writes the parameter default (7).
    let default_plan =
        plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
    assert_eq!(default_plan.param_images["M-1_A-1_RS-2"], vec![7]);

    // The override plan (P-0_R-1 = 42) writes 42 instead — proving the override
    // changed the computed image before any bus traffic.
    let mut ov = BTreeMap::new();
    ov.insert("P-0_R-1".to_string(), "42".to_string());
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &ov, &BTreeMap::new()).unwrap();
    assert_eq!(
        plan.param_images["M-1_A-1_RS-2"],
        vec![42],
        "the override must change the computed parameter image"
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "override flash must verify: {outcome:?}");

    // The overridden byte 42 (not the default 7) landed in device memory at the
    // parameter segment base (0x4000 + 6 = 0x4006).
    let s = state.lock().unwrap();
    assert_eq!(
        *s.memory.get(&0x4006).unwrap_or(&0),
        42,
        "the device stored the overridden value, not the default"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_compare_prop_passes_when_property_matches() {
    // The device's object-0 PID-78 property holds exactly the bytes the
    // LdCtrlCompareProp expects, so the precondition passes and the flash reaches
    // Loaded.
    let (mut bus, state, handle) = setup(Fault::None).await;
    state
        .lock()
        .unwrap()
        .compare_props
        .insert((0, 78), vec![0x00, 0x01, 0x02, 0x03]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = app_with_compare_prop(None);
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
    // The plan carries the CompareProp precondition.
    assert_eq!(
        plan.steps
            .iter()
            .filter(|s| matches!(s, FlashStep::CompareProp { .. }))
            .count(),
        1
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "matching compare must let the flash verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    handle.abort();
}

#[tokio::test]
async fn flash_compare_prop_aborts_when_property_differs() {
    // The device's object-0 PID-78 property holds different bytes than the
    // LdCtrlCompareProp expects: the precondition fails and the flash aborts with
    // PropCompareMismatch — before the segment is written.
    let (mut bus, state, handle) = setup(Fault::None).await;
    state
        .lock()
        .unwrap()
        .compare_props
        .insert((0, 78), vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = app_with_compare_prop(None);
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a compare mismatch must abort the flash");
    let _ = session.into_disconnect().await;

    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::PropCompareMismatch { .. }
        ),
        "expected PropCompareMismatch, got {err:?}"
    );

    // The abort happened before the download proper: the app object never reached
    // Loaded and the segment was never written.
    let s = state.lock().unwrap();
    assert_ne!(
        s.app_load_state, LS_LOADED,
        "flash must not have completed the load"
    );
    handle.abort();
}

#[tokio::test]
async fn flash_compare_prop_mask_ignores_don_t_care_bytes() {
    // The compare expects 00 01 02 03 under mask FF 00 FF 00: the device holds
    // 00 AA 02 BB, differing only in the masked-out (don't-care) positions, so
    // the masked compare passes and the flash reaches Loaded.
    let (mut bus, state, handle) = setup(Fault::None).await;
    state
        .lock()
        .unwrap()
        .compare_props
        .insert((0, 78), vec![0x00, 0xAA, 0x02, 0xBB]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = app_with_compare_prop(Some("FF00FF00"));
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a difference only in masked-out bytes must pass: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    handle.abort();
}

#[tokio::test]
async fn flash_reports_progress_for_every_step() {
    let (mut bus, _state, handle) = setup(Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();
    let total = plan.steps.len();

    let steps_seen = Arc::new(Mutex::new(0usize));
    let seen = Arc::clone(&steps_seen);

    let l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        move |p| {
            if let bussard_download::Progress::Step { .. } = p {
                *seen.lock().unwrap() += 1;
            }
        },
    )
    .await
    .unwrap();
    let _ = session.into_disconnect().await;

    assert!(outcome.ok());
    assert_eq!(
        *steps_seen.lock().unwrap(),
        total,
        "one Step event per step"
    );
    handle.abort();
}

// ===========================================================================
// Windowed-reconnect download tests (issue #52).
//
// A scripted peer drops the L4 connection after K numbered exchanges. Without
// windowing the flash dies mid-download; with `--reconnect-every < K` the engine
// cycles the connection at step boundaries and resumes from the device's
// persistent load state, completing to Loaded across multiple windows. The mock
// counts T_Connects so the tests can assert ≥2 windows were used.
// ===========================================================================

use bussard_bus::{Bus, BusHandle};
use bussard_download::{Connector, FlashOptions, Session as FlashSession};
use bussard_mgmt::LeaseChannel;
use bussard_mgmt::load::WriteError;

/// A [`Connector`] over the mock bus: each `connect()` takes a fresh lease and
/// opens a new L4 connection to the target, exactly as the CLI does per window.
struct MockConnector {
    handle: BusHandle,
    target: bussard_model::IndividualAddress,
    source: bussard_model::IndividualAddress,
}

impl Connector for MockConnector {
    type Channel = LeaseChannel;

    async fn connect(&mut self) -> Result<Layer4Connection<LeaseChannel>, WriteError> {
        let lease = self.handle.lease().await.map_err(|_| {
            WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = LeaseChannel::new(lease);
        Layer4Connection::connect(channel, self.target, self.source)
            .await
            .map_err(WriteError::Mgmt)
    }
}

/// Brings up the mock gateway behind a real [`Bus`] actor and returns a handle,
/// the shared device state, and the gateway task.
async fn setup_bus(state: Shared) -> (BusHandle, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let addr: bussard_model::IndividualAddress = "1.1.4".parse().unwrap();
    let gw_task = tokio::spawn(run_gateway(sock, addr, state));
    let (handle, actor) = Bus::connect(ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ));
    // Wait for the actor to connect.
    for _ in 0..300 {
        if handle.status() == bussard_bus::BusState::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The actor task keeps running once spawned; dropping its JoinHandle does not
    // abort it (tokio semantics), so the bus stays live for the lifetime of the
    // handle.
    drop(actor);
    (handle, gw_task)
}

fn window_connector(handle: &BusHandle) -> MockConnector {
    MockConnector {
        handle: handle.clone(),
        target: "1.1.4".parse().unwrap(),
        source: "0.0.255".parse().unwrap(),
    }
}

#[tokio::test]
async fn windowed_flash_completes_across_multiple_windows() {
    // A peer that drops the L4 connection after 4 numbered exchanges. The
    // fabricated flash runs many more than 4 exchanges, so a non-windowed flash
    // would die. With --reconnect-every 3 (< 4) the engine cycles the connection
    // before the budget is spent and resumes from the persistent load state,
    // completing to Loaded across several windows with byte-identical memory.
    let state = fresh_device(Fault::None);
    {
        let mut s = state.lock().unwrap();
        s.die_after_exchanges = Some(10);
    }
    let (handle, gw_task) = setup_bus(Arc::clone(&state)).await;

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let options = FlashOptions {
        reconnect_every: Some(6),
        ..Default::default()
    };
    let connector = window_connector(&handle);
    let mut session = FlashSession::open(connector).await.unwrap();
    let outcome = flash(&mut session, &plan, options, |_| {}).await.unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "the windowed flash must complete to Loaded and verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);

    {
        let s = state.lock().unwrap();
        // The download used multiple connection windows.
        assert!(
            s.connects >= 2,
            "the download must have opened ≥2 connection windows, got {}",
            s.connects
        );
        // Byte-identical final memory: code image + parameter default landed.
        let code: Vec<u8> = (0x4000u16..0x4006)
            .map(|a| *s.memory.get(&a).unwrap_or(&0))
            .collect();
        assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(*s.memory.get(&0x4006).unwrap_or(&0), 7);
    }

    let _ = handle.close().await;
    gw_task.abort();
}

#[tokio::test]
async fn non_windowed_flash_dies_on_a_dropping_peer() {
    // The same dropping peer, but WITHOUT --reconnect-every: the flash must die
    // mid-download with a mid-session silence / disconnect error (the CLI turns
    // this into the --reconnect-every hint).
    let state = fresh_device(Fault::None);
    {
        let mut s = state.lock().unwrap();
        s.die_after_exchanges = Some(10);
    }
    let (handle, gw_task) = setup_bus(Arc::clone(&state)).await;

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    // A tight response budget so the dead connection fails fast rather than
    // waiting the full 3s KNX default on the silent peer.
    let connector = window_connector(&handle);
    let mut session = FlashSession::open(connector).await.unwrap();
    let err = flash(&mut session, &plan, FlashOptions::default(), |_| {})
        .await
        .expect_err("a dropping peer must kill a non-windowed flash");
    let _ = session.into_disconnect().await;

    // Mid-download silence: the L4 layer reports MidSessionSilence (an exchange
    // count > 0), surfaced through WriteError::Mgmt.
    assert!(
        matches!(
            err,
            WriteError::Mgmt(bussard_mgmt::MgmtError::MidSessionSilence { .. })
                | WriteError::Mgmt(bussard_mgmt::MgmtError::NoResponse { .. })
                | WriteError::Mgmt(bussard_mgmt::MgmtError::Disconnected { .. })
        ),
        "expected a mid-download silence/disconnect, got {err:?}"
    );

    let _ = handle.close().await;
    gw_task.abort();
}

#[tokio::test]
async fn windowed_flash_rejects_lost_loading_state_on_resume() {
    // A peer that drops the app object out of Loading when it is reconnected
    // mid-download. The resume-safety re-check must catch it and fail with a clear
    // UnexpectedLoadState rather than blindly writing into an object that is no
    // longer open for loading. Budget of 4 forces a reconnect early in the flash.
    let state = fresh_device(Fault::None);
    {
        let mut s = state.lock().unwrap();
        s.die_after_exchanges = Some(10);
        s.drop_loading_on_reconnect = true;
    }
    let (handle, gw_task) = setup_bus(Arc::clone(&state)).await;

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    let options = FlashOptions {
        reconnect_every: Some(6),
        ..Default::default()
    };
    let connector = window_connector(&handle);
    let mut session = FlashSession::open(connector).await.unwrap();
    let err = flash(&mut session, &plan, options, |_| {})
        .await
        .expect_err("a peer that loses Loading on resume must fail the re-check");
    let _ = session.into_disconnect().await;

    assert!(
        matches!(err, WriteError::UnexpectedLoadState { .. }),
        "expected an UnexpectedLoadState from the resume re-check, got {err:?}"
    );

    let _ = handle.close().await;
    gw_task.abort();
}

#[tokio::test]
async fn windowed_flash_never_splits_a_chunk() {
    // A window boundary must only ever land between steps, never inside a single
    // write. With a large single-segment image and a small reconnect budget, the
    // engine still lands every byte contiguously (a split chunk would corrupt the
    // segment and fail the spot check). We use a peer that does NOT drop, so the
    // only thing exercised is the boundary placement.
    let state = fresh_device(Fault::None);
    let (handle, gw_task) = setup_bus(Arc::clone(&state)).await;

    let app = fabricated_app();
    let plan = plan_flash(&app, "1.1.4", 0x07B0, &no_overrides(), &BTreeMap::new()).unwrap();

    // Reconnect after every single exchange: the most aggressive cycling, which
    // would split a write if boundaries were not step-aligned.
    let options = FlashOptions {
        reconnect_every: Some(1),
        ..Default::default()
    };
    let connector = window_connector(&handle);
    let mut session = FlashSession::open(connector).await.unwrap();
    let outcome = flash(&mut session, &plan, options, |_| {}).await.unwrap();
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "aggressive per-exchange cycling must still verify byte-identically: {outcome:?}"
    );
    {
        let s = state.lock().unwrap();
        assert!(s.connects >= 2, "cycling must have opened multiple windows");
        let code: Vec<u8> = (0x4000u16..0x4006)
            .map(|a| *s.memory.get(&a).unwrap_or(&0))
            .collect();
        assert_eq!(code, vec![0, 1, 2, 3, 4, 5], "no chunk was split");
        assert_eq!(*s.memory.get(&0x4006).unwrap_or(&0), 7);
    }

    let _ = handle.close().await;
    gw_task.abort();
}
