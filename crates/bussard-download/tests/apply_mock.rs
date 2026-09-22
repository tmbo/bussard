//! Mock-device integration tests for the write path.
//!
//! A scripted System B device implements the load-state machine, relative
//! segment allocation and device memory **from the KNX spec semantics**, not
//! from bussard's own encoders (de-mirrored): the mock decodes the raw APDUs,
//! mutates its own load states and sparse memory, and answers with the responses
//! a real device sends. The client drives it through
//! [`bussard_download::apply_tables`].
//!
//! # Why this mock refuses `PID_TABLE` property writes
//!
//! The 2026 physical test campaign (issue #89) ran `bussard apply` against a Jung
//! F50 push-button module (52911ST, application `M-0004_A-D141-22`). The device
//! **rejected** the `A_PropertyValue_Write` to `PID_TABLE` (PID 23) with a
//! zero-count `A_PropertyValue_Response` — it echoed no elements at all. Two
//! independent ETS captures (a Jung F50 sibling at 1.1.18, and the KNX Virtual
//! DA.tp) confirm ETS never writes a table through the property array: after
//! `StartLoading` it writes a 10-octet `AdditionalLoadControls` /
//! `LdCtrlRelSegment`, reads `PID_TABLE_REFERENCE`, streams the table image
//! (count word + elements) with `A_Memory_Write` / `A_MemoryExtended_Write`, and
//! only then sends `LoadCompleted`.
//!
//! Only the lenient KNX Virtual stack also *accepts* property writes to
//! `PID_TABLE`, which is why the old mock (and the simulator) let the bug
//! through. This mock now models the real device: `PID_TABLE` writes are refused,
//! `PID_TABLE` **reads** still work (the Jung allows them), and the only way to
//! get a table into the device is allocate + memory-write.
//!
//! Cases:
//! - happy path: allocate + memory-write → both `Loaded` → verify byte-equal;
//! - the same over a segment above `0xFFFF`, which takes the
//!   `A_MemoryExtended_Write` service;
//! - the memory read-back path alone (`PID_TABLE` reads disabled) yields the same
//!   content as the property path;
//! - a device that flips to load `Error` on `LoadCompleted` → clear failure;
//! - a device that refuses the segment allocation (too large → `Error`) → clear
//!   failure;
//! - a device whose memory write is refused → the underlying error surfaces;
//! - the recorded op sequence is StartLoading(assoc), alloc(assoc),
//!   StartLoading(addr), alloc(addr), memory writes, LoadCompleted(addr),
//!   LoadCompleted(assoc), with **no** `PID_TABLE` property write anywhere;
//! - plan-only (a bare `read_tables`) touches no load state.
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
const A_MEMORY_READ_SEL: u16 = 0x200;
const A_MEMORY_RESPONSE: u16 = 0x240;
const A_MEMORY_WRITE_SEL: u16 = 0x280;
// A_MemoryExtended_* (System B, 24-bit address). Full 10-bit APCIs — unlike the
// plain services these carry no count in the low APCI bits.
const A_MEMORY_EXTENDED_WRITE: u16 = 0x1FB;
const A_MEMORY_EXTENDED_WRITE_RESPONSE: u16 = 0x1FC;
const A_MEMORY_EXTENDED_READ: u16 = 0x1FD;
const A_MEMORY_EXTENDED_READ_RESPONSE: u16 = 0x1FE;
const A_DEVICE_DESCRIPTOR_READ_SEL: u16 = 0x300;
const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
const APCI_SELECTOR: u16 = 0x3C0;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
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
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;
/// `AdditionalLoadControls` sub-command `LdCtrlRelSegment` (KNX 3/5/2): the tool
/// asks for a device-placed segment of `size` octets (big-endian `u32` at
/// octets 2..6), with an optional fill flag/byte at octets 6/7.
const SUB_REL_SEGMENT: u8 = 0x0B;

/// Object index of the address table on this mock (object type 1).
const OBJ_ADDRESS: u8 = 1;
/// Object index of the association table on this mock (object type 2).
const OBJ_ASSOCIATION: u8 = 2;

/// How the device misbehaves, if at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    /// Enter the load Error state when the association table's LoadCompleted is
    /// written (models a device rejecting the written content).
    ErrorOnAssocComplete,
    /// NAK every memory write (models a device that refuses the table image).
    NakMemoryWrite,
}

/// One op the device performed, in order — the write-side trace a test asserts
/// the download sequence against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    StartLoading(u8),
    /// A `LdCtrlRelSegment` allocation of `size` octets for an object.
    Allocate {
        object: u8,
        size: u32,
    },
    LoadCompleted(u8),
    Unload(u8),
    /// `len` octets written at a device address.
    MemWrite {
        addr: u32,
        len: usize,
    },
    /// A `PID_TABLE` property write — refused, but recorded so a test can assert
    /// the tool never attempts one.
    TablePropertyWrite(u8),
}

/// How the mock device is configured. Everything a test varies lives here so the
/// device itself stays one code path.
#[derive(Clone, Copy)]
struct DeviceCfg {
    fault: Fault,
    /// Base address of the address-table segment; the association table's
    /// segment sits `0x800` above it. A real device picks these itself and
    /// reports them through `PID_TABLE_REFERENCE`; this mock is deterministic.
    segment_base: u32,
    /// Whether `PID_TABLE` property **reads** are served. The Jung allows them;
    /// turning them off forces the read-back onto the `PID_TABLE_REFERENCE` +
    /// memory path so a test can prove both paths agree.
    table_property_reads: bool,
    /// The largest segment the device can place. A `LdCtrlRelSegment` asking for
    /// more drops the object into `Error` (KNX 3/5/2: "maximum table length
    /// exceeded").
    max_segment_size: u32,
}

impl Default for DeviceCfg {
    fn default() -> Self {
        Self {
            fault: Fault::None,
            segment_base: 0x4000,
            table_property_reads: true,
            max_segment_size: 0x400,
        }
    }
}

/// The mutable mock-device state, shared with the gateway task.
struct DeviceState {
    cfg: DeviceCfg,
    object_types: Vec<u16>,
    /// Per-object load state, keyed by object index.
    load_states: HashMap<u8, u8>,
    /// Per-object allocated segment: `(base, size)`. Absent = never allocated,
    /// so `PID_TABLE_REFERENCE` reports 0.
    segments: HashMap<u8, (u32, u32)>,
    /// Sparse device memory: 24-bit address → octet.
    memory: HashMap<u32, u8>,
    /// Count of load-control writes seen (plan-only must be zero).
    control_writes: usize,
    /// Count of `PID_TABLE` property writes seen — must stay zero.
    table_property_writes: usize,
    /// Every write-side op, in order.
    ops: Vec<Op>,
    /// The group object table element count (nice-to-have; read side counts it).
    go_count: u16,
}

impl DeviceState {
    /// The octet width of one element of a table object, from its object type.
    fn elem_size(&self, oi: u8) -> usize {
        match self.object_types.get(usize::from(oi)) {
            Some(&OT_ASSOCIATION_TABLE) => 4,
            _ => 2,
        }
    }

    /// Where this object's segment is placed when it is allocated.
    fn base_for(&self, oi: u8) -> u32 {
        self.cfg
            .segment_base
            .wrapping_add(u32::from(oi.saturating_sub(1)) * 0x800)
    }

    fn load_state(&self, oi: u8) -> u8 {
        *self.load_states.get(&oi).unwrap_or(&LS_UNLOADED)
    }

    /// Reads `len` octets of device memory (unmapped octets read as 0, exactly as
    /// a device's erased flash does).
    fn read_mem(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| *self.memory.get(&addr.wrapping_add(i as u32)).unwrap_or(&0))
            .collect()
    }

    /// Whether `addr..addr+len` lies wholly inside one allocated segment. A real
    /// device only accepts a configuration write into storage it has placed; a
    /// write anywhere else is refused.
    fn writable(&self, addr: u32, len: usize) -> bool {
        let end = u64::from(addr) + len as u64;
        self.segments.values().any(|&(base, size)| {
            u64::from(addr) >= u64::from(base) && end <= u64::from(base) + u64::from(size)
        })
    }

    /// The stored image (count word + elements) of a table object, or `None` when
    /// the object has no segment yet.
    fn table_image(&self, oi: u8) -> Option<Vec<u8>> {
        let &(base, size) = self.segments.get(&oi)?;
        Some(self.read_mem(base, size as usize))
    }
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

/// The zero-count `A_PropertyValue_Response` a device sends when it refuses (or
/// cannot serve) a property access: the header echoed back with `nr_of_elem = 0`
/// and no data. This is exactly what the Jung F50 answered a `PID_TABLE` write
/// with (KNX 3/3/7 § A_PropertyValue_Write).
fn prop_refused(object_index: u8, pid: u8, start: u16) -> Vec<u8> {
    prop_response(object_index, pid, 0, start, &[])
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

/// The device's reaction to one management request: answer with an APDU, or NAK
/// at the transport layer (a refused service).
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

    // --- Memory services -----------------------------------------------------

    // A_Memory_Read: [addr_hi, addr_lo], octet count in the low 6 APCI bits.
    // Answered with A_Memory_Response (0x240 | count) [addr_hi, addr_lo, data…].
    if req_apci & APCI_SELECTOR == A_MEMORY_READ_SEL {
        let count = (req_apci & 0x3f) as usize;
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&s.read_mem(u32::from(addr), count));
        return Reaction::Answer(A_MEMORY_RESPONSE | (count as u16 & 0x3f), payload);
    }

    // A_MemoryExtended_Read: [count][addr:3 BE]. Answered with an
    // A_MemoryExtended_Read_Response [return_code=0][addr:3][data…].
    if req_apci == A_MEMORY_EXTENDED_READ {
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = data[0] as usize;
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut payload = vec![0x00, data[1], data[2], data[3]];
        payload.extend_from_slice(&s.read_mem(addr, count));
        return Reaction::Answer(A_MEMORY_EXTENDED_READ_RESPONSE, payload);
    }

    // A_MemoryExtended_Write: [count][addr:3 BE][data…]. Stores the octets and
    // confirms inline with A_MemoryExtended_Write_Response [return_code=0][addr:3].
    if req_apci == A_MEMORY_EXTENDED_WRITE {
        if s.cfg.fault == Fault::NakMemoryWrite || data.len() < 4 {
            return Reaction::Nak;
        }
        let count = data[0] as usize;
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        if data.len() < 4 + count || !s.writable(addr, count) {
            return Reaction::Nak;
        }
        for (i, b) in data[4..4 + count].iter().enumerate() {
            s.memory.insert(addr.wrapping_add(i as u32), *b);
        }
        s.ops.push(Op::MemWrite { addr, len: count });
        return Reaction::Answer(
            A_MEMORY_EXTENDED_WRITE_RESPONSE,
            vec![0x00, data[1], data[2], data[3]],
        );
    }

    // A_Memory_Write: [addr_hi, addr_lo, data…], count in the low 6 APCI bits.
    // A verify-mode device answers it with an A_Memory_Response echoing the
    // octets it stored (KNX 3/3/7); bussard's `write_memory_chunked` sends the
    // write unconfirmed and drains that echo, so the mock exercises that path.
    if req_apci & APCI_SELECTOR == A_MEMORY_WRITE_SEL {
        if s.cfg.fault == Fault::NakMemoryWrite || data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let value = &data[2..];
        if !s.writable(u32::from(addr), value.len()) {
            return Reaction::Nak;
        }
        for (i, b) in value.iter().enumerate() {
            s.memory.insert(u32::from(addr).wrapping_add(i as u32), *b);
        }
        s.ops.push(Op::MemWrite {
            addr: u32::from(addr),
            len: value.len(),
        });
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(value);
        return Reaction::Answer(A_MEMORY_RESPONSE | (value.len() as u16 & 0x3f), payload);
    }

    // --- Property services ---------------------------------------------------

    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((oi, pid, count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        // Object type discovery.
        if pid == PID_OBJECT_TYPE {
            return match s.object_types.get(usize::from(oi)) {
                Some(ot) => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &ot.to_be_bytes()),
                ),
                None => Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start)),
            };
        }
        // Load state read: single octet.
        if pid == PID_LOAD_STATE_CONTROL {
            let st = s.load_state(oi);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[st]),
            );
        }
        // PID_TABLE_REFERENCE: the segment base as a 4-octet big-endian u32; 0
        // while the object has no segment (KNX 3/5/1).
        if pid == PID_TABLE_REFERENCE {
            let base = s.segments.get(&oi).map(|&(b, _)| b).unwrap_or(0);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &base.to_be_bytes()),
            );
        }
        // PID_TABLE read: element 0 = the count word, elements 1.. = the table
        // entries. Served straight out of the stored image so the property path
        // and the memory path can never disagree.
        if pid == PID_TABLE {
            if !s.cfg.table_property_reads {
                return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
            }
            // Group object table: report a fixed count at element 0 (the read
            // side only counts it).
            if s.object_types.get(usize::from(oi)) == Some(&OT_GROUP_OBJECT_TABLE) {
                if start == 0 {
                    let c = s.go_count;
                    return Reaction::Answer(
                        A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, 0, &c.to_be_bytes()),
                    );
                }
                return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
            }
            let elem_size = s.elem_size(oi);
            let Some(image) = s.table_image(oi) else {
                return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
            };
            if image.len() < 2 {
                return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
            }
            let stored = usize::from(u16::from_be_bytes([image[0], image[1]]));
            // The element count is bounded by what the segment actually holds.
            let held = (image.len() - 2) / elem_size;
            let total = stored.min(held);
            if start == 0 {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, 0, &(total as u16).to_be_bytes()),
                );
            }
            let idx = usize::from(start);
            if idx > total {
                return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
            }
            let want = (count as usize).clamp(1, total - idx + 1);
            let byte_start = 2 + (idx - 1) * elem_size;
            let byte_end = byte_start + want * elem_size;
            let chunk = image[byte_start..byte_end].to_vec();
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, want as u8, start, &chunk),
            );
        }
        return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
    }

    if req_apci == A_PROPERTY_VALUE_WRITE {
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = &data[4..];

        if pid == PID_LOAD_STATE_CONTROL {
            s.control_writes += 1;
            let event = value.first().copied().unwrap_or(0);

            // A 10-octet AdditionalLoadControls / LdCtrlRelSegment write is a
            // relative segment allocation: size is a big-endian u32 at octets
            // 2..6, with an optional fill flag/byte at 6/7 the mock ignores
            // beyond honouring the requested size.
            if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                // The standard only dispatches AdditionalLoadControls from the
                // loading state; in any other state the write is ignored and the
                // state is unchanged.
                if s.load_state(oi) != LS_LOADING {
                    let st = s.load_state(oi);
                    return Reaction::Answer(
                        A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, start, &[st]),
                    );
                }
                let size = if value.len() >= 6 {
                    u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                } else {
                    0
                };
                s.ops.push(Op::Allocate { object: oi, size });
                // Maximum table length exceeded → the object goes to Error.
                if size > s.cfg.max_segment_size {
                    s.load_states.insert(oi, LS_ERROR);
                    return Reaction::Answer(
                        A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, start, &[LS_ERROR]),
                    );
                }
                // Free any prior backing store and place a fresh segment.
                if let Some(&(old_base, old_size)) = s.segments.get(&oi) {
                    for i in 0..old_size {
                        s.memory.remove(&old_base.wrapping_add(i));
                    }
                }
                let base = s.base_for(oi);
                s.segments.insert(oi, (base, size));
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[LS_LOADING]),
                );
            }

            let is_assoc = s.object_types.get(usize::from(oi)) == Some(&OT_ASSOCIATION_TABLE);
            let fault = s.cfg.fault;
            let new_state = match event {
                LE_START_LOADING => {
                    s.ops.push(Op::StartLoading(oi));
                    LS_LOADING
                }
                LE_LOAD_COMPLETED => {
                    s.ops.push(Op::LoadCompleted(oi));
                    if is_assoc && fault == Fault::ErrorOnAssocComplete {
                        LS_ERROR
                    } else {
                        LS_LOADED
                    }
                }
                LE_UNLOAD => {
                    s.ops.push(Op::Unload(oi));
                    LS_UNLOADED
                }
                _ => s.load_state(oi),
            };
            s.load_states.insert(oi, new_state);
            // Echo the resulting load state (what a real device returns).
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[new_state]),
            );
        }

        if pid == PID_TABLE {
            // THE FINDING (issue #89): a real System B device does not take its
            // tables through the PID_TABLE property array. The Jung F50 52911ST
            // answered this write with a zero-count A_PropertyValue_Response —
            // no elements written, no error at the transport layer. Record it so
            // a test can assert the tool never tries.
            s.table_property_writes += 1;
            s.ops.push(Op::TablePropertyWrite(oi));
            return Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, prop_refused(oi, pid, start));
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

fn fresh_device(cfg: DeviceCfg) -> Shared {
    // Objects: 0 device, 1 address table, 2 association table, 3 group object.
    // Both table objects start Loaded with an empty (count-word-only) segment,
    // the state of a device that was programmed before.
    let mut load_states = HashMap::new();
    load_states.insert(OBJ_ADDRESS, LS_LOADED);
    load_states.insert(OBJ_ASSOCIATION, LS_LOADED);
    let mut segments = HashMap::new();
    segments.insert(OBJ_ADDRESS, (cfg.segment_base, 2));
    segments.insert(OBJ_ASSOCIATION, (cfg.segment_base.wrapping_add(0x800), 2));
    Arc::new(Mutex::new(DeviceState {
        cfg,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        load_states,
        segments,
        memory: HashMap::new(),
        control_writes: 0,
        table_property_writes: 0,
        ops: Vec::new(),
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

/// Spins up the gateway and returns a connected [`Transport`] plus the shared
/// device state.
async fn setup_cfg(cfg: DeviceCfg) -> (Transport, Shared, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let state = fresh_device(cfg);
    let addr: IndividualAddress = "1.1.4".parse().unwrap();
    let handle = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let bus = Transport::connect(&ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ))
    .await
    .unwrap();
    (bus, state, handle)
}

async fn setup(fault: Fault) -> (Transport, Shared, tokio::task::JoinHandle<()>) {
    setup_cfg(DeviceCfg {
        fault,
        ..DeviceCfg::default()
    })
    .await
}

const TARGET: &str = "1.1.4";
const SOURCE: &str = "0.0.255";

/// Runs the full apply against a configured device and returns the result.
async fn run_apply(
    cfg: DeviceCfg,
) -> (
    Result<bussard_download::VerifyOutcome, WriteError>,
    Shared,
    tokio::task::JoinHandle<()>,
) {
    let (mut bus, state, handle) = setup_cfg(cfg).await;
    let target: IndividualAddress = TARGET.parse().unwrap();
    let source: IndividualAddress = SOURCE.parse().unwrap();

    let desired = compute_tables(&model_links());
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();
    let objects = discover_table_objects(&mut l4).await.unwrap();
    let outcome = apply_tables(&mut l4, objects, &desired).await;
    let _ = l4.disconnect().await;
    (outcome, state, handle)
}

/// Asserts the device holds exactly the desired table images (count word +
/// elements) in the segments it allocated.
fn assert_stored_images(state: &Shared, desired: &bussard_download::DesiredTables) {
    let s = state.lock().unwrap();
    let addr_image = s.table_image(OBJ_ADDRESS).expect("address segment");
    let assoc_image = s.table_image(OBJ_ASSOCIATION).expect("association segment");

    let mut want_addr = (desired.addresses.len() as u16).to_be_bytes().to_vec();
    want_addr.extend_from_slice(&desired.address_elements());
    let mut want_assoc = (desired.associations.len() as u16).to_be_bytes().to_vec();
    want_assoc.extend_from_slice(&desired.association_elements());

    assert_eq!(addr_image, want_addr, "stored address-table image");
    assert_eq!(assoc_image, want_assoc, "stored association-table image");
}

#[tokio::test]
async fn apply_happy_path_writes_verifies_and_loads() {
    let (outcome, state, handle) = run_apply(DeviceCfg::default()).await;
    let outcome = outcome.expect("apply must succeed");
    let desired = compute_tables(&model_links());

    assert!(outcome.ok(), "apply must verify: {outcome:?}");
    assert_eq!(outcome.address_state, LoadState::Loaded);
    assert_eq!(outcome.association_state, LoadState::Loaded);
    assert!(outcome.addresses_match);
    assert!(outcome.associations_match);

    assert_stored_images(&state, &desired);
    assert_eq!(
        state.lock().unwrap().table_property_writes,
        0,
        "a real device refuses PID_TABLE writes; the tool must never send one"
    );
    handle.abort();
}

#[tokio::test]
async fn apply_uses_extended_memory_for_a_segment_above_16_bits() {
    // The real 07B0 actuators place their segments above 0xFFFF, where the plain
    // A_Memory_Write cannot reach. The same apply must run over
    // A_MemoryExtended_Write and verify identically.
    let cfg = DeviceCfg {
        segment_base: 0x01_0000,
        ..DeviceCfg::default()
    };
    let (outcome, state, handle) = run_apply(cfg).await;
    let outcome = outcome.expect("apply over extended memory must succeed");
    assert!(outcome.ok(), "apply must verify: {outcome:?}");

    let desired = compute_tables(&model_links());
    assert_stored_images(&state, &desired);
    {
        let s = state.lock().unwrap();
        assert!(
            s.ops
                .iter()
                .any(|op| matches!(op, Op::MemWrite { addr, .. } if *addr > 0xFFFF)),
            "the segment above 0xFFFF must be written through extended memory"
        );
    }
    handle.abort();
}

#[tokio::test]
async fn apply_verifies_through_memory_when_pid_table_reads_are_unavailable() {
    // A device that serves no PID_TABLE property read at all forces the read-back
    // onto PID_TABLE_REFERENCE + memory. Both paths must produce the same bytes,
    // so the verification outcome is identical.
    let cfg = DeviceCfg {
        table_property_reads: false,
        ..DeviceCfg::default()
    };
    let (outcome, state, handle) = run_apply(cfg).await;
    let outcome = outcome.expect("apply must succeed on the memory read-back path");
    assert!(outcome.ok(), "apply must verify via memory: {outcome:?}");

    let desired = compute_tables(&model_links());
    assert_stored_images(&state, &desired);
    handle.abort();
}

#[tokio::test]
async fn apply_reports_load_error_after_completed() {
    let (outcome, _state, handle) = run_apply(DeviceCfg {
        fault: Fault::ErrorOnAssocComplete,
        ..DeviceCfg::default()
    })
    .await;
    let err = outcome.expect_err("a load Error must surface");
    assert!(
        matches!(err, WriteError::LoadError { .. }),
        "expected LoadError, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn apply_fails_when_the_device_refuses_the_segment_allocation() {
    // A device whose maximum table length is smaller than the image drops the
    // object into Error on the LdCtrlRelSegment write. `allocate_segment` reads
    // the state back and must fail the apply loudly.
    let (outcome, state, handle) = run_apply(DeviceCfg {
        max_segment_size: 4,
        ..DeviceCfg::default()
    })
    .await;
    let err = outcome.expect_err("a refused allocation must surface");
    assert!(
        matches!(err, WriteError::LoadError { .. }),
        "expected LoadError from the refused allocation, got {err:?}"
    );
    {
        let s = state.lock().unwrap();
        assert!(
            !s.ops.iter().any(|op| matches!(op, Op::MemWrite { .. })),
            "no table image may be written after a refused allocation: {:?}",
            s.ops
        );
    }
    handle.abort();
}

#[tokio::test]
async fn apply_aborts_when_the_memory_write_is_refused() {
    let (outcome, _state, handle) = run_apply(DeviceCfg {
        fault: Fault::NakMemoryWrite,
        ..DeviceCfg::default()
    })
    .await;
    let err = outcome.expect_err("a refused memory write must abort the apply");
    // A NAK tears the connection down → a Mgmt(Nak/Disconnected) error.
    assert!(
        matches!(err, WriteError::Mgmt(_)),
        "expected a Mgmt error from the refused memory write, got {err:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn apply_drives_the_ets_op_sequence_and_never_writes_pid_table() {
    let (outcome, state, handle) = run_apply(DeviceCfg::default()).await;
    outcome.expect("apply must succeed");

    let desired = compute_tables(&model_links());
    let addr_size = (2 + desired.address_elements().len()) as u32;
    let assoc_size = (2 + desired.association_elements().len()) as u32;
    let ops = state.lock().unwrap().ops.clone();

    // 1..4: open both objects, each followed immediately by its allocation —
    // association first, address second (the ordering `apply_tables` documents).
    assert_eq!(ops[0], Op::StartLoading(OBJ_ASSOCIATION), "ops: {ops:?}");
    assert_eq!(
        ops[1],
        Op::Allocate {
            object: OBJ_ASSOCIATION,
            size: assoc_size
        },
        "ops: {ops:?}"
    );
    assert_eq!(ops[2], Op::StartLoading(OBJ_ADDRESS), "ops: {ops:?}");
    assert_eq!(
        ops[3],
        Op::Allocate {
            object: OBJ_ADDRESS,
            size: addr_size
        },
        "ops: {ops:?}"
    );

    // …then only memory writes until the two LoadCompleteds, address first.
    let tail = &ops[ops.len() - 2..];
    assert_eq!(
        tail,
        [
            Op::LoadCompleted(OBJ_ADDRESS),
            Op::LoadCompleted(OBJ_ASSOCIATION)
        ],
        "ops: {ops:?}"
    );
    let writes = &ops[4..ops.len() - 2];
    assert!(
        !writes.is_empty() && writes.iter().all(|op| matches!(op, Op::MemWrite { .. })),
        "only memory writes may sit between the allocations and the completions: {ops:?}"
    );

    // The address table is streamed before the association table, so the
    // association TSAPs only ever index content that is already written.
    let addr_base = 0x4000u32;
    let assoc_base = 0x4800u32;
    let written: Vec<(u32, usize)> = writes
        .iter()
        .map(|op| match op {
            Op::MemWrite { addr, len } => (*addr, *len),
            other => unreachable!("{other:?}"),
        })
        .collect();
    let split = written
        .iter()
        .position(|&(a, _)| a >= assoc_base)
        .expect("the association image must be written");
    assert!(
        written[..split]
            .iter()
            .all(|&(a, _)| a >= addr_base
                && u64::from(a) < u64::from(addr_base) + u64::from(addr_size)),
        "the address image is streamed first: {written:?}"
    );
    assert_eq!(
        written[..split].iter().map(|&(_, l)| l).sum::<usize>(),
        addr_size as usize,
        "the whole address image is written: {written:?}"
    );
    assert_eq!(
        written[split..].iter().map(|&(_, l)| l).sum::<usize>(),
        assoc_size as usize,
        "the whole association image is written: {written:?}"
    );

    // And at no point did the tool try the property array.
    assert!(
        !ops.iter().any(|op| matches!(op, Op::TablePropertyWrite(_))),
        "apply must never write PID_TABLE: {ops:?}"
    );
    assert_eq!(state.lock().unwrap().table_property_writes, 0);
    handle.abort();
}

#[tokio::test]
async fn plan_only_read_touches_no_load_state() {
    let (mut bus, state, handle) = setup(Fault::None).await;
    let target: IndividualAddress = TARGET.parse().unwrap();
    let source: IndividualAddress = SOURCE.parse().unwrap();

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
    assert!(s.ops.is_empty(), "a plan-only read performs no write op");
    handle.abort();
}
