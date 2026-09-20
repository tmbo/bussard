//! Mock-device integration tests for the **System 7** (mask 0705/0701)
//! application-download path (issue #49).
//!
//! Self-contained, mirroring `flash_mock.rs` but modelling a System 7 device
//! rather than System B — all from KNX spec / `docs/system7-spec.md` semantics,
//! never from bussard's own encoders:
//!
//! - descriptor **0705**, an **authorize gate** (free-access key), and object-0
//!   **PID 78** readable for the MDT preflight;
//! - **three parallel load-state machines**, driven either memory-mapped (a
//!   11-octet record written to `0x0104`, status polled at `0xB6EA+`) or
//!   property-based (`PID_LOAD_STATE_CONTROL` per object) — selected by a
//!   construction-time flag so the same device serves both `LsmAccess` variants;
//! - **absolute `A_Memory_Write`/`_Read`** over sparse memory, so the client's
//!   read-back verification sees exactly what it wrote (with a `0x4000` region
//!   that preserves device-owned bytes under the segment `<Mask>`).
//!
//! Cases: a full MDT-canonical flash to `Loaded` (both LSM realisations), a
//! drop-and-resume, and a verify-mismatch failure.
//!
//! **The flash path is only ever exercised here — never against a live bus.**

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{Session, flash, plan_flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::LoadState;
use bussard_prod::application::{ApplicationProgram, parse_application_program};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x37;

// --- KNX identifiers, redeclared here from the spec (de-mirrored) ---
const A_MEMORY_READ_SEL: u16 = 0x200;
const A_MEMORY_RESPONSE: u16 = 0x240;
const A_MEMORY_WRITE_SEL: u16 = 0x280;
const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const A_AUTHORIZE_REQUEST: u16 = 0x3D1;
const A_AUTHORIZE_RESPONSE: u16 = 0x3D2;
const A_DEVICE_DESCRIPTOR_READ_SEL: u16 = 0x300;
const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
const A_RESTART_SEL: u16 = 0x380;
const APCI_SELECTOR: u16 = 0x3C0;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_HARDWARE_TYPE: u8 = 78;
const PID_MCB_TABLE: u8 = 27;

// System 7 mask + memory-mapped LSM anchors (spec §5 defaults).
const MASK_0705: u16 = 0x0705;
const LSM_CONTROL_ADDR: u16 = 0x0104;
const LSM_STATUS_ADDR: u16 = 0xB6EA;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;
const LS_ERROR: u8 = 3;

const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;

/// Which load-state realisation the mock serves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LsmMode {
    /// 11-octet record to `0x0104`, status at `0xB6EA+` (Theben 0701 form).
    MemoryMapped,
    /// `PID_LOAD_STATE_CONTROL` per object.
    Property,
}

/// How the device misbehaves, if at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    /// Corrupt one stored octet of every segment memory write, so the read-back
    /// verify diverges and the flash fails at that write.
    CorruptStoredImage,
}

/// The mock System 7 device state.
struct DeviceState {
    lsm_mode: LsmMode,
    fault: Fault,
    /// Per-LSM load state (LSM index → state octet). LSM indices are 1-based.
    lsm_states: HashMap<u8, u8>,
    /// Sparse device memory: address → octet.
    memory: HashMap<u16, u8>,
    /// Object-0 PID 78 value the MDT preflight compares against.
    pid78: Vec<u8>,
    /// Whether the current connection has authorized (reset per T_Connect).
    authorized: bool,
    /// Count of authorize requests, so a test can assert the tool authorized.
    authorizes_seen: usize,
    /// Count of `A_Memory_Write` frames stored (the flash actually wrote).
    memory_writes_seen: usize,
    /// Count of basic restarts seen (the terminal step).
    restarts_seen: usize,
    /// If set, the device goes silent after this many numbered exchanges on one
    /// connection, modelling a mid-download L4 drop the tool must resume across.
    /// Only the first `deaths_remaining` connections die; later ones serve fully,
    /// so a resuming tool eventually completes.
    die_after_exchanges: Option<u32>,
    /// How many more connections will die at the budget before the device serves
    /// fully. Decremented each time a death trips.
    deaths_remaining: u32,
    /// Exchanges on the current connection (reset per T_Connect).
    exchanges_this_connection: u32,
    /// Objects that expose a readable `PID_MCB_TABLE` (the Jung A-A011 objects).
    mcb_objects: Vec<u8>,
    /// Interface-object types by index (for object-type discovery).
    object_types: Vec<u16>,
    /// When true, a basic restart reboots the device: it drops the current L4
    /// connection (goes silent, exactly like a real device that reboots) so the
    /// tool must reconnect before it can verify. Models the real
    /// restart-then-reconnect the terminal-restart verify handles.
    reboot_on_restart: bool,
    /// When true, the reboot reverts every LSM to `Unloaded` — a load that did
    /// *not* persist across the reboot. A verify that reads state *before* the
    /// restart would wrongly see the transient `Loaded`; verifying *after* the
    /// reconnect catches the revert and fails the flash.
    revert_on_reboot: bool,
    /// Set the moment a rebooting device sees its restart; the current connection
    /// then goes silent until a fresh T_Connect (the tool's reconnect) clears it.
    rebooting: bool,
    /// Count of `A_PropertyValue` accesses to object 5 / PID 5 (load-state
    /// control). A memory-mapped device has no such property, so a correct
    /// memory-mapped flash of a post-restart LSM 5 must leave this at zero.
    lsm5_property_accesses: usize,
}

impl DeviceState {
    fn lsm_state(&self, lsm: u8) -> u8 {
        self.lsm_states.get(&lsm).copied().unwrap_or(LS_UNLOADED)
    }
}

type Shared = Arc<Mutex<DeviceState>>;

fn fresh_device(mode: LsmMode, fault: Fault) -> Shared {
    Arc::new(Mutex::new(DeviceState {
        lsm_mode: mode,
        fault,
        lsm_states: HashMap::new(),
        memory: HashMap::new(),
        // The MDT A-000E preflight value: 00000000 03 12 00000000.
        pid78: vec![0x00, 0x00, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00, 0x00, 0x00],
        authorized: false,
        authorizes_seen: 0,
        memory_writes_seen: 0,
        restarts_seen: 0,
        die_after_exchanges: None,
        deaths_remaining: 0,
        exchanges_this_connection: 0,
        mcb_objects: Vec::new(),
        object_types: vec![0, 1, 2, 3],
        reboot_on_restart: false,
        revert_on_reboot: false,
        rebooting: false,
        lsm5_property_accesses: 0,
    }))
}

/// The MDT A-000E canonical System 7 app (mask 0705): obj0/PID78 preflight,
/// three LSMs, a 0x4000 table segment with a `<Mask>`, a 0x0700 allocate-only RAM
/// segment, a 0x4400 param segment, a TaskSegment per loaded LSM, a restart.
fn mdt_canonical_app() -> ApplicationProgram {
    // AS-1 @ 0x4000: 4 data bytes, mask FF FF 00 FF (byte 2 device-owned).
    // AS-2 @ 0x4201: 3 assoc bytes. AS-3 @ 0x0700: allocate-only (no Data).
    // AS-4 @ 0x4400: 2 param bytes.
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-83_A-E" ApplicationNumber="14" ApplicationVersion="35"
        MaskVersion="MV-0705" Name="MDT S7" LoadProcedureStyle="ProductProcedure">
      <Static>
       <Code>
        <AbsoluteSegment Id="M-83_A-E_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data><Mask>//8A/w==</Mask></AbsoluteSegment>
        <AbsoluteSegment Id="M-83_A-E_AS-2" Size="3" Address="16897"><Data>AQID</Data></AbsoluteSegment>
        <AbsoluteSegment Id="M-83_A-E_AS-3" Size="8" Address="1792" />
        <AbsoluteSegment Id="M-83_A-E_AS-4" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlCompareProp ObjIdx="0" PropId="78" InlineData="00000000031200000000" />
         <LdCtrlUnload LsmIdx="1" />
         <LdCtrlUnload LsmIdx="2" />
         <LdCtrlUnload LsmIdx="3" />
         <LdCtrlLoad LsmIdx="1" />
         <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
         <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
         <LdCtrlLoadCompleted LsmIdx="1" />
         <LdCtrlLoad LsmIdx="2" />
         <LdCtrlAbsSegment LsmIdx="2" Address="16897" Size="3" />
         <LdCtrlTaskSegment LsmIdx="2" Address="16897" />
         <LdCtrlLoadCompleted LsmIdx="2" />
         <LdCtrlLoad LsmIdx="3" />
         <LdCtrlAbsSegment LsmIdx="3" Address="1792" Size="8" />
         <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
         <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
         <LdCtrlLoadCompleted LsmIdx="3" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    parse_application_program("M-83_A-E", xml.as_bytes()).expect("parse MDT S7 app")
}

/// A Theben-style 0701 app with a **post-restart LSM-5** section (spec §3/§4.7):
/// LSMs 1/2/3 load normally, the device restarts, then a TaskSegment + Load are
/// issued on LSM 5 (a fourth machine the device opens only after the restart).
/// This is the memory-mapped × post-restart-LSM5 corner that no earlier mock or
/// replay test exercised — the shape that broke the live `run.sh` device 1.1.8.
fn theben_post_restart_lsm5_app() -> ApplicationProgram {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-48_A-4947" ApplicationNumber="18759" ApplicationVersion="16"
        MaskVersion="MV-0701" Name="FIX2 post-restart LSM5" LoadProcedureStyle="ProductProcedure">
      <Static>
       <Code>
        <AbsoluteSegment Id="M-48_A-4947_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
        <AbsoluteSegment Id="M-48_A-4947_AS-2" Size="3" Address="16897"><Data>AQID</Data></AbsoluteSegment>
        <AbsoluteSegment Id="M-48_A-4947_AS-3" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="1" />
         <LdCtrlUnload LsmIdx="2" />
         <LdCtrlUnload LsmIdx="3" />
         <LdCtrlLoad LsmIdx="1" />
         <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
         <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
         <LdCtrlLoadCompleted LsmIdx="1" />
         <LdCtrlLoad LsmIdx="2" />
         <LdCtrlAbsSegment LsmIdx="2" Address="16897" Size="3" />
         <LdCtrlTaskSegment LsmIdx="2" Address="16897" />
         <LdCtrlLoadCompleted LsmIdx="2" />
         <LdCtrlLoad LsmIdx="3" />
         <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
         <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
         <LdCtrlLoadCompleted LsmIdx="3" />
         <LdCtrlRestart />
         <LdCtrlTaskSegment LsmIdx="5" Address="17406" />
         <LdCtrlLoad LsmIdx="5" />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    parse_application_program("M-48_A-4947", xml.as_bytes())
        .expect("parse Theben post-restart LSM5 app")
}

// --- KNXnet/IP gateway scaffolding (mirrors flash_mock.rs) ------------------

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
    Some((
        payload[0],
        payload[1],
        (payload[2] >> 4) & 0x0f,
        (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16,
    ))
}

/// CRC-16/AUG-CCITT over the segment bytes (the KNX PID_MCB_TABLE CRC).
fn crc16_aug_ccitt(data: &[u8]) -> u16 {
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

enum Reaction {
    Ack,
    Nak,
    Answer(u16, Vec<u8>),
}

fn handle_request(state: &Shared, req_apci: u16, payload: &[u8]) -> Reaction {
    let sel = req_apci & APCI_SELECTOR;

    // Device descriptor: always answer the 0705 mask.
    if sel == A_DEVICE_DESCRIPTOR_READ_SEL {
        return Reaction::Answer(
            A_DEVICE_DESCRIPTOR_RESPONSE,
            MASK_0705.to_be_bytes().to_vec(),
        );
    }

    // Basic restart (terminal): fire-and-forget — just T_ACK, no response NDT.
    if sel == A_RESTART_SEL {
        let mut s = state.lock().unwrap();
        s.restarts_seen += 1;
        if s.reboot_on_restart {
            // The device reboots: it stops answering on this connection (the tool
            // must reconnect) and — when modelling a non-persisting load — reverts
            // every LSM to Unloaded.
            s.rebooting = true;
            if s.revert_on_reboot {
                for v in s.lsm_states.values_mut() {
                    *v = LS_UNLOADED;
                }
            }
        }
        return Reaction::Ack;
    }

    // Authorize: grant level 0 for the free-access key.
    if req_apci == A_AUTHORIZE_REQUEST {
        let mut s = state.lock().unwrap();
        s.authorizes_seen += 1;
        s.authorized = true;
        return Reaction::Answer(A_AUTHORIZE_RESPONSE, vec![0x00]);
    }

    // Memory read.
    if sel == A_MEMORY_READ_SEL {
        let count = (req_apci & 0x3f) as u8;
        if payload.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        let s = state.lock().unwrap();
        // Memory-mapped LSM status: read at 0xB6EA + (lsm-1).
        let mut data = Vec::with_capacity(count as usize);
        for i in 0..count {
            let a = addr.wrapping_add(u16::from(i));
            let byte = if s.lsm_mode == LsmMode::MemoryMapped
                && (LSM_STATUS_ADDR..LSM_STATUS_ADDR + 8).contains(&a)
            {
                let lsm = (a - LSM_STATUS_ADDR + 1) as u8;
                s.lsm_state(lsm)
            } else {
                s.memory.get(&a).copied().unwrap_or(0)
            };
            data.push(byte);
        }
        let mut resp = addr.to_be_bytes().to_vec();
        resp.extend_from_slice(&data);
        return Reaction::Answer(A_MEMORY_RESPONSE | u16::from(count), resp);
    }

    // Memory write.
    if sel == A_MEMORY_WRITE_SEL {
        if payload.len() < 2 {
            return Reaction::Nak;
        }
        let count = (req_apci & 0x3f) as usize;
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        let data = &payload[2..2 + count.min(payload.len() - 2)];
        let mut s = state.lock().unwrap();
        if !s.authorized {
            return Reaction::Nak;
        }
        // A write to the memory-mapped LSM control address (0x0104) is the LSM
        // event record: [lsm][00][10-octet event]. Apply it, and ALSO store the
        // bytes so the tool's read-back verify of the control write matches.
        if s.lsm_mode == LsmMode::MemoryMapped && addr == LSM_CONTROL_ADDR {
            apply_lsm_record(&mut s, data);
            for (i, &b) in data.iter().enumerate() {
                s.memory.insert(addr.wrapping_add(i as u16), b);
            }
            return Reaction::Ack;
        }
        // Otherwise a segment content write. Store it (corrupting one octet under
        // the fault). The read-back verify then sees exactly what we stored.
        s.memory_writes_seen += 1;
        for (i, &b) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u16);
            let stored = if s.fault == Fault::CorruptStoredImage && i == 0 {
                b ^ 0xFF
            } else {
                b
            };
            s.memory.insert(a, stored);
        }
        return Reaction::Ack;
    }

    // Property value read (a full 10-bit APCI, not a selector-masked service).
    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((obj, pid, count, start)) = decode_prop_header(payload) else {
            return Reaction::Nak;
        };
        let mut s = state.lock().unwrap();
        // A memory-mapped device has NO load-state-control property: a PID-5
        // access to object 5 (or any object) is a bug in the tool's realisation
        // switch. Count it and reject, exactly as the live sim does.
        if s.lsm_mode == LsmMode::MemoryMapped && pid == PID_LOAD_STATE_CONTROL {
            if obj == 5 {
                s.lsm5_property_accesses += 1;
            }
            return Reaction::Nak;
        }
        // Object-type discovery (PID 1 on each object).
        if pid == PID_OBJECT_TYPE {
            let ot = s
                .object_types
                .get(usize::from(obj))
                .copied()
                .map(|t| t.to_be_bytes().to_vec());
            return match ot {
                Some(bytes) => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(obj, pid, 1, start, &bytes),
                ),
                None => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(obj, pid, 0, start, &[]),
                ),
            };
        }
        // Object-0 PID 78 preflight value.
        if obj == 0 && pid == PID_HARDWARE_TYPE {
            let val = s.pid78.clone();
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &val),
            );
        }
        // Property-mode LSM state read.
        if s.lsm_mode == LsmMode::Property && pid == PID_LOAD_STATE_CONTROL {
            let st = s.lsm_state(obj);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &[st]),
            );
        }
        // PID_MCB_TABLE (Jung A-A011 objects): 8-octet entry with the device CRC
        // over the segment it holds. Model a plausible readable entry.
        if pid == PID_MCB_TABLE && s.mcb_objects.contains(&obj) {
            let crc = crc16_aug_ccitt(&[0u8; 4]);
            let mut entry = vec![0x00, 0x00, 0x00, 0x04, 0x00, 0xFF];
            entry.extend_from_slice(&crc.to_be_bytes());
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, count.max(1), start, &entry),
            );
        }
        // Anything else: count 0 (absent).
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(obj, pid, 0, start, &[]),
        );
    }

    // Property value write (a full 10-bit APCI, not a selector-masked service).
    if req_apci == A_PROPERTY_VALUE_WRITE {
        let Some((obj, pid, _count, start)) = decode_prop_header(payload) else {
            return Reaction::Nak;
        };
        let value = &payload[4..];
        let mut s = state.lock().unwrap();
        if !s.authorized {
            return Reaction::Nak;
        }
        // A memory-mapped device has NO load-state-control property: a PID-5 write
        // to object 5 (or any object) means the tool wrongly drove the LSM by
        // property instead of the 0x0104 memory record. Count it and reject.
        if s.lsm_mode == LsmMode::MemoryMapped && pid == PID_LOAD_STATE_CONTROL {
            if obj == 5 {
                s.lsm5_property_accesses += 1;
            }
            return Reaction::Nak;
        }
        // Property-mode LSM control write: a 10-octet load event to PID 5.
        if s.lsm_mode == LsmMode::Property && pid == PID_LOAD_STATE_CONTROL {
            apply_lsm_event(&mut s, obj, value);
            let st = s.lsm_state(obj);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &[st]),
            );
        }
        // Echo any other property write.
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(obj, pid, 1, start, value),
        );
    }

    Reaction::Nak
}

/// Applies a memory-mapped **11-octet** LSM record (Theben 0701 form): the LSM
/// index is the high nibble of octet 0 and the event opcode its low nibble; the
/// start address occupies 3 octets. Reconstruct the 10-octet abstract event
/// (narrowing the address) and apply it.
fn apply_lsm_record(s: &mut DeviceState, record: &[u8]) {
    if record.len() < 11 {
        return;
    }
    let lsm = record[0] >> 4;
    let mut event = [0u8; 10];
    event[0] = record[0] & 0x0F;
    event[1] = record[1];
    event[2..10].copy_from_slice(&record[3..11]);
    apply_lsm_event(s, lsm, &event);
}

/// Applies a 10-octet load event to LSM `lsm`.
fn apply_lsm_event(s: &mut DeviceState, lsm: u8, event: &[u8]) {
    let Some(&opcode) = event.first() else {
        return;
    };
    let cur = s.lsm_state(lsm);
    // The AdditionalLoadControls sub-command selector (octet 1); 0x02 = Task.
    let subtype = event.get(1).copied().unwrap_or(0);
    let next = match opcode {
        LE_UNLOAD => LS_UNLOADED,
        // StartLoading opens the LSM; idempotent while already Loading (the
        // post-restart LSM-5 dance re-asserts it after the task descriptor).
        LE_START_LOADING => LS_LOADING,
        LE_LOAD_COMPLETED => {
            if cur == LS_LOADING || cur == LS_LOADED {
                LS_LOADED
            } else {
                LS_ERROR
            }
        }
        LE_ADDITIONAL => {
            // Allocation / task control: normally valid only while Loading. A
            // subtype-0x02 (Task) record on an Unloaded LSM opens the post-restart
            // descriptor dance (Theben 0701 LSM 5, spec §3/§4.7): the device opens
            // the LSM to Loading to accept the descriptor. LSMs 1/2/3 never take
            // this edge (their alloc records always follow a StartLoading).
            if cur == LS_LOADING || cur == LS_LOADED {
                cur
            } else if cur == LS_UNLOADED && subtype == 0x02 {
                LS_LOADING
            } else {
                LS_ERROR
            }
        }
        _ => cur,
    };
    s.lsm_states.insert(lsm, next);
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
                        let mut s = state.lock().unwrap();
                        // A fresh window after a death: consume one death so the
                        // next window (or a later one) eventually serves fully.
                        if s.die_after_exchanges.is_some()
                            && s.exchanges_this_connection > s.die_after_exchanges.unwrap()
                            && s.deaths_remaining > 0
                        {
                            s.deaths_remaining -= 1;
                        }
                        s.exchanges_this_connection = 0;
                        s.authorized = false;
                        // The tool reconnecting after a reboot: the device is back
                        // up and answers the fresh connection normally.
                        s.rebooting = false;
                    }
                    TpciKind::Disconnect => {}
                    TpciKind::NumberedData(client_seq) => {
                        {
                            let mut s = state.lock().unwrap();
                            s.exchanges_this_connection += 1;
                            if let Some(budget) = s.die_after_exchanges {
                                if s.deaths_remaining > 0 && s.exchanges_this_connection > budget {
                                    // This connection dies; the next fresh T_Connect
                                    // decrements the death budget so a later window
                                    // serves fully and the resume completes.
                                    continue;
                                }
                            }
                            // A rebooting device is unreachable: it went silent when
                            // it saw the restart and stays silent until the tool
                            // reconnects (a fresh T_Connect clears `rebooting`).
                            if s.rebooting {
                                continue;
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

async fn setup(mode: LsmMode, fault: Fault) -> (Transport, Shared, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let addr: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let state = fresh_device(mode, fault);
    let handle = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let bus = Transport::connect(&ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ))
    .await
    .unwrap();
    (bus, state, handle)
}

/// Authorizes a fresh L4 connection with the free-access key and wraps it in a
/// single-connection session (System 7 requires authorize before memory access).
async fn authed_session<Ch: bussard_mgmt::L4Channel>(
    mut l4: Layer4Connection<Ch>,
) -> Session<bussard_download::SingleConnector<Ch>> {
    l4.authorize_or_fail(0xFFFF_FFFF)
        .await
        .expect("free-access authorize must be granted by the mock");
    Session::from_connection(l4)
}

fn no_overrides() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::new()
}

// --- Tests -------------------------------------------------------------------

/// Point bussard's System 7 plan at the LSM realisation matching a mock device's
/// `mode`. The plan defaults to property (M2 Jung 0705 capture, issue #70), so a
/// memory-mapped mock must set `BUSSARD_FLASH_SYS7_LSM=memory`; a property mock
/// clears the override to use the default.
///
/// SAFETY: nextest runs each test in its own process (see CLAUDE.md testing
/// notes), so this process-global env write races with no other thread.
fn set_sys7_lsm_env(mode: LsmMode) {
    unsafe {
        match mode {
            LsmMode::MemoryMapped => std::env::set_var("BUSSARD_FLASH_SYS7_LSM", "memory"),
            LsmMode::Property => std::env::remove_var("BUSSARD_FLASH_SYS7_LSM"),
        }
    }
}

async fn run_full_flash(mode: LsmMode) -> Result<(), Box<dyn std::error::Error>> {
    // Select the plan's LSM realisation to match the mock device's mode. Since the
    // M2 Jung 0705 capture (issue #70) the plan defaults to property, so a
    // memory-mapped mock must flip bussard's realisation switch, exactly as the
    // system7 example's run.sh does with `BUSSARD_FLASH_SYS7_LSM=memory`.
    set_sys7_lsm_env(mode);
    let (mut bus, state, handle) = setup(mode, Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();
    let app = mdt_canonical_app();
    let plan = plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    assert!(
        plan.is_sys7(),
        "MDT canonical app must lower to a System 7 plan"
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;

    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    {
        let s = state.lock().unwrap();
        assert!(s.authorizes_seen >= 1, "the tool must authorize");
        assert!(s.memory_writes_seen >= 1, "segment content must be written");
        assert_eq!(s.restarts_seen, 1, "one terminal restart");
        // All three LSMs reached Loaded.
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm} should be Loaded");
        }
        // The 0x4000 mask preserved the device-owned byte 2 (never written).
        assert_eq!(s.memory.get(&0x4000).copied(), Some(0x00));
        assert_eq!(s.memory.get(&0x4001).copied(), Some(0x01));
        // Byte at 0x4002 was device-owned (mask 0x00) — the tool never wrote it.
        assert!(
            !s.memory.contains_key(&0x4002),
            "masked byte left untouched"
        );
        assert_eq!(s.memory.get(&0x4003).copied(), Some(0x03));
    }
    handle.abort();
    let _ = session.into_disconnect().await;
    Ok(())
}

#[tokio::test]
async fn flash_system7_memory_mapped_reaches_loaded() -> Result<(), Box<dyn std::error::Error>> {
    run_full_flash(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn flash_system7_verify_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
    // A device that corrupts every stored write: the per-chunk read-back verify
    // inside write_memory_verified diverges and the flash fails at that write.
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, _state, handle) = setup(LsmMode::MemoryMapped, Fault::CorruptStoredImage).await;
    let target: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();
    let app = mdt_canonical_app();
    let plan = plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await;
    let result = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await;
    // A corrupted stored image must NOT report a successful flash: either the
    // write path errors, or the post-flash read-back spot check diverges and the
    // outcome is not `ok()`.
    let succeeded = matches!(result, Ok(ref o) if o.ok());
    assert!(
        !succeeded,
        "a corrupted stored image must not report success: {result:?}"
    );
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn flash_system7_resumes_across_a_connection_drop() -> Result<(), Box<dyn std::error::Error>>
{
    // The device drops the L4 connection mid-download; the tool must reconnect and
    // resume. This needs a reconnecting session (LeaseConnector), so use the bus
    // actor. Model a generous budget so the drop lands mid-procedure but the
    // resume completes.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let addr: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let state = fresh_device(LsmMode::MemoryMapped, Fault::None);
    {
        let mut s = state.lock().unwrap();
        // The device drops the L4 connection once, after 6 exchanges; the tool
        // reconnects and resumes, and the second window serves fully.
        s.die_after_exchanges = Some(6);
        s.deaths_remaining = 1;
    }
    let gw = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let (handle, _actor) = bussard_bus::Bus::connect(ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ));
    handle.wait_connected(Duration::from_secs(5)).await;

    let connector = LeaseConnector {
        handle: handle.clone(),
        target: "1.1.99".parse().unwrap(),
        source: "0.0.255".parse().unwrap(),
    };
    let mut session = Session::open_with_key(connector, None).await?;
    let app = mdt_canonical_app();
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let plan = plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;
    assert!(
        outcome.ok(),
        "flash should resume and reach Loaded: {outcome:?}"
    );
    {
        let s = state.lock().unwrap();
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED);
        }
    }
    gw.abort();
    let _ = session.into_disconnect().await;
    Ok(())
}

/// Runs a full MDT-canonical flash with `verify_after_restart` against a device
/// that **reboots** on the terminal restart (drops the L4 connection). `revert`
/// selects whether the load persists across the reboot (`false`, the honest
/// success) or silently reverts to Unloaded (`true`, the false-positive the
/// after-restart verify must catch). Returns the flash result and the shared
/// device state for assertions.
async fn run_flash_with_reboot(
    revert: bool,
) -> Result<
    (
        Result<bussard_download::FlashOutcome, bussard_mgmt::load::WriteError>,
        Shared,
    ),
    Box<dyn std::error::Error>,
> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let addr: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let state = fresh_device(LsmMode::MemoryMapped, Fault::None);
    {
        let mut s = state.lock().unwrap();
        s.reboot_on_restart = true;
        s.revert_on_reboot = revert;
    }
    let gw = tokio::spawn(run_gateway(sock, addr, Arc::clone(&state)));
    let (handle, _actor) = bussard_bus::Bus::connect(ConnectionConfig::tunnel(
        format!("127.0.0.1:{port}").parse().unwrap(),
    ));
    handle.wait_connected(Duration::from_secs(5)).await;

    let connector = LeaseConnector {
        handle: handle.clone(),
        target: "1.1.99".parse().unwrap(),
        source: "0.0.255".parse().unwrap(),
    };
    let mut session = Session::open_with_key(connector, None).await?;
    let app = mdt_canonical_app();
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let plan = plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    // Verify AFTER the restart: the reconnecting session re-opens the connection
    // once the (fast, test-tuned) reboot wait elapses, then re-reads the LSM state.
    // Shrink the reboot wait so the test does not stall on the 10 s production wait.
    // SAFETY: nextest runs each test in its own process (see CLAUDE.md testing
    // notes), so this process-global env write races with no other thread; the two
    // reboot tests set the same value and no other test reads it.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    let options = bussard_download::FlashOptions {
        bcu_key: None,
        verify_after_restart: true,
        ..Default::default()
    };
    let result = flash(&mut session, &plan, options, |_p| {}).await;
    gw.abort();
    let _ = session.into_disconnect().await;
    Ok((result, state))
}

#[tokio::test]
async fn flash_system7_verifies_after_restart_reaches_loaded()
-> Result<(), Box<dyn std::error::Error>> {
    // The device reboots on the terminal restart and the load PERSISTS. The
    // after-restart verify must reconnect and re-read the LSM state on the fresh
    // connection (a read on the dropped pre-restart connection would be rejected
    // as "no open connection"), then report the honest `Loaded`.
    let (result, state) = run_flash_with_reboot(false).await?;
    let outcome = result?;
    assert!(
        outcome.ok(),
        "a persisting load must verify Loaded after the reboot: {outcome:?}"
    );
    let s = state.lock().unwrap();
    assert_eq!(s.restarts_seen, 1, "one terminal restart");
    for lsm in [1u8, 2, 3] {
        assert_eq!(
            s.lsm_state(lsm),
            LS_LOADED,
            "LSM {lsm} should still be Loaded after the reboot"
        );
    }
    Ok(())
}

#[tokio::test]
async fn flash_system7_after_restart_verify_catches_reverted_load()
-> Result<(), Box<dyn std::error::Error>> {
    // The device reboots on the terminal restart and the load does NOT persist:
    // every LSM reverts to Unloaded. Verifying BEFORE the restart would read the
    // transient `Loaded` and wrongly report success — the exact false-positive the
    // after-restart verify exists to catch. It must NOT report a successful flash.
    let (result, state) = run_flash_with_reboot(true).await?;
    let succeeded = matches!(result, Ok(ref o) if o.ok());
    assert!(
        !succeeded,
        "a load that reverted to Unloaded after the reboot must not report success: {result:?}"
    );
    let s = state.lock().unwrap();
    assert_eq!(s.restarts_seen, 1, "the restart still fired");
    Ok(())
}

/// A [`bussard_download::Connector`] that leases the bus actor to (re)open an L4
/// connection (the reconnecting-session shape).
struct LeaseConnector {
    handle: bussard_bus::BusHandle,
    target: bussard_model::IndividualAddress,
    source: bussard_model::IndividualAddress,
}

impl bussard_download::Connector for LeaseConnector {
    type Channel = bussard_mgmt::LeaseChannel;

    async fn connect(
        &mut self,
    ) -> Result<Layer4Connection<bussard_mgmt::LeaseChannel>, bussard_mgmt::load::WriteError> {
        let lease = self.handle.lease().await.map_err(|_| {
            bussard_mgmt::load::WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = bussard_mgmt::LeaseChannel::new(lease);
        Layer4Connection::connect(channel, self.target, self.source)
            .await
            .map_err(bussard_mgmt::load::WriteError::Mgmt)
    }
}

/// A focused unit test of the LsmAccess Property seam against the mock device
/// driven in Property mode: StartLoading → Loading, LoadCompleted → Loaded.
#[tokio::test]
async fn lsm_access_property_drives_state() -> Result<(), Box<dyn std::error::Error>> {
    use bussard_mgmt::LsmAccess;
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let lsm = LsmAccess::Property;
    lsm.drive(&mut l4, 1, bussard_mgmt::LoadControl::StartLoading)
        .await?;
    assert_eq!(state.lock().unwrap().lsm_state(1), LS_LOADING);
    lsm.drive(&mut l4, 1, bussard_mgmt::LoadControl::LoadCompleted)
        .await?;
    assert_eq!(state.lock().unwrap().lsm_state(1), LS_LOADED);
    assert_eq!(lsm.read_state(&mut l4, 1).await?, LoadState::Loaded);
    handle.abort();
    Ok(())
}

/// A **memory-mapped** device with a **post-restart LSM-5** section (spec §3/§4.7,
/// the Theben 0701 shape) must reach Loaded, and every LSM — including the
/// post-restart LSM 5 — must be driven through the memory-mapped 0x0104 record,
/// never a property `A_PropertyValue` access to object 5 / PID 5. This is the
/// corner that broke the live `run.sh` device 1.1.8: a memory-mapped device has
/// no PID-5 property, so any property access to object 5 fails the flash. The
/// mock rejects (and counts) such an access, so the assertion below fails loudly
/// if the executor ever drives LSM 5 off the `LsmAccess` seam.
#[tokio::test]
async fn flash_system7_memory_mapped_post_restart_lsm5_reaches_loaded()
-> Result<(), Box<dyn std::error::Error>> {
    // 0701 defaults to memory-mapped; also flip the switch explicitly so the plan
    // and the mock device agree on the realisation.
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, state, handle) = setup(LsmMode::MemoryMapped, Fault::None).await;
    let target: bussard_model::IndividualAddress = "1.1.99".parse().unwrap();
    let source: bussard_model::IndividualAddress = "0.0.255".parse().unwrap();
    let app = theben_post_restart_lsm5_app();
    // Mask 0x0701 → memory-mapped LSM realisation by mask-family default.
    let plan = plan_flash(
        &app,
        "1.1.99",
        0x0701,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    assert!(
        plan.is_sys7(),
        "the Theben app must lower to a System 7 plan"
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;

    assert!(
        outcome.ok(),
        "memory-mapped post-restart LSM-5 flash should reach Loaded: {outcome:?}"
    );
    {
        let s = state.lock().unwrap();
        // LSMs 1/2/3 completed and persisted.
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm} should be Loaded");
        }
        // The post-restart LSM 5 was opened (Loading, no LoadCompleted in the plan)
        // via the memory-mapped record — never Error/Unloaded.
        assert_eq!(
            s.lsm_state(5),
            LS_LOADING,
            "post-restart LSM 5 should be open (Loading)"
        );
        // The load-bearing assertion: NO property access to object 5 / PID 5. A
        // memory-mapped device has no such property; driving LSM 5 that way is the
        // exact bug this test guards against.
        assert_eq!(
            s.lsm5_property_accesses, 0,
            "LSM 5 must be driven memory-mapped, never via object-5/PID-5 property"
        );
    }
    handle.abort();
    let _ = session.into_disconnect().await;
    Ok(())
}
