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
//! drop-and-resume, and a verify-mismatch failure — plus the **incremental link
//! path** (issue #91) against the same device: `read_sys7_tables` → `plan` →
//! `apply_sys7_tables` → read back (the `reconstruct` check), in both LSM
//! realisations, on a device whose LSMs start `Loaded` with a real table image in
//! memory.
//!
//! **The flash and apply paths are only ever exercised here — never against a
//! live bus.**

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{
    FlashStep, Session, apply_sys7_tables, compute_tables, flash, plan, plan_flash,
    read_sys7_tables, sys7_table_images,
};
use bussard_mgmt::LsmAccess;
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::LoadState;
use bussard_prod::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::{Inbound, MockDevice, MockGateway, Reaction, Verdict};
use bussard_transport::cemi::Destination;
use bussard_transport::knxnet::ServiceType;
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

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
const PID_DEVICE_CONTROL: u8 = 14;
/// `PID_DEVICE_CONTROL` bit 2: the device echoes every `A_Memory_Write`.
const DEVICE_CONTROL_VERIFY_MODE: u8 = 0x04;
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
    /// Every load event applied, as `(lsm, opcode)`, so a parameter-only
    /// download can be shown to unload nothing and touch only LSM 3 (#119).
    lsm_events: Vec<(u8, u8)>,
    /// The address and length of every segment content write.
    segment_writes: Vec<(u16, usize)>,
    /// Interface objects the device does not have: in property mode a
    /// `PID_LOAD_STATE_CONTROL` read or write of one answers count 0, as the
    /// Jung 2308.16REGHM does for object 5 (issue #178).
    absent_objects: Vec<u8>,
    /// `obj0/PID_DEVICE_CONTROL` (RAM: a restart clears it). With the
    /// verify-mode bit set the device answers every `A_Memory_Write` with an
    /// `A_Memory_Response` echo of the stored octets, as a real 0705 does.
    device_control: u8,
    /// Every value written to `obj0/PID_DEVICE_CONTROL`, in order.
    device_control_writes: Vec<u8>,
    /// The segment-write count at each restart, so a test can place the
    /// restarts relative to the download (issue #116).
    restart_at_writes: Vec<usize>,
    /// How many `A_Memory_Response` verify echoes the device sent.
    verify_echoes_sent: usize,
    /// How many load-state reads the tool made (property `PID_LOAD_STATE_CONTROL`
    /// reads, or memory-mapped status reads at `0xB6EA+`).
    lsm_state_reads: usize,
    /// Every numbered request the device answered or acknowledged.
    requests_seen: usize,
    /// A gateway link outage in the reconnect phase after a restart (issue
    /// #192): `(restart, after_frame, duration)` takes the link down for
    /// `duration` at the `after_frame + 1`-th numbered frame the tool sends
    /// after the `restart`-th restart (1-based) — the testkit
    /// `outage(after_frame, duration)` fault counted from that restart. The
    /// device drops its L4 connection while the link is down. Taken once it
    /// trips.
    restart_outage: Option<(usize, u32, Duration)>,
    /// Set once the restart `restart_outage` waits for was seen.
    restart_outage_armed: bool,
    /// Numbered frames to the device since the arming restart.
    restart_outage_frames: u32,
    /// While the link is down: when it comes back.
    tunnel_down_until: Option<tokio::time::Instant>,
    /// Datagrams the outage swallowed.
    outage_swallowed: usize,
    /// Set when an outage ended; the device answers no numbered frame until a
    /// fresh T_Connect.
    l4_dead_after_outage: bool,
    /// KNXnet/IP CONNECT_REQUESTs answered (tunnel (re)establishments).
    tunnel_connects: usize,
}

impl DeviceState {
    fn lsm_state(&self, lsm: u8) -> u8 {
        self.lsm_states.get(&lsm).copied().unwrap_or(LS_UNLOADED)
    }
}

type Shared = Arc<Mutex<DeviceState>>;

/// Locks the device state; a test that panicked while holding it has already
/// failed, so a poisoned lock is taken over as is.
fn lock(state: &Shared) -> std::sync::MutexGuard<'_, DeviceState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
        lsm_events: Vec::new(),
        segment_writes: Vec::new(),
        absent_objects: Vec::new(),
        device_control: 0,
        device_control_writes: Vec::new(),
        restart_at_writes: Vec::new(),
        verify_echoes_sent: 0,
        lsm_state_reads: 0,
        requests_seen: 0,
        restart_outage: None,
        restart_outage_armed: false,
        restart_outage_frames: 0,
        tunnel_down_until: None,
        outage_swallowed: 0,
        l4_dead_after_outage: false,
        tunnel_connects: 0,
    }))
}

/// The MDT A-000E canonical System 7 app (mask 0705): obj0/PID78 preflight,
/// three LSMs, a 0x4000 table segment with a `<Mask>`, a 0x0700 allocate-only RAM
/// segment, a 0x4400 param segment, a TaskSegment per loaded LSM, a restart.
fn mdt_canonical_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
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
    parse_application_program("M-83_A-E", xml.as_bytes())
        .map_err(|e| format!("parse MDT S7 app: {e}").into())
}

/// A Theben-style 0701 app with a **post-restart LSM-5** section (spec §3/§4.7):
/// LSMs 1/2/3 load normally, the device restarts, then a TaskSegment + Load are
/// issued on LSM 5 (a fourth machine the device opens only after the restart).
/// This is the memory-mapped × post-restart-LSM5 corner that no earlier mock or
/// replay test exercised — the shape that broke the live `run.sh` device 1.1.8.
fn theben_post_restart_lsm5_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
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
        .map_err(|e| format!("parse Theben post-restart LSM5 app: {e}").into())
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

fn handle_request(state: &Shared, req_apci: u16, payload: &[u8]) -> Reaction {
    let sel = req_apci & APCI_SELECTOR;
    lock(state).requests_seen += 1;

    // Device descriptor: always answer the 0705 mask.
    if sel == A_DEVICE_DESCRIPTOR_READ_SEL {
        return Reaction::Answer(
            A_DEVICE_DESCRIPTOR_RESPONSE,
            MASK_0705.to_be_bytes().to_vec(),
        );
    }

    // Basic restart (terminal): fire-and-forget — just T_ACK, no response NDT.
    if sel == A_RESTART_SEL {
        let mut s = lock(state);
        s.restarts_seen += 1;
        if s.restart_outage
            .is_some_and(|(nth, _, _)| nth == s.restarts_seen)
        {
            s.restart_outage_armed = true;
            s.restart_outage_frames = 0;
        }
        let writes = s.memory_writes_seen;
        s.restart_at_writes.push(writes);
        // PID_DEVICE_CONTROL lives in RAM: the restart clears verify mode.
        s.device_control = 0;
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
        let mut s = lock(state);
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
        let mut s = lock(state);
        if s.lsm_mode == LsmMode::MemoryMapped
            && (LSM_STATUS_ADDR..LSM_STATUS_ADDR + 8).contains(&addr)
        {
            s.lsm_state_reads += 1;
        }
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
        let mut s = lock(state);
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
        s.segment_writes.push((addr, data.len()));
        for (i, &b) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u16);
            let stored = if s.fault == Fault::CorruptStoredImage && i == 0 {
                b ^ 0xFF
            } else {
                b
            };
            s.memory.insert(a, stored);
        }
        // Verify mode: echo the stored octets back, as the Jung 0705 captures
        // show (`A_Memory_Write 0x47ca` answered by `A_Memory_Response 0x47ca`).
        if s.device_control & DEVICE_CONTROL_VERIFY_MODE != 0 {
            s.verify_echoes_sent += 1;
            let mut echo = addr.to_be_bytes().to_vec();
            for i in 0..data.len() {
                let a = addr.wrapping_add(i as u16);
                echo.push(s.memory.get(&a).copied().unwrap_or(0));
            }
            return Reaction::Answer(A_MEMORY_RESPONSE | count as u16, echo);
        }
        return Reaction::Ack;
    }

    // Property value read (a full 10-bit APCI, not a selector-masked service).
    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((obj, pid, count, start)) = decode_prop_header(payload) else {
            return Reaction::Nak;
        };
        let mut s = lock(state);
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
        // Device control (verify mode and friends).
        if obj == 0 && pid == PID_DEVICE_CONTROL {
            let val = s.device_control;
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &[val]),
            );
        }
        // Object-0 PID 78 preflight value.
        if obj == 0 && pid == PID_HARDWARE_TYPE {
            let val = s.pid78.clone();
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &val),
            );
        }
        // Property-mode LSM state read. An absent object answers count 0.
        if s.lsm_mode == LsmMode::Property && pid == PID_LOAD_STATE_CONTROL {
            if s.absent_objects.contains(&obj) {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(obj, pid, 0, start, &[]),
                );
            }
            s.lsm_state_reads += 1;
            let st = s.lsm_state(obj);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &[st]),
            );
        }
        // PID_MCB_TABLE (Jung A-A011 objects): 8-octet entry with the device CRC
        // over the segment it holds. Model a plausible readable entry.
        //
        // ONE entry per request. A real Jung 3361-1MWW (mask 0705, application
        // `M-0004_A-A011-13`) REFUSED a multi-element read — bussard sent
        // `A_PropertyValue_Read obj=3 pid=27 count=6 start=1`, straight from
        // `LdCtrlLoadImageProp ObjIdx="3" PropId="27" Count="6"`, and the device
        // answered count 0 with no data (issue #89 campaign, 1.1.36). Six
        // 8-octet entries are 48 octets of value, nowhere near a standard-frame
        // APDU, and a real device does not partially answer: it refuses the
        // whole read. The 1.1.31 ETS capture reads the six entries one at a
        // time, `count=1` at index 1..=6, which is what bussard does now.
        if pid == PID_MCB_TABLE && s.mcb_objects.contains(&obj) {
            if count > 1 {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(obj, pid, 0, start, &[]),
                );
            }
            let crc = crc16_aug_ccitt(&[0u8; 4]);
            let mut entry = vec![0x00, 0x00, 0x00, 0x04, 0x00, 0xFF];
            entry.extend_from_slice(&crc.to_be_bytes());
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &entry),
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
        let mut s = lock(state);
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
        // Property-mode LSM control write: a 10-octet load event to PID 5. An
        // absent object refuses it with count 0.
        if s.lsm_mode == LsmMode::Property && pid == PID_LOAD_STATE_CONTROL {
            if s.absent_objects.contains(&obj) {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(obj, pid, 0, start, &[]),
                );
            }
            apply_lsm_event(&mut s, obj, value);
            let st = s.lsm_state(obj);
            return Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(obj, pid, 1, start, &[st]),
            );
        }
        if obj == 0
            && pid == PID_DEVICE_CONTROL
            && let Some(&v) = value.first()
        {
            s.device_control = v;
            s.device_control_writes.push(v);
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
    s.lsm_events.push((lsm, opcode));
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

/// The gateway-level fault of issue #192: a link outage in the reconnect phase
/// after a restart. Nothing gets through while it lasts; when it ends the device
/// has dropped its L4 connection. Also counts tunnel (re)establishments.
fn gateway_faults(
    state: &Shared,
    address: bussard_model::IndividualAddress,
    inbound: &Inbound<'_>,
) -> Verdict {
    let mut s = lock(state);
    match s.tunnel_down_until {
        Some(until) if tokio::time::Instant::now() < until => {
            s.outage_swallowed += 1;
            return Verdict::Swallow;
        }
        Some(_) => {
            s.tunnel_down_until = None;
            s.l4_dead_after_outage = true;
        }
        None => {}
    }
    if s.restart_outage_armed
        && let Some(cemi) = inbound.cemi
        && cemi.destination == Destination::Individual(address)
        && matches!(tpci::classify(cemi.tpci_octet()), TpciKind::NumberedData(_))
    {
        s.restart_outage_frames += 1;
        if let Some((_, after, duration)) = s.restart_outage
            && s.restart_outage_frames > after
        {
            s.restart_outage = None;
            s.restart_outage_armed = false;
            s.tunnel_down_until = tokio::time::Instant::now().checked_add(duration);
            s.outage_swallowed += 1;
            return Verdict::Swallow;
        }
    }
    if inbound.service == ServiceType::ConnectRequest {
        s.tunnel_connects += 1;
    }
    Verdict::Serve
}

/// The device's reaction to a fresh `T_Connect`.
fn on_t_connect(state: &Shared) {
    let mut s = lock(state);
    // A fresh window after a death: consume one death so the next window (or a
    // later one) eventually serves fully.
    if let Some(budget) = s.die_after_exchanges
        && s.exchanges_this_connection > budget
        && s.deaths_remaining > 0
    {
        s.deaths_remaining -= 1;
    }
    s.exchanges_this_connection = 0;
    s.authorized = false;
    // The tool reconnecting after a reboot: the device is back up and answers
    // the fresh connection normally.
    s.rebooting = false;
    s.l4_dead_after_outage = false;
}

/// The device's reaction to one numbered request: the per-connection death
/// budget and reboot silence first, then [`handle_request`].
fn on_numbered(state: &Shared, apci: u16, data: &[u8]) -> Reaction {
    {
        let mut s = lock(state);
        s.exchanges_this_connection += 1;
        if let Some(budget) = s.die_after_exchanges
            && s.deaths_remaining > 0
            && s.exchanges_this_connection > budget
        {
            // This connection dies; the next fresh T_Connect decrements the death
            // budget so a later window serves fully and the resume completes.
            return Reaction::Silent;
        }
        // A rebooting device is unreachable: it went silent when it saw the
        // restart and stays silent until the tool reconnects (a fresh T_Connect
        // clears `rebooting`).
        if s.rebooting || s.l4_dead_after_outage {
            return Reaction::Silent;
        }
    }
    handle_request(state, apci, data)
}

/// The device's individual address on the mock line.
const DEVICE: &str = "1.1.99";

/// Starts the mock gateway with the System 7 device model behind it.
async fn start_gateway(state: &Shared) -> Result<MockGateway, Box<dyn std::error::Error>> {
    let addr: bussard_model::IndividualAddress = DEVICE.parse()?;
    let (faults, connects, requests) = (Arc::clone(state), Arc::clone(state), Arc::clone(state));
    Ok(MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        // A tool that re-establishes the tunnel sends DISCONNECT first; keep
        // serving so its follow-up CONNECT is answered.
        .keep_serving()
        .intercept(move |inbound| gateway_faults(&faults, addr, inbound))
        .device(
            MockDevice::new(addr)
                .with_control_hook(move |_, kind| {
                    if kind == TpciKind::Connect {
                        on_t_connect(&connects);
                    }
                    Vec::new()
                })
                .with_hook(move |_, apci, data| Some(on_numbered(&requests, apci, data))),
        )
        .start()
        .await?)
}

async fn setup(
    mode: LsmMode,
    fault: Fault,
) -> Result<(Transport, Shared, MockGateway), Box<dyn std::error::Error>> {
    let state = fresh_device(mode, fault);
    let handle = start_gateway(&state).await?;
    let bus = Transport::connect(
        &ConnectionConfig::tunnel(handle.addr())
            // These tests abort the mock gateway before the final T_Disconnect; with
            // the issue #177 re-establish on, that send would ride out the full budget.
            .with_reconnect(bussard_transport::TunnelReconnect::disabled()),
    )
    .await?;
    Ok((bus, state, handle))
}

/// Authorizes a fresh L4 connection with the free-access key and wraps it in a
/// single-connection session (System 7 requires authorize before memory access).
async fn authed_session<Ch: bussard_mgmt::L4Channel>(
    mut l4: Layer4Connection<Ch>,
) -> Result<Session<bussard_download::SingleConnector<Ch>>, Box<dyn std::error::Error>> {
    // The mock grants the free-access key.
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    Ok(Session::from_connection(l4))
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
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = mdt_canonical_app()?;
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
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;

    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    {
        let s = lock(&state);
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
    drop(handle);
    let _ = session.into_disconnect().await;
    Ok(())
}

#[tokio::test]
async fn flash_system7_memory_mapped_reaches_loaded() -> Result<(), Box<dyn std::error::Error>> {
    run_full_flash(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn flash_system7_verify_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
    // A device that corrupts every stored write: the flash must not report
    // success — either a step's own compare fails, or the post-flash read-back
    // spot check diverges.
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, _state, handle) = setup(LsmMode::MemoryMapped, Fault::CorruptStoredImage).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = mdt_canonical_app()?;
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
    let mut session = authed_session(l4).await?;
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
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_system7_resumes_across_a_connection_drop() -> Result<(), Box<dyn std::error::Error>>
{
    // The device drops the L4 connection mid-download; the tool must reconnect and
    // resume. This needs a reconnecting session (LeaseConnector), so use the bus
    // actor. Model a generous budget so the drop lands mid-procedure but the
    // resume completes.
    let state = fresh_device(LsmMode::MemoryMapped, Fault::None);
    {
        let mut s = lock(&state);
        // The device drops the L4 connection once, after 6 exchanges; the tool
        // reconnects and resumes, and the second window serves fully.
        s.die_after_exchanges = Some(6);
        s.deaths_remaining = 1;
    }
    let gw = start_gateway(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(
        ConnectionConfig::tunnel(gw.addr())
            // These tests abort the mock gateway before the final T_Disconnect; with
            // the issue #177 re-establish on, that send would ride out the full budget.
            .with_reconnect(bussard_transport::TunnelReconnect::disabled()),
    );
    handle.wait_connected(Duration::from_secs(5)).await;

    let connector = LeaseConnector {
        handle: handle.clone(),
        target: "1.1.99".parse()?,
        source: "0.0.255".parse()?,
        timeouts: Some(fast_timeouts()),
    };
    let mut session = Session::open_with_key(connector, None).await?;
    let app = mdt_canonical_app()?;
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
        let s = lock(&state);
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED);
        }
    }
    drop(gw);
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
    let state = fresh_device(LsmMode::MemoryMapped, Fault::None);
    {
        let mut s = lock(&state);
        s.reboot_on_restart = true;
        s.revert_on_reboot = revert;
    }
    let gw = start_gateway(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(
        ConnectionConfig::tunnel(gw.addr())
            // These tests abort the mock gateway before the final T_Disconnect; with
            // the issue #177 re-establish on, that send would ride out the full budget.
            .with_reconnect(bussard_transport::TunnelReconnect::disabled()),
    );
    handle.wait_connected(Duration::from_secs(5)).await;

    let connector = LeaseConnector {
        handle: handle.clone(),
        target: "1.1.99".parse()?,
        source: "0.0.255".parse()?,
        timeouts: None,
    };
    let mut session = Session::open_with_key(connector, None).await?;
    let app = mdt_canonical_app()?;
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
    drop(gw);
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
    let s = lock(&state);
    // ETS's pre-download restart before the first segment write, then the
    // terminal one after the last (issue #116).
    assert_eq!(
        s.restarts_seen, 2,
        "pre-download restart + terminal restart"
    );
    assert_eq!(s.restart_at_writes.first(), Some(&0));
    assert_eq!(s.restart_at_writes.get(1), Some(&s.memory_writes_seen));
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
    let s = lock(&state);
    assert_eq!(
        s.restarts_seen, 2,
        "the pre-download and the terminal restart still fired"
    );
    Ok(())
}

/// A [`bussard_download::Connector`] that leases the bus actor to (re)open an L4
/// connection (the reconnecting-session shape).
struct LeaseConnector {
    handle: bussard_bus::BusHandle,
    target: bussard_model::IndividualAddress,
    source: bussard_model::IndividualAddress,
    /// The L4 timeout budget each opened connection uses. `None` keeps the
    /// default (3 s ACK/response); the drop-and-resume test sets a tiny budget
    /// so the modelled silence of a dropped connection is detected in
    /// milliseconds rather than seconds. Mirrors `flash_mock.rs`.
    timeouts: Option<bussard_mgmt::Timeouts>,
}

/// A tiny L4 timeout budget for the drop-and-resume test: the connection the
/// mock drops goes silent, and with the default 3 s ACK budget x repetitions
/// each drop costs seconds of pure waiting. Mirrors `flash_mock.rs`.
fn fast_timeouts() -> bussard_mgmt::Timeouts {
    bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(50),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(50),
    }
}

impl bussard_download::Connector for LeaseConnector {
    type Channel = bussard_mgmt::LeaseChannel;

    async fn connect(
        &mut self,
    ) -> Result<Layer4Connection<bussard_mgmt::LeaseChannel>, bussard_mgmt::load::WriteError> {
        // After a gateway link loss wait for the re-established tunnel, as the
        // CLI's connector does; immediate when connected.
        self.handle
            .wait_connected(self.handle.reconnect_budget())
            .await;
        let lease = self.handle.lease().await.map_err(|_| {
            bussard_mgmt::load::WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = bussard_mgmt::LeaseChannel::new(lease);
        let timeouts = self.timeouts.unwrap_or_default();
        Layer4Connection::connect_with(channel, self.target, self.source, timeouts)
            .await
            .map_err(bussard_mgmt::load::WriteError::Mgmt)
    }

    fn link_losses(&self) -> u64 {
        self.handle.link_losses()
    }
}

/// A focused unit test of the LsmAccess Property seam against the mock device
/// driven in Property mode: StartLoading → Loading, LoadCompleted → Loaded.
#[tokio::test]
async fn lsm_access_property_drives_state() -> Result<(), Box<dyn std::error::Error>> {
    use bussard_mgmt::LsmAccess;
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let lsm = LsmAccess::Property;
    lsm.drive(&mut l4, 1, bussard_mgmt::LoadControl::StartLoading)
        .await?;
    assert_eq!(lock(&state).lsm_state(1), LS_LOADING);
    lsm.drive(&mut l4, 1, bussard_mgmt::LoadControl::LoadCompleted)
        .await?;
    assert_eq!(lock(&state).lsm_state(1), LS_LOADED);
    assert_eq!(lsm.read_state(&mut l4, 1).await?, LoadState::Loaded);
    drop(handle);
    Ok(())
}

/// A **memory-mapped** device whose procedure carries a **post-restart LSM-5**
/// tail (the Theben FIX2 `M-0048_A-4947` shape: `LdCtrlRestart`, then a
/// TaskSegment and a Load on LSM 5). ETS ends every System 7 download at the
/// restart (the 0701 Meteodata and 0705 2308.16REGHM captures), and a device
/// can lack object 5 altogether (issue #178), so the plan ends at the restart:
/// the flash reaches Loaded, LSM 5 is never touched, and in particular never
/// through an object-5/PID-5 property access, which a memory-mapped device
/// rejects (the live `run.sh` device 1.1.8).
#[tokio::test]
async fn flash_system7_memory_mapped_post_restart_lsm5_tail_is_not_run()
-> Result<(), Box<dyn std::error::Error>> {
    // 0701 defaults to memory-mapped; also flip the switch explicitly so the plan
    // and the mock device agree on the realisation.
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, state, handle) = setup(LsmMode::MemoryMapped, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = theben_post_restart_lsm5_app()?;
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
    assert!(
        matches!(plan.steps.last(), Some(FlashStep::Restart)),
        "the plan must end at the restart: {:?}",
        plan.steps.last()
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;

    assert!(
        outcome.ok(),
        "memory-mapped flash should reach Loaded: {outcome:?}"
    );
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    {
        let s = state.lock().map_err(|e| e.to_string())?;
        // LSMs 1/2/3 completed and persisted.
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm} should be Loaded");
        }
        assert!(
            s.lsm_events.iter().all(|(lsm, _)| *lsm != 5),
            "LSM 5 must not be driven: {:?}",
            s.lsm_events
        );
        assert_eq!(
            s.lsm5_property_accesses, 0,
            "LSM 5 must never be accessed via object-5/PID-5 property"
        );
    }
    drop(handle);
    let _ = session.into_disconnect().await;
    Ok(())
}

/// Issue #178: a property-mode device without object 5 answers its
/// `PID_LOAD_STATE_CONTROL` read with count 0 (`05 05 00 01`). That is an
/// absent object, not a malformed response.
#[tokio::test]
async fn test_lsm_access_read_state_count_zero_is_object_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await?;
    state.lock().map_err(|e| e.to_string())?.absent_objects = vec![5];
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let lsm = LsmAccess::Property;

    let read = lsm.read_state(&mut l4, 5).await;
    assert!(
        matches!(
            read,
            Err(bussard_mgmt::load::WriteError::ObjectAbsent {
                object_index: 5,
                ..
            })
        ),
        "{read:?}"
    );
    let message = read.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        message.contains("object 5 absent on the device"),
        "{message}"
    );
    assert!(!message.contains("malformed"), "{message}");

    // A load event written to the absent object is refused the same way.
    let drive = lsm
        .drive(&mut l4, 5, bussard_mgmt::LoadControl::StartLoading)
        .await;
    assert!(
        matches!(
            drive,
            Err(bussard_mgmt::load::WriteError::ObjectAbsent {
                object_index: 5,
                ..
            })
        ),
        "{drive:?}"
    );
    // An object the device has still reads normally.
    assert_eq!(lsm.read_state(&mut l4, 1).await?, LoadState::Unloaded);
    drop(handle);
    Ok(())
}

/// Issue #178: a completed download is not failed by a step after the final
/// restart. A hand-built plan (the planner emits no such step) with the
/// 2308.16REGHM's converted tail, a TaskSegment and a StartLoading on an
/// object 5 the device lacks, still verifies Loaded; the skipped steps are
/// reported as warnings naming the absent object. An Unload of the absent
/// object up front is skipped with a warning too.
#[tokio::test]
async fn test_flash_sys7_post_restart_step_on_absent_object_warns()
-> Result<(), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(LsmMode::Property);
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await?;
    state.lock().map_err(|e| e.to_string())?.absent_objects = vec![5];
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut plan = plan_flash(
        &mdt_canonical_app()?,
        "1.1.99",
        0x0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    assert!(matches!(plan.steps.last(), Some(FlashStep::Restart)));
    plan.steps.insert(0, FlashStep::Sys7Unload { lsm: 5 });
    plan.steps.push(FlashStep::Sys7TaskSegment {
        lsm: 5,
        address: 0x43FF,
        marker: [0x04, 0x20, 0x88, 0x11],
    });
    plan.steps.push(FlashStep::Sys7StartLoading { lsm: 5 });

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;

    assert!(outcome.ok(), "the download is complete: {outcome:?}");
    assert_eq!(outcome.warnings.len(), 3, "{:?}", outcome.warnings);
    assert!(
        outcome.warnings[0].contains("object 5 absent on the device, nothing to unload"),
        "{:?}",
        outcome.warnings
    );
    for warning in &outcome.warnings[1..] {
        assert!(
            warning.contains("after the final restart failed and was skipped")
                && warning.contains("object 5 absent on the device"),
            "{warning}"
        );
    }
    drop(handle);
    let _ = session.into_disconnect().await;
    Ok(())
}

// --- Read-compare-write on a mask without VerifyMode (issue #133) ----------
//
// ETS streams a Theben 0701 segment by reading each chunk back first and writing
// only the chunks that differ (`meteodata-1-1-202-new.pcapng`: 194 12-octet
// reads, a handful of writes). A 0705 mask declares `VerifyMode=1` and stays a
// blind write.

/// A Theben-style 0701 app: a masked 4-octet table segment at `0x4000` (octet 2
/// device-owned) on LSM 1 and a 40-octet parameter segment at `0x4400` (octets
/// `01..=28`) on LSM 3, spanning several memory chunks.
fn theben_read_compare_app(
    mask_version: &str,
) -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-48_A-4948" ApplicationNumber="18760" ApplicationVersion="16"
        MaskVersion="{mask_version}" Name="read-compare" LoadProcedureStyle="ProductProcedure">
      <Static>
       <Code>
        <AbsoluteSegment Id="M-48_A-4948_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data><Mask>//8A/w==</Mask></AbsoluteSegment>
        <AbsoluteSegment Id="M-48_A-4948_AS-2" Size="40" Address="17408"><Data>AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKA==</Data></AbsoluteSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="1" />
         <LdCtrlUnload LsmIdx="3" />
         <LdCtrlLoad LsmIdx="1" />
         <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
         <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
         <LdCtrlLoadCompleted LsmIdx="1" />
         <LdCtrlLoad LsmIdx="3" />
         <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="40" />
         <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
         <LdCtrlLoadCompleted LsmIdx="3" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    parse_application_program("M-48_A-4948", xml.as_bytes())
        .map_err(|e| format!("parse read-compare app: {e}").into())
}

/// Seeds the mock's memory with every image octet the plan owns, as if an
/// earlier download had already written this exact configuration.
fn seed_planned_images(state: &Shared, plan: &bussard_download::FlashPlan) {
    let mut s = lock(state);
    for step in &plan.steps {
        if let bussard_download::FlashStep::Sys7AbsSegment {
            address,
            image: Some(img),
            ..
        } = step
        {
            let bytes = plan.image_bytes(&img.segment_id).unwrap_or_default();
            let mask = plan.segment_mask(&img.segment_id);
            for (i, &b) in bytes.iter().enumerate() {
                if mask.is_none_or(|m| m.get(i).copied() == Some(0xFF)) {
                    s.memory.insert(*address as u16 + i as u16, b);
                }
            }
        }
    }
}

/// Plans the read-compare app for `mask`, runs the flash against a memory-mapped
/// mock whose memory `prepare` sets up, and returns the device state.
async fn run_read_compare_flash(
    mask: u16,
    prepare: impl FnOnce(&Shared, &bussard_download::FlashPlan),
) -> Result<(Shared, bussard_download::FlashPlan), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, state, handle) = setup(LsmMode::MemoryMapped, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = theben_read_compare_app(&format!("MV-{mask:04X}"))?;
    let plan = plan_flash(
        &app,
        "1.1.99",
        mask,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    prepare(&state, &plan);
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    drop(handle);
    let _ = session.into_disconnect().await;
    Ok((state, plan))
}

#[tokio::test]
async fn test_flash_sys7_read_compare_unchanged_device_writes_no_segment()
-> Result<(), Box<dyn std::error::Error>> {
    let (state, plan) = run_read_compare_flash(0x0701, seed_planned_images).await?;
    assert!(plan.sys7_read_compare(), "0701 declares no VerifyMode");
    assert!(
        bussard_download::trace(&plan)
            .iter()
            .any(|l| l.contains("stream segment (read-compare, 40 octets)")),
        "the plan text names the read-compare stream"
    );
    let s = lock(&state);
    assert_eq!(
        s.memory_writes_seen, 0,
        "an unchanged device gets no segment write, only LSM records"
    );
    assert!(
        !s.memory.contains_key(&0x4002),
        "masked octet never touched"
    );
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_read_compare_one_differing_octet_writes_one_chunk()
-> Result<(), Box<dyn std::error::Error>> {
    let (state, _plan) = run_read_compare_flash(0x0701, |state, plan| {
        seed_planned_images(state, plan);
        // One stale octet in the middle of the 40-octet parameter segment.
        lock(state).memory.insert(0x4414, 0xEE);
    })
    .await?;
    let s = lock(&state);
    assert_eq!(
        s.memory_writes_seen, 1,
        "exactly the differing chunk is written"
    );
    assert_eq!(
        s.memory.get(&0x4414).copied(),
        Some(0x15),
        "stale octet fixed"
    );
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_read_compare_fresh_device_writes_owned_octets()
-> Result<(), Box<dyn std::error::Error>> {
    let (state, _plan) = run_read_compare_flash(0x0701, |_, _| {}).await?;
    let s = lock(&state);
    assert!(s.memory_writes_seen >= 1, "differing chunks are written");
    for i in 0..40u16 {
        assert_eq!(s.memory.get(&(0x4400 + i)).copied(), Some(i as u8 + 1));
    }
    assert_eq!(s.memory.get(&0x4001).copied(), Some(0x01));
    assert_eq!(s.memory.get(&0x4003).copied(), Some(0x03));
    assert!(
        !s.memory.contains_key(&0x4002),
        "masked octet never written"
    );
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_verify_mode_mask_writes_blind() -> Result<(), Box<dyn std::error::Error>> {
    // 0705 declares VerifyMode=1: the whole image is written even when the
    // device already holds it.
    let (state, plan) = run_read_compare_flash(0x0705, seed_planned_images).await?;
    assert!(!plan.sys7_read_compare(), "0705 declares VerifyMode=1");
    let s = lock(&state);
    assert!(
        s.memory_writes_seen >= 3,
        "a blind write streams every segment: {}",
        s.memory_writes_seen
    );
    Ok(())
}

// --- Pre-flight factory-freshness probe (issue #79) -------------------------
//
// System 7's load-state machines are read through the same `LsmAccess` seam the
// flash drives, so what the probe reads is what the flash would overwrite. A
// System 7 device exposes no application-id property, so a loaded LSM can never
// be identified as "the same application": it is always a refusal that `--force`
// overrides. The probe is read-only — these tests assert the device saw no
// memory write and no LSM event.

/// Plans the MDT canonical System 7 app against the mock's mask.
fn sys7_plan() -> Result<bussard_download::FlashPlan, Box<dyn std::error::Error>> {
    let app = mdt_canonical_app()?;
    Ok(plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?)
}

/// Opens an authorized connection and runs the read-only pre-flight probe
/// through the realisation `plan` will drive, as `bussard flash`'s phase A does.
async fn sys7_probe(
    bus: &mut Transport,
    plan: &bussard_download::FlashPlan,
) -> Result<bussard_download::ResidentState, Box<dyn std::error::Error>> {
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let resident =
        bussard_download::probe_resident_state(&mut l4, MASK_0705, plan.sys7_lsm_access().as_ref())
            .await;
    let _ = l4.disconnect().await;
    Ok(resident)
}

async fn probe_fresh_sys7_device(mode: LsmMode) -> Result<(), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(mode);
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    let plan = sys7_plan()?;

    let resident = sys7_probe(&mut bus, &plan).await?;

    assert!(resident.unreadable.is_none(), "{resident:?}");
    assert!(
        resident
            .objects
            .iter()
            .all(|o| o.state == LoadState::Unloaded),
        "a fresh System 7 device reports every LSM Unloaded: {resident:?}"
    );
    assert_eq!(
        bussard_download::assess_freshness(&resident, &plan.identity),
        bussard_download::Freshness::Fresh
    );
    {
        let s = lock(&state);
        assert_eq!(s.memory_writes_seen, 0, "the probe must write no memory");
        for lsm in [1u8, 2, 3] {
            assert_eq!(s.lsm_state(lsm), LS_UNLOADED, "the probe drove no LSM");
        }
    }
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_sys7_memory_mapped_fresh_device_is_fresh()
-> Result<(), Box<dyn std::error::Error>> {
    probe_fresh_sys7_device(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn test_probe_resident_state_sys7_property_fresh_device_is_fresh()
-> Result<(), Box<dyn std::error::Error>> {
    probe_fresh_sys7_device(LsmMode::Property).await
}

async fn probe_loaded_sys7_device(mode: LsmMode) -> Result<(), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(mode);
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    {
        // A previously-programmed device: its application LSM is Loaded.
        let mut s = lock(&state);
        s.lsm_states.insert(3, LS_LOADED);
    }
    let plan = sys7_plan()?;

    let resident = sys7_probe(&mut bus, &plan).await?;

    assert!(resident.has_loaded_application(), "{resident:?}");
    match bussard_download::assess_freshness(&resident, &plan.identity) {
        bussard_download::Freshness::Resident { resident, objects } => {
            // System 7 has no application-id property: the resident application
            // exists but cannot be named, which is still a refusal.
            assert!(
                resident.is_none(),
                "System 7 cannot identify the resident app"
            );
            assert!(objects.contains(&"LSM 3".to_string()), "{objects:?}");
        }
        other => panic!("expected a refusal verdict, got {other:?}"),
    }
    {
        let s = lock(&state);
        assert_eq!(s.memory_writes_seen, 0, "the probe must write no memory");
        assert_eq!(s.lsm_state(3), LS_LOADED, "the probe left the LSM alone");
        assert_eq!(s.lsm_state(1), LS_UNLOADED, "the probe drove no other LSM");
    }
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_sys7_memory_mapped_loaded_device_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    probe_loaded_sys7_device(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn test_probe_resident_state_sys7_property_loaded_device_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    probe_loaded_sys7_device(LsmMode::Property).await
}

#[tokio::test]
async fn test_probe_resident_state_sys7_without_a_plan_follows_the_env_realisation()
-> Result<(), Box<dyn std::error::Error>> {
    // Passing no explicit `LsmAccess` (what the CLI's phase A does, before the
    // plan exists) must resolve the same realisation the plan will: the mask
    // default plus the `BUSSARD_FLASH_SYS7_LSM` override. Against a
    // memory-mapped device that means the status region, not PID 5.
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let (mut bus, state, handle) = setup(LsmMode::MemoryMapped, Fault::None).await?;
    lock(&state).lsm_states.insert(3, LS_LOADED);
    let plan = sys7_plan()?;

    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let resident = bussard_download::probe_resident_state(&mut l4, MASK_0705, None).await;
    let _ = l4.disconnect().await;

    assert!(
        resident.has_loaded_application(),
        "the mask+env realisation must read the loaded LSM: {resident:?}"
    );
    assert!(
        !bussard_download::assess_freshness(&resident, &plan.identity).allows_flash(),
        "a loaded System 7 device is refused without --force"
    );
    {
        let s = lock(&state);
        assert_eq!(
            s.lsm5_property_accesses, 0,
            "a memory-mapped probe must not touch PID 5"
        );
    }
    drop(handle);
    Ok(())
}

// --- The incremental link path (issue #91) -----------------------------------
//
// `bussard plan` / `apply` / `reconstruct` on a System 7 device: read the live
// tables out of the absolute memory regions, diff them against the model, and
// write only the two table LSMs back. The device here starts where a flashed
// device really is — all three LSMs `Loaded`, a vendor table image in memory —
// which is exactly the state the flash-path tests above end in.

/// The System 7 LSM access seam matching a mock device's realisation. A real
/// device is one or the other; the mock serves both so bussard's switch is
/// exercised against each (the `BUSSARD_FLASH_SYS7_LSM` override does the same
/// for the flash path).
fn lsm_access_for(mode: LsmMode) -> LsmAccess {
    match mode {
        LsmMode::MemoryMapped => LsmAccess::MemoryMapped {
            control_addr: LSM_CONTROL_ADDR,
            status_addr: LSM_STATUS_ADDR,
        },
        LsmMode::Property => LsmAccess::Property,
    }
}

/// Seeds the device with a programmed System 7 table image: the address table at
/// `0x4000` followed by `go` (the group-object descriptor table), the association
/// table at `0x4201`, and all three LSMs `Loaded`. Returns the group-object
/// table's base.
fn seed_tables(state: &Shared, own_ia: u16, gas: &[u16], assoc: &[(u8, u8)], go: &[u8]) -> u16 {
    let mut image = vec![(1 + gas.len()) as u8];
    image.extend_from_slice(&own_ia.to_be_bytes());
    for ga in gas {
        image.extend_from_slice(&ga.to_be_bytes());
    }
    let go_base = 0x4000u16 + image.len() as u16;
    let mut assoc_image = vec![assoc.len() as u8];
    for &(tsap, asap) in assoc {
        assoc_image.push(tsap);
        assoc_image.push(asap);
    }

    let mut s = lock(state);
    for (i, &b) in image.iter().enumerate() {
        s.memory.insert(0x4000 + i as u16, b);
    }
    for (i, &b) in go.iter().enumerate() {
        s.memory.insert(go_base + i as u16, b);
    }
    for (i, &b) in assoc_image.iter().enumerate() {
        s.memory.insert(0x4201 + i as u16, b);
    }
    for lsm in [1u8, 2, 3] {
        s.lsm_states.insert(lsm, LS_LOADED);
    }
    go_base
}

fn ga(s: &str) -> Result<bussard_model::GroupAddress, Box<dyn std::error::Error>> {
    Ok(s.parse()?)
}

/// The model the plan wants: com-object 1 sends 1/0/1 and listens on 1/0/2.
fn desired_links() -> Result<bussard_download::DesiredTables, Box<dyn std::error::Error>> {
    Ok(compute_tables(&[bussard_model::schema::Link {
        object: 1,
        name: None,
        send: Some(ga("1/0/1")?),
        listen: vec![ga("1/0/2")?],
    }]))
}

/// Connects and authorizes a plain layer-4 connection (System 7 gates memory
/// access behind `A_Authorize`).
async fn authed_connection<'a>(
    bus: &'a mut Transport,
    target: bussard_model::IndividualAddress,
) -> Result<Layer4Connection<impl bussard_mgmt::L4Channel + 'a>, Box<dyn std::error::Error>> {
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(bus, target, source).await?;
    // The mock grants the free-access key.
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    Ok(l4)
}

async fn run_table_apply(mode: LsmMode) -> Result<(), Box<dyn std::error::Error>> {
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let own_ia = target.raw();
    // Two descriptors the download put there; `apply` must carry them over
    // untouched even though the address table in front of them changes length.
    let go_image = vec![
        0x02, 0x07, 0x00, // CNT + RAM-flags ptr
        0x07, 0x00, 0xDF, 0x00, // descriptor 1
        0x07, 0x02, 0x87, 0x00, // descriptor 2
    ];
    let go_base = seed_tables(&state, own_ia, &[0x0801], &[(1, 1)], &go_image);
    assert_eq!(go_base, 0x4005, "CNT + own IA + one GA");

    let mut l4 = authed_connection(&mut bus, target).await?;

    // --- plan: read the live tables and diff them -----------------------------
    let live = read_sys7_tables(&mut l4).await?;
    assert_eq!(live.tables.mask, MASK_0705);
    assert_eq!(live.own_ia, own_ia, "entry 0 is the device's own IA");
    assert_eq!(live.tables.addresses, vec![ga("1/0/1")?]);
    assert_eq!(live.tables.associations, vec![(1, 1)]);
    assert_eq!(live.tables.resolved.len(), 1);
    assert_eq!(live.tables.resolved[0].object, 1);
    assert_eq!(live.tables.resolved[0].ga, ga("1/0/1")?);
    assert_eq!(live.group_object_base, go_base);
    assert_eq!(live.group_object_image, go_image);
    assert_eq!(live.group_objects.len(), 2);

    let desired = desired_links()?;
    let report = plan(&live.tables, &desired);
    assert_eq!(report.additions.len(), 1, "one new link: {report:?}");
    assert_eq!(report.additions[0].ga, ga("1/0/2")?);
    assert_eq!(report.unchanged.len(), 1);
    assert!(report.removals.is_empty());

    // --- apply: write only the two table LSMs ---------------------------------
    let images = sys7_table_images(&live, &desired, own_ia)?;
    assert_eq!(
        images.group_object_moved,
        Some((0x4005, 0x4007)),
        "the address table grew by one entry, so the descriptors move with it"
    );
    let profile = bussard_mgmt::MaskProfile::from_mask(MASK_0705)
        .sys7_default_profile()
        .ok_or("a System 7 profile")?;
    let outcome = apply_sys7_tables(
        &mut l4,
        &lsm_access_for(mode),
        &profile,
        &images,
        bussard_mgmt::task_segment_marker(MASK_0705, 0, 0),
    )
    .await?;
    assert!(outcome.ok(), "apply must verify: {outcome:?}");

    // --- reconstruct: read it all back and confirm the model is on the device --
    let after = read_sys7_tables(&mut l4).await?;
    assert_eq!(after.tables.addresses, desired.addresses);
    assert_eq!(after.tables.associations, desired.associations);
    assert!(
        plan(&after.tables, &desired).is_noop(),
        "a re-plan after apply must be a no-op: {:?}",
        plan(&after.tables, &desired)
    );
    assert_eq!(after.own_ia, own_ia, "the own-IA slot survived the rewrite");
    assert_eq!(
        after.group_object_base, 0x4007,
        "the descriptors moved with the longer address table"
    );
    assert_eq!(
        after.group_object_image, go_image,
        "the descriptors are byte-identical after the move"
    );

    {
        let s = lock(&state);
        assert_eq!(
            s.restarts_seen, 0,
            "a table-only apply must not restart the device"
        );
        for lsm in [1u8, 2] {
            assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm} must end Loaded");
        }
        assert_eq!(
            s.lsm_state(3),
            LS_LOADED,
            "the parameter LSM must never be touched"
        );
        if mode == LsmMode::MemoryMapped {
            assert_eq!(
                s.lsm5_property_accesses, 0,
                "a memory-mapped device must never see a PID-5 access"
            );
        }
    }

    let _ = l4.disconnect().await;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn apply_system7_tables_property_lsm() -> Result<(), Box<dyn std::error::Error>> {
    run_table_apply(LsmMode::Property).await
}

#[tokio::test]
async fn apply_system7_tables_memory_mapped_lsm() -> Result<(), Box<dyn std::error::Error>> {
    run_table_apply(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn read_system7_tables_never_invents_links_from_unprogrammed_memory()
-> Result<(), Box<dyn std::error::Error>> {
    // Erased EEPROM is all 0xFF, so both count octets claim 255 entries — a count
    // each region genuinely has room for — and every table slot reads 0xFFFF.
    // Two guards have to hold, or `plan` would offer to "remove" hundreds of
    // links that were never there:
    //
    // - the group-object table's 255 descriptors need 1023 octets, far past the
    //   0x4000 region, so that count is refused and its descriptors left alone;
    // - the one well-formed association entry resolves to an address-table slot
    //   reading 0xFFFF, whose D15 is reserved and never a group address, so it
    //   does not become a link.
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    {
        let mut s = lock(&state);
        for addr in 0x4000u16..0x4400 {
            s.memory.insert(addr, 0xFF);
        }
        // One well-formed association entry over the erased address table, so the
        // reserved-D15 guard is what has to reject it rather than a short table.
        for (i, b) in [0x01u8, 0x01, 0x01].iter().enumerate() {
            s.memory.insert(0x4201 + i as u16, *b);
        }
        for lsm in [1u8, 2, 3] {
            s.lsm_states.insert(lsm, LS_LOADED);
        }
    }
    let mut l4 = authed_connection(&mut bus, target).await?;
    let live = read_sys7_tables(&mut l4).await?;
    assert_eq!(
        live.tables.addresses.len(),
        254,
        "the 0xFF count is read as-is"
    );
    assert!(
        live.tables.resolved.is_empty(),
        "no link may be invented from unprogrammed slots: {:?}",
        live.tables.resolved
    );
    assert!(
        live.group_object_image.is_empty(),
        "an oversized group-object count leaves the descriptors untouched"
    );
    assert_eq!(live.tables.associations, vec![(1, 1)]);
    let notes = live.tables.notes.join(" | ");
    assert!(
        notes.contains("unprogrammed"),
        "the report must say why nothing resolved: {notes}"
    );
    assert!(
        live.tables.notes.len() <= 4,
        "one summary note per kind, not one per entry: {notes}"
    );
    // And the diff against a model is pure addition — nothing to "remove".
    let report = plan(&live.tables, &desired_links()?);
    assert!(report.removals.is_empty(), "{report:?}");
    assert_eq!(report.additions.len(), 2);
    let _ = l4.disconnect().await;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn read_system7_tables_refuses_a_count_its_region_cannot_hold()
-> Result<(), Box<dyn std::error::Error>> {
    // The region bound is the hard refusal. A group-object table claiming 255
    // descriptors needs 1023 octets; the 0x4000 region holds 513, so the reader
    // refuses the count rather than reading a kilobyte of neighbouring memory —
    // the same check `decode_sys7_group_object_table` makes offline.
    let err = bussard_download::decode_sys7_group_object_table(
        &[0xFF, 0x07, 0x00],
        bussard_download::SYS7_ADDRESS_REGION_LEN,
    )
    .expect_err("an oversized count must be refused");
    let text = err.to_string();
    assert!(
        text.contains("255") && text.contains("refusing"),
        "the refusal must name the count: {text}"
    );
    Ok(())
}

#[tokio::test]
async fn apply_system7_tables_fails_on_a_verify_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    // A device that corrupts every stored segment write: the per-chunk read-back
    // must catch it at the first chunk, before the load is completed.
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::CorruptStoredImage).await?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let own_ia = target.raw();
    let go_image = vec![0x01, 0x07, 0x00, 0x07, 0x00, 0xDF, 0x00];
    seed_tables(&state, own_ia, &[0x0801], &[(1, 1)], &go_image);

    let mut l4 = authed_connection(&mut bus, target).await?;
    let live = read_sys7_tables(&mut l4).await?;
    let desired = desired_links()?;
    let images = sys7_table_images(&live, &desired, own_ia)?;
    let profile = bussard_mgmt::MaskProfile::from_mask(MASK_0705)
        .sys7_default_profile()
        .ok_or("a System 7 profile")?;
    let err = apply_sys7_tables(
        &mut l4,
        &lsm_access_for(LsmMode::Property),
        &profile,
        &images,
        bussard_mgmt::task_segment_marker(MASK_0705, 0, 0),
    )
    .await
    .expect_err("a corrupted store must fail the read-back verify");
    assert!(
        matches!(err, bussard_download::Sys7ApplyError::VerifyMismatch { .. }),
        "expected a verify mismatch, got {err}"
    );
    {
        let s = lock(&state);
        assert_ne!(
            s.lsm_state(1),
            LS_LOADED,
            "a failed write must not leave the address table Loaded"
        );
    }
    let _ = l4.disconnect().await;
    drop(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Issue #119: parameter-only download on System 7.
// ---------------------------------------------------------------------------

/// [`mdt_canonical_app`] with two 8-bit parameters in the `0x4400` segment
/// (defaults 4 and 5, the segment's own `<Data>`).
fn mdt_app_with_parameters() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
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
       <ParameterTypes><ParameterType Id="M-83_A-E_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
       <Parameters>
        <Parameter Id="M-83_A-E_P-0" Name="delay" Text="Delay" ParameterType="M-83_A-E_PT-0" Value="4"><Memory CodeSegment="M-83_A-E_AS-4" Offset="0" BitOffset="0" /></Parameter>
        <Parameter Id="M-83_A-E_P-1" Name="step" Text="Step" ParameterType="M-83_A-E_PT-0" Value="5"><Memory CodeSegment="M-83_A-E_AS-4" Offset="1" BitOffset="0" /></Parameter>
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="M-83_A-E_P-0_R-1" RefId="M-83_A-E_P-0" />
        <ParameterRef Id="M-83_A-E_P-1_R-2" RefId="M-83_A-E_P-1" />
       </ParameterRefs>
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
    parse_application_program("M-83_A-E", xml.as_bytes())
        .map_err(|e| format!("parse MDT S7 app: {e}").into())
}

/// The programmed MDT S7 device (defaults 4, 5 at `0x4400`) with LSM 3 in
/// `lsm3`, and the full plan that moves the second parameter from 5 to 9.
fn parameters_only_fixture(
    state: &Shared,
    lsm3: u8,
) -> Result<(ApplicationProgram, bussard_download::FlashPlan), Box<dyn std::error::Error>> {
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.lsm_states.insert(1, LS_LOADED);
        s.lsm_states.insert(2, LS_LOADED);
        s.lsm_states.insert(3, lsm3);
        s.memory.insert(0x4400, 4);
        s.memory.insert(0x4401, 5);
    }
    let app = mdt_app_with_parameters()?;
    let overrides = std::collections::BTreeMap::from([("P-1_R-2".to_string(), "9".to_string())]);
    let full = plan_flash(
        &app,
        "1.1.99",
        MASK_0705,
        &overrides,
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    Ok((app, full))
}

async fn run_parameters_only_refuses_unloaded_lsm3(
    mode: LsmMode,
) -> Result<(), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(mode);
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    let (_app, full) = parameters_only_fixture(&state, LS_ERROR)?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let regions = bussard_download::read_parameter_regions(session.l4(), &full).await;
    let partial = full.parameters_only(&regions)?;
    let result = flash(
        &mut session,
        &partial,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await;
    drop(handle);
    let _ = session.into_disconnect().await;
    let Err(err) = result else {
        return Err("a device whose LSM 3 is not Loaded must be refused".into());
    };
    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::NotLoaded {
                object_index: 3,
                actual: LoadState::Error,
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("flash --force"), "{err}");
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        s.segment_writes.is_empty(),
        "nothing written: {:?}",
        s.segment_writes
    );
    assert!(s.lsm_events.is_empty(), "no load event: {:?}", s.lsm_events);
    assert_eq!(s.restarts_seen, 0);
    Ok(())
}

#[tokio::test]
async fn test_parameters_only_sys7_memory_mapped_refuses_unloaded_lsm3()
-> Result<(), Box<dyn std::error::Error>> {
    run_parameters_only_refuses_unloaded_lsm3(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn test_parameters_only_sys7_property_refuses_unloaded_lsm3()
-> Result<(), Box<dyn std::error::Error>> {
    run_parameters_only_refuses_unloaded_lsm3(LsmMode::Property).await
}

async fn run_parameters_only_sys7(mode: LsmMode) -> Result<(), Box<dyn std::error::Error>> {
    set_sys7_lsm_env(mode);
    let (mut bus, state, handle) = setup(mode, Fault::None).await?;
    // A programmed device holding the vendor defaults 4, 5 at 0x4400; the
    // model moves the second parameter from 5 to 9.
    let (app, full) = parameters_only_fixture(&state, LS_LOADED)?;
    let target: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let regions = bussard_download::read_parameter_regions(session.l4(), &full).await;
    let region = regions
        .get("M-83_A-E_AS-4")
        .ok_or("the System 7 parameter segment must be read back")?;
    assert_eq!(
        (region.address, region.bytes.as_slice()),
        (0x4400, &[4u8, 5][..])
    );

    let partial = full.parameters_only(&regions)?;
    assert_eq!(partial.changed_octets(), 1);
    // The plan: open LSM 3, one in-place write, complete, restart; no
    // allocation record and no task segment (issue #146).
    assert!(
        !partial.steps.iter().any(|st| matches!(
            st,
            FlashStep::Sys7AbsSegment { .. }
                | FlashStep::Sys7TaskSegment { .. }
                | FlashStep::Sys7TaskCtrl1 { .. }
                | FlashStep::Sys7Unload { .. }
        )),
        "{:?}",
        partial.steps
    );
    assert!(matches!(partial.steps.last(), Some(FlashStep::Restart)));
    // ETS restarts the device before a parameter download too, but unloads
    // nothing (meteodata-1-1-202.pcapng, issue #116).
    assert!(
        partial
            .steps
            .contains(&FlashStep::Sys7PreDownloadRestart { unload: Vec::new() }),
        "{:?}",
        partial.steps
    );
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.lsm_events.clear();
        s.segment_writes.clear();
    }
    let outcome = flash(
        &mut session,
        &partial,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;
    let after = bussard_download::read_parameter_regions(session.l4(), &full).await;
    drop(handle);
    let _ = session.into_disconnect().await;
    assert!(
        outcome.ok(),
        "the parameter-only download must verify: {outcome:?}"
    );
    let readings = bussard_download::non_default_parameters(
        &app,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &bussard_download::regions_memory(&after),
    );
    assert_eq!(readings.len(), 1);
    assert_eq!(readings[0].line(), "Step: 9 (default 5)");

    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    // One octet written, at 0x4401; the tables at 0x4000 / 0x4201 untouched.
    assert_eq!(s.segment_writes, vec![(0x4401, 1)]);
    assert_eq!(s.memory.get(&0x4401).copied(), Some(9));
    assert_eq!(s.memory.get(&0x4400).copied(), Some(4));
    // Only LSM 3 was driven, the way ETS's partial download of the Jung
    // 3361-1MWW drives it (issue #146): opened and completed around the plain
    // memory write, with no allocation, task segment or unload. A re-sent
    // allocation put the real device into load state Error.
    assert_eq!(
        s.lsm_events,
        vec![(3, LE_START_LOADING), (3, LE_LOAD_COMPLETED)],
        "no allocation or task record, no unload"
    );
    for lsm in [1u8, 2, 3] {
        assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm} stays Loaded");
    }
    assert_eq!(s.restarts_seen, 1, "the device is restarted");
    Ok(())
}

#[tokio::test]
async fn test_parameters_only_sys7_memory_mapped_writes_one_octet()
-> Result<(), Box<dyn std::error::Error>> {
    run_parameters_only_sys7(LsmMode::MemoryMapped).await
}

#[tokio::test]
async fn test_parameters_only_sys7_property_writes_one_octet()
-> Result<(), Box<dyn std::error::Error>> {
    run_parameters_only_sys7(LsmMode::Property).await
}

// --- ETS parity: state read-backs, one connection, prelude (issue #116) -----

/// Runs a full MDT-canonical flash of a `mode` device over a reconnecting
/// session (the CLI's shape), with a device that reboots on every restart and
/// starts with `device_control` in `PID_DEVICE_CONTROL`.
async fn run_parity_flash(
    mode: LsmMode,
    device_control: u8,
) -> Result<(bussard_download::FlashOutcome, Shared), Box<dyn std::error::Error>> {
    let addr: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let state = fresh_device(mode, Fault::None);
    {
        let mut s = lock(&state);
        s.reboot_on_restart = true;
        s.device_control = device_control;
    }
    let gw = start_gateway(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(
        ConnectionConfig::tunnel(gw.addr())
            .with_reconnect(bussard_transport::TunnelReconnect::disabled()),
    );
    handle.wait_connected(Duration::from_secs(5)).await;
    let connector = LeaseConnector {
        handle: handle.clone(),
        target: addr,
        source: "0.0.255".parse()?,
        timeouts: None,
    };
    set_sys7_lsm_env(mode);
    // SAFETY: nextest runs each test in its own process, so these
    // process-global env writes race with no other thread. The reconnect
    // threshold is left to the device-class default (unset).
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
    }
    let mut session = Session::open_with_key(connector, None).await?;
    let plan = plan_flash(
        &mdt_canonical_app()?,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let options = bussard_download::FlashOptions {
        verify_after_restart: true,
        ..Default::default()
    };
    let result = flash(&mut session, &plan, options, |_p| {}).await;
    drop(gw);
    let _ = session.into_disconnect().await;
    Ok((result?, state))
}

#[tokio::test]
async fn test_flash_sys7_property_reads_state_only_as_the_verdict()
-> Result<(), Box<dyn std::error::Error>> {
    // The Jung 0705 captures never read PID_LOAD_STATE_CONTROL back: the answer
    // to each PID 5 write carries the state. bussard reads it once per LSM after
    // LoadCompleted (the verdict) and once per LSM after the terminal restart
    // (the persisted-load verify): 3 + 3, where every event used to add one.
    let (outcome, state) = run_parity_flash(LsmMode::Property, 0x00).await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    let s = lock(&state);
    assert_eq!(
        s.lsm_state_reads, 6,
        "LoadCompleted verdicts + post-restart verify"
    );
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_memory_mapped_reads_state_after_every_event()
-> Result<(), Box<dyn std::error::Error>> {
    // The Theben 0701 capture reads the status octet after every event (the
    // memory write has no answer), so the memory-mapped realisation keeps one
    // read per event: 4 prelude unloads + 16 procedure events + 3 verify.
    let (outcome, state) = run_parity_flash(LsmMode::MemoryMapped, 0x00).await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    let s = lock(&state);
    assert_eq!(s.lsm_events.len(), 4 + 16);
    assert_eq!(s.lsm_state_reads, 4 + 16 + 3);
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_holds_one_connection_between_restarts()
-> Result<(), Box<dyn std::error::Error>> {
    // ETS holds one connection for the whole procedure; with no proactive L4
    // cycling a real device is authorized exactly three times: the opening
    // connection, the one after the pre-download restart and the one after
    // the terminal restart.
    let (outcome, state) = run_parity_flash(LsmMode::Property, 0x00).await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    let s = lock(&state);
    assert_eq!(s.authorizes_seen, 3, "no proactive reconnect");
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_runs_the_ets_prelude() -> Result<(), Box<dyn std::error::Error>> {
    // ETS unloads LSMs 1 to 4 and restarts the device before the download, then
    // switches on verify mode (PID_DEVICE_CONTROL 00 -> 04) before the first
    // segment write (schaltaktor-8fach-1-1-49.pcapng).
    let (outcome, state) = run_parity_flash(LsmMode::Property, 0x00).await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    let s = lock(&state);
    let prelude: Vec<(u8, u8)> = s.lsm_events.iter().copied().take(4).collect();
    assert_eq!(
        prelude,
        vec![
            (1, LE_UNLOAD),
            (2, LE_UNLOAD),
            (3, LE_UNLOAD),
            (4, LE_UNLOAD)
        ]
    );
    assert_eq!(s.restart_at_writes, vec![0, s.memory_writes_seen]);
    assert_eq!(s.device_control_writes, vec![DEVICE_CONTROL_VERIFY_MODE]);
    // Every segment write was echoed, and the echoes did not derail the flash.
    assert!(s.memory_writes_seen > 0);
    assert_eq!(s.verify_echoes_sent, s.memory_writes_seen);
    // The terminal restart cleared the RAM bit again.
    assert_eq!(s.device_control, 0);
    Ok(())
}

#[tokio::test]
async fn test_flash_sys7_leaves_verify_mode_alone_when_already_on()
-> Result<(), Box<dyn std::error::Error>> {
    // A single-connection session skips the pre-download restart, so the
    // device keeps the verify-mode bit it already holds: nothing is written.
    set_sys7_lsm_env(LsmMode::Property);
    let (mut bus, state, handle) = setup(LsmMode::Property, Fault::None).await?;
    lock(&state).device_control = DEVICE_CONTROL_VERIFY_MODE | 0x01;
    let plan = plan_flash(
        &mdt_canonical_app()?,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let l4 = Layer4Connection::connect(&mut bus, "1.1.99".parse()?, "0.0.255".parse()?).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_p| {},
    )
    .await?;
    assert!(outcome.ok(), "flash should reach Loaded: {outcome:?}");
    {
        let s = lock(&state);
        assert!(s.device_control_writes.is_empty(), "bit already set");
        assert_eq!(s.restarts_seen, 1, "only the terminal restart");
    }
    drop(handle);
    let _ = session.into_disconnect().await;
    Ok(())
}

// --- issue #192: a gateway link loss in the post-restart reconnect phase -----

/// Flashes the MDT app onto a rebooting System 7 device while a 1.5 s gateway
/// link outage hits the reconnect phase after the `restart`-th restart (1 =
/// the pre-download restart, 2 = the terminal one). The readiness probe's
/// descriptor read gets through; the session connection's authorize is lost
/// with the link and the device drops its L4 connection meanwhile.
async fn run_flash_across_restart_outage(
    restart: usize,
) -> Result<
    (
        Result<bussard_download::FlashOutcome, bussard_mgmt::load::WriteError>,
        Shared,
    ),
    Box<dyn std::error::Error>,
> {
    // SAFETY of env: nextest runs this test in its own process; the vars only
    // shorten the post-reboot poll and select the LSM realisation.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    set_sys7_lsm_env(LsmMode::MemoryMapped);
    let addr: bussard_model::IndividualAddress = "1.1.99".parse()?;
    let state = fresh_device(LsmMode::MemoryMapped, Fault::None);
    {
        let mut s = lock(&state);
        s.reboot_on_restart = true;
        s.restart_outage = Some((restart, 1, Duration::from_millis(1500)));
    }
    let gw = start_gateway(&state).await?;
    let reconnect = bussard_transport::TunnelReconnect {
        budget: Duration::from_secs(20),
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(200),
        attempt_timeout: Duration::from_millis(300),
        ..bussard_transport::TunnelReconnect::default()
    };
    let (handle, _actor) =
        bussard_bus::Bus::connect(ConnectionConfig::tunnel(gw.addr()).with_reconnect(reconnect));
    handle.wait_connected(Duration::from_secs(5)).await;
    let connector = LeaseConnector {
        handle: handle.clone(),
        target: addr,
        source: "0.0.255".parse()?,
        timeouts: Some(bussard_mgmt::Timeouts {
            ack_timeout: Duration::from_millis(300),
            max_repetitions: 1,
            response_timeout: Duration::from_millis(300),
        }),
    };
    let mut session = Session::open_with_key(connector, None).await?;
    let plan = plan_flash(
        &mdt_canonical_app()?,
        "1.1.99",
        MASK_0705,
        &no_overrides(),
        &std::collections::BTreeMap::new(),
        None,
        &std::collections::BTreeMap::new(),
    )?;
    let options = bussard_download::FlashOptions {
        verify_after_restart: true,
        ..Default::default()
    };
    let result = flash(&mut session, &plan, options, |_p| {}).await;
    let _ = session.into_disconnect().await;
    let _ = handle.close().await;
    drop(gw);
    Ok((result, state))
}

/// The shared assertions: the flash verified after the outage fired and the
/// tunnel was re-established, and every LSM is `Loaded`.
fn assert_sys7_resumed(
    result: Result<bussard_download::FlashOutcome, bussard_mgmt::load::WriteError>,
    state: &Shared,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = result?;
    assert!(outcome.ok(), "the resumed flash must verify: {outcome:?}");
    let s = lock(state);
    assert!(s.restart_outage.is_none(), "the outage fired");
    assert!(s.outage_swallowed >= 1);
    assert!(
        s.tunnel_connects >= 2,
        "the tunnel was re-established (connects = {})",
        s.tunnel_connects
    );
    assert_eq!(s.restarts_seen, 2, "no restart was repeated");
    for lsm in [1u8, 2, 3] {
        assert_eq!(s.lsm_state(lsm), LS_LOADED, "LSM {lsm}");
    }
    Ok(())
}

#[tokio::test]
async fn test_flash_system7_resumes_tunnel_loss_after_pre_download_restart()
-> Result<(), Box<dyn std::error::Error>> {
    // The download has not written anything yet: the lost authorize must not
    // leave the session unauthorized, or the device's gate would refuse the
    // first segment write.
    let (result, state) = run_flash_across_restart_outage(1).await?;
    assert_sys7_resumed(result, &state)
}

#[tokio::test]
async fn test_flash_system7_resumes_tunnel_loss_during_terminal_restart_verify()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, state) = run_flash_across_restart_outage(2).await?;
    assert_sys7_resumed(result, &state)?;
    assert!(
        lock(&state).authorized,
        "the verify connection presented the key again"
    );
    Ok(())
}
