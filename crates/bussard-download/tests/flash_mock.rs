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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{FlashStep, Session, flash, plan_flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::{LoadState, WriteError};
use bussard_prod::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::{Inbound, MockDevice, MockGateway, Step, TestResult, Verdict, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination};
use bussard_transport::knxnet::ServiceType;
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x33;

// --- KNX identifiers, redeclared here from the spec (de-mirrored) ---
const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const A_MEMORY_READ_SEL: u16 = 0x200;
const A_MEMORY_RESPONSE: u16 = 0x240;
const A_MEMORY_WRITE_SEL: u16 = 0x280;
// A_MemoryExtended_* (System B, 24-bit address): the services ETS drives a
// capable 07B0 device with. Full 10-bit APCIs (no low-6-bit count field).
const A_MEMORY_EXTENDED_WRITE: u16 = 0x1FB;
const A_MEMORY_EXTENDED_WRITE_RESPONSE: u16 = 0x1FC;
const A_MEMORY_EXTENDED_READ: u16 = 0x1FD;
const A_MEMORY_EXTENDED_READ_RESPONSE: u16 = 0x1FE;
// A_Authorize_Request/Response (issue #52 finding #1): ETS presents a key before
// any configuration access. De-mirrored from the spec here so the mock models an
// authorization gate — config writes are refused until an authorize is granted.
const A_AUTHORIZE_REQUEST: u16 = 0x3D1;
const A_AUTHORIZE_RESPONSE: u16 = 0x3D2;
const FREE_ACCESS_KEY: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
const A_DEVICE_DESCRIPTOR_READ_SEL: u16 = 0x300;
const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
const A_RESTART_SEL: u16 = 0x380;
// A_Restart with the master-reset restart-type bit set, and its response.
// De-mirrored from the KNX spec: master reset is A_Restart | 1, confirmed by an
// A_Restart_Response (same APCI, response direction) carrying an error code.
const A_RESTART_MASTER_RESET: u16 = 0x381;
const A_RESTART_RESPONSE: u16 = 0x3A1;
const APCI_SELECTOR: u16 = 0x3C0;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
const PID_MCB_TABLE: u8 = 27;
const PID_MAX_APDU_LENGTH: u8 = 56;

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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    /// Go silent on the current L4 connection immediately after a BASIC restart
    /// (`A_Restart`, the terminal step): models the device rebooting and dropping
    /// the link after the final restart. The flash must treat this silence as
    /// success (it verified BEFORE sending the restart), not as "device absent".
    SilentAfterBasicRestart,
    /// Revert the application object to `Unloaded` after the terminal basic
    /// restart, exposing that state on the *next* (post-reboot) connection —
    /// models KNX Virtual discarding a content-incomplete load on reboot: the
    /// device reports a transient `Loaded` before the restart, then comes back up
    /// `Unloaded`. A post-restart verify must catch this and fail the flash; a
    /// pre-restart verify would wrongly report success.
    UnloadedAfterBasicRestart,
    /// Ignore `StartLoading` and stay `Unloaded` — a genuinely broken device that
    /// never opens the object for writing. Unlike the lenient `Loaded` snap (which
    /// the flash now tolerates), `Unloaded` means the load-control write was
    /// dropped, so the flash must reject it with a rich `UnexpectedLoadState`.
    IgnoresStartLoading,
}

/// Which restart arms a [`RestartOutage`] (issue #192).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RestartKind {
    /// The factory reset (`A_Restart` master reset, erase code 7).
    FactoryReset,
    /// The terminal confirmed restart (`A_Restart` master reset, erase code 1).
    ConfirmedRestart,
    /// A bare `A_Restart` (the KNX Virtual master reset or a terminal restart).
    BasicRestart,
}

/// A gateway link outage in the reconnect phase after a restart (issue #192,
/// S2.6 of #90): once the device accepted a restart of `kind`, the
/// `after_frame + 1`-th numbered frame the tool sends it takes the link down
/// for `duration`, swallowing every datagram. It is the testkit
/// `outage(after_frame, duration)` fault, counted from the restart instead of
/// from the start of the tunnel.
#[derive(Clone, Copy, Debug)]
struct RestartOutage {
    kind: RestartKind,
    after_frame: u32,
    duration: Duration,
}

/// How a device comes back after a restart it confirmed (issue #212),
/// measured from its `A_Restart_Response`.
#[derive(Clone, Copy, Debug)]
struct RebootProfile {
    /// Silent (and negatively confirmed by the interface) for this long.
    silent: Duration,
    /// Then answering every request `slow_answer` late until this point.
    slow_until: Duration,
    /// How late an answer comes during the slow phase.
    slow_answer: Duration,
}

impl RebootProfile {
    /// Ready at `ready`, prompt from then on.
    fn ready_at(ready: Duration) -> RebootProfile {
        RebootProfile {
            silent: ready,
            slow_until: ready,
            slow_answer: Duration::ZERO,
        }
    }
}

/// Where the device is in its reboot, per [`DeviceState::reboot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebootPhase {
    Silent,
    Slow(Duration),
    Up,
}

/// Arms `s.restart_outage` when it waits for a restart of `kind`.
fn arm_restart_outage(s: &mut DeviceState, kind: RestartKind) {
    if s.restart_outage.is_some_and(|o| o.kind == kind) {
        s.restart_outage_armed = true;
        s.restart_outage_frames = 0;
    }
}

/// The mutable mock-device state, shared with the gateway task.
struct DeviceState {
    object_types: Vec<u16>,
    /// The application object's load state (object index resolved via type 3).
    app_load_state: u8,
    /// Per-object load states, keyed by object index, for a **multi-object**
    /// flash (obj1/obj2/obj3/obj4 each track Unloaded→Loading→Loaded
    /// independently). Empty for the single-object tests, which use
    /// `app_load_state` alone. When an object index has an entry here it takes
    /// precedence; `loadable_object_index`/the app path remain the fallback so
    /// every existing single-object test is unaffected.
    object_load_states: HashMap<u8, u8>,
    /// Per-object allocated segment bases, keyed by object index, for the
    /// multi-object flash (each object's `PID_TABLE_REFERENCE` reports its own
    /// base). Empty for single-object tests (they use `last_segment_base`).
    object_segment_bases: HashMap<u8, u32>,
    /// Per-object allocated segment sizes, keyed by object index.
    object_segment_sizes: HashMap<u8, u32>,
    /// Whether this device models the multi-object (master-template) flash. When
    /// true the load-control / PID7 / memory handlers key off the requested
    /// object index (`object_load_states`/`object_segment_bases`) instead of the
    /// single `app_load_state`. Off by default (single-object tests unchanged).
    multi_object: bool,
    /// Device-placed segment base address, chosen on the first RelSegment. A
    /// 24-bit cursor: a capable 07B0 device places its segment above 0xFFFF and a
    /// tool must address it via the extended memory service.
    next_segment_base: u32,
    /// The base of the most-recently allocated segment (reported via
    /// `PID_TABLE_REFERENCE`).
    last_segment_base: u32,
    /// The size (octets) of the most-recently allocated segment, so a
    /// `PID_MCB_TABLE` read can CRC exactly the segment the device stored.
    last_segment_size: u32,
    /// Sparse device memory: 24-bit address → octet.
    memory: HashMap<u32, u8>,
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
    /// If set, the device goes silent after this many numbered exchanges *counted
    /// only once the first `A_Memory_Write` of the connection has been seen* — a
    /// death that lands strictly INSIDE a memory write, not during the discovery /
    /// load-control preamble or the resume re-check. Models KV's random mid-write
    /// drop (issue #52). With a budget too small to confirm even one new chunk
    /// (a write plus its read-back), no forward progress is ever made, so the
    /// window-retry bound is exercised.
    die_after_write_exchanges: Option<u32>,
    /// Exchanges seen since the first memory write on the current connection
    /// (`None` until that first write), the counter `die_after_write_exchanges`
    /// meters against. Reset on every `T_Connect`.
    write_phase_exchanges: Option<u32>,
    /// Total `A_Memory_Write` frames the device has stored across the whole
    /// download, so a test can assert the write was actually driven to completion
    /// (every source byte written at least once) across all the windows.
    memory_writes_seen: usize,
    /// Count of `A_MemoryExtended_Write` frames seen — a test asserts the extended
    /// service (not the plain `A_Memory_Write`) carried the >0xFFFF segment.
    extended_writes_seen: usize,
    /// If set, the device answers `PID_MAX_APDU_LENGTH` (PID 56 on obj0) with this
    /// value, so the tool scales its extended-write chunks to it (e.g. 233 -> 228).
    /// `None` (the default) leaves the property absent — the tool falls back to the
    /// conservative chunk, exactly as before, so existing tests are unaffected.
    max_apdu: Option<u16>,
    /// If set, the first `RelSegment` allocation is placed at this 24-bit base
    /// instead of `next_segment_base`, so a test can drive a segment above 0xFFFF
    /// (the real 07B0 actuators) through the extended service.
    segment_base_override: Option<u32>,
    /// If set, the device drops the application object out of `Loading` (back to
    /// `Unloaded`) the first time it is reconnected mid-download — modelling a peer
    /// that does not persist the intermediate state across a graceful window. The
    /// resume-safety load-state re-check must catch this.
    drop_loading_on_reconnect: bool,
    /// Whether the object was in `Loading` at the last disconnect, so a reconnect
    /// can decide whether to apply `drop_loading_on_reconnect`.
    was_loading_at_disconnect: bool,
    /// Whether the current connection has been authorized (issue #52 finding #1).
    /// Reset to `false` on every `T_Connect` (a fresh connection is a fresh
    /// authorization context), set `true` when an `A_Authorize_Request` is granted.
    /// While `false`, config writes (property/memory writes) are REFUSED — this
    /// reproduces the real device semantic and proves authorize is required.
    authorized: bool,
    /// The access level the device grants in its `A_Authorize_Response`. `0` (the
    /// default) means full access; a non-zero value models a keyed device denying
    /// the presented (free-access) key, so the tool surfaces `AccessDenied`.
    grant_level: u8,
    /// If set, the device does not answer `A_Authorize_Request` at all — modelling
    /// an older/simpler device that does not implement authorize. The tool must
    /// tolerate this and proceed (the gate is also open in this mode).
    authorize_unsupported: bool,
    /// If set, the device keeps answering its last segment's `PID_MCB_TABLE`
    /// entry even while the object is not `Loaded` — an app-unload or an
    /// interrupted load flips the load state without erasing the stored image.
    mcb_survives_unload: bool,
    /// Count of `PID_OBJECT_TYPE` reads, so a test can assert the flash reused a
    /// pre-flight's object table instead of walking it again.
    object_type_reads: usize,
    /// Count of `A_Authorize_Request` frames seen, so a test can assert the tool
    /// authorized on each connection window.
    authorizes_seen: usize,
    /// The payload of the last `A_Authorize_Request`, so a test can assert the tool
    /// sent exactly `[00 FF FF FF FF]` (reserved octet + free-access key).
    last_authorize_payload: Vec<u8>,
    /// Non-load-state property writes the device stored, keyed by
    /// `(object_index, pid)` → written value. Lets a test assert an
    /// `LdCtrlWriteProp` value actually landed on the device (issue #54).
    prop_writes: HashMap<(u8, u8), Vec<u8>>,
    /// If set, the gateway drops the KNXnet/IP TUNNEL — not just the L4 session —
    /// after this many TUNNELING_REQUESTs on the current KNXnet/IP connection: it
    /// stops sending the TUNNELING_ACK for the tripping request, so the client's
    /// `Transport` times out waiting for the ACK, the bus actor tears the tunnel
    /// down and reconnects with a fresh CONNECT_REQUEST. Distinct from
    /// `die_after_exchanges` (an L4 silence over a still-live tunnel): this
    /// models KV dropping the underlying tunnel every ~500 frames (issue #52).
    /// Reset per KNXnet/IP connection (each CONNECT_REQUEST).
    drop_tunnel_after_frames: Option<u32>,
    /// How many more tunnel drops to inject. Each drop decrements this; once `0`
    /// the gateway ACKs normally forever, so the download can finally complete.
    /// `None` in `drop_tunnel_after_frames` ignores this.
    tunnel_drops_remaining: u32,
    /// Memory TUNNELING_REQUESTs seen on the current KNXnet/IP connection, metered
    /// against `drop_tunnel_after_frames`. Reset on every CONNECT_REQUEST.
    tunnel_frames_this_connection: u32,
    /// Once a tunnel drop trips on the current connection, this is set so ALL
    /// further tunneling requests (including the client's retransmit of the very
    /// frame that tripped the drop) are swallowed with no ACK — the client's
    /// Transport must therefore time out and the actor must reconnect, rather than
    /// the single-frame retransmit sneaking through. Cleared on each CONNECT_REQUEST.
    tunnel_dead_this_connection: bool,
    /// A gateway link outage (issue #177): after this many MEMORY
    /// TUNNELING_REQUESTs the link goes down for the duration, swallowing every
    /// datagram (the tripping frame included) with no answer: a pulled LAN cable
    /// on the IP interface. Taken (`None`) once it trips.
    tunnel_outage: Option<(u32, Duration)>,
    /// Memory TUNNELING_REQUESTs seen, metered against `tunnel_outage`.
    outage_memory_frames: u32,
    /// While the link is down: when it comes back (`Some(None)` = never).
    tunnel_down_until: Option<Option<tokio::time::Instant>>,
    /// Datagrams the outage swallowed.
    outage_swallowed: usize,
    /// Whether the device drops its L4 connection while the link is down (its
    /// ~6 s idle timeout), so it answers nothing until a fresh T_Connect.
    outage_kills_l4: bool,
    /// Set when an outage ended with `outage_kills_l4`; cleared by T_Connect.
    l4_dead_after_outage: bool,
    /// A link outage in the reconnect phase after a restart (issue #192).
    /// Taken (`None`) once it trips.
    restart_outage: Option<RestartOutage>,
    /// Set once the restart `restart_outage` waits for was accepted.
    restart_outage_armed: bool,
    /// Numbered frames to the device since the arming restart.
    restart_outage_frames: u32,
    /// Count of KNXnet/IP CONNECT_REQUESTs the gateway answered — i.e. how many
    /// times the tunnel was (re)established. A tunnel-drop test asserts this
    /// reaches ≥2 (the actor reconnected the tunnel).
    tunnel_connects: usize,
    /// Count of master-reset `A_Restart` requests (APCI 0x381) seen, so the
    /// master-reset test can assert the tool issued exactly one.
    master_resets_seen: usize,
    /// The `[erase_code, channel_number]` payload of the last master-reset
    /// request, so the test can assert the tool encoded `EraseCode`/`ChannelNumber`
    /// onto the wire.
    last_master_reset_payload: Vec<u8>,
    /// Set true once a master reset is accepted on the current L4 connection:
    /// after answering the `A_Restart_Response` the device "reboots", so it goes
    /// silent for the rest of THIS connection (all further numbered telegrams are
    /// dropped with no ACK), modelling the real device dropping the link. A fresh
    /// `T_Connect` clears it and the device serves normally again — this is the
    /// spec-required single reconnect the tool must perform.
    l4_dead_after_master_reset: bool,
    /// How long the device stays silent after a master reset, measured from the
    /// first frame the tool sends it afterwards; meanwhile the gateway reports
    /// a negative `L_Data.con` for every frame to it, as a real interface does
    /// for a rebooting device (issue #45). Only with [`start_gateway_booting`].
    boot_silence: Option<Duration>,
    /// While the device is booting: until when.
    booting_until: Option<std::time::Instant>,
    /// Negative `L_Data.con`s the gateway reported for the booting device.
    negative_cons: usize,
    /// How the device comes back after its confirmed restart (erase code 1)
    /// and after its factory reset (erase code 7); `None` answers at once.
    restart_profile: Option<RebootProfile>,
    factory_profile: Option<RebootProfile>,
    /// The process time the factory reset answers (seconds).
    factory_process_time: u16,
    /// The profile of the restart the device is coming back from, and when it
    /// accepted it.
    reboot: Option<(std::time::Instant, RebootProfile)>,
    /// Every answered request is delayed by `fixed + per_octet * request
    /// payload octets`, without holding up the gateway: the ~200 ms plus
    /// ~1.7 ms per octet request cycle of the 2026-09-24 Data Secure flashes
    /// (issue #210).
    latency: Option<(Duration, Duration)>,
    /// Numbered requests answered, across the whole flash.
    answered_requests: usize,
    /// Per restart with a profile: from its acceptance to the first answer
    /// the device sent afterwards (as the tool receives it).
    reboot_answers: Vec<Duration>,
    /// Whether the current [`DeviceState::reboot`] was answered yet.
    reboot_answered: bool,
    /// Per restart with a profile: from its acceptance to the first request
    /// other than a readiness probe (the tool moved on: Sync_Req, authorize
    /// or the first read).
    reboot_proceeded: Vec<Duration>,
    /// Whether the tool moved on from the current reboot yet.
    reboot_moved_on: bool,
    /// Count of factory resets (master-reset `A_Restart`, erase code 7) seen.
    factory_resets_seen: usize,
    /// `control_writes` at the moment the first factory reset arrived, so a test
    /// can assert the reset preceded every load-control write.
    control_writes_at_factory_reset: Option<usize>,
    /// Count of confirmed restarts (master-reset `A_Restart`, erase code 1) seen.
    confirmed_restarts_seen: usize,
    /// Whether a basic restart (`A_Restart`, terminal step) has been seen — so the
    /// terminal-restart-silence test can assert the restart was actually sent.
    saw_basic_restart: bool,
    /// Set when a terminal basic restart is seen under
    /// [`Fault::UnloadedAfterBasicRestart`], so the next `T_Connect` (the
    /// post-reboot reconnect) reverts `app_load_state` to `Unloaded` — modelling a
    /// device that discards a content-incomplete load on reboot.
    revert_app_on_next_connect: bool,
    /// Every request APCI the device handled since the terminal restart (a
    /// bare `A_Restart` that is not the master reset, or a confirmed restart
    /// with erase code 1), so a test can count the post-restart verify reads
    /// (issue #215). `None` until that restart.
    after_terminal_restart: Option<Vec<u16>>,
    /// Model KNX Virtual's `EraseCode=4` master reset: erasing the app object's
    /// load state (back to `Unloaded`) and dropping the segment allocated before
    /// the reset. When set, accepting a master reset drops `app_load_state` to
    /// `Unloaded`, forgets `last_segment_base` (the placement cursor already points
    /// past the dropped segment, so the next allocation is placed at a fresh base
    /// distinct from the stale pre-reset one), and marks the object erased. While it
    /// is erased the device REFUSES `A_Memory_Write` (writing to an erased/closed
    /// object) — so a tool that naively resumed writing to the stale pre-reset base
    /// without re-opening + re-allocating would be NAKed. The tool must re-run the
    /// load-control sequence (StartLoading + re-allocate) after the reconnect,
    /// exactly as ETS does in the real KV capture.
    wipe_app_on_master_reset: bool,
    /// Set true while the app object has been erased by a master reset and not yet
    /// re-opened, so the memory-write handler can refuse writes to the erased
    /// object. Cleared when the object is re-opened (`StartLoading`).
    app_erased_by_master_reset: bool,
    /// Optional override for [`loadable_object_index`]: the object index the load
    /// state / PID7 base / MCB are modelled on, when it must differ from the
    /// type-discovered application-program object. Set by the LsmIdx-resolution
    /// test to place the loadable object at the ObjIdx the DA.tp write names (e.g.
    /// obj4), while the type-3 object sits at a different index. `None` = the
    /// type-discovered app object (the default, every other test).
    loadable_object_override: Option<u8>,
    /// The object index of every `PID_TABLE_REFERENCE` (PID7) read, in order — the
    /// per-object base reads. A test asserts the tool read PID7 on the LsmIdx-named
    /// object before writing it.
    pid7_reads: Vec<u8>,
    /// The object index of every `PID_LOAD_STATE_CONTROL` write, in order — the
    /// StartLoading / allocate / LoadCompleted targets.
    load_control_targets: Vec<u8>,
    /// Every `PID_LOAD_STATE_CONTROL` write as `(object index, event octet)`, in
    /// order, so a parameter-only download can be shown to send no `Unload`
    /// and no segment allocation (issue #119).
    load_events: Vec<(u8, u8)>,

    // --- KNX Data Secure (issue #71, spec §5/§6) ---
    /// When set, the device is security-ACTIVATED: every management APDU must
    /// arrive as an `A_SecureData` (`0x03F1`) wrapped with this tool key, and
    /// every response is wrapped back. `None` is the plain device (the default),
    /// whose behaviour is byte-identical to a bussard without KNX Secure.
    secure: Option<bussard_secure::DataSecureSession>,
    /// Secured APDUs accepted (MAC verified, sequence fresh).
    secure_frames_accepted: u32,
    /// Secured APDUs refused (bad MAC, stale sequence): the device drops them.
    secure_refusals: u32,
    /// Plain management APDUs refused because the device is activated (spec §6.4).
    plain_refusals: u32,
    /// How many S-A_Sync_Reqs an activated device T_ACKs without answering after
    /// each restart it accepts (`u32::MAX`: it never answers again), modelling a
    /// security layer that comes up after the transport layer (issue #166).
    sync_drops_after_restart: u32,
    /// Sync_Reqs still to be dropped since the last restart.
    sync_drops_pending: u32,
    /// Sync_Reqs dropped (T_ACK only) so far.
    sync_reqs_dropped: u32,
    /// Plain `A_DeviceDescriptor_Read`s an activated device answered in the
    /// clear (the readiness probe ETS and bussard send before the Sync_Req).
    plain_descriptor_reads: u32,
    /// The connection-level events an activated device saw, in order: a
    /// readable log of the wire sequence around a restart.
    secure_log: Vec<String>,
}

type Shared = Arc<Mutex<DeviceState>>;

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

/// The index of the single loadable object the mock's load-state machine models.
///
/// Normally the type-discovered application-program object. A test that exercises
/// the ETS→KNX-Virtual "write the app segment to a DIFFERENT object index than the
/// type-discovered one" shape (the divergence-#2 fix) sets
/// `loadable_object_override` so the load state / PID7 base / MCB are modelled on
/// **that** object index (e.g. obj4), proving the tool resolved the write target by
/// `LsmIdx`/`ObjIdx`, not by object type.
fn loadable_object_index(s: &DeviceState) -> Option<u8> {
    s.loadable_object_override.or_else(|| app_object_index(s))
}

enum Reaction {
    Answer(u16, Vec<u8>),
    /// No response (a bare T_ACK) — for A_Memory_Write, which is not answered.
    Ack,
    Nak,
}

fn handle_request(state: &Shared, req_apci: u16, data: &[u8]) -> Reaction {
    let Ok(mut s) = state.lock() else {
        return Reaction::Nak;
    };
    if let Some(log) = s.after_terminal_restart.as_mut() {
        log.push(req_apci);
    }

    // Device descriptor read (empty payload, strict).
    if req_apci & APCI_SELECTOR == A_DEVICE_DESCRIPTOR_READ_SEL && data.is_empty() {
        return Reaction::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]);
    }

    // Authorize request: reserved octet + 4-byte key. Grant `grant_level` and
    // open the write gate on a level-0 grant. `authorize_unsupported` models a
    // device that does not implement authorize: ACK but never answer, so the
    // tool times out and tolerates it (and the gate is treated as open below).
    if req_apci == A_AUTHORIZE_REQUEST {
        s.authorizes_seen += 1;
        s.last_authorize_payload = data.to_vec();
        if s.authorize_unsupported {
            // An older/simpler device that does not implement the authorize
            // service: it does not answer an A_Authorize_Response. Model this as a
            // benign non-authorize reply (a device-descriptor response) rather than
            // a silent no-answer, so the connection is not torn down by the
            // response timeout — the tool must recognise the non-authorize APCI as
            // "authorize unsupported", tolerate it, and continue on the SAME live
            // connection. The gate is treated as open for such a device.
            s.authorized = true;
            return Reaction::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]);
        }
        if s.grant_level == 0 {
            s.authorized = true;
        }
        return Reaction::Answer(A_AUTHORIZE_RESPONSE, vec![s.grant_level]);
    }

    // Master-reset A_Restart (0x381): the device confirms with an
    // A_Restart_Response (error code 0 = accepted, + 2-byte process time), then
    // "reboots" — it goes silent for the rest of THIS connection so the tool must
    // reconnect. A basic restart (0x380) is still fire-and-forget (just ACK).
    // Erase code 7 (factory reset without individual address, the ETS opening
    // of an initial System B download): confirm with process time 0, erase every
    // loadable object's state and memory (the individual address lives outside
    // `memory` and is untouched), and reboot.
    if req_apci == A_RESTART_MASTER_RESET && data.first() == Some(&0x07) {
        s.factory_resets_seen += 1;
        if s.control_writes_at_factory_reset.is_none() {
            s.control_writes_at_factory_reset = Some(s.control_writes);
        }
        s.last_master_reset_payload = data.to_vec();
        s.l4_dead_after_master_reset = true;
        s.sync_drops_pending = s.sync_drops_after_restart;
        arm_restart_outage(&mut s, RestartKind::FactoryReset);
        s.app_load_state = LS_UNLOADED;
        for state in s.object_load_states.values_mut() {
            *state = LS_UNLOADED;
        }
        s.object_segment_bases.clear();
        s.object_segment_sizes.clear();
        s.memory.clear();
        s.last_segment_base = 0;
        s.last_segment_size = 0;
        s.next_segment_base = 0x4000;
        s.reboot = s
            .factory_profile
            .map(|profile| (std::time::Instant::now(), profile));
        s.reboot_answered = false;
        s.reboot_moved_on = false;
        let [hi, lo] = s.factory_process_time.to_be_bytes();
        return Reaction::Answer(A_RESTART_RESPONSE, vec![0x00, hi, lo]);
    }
    // Erase code 1 (confirmed restart, the ETS close of a System B download):
    // confirm and reboot, erasing nothing.
    if req_apci == A_RESTART_MASTER_RESET && data.first() == Some(&0x01) {
        s.confirmed_restarts_seen += 1;
        s.after_terminal_restart = Some(Vec::new());
        s.l4_dead_after_master_reset = true;
        s.sync_drops_pending = s.sync_drops_after_restart;
        arm_restart_outage(&mut s, RestartKind::ConfirmedRestart);
        s.reboot = s
            .restart_profile
            .map(|profile| (std::time::Instant::now(), profile));
        s.reboot_answered = false;
        s.reboot_moved_on = false;
        return Reaction::Answer(A_RESTART_RESPONSE, vec![0x00, 0x00, 0x00]);
    }
    if req_apci == A_RESTART_MASTER_RESET {
        s.master_resets_seen += 1;
        s.last_master_reset_payload = data.to_vec();
        s.l4_dead_after_master_reset = true;
        // KNX Virtual's EraseCode=4 reset erases the app object's load state and
        // drops the segment allocated before it. Model that: the object falls back
        // to Unloaded, the next allocation is placed at a FRESH base (so the tool
        // must re-read PID_TABLE_REFERENCE rather than reuse the stale pre-reset
        // base), and the erased object refuses memory writes until re-opened.
        if s.wipe_app_on_master_reset {
            s.app_load_state = LS_UNLOADED;
            s.app_erased_by_master_reset = true;
            // Drop the segment allocated before the reset. `next_segment_base`
            // already points past it (the alloc advanced the cursor), so the
            // re-allocation after the reconnect is placed at a fresh base distinct
            // from the stale pre-reset one — the tool must re-read it.
            s.last_segment_base = 0;
            s.last_segment_size = 0;
        }
        // error_code = 0x00, process_time = 0x0064 (100, a plausible reboot time).
        return Reaction::Answer(A_RESTART_RESPONSE, vec![0x00, 0x00, 0x64]);
    }
    // Basic restart (bare A_Restart, 0x380, no payload). This is BOTH the terminal
    // restart AND — matching ETS→KNX-Virtual — the mid-procedure master reset
    // (bussard now realises LdCtrlMasterReset as a bare 0x380, not the confirmed
    // 0x381). The device T_ACKs it (fire-and-forget, no A_Restart_Response) and, if
    // this is the master reset, reboots.
    //
    // Distinguishing the two: when `wipe_app_on_master_reset` is set (the KV
    // EraseCode=4 model the master-reset test enables) the FIRST bare restart is
    // the master reset — it reboots (drops L4), wipes the app object, and is
    // counted; any later bare restart is the terminal one (fire-and-forget). When
    // the flag is unset, every bare restart is a plain terminal restart.
    if req_apci & APCI_SELECTOR == A_RESTART_SEL {
        s.saw_basic_restart = true;
        arm_restart_outage(&mut s, RestartKind::BasicRestart);
        let is_master_reset = s.wipe_app_on_master_reset && s.master_resets_seen == 0;
        if !is_master_reset {
            s.after_terminal_restart = Some(Vec::new());
        }
        if is_master_reset {
            s.master_resets_seen += 1;
            s.last_master_reset_payload = data.to_vec();
            // Reboot: the device goes silent on THIS connection; the tool reconnects.
            s.l4_dead_after_master_reset = true;
            // KV EraseCode=4: erase the app object and drop its segment (see
            // `wipe_app_on_master_reset`).
            s.app_load_state = LS_UNLOADED;
            s.app_erased_by_master_reset = true;
            s.last_segment_base = 0;
            s.last_segment_size = 0;
            // Multi-object flash: the reset erases the app object (obj4) load
            // state and drops its segment; the other table objects are untouched.
            if s.multi_object
                && let Some(app) = app_object_index(&s)
            {
                s.object_load_states.insert(app, LS_UNLOADED);
                s.object_segment_bases.remove(&app);
            }
        } else if s.fault == Fault::SilentAfterBasicRestart {
            s.l4_dead_after_master_reset = true;
        } else if s.fault == Fault::UnloadedAfterBasicRestart {
            // The device reboots (goes silent on this link) and, on the next
            // connection, will report the app object as Unloaded — the load did
            // not persist across the reboot.
            s.l4_dead_after_master_reset = true;
            s.revert_app_on_next_connect = true;
        }
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
            let a = u32::from(addr).wrapping_add(i as u32);
            out.push(*s.memory.get(&a).unwrap_or(&0));
        }
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&out);
        return Reaction::Answer(A_MEMORY_RESPONSE | (count as u16 & 0x3f), payload);
    }

    // Extended memory read: [count][addr:3 BE]. Answer with an
    // A_MemoryExtended_Read_Response [return_code=0][addr:3][data].
    if req_apci == A_MEMORY_EXTENDED_READ {
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = data[0] as usize;
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut payload = vec![0x00, data[1], data[2], data[3]];
        for i in 0..count {
            payload.push(*s.memory.get(&addr.wrapping_add(i as u32)).unwrap_or(&0));
        }
        return Reaction::Answer(A_MEMORY_EXTENDED_READ_RESPONSE, payload);
    }

    // Extended memory write: [count][addr:3 BE][data]. Store the bytes at the
    // 24-bit address and confirm inline with an A_MemoryExtended_Write_Response
    // [return_code=0][addr:3]. Same authorization gate as the plain write.
    if req_apci == A_MEMORY_EXTENDED_WRITE {
        if !s.authorized && !s.authorize_unsupported {
            return Reaction::Nak;
        }
        if s.app_erased_by_master_reset {
            return Reaction::Nak;
        }
        if s.fault == Fault::NakMemoryWrite {
            return Reaction::Nak;
        }
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = data[0] as usize;
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        if data.len() < 4 + count {
            return Reaction::Nak;
        }
        for (i, b) in data[4..4 + count].iter().enumerate() {
            s.memory.insert(addr.wrapping_add(i as u32), *b);
        }
        s.memory_writes_seen += 1;
        s.extended_writes_seen += 1;
        if s.write_phase_exchanges.is_none() {
            s.write_phase_exchanges = Some(0);
        }
        return Reaction::Answer(
            A_MEMORY_EXTENDED_WRITE_RESPONSE,
            vec![0x00, data[1], data[2], data[3]],
        );
    }

    // Memory write: [addr_hi, addr_lo, data…], count in APCI low bits.
    if req_apci & APCI_SELECTOR == A_MEMORY_WRITE_SEL {
        // Authorization gate: an unauthorized config write is REFUSED (this
        // reproduces the real device semantic and proves authorize is required).
        // A device that does not implement authorize never gates.
        if !s.authorized && !s.authorize_unsupported {
            return Reaction::Nak;
        }
        // An app object erased by a master reset and not yet re-opened refuses
        // memory writes (KNX Virtual rejects writes to an Unloaded/erased object).
        // A tool that resumed writing to the stale pre-reset base without first
        // re-opening (StartLoading) + re-allocating is NAKed here.
        if s.app_erased_by_master_reset {
            return Reaction::Nak;
        }
        if s.fault == Fault::NakMemoryWrite {
            return Reaction::Nak;
        }
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        for (i, b) in data[2..].iter().enumerate() {
            s.memory.insert(u32::from(addr).wrapping_add(i as u32), *b);
        }
        s.memory_writes_seen += 1;
        // Arm the write-phase death counter on the first memory write of the
        // connection (it only meters exchanges once the write is under way).
        if s.write_phase_exchanges.is_none() {
            s.write_phase_exchanges = Some(0);
        }
        // A_Memory_Write is acknowledged (T_ACK) but not answered.
        return Reaction::Ack;
    }

    if req_apci == A_PROPERTY_VALUE_READ {
        let Some((oi, pid, req_count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        if pid == PID_OBJECT_TYPE {
            s.object_type_reads += 1;
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
            let st = if s.multi_object {
                // Multi-object flash: every loadable object tracks its own state.
                *s.object_load_states.get(&oi).unwrap_or(&LS_UNLOADED)
            } else if loadable_object_index(&s) == Some(oi) {
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
            // Record which object index the tool read the per-object base from, so a
            // test can assert the PID7 base read targeted the LsmIdx-named object.
            s.pid7_reads.push(oi);
            // Report the object's allocated base as a big-endian u32. In the
            // multi-object flash each object has its own base; otherwise the
            // single last-allocated base.
            let base: u32 = if s.multi_object {
                *s.object_segment_bases.get(&oi).unwrap_or(&0)
            } else {
                s.last_segment_base
            };
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
            //
            // ONE entry per request. A real Jung 3361-1MWW refused a
            // `count=6` read of PID 27 with a zero-count response (issue #89
            // campaign, 1.1.36); ETS reads the entries one at a time, `count=1`
            // at index 1..=6. Several 8-octet entries do not fit a
            // standard-frame APDU and a real device does not partially answer,
            // so a multi-element read is refused whole here too.
            if req_count > 1 {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            }
            // Multi-object flash: every loadable object has its own segment
            // and MCB, valid while that object is Loaded.
            if s.multi_object
                && let (Some(&base), Some(&size)) = (
                    s.object_segment_bases.get(&oi),
                    s.object_segment_sizes.get(&oi),
                )
                && s.object_load_states.get(&oi) == Some(&LS_LOADED)
            {
                let segment: Vec<u8> = (0..size)
                    .map(|i| *s.memory.get(&base.wrapping_add(i)).unwrap_or(&0))
                    .collect();
                let mut entry = size.to_be_bytes().to_vec();
                entry.extend_from_slice(&[0x00, 0xFF]);
                entry.extend_from_slice(&crc16_ccitt(&segment).to_be_bytes());
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &entry),
                );
            }
            if loadable_object_index(&s) != Some(oi)
                || (s.app_load_state != LS_LOADED && !s.mcb_survives_unload)
            {
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                );
            }
            let base = s.last_segment_base;
            let size = s.last_segment_size;
            let segment: Vec<u8> = (0..size)
                .map(|i| *s.memory.get(&base.wrapping_add(i)).unwrap_or(&0))
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
        // PID_MAX_APDU_LENGTH (obj0): advertise the device's max APDU so the tool
        // scales its extended-write chunks to it. Absent unless a test sets it.
        if pid == PID_MAX_APDU_LENGTH && oi == 0 {
            return match s.max_apdu {
                Some(v) => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &v.to_be_bytes()),
                ),
                None => Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 0, start, &[]),
                ),
            };
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
        // Authorization gate: an unauthorized config write is REFUSED. A device
        // that does not implement authorize never gates.
        if !s.authorized && !s.authorize_unsupported {
            return Reaction::Nak;
        }
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = &data[4..];

        if pid == PID_LOAD_STATE_CONTROL {
            s.control_writes += 1;
            // Record which object index each load-control write targeted, so a test
            // can assert the tool drove StartLoading/allocate/LoadCompleted against
            // the LsmIdx-named object.
            s.load_control_targets.push(oi);
            let event = value.first().copied().unwrap_or(0);
            s.load_events.push((oi, event));
            let is_app = loadable_object_index(&s) == Some(oi);
            let fault = s.fault;

            // Multi-object flash: every loadable object has its own load state,
            // segment base and size, keyed by object index. The allocate /
            // start / complete / unload events act on the requested object `oi`.
            if s.multi_object {
                if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                    let size = if value.len() >= 6 {
                        u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                    } else {
                        0
                    };
                    let base = s
                        .segment_base_override
                        .take()
                        .unwrap_or(s.next_segment_base);
                    s.object_segment_bases.insert(oi, base);
                    s.object_segment_sizes.insert(oi, size);
                    // Mirror into the single-object fields too so the MCB handler
                    // (which reads last_segment_*) still works for the app object.
                    s.last_segment_base = base;
                    s.last_segment_size = size;
                    s.next_segment_base = base.wrapping_add(size.max(1));
                    let st = *s.object_load_states.get(&oi).unwrap_or(&LS_LOADING);
                    return Reaction::Answer(
                        A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, start, &[st]),
                    );
                }
                let new_state = match event {
                    LE_START_LOADING => {
                        // Re-opening the app object clears a prior master-reset
                        // erase so its re-allocated segment accepts writes again.
                        if app_object_index(&s) == Some(oi) {
                            s.app_erased_by_master_reset = false;
                        }
                        LS_LOADING
                    }
                    LE_LOAD_COMPLETED => LS_LOADED,
                    LE_UNLOAD => LS_UNLOADED,
                    _ => *s.object_load_states.get(&oi).unwrap_or(&LS_UNLOADED),
                };
                s.object_load_states.insert(oi, new_state);
                return Reaction::Answer(
                    A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[new_state]),
                );
            }

            // A 10-octet AdditionalLoadControls write is a segment allocation.
            if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                // Allocate: pick the next base, advance the cursor by the
                // requested size (data[2..6] big-endian u32).
                let size = if value.len() >= 6 {
                    u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                } else {
                    0
                };
                let base = s
                    .segment_base_override
                    .take()
                    .unwrap_or(s.next_segment_base);
                s.last_segment_base = base;
                s.last_segment_size = size;
                s.next_segment_base = base.wrapping_add(size.max(1));
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
                        // Re-opening the object clears a prior master-reset erase,
                        // so memory writes to the freshly re-allocated segment are
                        // accepted again.
                        s.app_erased_by_master_reset = false;
                        // A conformant device exposes LS_LOADING; KV snaps to
                        // LS_LOADED (the LoadedAfterStartLoading fault, now
                        // tolerated); a broken device ignores StartLoading and
                        // stays LS_UNLOADED (IgnoresStartLoading, still rejected).
                        if fault == Fault::LoadedAfterStartLoading {
                            s.app_load_state = LS_LOADED;
                            LS_LOADED
                        } else if fault == Fault::IgnoresStartLoading {
                            s.app_load_state = LS_UNLOADED;
                            LS_UNLOADED
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

        // Any other property write (e.g. an LdCtrlWriteProp value): record it so a
        // test can assert it landed, then echo it (confirm).
        s.prop_writes.insert((oi, pid), value.to_vec());
        return Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, _count, start, value),
        );
    }

    Reaction::Nak
}

/// The tool key the secure mock device is activated with (synthetic — no key
/// material in this repository is ever derived from a real installation).
const MOCK_TOOL_KEY: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

/// The addressing context of a frame, as both sides reconstruct it for the CCM
/// nonce (spec §5.4): raw source/destination, individual addressing, standard
/// frame format, and the carrier's TPCI octet.
fn mock_addressing(
    source: bussard_model::IndividualAddress,
    dest: bussard_model::IndividualAddress,
    tpci_octet: u8,
) -> bussard_secure::TpAddressing {
    bussard_secure::TpAddressing {
        source: source.raw(),
        destination: dest.raw(),
        address_type_group: false,
        extended_frame_format: 0,
        tpci: tpci_octet,
    }
}

/// The device side of the secure seam on receive: returns the inner `(apci,
/// data)` to dispatch, or `None` when the frame must be dropped.
///
/// A plain device passes everything through untouched. An activated device
/// refuses a plain management APDU (spec §6.4) and refuses a secured one whose
/// MAC does not verify or whose sequence is stale (spec §5.9) — in both cases by
/// dropping the frame, which is what a real device does.
fn unwrap_secure(
    state: &Shared,
    tool: bussard_model::IndividualAddress,
    address: bussard_model::IndividualAddress,
    tpci_octet: u8,
    apci: u16,
    data: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut s = state.lock().ok()?;
    let Some(session) = s.secure.as_mut() else {
        return Some((apci, data.to_vec()));
    };
    if apci != bussard_secure::A_SECURE_DATA {
        s.plain_refusals += 1;
        return None;
    }
    let addr = mock_addressing(tool, address, tpci_octet);
    match session.unwrap(&addr, apci, data) {
        Ok(bussard_secure::UnwrapOutcome::Secured { apci, data }) => {
            s.secure_frames_accepted += 1;
            s.secure_log.push(format!("S-A_Data({apci:#05x})"));
            Some((apci, data))
        }
        Ok(bussard_secure::UnwrapOutcome::Plain | bussard_secure::UnwrapOutcome::Synced { .. })
        | Err(_) => {
            s.secure_refusals += 1;
            None
        }
    }
}

/// The device side of the secure seam on send: wraps a response for an activated
/// device, or returns it untouched on a plain one. `None` when the state lock is
/// poisoned or the wrap fails.
fn wrap_secure(
    state: &Shared,
    address: bussard_model::IndividualAddress,
    tool: bussard_model::IndividualAddress,
    tpci_octet: u8,
    apci: u16,
    data: Vec<u8>,
) -> Option<(u16, Vec<u8>)> {
    let mut s = state.lock().ok()?;
    match s.secure.as_mut() {
        None => Some((apci, data)),
        Some(session) => {
            let addr = mock_addressing(address, tool, tpci_octet);
            // A wrap failure leaves the device silent (the test then fails on
            // the tool's timeout); it never happens with a valid session.
            session.wrap(&addr, apci, &data).ok()
        }
    }
}

/// Whether `apci` is a plain memory read or write (the frames the tunnel-drop
/// and outage budgets meter).
fn is_memory_apci(apci: u16) -> bool {
    (apci & APCI_SELECTOR == A_MEMORY_WRITE_SEL) || (apci & APCI_SELECTOR == A_MEMORY_READ_SEL)
}

/// Whether a tunnelled frame carries a plain memory read or write.
fn is_memory_frame(cemi: &CemiFrame) -> bool {
    matches!(&cemi.apdu, Apdu::Other { apci, .. } if is_memory_apci(*apci))
}

/// The gateway-level faults, as a testkit intercept hook: the link outage
/// (issue #177), the post-restart outage (issue #192) and the tunnel drops
/// (issue #52). Every datagram passes through here before the gateway acts.
fn intercept(
    state: &Shared,
    address: bussard_model::IndividualAddress,
    inbound: &Inbound<'_>,
) -> Verdict {
    let Ok(mut s) = state.lock() else {
        return Verdict::Serve;
    };
    // Gateway link outage (issue #177): while the link is down nothing gets
    // through in either direction.
    match s.tunnel_down_until {
        Some(None) => {
            s.outage_swallowed += 1;
            return Verdict::Swallow;
        }
        Some(Some(until)) if tokio::time::Instant::now() < until => {
            s.outage_swallowed += 1;
            return Verdict::Swallow;
        }
        Some(Some(_)) => {
            s.tunnel_down_until = None;
            if s.outage_kills_l4 {
                s.l4_dead_after_outage = true;
            }
        }
        None => {}
    }
    if let Some(cemi) = inbound.cemi {
        if s.tunnel_outage.is_some() && is_memory_frame(cemi) {
            s.outage_memory_frames += 1;
            if let Some((after, duration)) = s.tunnel_outage
                && s.outage_memory_frames > after
            {
                s.tunnel_outage = None;
                s.tunnel_down_until = Some(tokio::time::Instant::now().checked_add(duration));
                s.outage_swallowed += 1;
                return Verdict::Swallow;
            }
        }
        // The post-restart outage (issue #192): count the numbered frames
        // the tool sends the device after the arming restart.
        if s.restart_outage_armed
            && cemi.destination == Destination::Individual(address)
            && matches!(tpci::classify(cemi.tpci_octet()), TpciKind::NumberedData(_))
        {
            s.restart_outage_frames += 1;
            if let Some(outage) = s.restart_outage
                && s.restart_outage_frames > outage.after_frame
            {
                s.restart_outage = None;
                s.restart_outage_armed = false;
                s.tunnel_down_until =
                    Some(tokio::time::Instant::now().checked_add(outage.duration));
                s.outage_swallowed += 1;
                return Verdict::Swallow;
            }
        }
    }
    if inbound.service == ServiceType::ConnectRequest {
        // A fresh KNXnet/IP tunnel: reset the per-connection tunnel-drop
        // frame counter and record the (re)connect.
        s.tunnel_frames_this_connection = 0;
        s.tunnel_dead_this_connection = false;
        s.tunnel_connects += 1;
    }
    if let Some(cemi) = inbound.cemi {
        // Tunnel-drop injection: if this frame trips the tunnel-drop budget,
        // do NOT send the TUNNELING_ACK. The client's Transport then times
        // out waiting for the ACK, the bus actor tears the tunnel down and
        // reconnects — modelling KV dropping the underlying KNXnet/IP tunnel
        // (issue #52), distinct from an L4 silence over a live tunnel. The
        // budget is metered against MEMORY frames on the current connection
        // (writes and their read-backs), so a drop always lands strictly
        // inside the write — the discovery/authorize/load-control preamble
        // gets through on every fresh tunnel, isolating the mid-write path.
        //
        // Once the tunnel is dead on this connection, swallow EVERY
        // further frame (including the client's retransmit of the frame
        // that tripped the drop) so the Transport really times out and
        // the actor reconnects — a single-frame drop would be defeated
        // by the transport's one retransmit sneaking through.
        if s.tunnel_dead_this_connection {
            return Verdict::Swallow;
        }
        if is_memory_frame(cemi) {
            s.tunnel_frames_this_connection += 1;
            if let Some(budget) = s.drop_tunnel_after_frames
                && s.tunnel_drops_remaining > 0
                && s.tunnel_frames_this_connection > budget
            {
                s.tunnel_drops_remaining -= 1;
                s.tunnel_dead_this_connection = true;
                // Drop: swallow this and all further frames on this
                // connection with no ACK. The next CONNECT_REQUEST
                // resets the counters so the fresh tunnel's preamble
                // serves normally before the next drop.
                return Verdict::Swallow;
            }
        }
    }
    Verdict::Serve
}

/// The device's reaction to the tool's transport control frames.
fn on_control(state: &Shared, kind: TpciKind) -> Vec<Step> {
    let Ok(mut s) = state.lock() else {
        return Vec::new();
    };
    match kind {
        TpciKind::Connect => {
            // A fresh connection window: reset the per-connection
            // exchange budget and, if configured, drop the app object
            // out of Loading to model a peer that does not persist the
            // intermediate state across a graceful window.
            s.connects += 1;
            if s.secure.is_some() {
                s.secure_log.push("T_Connect".to_string());
            }
            s.exchanges_this_connection = 0;
            s.write_phase_exchanges = None;
            // A fresh connection is a fresh authorization context: the
            // session must re-authorize before any config write.
            s.authorized = false;
            // A fresh connection after a master-reset reboot: the device
            // is alive again on the new link.
            s.l4_dead_after_master_reset = false;
            s.l4_dead_after_outage = false;
            // A device that discarded a content-incomplete load on
            // reboot (Fault::UnloadedAfterBasicRestart) comes back up
            // with the app object Unloaded — the post-restart verify
            // must observe this and fail the flash.
            if s.revert_app_on_next_connect {
                s.revert_app_on_next_connect = false;
                s.app_load_state = LS_UNLOADED;
                if s.multi_object
                    && let Some(app) = app_object_index(&s)
                {
                    s.object_load_states.insert(app, LS_UNLOADED);
                }
            }
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
            s.disconnects += 1;
            if s.secure.is_some() {
                s.secure_log.push("T_Disconnect".to_string());
            }
            s.was_loading_at_disconnect = s.app_load_state == LS_LOADING;
        }
        _ => {}
    }
    Vec::new()
}

/// The device's reaction to one numbered data telegram (`wire_apci` and
/// `wire_payload` as they came off the wire, before any Data Secure unwrap).
fn on_numbered(
    state: &Shared,
    dev: &MockDevice,
    wire_apci: u16,
    wire_payload: &[u8],
) -> bussard_testkit::Reaction {
    use bussard_testkit::Reaction as Tk;
    let (tool, address) = (dev.tool, dev.address);
    let dev_seq = dev.send_seq().unwrap_or(0);
    // Per-connection death budget: once this connection has run
    // its allotted exchanges, the device goes silent for the
    // rest of the connection (KV drops the L4 link, issue #52).
    {
        let Ok(mut s) = state.lock() else {
            return Tk::Silent;
        };
        s.exchanges_this_connection += 1;
        // Still booting (issue #45): nothing answers yet.
        if s.booting_until
            .is_some_and(|until| std::time::Instant::now() < until)
            || reboot_phase(&s) == RebootPhase::Silent
        {
            return Tk::Silent;
        }
        // Master-reset reboot: once a master reset was accepted
        // on this connection, the device is rebooting and answers
        // nothing more until a fresh T_Connect. The tool must
        // reconnect to continue.
        if s.l4_dead_after_master_reset || s.l4_dead_after_outage {
            return Tk::Silent;
        }
        if let Some(budget) = s.die_after_exchanges
            && s.exchanges_this_connection > budget
        {
            // No ACK, no response: the connection is dead
            // until a fresh T_Connect resets the budget.
            return Tk::Silent;
        }
        // Write-phase death: once the write is under way (the
        // first memory write of the connection armed the
        // counter), meter only MEMORY frames (writes and their
        // read-backs) against the write-phase budget and go
        // silent past it — a death strictly INSIDE the memory
        // write (KV's random mid-write drop), leaving the
        // post-write property steps (LoadCompleted, verify)
        // untouched so this fault models exactly a mid-write
        // drop and nothing else.
        if let (Some(budget), Some(seen)) = (s.die_after_write_exchanges, s.write_phase_exchanges)
            && is_memory_apci(wire_apci)
        {
            if seen >= budget {
                return Tk::Silent;
            }
            s.write_phase_exchanges = Some(seen + 1);
        }
    }
    // Issue #212 measurement: the first request after a restart that is not
    // a readiness probe marks when the tool moved on.
    if wire_apci & APCI_SELECTOR != A_DEVICE_DESCRIPTOR_READ_SEL
        && let Ok(mut s) = state.lock()
        && let Some((accepted, _)) = s.reboot
        && !s.reboot_moved_on
        && reboot_phase(&s) != RebootPhase::Silent
    {
        s.reboot_moved_on = true;
        let moved_on = accepted.elapsed();
        s.reboot_proceeded.push(moved_on);
    }
    // KNX Data Secure S-A_Sync (spec §6.3): an activated
    // device answers the tool's Sync_Req with a Sync_Res, as
    // the real device does in the ETS capture.
    if wire_apci == bussard_secure::A_SECURE_DATA && wire_payload.first() == Some(&0x92) {
        let Ok(mut s) = state.lock() else {
            return Tk::Silent;
        };
        // A security layer that is not ready yet (issue
        // #166): the transport layer acknowledges the
        // request, the security layer never answers it.
        if s.secure.is_some() && s.sync_drops_pending > 0 {
            s.sync_drops_pending -= 1;
            s.sync_reqs_dropped += 1;
            s.secure_log.push("S-A_Sync_Req (T_ACK only)".to_string());
            return Tk::Ack;
        }
        let resp_tpci = tpci::ndt(dev_seq);
        if s.secure.is_some() {
            s.secure_log
                .push("S-A_Sync_Req -> S-A_Sync_Res".to_string());
        }
        let answered = s.secure.as_mut().map(|session| {
            session.answer_sync_request(
                &mock_addressing(tool, address, dev.request_tpci),
                wire_payload,
                &mock_addressing(address, tool, resp_tpci),
            )
        });
        let Some(Ok((rapci, rdata))) = answered else {
            // A Sync_Req that does not verify is dropped.
            s.secure_refusals += 1;
            return Tk::Silent;
        };
        return Tk::Answer(rapci, rdata);
    }
    // An activated device still answers a plain
    // A_DeviceDescriptor_Read in the clear, as the real
    // device does for ETS's opening probe (issue #166).
    let plain_probe = wire_apci & APCI_SELECTOR == A_DEVICE_DESCRIPTOR_READ_SEL && {
        let Ok(mut s) = state.lock() else {
            return Tk::Silent;
        };
        if s.secure.is_some() {
            s.plain_descriptor_reads += 1;
            s.secure_log
                .push("A_DeviceDescriptor_Read (plain)".to_string());
            true
        } else {
            false
        }
    };
    if plain_probe {
        return Tk::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]);
    }
    // KNX Data Secure (issue #71): an activated device unwraps
    // A_SecureData and refuses plain management outright. A
    // refused frame is DROPPED — no ACK, no response — exactly
    // as a real activated device (and the knx-sim) behaves.
    let Some((req_apci, payload)) = unwrap_secure(
        state,
        tool,
        address,
        dev.request_tpci,
        wire_apci,
        wire_payload,
    ) else {
        return Tk::Silent;
    };
    match handle_request(state, req_apci, &payload) {
        Reaction::Nak => Tk::Nak,
        Reaction::Ack => Tk::Ack,
        Reaction::Answer(rapci, rdata) => {
            // An activated device answers in kind: the response
            // rides back inside A_SecureData under the same key.
            let resp_tpci = tpci::ndt(dev_seq);
            match wrap_secure(state, address, tool, resp_tpci, rapci, rdata) {
                Some((rapci, rdata)) => Tk::Answer(rapci, rdata),
                None => Tk::Silent,
            }
        }
    }
}

/// Delays an answer by the device's request latency ([`DeviceState::latency`])
/// and, while it comes back from a restart slowly, by the profile's late
/// answer ([`RebootPhase::Slow`]), without holding up the gateway.
fn delay_answer(
    state: &Shared,
    reaction: bussard_testkit::Reaction,
    payload_len: usize,
) -> bussard_testkit::Reaction {
    use bussard_testkit::Reaction as Tk;
    let Ok(mut s) = state.lock() else {
        return reaction;
    };
    let steps = match reaction {
        Tk::Answer(apci, data) => vec![Step::Ack, Step::Data(apci, data)],
        Tk::Ack => vec![Step::Ack],
        other => return other,
    };
    s.answered_requests += 1;
    let mut delay = Duration::ZERO;
    if let Some((fixed, per_octet)) = s.latency {
        delay += fixed + per_octet * u32::try_from(payload_len).unwrap_or(u32::MAX);
    }
    if let RebootPhase::Slow(late) = reboot_phase(&s) {
        delay += late;
    }
    if let Some((accepted, _)) = s.reboot
        && !s.reboot_answered
        && reboot_phase(&s) != RebootPhase::Silent
    {
        s.reboot_answered = true;
        let answered = accepted.elapsed() + delay;
        s.reboot_answers.push(answered);
    }
    if delay.is_zero() {
        return Tk::Script(steps);
    }
    Tk::Script(vec![Step::After(delay, steps)])
}

/// The mock gateway in front of the device modelled by `state` at 1.1.4: the
/// testkit gateway with this suite's faults (see [`intercept`]) and device
/// model (see [`on_numbered`], [`on_control`]).
///
/// It keeps serving after a DISCONNECT: a client that drops and re-establishes
/// the tunnel mid-test (a bus-actor reconnect after a tunnel drop, issue #52)
/// tears down the old Transport — which sends a DISCONNECT_REQUEST — before
/// opening a fresh one, and the follow-up CONNECT_REQUEST must be answered.
async fn start_gateway(state: &Shared) -> TestResult<MockGateway> {
    start_gateway_with(state, false).await
}

/// [`start_gateway`] behind an interface that reports a negative `L_Data.con`
/// for every frame to the device while it boots after a master reset (see
/// [`DeviceState::boot_silence`]) and no confirmation otherwise.
async fn start_gateway_booting(state: &Shared) -> TestResult<MockGateway> {
    start_gateway_with(state, true).await
}

/// Where the device is in the reboot [`DeviceState::reboot`] describes.
fn reboot_phase(s: &DeviceState) -> RebootPhase {
    let Some((accepted, profile)) = s.reboot else {
        return RebootPhase::Up;
    };
    let since = accepted.elapsed();
    if since < profile.silent {
        RebootPhase::Silent
    } else if since < profile.slow_until {
        RebootPhase::Slow(profile.slow_answer)
    } else {
        RebootPhase::Up
    }
}

/// The negative-con decision of [`start_gateway_booting`] for one client frame.
fn boot_confirmation(
    state: &Shared,
    address: bussard_model::IndividualAddress,
    frame: &CemiFrame,
) -> Option<bool> {
    if frame.individual_destination() != Some(address) {
        return None;
    }
    let mut s = state.lock().ok()?;
    let now = std::time::Instant::now();
    if s.booting_until.is_none()
        && s.l4_dead_after_master_reset
        && let Some(boot) = s.boot_silence
    {
        s.booting_until = Some(now + boot);
    }
    if s.booting_until.is_some_and(|until| now < until) || reboot_phase(&s) == RebootPhase::Silent {
        s.negative_cons += 1;
        return Some(false);
    }
    None
}

async fn start_gateway_with(state: &Shared, booting: bool) -> TestResult<MockGateway> {
    let address = ia("1.1.4")?;
    let hook_state = Arc::clone(state);
    let control_state = Arc::clone(state);
    let intercept_state = Arc::clone(state);
    let device = MockDevice::new(address)
        .with_hook(move |dev, apci, data| {
            let reaction = on_numbered(&hook_state, dev, apci, data);
            Some(delay_answer(&hook_state, reaction, data.len()))
        })
        .with_control_hook(move |_, kind| on_control(&control_state, kind));
    let builder = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(30))
        .intercept(move |inbound| intercept(&intercept_state, address, inbound))
        .device(device);
    let builder = if booting {
        let con_state = Arc::clone(state);
        builder.confirm_with(bussard_testkit::CONFIRMATION_DELAY, move |frame, _| {
            boot_confirmation(&con_state, address, frame)
        })
    } else {
        builder
    };
    Ok(builder.start().await?)
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
        object_load_states: HashMap::new(),
        object_segment_bases: HashMap::new(),
        object_segment_sizes: HashMap::new(),
        multi_object: false,
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
        die_after_write_exchanges: None,
        write_phase_exchanges: None,
        memory_writes_seen: 0,
        extended_writes_seen: 0,
        max_apdu: None,
        segment_base_override: None,
        drop_loading_on_reconnect: false,
        was_loading_at_disconnect: false,
        authorized: false,
        grant_level: 0,
        authorize_unsupported: false,
        mcb_survives_unload: false,
        object_type_reads: 0,
        authorizes_seen: 0,
        last_authorize_payload: Vec::new(),
        prop_writes: HashMap::new(),
        drop_tunnel_after_frames: None,
        tunnel_drops_remaining: 0,
        tunnel_frames_this_connection: 0,
        tunnel_dead_this_connection: false,
        tunnel_connects: 0,
        tunnel_outage: None,
        outage_memory_frames: 0,
        tunnel_down_until: None,
        outage_swallowed: 0,
        outage_kills_l4: false,
        l4_dead_after_outage: false,
        restart_outage: None,
        restart_outage_armed: false,
        restart_outage_frames: 0,
        master_resets_seen: 0,
        factory_resets_seen: 0,
        control_writes_at_factory_reset: None,
        confirmed_restarts_seen: 0,
        last_master_reset_payload: Vec::new(),
        l4_dead_after_master_reset: false,
        boot_silence: None,
        booting_until: None,
        negative_cons: 0,
        restart_profile: None,
        factory_profile: None,
        factory_process_time: 0,
        reboot: None,
        latency: None,
        answered_requests: 0,
        reboot_answers: Vec::new(),
        reboot_answered: false,
        reboot_proceeded: Vec::new(),
        reboot_moved_on: false,
        saw_basic_restart: false,
        revert_app_on_next_connect: false,
        after_terminal_restart: None,
        wipe_app_on_master_reset: false,
        app_erased_by_master_reset: false,
        loadable_object_override: None,
        pid7_reads: Vec::new(),
        load_control_targets: Vec::new(),
        load_events: Vec::new(),
        secure: None,
        secure_frames_accepted: 0,
        secure_refusals: 0,
        plain_refusals: 0,
        sync_drops_after_restart: 0,
        sync_drops_pending: 0,
        sync_reqs_dropped: 0,
        plain_descriptor_reads: 0,
        secure_log: Vec::new(),
    }))
}

/// A factory-fresh System B device that is ALSO security-ACTIVATED (issue #71):
/// it holds [`MOCK_TOOL_KEY`] and refuses any management access that does not
/// ride `A_SecureData`.
fn secure_device(fault: Fault) -> TestResult<Shared> {
    let state = fresh_device(fault);
    lock(&state)?.secure = Some(bussard_secure::DataSecureSession::new(
        bussard_secure::Key16::new(MOCK_TOOL_KEY),
    ));
    Ok(state)
}

/// A minimal single-application System B app: code segment (6 bytes) + parameter
/// segment (1 byte, default 7 over a zero base).
fn fabricated_app() -> TestResult<ApplicationProgram> {
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
    Ok(parse_application_program("M-1_A-1", xml.as_bytes())?)
}

/// A single-application System B app in the real MDT A-0007 / Jung 23024 shape:
/// one relative segment written as a combined `full,par` image, followed by four
/// `LdCtrlLoadImageProp` MCB integrity checks (ObjIdx 1..4, the last Count=2).
fn app_with_image_prop() -> TestResult<ApplicationProgram> {
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
    Ok(parse_application_program("M-2_A-7", xml.as_bytes())?)
}

/// A single-application System B app in the MDT SCN-DA64x DALI-gateway shape: a
/// `LdCtrlCompareProp` precondition (object 0, PID 78, expecting the 4-byte
/// `AAECAw==`/`00 01 02 03`) verified before the download proper writes the
/// segment. The compare gates the flash: only a device whose property matches
/// proceeds. `mask`, when set, is emitted as the op's hex `Mask` attribute.
fn app_with_compare_prop(mask: Option<&str>) -> TestResult<ApplicationProgram> {
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
    Ok(parse_application_program("M-3_A-8", xml.as_bytes())?)
}

/// A single-application System B app whose procedure carries a value-carrying
/// `LdCtrlWriteProp` (object 0, PID 204, value `01 02`) after the segment write.
/// Used to prove the value actually lands on the device (issue #54).
fn app_with_write_prop() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-4_A-9" ApplicationNumber="9" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="WriteProp" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-4_A-9_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" />
         <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="0" Offset="0" Size="6" />
         <LdCtrlWriteProp ObjIdx="0" ObjType="11" PropId="204" InlineData="0102" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program("M-4_A-9", xml.as_bytes())?)
}

/// A single-application System B app whose procedure carries an
/// `LdCtrlMasterReset` (EraseCode 4, ChannelNumber 0) mid-procedure, in the
/// KNX-Virtual shape: allocate the segment, master-reset the device, then write
/// the segment and complete the load. The master reset reboots the device and
/// drops the L4 connection, so the download engine must reconnect and resume.
fn app_with_master_reset() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-5_A-1" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="MasterReset" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-5_A-1_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" />
         <LdCtrlMasterReset EraseCode="4" ChannelNumber="0" />
         <LdCtrlWriteRelMem AppliesTo="full" ObjIdx="0" Offset="0" Size="6" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program("M-5_A-1", xml.as_bytes())?)
}

async fn setup(fault: Fault) -> TestResult<(Transport, Shared, MockGateway)> {
    setup_device(fresh_device(fault)).await
}

/// Like [`setup`] but installs a caller-provided device state, so a test can model
/// a device whose object layout differs from the factory default (e.g. exposing an
/// extra loadable object for the LsmIdx-resolution test).
async fn setup_device(state: Shared) -> TestResult<(Transport, Shared, MockGateway)> {
    let gw = start_gateway(&state).await?;
    let bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    Ok((bus, state, gw))
}

fn no_overrides() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// A tiny L4 timeout budget for the resume-on-drop tests: a modelled mid-write
/// silence (the device dropped the connection) is then detected in ~50 ms instead
/// of the default 3 s, so the bounded-retry give-up path resolves quickly.
fn fast_timeouts() -> bussard_mgmt::Timeouts {
    bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(50),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(50),
        absent_on_negative_confirmation: false,
    }
}

/// Authorizes a freshly-connected [`Layer4Connection`] with the free-access key
/// and wraps it in a single-connection [`Session`], exactly as the real flow does
/// (issue #52 finding #1): the mock's authorization gate refuses config writes
/// until a session authorizes, so every flash-over-a-fixed-connection test
/// authorizes first. Asserts the authorize is granted (the mock defaults to
/// level 0 / full access).
async fn authed_session<Ch: bussard_mgmt::L4Channel>(
    mut l4: Layer4Connection<Ch>,
) -> TestResult<Session<bussard_download::SingleConnector<Ch>>> {
    l4.authorize_or_fail(0xFFFF_FFFF)
        .await
        .map_err(|e| format!("free-access authorize must be granted by the mock: {e:?}"))?;
    Ok(Session::from_connection(l4))
}

#[tokio::test]
async fn flash_happy_path_loads_and_verifies() -> TestResult {
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    assert!(outcome.spot_checks_match);

    // The code image landed at the first segment base 0x4000; the parameter
    // image at the second base (0x4000 + 6 = 0x4006).
    let s = lock(&state)?;
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(*s.memory.get(&0x4006).unwrap_or(&0), 7); // parameter default 7

    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_with_image_prop_loads_and_verifies_mcb() -> TestResult {
    // A full flash of the real MDT/Jung shape: write the segment, complete the
    // load, then four LoadImageProp MCB checks. The device computes its own CRC
    // over the stored segment; the tool's CRC over the bytes it sent matches, so
    // the flash reaches Loaded and every integrity check passes.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();
    // The plan carries the four MCB checks.
    let checks = plan
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::LoadImageProp { .. }))
        .count();
    assert_eq!(checks, 4);

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "flash with LoadImageProp must verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);

    // The code image landed at the segment base.
    let s = lock(&state)?;
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    drop(handle);
    Ok(())
}

/// A device whose application object is already Loaded and holds `image` in its
/// segment at `0x4000`, with `PID_MCB_TABLE` reporting that resident segment —
/// so a pre-download MCB read (issue #73 item 2) sees the resident size+CRC and
/// can skip the re-stream. Model of a re-download onto an unchanged install.
fn preloaded_device(image: &[u8]) -> TestResult<Shared> {
    let state = fresh_device(Fault::None);
    {
        let mut s = lock(&state)?;
        s.app_load_state = LS_LOADED;
        s.last_segment_base = 0x4000;
        s.last_segment_size = image.len() as u32;
        for (i, b) in image.iter().enumerate() {
            s.memory.insert(0x4000u32 + i as u32, *b);
        }
    }
    Ok(state)
}

#[tokio::test]
async fn flash_skips_restream_when_resident_mcb_matches() -> TestResult {
    // Item 2 (issue #73), match→skip branch: the device already holds the exact
    // image bussard would stream (resident MCB size+CRC match). With
    // `skip_matching_mcb` on, the pre-pass reads PID 27, sees the match and skips
    // the object's re-load — ZERO body bytes stream — yet the flash still reaches
    // Loaded and the LoadImageProp MCB re-verify passes.
    let image = [0u8, 1, 2, 3, 4, 5];
    let state = preloaded_device(&image)?;
    let (mut bus, state, handle) = setup_device(state).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            skip_matching_mcb: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a resident-match re-download must still verify Loaded: {outcome:?}"
    );
    let s = lock(&state)?;
    assert_eq!(
        s.memory_writes_seen, 0,
        "a resident-MCB match must stream ZERO body bytes"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_flash_full_streams_when_resident_mcb_matches_but_object_not_loaded() -> TestResult {
    // Differential download guard: the device still describes the exact image
    // bussard would stream (MCB size+CRC match) but the object is NOT Loaded —
    // an interrupted flash or an app-unload leaves the stored bytes intact while
    // the load state says Unloaded. Skipping the re-load here would also skip the
    // StartLoading/LoadCompleted that bring the object back, so the flash must
    // full-stream and end Loaded.
    let image = [0u8, 1, 2, 3, 4, 5];
    let state = preloaded_device(&image)?;
    {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.app_load_state = LS_UNLOADED;
        s.mcb_survives_unload = true;
    }
    let (mut bus, state, handle) = setup_device(state).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            skip_matching_mcb: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a not-Loaded object must be re-loaded: {outcome:?}"
    );
    let s = state.lock().map_err(|e| e.to_string())?;
    assert!(
        s.memory_writes_seen > 0,
        "an object that is not Loaded must full-stream even when its MCB matches"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_full_streams_when_resident_mcb_absent_even_with_skip_on() -> TestResult {
    // Item 2 (issue #73), mismatch→write branch: a fresh/blank device answers no
    // MCB entry, so even with `skip_matching_mcb` on the pre-pass finds no match
    // and the object full-streams exactly as before — a needed write is NEVER
    // skipped. Contrast with the match case above.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            skip_matching_mcb: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "a blank device must full-stream: {outcome:?}");
    let s = lock(&state)?;
    assert!(
        s.memory_writes_seen > 0,
        "a blank device (no resident MCB) must full-stream even with skip on"
    );
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_full_streams_when_resident_mcb_matches_but_skip_off() -> TestResult {
    // Item 2 (issue #73), default-off guard: with `skip_matching_mcb` OFF (the
    // default, and the DA.tp-validated path), even a resident-match device
    // full-streams — the skip is opt-in, so no existing path changes byte-for-byte.
    let image = [0u8, 1, 2, 3, 4, 5];
    let state = preloaded_device(&image)?;
    let (mut bus, state, handle) = setup_device(state).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "default-off must still verify: {outcome:?}");
    let s = lock(&state)?;
    assert!(
        s.memory_writes_seen > 0,
        "skip OFF must full-stream even when the resident MCB would match"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_image_prop_catches_corrupted_stored_image() -> TestResult {
    // The device stores a corrupted segment (one octet flipped after the load
    // completes). Its own MCB CRC therefore diverges from the CRC the tool
    // computed over the bytes it sent, and the LoadImageProp step must surface
    // an ImagePropMismatch — proving the mock's independent CRC really gates it.
    let (mut bus, _state, handle) = setup(Fault::CorruptStoredImage).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_image_prop()?;
    let mut plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The fill (`Mode=1`) makes the planner add a factory reset, which a
    // single-connection session cannot reconnect after; this test exercises the
    // `--no-factory-reset` path.
    plan.skip_factory_reset();

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
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
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_surfaces_load_error_on_completed() -> TestResult {
    let (mut bus, _state, handle) = setup(Fault::ErrorOnLoadCompleted).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
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
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_aborts_on_memory_write_nak() -> TestResult {
    let (mut bus, _state, handle) = setup(Fault::NakMemoryWrite).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
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
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_disconnects_even_when_it_fails_mid_procedure() -> TestResult {
    // Finding 3: after a failed flash the L4 session must be torn down, or the
    // device holds a stale connection and the next `reconstruct` reports it
    // absent. Here the device ignores StartLoading and stays Unloaded, so the
    // load-state check rejects it — an application-level error that leaves the
    // connection OPEN. The flash body returns Err, and the explicit
    // `l4.disconnect()` must still emit a T_Disconnect that reaches the device.
    let (mut bus, state, handle) = setup(Fault::IgnoresStartLoading).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    // The device never opens the object, so the load-state check fails.
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a device that never opens the object must fail the flash");
    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::UnexpectedLoadState { .. }
        ),
        "expected UnexpectedLoadState, got {err:?}"
    );
    // Before the disconnect the device saw none; the connection is still open.
    assert_eq!(
        lock(&state)?.disconnects,
        0,
        "the failed flash must not have disconnected on its own yet"
    );

    // The disconnect-on-error guarantee: this must reach the device.
    let _ = session.into_disconnect().await;

    // Poll briefly for the async gateway to record the T_Disconnect.
    let mut saw = false;
    for _ in 0..50 {
        if lock(&state)?.disconnects >= 1 {
            saw = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        saw,
        "a failed flash must still emit T_Disconnect to release the L4 session"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_unexpected_load_state_names_object_and_table() -> TestResult {
    // When the device lands in a genuinely-wrong load state (here: it ignores
    // StartLoading and stays Unloaded), the flash fails with a RICH error — it
    // names the targeted object's discovered interface-object type and the full
    // discovered object table, so "object 3 did not reach Loading" is actionable.
    let (mut bus, _state, handle) = setup(Fault::IgnoresStartLoading).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("an object that never opens must be rejected");
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
            assert_eq!(*actual, LoadState::Unloaded);
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
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_tolerates_snap_to_loaded() -> TestResult {
    // KNX Virtual (and other lenient stacks) snap the object straight to Loaded
    // instead of exposing the intermediate Loading state — either right after
    // StartLoading or on the AdditionalLoadControls allocation. Both are open
    // states, so the flash must proceed and reach Loaded (the image's real
    // integrity is confirmed by the MCB CRC check, not by the load-state octet).
    for fault in [Fault::LoadedAfterStartLoading, Fault::LoadedOnAllocate] {
        let (mut bus, _state, handle) = setup(fault).await?;
        let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
        let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

        let app = fabricated_app()?;
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;

        let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
        let mut session = authed_session(l4).await?;
        let outcome = flash(
            &mut session,
            &plan,
            bussard_download::FlashOptions::default(),
            |_| {},
        )
        .await
        .unwrap_or_else(|e| panic!("snap-to-Loaded ({fault:?}) must still flash to Loaded: {e:?}"));
        assert_eq!(
            outcome.load_state,
            LoadState::Loaded,
            "the flash must reach Loaded despite the {fault:?} snap"
        );
        let _ = session.into_disconnect().await;
        drop(handle);
    }
    Ok(())
}

#[tokio::test]
async fn plan_only_touches_no_load_state() -> TestResult {
    let (_bus, state, handle) = setup(Fault::None).await?;

    // Building a plan is a pure, offline operation: it must never write a load
    // control (or anything) to the device.
    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert!(!plan.steps.is_empty());
    // The first supported device step is the unload of the application object
    // (LsmIdx=4 in the fabricated app).
    assert_eq!(plan.steps[0], FlashStep::Unload { target: Some(4) });

    let s = lock(&state)?;
    assert_eq!(
        s.control_writes, 0,
        "a plan-only pre-flight must not write any load-state control"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_applies_device_file_parameter_override() -> TestResult {
    // A device-file override (keyed by app-relative ParameterRef id) changes the
    // parameter byte away from the vendor default 7. The overridden value must
    // reach device memory AND be reflected in the segment the device CRCs — the
    // MCB integrity check passing proves the OVERRIDDEN image (not the default)
    // is what actually flowed onto the device.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;

    // The default plan writes the parameter default (7).
    let default_plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert_eq!(default_plan.param_images["M-1_A-1_RS-2"], vec![7]);

    // The override plan (P-0_R-1 = 42) writes 42 instead — proving the override
    // changed the computed image before any bus traffic.
    let mut ov = BTreeMap::new();
    ov.insert("P-0_R-1".to_string(), "42".to_string());
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &ov,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert_eq!(
        plan.param_images["M-1_A-1_RS-2"],
        vec![42],
        "the override must change the computed parameter image"
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "override flash must verify: {outcome:?}");

    // The overridden byte 42 (not the default 7) landed in device memory at the
    // parameter segment base (0x4000 + 6 = 0x4006).
    let s = lock(&state)?;
    assert_eq!(
        *s.memory.get(&0x4006).unwrap_or(&0),
        42,
        "the device stored the overridden value, not the default"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_compare_prop_passes_when_property_matches() -> TestResult {
    // The device's object-0 PID-78 property holds exactly the bytes the
    // LdCtrlCompareProp expects, so the precondition passes and the flash reaches
    // Loaded.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?
        .compare_props
        .insert((0, 78), vec![0x00, 0x01, 0x02, 0x03]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_compare_prop(None)?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The plan carries the CompareProp precondition.
    assert_eq!(
        plan.steps
            .iter()
            .filter(|s| matches!(s, FlashStep::CompareProp { .. }))
            .count(),
        1
    );

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "matching compare must let the flash verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_write_prop_value_lands_on_the_device() -> TestResult {
    // Issue #54: a value-carrying LdCtrlWriteProp is executed as a real,
    // echo-validated property write — the value must land on the device, not be
    // silently dropped as a no-op.
    let (mut bus, state, handle) = setup(Fault::None).await?;

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_write_prop()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The plan lists the WriteProp as a real write carrying the value.
    let write_props: Vec<&FlashStep> = plan
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::WriteProp { .. }))
        .collect();
    assert_eq!(write_props.len(), 1, "the value-carrying WriteProp lowers");
    match write_props[0] {
        FlashStep::WriteProp { value, .. } => assert_eq!(value, &vec![0x01, 0x02]),
        other => panic!("expected WriteProp, got {other:?}"),
    }

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "flash with a WriteProp must succeed: {outcome:?}"
    );
    // The value landed on the mock device at object 0 / PID 204.
    let stored = lock(&state)?.prop_writes.get(&(0, 204)).cloned();
    assert_eq!(
        stored,
        Some(vec![0x01, 0x02]),
        "the WriteProp value must have been written to the device"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_compare_prop_aborts_when_property_differs() -> TestResult {
    // The device's object-0 PID-78 property holds different bytes than the
    // LdCtrlCompareProp expects: the precondition fails and the flash aborts with
    // PropCompareMismatch — before the segment is written.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?
        .compare_props
        .insert((0, 78), vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_compare_prop(None)?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
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
    let s = lock(&state)?;
    assert_ne!(
        s.app_load_state, LS_LOADED,
        "flash must not have completed the load"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_compare_prop_mask_ignores_don_t_care_bytes() -> TestResult {
    // The compare expects 00 01 02 03 under mask FF 00 FF 00: the device holds
    // 00 AA 02 BB, differing only in the masked-out (don't-care) positions, so
    // the masked compare passes and the flash reaches Loaded.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?
        .compare_props
        .insert((0, 78), vec![0x00, 0xAA, 0x02, 0xBB]);

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = app_with_compare_prop(Some("FF00FF00"))?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a difference only in masked-out bytes must pass: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_reports_progress_for_every_step() -> TestResult {
    let (mut bus, _state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let total = plan.steps.len();

    let steps_seen = Arc::new(Mutex::new(0usize));
    let seen = Arc::clone(&steps_seen);

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        move |p| {
            if let bussard_download::Progress::Step { .. } = p
                && let Ok(mut n) = seen.lock()
            {
                *n += 1;
            }
        },
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok());
    assert_eq!(
        *steps_seen.lock().map_err(|_| "step counter poisoned")?,
        total,
        "one Step event per step"
    );
    drop(handle);
    Ok(())
}

// ===========================================================================
// Authorization tests (issue #52 finding #1).
//
// ETS presents A_Authorize_Request (free-access key FF FF FF FF) as the first
// operation after the descriptor read; the mock models an authorization GATE —
// config writes are refused until a session authorizes. These prove bussard
// authorizes on every management connection, sends the exact captured wire form,
// re-authorizes each fresh window, tolerates a device without authorize, and
// surfaces a real access-denied.
// ===========================================================================

#[tokio::test]
async fn flash_sends_free_access_authorize_and_the_gate_opens() -> TestResult {
    // A device with the authorization gate ON (the default fresh device): the
    // flash must authorize with the free-access key before any write, or the
    // gate refuses. Assert the flash completes AND the tool sent exactly the
    // captured payload [00 FF FF FF FF].
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "authorized flash must verify: {outcome:?}");
    let s = lock(&state)?;
    assert!(s.authorizes_seen >= 1, "the tool must have authorized");
    let mut want = vec![0x00];
    want.extend_from_slice(&FREE_ACCESS_KEY);
    assert_eq!(
        s.last_authorize_payload, want,
        "the authorize payload must be the reserved octet + free-access key"
    );
    assert!(s.authorized, "the gate must be open after the grant");
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_without_authorize_is_refused_by_the_gate() -> TestResult {
    // The regression that proves authorize is REQUIRED: wrap the raw connection
    // in a session WITHOUT authorizing (Session::from_connection directly), so the
    // first config write hits the closed gate and is NAKed.
    let (mut bus, _state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    // Deliberately skip the authorize step.
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("an unauthorized session must be refused by the gate");
    let _ = session.into_disconnect().await;
    assert!(
        matches!(
            err,
            bussard_mgmt::load::WriteError::Mgmt(bussard_mgmt::MgmtError::Nak { .. })
        ),
        "the closed gate NAKs the first config write, got {err:?}"
    );
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_tolerates_a_device_without_authorize() -> TestResult {
    // An older/simpler device that does not implement authorize: it answers the
    // request with a non-authorize APCI rather than an A_Authorize_Response. The
    // tool must recognise that as "authorize unsupported", tolerate it (the gate
    // is open for such a device), keep the live connection, and complete the flash.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.authorize_unsupported = true;
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a device without authorize must be tolerated and flashed: {outcome:?}"
    );
    let s = lock(&state)?;
    assert!(s.authorizes_seen >= 1, "the tool still attempted authorize");
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_surfaces_access_denied_on_a_nonzero_level() -> TestResult {
    // A keyed device that grants only a non-zero (insufficient) level for the
    // presented free-access key: the tool must surface AccessDenied, not proceed.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.grant_level = 3; // deny full access
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    // authorize_or_fail must map the non-zero grant to AccessDenied.
    let err = {
        let mut l4 = l4;
        let e = l4
            .authorize_or_fail(0xFFFF_FFFF)
            .await
            .expect_err("a non-zero grant must be access-denied");
        let _ = l4.disconnect().await;
        e
    };
    match err {
        bussard_mgmt::MgmtError::AccessDenied { level, .. } => assert_eq!(level, 3),
        other => panic!("expected AccessDenied, got {other:?}"),
    }
    assert!(lock(&state)?.authorizes_seen >= 1);
    drop(handle);
    Ok(())
}

// ===========================================================================
// Master-reset (LdCtrlMasterReset) and terminal-restart-silence tests.
//
// A master reset is realised as an A_Restart with the master-reset bit set; the
// device confirms with an A_Restart_Response, then reboots and drops the L4
// connection. The download engine must reconnect ONCE, re-authorize, and resume
// the remaining steps. These tests run over the real bus actor + a leasing
// connector (like the CLI) so the Session can genuinely reconnect.
// ===========================================================================

/// A [`bussard_download::Connector`] that leases the bus actor to (re)open an L4
/// connection — the same shape the CLI's `LeaseConnector` uses. Unlike the raw
/// `Transport` the other tests borrow, this can be reconnected, which the
/// master-reset step requires after the device reboots.
struct LeaseConnector {
    handle: bussard_bus::BusHandle,
    target: bussard_model::IndividualAddress,
    source: bussard_model::IndividualAddress,
    /// The L4 timeout budget each opened connection uses. `None` keeps the default
    /// (3 s response/ACK); the resume-on-drop tests set a tiny budget so a modelled
    /// mid-write silence is detected in milliseconds rather than seconds, keeping
    /// the bounded-retry give-up test fast.
    timeouts: Option<bussard_mgmt::Timeouts>,
    /// The KNX Data Secure tool key (issue #71), `None` for the plain path. Set,
    /// every management APDU of every connection is wrapped in `A_SecureData`.
    secure_tool_key: Option<bussard_secure::Key16>,
    /// The send-sequence high-water mark shared across reconnects (spec §5.9).
    /// Without it a reconnect reseeds from the clock and replays sequences the
    /// device has already accepted, which an activated device refuses.
    secure_seq: bussard_secure::SequenceHighWater,
}

impl LeaseConnector {
    /// A plain connector (no KNX Secure), as every pre-#71 test uses.
    fn plain(
        handle: bussard_bus::BusHandle,
        target: bussard_model::IndividualAddress,
        source: bussard_model::IndividualAddress,
        timeouts: Option<bussard_mgmt::Timeouts>,
    ) -> Self {
        LeaseConnector {
            handle,
            target,
            source,
            timeouts,
            secure_tool_key: None,
            secure_seq: bussard_secure::SequenceHighWater::new(),
        }
    }

    /// A connector that presents `key` as the target's tool key.
    fn secure(
        handle: bussard_bus::BusHandle,
        target: bussard_model::IndividualAddress,
        source: bussard_model::IndividualAddress,
        timeouts: Option<bussard_mgmt::Timeouts>,
        key: [u8; 16],
    ) -> Self {
        LeaseConnector {
            secure_tool_key: Some(bussard_secure::Key16::new(key)),
            ..LeaseConnector::plain(handle, target, source, timeouts)
        }
    }
}

impl bussard_download::Connector for LeaseConnector {
    type Channel = bussard_mgmt::LeaseChannel;

    async fn connect(
        &mut self,
    ) -> Result<Layer4Connection<bussard_mgmt::LeaseChannel>, bussard_mgmt::load::WriteError> {
        // After a gateway link loss (issue #177) wait for the re-established
        // tunnel before the fresh T_Connect; immediate when connected.
        self.handle
            .wait_connected(self.handle.reconnect_budget())
            .await;
        let lease = self.handle.lease().await.map_err(|_| {
            bussard_mgmt::load::WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = bussard_mgmt::LeaseChannel::new(lease);
        // KNX Data Secure seam (issue #71, spec §6.1), exactly as the CLI builds
        // it: plain when no tool key is set, wrapped when one is.
        let secure = match &self.secure_tool_key {
            None => bussard_mgmt::SecureLayer::plain(),
            Some(key) => bussard_mgmt::SecureLayer::activated(
                bussard_secure::DataSecureSession::new(key.clone())
                    .with_high_water(self.secure_seq.clone()),
            ),
        };
        let timeouts = self.timeouts.unwrap_or_default();
        Layer4Connection::connect_with_secure(channel, self.target, self.source, timeouts, secure)
            .await
            .map_err(bussard_mgmt::load::WriteError::Mgmt)
    }

    fn link_losses(&self) -> u64 {
        self.handle.link_losses()
    }
}

/// Spins up the mock gateway and a bus actor over it, returning the actor handle
/// and shared device state. The caller drives the flash through a leasing
/// [`Session`] so it can reconnect.
async fn setup_bus(fault: Fault) -> TestResult<(bussard_bus::BusHandle, Shared, MockGateway)> {
    setup_bus_with(fresh_device(fault)).await
}

/// [`setup_bus`] over a caller-built device, so a test can start from a
/// security-activated mock ([`secure_device`]).
/// [`setup_bus_with`] with a caller-chosen tunnel re-establish policy (issue
/// #177). Also returns the gateway address, which a lost-tunnel error names.
async fn setup_bus_reconnect(
    state: Shared,
    reconnect: bussard_transport::TunnelReconnect,
) -> TestResult<(
    bussard_bus::BusHandle,
    Shared,
    MockGateway,
    std::net::SocketAddrV4,
)> {
    let gw = start_gateway(&state).await?;
    let gateway = gw.addr();
    let (handle, _actor) =
        bussard_bus::Bus::connect(ConnectionConfig::tunnel(gateway).with_reconnect(reconnect));
    handle.wait_connected(Duration::from_secs(5)).await;
    Ok((handle, state, gw, gateway))
}

async fn setup_bus_with(
    state: Shared,
) -> TestResult<(bussard_bus::BusHandle, Shared, MockGateway)> {
    let gw = start_gateway(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    handle.wait_connected(Duration::from_secs(5)).await;
    Ok((handle, state, gw))
}

#[tokio::test]
async fn flash_master_reset_reconnects_and_reaches_loaded() -> TestResult {
    // The full acceptance case for LdCtrlMasterReset: the procedure allocates the
    // segment, master-resets the device mid-flash, then writes the segment and
    // completes the load. The device confirms the reset, reboots (goes silent on
    // the L4 connection), and — modelling KNX Virtual's EraseCode=4 reset — ERASES
    // the app object's load state (back to Unloaded) and DROPS the segment
    // allocated before the reset (the mock's `wipe_app_on_master_reset`, enabled
    // below). The engine must reconnect, re-authorize, RE-RUN the load-control
    // sequence (StartLoading + re-allocate) so the segment is re-established at its
    // fresh device-placed base, and only then resume the write — exactly as ETS
    // does after the reset in the real KV capture. A tool that naively resumed
    // writing to the stale pre-reset base while the object is Unloaded/erased would
    // be NAKed by the device (regression asserted below via the erased-write gate).
    // Shorten the reboot wait so the test does not stall.
    // SAFETY of env: this test binds its own socket/actor; the var only shortens a
    // sleep and is read once per master-reset step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }

    let (handle, state, gw) = setup_bus(Fault::None).await?;
    // Model KV's EraseCode=4: the master reset wipes the app object to Unloaded and
    // drops its segment, so the re-allocation after the reconnect must be placed at
    // a FRESH base and the tool must re-read it (not reuse the stale pre-reset one).
    lock(&state)?.wipe_app_on_master_reset = true;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = app_with_master_reset()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The plan lowers the master reset to a MasterReset step carrying the op's
    // EraseCode/ChannelNumber.
    let master_resets: Vec<&FlashStep> = plan
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::MasterReset { .. }))
        .collect();
    assert_eq!(
        master_resets.len(),
        1,
        "the master reset lowers to one step"
    );
    assert!(matches!(
        master_resets[0],
        FlashStep::MasterReset {
            erase_code: 4,
            channel_number: 0
        }
    ));

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "a master-reset flash must reconnect, resume, and verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);

    {
        let s = lock(&state)?;
        // The tool issued exactly one master reset, and it was a BARE A_Restart
        // (0x380) with NO payload — exactly as ETS→KNX-Virtual sends it, NOT the
        // confirmed master-reset A_Restart (0x381 + [erase_code, channel_number]).
        assert_eq!(
            s.master_resets_seen, 1,
            "exactly one master reset was issued"
        );
        assert!(
            s.last_master_reset_payload.is_empty(),
            "the master reset must be a bare A_Restart with no payload, got {:?}",
            s.last_master_reset_payload
        );
        // The device did see the bare basic-restart APCI on the wire.
        assert!(
            s.saw_basic_restart,
            "the master reset must be realised as a bare 0x380 A_Restart"
        );
        // The device reconnected: at least two L4 T_Connects (the original plus the
        // post-reboot reconnect).
        assert!(
            s.connects >= 2,
            "the engine must reconnect after the reboot (connects = {})",
            s.connects
        );
        // The tool re-authorized on the fresh connection (one per connection window).
        assert!(
            s.authorizes_seen >= 2,
            "the engine must re-authorize after the reconnect (authorizes = {})",
            s.authorizes_seen
        );
        // The master reset erased the object, so the re-allocation after the
        // reconnect is placed at a FRESH base (pre-reset base 0x4000 + dropped
        // size 6 = 0x4006). The tool must have re-read that fresh base and written
        // the code image there — proving it re-established the segment and updated
        // `segment_base` rather than reusing the stale pre-reset value.
        let fresh: Vec<u8> = (0x4006u16..0x400C)
            .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
            .collect();
        assert_eq!(
            fresh,
            vec![0, 1, 2, 3, 4, 5],
            "the post-reset segment write must land at the freshly re-allocated base 0x4006"
        );
        // REGRESSION: a naive resume that kept writing to the STALE pre-reset base
        // (0x4000) is exactly the bug being fixed. The erased object refuses writes
        // (the write gate NAKs while Unloaded), so no code image ever reaches the
        // stale base — it stays untouched. Had the engine written there, the flash
        // would have failed on the NAK; asserting the stale base is empty pins the
        // fix to re-establishing the segment before the resumed write.
        let stale: Vec<u8> = (0x4000u16..0x4006)
            .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
            .collect();
        assert_eq!(
            stale,
            vec![0, 0, 0, 0, 0, 0],
            "the stale pre-reset base 0x4000 must never be written after the erase"
        );
        // The object was re-opened (StartLoading) after the reset, so the
        // erased-write gate is cleared and the load reached Loaded.
        assert!(
            !s.app_erased_by_master_reset,
            "the engine must re-open the erased object before resuming"
        );
    }

    let _ = handle.close().await;
    drop(gw);
    unsafe {
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

/// The #168 readiness probe after a master reset, behind an interface that
/// reports negative `L_Data.con`s (issue #45): while the device boots, every
/// probe frame comes back negatively confirmed. The probe must read that as
/// "not up yet" and poll again, never as "absent", and the flash completes once
/// the device answers.
#[tokio::test]
async fn test_flash_reboot_probe_treats_negative_con_as_not_up_yet() -> TestResult {
    // SAFETY of env: nextest runs this test in its own process; the var only
    // bounds the post-reboot poll (first probe after 1.5 s, then every 0.5 s).
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "4000");
    }
    let state = fresh_device(Fault::None);
    // Booting 0.7 s from the first post-reset probe: the first probe is
    // negatively confirmed and times out, a later one finds the device up.
    {
        let mut s = lock(&state)?;
        s.boot_silence = Some(Duration::from_millis(700));
        // The KNX Virtual master reset of `app_with_master_reset`: a bare
        // A_Restart that reboots the device.
        s.wipe_app_on_master_reset = true;
    }
    let gw = start_gateway_booting(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    handle.wait_connected(Duration::from_secs(5)).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        &app_with_master_reset()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    let _ = handle.close().await;
    drop(gw);

    assert!(outcome.ok(), "the flash must complete: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    let s = lock(&state)?;
    assert!(
        s.negative_cons >= 1,
        "the booting device was negatively confirmed at least once"
    );
    assert!(s.booting_until.is_some(), "the boot window was entered");
    // The original connection, at least one unanswered probe, the probe that
    // found the device up and the session reconnect.
    assert!(
        s.connects >= 3,
        "the probe polled past the negative con (connects = {})",
        s.connects
    );
    Ok(())
}

#[tokio::test]
async fn flash_cycles_l4_connection_before_the_exchange_budget_and_reaches_loaded() -> TestResult {
    // Proactive periodic L4 reconnection (the ETS pattern): a real
    // connection-oriented device drops a long-held L4 connection after a bounded
    // number of numbered exchanges (KNX Virtual DA.tp at ~35). Running the whole
    // flash on ONE connection sits at that edge and fails ~half the time. The fix
    // is to cycle the L4 connection (graceful T_Disconnect / T_Connect +
    // re-authorize) BETWEEN steps once the connection's numbered-exchange count
    // crosses a threshold well under the budget — the objects' load states and
    // allocated segments persist across the cycle, so the procedure resumes
    // seamlessly.
    //
    // This test proves both halves:
    //   1. Even WITHOUT proactive cycling (threshold 0 = disabled), resume-on-drop
    //      alone recovers: a device with a low per-connection exchange budget drops
    //      the connection mid-flash, and the engine reconnects and replays the
    //      dropped step until the flash reaches `Loaded` (the second safety net —
    //      each step is small enough to finish inside one budget window). This is
    //      the resilience that makes the non-deterministic live-KV drop survivable.
    //   2. WITH proactive cycling at a low threshold, the flash cycles the
    //      connection *before* the budget every time and reaches `Loaded` — and the
    //      device saw several T_Connects (the periodic reconnects) with graceful
    //      T_Disconnects (a clean cycle, not a drop-and-resume).
    //
    // SAFETY of env: nextest runs each test in its own process, so these
    // process-global vars are isolated to this test; they only tune a sleep and
    // the reconnect threshold and are read once per step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }

    // A per-connection budget below the fabricated procedure's total exchange
    // count, but above the low threshold we cycle at — so a single connection dies
    // yet cycling keeps every window under budget.
    const BUDGET: u32 = 12;
    const THRESHOLD: u32 = 5;

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;

    // --- 1. Proactive cycling OFF: resume-on-drop alone still reaches Loaded. ---
    unsafe {
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0");
    }
    {
        let (handle, state, gw) = setup_bus(Fault::None).await?;
        lock(&state)?.die_after_exchanges = Some(BUDGET);
        let source = bussard_bus::ops::group_source(&handle);
        let app = fabricated_app()?;
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        // Fast L4 timeouts: the drop the mock forces below is only observed as
        // silence, so with the default 3 s ACK budget x repetitions each
        // forced drop would cost seconds of pure waiting (~24 s for the test).
        let connector =
            LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
        let mut session = Session::open_with_key(connector, None).await?;
        let outcome = flash(
            &mut session,
            &plan,
            bussard_download::FlashOptions::default(),
            |_| {},
        )
        .await
        .map_err(|e| {
            format!(
                "{}: {e:?}",
                "resume-on-drop alone must recover the dropped connection and finish the flash"
            )
        })?;
        let _ = session.into_disconnect().await;
        assert!(
            outcome.ok(),
            "the resumed flash must verify as Loaded: {outcome:?}"
        );
        {
            let s = lock(&state)?;
            // The single-connection budget was exceeded at least once, so the engine
            // must have reconnected (resume-on-drop) to finish — several T_Connects.
            assert!(
                s.connects >= 2,
                "resume-on-drop must reconnect the dropped connection (connects = {})",
                s.connects
            );
        }
        let _ = handle.close().await;
        drop(gw);
    }

    // --- 2. With the fix: cycling before the budget reaches Loaded reliably. ---
    unsafe {
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", THRESHOLD.to_string());
    }
    {
        let (handle, state, gw) = setup_bus(Fault::None).await?;
        lock(&state)?.die_after_exchanges = Some(BUDGET);
        let source = bussard_bus::ops::group_source(&handle);
        let app = fabricated_app()?;
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        // Fast L4 timeouts, as in the first half.
        let connector =
            LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
        let mut session = Session::open_with_key(connector, None).await?;
        let outcome = flash(
            &mut session,
            &plan,
            bussard_download::FlashOptions::default(),
            |_| {},
        )
        .await
        .map_err(|e| {
            format!(
                "{}: {e:?}",
                "proactive cycling must keep every window under budget and complete the flash"
            )
        })?;
        let _ = session.into_disconnect().await;
        assert!(
            outcome.ok(),
            "the cycled flash must verify as Loaded: {outcome:?}"
        );
        assert_eq!(outcome.load_state, LoadState::Loaded);
        {
            let s = lock(&state)?;
            // The engine cycled the connection at least once (the original connect
            // plus one proactive reconnect) to stay under the budget.
            assert!(
                s.connects >= 2,
                "the flash must cycle the L4 connection to stay under the budget (connects = {})",
                s.connects
            );
            // It re-authorized on each fresh window.
            assert!(
                s.authorizes_seen >= 2,
                "each reconnected window must re-authorize (authorizes = {})",
                s.authorizes_seen
            );
            // The connection was gracefully closed each cycle (T_Disconnect), not
            // just dropped: at least one clean teardown before the terminal one.
            assert!(
                s.disconnects >= 1,
                "a proactive cycle must gracefully T_Disconnect (disconnects = {})",
                s.disconnects
            );
        }
        let _ = handle.close().await;
        drop(gw);
    }

    unsafe {
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

#[tokio::test]
async fn authorize_is_cached_and_not_repeated_on_a_device_without_authorize() -> TestResult {
    // A device that does not implement authorize answers the request with silence,
    // so each reconnect/cycle window burns a full RESPONSE_TIMEOUT re-presenting a
    // key it will never answer. The session caches the first Unsupported outcome
    // and skips the re-authorize on later windows (issue #58): with proactive
    // cycling forcing several fresh connections, the device must see exactly ONE
    // A_Authorize_Request even though it connected multiple times.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    const BUDGET: u32 = 12;
    const THRESHOLD: u32 = 5;
    unsafe {
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", THRESHOLD.to_string());
    }

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;

    let (handle, state, gw) = setup_bus(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.authorize_unsupported = true;
        s.die_after_exchanges = Some(BUDGET);
    }
    let source = bussard_bus::ops::group_source(&handle);
    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "a device without authorize must still flash while cycling connections"
        )
    })?;
    let _ = session.into_disconnect().await;
    assert!(outcome.ok(), "the cycled flash must verify: {outcome:?}");

    {
        let s = lock(&state)?;
        // Several fresh connections were opened (initial + proactive cycles).
        assert!(
            s.connects >= 2,
            "the flash must have cycled the connection (connects = {})",
            s.connects
        );
        // ...yet the device was asked to authorize exactly ONCE: the cached
        // Unsupported outcome suppressed the wasted re-authorize on every later
        // window. This is the whole point of the cache.
        assert_eq!(
            s.authorizes_seen, 1,
            "a device without authorize must be asked exactly once ({} connects, {} authorizes)",
            s.connects, s.authorizes_seen
        );
    }
    let _ = handle.close().await;
    drop(gw);

    unsafe {
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

#[tokio::test]
async fn test_open_with_facts_reuses_the_preflight_table_and_authorize_verdict() -> TestResult {
    // The CLI's read-only pre-flight already walked PID_OBJECT_TYPE and found the
    // device does not implement authorize. A session opened with those facts
    // must neither walk the object table again nor re-present the key, and the
    // flash must still verify.
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let (handle, state, gw) = setup_bus(Fault::None).await?;
    state
        .lock()
        .map_err(|e| e.to_string())?
        .authorize_unsupported = true;
    let source = bussard_bus::ops::group_source(&handle);

    // Phase A, as the CLI runs it: its own connection, table walk, disconnect.
    let mut preflight = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut l4 = bussard_download::Connector::connect(&mut preflight).await?;
    let object_table = bussard_mgmt::probe_object_types(&mut l4).await?;
    let _ = l4.disconnect().await;
    let (reads_before, authorizes_before) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.object_type_reads, s.authorizes_seen)
    };
    assert!(reads_before > 0, "the pre-flight walked the table");

    let facts = bussard_download::DeviceFacts {
        object_table,
        authorize: Some(bussard_mgmt::AuthorizeOutcome::Unsupported {
            detail: "pre-flight: no answer".to_string(),
        }),
        max_apdu: None,
    };
    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_facts(connector, None, facts).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    assert!(
        outcome.ok(),
        "a facts-seeded flash must verify: {outcome:?}"
    );

    {
        let s = state.lock().map_err(|e| e.to_string())?;
        assert_eq!(
            s.object_type_reads, reads_before,
            "the write phase must not walk the object table again"
        );
        assert_eq!(
            s.authorizes_seen, authorizes_before,
            "a device known not to implement authorize must not be asked again"
        );
    }
    let _ = handle.close().await;
    drop(gw);
    Ok(())
}

/// A single-application System B app whose code segment is 256 bytes of 0xFF, so
/// its `WriteRelMem` spans several `A_Memory_Write` chunks (63 octets each) — big
/// enough that a low per-connection exchange budget drops the connection *strictly
/// inside* the write, exercising resume-on-drop of a partially-written segment.
fn fabricated_app_big() -> TestResult<ApplicationProgram> {
    let data = base64_ff_256();
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-9_A-1" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Big" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-9_A-1_RS-1" Size="256" LoadStateMachine="4" Offset="0"><Data>{data}</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="256" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="256" AppliesTo="full" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    Ok(parse_application_program("M-9_A-1", xml.as_bytes())?)
}

#[tokio::test]
async fn flash_resumes_when_connection_drops_inside_a_write() -> TestResult {
    // Resume-on-drop, the live-KV reliability fix: KNX Virtual drops the
    // connection-oriented L4 connection at a NON-DETERMINISTIC exchange count, so no
    // fixed proactive threshold is reliable. When a step dies from that unexpected
    // mid-flow connection death, the engine must reconnect, re-authorize, and REPLAY
    // the step — load state and allocated segments are persistent device state that
    // survive the drop, so re-running the step is safe.
    //
    // Here proactive cycling is DISABLED (threshold 0) so ONLY resume-on-drop can
    // save the flash. The app's 256-byte segment is written across several chunks;
    // a low per-connection budget drops the connection strictly INSIDE that write.
    // The engine reconnects and replays the write on a fresh, budget-reset window
    // (whose whole allowance covers the single remaining write step), completing the
    // 256 bytes across windows and reaching Loaded.
    //
    // SAFETY of env: nextest isolates process-global vars per test; these only tune
    // a sleep and disable proactive cycling, read once per step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0");
    }

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let (handle, state, gw) = setup_bus(Fault::None).await?;
    // Budget above the discovery+authorize+load-control preamble but low enough that
    // the multi-chunk write trips it — the drop lands inside the write. On the fresh
    // window the preamble is not re-run (only the write step replays), so the budget
    // comfortably covers finishing the segment.
    // 7 since the load-control writes trust the echoed state (issue #211):
    // StartLoading and the allocation send three requests fewer.
    lock(&state)?.die_after_exchanges = Some(7);
    let source = bussard_bus::ops::group_source(&handle);
    let app = fabricated_app_big()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "resume-on-drop must recover the mid-write connection death and finish"
        )
    })?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "the resumed flash must verify as Loaded: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    {
        let s = lock(&state)?;
        // The connection was dropped mid-flash, so the engine reconnected at least
        // once to resume (several T_Connects).
        assert!(
            s.connects >= 2,
            "resume-on-drop must reconnect after the mid-write drop (connects = {})",
            s.connects
        );
        // The whole 256-byte segment landed at the segment base despite the drop.
        let full: Vec<u8> = (0x4000u16..0x4000 + 256)
            .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
            .collect();
        assert_eq!(
            full,
            vec![0xFFu8; 256],
            "every byte of the segment must be written across the resumed windows"
        );
    }
    let _ = handle.close().await;
    drop(gw);

    unsafe {
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

/// A re-establish policy fast enough for the tunnel-loss tests (issue #177):
/// attempts every 100-200 ms, each waiting 300 ms, within `budget`.
fn fast_reconnect(budget: Duration) -> bussard_transport::TunnelReconnect {
    bussard_transport::TunnelReconnect {
        budget,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(200),
        attempt_timeout: Duration::from_millis(300),
        ..bussard_transport::TunnelReconnect::default()
    }
}

/// Locks the shared mock state, turning a poisoned lock into a test error.
fn lock(state: &Shared) -> Result<std::sync::MutexGuard<'_, DeviceState>, String> {
    state
        .lock()
        .map_err(|_| "mock device state poisoned".to_string())
}

#[tokio::test]
async fn test_flash_resumes_after_gateway_tunnel_loss_mid_write() -> TestResult {
    // Issue #177 (S2.6 of #90): the IP interface's LAN cable is pulled for a few
    // seconds in the middle of the segment write. The gateway swallows every
    // datagram (the pending memory write, its retransmit, the first
    // re-establish attempts); meanwhile the device drops its L4 connection (its
    // idle timeout). The tunnel re-establishes itself and re-sends the pending
    // frame; the device, now L4-dead, stays silent; the flash classifies that as
    // a connection death, reconnects L4 and resumes the write from the last
    // confirmed chunk, then verifies Loaded.
    //
    // SAFETY of env: nextest isolates process-global vars per test; these only
    // tune a sleep and disable proactive cycling.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0");
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let state = fresh_device(Fault::None);
    {
        let mut s = lock(&state)?;
        s.tunnel_outage = Some((3, Duration::from_millis(2500)));
        s.outage_kills_l4 = true;
    }
    let (handle, state, gw, _gateway) =
        setup_bus_reconnect(state, fast_reconnect(Duration::from_secs(20))).await?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        &fabricated_app_big()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "the resumed flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    {
        let s = lock(&state)?;
        assert!(
            s.outage_swallowed >= 2,
            "the outage swallowed the pending frame and its retransmit"
        );
        assert!(
            s.tunnel_connects >= 2,
            "the tunnel was re-established (connects = {})",
            s.tunnel_connects
        );
        assert!(
            s.connects >= 2,
            "L4 reconnected after the outage (T_Connects = {})",
            s.connects
        );
        let full: Vec<u8> = (0x4000u32..0x4000 + 256)
            .map(|a| *s.memory.get(&a).unwrap_or(&0))
            .collect();
        assert_eq!(
            full,
            vec![0xFFu8; 256],
            "the whole segment landed across the outage"
        );
    }
    let _ = handle.close().await;
    drop(gw);
    unsafe {
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

#[tokio::test]
async fn test_flash_fails_with_gateway_hint_when_tunnel_never_returns() -> TestResult {
    // Issue #177: the link goes down mid-write and never comes back. After the
    // re-establish budget the flash fails with the original ACK timeout plus a
    // hint that names the gateway, instead of hanging or resuming forever.
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let state = fresh_device(Fault::None);
    lock(&state)?.tunnel_outage = Some((3, Duration::MAX));
    let (handle, _state, gw, gateway) =
        setup_bus_reconnect(state, fast_reconnect(Duration::from_secs(2))).await?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        &fabricated_app_big()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
    let mut session = Session::open_with_key(connector, None).await?;
    let started = std::time::Instant::now();
    let result = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await;
    let elapsed = started.elapsed();
    let Err(err) = result else {
        return Err("a flash whose gateway never returns must fail".into());
    };
    let text = err.to_string();
    assert!(
        text.contains("timed out waiting for TUNNELING_ACK"),
        "{text}"
    );
    assert!(
        text.contains("could not be re-established within 2 s"),
        "{text}"
    );
    assert!(
        text.contains(&gateway.to_string()),
        "the error names the gateway: {text}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "gave up after {elapsed:?}"
    );
    drop(session);
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn flash_gives_up_cleanly_when_a_device_never_makes_progress() -> TestResult {
    // The bound on resume-on-drop: a genuinely dead device that answers NOTHING —
    // it drops every numbered exchange on every window, so not one probe, write, or
    // read ever confirms — must fail cleanly after the retry budget, never loop
    // forever. (Resume-on-drop makes forward progress at primitive/chunk
    // granularity, so a device that lets even one exchange through is recoverable;
    // only a device that makes ZERO progress hits the give-up bound.)
    //
    // `die_after_exchanges = 0` drops the FIRST numbered exchange on every
    // connection — the device is effectively silent. Discovery's first probe dies;
    // resume-on-drop reconnects and re-probes; it dies again at the same point with
    // no forward progress. After the bound of consecutive fruitless reconnects the
    // flash surfaces the connection-death error rather than spinning.
    //
    // SAFETY of env: nextest isolates these process-global vars; they only tune a
    // sleep and disable proactive cycling, read once per step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0");
    }

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let (handle, state, gw) = setup_bus(Fault::None).await?;
    // Drop every numbered exchange (budget 0): the device answers nothing, so no
    // operation can make any forward progress on any window.
    lock(&state)?.die_after_exchanges = Some(0);
    let source = bussard_bus::ops::group_source(&handle);
    let app = fabricated_app_big()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
    let mut session = Session::open_with_key(connector, None).await?;
    // Bound the wall-clock so a regression that loops forever fails the test loudly
    // rather than hanging: the give-up must happen within a handful of reconnects.
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        flash(
            &mut session,
            &plan,
            bussard_download::FlashOptions::default(),
            |_| {},
        ),
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "resume-on-drop must give up (not hang) when the device never makes progress"
        )
    })?;
    let _ = session.into_disconnect().await;

    assert!(
        result.is_err(),
        "a device that never makes progress must fail the flash, got {result:?}"
    );
    {
        let s = lock(&state)?;
        // It DID retry (reconnected) before giving up — resume-on-drop was exercised,
        // it just could not make progress — but the number of reconnects is bounded,
        // proving no infinite loop.
        assert!(
            s.connects >= 2,
            "the engine must have retried at least once before giving up (connects = {})",
            s.connects
        );
        assert!(
            s.connects <= 8,
            "resume-on-drop must be BOUNDED — a stuck device may not reconnect forever \
             (connects = {})",
            s.connects
        );
    }
    let _ = handle.close().await;
    drop(gw);

    unsafe {
        std::env::remove_var("BUSSARD_FLASH_RECONNECT_EXCHANGES");
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    Ok(())
}

#[tokio::test]
async fn flash_final_restart_silence_is_success_not_failure() -> TestResult {
    // The terminal LdCtrlRestart is the SUCCESSFUL last step: bussard sends
    // A_Restart, the device reboots and goes silent, and that silence must be
    // treated as success — NOT surfaced as "device absent". The mock goes silent
    // on the current connection right after the basic restart; the flash must
    // still return Ok with load_state == Loaded (verified BEFORE the restart).
    let (handle, state, gw) = setup_bus(Fault::SilentAfterBasicRestart).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // The procedure ends with a Restart step.
    assert!(
        matches!(plan.steps.last(), Some(FlashStep::Restart)),
        "the fabricated procedure ends with a restart"
    );

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "the final-restart silence must be success, not a flash failure"
        )
    })?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "the flash must verify before the terminal restart: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    assert!(lock(&state)?.saw_basic_restart, "the restart was sent");

    let _ = handle.close().await;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn flash_verifies_after_terminal_restart_when_it_can_reconnect() -> TestResult {
    // With `verify_after_restart` set (the real `bussard flash`), the terminal
    // restart is fired, the reboot is waited out, the connection is re-opened and
    // re-authorized, and the load state is re-read on the FRESH connection. A
    // device whose load survives the reboot must still verify as `Loaded`.
    // Shorten the reboot wait so the test does not stall.
    // SAFETY of env: this test binds its own socket/actor; the var only shortens a
    // sleep and is read once per restart step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }

    let (handle, state, gw) = setup_bus(Fault::SilentAfterBasicRestart).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            bcu_key: None,
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "a persisting flash must verify after the restart"
        )
    })?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "the load persisted across the reboot, so the post-restart verify must pass: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    {
        let s = lock(&state)?;
        assert!(s.saw_basic_restart, "the terminal restart was sent");
        // The tool opened at least two connection windows: the flash proper, then
        // the post-reboot reconnect for the verify.
        assert!(
            s.connects >= 2,
            "the tool must reconnect after the restart to verify (connects={})",
            s.connects
        );
    }

    // SAFETY: same justification as the set above; clean up so other tests are
    // unaffected.
    unsafe {
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    let _ = handle.close().await;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn flash_fails_when_load_does_not_persist_across_the_restart() -> TestResult {
    // The false-positive this fixes: KNX Virtual reports a transient `Loaded`
    // before the terminal restart, then comes back up `Unloaded` when the written
    // image is content-incomplete. A pre-restart verify would report success; the
    // post-restart verify (this path) re-reads the load state after the reboot and
    // must FAIL the flash because the app object is `Unloaded`.
    // SAFETY of env: this test binds its own socket/actor; the var only shortens a
    // sleep and is read once per restart step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }

    let (handle, state, gw) = setup_bus(Fault::UnloadedAfterBasicRestart).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            bcu_key: None,
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await
    .map_err(|e| {
        format!(
            "{}: {e:?}",
            "the flash executes; the non-persisting load is caught by the verify, not an error"
        )
    })?;
    let _ = session.into_disconnect().await;

    // The load did NOT persist: the post-restart verify read `Unloaded`, so the
    // outcome must NOT be `ok()` — a non-persisting flash is never reported as a
    // success.
    assert!(
        !outcome.ok(),
        "a load that reverted to Unloaded after the restart must fail verification: {outcome:?}"
    );
    assert_eq!(
        outcome.load_state,
        LoadState::Unloaded,
        "the post-restart re-read must observe the reverted (non-persisting) state"
    );
    assert!(
        lock(&state)?.saw_basic_restart,
        "the terminal restart was sent"
    );

    // SAFETY: same justification as the set above.
    unsafe {
        std::env::remove_var("BUSSARD_FLASH_REBOOT_WAIT_MS");
    }
    let _ = handle.close().await;
    drop(gw);
    Ok(())
}

/// The ETS→KNX-Virtual DA.tp shape: the application-program-TYPE object is at
/// index 3 (base 0x8000) but ETS writes the app segment to object index 4 (base
/// 0x6000), named by the procedure's `ObjIdx=4`/`LsmIdx=4`. This proves bussard
/// resolves the write target by index, not by object type (the divergence-#2 fix):
/// the load-control sequence, the PID7 base read, and the memory write all target
/// object 4 — never the type-discovered object 3.
#[tokio::test]
async fn flash_targets_the_obj_idx_object_not_the_type_object() -> TestResult {
    // Object table: obj0 device, obj1 address, obj2 association, obj3
    // application-program (type 3 — what a type probe discovers), obj4 the app
    // segment (type 4). Model the loadable state on obj4 (the ObjIdx the write
    // names), so a tool that wrongly targeted the type-discovered obj3 would find
    // it Unloaded and fail.
    let state = fresh_device(Fault::None);
    {
        let mut s = lock(&state)?;
        s.object_types = vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_APPLICATION_PROGRAM, // index 3, type 3 — the type-discovered object
            4,                      // index 4, type 4 — the app segment ETS writes
        ];
        s.loadable_object_override = Some(4);
    }
    let (mut bus, state, handle) = setup_device(state).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    // A DA.tp-shape procedure: allocate LsmIdx=4, write ObjIdx=4.
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-1_A-DA" MaskVersion="MV-07B0" Name="DA"
        LoadProcedureStyle="ProductDefault">
      <Static>
       <Code><RelativeSegment Id="M-1_A-DA_RS-04" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    let app = parse_application_program("M-1_A-DA", xml.as_bytes())?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    // The flash routes every load-control write, the PID7 base read, and the memory
    // write to object 4 (the ObjIdx). The final verify re-reads the
    // type-discovered object's load state — which for this device is obj3 (Unloaded
    // in this minimal single-loadable-object mock) — so `outcome.ok()` is not the
    // signal here; the routing is. (A real KNX-Virtual loads all four objects, so
    // its verify passes.) We assert the flash ran to completion and routed
    // correctly.
    let _ = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    let s = lock(&state)?;
    // Every load-control write (Unload, StartLoading, LoadCompleted, and the
    // allocate) targeted object 4 — never the type-discovered object 3.
    assert!(
        !s.load_control_targets.is_empty(),
        "the flash drove load-control writes"
    );
    assert!(
        s.load_control_targets.iter().all(|&oi| oi == 4),
        "all load-control writes must target object 4 (the ObjIdx), got {:?}",
        s.load_control_targets
    );
    assert!(
        !s.load_control_targets.contains(&3),
        "no load-control write may target the type-discovered object 3"
    );
    // The per-object PID7 base read targeted object 4 (the base for its write).
    assert!(
        s.pid7_reads.contains(&4),
        "the tool must read PID7 (the base) from object 4, got {:?}",
        s.pid7_reads
    );
    // The app segment image landed at object 4's segment base (0x4000, the mock's
    // first allocation base), proving the write used obj4's PID7 base.
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
        .collect();
    assert_eq!(
        code,
        vec![0, 1, 2, 3, 4, 5],
        "the app image landed at obj4's base"
    );

    drop(handle);
    Ok(())
}

/// The MV-07B0 `Load/all` master-template op list, verbatim from the real
/// `knx_master.xml` (parsed so the fixture cannot drift from the parser). This is
/// the skeleton the DA.tp app's MergeId 2/4 blocks splice into.
fn master_template_all_ops() -> TestResult<Vec<bussard_prod::LoadOp>> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <MaskVersion Id="MV-07B0" Name="System B">
      <Procedures>
       <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote local2">
        <LdCtrlConnect />
        <LdCtrlMerge MergeId="1" />
        <LdCtrlUnload LsmIdx="5" />
        <LdCtrlUnload LsmIdx="4" />
        <LdCtrlUnload LsmIdx="3" />
        <LdCtrlUnload LsmIdx="2" />
        <LdCtrlUnload LsmIdx="1" />
        <LdCtrlLoad LsmIdx="5" />
        <LdCtrlMerge MergeId="3" />
        <LdCtrlLoad LsmIdx="4" />
        <LdCtrlMerge MergeId="2" />
        <LdCtrlLoad LsmIdx="3" />
        <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
        <LdCtrlLoad LsmIdx="1" />
        <LdCtrlRelSegment LsmIdx="1" Size="2" Mode="0" Fill="0" />
        <LdCtrlLoad LsmIdx="2" />
        <LdCtrlRelSegment LsmIdx="2" Size="2" Mode="0" Fill="0" />
        <LdCtrlMerge MergeId="5" />
        <LdCtrlMerge MergeId="4" />
        <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" Verify="true" />
        <LdCtrlWriteRelMem ObjIdx="2" Offset="0" Size="1048576" Verify="true" />
        <LdCtrlWriteRelMem ObjIdx="1" Offset="0" Size="1048576" Verify="true" />
        <LdCtrlWriteProp ObjIdx="5" PropId="13" Verify="true" InlineData="0000000000" />
        <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
        <LdCtrlLoadCompleted LsmIdx="5" />
        <LdCtrlLoadCompleted LsmIdx="4" />
        <LdCtrlLoadCompleted LsmIdx="3" />
        <LdCtrlLoadCompleted LsmIdx="2" />
        <LdCtrlLoadCompleted LsmIdx="1" />
        <LdCtrlMerge MergeId="6" />
        <LdCtrlMerge MergeId="7" />
        <LdCtrlRestart />
       </Procedure>
      </Procedures>
     </MaskVersion></KNX>"#;
    let t = bussard_prod::parse_master_template(xml.as_bytes(), "test")?;
    Ok(t.full_load_procedure("07B0")
        .ok_or("the template has a 07B0 procedure")?
        .ops
        .clone())
}

/// 256 bytes of 0xFF as base64 (the DA.tp app segment `<Data>`).
fn base64_ff_256() -> String {
    // 256 = 85*3 + 1: 85 groups of 0xFFFFFF ("////") then one trailing 0xFF.
    let mut s = "////".repeat(85); // 255 bytes
    s.push_str("/w=="); // one more 0xFF byte
    s
}

/// The KNX-Virtual DA.tp merged application: only its own MergeId 2 (allocate the
/// app segment + master reset) and MergeId 4 (write the app segment) blocks; one
/// 256-byte LSM4 relative segment of 0xFF (like the real app).
fn app_da_tp() -> TestResult<ApplicationProgram> {
    app_da_tp_with("")
}

/// [`app_da_tp`] plus a MergeId 7 block with the `LdCtrlLoadImageProp` MCB
/// checks of objects 1 to 4, as the real 07B0 applications carry.
fn app_da_tp_with_mcb_checks() -> TestResult<ApplicationProgram> {
    app_da_tp_with(
        r#"<LoadProcedure MergeId="7">
         <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
         <LdCtrlLoadImageProp ObjIdx="4" PropId="27" />
        </LoadProcedure>"#,
    )
}

/// [`app_da_tp`] with `extra` load procedures appended.
fn app_da_tp_with(extra: &str) -> TestResult<ApplicationProgram> {
    let data = base64_ff_256();
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-00FA_A-DA" ApplicationNumber="9472" ApplicationVersion="16"
        MaskVersion="MV-07B0" Name="Dimming" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-00FA_A-DA_RS-04" Size="256" LoadStateMachine="4" Offset="0"><Data>{data}</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="2">
         <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0" Fill="0" />
         <LdCtrlMasterReset EraseCode="4" ChannelNumber="0" />
        </LoadProcedure>
        <LoadProcedure MergeId="4">
         <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="256" Verify="false" />
        </LoadProcedure>
        {extra}
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    Ok(parse_application_program("M-00FA_A-DA", xml.as_bytes())?)
}

/// A full 4-object flash of the KNX-Virtual DA.tp shape: the master `Load/all`
/// template spliced with the app's MergeId 2/4 blocks programs obj4 (app), obj3
/// (group-object table), obj2 (association), obj1 (address) — each with its own
/// StartLoading → allocate → PID7 base read → memory write → LoadCompleted — and
/// the LSM5 template ops are skipped (the device has no obj5). The final verify
/// confirms every programmed object reached Loaded.
#[tokio::test]
async fn flash_da_tp_programs_all_four_objects() -> TestResult {
    flash_da_tp_four_objects(false, false).await.map(|_| ())
}

/// Issue #215: after the terminal restart the verify reads only what decides,
/// the application object's type (the confirm probe) and its load state. The
/// three table objects keep the `Loaded` their `LoadCompleted` confirmed, and
/// the four memory samples are covered by the passed MCB checks. Before this
/// change the same flash read `PID_OBJECT_TYPE`, four `PID_LOAD_STATE`s and
/// four memory samples (9 reads).
#[tokio::test]
async fn test_flash_post_restart_verify_reads_only_what_decides() -> TestResult {
    let (outcome, state) = flash_da_tp_four_objects(true, true).await?;
    assert!(outcome.ok(), "the flash must verify: {outcome:?}");
    let s = lock(&state)?;
    let log = s
        .after_terminal_restart
        .as_ref()
        .ok_or("the terminal restart was not seen")?;
    let property_reads = log.iter().filter(|a| **a == A_PROPERTY_VALUE_READ).count();
    let memory_reads = log
        .iter()
        .filter(|a| **a & APCI_SELECTOR == A_MEMORY_READ_SEL || **a == A_MEMORY_EXTENDED_READ)
        .count();
    println!("post-restart reads: property {property_reads}, memory {memory_reads}");
    assert_eq!(
        (property_reads, memory_reads),
        (2, 0),
        "one PID_OBJECT_TYPE and one PID_LOAD_STATE after the restart; got {log:x?}"
    );
    Ok(())
}

/// Issue #215: a segment no MCB check covers keeps its post-restart memory
/// sample (the DA.tp template here carries no `LdCtrlLoadImageProp`).
#[tokio::test]
async fn test_flash_post_restart_verify_keeps_samples_without_mcb_checks() -> TestResult {
    let (outcome, state) = flash_da_tp_four_objects(true, false).await?;
    assert!(outcome.ok(), "the flash must verify: {outcome:?}");
    let s = lock(&state)?;
    let log = s
        .after_terminal_restart
        .as_ref()
        .ok_or("the terminal restart was not seen")?;
    let memory_reads = log
        .iter()
        .filter(|a| **a & APCI_SELECTOR == A_MEMORY_READ_SEL || **a == A_MEMORY_EXTENDED_READ)
        .count();
    assert_eq!(
        memory_reads, 4,
        "one sample per written segment; got {log:x?}"
    );
    Ok(())
}

/// The DA.tp 4-object flash of [`flash_da_tp_programs_all_four_objects`],
/// verified before (`false`) or after (`true`) the terminal restart, with or
/// without the MergeId 7 MCB checks.
async fn flash_da_tp_four_objects(
    verify_after_restart: bool,
    mcb_checks: bool,
) -> TestResult<(bussard_download::FlashOutcome, Shared)> {
    use bussard_download::compute::{
        GroupObjectDescriptor, compute_group_object_table, table_image_with_count,
    };
    use bussard_download::compute_tables;
    use bussard_model::schema::Link;

    // DA.tp carries a MasterReset mid-procedure, so the flash must be able to
    // reconnect — drive it over the bus actor + a leasing connector like the CLI.
    // Shorten the reboot wait so the test does not stall.
    // SAFETY: this test binds its own socket/actor; the var only shortens a sleep.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    let (handle, state, gw) = setup_bus(Fault::None).await?;
    // obj0 device, obj1 address(1), obj2 association(2), obj3 group-object(9),
    // obj4 application(3). No obj5 — the LSM5 template ops must be skipped.
    {
        let mut s = lock(&state)?;
        s.object_types = vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,       // 1
            OT_ASSOCIATION_TABLE,   // 2
            9,                      // 3 = group-object table
            OT_APPLICATION_PROGRAM, // 4 = application program (the app segment)
        ];
        s.multi_object = true;
        s.wipe_app_on_master_reset = true; // DA.tp carries a MasterReset
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    // A couple of links so the tables are non-empty.
    let links = vec![
        Link {
            object: 0,
            name: None,
            send: Some("1/1/1".parse()?),
            listen: vec![],
        },
        Link {
            object: 1,
            name: None,
            send: None,
            listen: vec!["1/1/2".parse()?],
        },
    ];
    let desired = compute_tables(&links);
    let mut table_images: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    table_images.insert(
        1,
        table_image_with_count(desired.address_count(), &desired.address_elements()),
    );
    table_images.insert(
        2,
        table_image_with_count(desired.association_count(), &desired.association_elements()),
    );
    let obj3 = compute_group_object_table(&[
        GroupObjectDescriptor {
            asap: 1,
            flags: bussard_model::Flags::COMMUNICATION | bussard_model::Flags::TRANSMIT,
            size_code: 0,
            priority: bussard_download::Priority::Low,
        },
        GroupObjectDescriptor {
            asap: 2,
            flags: bussard_model::Flags::COMMUNICATION | bussard_model::Flags::WRITE,
            size_code: 0,
            priority: bussard_download::Priority::Low,
        },
    ])
    .ok_or("the group-object table computes")?;
    table_images.insert(3, obj3.clone());

    let app = if mcb_checks {
        app_da_tp_with_mcb_checks()?
    } else {
        app_da_tp()?
    };
    let template = master_template_all_ops()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        Some(&template),
        &table_images,
    )?;

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            verify_after_restart,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    // Every programmed object reached Loaded (the verify_outcome fix): obj1..4.
    assert!(outcome.ok(), "the 4-object flash must verify: {outcome:?}");
    for obj in [1u8, 2, 3, 4] {
        assert!(
            outcome
                .object_states
                .iter()
                .any(|(o, st)| *o == obj && *st == LoadState::Loaded),
            "object {obj} must be Loaded; states {:?}",
            outcome.object_states
        );
    }

    {
        let s = lock(&state)?;
        for obj in [1u8, 2, 3, 4] {
            assert!(
                s.load_control_targets.contains(&obj),
                "load-control must target object {obj}; got {:?}",
                s.load_control_targets
            );
        }
        assert!(
            !s.load_control_targets.contains(&5),
            "LSM5 ops must be skipped (no obj5); got {:?}",
            s.load_control_targets
        );
        assert!(
            !s.load_control_targets.contains(&0),
            "no load-control write may target the device object 0"
        );
        for obj in [1u8, 2, 3, 4] {
            assert!(
                s.pid7_reads.contains(&obj),
                "the tool must read PID7 from object {obj}; got {:?}",
                s.pid7_reads
            );
        }
        // The obj3 group-object image landed at obj3's own allocated base.
        let obj3_base = *s
            .object_segment_bases
            .get(&3)
            .ok_or("no segment base for obj3")?;
        let obj3_written: Vec<u8> = (0..obj3.len() as u32)
            .map(|i| *s.memory.get(&obj3_base.wrapping_add(i)).unwrap_or(&0))
            .collect();
        assert_eq!(obj3_written, obj3, "obj3 table body landed at obj3's base");
        // The obj1 address image landed at obj1's own base.
        let obj1_base = *s
            .object_segment_bases
            .get(&1)
            .ok_or("no segment base for obj1")?;
        let obj1_img = &table_images[&1];
        let obj1_written: Vec<u8> = (0..obj1_img.len() as u32)
            .map(|i| *s.memory.get(&obj1_base.wrapping_add(i)).unwrap_or(&0))
            .collect();
        assert_eq!(
            &obj1_written, obj1_img,
            "obj1 address table landed at obj1's base"
        );
    }

    let _ = handle.close().await;
    drop(gw);
    Ok((outcome, state))
}

/// A merged flash whose master template programs obj1/obj2/obj3 but the caller
/// supplies no table images: the template `WriteRelMem` for those objects then
/// resolves against the app's (single, obj4) code segments and fails to resolve —
/// the whole procedure is refused at pre-flight rather than writing a wrong
/// image. Proves the table images are required when the template programs the
/// table objects.
#[tokio::test]
async fn flash_da_tp_without_table_images_refuses() -> TestResult {
    let app = app_da_tp()?;
    let template = master_template_all_ops()?;
    let empty: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let result = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        Some(&template),
        &empty,
    );
    assert!(
        result.is_err(),
        "a template that writes obj1/2/3 with no table images must refuse, not \
         silently write the app segment to a table object"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended-memory (System B, 24-bit address) flash: a capable 07B0 device whose
// segment lives above 0x10000 is streamed with A_MemoryExtended_Write and
// verified to Loaded. The ETS captures (scratchpad/ets-analysis/sysb-{a,c}.md)
// show ETS drives exactly these devices with the extended service in chunks
// scaled to PID_MAX_APDU (233 -> 228). A small-image (<=0xFFFF) device must keep
// using the plain A_Memory_Write path (asserted alongside), byte-identically.
// ---------------------------------------------------------------------------

/// Standard-alphabet base64 encoder (no external crate; the download crate does
/// not depend on `base64`). Enough to embed a code-segment `<Data>` payload.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// A single-object 07B0 app whose one relative code segment is `size` octets, so
/// a flash chunks it (with the extended service, into ~228-octet pieces). The
/// data is a deterministic ramp so a test can byte-compare what landed.
fn app_with_segment_of(size: usize) -> TestResult<(ApplicationProgram, Vec<u8>)> {
    let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(3)).collect();
    let b64 = base64_encode(&data);
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-1_A-EXT" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Ext" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-1_A-EXT_RS-1" Size="{size}" LoadStateMachine="4" Offset="0"><Data>{b64}</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="{size}" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="{size}" AppliesTo="full" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    Ok((
        parse_application_program("M-1_A-EXT", xml.as_bytes())?,
        data,
    ))
}

#[tokio::test]
async fn flash_extended_memory_segment_above_64k_loads_and_verifies() -> TestResult {
    // A 400-octet segment placed at base 0x016000 (top address 0x01618F, well
    // above 0xFFFF): the whole segment must stream via A_MemoryExtended_Write in
    // 228-octet chunks (PID_MAX_APDU=233), confirm to Loaded, and land verbatim.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.max_apdu = Some(233);
        s.segment_base_override = Some(0x01_6000);
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let (app, data) = app_with_segment_of(400)?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    // Negotiate PID_MAX_APDU on the connection so extended writes scale to 228,
    // exactly as `Session::open` does for the real connector-backed flow.
    let negotiated = l4.negotiate_max_apdu().await?;
    assert_eq!(
        negotiated,
        Some(233),
        "the mock advertises PID_MAX_APDU=233"
    );
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(
        outcome.ok(),
        "extended-memory flash must verify: {outcome:?}"
    );
    assert_eq!(outcome.load_state, LoadState::Loaded);
    assert!(outcome.spot_checks_match);

    let s = lock(&state)?;
    // The segment was streamed with the extended service, NOT the plain write.
    assert!(
        s.extended_writes_seen > 0,
        "a >0xFFFF segment must use A_MemoryExtended_Write"
    );
    // 400 octets at a 228-octet extended chunk = 2 frames (228 + 172).
    assert_eq!(
        s.extended_writes_seen, 2,
        "400 octets at PID_MAX_APDU=233 (228-octet chunks) is two extended writes"
    );
    // Every byte landed at its 24-bit address.
    let landed: Vec<u8> = (0..data.len() as u32)
        .map(|i| *s.memory.get(&(0x01_6000u32 + i)).unwrap_or(&0))
        .collect();
    assert_eq!(landed, data, "the image landed verbatim at 0x016000");
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn flash_small_image_stays_on_the_plain_write_path() -> TestResult {
    // The byte-identical guarantee: a device whose segment fits 0xFFFF (base
    // 0x4000, the historical placement) is flashed with the plain A_Memory_Write
    // service and NO extended write is ever emitted, even when PID_MAX_APDU is
    // advertised. This is the small-image path the KV/DA.tp oracle depends on.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.max_apdu = Some(233);
        // No base override: the mock places the segment at 0x4000 (<=0xFFFF).
    }
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "small-image flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    let s = lock(&state)?;
    assert_eq!(
        s.extended_writes_seen, 0,
        "a <=0xFFFF segment must NEVER use the extended service (byte-identical plain path)"
    );
    assert!(
        s.memory_writes_seen > 0,
        "the small image is streamed with the plain A_Memory_Write"
    );
    drop(handle);
    Ok(())
}

// --- Pre-flight factory-freshness probe (issue #79) -------------------------
//
// `flash` takes no backup, so before it writes anything the CLI reads what the
// device already carries: every interface object's load state, and the resident
// application id (`PID_PROGRAM_VERSION`, PID 13) of the application objects. The
// probe is READ-ONLY — these tests assert the device saw no load control and no
// memory write — and the verdict drives the refusal: a *different* resident
// application needs `--force`, the *same* one is the documented re-flash
// recovery path, and an unreadable state is refused as unknown (not "fresh").

/// An app whose id carries a parseable `M-XXXX` manufacturer prefix, so its
/// identity yields the 5-octet `PID_PROGRAM_VERSION` value a completed flash
/// stamps on the device: KNX Virtual DA.tp's `00 FA 25 00 10` (manufacturer
/// `0x00FA`, application number 9472, version 16).
fn identified_app() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-00FA_A-2500-10-51CB" ApplicationNumber="9472" ApplicationVersion="16"
        MaskVersion="MV-07B0" Name="DA.tp" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-00FA_A-2500-10-51CB_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program(
        "M-00FA_A-2500-10-51CB",
        xml.as_bytes(),
    )?)
}

/// Plans the identified app against a 07B0 device.
fn identified_plan(app: &ApplicationProgram) -> TestResult<bussard_download::FlashPlan> {
    Ok(plan_flash(
        app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}

/// Opens an authorized connection and runs the read-only pre-flight probe,
/// exactly as `bussard flash`'s phase A does.
async fn probe(bus: &mut Transport) -> TestResult<bussard_download::ResidentState> {
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let resident = bussard_download::probe_resident_state(&mut l4, 0x07B0, None).await;
    let _ = l4.disconnect().await;
    Ok(resident)
}

/// Asserts the probe wrote nothing: no load control, no memory, no property.
fn assert_probe_wrote_nothing(state: &Shared) -> TestResult {
    let s = lock(state)?;
    assert_eq!(s.control_writes, 0, "the probe must write no load control");
    assert_eq!(s.memory_writes_seen, 0, "the probe must write no memory");
    assert!(s.prop_writes.is_empty(), "the probe must write no property");
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_factory_fresh_device_is_fresh() -> TestResult {
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    assert!(resident.unreadable.is_none(), "{resident:?}");
    // The three loadable objects answered; the device object (type 0) carries no
    // load-state machine and is not probed.
    assert_eq!(resident.objects.len(), 3, "{resident:?}");
    assert!(
        resident
            .objects
            .iter()
            .all(|o| o.state == LoadState::Unloaded),
        "a factory-fresh device reports every object Unloaded: {resident:?}"
    );
    assert!(
        resident.app_id.is_none(),
        "nothing stamped an application id"
    );
    assert_eq!(
        bussard_download::assess_freshness(&resident, &plan.identity),
        bussard_download::Freshness::Fresh
    );
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_other_application_is_refused() -> TestResult {
    // The device runs MDT A-0007 v35 (`00 83 00 07 23`) and we are about to flash
    // DA.tp: a different application, so the verdict refuses and names what is
    // resident. Nothing is written — the CLI never gets as far as `flash`.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.app_load_state = LS_LOADED;
        s.compare_props
            .insert((3, 13), vec![0x00, 0x83, 0x00, 0x07, 0x23]);
    }
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    assert_eq!(
        resident.app_id_display().as_deref(),
        Some("M-0083 A-0007 v35")
    );
    assert!(resident.has_loaded_application());
    match bussard_download::assess_freshness(&resident, &plan.identity) {
        bussard_download::Freshness::Resident { resident, objects } => {
            assert_eq!(resident.as_deref(), Some("M-0083 A-0007 v35"));
            assert_eq!(objects, vec!["object 3 (application program)".to_string()]);
        }
        other => panic!("expected a refusal verdict, got {other:?}"),
    }
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_same_application_allows_reflash() -> TestResult {
    // The device already runs the very application being flashed (DA.tp's
    // `00 FA 25 00 10`). Re-flashing it is the documented recovery path for an
    // interrupted flash, so the verdict allows it without --force.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    {
        let mut s = lock(&state)?;
        s.app_load_state = LS_LOADED;
        s.compare_props
            .insert((3, 13), vec![0x00, 0xFA, 0x25, 0x00, 0x10]);
    }
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    let verdict = bussard_download::assess_freshness(&resident, &plan.identity);
    assert_eq!(
        verdict,
        bussard_download::Freshness::SameApplication {
            resident: "M-00FA A-2500 v16".to_string()
        }
    );
    assert!(verdict.allows_flash());
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_loaded_without_app_id_is_refused() -> TestResult {
    // Loaded, but nothing answers PID 13 (the mock reports no such property):
    // the resident application cannot be identified, which must NOT be read as
    // "fresh" — it is refused, and the message says it could not be identified.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?.app_load_state = LS_LOADED;
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    assert!(resident.app_id.is_none());
    match bussard_download::assess_freshness(&resident, &plan.identity) {
        bussard_download::Freshness::Resident { resident, objects } => {
            assert!(resident.is_none(), "unidentifiable resident application");
            assert_eq!(objects, vec!["object 3 (application program)".to_string()]);
        }
        other => panic!("expected a refusal verdict, got {other:?}"),
    }
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_unreadable_device_is_unknown() -> TestResult {
    // A device that answers no interface object at all: the load state is
    // unreadable, which is reported as unknown (not fresh) and refused without
    // --force. The message says it was unreadable, not Loaded.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?.object_types = Vec::new();
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    assert!(resident.objects.is_empty());
    match bussard_download::assess_freshness(&resident, &plan.identity) {
        bussard_download::Freshness::Unknown { reason } => {
            assert!(
                reason.contains("interface object"),
                "the reason names the unreadable read: {reason}"
            );
        }
        other => panic!("expected an unknown verdict, got {other:?}"),
    }
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_probe_resident_state_interrupted_flash_still_flashes() -> TestResult {
    // An object left mid-`Loading` by an interrupted flash is not a programmed
    // device: re-running `flash` is the documented recovery, so the verdict is
    // Fresh and no --force is needed.
    let (mut bus, state, handle) = setup(Fault::None).await?;
    lock(&state)?.app_load_state = LS_LOADING;
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;

    assert_eq!(
        bussard_download::assess_freshness(&resident, &plan.identity),
        bussard_download::Freshness::Fresh
    );
    assert_probe_wrote_nothing(&state)?;
    drop(handle);
    Ok(())
}

#[tokio::test]
async fn test_flash_after_a_fresh_probe_is_unchanged() -> TestResult {
    // The probe is a separate read-only pass: a flash that follows it writes
    // exactly what it always did (the byte-path is untouched — this is the
    // end-to-end proof next to the byte-for-byte corpus tests).
    let (mut bus, state, handle) = setup(Fault::None).await?;
    let app = identified_app()?;
    let plan = identified_plan(&app)?;

    let resident = probe(&mut bus).await?;
    assert_eq!(
        bussard_download::assess_freshness(&resident, &plan.identity),
        bussard_download::Freshness::Fresh
    );

    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "flash must verify after a probe: {outcome:?}");
    let s = lock(&state)?;
    let code: Vec<u8> = (0x4000u16..0x4006)
        .map(|a| *s.memory.get(&u32::from(a)).unwrap_or(&0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    drop(handle);
    Ok(())
}

// ===========================================================================
// KNX Data Secure (issue #71, spec §5/§6): flashing a security-ACTIVATED device
// through A_SecureData tool-access.
//
// The mock device holds a synthetic tool key, unwraps every management APDU and
// wraps every response; it refuses (drops) a plain APDU and one whose MAC does
// not verify, exactly as the knx-sim's activated device and a real device do.
// The cross-implementation half of this lives in `knx-sim/examples/secure/run.sh`
// (bussard against the independent simulator); these tests keep the seam guarded
// in `cargo nextest` without the external simulator.
// ===========================================================================

/// The acceptance case: a security-activated device is flashed to a verified
/// `Loaded` with every management APDU wrapped in A_SecureData, and the device
/// never sees a plain management APDU.
#[tokio::test]
async fn flash_secure_reaches_loaded_with_every_apdu_wrapped() -> TestResult {
    let (handle, state, gw) = setup_bus_with(secure_device(Fault::None)?).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let connector = LeaseConnector::secure(
        handle.clone(),
        target,
        source,
        Some(fast_timeouts()),
        MOCK_TOOL_KEY,
    );
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF))
        .await
        .map_err(|e| format!("{}: {e:?}", "the secure authorize is granted"))?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .map_err(|e| format!("{}: {e:?}", "the secure flash completes"))?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "secure flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    {
        let s = lock(&state)?;
        assert!(
            s.secure_frames_accepted > 10,
            "every management APDU must have been wrapped (accepted = {})",
            s.secure_frames_accepted
        );
        assert_eq!(s.plain_refusals, 0, "no plain APDU may reach the device");
        assert_eq!(s.secure_refusals, 0, "no secured APDU may be refused");
        // The image really landed: the code segment is at the allocated base.
        let code: Vec<u8> = (0x4000u32..0x4006)
            .map(|a| *s.memory.get(&a).unwrap_or(&0))
            .collect();
        assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    }
    drop(gw);
    Ok(())
}

/// REGRESSION (spec §5.9): a flash that reconnects mid-procedure must CONTINUE
/// its Data Secure send sequence, not reseed it from the clock. The send counter
/// runs far ahead of the millisecond clock, so a clock-reseeded session replays
/// sequences the device has already accepted and the device refuses every one of
/// them — the divergence the knx-sim conformance loop caught.
#[tokio::test]
async fn flash_secure_master_reset_reconnect_keeps_the_sequence_monotonic() -> TestResult {
    // Shorten the reboot wait so the test does not stall.
    // SAFETY of env: this test binds its own socket/actor; the var only shortens
    // a sleep and is read once per master-reset step.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    let (handle, state, gw) = setup_bus_with(secure_device(Fault::None)?).await?;
    lock(&state)?.wipe_app_on_master_reset = true;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = app_with_master_reset()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    // A short-but-not-tiny L4 budget: the happy path never waits on it, and a
    // regression (a reconnect that replays sequences, which the device refuses by
    // going silent) fails in seconds instead of minutes.
    let budget = bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(300),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(300),
        absent_on_negative_confirmation: false,
    };
    let connector =
        LeaseConnector::secure(handle.clone(), target, source, Some(budget), MOCK_TOOL_KEY);
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF))
        .await
        .map_err(|e| format!("{}: {e:?}", "the secure authorize is granted"))?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .map_err(|e| format!("{}: {e:?}", "the secure flash survives the reconnect"))?;
    let _ = session.into_disconnect().await;

    assert!(outcome.ok(), "secure flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    {
        let s = lock(&state)?;
        assert!(
            s.connects >= 2,
            "the master reset must have forced a reconnect (connects = {})",
            s.connects
        );
        assert_eq!(
            s.secure_refusals, 0,
            "a reconnected session must not replay a stale sequence"
        );
    }
    drop(gw);
    Ok(())
}

/// NEGATIVE (spec §6.4): plain management against an activated device is refused
/// outright — the device drops every frame, the flash fails, and nothing is
/// written.
#[tokio::test]
async fn flash_plain_against_an_activated_device_is_refused() -> TestResult {
    let (handle, state, gw) = setup_bus_with(secure_device(Fault::None)?).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    // A PLAIN connector against the activated device. The authorize itself is
    // tolerated as "device does not implement authorize" (a silent device is
    // indistinguishable from one without the service), so the refusal surfaces on
    // the first real management step of the flash.
    let connector = LeaseConnector::plain(handle.clone(), target, source, Some(fast_timeouts()));
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF))
        .await
        .map_err(|e| {
            format!(
                "{}: {e:?}",
                "the session opens; the device simply never answers"
            )
        })?;
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a plain flash of an activated device must fail");
    let _ = session.into_disconnect().await;
    {
        let s = lock(&state)?;
        assert!(
            s.plain_refusals > 0,
            "the device must have refused the plain access"
        );
        assert!(s.memory.is_empty(), "nothing may be written: {err:?}");
    }
    drop(gw);
    Ok(())
}

/// NEGATIVE (spec §5.6): a WRONG tool key fails the MAC on the device, which
/// drops the frame. The flash fails cleanly and nothing is written.
#[tokio::test]
async fn flash_with_a_wrong_tool_key_is_refused() -> TestResult {
    let (handle, state, gw) = setup_bus_with(secure_device(Fault::None)?).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let app = fabricated_app()?;
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let connector = LeaseConnector::secure(
        handle.clone(),
        target,
        source,
        Some(fast_timeouts()),
        [0xAA; 16], // NOT the device's tool key
    );
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF))
        .await
        .map_err(|e| {
            format!(
                "{}: {e:?}",
                "the session opens; the device simply never answers"
            )
        })?;
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .expect_err("a wrong tool key must fail the flash");
    let _ = session.into_disconnect().await;
    {
        let s = lock(&state)?;
        assert!(
            s.secure_refusals > 0,
            "the device must have refused the MAC"
        );
        assert_eq!(s.secure_frames_accepted, 0, "nothing may authenticate");
        assert!(s.memory.is_empty(), "nothing may be written: {err:?}");
    }
    drop(gw);
    Ok(())
}

// --- Parameter-level plan (issue #109) ---------------------------------------

/// Flashes the vendor defaults onto the mock, then plans a flash that changes the
/// one parameter: the read-back must decode the device's current value and the
/// parameter plan must show exactly one line, old value to new.
#[tokio::test]
async fn test_param_plan_one_changed_parameter_on_mock_device() -> TestResult {
    let (mut bus, _state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = fabricated_app()?;

    // 1. The device carries the vendor-default application (parameter = 7).
    let default_plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let outcome = flash(
        &mut session,
        &default_plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    assert!(outcome.ok(), "the default flash must verify: {outcome:?}");

    // 2. The device file now changes the one parameter to 42.
    let overrides = BTreeMap::from([("P-0_R-1".to_string(), "42".to_string())]);
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    // 3. Read the current parameter memory back (read-only) and diff.
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let current = bussard_download::read_current_parameter_memory(&mut l4, &plan).await;
    let _ = l4.disconnect().await;
    assert_eq!(
        current.get("M-1_A-1_RS-2").map(Vec::as_slice),
        Some(&[7u8][..]),
        "the read-back must return the parameter segment the device holds"
    );

    let params = bussard_download::param_plan(&app, &overrides, &BTreeMap::new(), &current);
    assert_eq!(params.changes.len(), 1, "changes: {:?}", params.changes);
    assert_eq!(params.changes[0].line(), "thr: 7 to 42");
    assert_eq!(params.unknown, 0);
    drop(handle);
    Ok(())
}

/// On a factory-fresh mock nothing is loaded, so nothing is read back and the
/// one changed parameter is listed with an unknown current value.
#[tokio::test]
async fn test_param_plan_fresh_mock_device_reports_unknown() -> TestResult {
    let (mut bus, _state, handle) = setup(Fault::None).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = fabricated_app()?;
    let overrides = BTreeMap::from([("P-0_R-1".to_string(), "42".to_string())]);
    let plan = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    l4.authorize_or_fail(0xFFFF_FFFF).await?;
    let current = bussard_download::read_current_parameter_memory(&mut l4, &plan).await;
    let _ = l4.disconnect().await;
    assert!(
        current.is_empty(),
        "a fresh device has no segment to read: {current:?}"
    );

    let params = bussard_download::param_plan(&app, &overrides, &BTreeMap::new(), &current);
    assert_eq!(params.changes.len(), 1);
    assert_eq!(params.changes[0].old, bussard_download::ParamValue::Unknown);
    assert_eq!(params.unknown, 1);
    drop(handle);
    Ok(())
}

/// A sparse System B app: one filled (`Mode=1 Fill=0`) segment whose image is
/// half zeros, so the engine writes only octets 1, 3 and 5. Its plan therefore
/// opens with a factory reset and ends with a confirmed restart.
fn app_with_sparse_segment() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-2_A-8" ApplicationNumber="8" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Sparse" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-2_A-8_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAEAAwAF</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="1">
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
         <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program("M-2_A-8", xml.as_bytes())?)
}

/// Re-flashes [`app_with_sparse_segment`] onto a device whose segment at
/// `0x4000` still holds a previous image of `0xAA` octets, over a reconnecting
/// session, and returns the six octets the device holds afterwards plus the
/// final device state and the flash outcome. `factory_reset` false runs the
/// `--no-factory-reset` plan.
async fn reflash_over_stale_image(
    factory_reset: bool,
) -> TestResult<(Vec<u8>, Shared, bussard_download::FlashOutcome)> {
    // Shorten the post-reboot poll so the test does not stall; the var only
    // bounds a sleep.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    let stale = [0xAAu8; 6];
    let (handle, state, gw) = setup_bus_with(preloaded_device(&stale)?).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);

    let mut plan = plan_flash(
        &app_with_sparse_segment()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    if !factory_reset {
        plan.skip_factory_reset();
    }

    let connector = LeaseConnector::plain(handle.clone(), target, source, None);
    let mut session = Session::open_with_key(connector, None).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    drop(gw);

    let image: Vec<u8> = {
        let s = state.lock().map_err(|_| "poisoned")?;
        (0x4000u32..0x4006)
            .map(|a| *s.memory.get(&a).unwrap_or(&0))
            .collect()
    };
    Ok((image, state, outcome))
}

#[tokio::test]
async fn test_flash_factory_reset_clears_stale_octets_before_sparse_reflash() -> TestResult {
    // Issue #117 (#89 campaign): a filled segment is written sparsely, and the
    // device's fill is bookkeeping, not an erase. A re-flash therefore inherits
    // the previous image's octets wherever the new image writes nothing. The
    // factory reset (erase code 7) that opens the plan, like ETS's initial
    // download, is what makes the result equal the ETS image.
    let plan = plan_flash(
        &app_with_sparse_segment()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert_eq!(
        plan.steps.first(),
        Some(&FlashStep::FactoryReset { erase_code: 7 }),
        "a sparse plan opens with the factory reset, before the first Unload"
    );
    assert!(matches!(plan.steps.get(1), Some(FlashStep::Unload { .. })));
    assert!(plan.uses_confirmed_restart());

    let (image, state, outcome) = reflash_over_stale_image(true).await?;
    assert!(outcome.ok(), "the re-flash must verify: {outcome:?}");
    assert_eq!(
        image,
        vec![0x00, 0x01, 0x00, 0x03, 0x00, 0x05],
        "after the factory reset the device holds exactly the ETS image"
    );
    let s = state.lock().map_err(|_| "poisoned")?;
    assert_eq!(s.factory_resets_seen, 1);
    assert_eq!(s.last_master_reset_payload, vec![0x07, 0x00]);
    assert_eq!(
        s.control_writes_at_factory_reset,
        Some(0),
        "the factory reset precedes every load-control write"
    );
    // The terminal restart went out as the confirmed form (erase code 1).
    assert_eq!(s.confirmed_restarts_seen, 1);
    assert!(!s.saw_basic_restart);
    assert!(s.connects >= 3, "reset and restart each force a reconnect");
    Ok(())
}

#[tokio::test]
async fn test_flash_without_factory_reset_inherits_stale_octets() -> TestResult {
    // The control for the test above: the same re-flash with the reset skipped
    // (`--no-factory-reset`) leaves the stale 0xAA octets wherever the sparse
    // image writes nothing, so the device does NOT hold the ETS image.
    let (image, state, outcome) = reflash_over_stale_image(false).await?;
    // Octet 0 is a fill octet the sparse write skips, so it keeps the stale
    // 0xAA (how the engine groups the short zero gaps between 1, 3 and 5 is its
    // own business; the leading gap is never written).
    assert_eq!(image[0], 0xAA);
    assert_ne!(image, vec![0x00, 0x01, 0x00, 0x03, 0x00, 0x05]);
    // The object still reports Loaded (the device cannot tell), but the
    // end-of-segment read-back no longer matches what bussard meant to write.
    assert_eq!(outcome.load_state, LoadState::Loaded);
    assert!(!outcome.spot_checks_match);
    let s = state.lock().map_err(|_| "poisoned")?;
    assert_eq!(s.factory_resets_seen, 0);
    Ok(())
}

#[tokio::test]
async fn test_require_factory_reset_adds_one_step_and_skip_removes_it() -> TestResult {
    // A plan without filled segments (the DA.tp / thelsing shape) has no reset
    // of its own; the CLI adds one for a device that is not factory-fresh, and
    // `--no-factory-reset` takes it out again.
    let mut plan = plan_flash(
        &fabricated_app()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert!(!plan.has_factory_reset());
    assert!(!plan.uses_confirmed_restart());
    plan.require_factory_reset();
    plan.require_factory_reset();
    let resets = plan
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::FactoryReset { .. }))
        .count();
    assert_eq!(resets, 1, "require_factory_reset is idempotent");
    let reset_at = plan
        .steps
        .iter()
        .position(|s| matches!(s, FlashStep::FactoryReset { .. }))
        .ok_or("reset step")?;
    let first_unload = plan
        .steps
        .iter()
        .position(|s| matches!(s, FlashStep::Unload { .. }))
        .ok_or("unload step")?;
    assert!(reset_at < first_unload);
    plan.skip_factory_reset();
    assert!(!plan.has_factory_reset());
    Ok(())
}

/// Issue #160, Jung 2-fold switch actuator 1.1.47 and 6-fold heating actuator
/// 1.1.2: the 07B0 template writes PID 13 to objects 5 and 4, but an app with
/// nothing to load into object 5 leaves that object unloaded, and ETS then
/// writes the program version only to object 4. The plan keeps object 5's
/// Unload and drops its StartLoading, LoadCompleted and PID 13 write.
#[test]
fn test_plan_flash_skips_program_version_of_an_unloaded_object() -> TestResult {
    let app = app_da_tp()?;
    let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
    let template = master_template_all_ops()?;
    let plan = plan_flash(
        &app,
        "1.1.47",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?;
    let pid13_objects: Vec<u32> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::WriteProp {
                obj_idx,
                prop_id: 13,
                ..
            } => Some(*obj_idx),
            _ => None,
        })
        .collect();
    assert_eq!(pid13_objects, vec![4], "PID 13 only on the loaded object 4");
    assert!(
        plan.steps
            .iter()
            .any(|s| matches!(s, FlashStep::Unload { target: Some(5) })),
        "object 5 is still unloaded, as ETS does"
    );
    assert!(!plan.steps.iter().any(|s| matches!(
        s,
        FlashStep::StartLoading { target: Some(5) } | FlashStep::LoadCompleted { target: Some(5) }
    )));
    Ok(())
}

/// Issue #126, ABB BE/S16.230.3.2: the application's `Hardware2Program` also
/// lists a `PeiProgram` (object 5). Its merged blocks fill MergeId 3 and 5 of
/// the 07B0 template, so the plan opens, fill-allocates and streams object 5
/// before object 4, writes the PEI program's own id to object 5's PID 13, and
/// checks object 5's image, as ETS does.
#[test]
fn test_plan_flash_streams_a_companion_pei_program() -> TestResult {
    let mut app = app_da_tp()?;
    let pei = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-00FA_A-DB" ApplicationNumber="9472" ApplicationVersion="32"
        ProgramType="PeiProgram" MaskVersion="MV-07B0" Name="Pei" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-00FA_A-DB_RS-05" Size="4" LoadStateMachine="5" Offset="0"><Data>AQIDBA==</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="3">
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="5" Size="4" Mode="1" Fill="0" />
         <LdCtrlRelSegment AppliesTo="par" LsmIdx="5" Size="4" Mode="0" Fill="0" />
        </LoadProcedure>
        <LoadProcedure MergeId="5">
         <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="5" Offset="0" Size="4" Verify="true" />
        </LoadProcedure>
        <LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="5" PropId="27" /></LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    let pei = parse_application_program("M-00FA_A-DB", pei.as_bytes())?;
    assert!(pei.is_pei_program());
    app.companion_programs.push(pei);

    let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
    let template = master_template_all_ops()?;
    let plan = plan_flash(
        &app,
        "1.1.39",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?;
    let pos = |pred: &dyn Fn(&FlashStep) -> bool| plan.steps.iter().position(pred);
    let open5 = pos(&|s| matches!(s, FlashStep::StartLoading { target: Some(5) }));
    let open4 = pos(&|s| matches!(s, FlashStep::StartLoading { target: Some(4) }));
    assert!(
        open5.is_some() && open5 < open4,
        "object 5 opens before object 4"
    );
    assert_eq!(
        plan.steps
            .iter()
            .filter(|s| matches!(
                s,
                FlashStep::AllocateSegment {
                    target: Some(5),
                    ..
                }
            ))
            .count(),
        1,
        "the restated full/par allocation of object 5 is one step"
    );
    assert!(plan.steps.iter().any(|s| matches!(
        s,
        FlashStep::AllocateSegment {
            size: 4,
            target: Some(5),
            fill: Some(0)
        }
    )));
    let write5 = plan
        .steps
        .iter()
        .find_map(|s| match s {
            FlashStep::WriteRelMem {
                target: Some(5),
                image,
                ..
            } => Some(image.segment_id.clone()),
            _ => None,
        })
        .ok_or("no write to object 5")?;
    assert_eq!(write5, "M-00FA_A-DB_RS-05");
    assert_eq!(plan.image_bytes(&write5), Some(&[1u8, 2, 3, 4][..]));
    let pid13 = |obj: u32| {
        plan.steps.iter().find_map(|s| match s {
            FlashStep::WriteProp {
                obj_idx,
                prop_id: 13,
                value,
                ..
            } if *obj_idx == obj => Some(value.clone()),
            _ => None,
        })
    };
    assert_eq!(pid13(5), Some(vec![0x00, 0xFA, 0x25, 0x00, 0x20]));
    assert_eq!(pid13(4), Some(vec![0x00, 0xFA, 0x25, 0x00, 0x10]));
    // Only the companion program declares object 5's check, so a mismatch
    // there warns rather than aborts (issue #145: ETS reads that MCB on the
    // BE/S16 and the Busch-Wächter PRO 280 and carries on).
    assert!(plan.steps.iter().any(|s| matches!(
        s,
        FlashStep::LoadImageProp {
            obj_idx: 5,
            advisory: true,
            ..
        }
    )));
    Ok(())
}

/// The 07B0 template with an extra `LdCtrlLoadImageProp` for object 4 after
/// the MergeId 7 marker, to tell template checks apart from the app's own.
fn master_template_with_image_check() -> TestResult<Vec<bussard_prod::LoadOp>> {
    let mut ops = master_template_all_ops()?;
    let at = ops
        .iter()
        .position(|op| matches!(op, bussard_prod::LoadOp::Restart))
        .ok_or("template has no restart")?;
    ops.insert(
        at,
        bussard_prod::LoadOp::LoadImageProp {
            obj_idx: Some(4),
            obj_type: None,
            occurrence: None,
            prop_id: Some(27),
            count: None,
        },
    );
    Ok(ops)
}

/// The image checks a plan lowers, as `(object, advisory)`.
fn image_checks(plan: &bussard_download::FlashPlan) -> Vec<(u32, bool)> {
    plan.steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::LoadImageProp {
                obj_idx, advisory, ..
            } => Some((*obj_idx, *advisory)),
            _ => None,
        })
        .collect()
}

/// Issue #145: when the application declares its own `LdCtrlLoadImageProp`
/// checks, a template check for an object it does not name is dropped; the
/// app's checks stay authoritative.
#[test]
fn test_plan_flash_image_checks_follow_the_app_procedure() -> TestResult {
    let mut app = app_da_tp()?;
    app.load_procedures.push(bussard_prod::LoadProcedure {
        merge_id: Some("7".to_string()),
        ops: (1..=3)
            .map(|obj| bussard_prod::LoadOp::LoadImageProp {
                obj_idx: Some(obj),
                obj_type: None,
                occurrence: None,
                prop_id: Some(27),
                count: None,
            })
            .collect(),
    });
    let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
    let template = master_template_with_image_check()?;
    let plan = plan_flash(
        &app,
        "1.1.30",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?;
    assert_eq!(
        image_checks(&plan),
        vec![(1, false), (2, false), (3, false)]
    );
    Ok(())
}

/// Issue #145: an application that declares no check of its own (the pure
/// template-driven KNX Virtual DA.tp shape) keeps the template's checks, and
/// they stay authoritative.
#[test]
fn test_plan_flash_template_image_checks_kept_without_app_checks() -> TestResult {
    let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
    let template = master_template_with_image_check()?;
    let plan = plan_flash(
        &app_da_tp()?,
        "1.1.4",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?;
    assert_eq!(image_checks(&plan), vec![(4, false)]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Issue #119: parameter-only download and parameter read-back.
// ---------------------------------------------------------------------------

/// A device that already runs [`fabricated_app`]: the code image at `0x4000`,
/// the one-octet parameter segment (value `param`) at `0x4006`, which is the
/// application object's last allocation and so the base `PID_TABLE_REFERENCE`
/// reports. The application object is `Loaded`.
fn device_running_fabricated_app(param: u8) -> Shared {
    let state = fresh_device(Fault::None);
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.app_load_state = LS_LOADED;
        s.last_segment_base = 0x4006;
        s.last_segment_size = 1;
        for (i, b) in [0u8, 1, 2, 3, 4, 5].iter().enumerate() {
            s.memory.insert(0x4000 + i as u32, *b);
        }
        s.memory.insert(0x4006, param);
    }
    state
}

#[tokio::test]
async fn test_parameters_only_download_writes_only_the_changed_parameter() -> TestResult {
    let (mut bus, state, handle) = setup_device(device_running_fabricated_app(7)).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;

    // The model changes the one parameter from its default 7 to 9.
    let app = fabricated_app()?;
    let overrides = BTreeMap::from([("P-0_R-0".to_string(), "9".to_string())]);
    let full = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;

    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let regions = bussard_download::read_parameter_regions(session.l4(), &full).await;
    let region = regions
        .get("M-1_A-1_RS-2")
        .ok_or("the parameter segment must be read back")?;
    assert_eq!(
        (region.address, region.bytes.as_slice()),
        (0x4006, &[7u8][..])
    );

    // The read-back decodes to the vendor default, so nothing is non-default.
    let current = bussard_download::regions_memory(&regions);
    assert!(
        bussard_download::non_default_parameters(
            &app,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &current
        )
        .is_empty()
    );

    let partial = full.parameters_only(&regions)?;
    assert_eq!(partial.changed_octets(), 1);
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.load_events.clear();
        s.memory_writes_seen = 0;
    }
    let outcome = flash(
        &mut session,
        &partial,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;

    // Read back after the load: the new value decodes.
    let after = bussard_download::read_parameter_regions(session.l4(), &full).await;
    let _ = session.into_disconnect().await;
    drop(handle);
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
    assert_eq!(readings[0].value, "9");
    assert_eq!(readings[0].default, "7");

    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    // Only the parameter octet was written: one memory write, the code intact.
    assert_eq!(s.memory_writes_seen, 1);
    assert_eq!(s.memory.get(&0x4006).copied(), Some(9));
    let code: Vec<u8> = (0x4000u32..0x4006)
        .map(|a| s.memory.get(&a).copied().unwrap_or(0))
        .collect();
    assert_eq!(code, vec![0, 1, 2, 3, 4, 5]);
    // StartLoading then LoadCompleted on the app object: no Unload, no
    // allocation, no table object touched.
    let events: Vec<u8> = s.load_events.iter().map(|(_, e)| *e).collect();
    assert_eq!(events, vec![LE_START_LOADING, LE_LOAD_COMPLETED]);
    assert!(s.load_events.iter().all(|(oi, _)| *oi == 3));
    assert!(s.saw_basic_restart, "the device is restarted");
    Ok(())
}

#[tokio::test]
async fn test_parameters_only_download_with_nothing_changed_writes_nothing() -> TestResult {
    let (mut bus, state, handle) = setup_device(device_running_fabricated_app(9)).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source: bussard_model::IndividualAddress = "0.0.255".parse()?;
    let app = fabricated_app()?;
    let overrides = BTreeMap::from([("P-0_R-0".to_string(), "9".to_string())]);
    let full = plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    let mut session = authed_session(l4).await?;
    let regions = bussard_download::read_parameter_regions(session.l4(), &full).await;
    let _ = session.into_disconnect().await;
    drop(handle);
    let partial = full.parameters_only(&regions)?;
    assert_eq!(partial.changed_octets(), 0);
    let readings = bussard_download::non_default_parameters(
        &app,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &bussard_download::regions_memory(&regions),
    );
    assert_eq!(
        readings.len(),
        1,
        "the read-back names the non-default value"
    );
    assert_eq!(readings[0].line(), "thr: 9 (default 7)");
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(s.control_writes, 0, "planning writes nothing");
    Ok(())
}

/// Flashes [`app_with_sparse_segment`] (factory reset first, confirmed restart
/// last) onto a Data Secure mock whose security layer drops the first
/// `sync_drops` S-A_Sync_Reqs after every restart, and returns the flash result
/// and the device state (issue #166).
async fn secure_flash_across_slow_security_layer(
    sync_drops: u32,
) -> TestResult<(Result<bussard_download::FlashOutcome, WriteError>, Shared)> {
    // Shorten the post-reboot poll and the Sync backoff; the var only bounds
    // sleeps.
    // SAFETY of env: nextest runs this test in its own process.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
    }
    let (handle, state, gw) = setup_bus_with(secure_device(Fault::None)?).await?;
    state
        .lock()
        .map_err(|_| "poisoned")?
        .sync_drops_after_restart = sync_drops;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        &app_with_sparse_segment()?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert_eq!(
        plan.steps.first(),
        Some(&FlashStep::FactoryReset { erase_code: 7 }),
        "the plan opens with the erase-7 factory reset"
    );
    // A short L4 budget: each unanswered Sync_Req costs one response timeout.
    let budget = bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(300),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(300),
        absent_on_negative_confirmation: false,
    };
    let connector =
        LeaseConnector::secure(handle.clone(), target, source, Some(budget), MOCK_TOOL_KEY);
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF)).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await;
    let _ = session.into_disconnect().await;
    drop(gw);
    Ok((outcome, state))
}

/// Issue #166: after the factory reset (and again after the terminal confirmed
/// restart) the Secure device T_ACKs the first two S-A_Sync_Reqs without
/// answering. bussard probes readiness with a plain `A_DeviceDescriptor_Read`
/// on the new connection, repeats the Sync_Req on that same connection, and the
/// flash completes.
#[tokio::test]
async fn test_flash_secure_factory_reset_retries_unanswered_sync_reqs() -> TestResult {
    let (outcome, state) = secure_flash_across_slow_security_layer(2).await?;
    let outcome = outcome?;
    assert!(outcome.ok(), "the secure flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    let s = state.lock().map_err(|_| "poisoned")?;
    assert_eq!(s.factory_resets_seen, 1);
    assert_eq!(s.confirmed_restarts_seen, 1);
    assert_eq!(
        s.sync_reqs_dropped, 4,
        "two dropped Sync_Reqs after each of the two restarts"
    );
    assert_eq!(s.secure_refusals, 0, "no stale or unverifiable frame");
    assert_eq!(
        s.plain_refusals, 0,
        "only the descriptor probe goes in the clear"
    );
    assert!(
        s.plain_descriptor_reads >= 2,
        "one readiness probe per restart (got {})",
        s.plain_descriptor_reads
    );
    // The wire sequence right after the factory reset, as ETS does it: one
    // connection that opens with the plain descriptor read, then the Sync_Req
    // (repeated until answered), then the secured authorize.
    let reset = s
        .secure_log
        .iter()
        .position(|e| e == "S-A_Data(0x381)")
        .ok_or("the factory reset went out secured")?;
    let after: Vec<&str> = s.secure_log[reset + 1..]
        .iter()
        .take(6)
        .map(String::as_str)
        .collect();
    assert_eq!(
        after,
        vec![
            "T_Connect",
            "A_DeviceDescriptor_Read (plain)",
            "S-A_Sync_Req (T_ACK only)",
            "S-A_Sync_Req (T_ACK only)",
            "S-A_Sync_Req -> S-A_Sync_Res",
            "S-A_Data(0x3d1)",
        ]
    );
    Ok(())
}

/// Issue #166: a Secure device that never answers the Sync_Req after the
/// factory reset fails the flash with `SyncUnanswered` once the bounded
/// retries (five attempts on the post-restart connection) are spent.
#[tokio::test]
async fn test_flash_secure_factory_reset_gives_up_on_a_sync_never_answered() -> TestResult {
    let (outcome, state) = secure_flash_across_slow_security_layer(u32::MAX).await?;
    let err = match outcome {
        Ok(outcome) => return Err(format!("the flash must fail, got {outcome:?}").into()),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            WriteError::Mgmt(bussard_mgmt::MgmtError::Secure {
                source: bussard_secure::AsduError::SyncUnanswered,
                ..
            })
        ),
        "got {err:?}"
    );
    let s = state.lock().map_err(|_| "poisoned")?;
    assert_eq!(s.factory_resets_seen, 1);
    assert_eq!(
        s.sync_reqs_dropped,
        bussard_mgmt::SyncRetry::after_restart().attempts,
        "the Sync_Req is repeated a bounded number of times"
    );
    Ok(())
}

// --- issue #192: a gateway link loss in the post-restart reconnect phase -----

/// Flashes `app` over a reconnecting session while a gateway link outage of
/// 1.5 s hits the reconnect phase after the device accepted a restart of
/// `kind` (issue #192, S2.6 of #90). The outage trips on the second numbered
/// frame after the restart: the readiness probe's `A_DeviceDescriptor_Read`
/// gets through, then the session connection's first frame (the authorize, or
/// the S-A_Sync_Req on a Data Secure device) is swallowed and the device drops
/// its L4 connection while the link is down. Returns the flash result and the
/// device state.
async fn flash_across_restart_outage(
    app: &ApplicationProgram,
    kind: RestartKind,
    secure: bool,
    prepare: impl FnOnce(&mut DeviceState),
) -> TestResult<(Result<bussard_download::FlashOutcome, WriteError>, Shared)> {
    // SAFETY of env: nextest runs this test in its own process; the vars only
    // shorten the post-reboot poll and keep proactive cycling off.
    unsafe {
        std::env::set_var("BUSSARD_FLASH_REBOOT_WAIT_MS", "50");
        std::env::set_var("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0");
    }
    let state = if secure {
        secure_device(Fault::None)?
    } else {
        fresh_device(Fault::None)
    };
    {
        let mut s = lock(&state)?;
        s.restart_outage = Some(RestartOutage {
            kind,
            after_frame: 1,
            duration: Duration::from_millis(1500),
        });
        s.outage_kills_l4 = true;
        prepare(&mut s);
    }
    let (handle, state, gw, _gateway) =
        setup_bus_reconnect(state, fast_reconnect(Duration::from_secs(20))).await?;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    // A short-but-not-tiny L4 budget: each silent exchange costs one timeout.
    let budget = bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(300),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(300),
        absent_on_negative_confirmation: false,
    };
    let (connector, key) = if secure {
        (
            LeaseConnector::secure(handle.clone(), target, source, Some(budget), MOCK_TOOL_KEY),
            Some(0xFFFF_FFFF),
        )
    } else {
        (
            LeaseConnector::plain(handle.clone(), target, source, Some(budget)),
            None,
        )
    };
    let mut session = Session::open_with_key(connector, key).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await;
    let _ = session.into_disconnect().await;
    let _ = handle.close().await;
    drop(gw);
    Ok((outcome, state))
}

/// The assertions every post-restart outage case shares: the flash verified,
/// the outage really fired and the tunnel was re-established.
fn assert_resumed_across_outage(
    outcome: Result<bussard_download::FlashOutcome, WriteError>,
    state: &Shared,
) -> TestResult {
    let outcome = outcome?;
    assert!(outcome.ok(), "the resumed flash must verify: {outcome:?}");
    assert_eq!(outcome.load_state, LoadState::Loaded);
    let s = lock(state)?;
    assert!(s.restart_outage.is_none(), "the outage fired");
    assert!(s.outage_swallowed >= 1, "the outage swallowed the frame");
    assert!(
        s.tunnel_connects >= 2,
        "the tunnel was re-established (connects = {})",
        s.tunnel_connects
    );
    assert_eq!(s.secure_refusals, 0, "no stale or unverifiable frame");
    // The authorize the outage swallowed was not cached as "device has no
    // authorize": the last connection presented the key again.
    assert!(
        s.authorized,
        "the final connection was authorized, not skipped as unsupported"
    );
    Ok(())
}

/// The sparse image [`app_with_sparse_segment`] writes, as ETS leaves it.
const SPARSE_IMAGE: [u8; 6] = [0x00, 0x01, 0x00, 0x03, 0x00, 0x05];

/// The six octets at the sparse segment's base.
fn sparse_image(state: &Shared) -> Result<Vec<u8>, String> {
    let s = lock(state)?;
    Ok((0x4000u32..0x4006)
        .map(|a| *s.memory.get(&a).unwrap_or(&0))
        .collect())
}

#[tokio::test]
async fn test_flash_resumes_tunnel_loss_during_factory_reset_reconnect() -> TestResult {
    // The live failure of #192: the link drops while bussard reconnects to the
    // device after its factory reset. The unanswered authorize must not be
    // taken for "device has no authorize"; the reconnect phase waits for the
    // tunnel, probes readiness again, reconnects and the flash continues with
    // the same step. The reset itself is not repeated.
    let (outcome, state) = flash_across_restart_outage(
        &app_with_sparse_segment()?,
        RestartKind::FactoryReset,
        false,
        |_| {},
    )
    .await?;
    assert_resumed_across_outage(outcome, &state)?;
    assert_eq!(sparse_image(&state)?, SPARSE_IMAGE.to_vec());
    let s = lock(&state)?;
    assert_eq!(s.factory_resets_seen, 1, "the reset was not sent again");
    assert_eq!(s.confirmed_restarts_seen, 1);
    Ok(())
}

#[tokio::test]
async fn test_flash_secure_resumes_tunnel_loss_during_factory_reset_reconnect() -> TestResult {
    // The same on a Data Secure device (the #90 S2.6 setup): the S-A_Sync_Req
    // of the post-reset connection is lost with the link; the Sync is redone
    // on a fresh connection once the tunnel is back.
    let (outcome, state) = flash_across_restart_outage(
        &app_with_sparse_segment()?,
        RestartKind::FactoryReset,
        true,
        |_| {},
    )
    .await?;
    assert_resumed_across_outage(outcome, &state)?;
    assert_eq!(sparse_image(&state)?, SPARSE_IMAGE.to_vec());
    let s = lock(&state)?;
    assert_eq!(s.factory_resets_seen, 1, "the reset was not sent again");
    assert!(
        s.plain_descriptor_reads >= 3,
        "the readiness probe ran again after the outage (got {})",
        s.plain_descriptor_reads
    );
    Ok(())
}

#[tokio::test]
async fn test_flash_resumes_tunnel_loss_during_terminal_restart_verify() -> TestResult {
    // The link drops while bussard reconnects after the terminal (confirmed)
    // restart to verify the load: the verify still runs on a fresh connection.
    let (outcome, state) = flash_across_restart_outage(
        &app_with_sparse_segment()?,
        RestartKind::ConfirmedRestart,
        false,
        |_| {},
    )
    .await?;
    assert_resumed_across_outage(outcome, &state)?;
    let s = lock(&state)?;
    assert_eq!(s.factory_resets_seen, 1);
    assert_eq!(s.confirmed_restarts_seen, 1, "the restart was not repeated");
    Ok(())
}

#[tokio::test]
async fn test_flash_secure_resumes_tunnel_loss_during_terminal_restart_verify() -> TestResult {
    let (outcome, state) = flash_across_restart_outage(
        &app_with_sparse_segment()?,
        RestartKind::ConfirmedRestart,
        true,
        |_| {},
    )
    .await?;
    assert_resumed_across_outage(outcome, &state)?;
    let s = lock(&state)?;
    assert_eq!(s.confirmed_restarts_seen, 1, "the restart was not repeated");
    Ok(())
}

#[tokio::test]
async fn test_flash_resumes_tunnel_loss_during_master_reset_reconnect() -> TestResult {
    // The mid-procedure `LdCtrlMasterReset` (KNX Virtual's bare A_Restart,
    // erase code 4): the link drops in its reconnect phase; the object is
    // re-opened and re-allocated on the fresh connection as usual.
    let (outcome, state) = flash_across_restart_outage(
        &app_with_master_reset()?,
        RestartKind::BasicRestart,
        false,
        |s| s.wipe_app_on_master_reset = true,
    )
    .await?;
    assert_resumed_across_outage(outcome, &state)?;
    let s = lock(&state)?;
    assert_eq!(s.master_resets_seen, 1, "the master reset was not repeated");
    Ok(())
}

// ===========================================================================
// Issue #212: reboot readiness after a confirmed restart and a factory reset
// ===========================================================================

/// A single-object 07B0 app whose parameter segment holds `image` over a zero
/// fill: the plan opens with the factory reset and ends with the confirmed
/// restart, like the 1.1.5 and 1.1.12 downloads.
fn app_with_filled_segment(image: &[u8]) -> TestResult<ApplicationProgram> {
    let size = image.len();
    let b64 = base64_encode(image);
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-2_A-9" ApplicationNumber="9" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Filled" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-2_A-9_RS-1" Size="{size}" LoadStateMachine="4" Offset="0"><Data>{b64}</Data></RelativeSegment>
       </Code>
       <LoadProcedures>
        <LoadProcedure MergeId="1">
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="{size}" Mode="1" Fill="0" />
         <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="{size}" Verify="true" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    Ok(parse_application_program("M-2_A-9", xml.as_bytes())?)
}

/// What one reboot-profile flash observed.
struct TimedFlash {
    outcome: bussard_download::FlashOutcome,
    state: Shared,
    /// From the start of the flash to its end.
    elapsed: Duration,
}

/// Flashes [`app_with_filled_segment`] onto a Data Secure mock (1.1.5 and
/// 1.1.12 are Data Secure) behind an interface that reports negative
/// `L_Data.con`s while the device is silent. `configure` sets the device's
/// reboot profiles, process time and latency.
async fn timed_secure_flash(
    image: &[u8],
    configure: impl FnOnce(&mut DeviceState),
) -> TestResult<TimedFlash> {
    let state = secure_device(Fault::None)?;
    configure(&mut *lock(&state)?);
    let gw = start_gateway_booting(&state).await?;
    let (handle, _actor) = bussard_bus::Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    handle.wait_connected(Duration::from_secs(5)).await;
    let target: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let source = bussard_bus::ops::group_source(&handle);
    let plan = plan_flash(
        &app_with_filled_segment(image)?,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let connector = LeaseConnector::secure(handle.clone(), target, source, None, MOCK_TOOL_KEY);
    let started = std::time::Instant::now();
    let mut session = Session::open_with_key(connector, Some(0xFFFF_FFFF)).await?;
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions {
            verify_after_restart: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let elapsed = started.elapsed();
    let _ = session.into_disconnect().await;
    let _ = handle.close().await;
    drop(gw);
    Ok(TimedFlash {
        outcome,
        state,
        elapsed,
    })
}

/// A small sparse image: three runs over a zero fill.
fn small_sparse_image() -> Vec<u8> {
    let mut image = vec![0u8; 64];
    image[2] = 1;
    image[30] = 2;
    image[60] = 3;
    image
}

fn readiness_of(
    outcome: &bussard_download::FlashOutcome,
    kind: bussard_download::RestartKind,
) -> TestResult<bussard_download::RebootReadiness> {
    Ok(*outcome
        .reboot_readiness
        .iter()
        .find(|r| r.kind == kind)
        .ok_or("no readiness recorded for the restart")?)
}

/// The 1.1.5 pattern (issue #212, wire log 203822): after the confirmed
/// restart the device is silent and negatively confirmed, then answers its
/// probes 1.5 s late while it sends its power-up telegrams, then promptly.
/// The 2 s answer window accepts the late answer instead of discarding it.
#[tokio::test]
async fn test_flash_reboot_probe_accepts_a_late_answer() -> TestResult {
    let run = timed_secure_flash(&small_sparse_image(), |s| {
        s.restart_profile = Some(RebootProfile {
            silent: Duration::from_millis(1500),
            slow_until: Duration::from_secs(4),
            slow_answer: Duration::from_millis(1500),
        });
    })
    .await?;
    assert!(run.outcome.ok(), "the flash must verify: {:?}", run.outcome);
    let restart = readiness_of(&run.outcome, bussard_download::RestartKind::Restart)?;
    let ready = restart.ready_after.ok_or("a probe must have answered")?;
    // The probe at +1.5 s is acknowledged and answered 1.5 s late; the next
    // probe, sent with the same sequence number, accepts that answer at
    // +3.0 s. The 1, 2, 4 s backoff with a 400 ms window discarded such
    // answers and waited for the prompt phase (+4 s here, +9.7 s on 1.1.5).
    assert!(
        ready >= Duration::from_millis(3000) && ready < Duration::from_millis(4500),
        "ready after {ready:?}"
    );
    let s = lock(&run.state)?;
    assert!(
        s.negative_cons >= 1,
        "the silent phase was negatively confirmed"
    );
    Ok(())
}

/// A device that is back 1 s after its confirmed restart: the first probe
/// goes out at +0.5 s (no fixed 1.5 s any more), is negatively confirmed and
/// unanswered, and the poll finds the device within one more interval.
#[tokio::test]
async fn test_flash_reboot_probe_polls_from_half_a_second() -> TestResult {
    let run = timed_secure_flash(&small_sparse_image(), |s| {
        s.restart_profile = Some(RebootProfile::ready_at(Duration::from_millis(1000)));
    })
    .await?;
    assert!(run.outcome.ok(), "the flash must verify: {:?}", run.outcome);
    let restart = readiness_of(&run.outcome, bussard_download::RestartKind::Restart)?;
    let ready = restart.ready_after.ok_or("a probe must have answered")?;
    assert!(
        ready >= Duration::from_millis(1000) && ready < Duration::from_millis(1700),
        "ready after {ready:?}"
    );
    assert!(lock(&run.state)?.negative_cons >= 1);
    Ok(())
}

/// A device that answers its first probe at once: ready at +0.5 s.
#[tokio::test]
async fn test_flash_reboot_probe_first_probe_at_half_a_second() -> TestResult {
    let run = timed_secure_flash(&small_sparse_image(), |_| {}).await?;
    assert!(run.outcome.ok(), "the flash must verify: {:?}", run.outcome);
    let restart = readiness_of(&run.outcome, bussard_download::RestartKind::Restart)?;
    let ready = restart.ready_after.ok_or("a probe must have answered")?;
    assert!(
        ready >= Duration::from_millis(500) && ready < Duration::from_millis(900),
        "ready after {ready:?}"
    );
    Ok(())
}

/// The factory reset's process time is never shortened: the device answers
/// the measurement probes from +3 s on, the readiness records that, and the
/// download still starts only after the reported 4 s.
#[tokio::test]
async fn test_flash_factory_reset_measures_readiness_but_waits_the_process_time() -> TestResult {
    let run = timed_secure_flash(&small_sparse_image(), |s| {
        s.factory_process_time = 4;
        s.factory_profile = Some(RebootProfile::ready_at(Duration::from_millis(3200)));
    })
    .await?;
    assert!(run.outcome.ok(), "the flash must verify: {:?}", run.outcome);
    let reset = readiness_of(&run.outcome, bussard_download::RestartKind::FactoryReset)?;
    assert_eq!(reset.process_time, Duration::from_secs(4));
    let ready = reset
        .ready_after
        .ok_or("a measurement probe must have answered")?;
    assert!(
        ready >= Duration::from_millis(3200) && ready < Duration::from_millis(3900),
        "ready after {ready:?}"
    );
    // 4 s process time + 0.5 s quiet + the confirmed restart's 0.5 s.
    assert!(
        run.elapsed >= Duration::from_millis(5000),
        "the flash waited out the process time ({:?})",
        run.elapsed
    );
    Ok(())
}

/// Measurement harness for the PR (issue #210/#211/#212), not a regression
/// test: flashes a 1.1.5-like or 1.1.12-like Data Secure device with the
/// 200 ms + 1.7 ms/octet request latency and the reboot pattern of the
/// 2026-09-24 wire logs, and prints requests and wall clock.
///
/// `BUSSARD_SPEED_IMAGE` names the parameter image (`.bin`, over a zero fill),
/// `BUSSARD_SPEED_PROFILE` is `1.1.5` or `1.1.12`.
#[tokio::test]
#[ignore = "measurement harness; run by hand"]
async fn measure_flash_speed_profile() -> TestResult {
    let image = std::fs::read(std::env::var("BUSSARD_SPEED_IMAGE")?)?;
    let profile = std::env::var("BUSSARD_SPEED_PROFILE")?;
    let restart = match profile.as_str() {
        // 203822: silent until ~+2.9 s, answers 1.3-1.9 s late until ~+8 s.
        "1.1.5" => RebootProfile {
            silent: Duration::from_millis(2900),
            slow_until: Duration::from_secs(8),
            slow_answer: Duration::from_millis(1500),
        },
        // 202407 / ETS: answered at +1.4 s; assume ready at +1.2 s.
        _ => RebootProfile::ready_at(Duration::from_millis(1200)),
    };
    let run = timed_secure_flash(&image, |s| {
        s.latency = Some((Duration::from_millis(200), Duration::from_micros(1700)));
        // PID 56 of the 07B0 actuators: 233, a 215-octet Data Secure chunk
        // of the extended service, which a segment above 0xFFFF uses (1.1.5's
        // parameters sit at 0x17C56).
        s.max_apdu = Some(233);
        s.segment_base_override = Some(0x1_7C56);
        s.factory_process_time = 8;
        // No capture shows the factory reset readiness; ETS answered at 8.9 s.
        s.factory_profile = Some(RebootProfile::ready_at(Duration::from_millis(8000)));
        s.restart_profile = Some(restart);
    })
    .await?;
    let s = lock(&run.state)?;
    println!(
        "profile {profile}: ok={} requests={} memory_writes={} elapsed={:.1} s \
         first answers after the reset / restart={:?} tool moved on at={:?} readiness={:?}",
        run.outcome.ok(),
        s.answered_requests,
        s.memory_writes_seen,
        run.elapsed.as_secs_f64(),
        s.reboot_answers,
        s.reboot_proceeded,
        run.outcome.reboot_readiness
    );
    Ok(())
}
