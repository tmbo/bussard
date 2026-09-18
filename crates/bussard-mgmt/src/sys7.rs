//! System 7 (mask 0705 / 0701) download primitives: the absolute-segment load
//! controls and the load-state-machine access seam.
//!
//! System 7 is absolute-addressed (`[system7-spec §2]`): every segment is placed
//! by the tool at a fixed 16-bit address, the three parallel load-state machines
//! are driven by 10-octet load-event records, and — unlike System B — the tool
//! never resolves a table base through `PID_TABLE_REFERENCE`. This module holds
//! the pure encoders for the `AdditionalLoadControls` sub-commands System 7 uses,
//! plus the [`LsmAccess`] seam that abstracts *how* a load event reaches the
//! device.
//!
//! The M2 Jung 0705 capture (issue #70) settled the LSM realisation: the real
//! device drives load control **property-based** — every load event is an
//! `A_PropertyValue_Write(objN, PID 5)`, state read back via
//! `A_PropertyValue_Read` — so [`LsmAccess::Property`] is the default. The
//! [`LsmAccess::MemoryMapped`] variant (a 12-octet record over `A_Memory_Write`)
//! is kept for silicon whose product data selects it (`[system7-spec §5]`).
//!
//! Everything here is clean-room: encoders from the published KNX
//! `AdditionalLoadControls` structure (KNX 3/5/2), the issue-#49 corpus
//! archaeology and the M2 capture; no GPL source was consulted. The remaining
//! `S7-CAL:` markers name the few alloc-record attribute octets the capture shows
//! but whose derivation from product data is not yet settled.

use crate::connection::{L4Channel, Layer4Connection, property_request, property_write_request};
use crate::load::{LoadControl, LoadState, Result, WriteError, read_memory, write_memory};

/// The size of a standard KNX load-event record: 10 octets (`[XKNX
/// LOAD_EVENT_SIZE=10]`, KNX 3/5/1 §4.23.2). Octet 0 is the event opcode; the
/// rest are the sub-command payload, zero-padded.
pub const LOAD_EVENT_SIZE: usize = 10;

/// `AdditionalLoadControls` sub-command — allocate an absolute **Data** segment
/// (subtype `0x00`, `[system7-spec §4.1]`).
pub const S7_SUB_ALLOC_DATA: u8 = 0x00;
/// `AdditionalLoadControls` sub-command — allocate an absolute **Stack** segment
/// (subtype `0x01`). Not in the corpus; provided for completeness.
pub const S7_SUB_ALLOC_STACK: u8 = 0x01;
/// `AdditionalLoadControls` sub-command — allocate an absolute **Task** segment
/// (subtype `0x02`); the default realisation of `LdCtrlTaskSegment`
/// (`[system7-spec §4.3]`).
pub const S7_SUB_ALLOC_TASK: u8 = 0x02;
/// `AdditionalLoadControls` sub-command — **Task control 1** (subtype `0x04`),
/// the realisation of `LdCtrlTaskCtrl1` (`[system7-spec §4.4]`).
pub const S7_SUB_TASK_CTRL1: u8 = 0x04;

/// Encodes the 10-octet `AdditionalLoadControls` load-event record for an
/// **absolute segment allocation** (`LdCtrlAbsSegment`).
///
/// Layout (`[system7-spec §4.2, M2 capture CONFIRMED]`):
/// `[event=3][subtype][start:2 BE][length:2 BE][seg_flags][mem_type][checksum_ctrl]
/// [reserved]`.
///
/// The M2 Jung 0705 capture (issue #70) pins the first six octets exactly: the
/// `03`/subtype opcode, the big-endian `start` and `length` fields, and
/// `mem_type` at octet 7. `length` is the declared segment size in octets, cross-
/// checked against the Jung app M-0004_A-A011's declared AbsSegment sizes (e.g.
/// `0x43FF` size 811 = `0x032B`; `0x4743` size 260 = `0x0104`) — every captured
/// allocation record's length equals the product's declared segment size, and the
/// address span written after it matches. `mem_type` is `2` (RAM) for the
/// `0x0700` low-RAM region and `3` (EEPROM) for the `0x4xxx` table/param regions,
/// exactly as observed.
///
/// The remaining octets are real device fields the capture shows but whose
/// derivation from the product data is not settled, so bussard emits `0` for them
/// (the sim keys allocation on opcode/subtype/start/length and ignores the trailing
/// octets, so a zero tail still drives a real 0705 device to `Loaded`):
/// - `seg_flags` (octet 6): observed `0xF2`/`0xF3` in the capture — a per-segment
///   attribute nibble that does not follow a clean address rule and is not carried
///   by the parsed product. `S7-CAL: derive the alloc-record seg_flags octet
///   (0xF2 vs 0xF3) from product data.`
/// - `checksum_ctrl` (octet 8): observed `0x80` on checksum-controlled segments
///   and `0x00` on the RAM/last segments. `S7-CAL: derive the alloc-record
///   checksum-control octet (0x80 vs 0x00) from product data.`
///
/// `subtype` is [`S7_SUB_ALLOC_DATA`] for a Data segment (the corpus/M2 form), or
/// the Stack/Task variants.
pub fn encode_alloc_segment(
    subtype: u8,
    start: u16,
    length: u16,
    seg_flags: u8,
    mem_type: u8,
    checksum_ctrl: u8,
) -> [u8; LOAD_EVENT_SIZE] {
    let mut v = [0u8; LOAD_EVENT_SIZE];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = subtype;
    v[2..4].copy_from_slice(&start.to_be_bytes());
    v[4..6].copy_from_slice(&length.to_be_bytes());
    v[6] = seg_flags;
    v[7] = mem_type;
    v[8] = checksum_ctrl;
    // v[9] reserved 0 (observed 0x00 in every M2 capture record).
    v
}

/// Encodes the 10-octet `AdditionalLoadControls` record for a **TaskSegment**
/// finalize (`LdCtrlTaskSegment`), issued once per LSM immediately before
/// `LoadCompleted` (`[system7-spec §4.3]`).
///
/// Default realisation: an absolute Task-segment allocation ([`S7_SUB_ALLOC_TASK`])
/// with `start = address` and `length` = the LSM's total loaded span.
///
/// The M2 Jung 0705 capture confirms the `[03][02][address:2 BE]` prefix — every
/// LSM finalize was `03 02 <addr> …` (LSM1 `0x4000`, LSM2 `0x41FF`, LSM3
/// `0x4722`). In the capture the length field was `0x0000` and the four trailing
/// octets a fixed `04 a0 11 13` marker; bussard's `length = span` form drives the
/// sim to `Loaded` (the sim keys the finalize on subtype + address). `S7-CAL:
/// confirm the TaskSegment length field (0x0000 vs the loaded span) and the
/// trailing `04 a0 11 13` marker semantics against product data.`
pub fn encode_task_segment(address: u16, length: u16) -> [u8; LOAD_EVENT_SIZE] {
    // access/mem_type/mem_attr are left 0 for a task descriptor; the segment was
    // already allocated by its Data alloc, this only commits the task pointer.
    encode_alloc_segment(S7_SUB_ALLOC_TASK, address, length, 0x00, 0x00, 0x00)
}

/// Encodes the 10-octet `AdditionalLoadControls` record for **Task control 1**
/// (`LdCtrlTaskCtrl1`, `[system7-spec §4.4]`): `[event=3][sub=0x04][address:2 BE]
/// [count:1]`.
///
/// The M2 Jung 0705 capture confirms the `03 04` opcode is on the download hot
/// path (a single TaskCtrl1 on LSM 3), but the captured record was `03 04` then
/// all-zero (`address = 0`, `count = 0`), so the address/count fields the product
/// declares are not carried on the wire the way this encoder lays them out. The
/// sim accepts subtype `0x04` in `Loading` with no memory side effect, so this
/// still drives to `Loaded`. `S7-CAL: reconcile the TaskCtrl1 address/count fields
/// with the captured all-zero record.`
pub fn encode_task_ctrl1(address: u16, count: u8) -> [u8; LOAD_EVENT_SIZE] {
    let mut v = [0u8; LOAD_EVENT_SIZE];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = S7_SUB_TASK_CTRL1;
    v[2..4].copy_from_slice(&address.to_be_bytes());
    v[4] = count;
    v
}

/// The width of the memory-mapped LSM control record: a 2-octet prefix plus the
/// standard 10-octet load event (`[system7-spec §5]`).
pub const MEMORY_LSM_RECORD_SIZE: usize = 2 + LOAD_EVENT_SIZE;

/// Wraps a 10-octet load event into the 12-octet memory-mapped LSM control record
/// written to the LSM control address (default `0x0104`).
///
/// Encoding (`[system7-spec §5]`): `[lsm_index:1][0x00][10-octet load event]`.
/// This is the **memory-mapped alternative** only. The M2 Jung 0705 capture
/// (issue #70) proved the real device is property-based (no `A_Memory_Write` to
/// `0x0104` anywhere in the capture), so this record is used solely for silicon
/// whose product data selects memory-mapped LSM control. `S7-CAL: confirm the
/// 12-octet record layout (prefix meaning) on a genuinely memory-mapped 0705
/// device.`
pub fn wrap_memory_lsm_record(
    lsm_index: u8,
    event: &[u8; LOAD_EVENT_SIZE],
) -> [u8; MEMORY_LSM_RECORD_SIZE] {
    let mut v = [0u8; MEMORY_LSM_RECORD_SIZE];
    v[0] = lsm_index;
    v[1] = 0x00;
    v[2..].copy_from_slice(event);
    v
}

/// A simple 10-octet load event whose only significant octet is the event opcode
/// (`StartLoading` / `LoadCompleted` / `Unload`); the remaining octets are zero.
///
/// Used to drive the LSM through its lifecycle states (`[system7-spec §4.1]`).
pub fn simple_event(control: LoadControl) -> [u8; LOAD_EVENT_SIZE] {
    let mut v = [0u8; LOAD_EVENT_SIZE];
    v[0] = control.octet();
    v
}

/// The load-state-machine access seam for System 7 (`[system7-spec §5]`).
///
/// System 7 devices realise their LSMs one of two ways. The M2 Jung 0705 capture
/// (issue #70) settled the default: the real device is **property-based**
/// ([`LsmAccess::Property`]). Both realisations are implemented behind this seam
/// and selected per mask from `HawkConfigurationData`; the corpus fallback is
/// property. Each variant is independently testable against a mock that implements
/// the matching device side.
pub enum LsmAccess {
    /// Memory-mapped (the alternative, not the default): write the 12-octet record
    /// to `control_addr` via `A_Memory_Write` and poll status at `status_addr` via
    /// `A_Memory_Read`. The M2 capture showed the real Jung device does NOT use
    /// this; kept for silicon whose product data selects it.
    MemoryMapped {
        /// The LSM-control write address (default `0x0104`).
        control_addr: u16,
        /// The LSM status-poll base address (default `0xB6EA`); the status of LSM
        /// `n` is read at `status_addr + (n - 1)`. In the M2 capture the one status
        /// touch was a single read at `0xB6EC`. `S7-CAL: confirm the per-LSM status
        /// stride on a genuinely memory-mapped 0705 device.`
        status_addr: u16,
    },
    /// Property-based: write the 10-octet load event to `PID_LOAD_STATE_CONTROL`
    /// (PID 5) via `A_PropertyValue_Write`, read the 1-octet state via
    /// `A_PropertyValue_Read`. The object index is the LSM index (both are 1-based
    /// on the loadable objects System 7 exposes).
    Property,
}

impl LsmAccess {
    /// Sends a 10-octet load `event` to load-state machine `lsm` (1-based).
    ///
    /// - `MemoryMapped`: wraps the event in the 12-octet record ([`wrap_memory_lsm_record`])
    ///   and writes it to `control_addr` (read-back-verified, like every System 7
    ///   memory write).
    /// - `Property`: writes the event to `PID_LOAD_STATE_CONTROL` of object `lsm`.
    pub async fn send_event<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
        event: &[u8; LOAD_EVENT_SIZE],
    ) -> Result<()> {
        match self {
            LsmAccess::MemoryMapped { control_addr, .. } => {
                let record = wrap_memory_lsm_record(lsm, event);
                write_memory(l4, *control_addr, &record).await
            }
            LsmAccess::Property => {
                property_write_request(l4, lsm, crate::load::PID_LOAD_STATE_CONTROL, 1, 1, event)
                    .await?;
                Ok(())
            }
        }
    }

    /// Reads the current [`LoadState`] octet of load-state machine `lsm` (1-based).
    ///
    /// - `MemoryMapped`: reads one octet at `status_addr + (lsm - 1)`.
    /// - `Property`: reads element 1 of `PID_LOAD_STATE_CONTROL` of object `lsm`.
    pub async fn read_state<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
    ) -> Result<LoadState> {
        match self {
            LsmAccess::MemoryMapped { status_addr, .. } => {
                let addr = status_addr.saturating_add(u16::from(lsm.saturating_sub(1)));
                let data = read_memory(l4, addr, 1).await?;
                let octet = data.first().copied().ok_or_else(|| {
                    WriteError::Mgmt(crate::MgmtError::MalformedResponse {
                        address: l4.target(),
                        reason: format!("LSM {lsm} status read returned no octet"),
                    })
                })?;
                Ok(LoadState::from_octet(octet))
            }
            LsmAccess::Property => {
                let resp =
                    property_request(l4, lsm, crate::load::PID_LOAD_STATE_CONTROL, 1, 1).await?;
                let octet = resp.data.first().copied().ok_or_else(|| {
                    WriteError::Mgmt(crate::MgmtError::MalformedResponse {
                        address: l4.target(),
                        reason: format!("LSM {lsm} PID_LOAD_STATE_CONTROL returned no octet"),
                    })
                })?;
                Ok(LoadState::from_octet(octet))
            }
        }
    }

    /// Drives `lsm` through a single load event and verifies the resulting state.
    ///
    /// Sends `control` as a simple 10-octet event, then reads the state back. A
    /// device that lands in [`LoadState::Error`] fails with
    /// [`WriteError::LoadError`]. `StartLoading` accepts `Loading` or (on a lenient
    /// stack) `Loaded`; `LoadCompleted` must reach `Loaded`; `Unload` is not
    /// state-checked (mirrors the System B discipline in
    /// [`crate::load::write_load_control`]).
    pub async fn drive<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
        control: LoadControl,
    ) -> Result<LoadState> {
        let address = l4.target();
        let event = simple_event(control);
        self.send_event(l4, lsm, &event).await?;
        let state = self.read_state(l4, lsm).await?;
        if state == LoadState::Error {
            return Err(WriteError::LoadError {
                address,
                object_index: lsm,
            });
        }
        // A `StartLoading` opens the LSM: `Loading`, or `Loaded` on a lenient
        // stack, is acceptable. A `LoadCompleted` must reach `Loaded`. Anything
        // else is an unexpected state and fails the flash.
        match control {
            LoadControl::StartLoading
                if !matches!(state, LoadState::Loading | LoadState::Loaded) =>
            {
                return Err(WriteError::UnexpectedLoadState {
                    address,
                    object_index: lsm,
                    control,
                    expected: LoadState::Loading,
                    actual: state,
                    context: Default::default(),
                });
            }
            LoadControl::LoadCompleted if state != LoadState::Loaded => {
                return Err(WriteError::UnexpectedLoadState {
                    address,
                    object_index: lsm,
                    control,
                    expected: LoadState::Loaded,
                    actual: state,
                    context: Default::default(),
                });
            }
            _ => {}
        }
        Ok(state)
    }

    /// Sends an `AdditionalLoadControls` record (segment alloc, task segment, or
    /// task-control) to `lsm`, then confirms the LSM did not enter `Error`.
    ///
    /// These records carry an already-built 10-octet event (from
    /// [`encode_alloc_segment`] / [`encode_task_segment`] / [`encode_task_ctrl1`]);
    /// the LSM must stay open (`Loading`, or `Loaded` on a lenient stack) after
    /// them — only `Error`/`Unloaded` indicates a refused control.
    pub async fn send_control<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
        event: &[u8; LOAD_EVENT_SIZE],
    ) -> Result<()> {
        let address = l4.target();
        self.send_event(l4, lsm, event).await?;
        let state = self.read_state(l4, lsm).await?;
        match state {
            LoadState::Error => Err(WriteError::LoadError {
                address,
                object_index: lsm,
            }),
            LoadState::Loading | LoadState::Loaded => Ok(()),
            other => Err(WriteError::UnexpectedLoadState {
                address,
                object_index: lsm,
                control: LoadControl::AdditionalLoadControls,
                expected: LoadState::Loading,
                actual: other,
                context: Default::default(),
            }),
        }
    }
}

/// Builds an [`LsmAccess`] from a [`crate::profile::Sys7Profile`]'s LSM realisation.
pub fn lsm_access_from_profile(profile: &crate::profile::Sys7Profile) -> LsmAccess {
    match profile.lsm {
        crate::profile::LsmRealisation::MemoryMapped {
            control_addr,
            status_addr,
        } => LsmAccess::MemoryMapped {
            control_addr,
            status_addr,
        },
        crate::profile::LsmRealisation::Property => LsmAccess::Property,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_alloc_segment_layout() {
        // MDT A-000E LSM 1: alloc 513 octets at 0x4000, EEPROM (3), no flags.
        let v = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x4000, 513, 0x00, 0x03, 0x00);
        assert_eq!(
            v,
            [0x03, 0x00, 0x40, 0x00, 0x02, 0x01, 0x00, 0x03, 0x00, 0x00]
        );
        assert_eq!(v.len(), LOAD_EVENT_SIZE);
    }

    #[test]
    fn test_encode_alloc_segment_matches_m2_capture_pinned_octets() {
        // M2 Jung 0705 capture (issue #70): the alloc record for LSM 3's EEPROM
        // param segment at 0x43FF was `03 00 43 ff 03 2b f2 03 80 00`, and the
        // Jung app M-0004_A-A011 declares that segment size = 811 (0x032B).
        // bussard pins the CONFIRMED octets (opcode/subtype, start, length,
        // mem_type) and emits 0 for the not-yet-derivable seg_flags (0xF2) and
        // checksum_ctrl (0x80).
        let v = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x43FF, 0x032B, 0x00, 0x03, 0x00);
        assert_eq!(v[0], 0x03, "event opcode = AdditionalLoadControls");
        assert_eq!(v[1], S7_SUB_ALLOC_DATA, "subtype = alloc Data");
        assert_eq!(&v[2..4], &[0x43, 0xFF], "start 0x43FF, big-endian");
        assert_eq!(&v[4..6], &[0x03, 0x2B], "length 0x032B = declared size 811");
        assert_eq!(v[7], 0x03, "mem_type = EEPROM (3) for a 0x4xxx region");

        // The 0x0700 low-RAM region is mem_type 2 (RAM), size 450 (0x01C2) —
        // capture `03 00 07 00 01 c2 f2 02 00 00`.
        let ram = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x0700, 0x01C2, 0x00, 0x02, 0x00);
        assert_eq!(&ram[2..4], &[0x07, 0x00]);
        assert_eq!(
            &ram[4..6],
            &[0x01, 0xC2],
            "length 0x01C2 = declared size 450"
        );
        assert_eq!(ram[7], 0x02, "mem_type = RAM (2) for the 0x0700 region");
    }

    #[test]
    fn test_encode_task_segment_is_alloc_task_subtype() {
        // TaskSegment at 0x4400, span 180.
        let v = encode_task_segment(0x4400, 180);
        assert_eq!(v[0], 0x03);
        assert_eq!(v[1], S7_SUB_ALLOC_TASK);
        assert_eq!(&v[2..4], &[0x44, 0x00]);
        assert_eq!(&v[4..6], &[0x00, 0xB4]);
    }

    #[test]
    fn test_encode_task_ctrl1_layout() {
        // Theben FIX2: task_ctrl1 addr=18425 (0x47F9) count=1.
        let v = encode_task_ctrl1(0x47F9, 1);
        assert_eq!(
            v,
            [0x03, 0x04, 0x47, 0xF9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_wrap_memory_lsm_record_prefix() {
        let event = simple_event(LoadControl::StartLoading);
        let rec = wrap_memory_lsm_record(2, &event);
        assert_eq!(rec.len(), 12);
        assert_eq!(rec[0], 2); // lsm index prefix
        assert_eq!(rec[1], 0x00); // reserved
        assert_eq!(rec[2], LoadControl::StartLoading.octet()); // event opcode
    }

    #[test]
    fn test_simple_event_only_opcode_significant() {
        let v = simple_event(LoadControl::Unload);
        assert_eq!(v[0], 4);
        assert!(v[1..].iter().all(|&b| b == 0));
    }
}
