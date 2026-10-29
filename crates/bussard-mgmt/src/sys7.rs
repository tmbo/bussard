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
//! The LSM realisation is **mask-family dependent** (`[system7-spec §5]`): the
//! Jung `0705` family drives load control **property-based**
//! (`A_PropertyValue_Write(objN, PID 5)`, [`LsmAccess::Property`], M2 capture
//! issue #70), while the Theben `0701` family drives it **memory-mapped** — an
//! **11-octet** record over `A_Memory_Write` to `0x0104`
//! ([`LsmAccess::MemoryMapped`], Meteodata capture). Both live behind the seam.
//!
//! Everything here is clean-room: encoders from the published KNX
//! `AdditionalLoadControls` structure (KNX 3/5/2), the issue-#49 corpus
//! archaeology and the real-ETS download analysis; no GPL source was consulted.
//! Every octet of the allocation, TaskSegment and TaskCtrl1 records comes from
//! the product's load procedure and application attributes, checked against the
//! ETS 6 sweep captures of nine manufacturers.

use crate::connection::{L4Channel, Layer4Connection, property_request, property_write_request};
use crate::load::{LoadControl, LoadState, Result, WriteError, read_memory_strict, write_memory};

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
/// Octets 6 to 8 are the `LdCtrlAbsSegment` attributes verbatim: octet 6 is
/// `Access`, octet 7 `MemType`, octet 8 `SegFlags`. All 172 allocation records
/// of the ETS sweep captures (nine manufacturers, 0705 and 0701) match that,
/// including the `ff 03 00` of an M-0002 segment with `Access="255"
/// SegFlags="0"`. The planner passes the product's values; [`alloc_attr_octets`]
/// is only the fallback for an op that does not declare them.
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
    // v[9] reserved 0 (observed 0x00 in every capture record).
    v
}

/// The fallback AbsSegment `(access, seg_flags)` octets for an op that does not
/// declare `Access`/`SegFlags`, from the segment's `mem_type`
/// (`[system7-spec §4.2]`), reproducing the dominant real-ETS pattern (see
/// [`encode_alloc_segment`]):
/// - EEPROM (`mem_type == 3`) → `(0xF2, 0x80)` — checksum-controlled;
/// - RAM (`mem_type == 2`, and anything else) → `(0xF2, 0x00)` — no checksum.
///
/// Cites the binaereingang-6fach 0705 capture (`0300400001ff f2 03 80 00` EEPROM,
/// `0300070001c2 f2 02 00 00` RAM) and the Theben 0701 Meteodata capture
/// (`13 00 00 40 00 00 1d f2 03 80 00` EEPROM, `33 00 00 1c 00 01 b0 f2 02 00 00`
/// RAM).
pub fn alloc_attr_octets(mem_type: u8) -> (u8, u8) {
    let seg_flags = 0xF2;
    let checksum_ctrl = if mem_type == 3 { 0x80 } else { 0x00 };
    (seg_flags, checksum_ctrl)
}

/// The application identity a System 7 TaskSegment record carries
/// ([`encode_task_segment`]). Every field comes from the product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sys7TaskIdentity {
    /// The application's `PeiType` (`0` on the Jung and Theben products, `1` on
    /// the Ekinex EK-E72, `128` on the Busch-Jaeger A-A002).
    pub pei_type: u8,
    /// The manufacturer id: the one in the application id (`M-00B6` gives
    /// `0x00B6`), or the `OriginalManufacturer` when the application declares
    /// `LegacyPatchManufacturerIdInTaskSegment`.
    pub manufacturer: u16,
    /// The application's `ApplicationNumber`.
    pub application_number: u16,
    /// The application's `ApplicationVersion`.
    pub application_version: u8,
}

impl Sys7TaskIdentity {
    /// The six identity octets as the record carries them:
    /// `[PEI type][manufacturer:2 BE][application number:2 BE][version]`.
    pub fn octets(&self) -> [u8; 6] {
        let [m_hi, m_lo] = self.manufacturer.to_be_bytes();
        let [a_hi, a_lo] = self.application_number.to_be_bytes();
        [
            self.pei_type,
            m_hi,
            m_lo,
            a_hi,
            a_lo,
            self.application_version,
        ]
    }
}

/// Encodes the 10-octet `AdditionalLoadControls` record for a **TaskSegment**
/// (`LdCtrlTaskSegment`), issued once per LSM immediately before
/// `LoadCompleted` (`[system7-spec §4.3]`).
///
/// Layout: `[03][02][address:2 BE][PEI type][manufacturer:2 BE]
/// [application number:2 BE][application version]`.
///
/// ETS 6.4.1 into knx-sim with the Ekinex EK-E72 (`M-00B6_A-4537-03-DE59`,
/// `PeiType="1" ApplicationNumber="17719" ApplicationVersion="3"`) wrote
/// `03 02 40 00 01 00 b6 45 37 03` on object 1 and `03 02 40 ed 01 00 b6 45 37 03`
/// on object 2. The Jung (`00 00 04 …`) and Theben (`00 00 48 …`) records read
/// the same way with PEI type 0, and the TaskSegment records of the ETS sweep
/// captures of 30 applications from nine manufacturers all match.
pub fn encode_task_segment(address: u16, identity: &Sys7TaskIdentity) -> [u8; LOAD_EVENT_SIZE] {
    let mut v = [0u8; LOAD_EVENT_SIZE];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = S7_SUB_ALLOC_TASK;
    v[2..4].copy_from_slice(&address.to_be_bytes());
    v[4..10].copy_from_slice(&identity.octets());
    v
}

/// Encodes the 10-octet `AdditionalLoadControls` record for **Task control 1**
/// (`LdCtrlTaskCtrl1`, `[system7-spec §4.4]`): `[event=3][sub=0x04][address:2 BE]
/// [count:1]`.
///
/// This encoder is **CONFIRMED correct** by the schaltaktor-8-fach 0705 capture,
/// whose real non-zero TaskCtrl1 on LSM 3 was `03 04 4b b9 01 00 00 00 00 00`
/// (address `0x4BB9`, count 1) — exactly what `encode_task_ctrl1(0x4BB9, 1)`
/// produces. The all-zero TaskCtrl1 seen on the Jung presence/binary devices is
/// that app's declared address/count 0 (a family-specific quirk), NOT an encoder
/// bug. The Theben 0701 Meteodata capture likewise carried a non-zero memory-form
/// TaskCtrl1 (`33 04 00 46 eb 01 …`, address `0x46EB` count 1) that this encoder
/// reproduces once wrapped by [`wrap_memory_lsm_record`]. No `S7-CAL` remains.
pub fn encode_task_ctrl1(address: u16, count: u8) -> [u8; LOAD_EVENT_SIZE] {
    let mut v = [0u8; LOAD_EVENT_SIZE];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = S7_SUB_TASK_CTRL1;
    v[2..4].copy_from_slice(&address.to_be_bytes());
    v[4] = count;
    v
}

/// The width of the memory-mapped LSM control record: **11 octets**, written by
/// `A_Memory_Write` to the LSM control address (default `0x0104`).
///
/// The Theben `0701` Meteodata capture pins this at 11 octets (every
/// `MemoryWrite @0x0104` was `n=11`), NOT the pre-analysis 12-octet
/// `[lsm][00][10-octet event]` guess. See [`wrap_memory_lsm_record`] for the
/// layout.
pub const MEMORY_LSM_RECORD_SIZE: usize = 11;

/// Wraps a 10-octet abstract load event into the **11-octet** memory-mapped LSM
/// control record written to the LSM control address (default `0x0104`).
///
/// Encoding (`[system7-spec §5]`, Theben `0701` Meteodata capture CONFIRMED):
/// ```text
/// [0]      (lsm_index << 4) | event_opcode   e.g. 0x13 = LSM1 + AdditionalLoadControls(3)
/// [1]      subtype                           00 alloc / 02 task / 04 taskctrl1
/// [2]      0x00                              high octet of the 3-octet start address
/// [3..5]   start:2 BE                        the segment start address (low 16 bits)
/// [5..11]  the event's octets 4..10          length/access/mem_type/seg_flags/reserved (alloc)
///                                            OR the 6-octet application identity (task segment)
/// ```
/// The LSM index is folded into the **high nibble of the event opcode byte**;
/// there is NO separate `[lsm][00]` prefix. Relative to the abstract 10-octet
/// event the address field is widened to 3 octets (a leading `0x00`), which is
/// exactly the byte-for-byte transform that reproduces the captured records:
/// - alloc `13 00 00 40 00 00 1d f2 03 80 00` (LSM1, 0x4000 len 0x1D, EEPROM),
/// - task  `13 02 00 40 00 00 00 48 14 0c 14` (LSM1, identity `00 00 48 14 0c 14`),
/// - taskctrl1 `33 04 00 46 eb 01 00 00 00 00 00` (LSM3, addr 0x46EB count 1).
///
/// `lsm_index` must be `1..=15` (it occupies the high nibble; `0` names no
/// machine), and the callers validate that — `bussard-download` refuses such a
/// plan at plan time and re-checks in the executor (issue #81). Here the index is
/// masked to its nibble so a stray value can never bleed into the **opcode** half
/// of the octet and send a different load event than the caller asked for.
pub fn wrap_memory_lsm_record(
    lsm_index: u8,
    event: &[u8; LOAD_EVENT_SIZE],
) -> [u8; MEMORY_LSM_RECORD_SIZE] {
    let mut v = [0u8; MEMORY_LSM_RECORD_SIZE];
    // Fold the LSM index into the high nibble of the event opcode byte. The event
    // opcode is <= 0x04 so the low nibble carries it losslessly. The index is
    // masked to a nibble first: `(16 << 4)` would truncate to `0x00` and silently
    // rewrite the opcode, so the mask keeps the corruption out of the half of the
    // octet that decides *what* the record does.
    debug_assert!(
        (1..=15).contains(&lsm_index),
        "LSM index {lsm_index} is outside 1..=15"
    );
    v[0] = ((lsm_index & 0x0F) << 4) | (event[0] & 0x0F);
    v[1] = event[1]; // subtype
    v[2] = 0x00; // high octet of the widened 3-octet start address
    // Widen the 2-octet address to 3 octets and copy the remaining event fields
    // (length + tail) verbatim: event[2..10] -> record[3..11].
    v[3..MEMORY_LSM_RECORD_SIZE].copy_from_slice(&event[2..LOAD_EVENT_SIZE]);
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
/// System 7 devices realise their LSMs one of two ways, selected by mask family:
/// the Jung `0705` family is **property-based** ([`LsmAccess::Property`], M2
/// capture issue #70) and the Theben `0701` family is **memory-mapped**
/// ([`LsmAccess::MemoryMapped`], Meteodata capture). Both realisations are
/// implemented behind this seam and selected per mask
/// ([`crate::Sys7Profile::corpus_default_for_mask`]) or from
/// `HawkConfigurationData`. Each variant is independently testable against a mock
/// that implements the matching device side.
pub enum LsmAccess {
    /// Memory-mapped (the Theben `0701` realisation): write the **11-octet** record
    /// ([`wrap_memory_lsm_record`]) to `control_addr` via `A_Memory_Write` and poll
    /// status at `status_addr + (lsm - 1)` via `A_Memory_Read`. Confirmed by the
    /// Theben 0701 Meteodata capture (11-octet writes to `0x0104`, status at
    /// `0xB6EA+`). The Jung `0705` family uses `Property` instead.
    MemoryMapped {
        /// The LSM-control write address (default `0x0104`).
        control_addr: u16,
        /// The LSM status-poll base address (default `0xB6EA`); the status of LSM
        /// `n` is read at `status_addr + (n - 1)`. Confirmed by the Theben 0701
        /// capture (`MemoryRead @0xB6EC` for LSM 3, i.e. base `0xB6EA` + 2).
        status_addr: u16,
    },
    /// Property-based: write the 10-octet load event to `PID_LOAD_STATE_CONTROL`
    /// (PID 5) via `A_PropertyValue_Write`, read the 1-octet state via
    /// `A_PropertyValue_Read`. The object index is the LSM index (both are 1-based
    /// on the loadable objects System 7 exposes).
    Property,
}

impl LsmAccess {
    /// Sends a 10-octet load `event` to load-state machine `lsm` (1-based) and
    /// returns the state the device reported in its answer, when the realisation
    /// carries one.
    ///
    /// - `MemoryMapped`: wraps the event in the 11-octet record ([`wrap_memory_lsm_record`])
    ///   and writes it to `control_addr` via the shared
    ///   [`crate::memory::write_memory`] (a plain `A_Memory_Write`, which has no
    ///   answer). Returns `None`: the LSM's own status read is what confirms the
    ///   event took, and ETS reads it after every event on this realisation
    ///   (Theben `0701` Meteodata capture).
    /// - `Property`: writes the event to `PID_LOAD_STATE_CONTROL` of object `lsm`.
    ///   The `A_PropertyValue_Response` to the write carries the state the event
    ///   left the machine in (every write in the Jung `0705` captures, e.g.
    ///   `Unload` answered `00`, `StartLoading` `02`, `LoadCompleted` `01`), so it
    ///   is returned as `Some(state)` and ETS never reads the state separately.
    ///   `None` when the answer is not a single state octet. An answer with count 0
    ///   fails with [`WriteError::ObjectAbsent`].
    pub async fn send_event<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
        event: &[u8; LOAD_EVENT_SIZE],
    ) -> Result<Option<LoadState>> {
        match self {
            LsmAccess::MemoryMapped { control_addr, .. } => {
                let record = wrap_memory_lsm_record(lsm, event);
                // System 7 addresses are always ≤16-bit, so this stays on the
                // plain A_Memory_Write path (see `select_extended_memory`).
                write_memory(l4, u32::from(*control_addr), &record).await?;
                Ok(None)
            }
            LsmAccess::Property => {
                let resp = property_write_request(
                    l4,
                    lsm,
                    crate::load::PID_LOAD_STATE_CONTROL,
                    1,
                    1,
                    event,
                )
                .await?;
                // Count 0 is the negative answer: the device has no such object.
                if resp.count == 0 {
                    return Err(WriteError::ObjectAbsent {
                        address: l4.target(),
                        object_index: lsm,
                    });
                }
                // The state is one octet. A stack that echoes the written
                // event instead (10 octets) says nothing about the state, so
                // that answer falls back to a read.
                Ok(match resp.data.as_slice() {
                    [state] => Some(LoadState::from_octet(*state)),
                    _ => None,
                })
            }
        }
    }

    /// The state `lsm` is in after an event: the state the event's answer
    /// carried (`reported`), else a separate [`read_state`](Self::read_state).
    async fn state_after<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
        reported: Option<LoadState>,
    ) -> Result<LoadState> {
        match reported {
            Some(state) => Ok(state),
            None => self.read_state(l4, lsm).await,
        }
    }

    /// Reads the current [`LoadState`] octet of load-state machine `lsm` (1-based).
    ///
    /// - `MemoryMapped`: reads one octet at `status_addr + (lsm - 1)`.
    /// - `Property`: reads element 1 of `PID_LOAD_STATE_CONTROL` of object `lsm`;
    ///   an answer with count 0 fails with [`WriteError::ObjectAbsent`].
    pub async fn read_state<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        lsm: u8,
    ) -> Result<LoadState> {
        match self {
            LsmAccess::MemoryMapped { status_addr, .. } => {
                let addr = status_addr.saturating_add(u16::from(lsm.saturating_sub(1)));
                let data = read_memory_strict(l4, u32::from(addr), 1).await?;
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
                // Count 0 is the negative answer for an object the device does
                // not have (issue #178), not a malformed response.
                if resp.count == 0 {
                    return Err(WriteError::ObjectAbsent {
                        address: l4.target(),
                        object_index: lsm,
                    });
                }
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
    /// Sends `control` as a simple 10-octet event and takes the resulting state
    /// from the event's answer (property realisation) or a status read
    /// (memory-mapped realisation, as ETS does there). The verdict on the whole
    /// load, the state after `LoadCompleted`, comes from the answer only when it
    /// is exactly `Loaded` (the `01` every write answer in the Jung `0705`
    /// captures carries, where ETS never reads PID 5, issue #211); any other
    /// answer is confirmed by a separate read, and the memory-mapped
    /// realisation (Theben `0701`) always reads, as ETS does there (#186). A
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
        let reported = self.send_event(l4, lsm, &event).await?;
        // The verdict on the load trusts the write's answer only when it is
        // the `Loaded` a conformant 0705 device answers (issue #211); anything
        // else, or no answer state at all, is read back as before (#116).
        let reported = if control == LoadControl::LoadCompleted {
            reported.filter(|state| *state == LoadState::Loaded)
        } else {
            reported
        };
        let state = self.state_after(l4, lsm, reported).await?;
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
    /// The state comes from the record's answer on the property realisation (no
    /// extra read, like ETS) and from a status read on the memory-mapped one.
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
        let reported = self.send_event(l4, lsm, event).await?;
        let state = self.state_after(l4, lsm, reported).await?;
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

/// `PID_DEVICE_CONTROL` (PID 14) of the device object: the 1-octet device
/// control bit field (KNX 3/5/1, device object).
///
/// Bit 0 is "user application stopped", bit 1 "own individual address
/// duplicated", bit 2 **verify mode** (the device answers every
/// `A_Memory_Write` with an `A_Memory_Response` carrying the octets it
/// stored), bit 3 "safe state".
pub const PID_DEVICE_CONTROL: u8 = 14;

/// The verify-mode bit of [`PID_DEVICE_CONTROL`].
pub const DEVICE_CONTROL_VERIFY_MODE: u8 = 0x04;

/// What [`enable_verify_mode`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyModeOutcome {
    /// The bit was clear: the device held `previous` and now holds `written`.
    Enabled {
        /// The value read before the write.
        previous: u8,
        /// The value written (`previous` with the verify-mode bit set).
        written: u8,
    },
    /// The bit was already set; nothing was written.
    AlreadyOn(u8),
    /// The device has no readable `PID_DEVICE_CONTROL` (the read answered
    /// count 0 or no value); nothing was written.
    Unsupported,
    /// The device refused the write (count 0); it still holds `previous`.
    Refused {
        /// The value read before the refused write.
        previous: u8,
    },
}

/// Switches on the device's verify mode the way ETS does before the first
/// memory write of a System 7 download on a mask with the Hawk `VerifyMode`
/// feature (issue #116).
///
/// Every Jung `0705` capture (`schaltaktor-8fach-1-1-49`, `pm-mini-1-1-52`,
/// `bad-eg-pm-1-1-18`) reads `obj0/PID_DEVICE_CONTROL` (answer `00`) and writes
/// back `04`, the verify-mode bit, right after the first allocation record. The
/// device then answers each segment write with an `A_Memory_Response` echo,
/// which [`crate::write_memory_echoed`] compares with the chunk written. The
/// device clears the bit when the transport connection closes (Resources
/// 03_05_01 §4.2.14), so a caller runs this again on every connection it
/// opens before the next write. Reads first and writes only when the bit
/// is clear, keeping every other bit as the device holds it. The bit lives in
/// RAM: the terminal restart clears it again.
pub async fn enable_verify_mode<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<VerifyModeOutcome> {
    let read = property_request(
        l4,
        crate::apci::DEVICE_OBJECT_INDEX,
        PID_DEVICE_CONTROL,
        1,
        1,
    )
    .await?;
    let Some(previous) = read.data.first().copied().filter(|_| read.count > 0) else {
        return Ok(VerifyModeOutcome::Unsupported);
    };
    if previous & DEVICE_CONTROL_VERIFY_MODE != 0 {
        return Ok(VerifyModeOutcome::AlreadyOn(previous));
    }
    let written = previous | DEVICE_CONTROL_VERIFY_MODE;
    let resp = property_write_request(
        l4,
        crate::apci::DEVICE_OBJECT_INDEX,
        PID_DEVICE_CONTROL,
        1,
        1,
        &[written],
    )
    .await?;
    // DMP_MemWrite_RCoV (Management Procedures 03_05_02 §3.16.3): the
    // response must carry the bit, a different or empty answer means the
    // device did not take it.
    let took = resp
        .data
        .first()
        .is_none_or(|v| v & DEVICE_CONTROL_VERIFY_MODE != 0);
    if resp.count == 0 || !took {
        return Ok(VerifyModeOutcome::Refused { previous });
    }
    Ok(VerifyModeOutcome::Enabled { previous, written })
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
    fn test_encode_alloc_segment_matches_capture_with_derived_attr_octets() {
        // binaereingang-6fach 0705 capture: LSM 3's EEPROM param segment at 0x43FE
        // was `03 00 43 fe 03 73 f2 03 80 00`. With the derived attribute octets
        // (0xF2 seg_flags, 0x80 checksum for EEPROM) bussard now reproduces it
        // byte-for-byte.
        let (sf, cc) = alloc_attr_octets(0x03);
        let v = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x43FE, 0x0373, sf, 0x03, cc);
        assert_eq!(
            v,
            [0x03, 0x00, 0x43, 0xFE, 0x03, 0x73, 0xF2, 0x03, 0x80, 0x00],
            "EEPROM alloc reproduces the captured f2/03/80 tail"
        );

        // The 0x0700 low-RAM region is mem_type 2 (RAM), size 450 (0x01C2) —
        // capture `03 00 07 00 01 c2 f2 02 00 00`.
        let (sf, cc) = alloc_attr_octets(0x02);
        let ram = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x0700, 0x01C2, sf, 0x02, cc);
        assert_eq!(
            ram,
            [0x03, 0x00, 0x07, 0x00, 0x01, 0xC2, 0xF2, 0x02, 0x00, 0x00],
            "RAM alloc reproduces the captured f2/02/00 tail"
        );
    }

    #[test]
    fn test_alloc_attr_octets_derives_from_mem_type() {
        // EEPROM (3) is checksum-controlled (0x80); RAM (2) is not (0x00). seg_flags
        // is the dominant 0xF2 in both.
        assert_eq!(alloc_attr_octets(0x03), (0xF2, 0x80));
        assert_eq!(alloc_attr_octets(0x02), (0xF2, 0x00));
    }

    /// The Jung 0705 binaereingang (M-0004_A-7066-11, PEI type 0).
    const JUNG_7066: Sys7TaskIdentity = Sys7TaskIdentity {
        pei_type: 0,
        manufacturer: 0x0004,
        application_number: 0x7066,
        application_version: 0x11,
    };

    /// The Theben 0701 Meteodata (M-0048_A-140C-14, PEI type 0).
    const THEBEN_140C: Sys7TaskIdentity = Sys7TaskIdentity {
        pei_type: 0,
        manufacturer: 0x0048,
        application_number: 0x140C,
        application_version: 0x14,
    };

    #[test]
    fn test_encode_task_segment_ekinex_e72_matches_ets() {
        // ETS 6.4.1 into knx-sim, M-00B6_A-4537-03-DE59 (PeiType 1, number
        // 17719 = 0x4537, version 3): obj1 and obj2 PID 5.
        let e72 = Sys7TaskIdentity {
            pei_type: 1,
            manufacturer: 0x00B6,
            application_number: 17719,
            application_version: 3,
        };
        assert_eq!(
            encode_task_segment(0x4000, &e72),
            [0x03, 0x02, 0x40, 0x00, 0x01, 0x00, 0xB6, 0x45, 0x37, 0x03]
        );
        assert_eq!(
            encode_task_segment(0x40ED, &e72),
            [0x03, 0x02, 0x40, 0xED, 0x01, 0x00, 0xB6, 0x45, 0x37, 0x03]
        );
    }

    #[test]
    fn test_encode_task_segment_jung_0705() {
        // binaereingang-6fach capture: `03 02 40 00 00 00 04 70 66 11`.
        assert_eq!(
            encode_task_segment(0x4000, &JUNG_7066),
            [0x03, 0x02, 0x40, 0x00, 0x00, 0x00, 0x04, 0x70, 0x66, 0x11]
        );
    }

    #[test]
    fn test_encode_task_segment_theben_0701() {
        // Meteodata capture, property-form event `03 02 40 00 00 00 48 14 0c 14`.
        assert_eq!(
            encode_task_segment(0x4000, &THEBEN_140C),
            [0x03, 0x02, 0x40, 0x00, 0x00, 0x00, 0x48, 0x14, 0x0C, 0x14]
        );
    }

    #[test]
    fn test_encode_task_segment_two_octet_manufacturer() {
        // ETS sweep, M-011E_A-BC87-13: the manufacturer fills both octets.
        let id = Sys7TaskIdentity {
            pei_type: 0,
            manufacturer: 0x011E,
            application_number: 0xBC87,
            application_version: 0x13,
        };
        assert_eq!(id.octets(), [0x00, 0x01, 0x1E, 0xBC, 0x87, 0x13]);
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
    fn test_wrap_memory_lsm_record_is_11_octet_theben_layout() {
        // 11 octets, LSM folded into the high nibble of byte 0, no [lsm][00] prefix.
        // StartLoading LSM2: `21 00 00 00 00 00 00 00 00 00 00`.
        let event = simple_event(LoadControl::StartLoading);
        let rec = wrap_memory_lsm_record(2, &event);
        assert_eq!(rec.len(), 11);
        assert_eq!(rec[0], 0x21, "LSM2 (2<<4) | StartLoading (1)");
        assert!(rec[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_wrap_memory_lsm_record_matches_theben_capture_bytes() {
        // Theben 0701 Meteodata capture, byte-for-byte:
        // alloc LSM1 0x4000 len 0x1D EEPROM -> `13 00 00 40 00 00 1d f2 03 80 00`.
        let (sf, cc) = alloc_attr_octets(0x03);
        let alloc = encode_alloc_segment(S7_SUB_ALLOC_DATA, 0x4000, 0x001D, sf, 0x03, cc);
        assert_eq!(
            wrap_memory_lsm_record(1, &alloc),
            [
                0x13, 0x00, 0x00, 0x40, 0x00, 0x00, 0x1D, 0xF2, 0x03, 0x80, 0x00
            ]
        );

        // task LSM1 -> `13 02 00 40 00 00 00 48 14 0c 14` (marker `48 14 0c 14`).
        let task = encode_task_segment(0x4000, &THEBEN_140C);
        assert_eq!(
            wrap_memory_lsm_record(1, &task),
            [
                0x13, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x48, 0x14, 0x0C, 0x14
            ]
        );

        // taskctrl1 LSM3 addr 0x46EB count 1 -> `33 04 00 46 eb 01 00 00 00 00 00`.
        let tc = encode_task_ctrl1(0x46EB, 1);
        assert_eq!(
            wrap_memory_lsm_record(3, &tc),
            [
                0x33, 0x04, 0x00, 0x46, 0xEB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        // Unload LSM1 -> `14 00 00 …` (all-zero tail).
        let unload = simple_event(LoadControl::Unload);
        assert_eq!(
            wrap_memory_lsm_record(1, &unload),
            [
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn test_simple_event_only_opcode_significant() {
        let v = simple_event(LoadControl::Unload);
        assert_eq!(v[0], 4);
        assert!(v[1..].iter().all(|&b| b == 0));
    }
}
