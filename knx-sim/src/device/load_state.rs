//! Load-state control: System B `PID_LOAD_STATE_CONTROL` writes and the System 7
//! load-state machines driven by memory-mapped or property records.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;

use super::{
    Device, DeviceError, DeviceReaction, LoadEvent, LoadState, PID_LOAD_STATE_CONTROL,
    Sys7LoadStateMachine, Sys7Step, profile, sys7_lsm,
};

impl Device {
    pub(super) fn on_load_state_write(
        &mut self,
        tool: IndividualAddress,
        object: u8,
        count: u8,
        start: u16,
        value: &[u8],
    ) -> Result<DeviceReaction, DeviceError> {
        let state = self
            .loadables
            .get_mut(&object)
            .ok_or(DeviceError::NoProperty {
                object,
                pid: PID_LOAD_STATE_CONTROL,
            })?;
        let event =
            LoadEvent::decode(value).map_err(|e| DeviceError::LoadControl(e.to_string()))?;
        // On allocation, wire the segment into memory at the object's base.
        let new_state = match state.lsm.apply(event) {
            Ok(s) => s,
            Err(e) => {
                // Strict: report Error state back, surface rejection.
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object,
                    state: LoadState::Error.to_byte(),
                });
                return Err(DeviceError::LoadControl(e.to_string()));
            }
        };
        if let LoadEvent::AllocRelSegment { size } = event {
            let base = state.base;
            self.memory.allocate(object, base, size);
        }
        self.emit(Event::LoadStateChanged {
            device: self.address,
            object,
            state: new_state.to_byte(),
        });
        // Reaching Loaded on a table object may complete the device's group
        // configuration: reconstruct its runtime routing from the freshly-written
        // tables (a no-op until obj1/2/3 are all Loaded). A LoadCompleted that
        // does not finish the set leaves the device silent.
        if new_state == LoadState::Loaded {
            self.refresh_group_comm();
        }
        // The write response reports the resulting load state as the value.
        let mut data = vec![
            object,
            PID_LOAD_STATE_CONTROL,
            (count << 4) | ((start >> 8) as u8 & 0x0F),
            (start & 0xFF) as u8,
        ];
        data.push(new_state.to_byte());
        let resp = self.respond(tool, 0x3D6, &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Apply a System 7 load event (10-octet record) to the addressed LSM,
    /// wiring the side effects: AbsSegment allocation reserves the memory
    /// segment; TaskSegment commits the descriptor; LoadCompleted may complete
    /// the group configuration. Shared by both LSM-access realisations.
    pub(super) fn apply_sys7_event(
        &mut self,
        _tool: IndividualAddress,
        lsm_index: u8,
        event_record: &[u8],
    ) -> Result<(), DeviceError> {
        let event = sys7_lsm::Sys7Event::decode(event_record)
            .map_err(|e| DeviceError::LoadControl(e.to_string()))?;
        let s7 = self
            .sys7
            .as_mut()
            .ok_or_else(|| DeviceError::LoadControl("not a System 7 device".into()))?;
        // A post-restart LSM (spec §3/§4.7, the Theben 0701 LSM 5) is opened by the
        // device *after* the terminal restart, so it is not among the canonical
        // 1..4 seeded at construction. Only the memory-mapped realisation drives
        // such an LSM through the control record (the property realisation would
        // address an interface object that must already exist), so lazily register
        // a memory-mapped LSM the device has not seen, starting in `Unloaded`: the
        // post-restart descriptor-commit dance (TaskSegment then StartLoading, no
        // LoadCompleted) opens it (see the LSM transition table). A property PID-5
        // access to an unknown object is still rejected below (and by
        // `on_property_write`).
        if !s7.lsms.contains_key(&lsm_index)
            && s7.profile.lsm_access == profile::LsmAccess::MemoryMapped
        {
            s7.lsms
                .insert(lsm_index, Sys7LoadStateMachine::new(LoadState::Unloaded));
        }
        let lsm = s7.lsms.get_mut(&lsm_index).ok_or(DeviceError::NoProperty {
            object: lsm_index,
            pid: PID_LOAD_STATE_CONTROL,
        })?;
        let step = match lsm.apply(event) {
            Ok(s) => s,
            Err(e) => {
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object: lsm_index,
                    state: LoadState::Error.to_byte(),
                });
                return Err(DeviceError::LoadControl(e.to_string()));
            }
        };
        match step {
            Sys7Step::Alloc {
                start,
                length,
                subtype,
            } => {
                // Reserve the absolute segment for this LSM. A subtype-0x02 (Task)
                // record with a base already allocated for the LSM is a descriptor
                // commit rather than a fresh allocation, so only (re)allocate when
                // the address is not already inside the LSM's open segment.
                let start = u32::from(start);
                let already = self
                    .memory
                    .segment_of(lsm_index)
                    .is_some_and(|seg| seg.contains(start, 1));
                if !(subtype == 0x02 && already) {
                    self.memory.allocate(lsm_index, start, length as u32);
                }
            }
            Sys7Step::TaskCommitted { address: _ } => {
                // The descriptor is committed inside the LSM; no memory side effect
                // in the M1 model (the sim treats it as a precondition flag).
            }
            Sys7Step::TaskCtrl1 {
                address: _,
                count: _,
            } => {
                // A task-control-1 entry (spec §4.4, Jung M-0004_A-A011): accepted
                // while Loading with no memory side effect in the M1 model.
            }
            Sys7Step::State(new_state) => {
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object: lsm_index,
                    state: new_state.to_byte(),
                });
                // Every System 7 LSM state change re-evaluates the runtime
                // routing, not just the one that reaches Loaded. A `LoadCompleted`
                // brings the device alive on the freshly written tables; an
                // `Unload` or `StartLoading` on a table LSM takes it back off the
                // group side while its tables are being rewritten (spec §4.1: a
                // table is active only in `Loaded`). That is what makes a
                // table-only reload of an already-Loaded device — Unload,
                // StartLoading, rewrite, LoadCompleted — observable: the device
                // goes silent mid-reload and comes back on the new tables.
                self.refresh_group_comm();
            }
            Sys7Step::NoOp => {}
        }
        Ok(())
    }

    /// If `addr` falls in the System 7 memory-mapped LSM status region, return
    /// the `n` status bytes (one live LSM state per octet), else `None`.
    pub(super) fn sys7_status_bytes(&self, addr: u16, n: usize) -> Option<Vec<u8>> {
        let s7 = self.sys7.as_ref()?;
        if s7.profile.lsm_access != profile::LsmAccess::MemoryMapped {
            return None;
        }
        let base = s7.profile.mm_lsm.status_addr;
        // The status region spans one octet per LSM index starting at `base`
        // (index 1 at base+0). Only serve reads wholly inside that region.
        let region_len = s7.lsms.keys().copied().max().unwrap_or(0) as usize;
        let end = base as u32 + region_len as u32;
        if (addr as u32) < base as u32 || (addr as u32 + n as u32) > end.max(base as u32 + 1) {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let lsm_index = (addr.wrapping_add(i as u16).wrapping_sub(base)) as u8 + 1;
            let state = self
                .load_state(lsm_index)
                .map(|s| s.to_byte())
                .unwrap_or(0x00);
            out.push(state);
        }
        Some(out)
    }

    /// The entry count of a System B table object (by LSM index), read from the
    /// big-endian count word at its segment base, but only once that object is
    /// `Loaded` (a table being rewritten has no trustworthy count yet). `None`
    /// on System 7, for an unloaded object, or when the count word lies outside
    /// the object's segment.
    pub(super) fn loaded_table_count(&self, lsm_index: u8) -> Option<u16> {
        if self.sys7.is_some() || self.load_state(lsm_index) != Some(LoadState::Loaded) {
            return None;
        }
        let base = self.loadables.get(&lsm_index)?.base;
        let word = self.memory.read_bounded(base, 2)?;
        Some(u16::from_be_bytes([word[0], word[1]]))
    }

    /// Apply a System 7 memory-mapped LSM control record (the **11-octet** form
    /// written to the control address, spec section 5). The encoding is confirmed
    /// by the Theben 0701 Meteodata capture:
    /// ```text
    /// [0] (lsm_index << 4) | event_opcode   [1] subtype   [2] 0x00 (addr high)
    /// [3..5] start:2 BE   [5..7] length:2 BE   [7..11] tail
    /// ```
    /// The LSM index is folded into the high nibble of the event byte — there is
    /// NO separate `[lsm][00]` prefix. This is the memory-mapped device side, used
    /// by a device configured `lsm_access: memory` (the Theben 0701 family); the
    /// Jung 0705 family is property-based (`on_sys7_property_lsm`).
    pub(super) fn on_sys7_lsm_record(
        &mut self,
        tool: IndividualAddress,
        record: &[u8],
    ) -> Result<DeviceReaction, DeviceError> {
        let (lsm_index, event_record) =
            sys7_lsm::decode_memory_lsm_record(record).map_err(|e| DeviceError::Malformed {
                service: "System7 LSM record".into(),
                detail: e.to_string(),
            })?;
        self.apply_sys7_event(tool, lsm_index, &event_record)?;
        // A memory-mapped LSM write is unconfirmed at the application layer (the
        // tool polls the status address); no APDU response.
        Ok(DeviceReaction::default())
    }
}
