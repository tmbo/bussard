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

#[cfg(test)]
mod tests {
    use crate::bus::event::RecordingSink;
    use crate::device::profile::LsmAccess;
    use crate::device::test_support::*;
    use crate::device::*;
    use crate::prod::read_knxprod_bytes;
    use crate::wire::GroupAddress;

    #[test]
    fn test_load_flow_reaches_loaded() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        // StartLoading obj4
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
        assert_eq!(dev.load_state(4), Some(LoadState::Loading));
        // Allocate 256
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?;
        assert_eq!(
            dev.memory().segment_of(4).map(|s| (s.base, s.len)),
            Some((0x6000, 256))
        );
        // Memory write at base 0x6000
        dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?;
        // LoadCompleted
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?;
        assert_eq!(dev.load_state(4), Some(LoadState::Loaded));
        Ok(())
    }

    #[test]
    fn test_load_state_read_reflects_live_lsm_state() -> Result<(), Box<dyn std::error::Error>> {
        // A wire read of PID_LOAD_STATE_CONTROL must return the LIVE load state
        // (1 octet), tracking the LSM as it transitions — not a value seeded at
        // construction. A tool verifies StartLoading/LoadCompleted by reading
        // PID 5 back, so a stale answer would stall it. Start Unloaded to make
        // the transitions observable.
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            return Ok(());
        };
        let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
        let mut dev = Device::from_product(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Unloaded,
            std::sync::Arc::new(RecordingSink::new()),
        );
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

        // Reads the single load-state octet from a PID 5 read response.
        let read_state = |dev: &mut Device| -> Result<u8, Box<dyn std::error::Error>> {
            let r = dev.handle_cemi(&data(dev, 0x3D5, &[0x04, 0x05, 0x10, 0x01]))?;
            // TPDU: [tpci][d6][obj][pid][count|start_hi][start_lo][state].
            let state = *r.responses[0]
                .tpdu
                .last()
                .ok_or("empty load-state response")?;
            Ok(state)
        };

        assert_eq!(read_state(&mut dev)?, LoadState::Unloaded.to_byte());
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?; // StartLoading
        assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?; // Alloc 256
        assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
        dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?; // mem write
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?; // LoadCompleted
        assert_eq!(read_state(&mut dev)?, LoadState::Loaded.to_byte());
        Ok(())
    }

    // --- Table-only reload (spec §3/§4, §7) ------------------------------
    //
    // A tool that only changes group links rewrites the two *table* LSMs and
    // leaves the parameter LSM (3) and the application image alone. From the
    // device's side that is an ordinary load sequence restricted to LSM 1 and
    // LSM 2, issued against a device that is already `Loaded`: Unload,
    // StartLoading, allocate, stream, TaskSegment, LoadCompleted. The device
    // must accept it in both LSM realisations and come back on the *new*
    // tables it just parsed out of its own memory.

    /// Send one 10-octet load event to `lsm` in the device's realisation:
    /// `Property` writes PID 5 on the object, `MemoryMapped` writes the
    /// 11-octet record to the control address (spec §5).
    fn send_event(
        dev: &mut Device,
        access: LsmAccess,
        lsm: u8,
        event: [u8; 10],
    ) -> Result<(), DeviceError> {
        match access {
            LsmAccess::Property => {
                let mut payload = vec![lsm, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
                payload.extend_from_slice(&event);
                dev.handle_cemi(&data(dev, 0x3D7, &payload))?;
            }
            LsmAccess::MemoryMapped => {
                let mut record = [0u8; 11];
                record[0] = (lsm << 4) | (event[0] & 0x0F);
                record[1] = event[1];
                record[3..11].copy_from_slice(&event[2..10]);
                let frame = mem_write_frame(dev, 0x0104, &record);
                dev.handle_cemi(&frame)?;
            }
        }
        Ok(())
    }

    /// A 10-octet event carrying only its opcode (spec §4.1).
    fn simple(opcode: u8) -> [u8; 10] {
        let mut v = [0u8; 10];
        v[0] = opcode;
        v
    }

    /// An `AdditionalLoadControls` absolute-Data-segment allocation record
    /// (spec §4.2): `[03][00][start:2][length:2][…]`.
    fn alloc(start: u16, length: u16) -> [u8; 10] {
        let mut v = [0u8; 10];
        v[0] = 0x03;
        v[1] = 0x00;
        v[2..4].copy_from_slice(&start.to_be_bytes());
        v[4..6].copy_from_slice(&length.to_be_bytes());
        v[7] = 0x03; // EEPROM
        v
    }

    /// An `AdditionalLoadControls` task-segment finalize record (spec §4.3).
    fn task(address: u16) -> [u8; 10] {
        let mut v = [0u8; 10];
        v[0] = 0x03;
        v[1] = 0x02;
        v[2..4].copy_from_slice(&address.to_be_bytes());
        v
    }

    /// Write a whole table region in 12-octet chunks (the System 7
    /// standard-frame cap, spec §6).
    fn stream(dev: &mut Device, base: u16, image: &[u8]) -> Result<(), DeviceError> {
        for (i, piece) in image.chunks(12).enumerate() {
            let at = base + (i * 12) as u16;
            let frame = mem_write_frame(dev, at, piece);
            dev.handle_cemi(&frame)?;
        }
        Ok(())
    }

    /// Load the two table LSMs with the given region images, the way both a
    /// full download and a table-only reload do it (spec §3): open both,
    /// allocate, stream, finalize, complete.
    fn load_tables(
        dev: &mut Device,
        access: LsmAccess,
        lsm1: &[u8],
        lsm2: &[u8],
    ) -> Result<(), DeviceError> {
        send_event(dev, access, 2, simple(0x04))?; // Unload LSM 2
        send_event(dev, access, 1, simple(0x04))?; // Unload LSM 1
        send_event(dev, access, 2, simple(0x01))?; // StartLoading LSM 2
        send_event(dev, access, 1, simple(0x01))?; // StartLoading LSM 1
        send_event(dev, access, 1, alloc(0x4000, lsm1.len() as u16))?;
        stream(dev, 0x4000, lsm1)?;
        send_event(dev, access, 2, alloc(0x4201, lsm2.len() as u16))?;
        stream(dev, 0x4201, lsm2)?;
        send_event(dev, access, 1, task(0x4000))?;
        send_event(dev, access, 1, simple(0x02))?; // LoadCompleted LSM 1
        send_event(dev, access, 2, task(0x4201))?;
        send_event(dev, access, 2, simple(0x02))?; // LoadCompleted LSM 2
        Ok(())
    }

    /// The LSM 1 region image: the address table (spec §7.1) followed by the
    /// group-object descriptor table (spec §7.3, co-located in the 0x4000
    /// region per §2.3).
    fn lsm1_region(own_ia: u16, gas: &[u16]) -> Vec<u8> {
        let mut img = vec![(1 + gas.len()) as u8];
        img.extend_from_slice(&own_ia.to_be_bytes());
        for ga in gas {
            img.extend_from_slice(&ga.to_be_bytes());
        }
        // One com-object (ASAP 0): data-ptr 0x0700, CONFIG C|W, TYPE 1 bit.
        img.extend_from_slice(&[0x01, 0x07, 0x00]);
        img.extend_from_slice(&[0x07, 0x00, 0x94, 0x00]);
        img
    }

    /// The LSM 2 region image: the association table (spec §7.2), linking
    /// every TSAP to com-object 0.
    fn lsm2_region(count: u8) -> Vec<u8> {
        let mut img = vec![count];
        for tsap in 1..=count {
            img.push(tsap);
            img.push(0); // ASAP 0
        }
        img
    }

    fn table_only_reload(access: LsmAccess) -> Result<(), Box<dyn std::error::Error>> {
        let mut dev = sys7_device(access);
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

        // First download: one GA, 1/0/1 (0x0801), on com-object 0.
        load_tables(
            &mut dev,
            access,
            &lsm1_region(0x1105, &[0x0801]),
            &lsm2_region(1),
        )?;
        assert_eq!(dev.load_state(1), Some(LoadState::Loaded));
        assert_eq!(dev.load_state(2), Some(LoadState::Loaded));
        let gc = dev.group_comm().expect("the device routes after the load");
        assert_eq!(
            gc.object(0).expect("com-object 0").gas,
            vec![GroupAddress(0x0801)]
        );
        assert!(gc.object(0).expect("com-object 0").is_writable());

        // The parameter LSM was never opened and must stay exactly as it was:
        // that is the whole point of a table-only reload.
        let lsm3_before = dev.load_state(3);

        // Table-only reload: two GAs now, 1/0/1 and 1/0/2. The address table
        // grows by two octets, so the group-object descriptor table moves with
        // it — the device must re-parse both from their new offsets.
        load_tables(
            &mut dev,
            access,
            &lsm1_region(0x1105, &[0x0801, 0x0802]),
            &lsm2_region(2),
        )?;
        assert_eq!(dev.load_state(1), Some(LoadState::Loaded));
        assert_eq!(dev.load_state(2), Some(LoadState::Loaded));
        assert_eq!(
            dev.load_state(3),
            lsm3_before,
            "a table-only reload must not touch the parameter LSM"
        );
        let gc = dev
            .group_comm()
            .expect("the device routes again after the reload");
        assert_eq!(
            gc.object(0).expect("com-object 0").gas,
            vec![GroupAddress(0x0801), GroupAddress(0x0802)],
            "the reloaded tables are re-parsed, not the old ones"
        );

        // And a shrink: back to a single GA. The descriptor table moves down
        // again and the dropped GA stops routing.
        load_tables(
            &mut dev,
            access,
            &lsm1_region(0x1105, &[0x0802]),
            &lsm2_region(1),
        )?;
        let gc = dev.group_comm().expect("still routing after the shrink");
        assert_eq!(
            gc.object(0).expect("com-object 0").gas,
            vec![GroupAddress(0x0802)]
        );
        assert!(
            gc.on_group_read(GroupAddress(0x0801)).is_none(),
            "the removed GA no longer routes"
        );
        Ok(())
    }

    #[test]
    fn test_sys7_table_only_reload_property_lsm() -> Result<(), Box<dyn std::error::Error>> {
        table_only_reload(LsmAccess::Property)
    }

    #[test]
    fn test_sys7_table_only_reload_memory_mapped_lsm() -> Result<(), Box<dyn std::error::Error>> {
        table_only_reload(LsmAccess::MemoryMapped)
    }

    #[test]
    fn test_sys7_goes_silent_while_its_tables_are_being_rewritten()
    -> Result<(), Box<dyn std::error::Error>> {
        // A table LSM that leaves `Loaded` takes the device off the group side
        // until the reload completes (spec §4.1: a table is active only in
        // `Loaded`). Without that, a device would keep routing on tables that
        // are mid-rewrite.
        let access = LsmAccess::Property;
        let mut dev = sys7_device(access);
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        load_tables(
            &mut dev,
            access,
            &lsm1_region(0x1105, &[0x0801]),
            &lsm2_region(1),
        )?;
        assert!(dev.group_comm().is_some());

        send_event(&mut dev, access, 1, simple(0x04))?; // Unload LSM 1
        assert!(
            dev.group_comm().is_none(),
            "an unloaded address table silences the device"
        );
        Ok(())
    }
}
