//! The System 2 (BCU 2, masks 0020 / 0021 / 0025) device behaviour (bussard
//! issue #525).
//!
//! A BCU 2 drives its three load-state machines (address table, association
//! table, application program; objects 1 to 3) through `PID_LOAD_STATE_CONTROL`
//! (Realisation Type 1, KNX 6 Profiles §4.2 row 7) with the 10-octet records
//! of KNX 3/5/2 §3.31.3. The records are the System 7 ones, so the device
//! reuses the System 7 LSM machinery ([`super::Sys7LoadStateMachine`]) and adds
//! what a BCU 2 does differently, all here:
//!
//! - an absolute allocation (`03 00`) must lie in one memory region of its
//!   memory type and may not overlap another LSM's segment, else the LSM goes
//!   to Error (the device's memory map, KNX 9/4/1 §5.1.2.12, plus the ranges
//!   the product's own procedure allocates);
//! - the stack allocation (`03 01`) is refused (not required on BCU 2,
//!   Profiles Annex A.2.4.1 Table 7);
//! - the Segment Control Record (`03 02`) allocates nothing: on the
//!   application LSM it sets the application id (0103h, object 3 PID 13) and
//!   the required PEI type (0109h, object 3 PID 16); on the association table
//!   LSM it sets the table pointer (object 2 PID 7, 0111h);
//! - the task records (`03 03` to `03 05`) are refused outside the
//!   application LSM (3/5/2 §3.31.1 table); Task Control Record 2 sets the
//!   group object table pointer (object 3 PID 7, 0112h); the application
//!   interface objects Task Control Record 1 announces are accepted but not
//!   served;
//! - memory writes are checked against the segment's access attributes, the
//!   product manufacturer at 0101h is never overwritten on 0020/0021 (9/4/1
//!   §5.1.2.12.5.1), and RunError (010Dh) and the system status (0060h) are
//!   writable outside a segment, as the mask resources say.
//!
//! What is not modelled is listed in `knx-sim/DESIGN.md` ("System 2").

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::Apdu;

use super::interface_object::{PID_PROGRAM_VERSION, PID_TABLE_REFERENCE};
use super::{Device, DeviceError, DeviceReaction, LoadState, Property};

/// The system status byte: bit 0 is the programming mode (KNX 9/4/1 Figure
/// 18; the mask's `ProgrammingMode` resource, `ProgrammingMode_Bcu1`).
pub const SYSTEM_STATUS: u16 = 0x0060;
/// The product manufacturer, `PID_MANUFACTURER_ID` of the device object
/// (9/4/1 §5.1.2.12.5.1). Never overwritten by a download.
pub const MANUFACTURER: u16 = 0x0101;
/// The application id (manufacturer, type, version), set by the application
/// LSM's Segment Control Record.
pub const APPLICATION_ID: u16 = 0x0103;
/// The required PEI type, set by the application LSM's Segment Control Record.
pub const PEI_TYPE: u16 = 0x0109;
/// The run-time error flags (low active; FFh = no error).
pub const RUN_ERROR: u16 = 0x010D;
/// The association table pointer (one octet, offset from 0100h).
pub const ASSOC_TAB_PTR: u16 = 0x0111;
/// The group object table pointer (one octet, offset from 0100h).
pub const COMMS_TAB_PTR: u16 = 0x0112;
/// The group address table, Realisation Type 2 (KNX 3/5/1 §4.16.4): the
/// length octet, the own individual address, then the group addresses.
pub const ADDRESS_TABLE: u16 = 0x0116;
/// The application object, which carries the program LSM, run control and
/// the group object table reference.
pub const APP_OBJECT: u8 = 3;
/// `PID_RUN_STATE_CONTROL`.
pub const PID_RUN_STATE_CONTROL: u8 = 6;
/// `PID_PEI_TYPE`.
pub const PID_PEI_TYPE: u8 = 16;

/// A memory range the device can allocate from, with its memory type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// The first address.
    pub start: u16,
    /// The last address (inclusive).
    pub end: u16,
    /// The memory type (1 zero page RAM, 2 RAM, 3 EEPROM).
    pub mem_type: u8,
}

/// The fixed BCU 2 memory map an allocation may use (KNX 9/4/1 §5.1.2.12):
/// the user part of page 0 RAM (00BDh to 00DFh, Profiles §4.2.9), RAM 2
/// from UserRAM2 to the end of the PEI buffers (0972h to 09BBh, available to
/// the application when its PEI type does not use them, §5.1.2.12.4), and
/// the EEPROM from the system table to the end of user EEPROM (0100h to
/// 046Fh, the mask's `MemorySegment` of 880 octets).
pub const STANDARD_REGIONS: [Region; 3] = [
    Region {
        start: 0x00BD,
        end: 0x00DF,
        mem_type: 1,
    },
    Region {
        start: 0x0972,
        end: 0x09BB,
        mem_type: 2,
    },
    Region {
        start: 0x0100,
        end: 0x046F,
        mem_type: 3,
    },
];

/// One absolute segment an LSM allocated, with its access attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Allocation {
    lsm: u8,
    start: u16,
    len: u16,
    access: u8,
}

/// The BCU 2 runtime state beside the shared LSM machinery.
#[derive(Debug, Clone)]
pub(super) struct Bcu2Runtime {
    /// The memory the device can allocate from.
    regions: Vec<Region>,
    /// The four authorization keys, level 0 first (9/4/1 §5.1.2.14; all
    /// FFFFFFFFh on a fresh device, §5.1.2.6.1).
    keys: [u32; 4],
    /// The segments allocated so far.
    allocations: Vec<Allocation>,
    /// The PEI type physically connected (object 0 PID 16).
    pei_actual: u8,
}

impl Bcu2Runtime {
    /// The runtime of a fresh device: the standard regions plus every range
    /// the product's own procedure allocates (a device of that hardware has
    /// memory there: the Busch-Jaeger 0021 programs `M-00B1_A-006x` allocate
    /// EEPROM up to 07A4h, the 0025 programs above 1C00h).
    pub(super) fn new(product: &crate::prod::ProductData) -> Self {
        let mut regions = STANDARD_REGIONS.to_vec();
        for step in &product.abs_segment_steps {
            if step.size == 0 {
                continue;
            }
            let end = step.address.saturating_add(step.size - 1);
            let inside = regions
                .iter()
                .any(|r| r.mem_type == step.mem_type && r.start <= step.address && end <= r.end);
            if !inside {
                regions.push(Region {
                    start: step.address,
                    end,
                    mem_type: step.mem_type,
                });
            }
        }
        Self {
            regions,
            keys: [crate::device::FREE_ACCESS_KEY; 4],
            allocations: Vec::new(),
            pei_actual: product.pei_type.unwrap_or(0),
        }
    }

    /// The access level an `A_Authorize` key grants: the lowest level whose
    /// key matches, else level 3, free access (9/4/1 §5.1.2.14).
    pub(super) fn level_for_key(&self, key: u32) -> u8 {
        self.keys
            .iter()
            .position(|k| *k == key)
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(3)
    }

    /// Why an allocation of `[start, start + len)` of `mem_type` by `lsm` is
    /// refused, or `None` when it fits.
    fn allocation_refusal(&self, lsm: u8, start: u16, len: u16, mem_type: u8) -> Option<String> {
        if len == 0 {
            return Some("zero-length allocation".into());
        }
        let Some(end) = start.checked_add(len - 1) else {
            return Some(format!("allocation at {start:04X}h of {len} octets wraps"));
        };
        if !self
            .regions
            .iter()
            .any(|r| r.mem_type == mem_type && r.start <= start && end <= r.end)
        {
            return Some(format!(
                "allocation {start:04X}h..{end:04X}h of memory type {mem_type} is not in the \
                 device's memory map"
            ));
        }
        if let Some(other) = self
            .allocations
            .iter()
            .find(|a| a.lsm != lsm && start <= a.start.saturating_add(a.len - 1) && a.start <= end)
        {
            return Some(format!(
                "allocation {start:04X}h..{end:04X}h overlaps the segment of LSM {} at {:04X}h",
                other.lsm, other.start
            ));
        }
        None
    }

    /// The allocation that holds every octet of `[addr, addr + n)`.
    fn allocation_at(&self, addr: u16, n: usize) -> Option<&Allocation> {
        let end = u32::from(addr) + n as u32;
        self.allocations.iter().find(|a| {
            u32::from(a.start) <= u32::from(addr) && end <= u32::from(a.start) + u32::from(a.len)
        })
    }
}

impl Device {
    /// Whether this is a BCU 2 device.
    pub(super) fn is_bcu2(&self) -> bool {
        self.bcu2.is_some()
    }

    /// The level a BCU 2 grants for `key`, `None` on any other device.
    pub(super) fn bcu2_authorize_level(&self, key: u32) -> Option<u8> {
        self.bcu2.as_ref().map(|b| b.level_for_key(key))
    }

    /// The access level a BCU 2 requires to write `pid` of `object`: level 1
    /// for the table LSMs, level 0 for everything else (9/4/1 §5.1.2.14).
    pub(super) fn bcu2_property_write_level(&self, object: u8, pid: u8) -> u8 {
        if pid == super::PID_LOAD_STATE_CONTROL && (object == 1 || object == 2) {
            1
        } else {
            0
        }
    }

    /// The run state of the application (object 3 PID 6): Running (1) when
    /// the three LSMs are Loaded, RunError reports no error and the required
    /// PEI type equals the connected one (9/4/1 §5.1.2.6.3), else Halted (0).
    pub(super) fn bcu2_run_state(&self) -> Option<u8> {
        let b = self.bcu2.as_ref()?;
        let loaded = (1..=3).all(|i| self.load_state(i) == Some(LoadState::Loaded));
        let run_error = self.memory.read(u32::from(RUN_ERROR), 1);
        let pei = self.memory.read(u32::from(PEI_TYPE), 1);
        let running = loaded && run_error == [0xFF] && pei == [b.pei_actual];
        Some(u8::from(running))
    }

    /// The BCU 2 side of an `AdditionalLoadControls` record the LSM accepted
    /// while Loading (see the module doc). `record` is the 10-octet PID 5
    /// value. Returns the refusal that puts the LSM into Error.
    pub(super) fn bcu2_load_control(&mut self, lsm: u8, record: &[u8]) -> Result<(), String> {
        let (Some(&kind), Some(&sub)) = (record.first(), record.get(1)) else {
            return Ok(());
        };
        if kind != 0x03 {
            return Ok(());
        }
        let word = |i: usize| -> u16 {
            u16::from_be_bytes([
                record.get(i).copied().unwrap_or(0),
                record.get(i + 1).copied().unwrap_or(0),
            ])
        };
        let Some(bcu2) = self.bcu2.as_mut() else {
            return Ok(());
        };
        match sub {
            0x00 => {
                let (start, len) = (word(2), word(4));
                let access = record.get(6).copied().unwrap_or(0);
                let mem_type = record.get(7).copied().unwrap_or(0) & 0x07;
                if let Some(why) = bcu2.allocation_refusal(lsm, start, len, mem_type) {
                    return Err(why);
                }
                bcu2.allocations
                    .retain(|a| !(a.lsm == lsm && a.start == start));
                bcu2.allocations.push(Allocation {
                    lsm,
                    start,
                    len,
                    access,
                });
                self.memory
                    .allocate_additional(lsm, u32::from(start), u32::from(len));
            }
            0x01 => {
                return Err("absolute stack allocation is not supported on BCU 2 \
                            (Profiles Annex A.2.4.1 Table 7)"
                    .into());
            }
            0x02 => {
                let address = word(2);
                let pei = record.get(4).copied().unwrap_or(0);
                let id = record.get(5..10).unwrap_or(&[]).to_vec();
                match lsm {
                    APP_OBJECT => {
                        self.memory.seed(u32::from(APPLICATION_ID), &id);
                        self.memory.seed(u32::from(PEI_TYPE), &[pei]);
                        self.set_bcu2_property(APP_OBJECT, PID_PROGRAM_VERSION, id);
                        self.set_bcu2_property(APP_OBJECT, PID_PEI_TYPE, vec![pei]);
                    }
                    2 => {
                        self.set_bcu2_pointer(2, address, Some(ASSOC_TAB_PTR));
                    }
                    // The address table of 0020/0021 sits at 0116h whatever
                    // the record says (3/5/1 §4.16.4); mask 0025 reports it
                    // only through PID 7, so the record sets it.
                    1 if self.profile.mask() == 0x0025 => {
                        self.set_bcu2_pointer(1, address, None);
                    }
                    _ => {}
                }
            }
            0x03..=0x05 if lsm != APP_OBJECT => {
                return Err(format!(
                    "task record 03 {sub:02X} on LSM {lsm}: only the application program \
                     takes TaskPtr, TaskCtrl1 and TaskCtrl2 (KNX 3/5/2 §3.31.1)"
                ));
            }
            0x05 => {
                self.set_bcu2_pointer(APP_OBJECT, word(4), Some(COMMS_TAB_PTR));
            }
            _ => {}
        }
        Ok(())
    }

    /// Sets a 2-octet `PID_TABLE_REFERENCE` and, when the address fits the
    /// one-octet pointer of 0020/0021 (offset from 0100h), the pointer octet.
    fn set_bcu2_pointer(&mut self, object: u8, address: u16, octet: Option<u16>) {
        self.set_bcu2_property(object, PID_TABLE_REFERENCE, address.to_be_bytes().to_vec());
        if let Some(at) = octet
            && self.profile.mask() != 0x0025
            && (0x0100..=0x01FF).contains(&address)
        {
            self.memory.seed(u32::from(at), &[(address - 0x0100) as u8]);
        }
    }

    fn set_bcu2_property(&mut self, object: u8, pid: u8, value: Vec<u8>) {
        if let Some(obj) = self.objects.get_mut(&object) {
            obj.set_property(pid, Property::read_only(value));
        }
    }

    /// The octets a memory read at `addr` answers on a BCU 2, where it differs
    /// from plain memory: the system status with the programming mode.
    pub(super) fn bcu2_memory_read(&self, addr: u16, n: usize) -> Option<Vec<u8>> {
        self.bcu2.as_ref()?;
        let mut bytes = self.memory.read(u32::from(addr), n);
        if let Some(i) = SYSTEM_STATUS.checked_sub(addr).map(usize::from)
            && let Some(b) = bytes.get_mut(i)
        {
            *b = (*b & !0x01) | u8::from(self.prog_mode);
        }
        Some(bytes)
    }

    /// An `A_Memory_Write` to a BCU 2 (see the module doc).
    pub(super) fn on_bcu2_memory_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let n = apdu.memory_count() as usize;
        if apdu.data.len() < 2 + n {
            return Err(DeviceError::Malformed {
                service: "A_MemoryWrite".into(),
                detail: "payload shorter than declared count".into(),
            });
        }
        let addr = u16::from_be_bytes([apdu.data[0], apdu.data[1]]);
        let payload = apdu.data[2..2 + n].to_vec();
        let end = u32::from(addr) + n as u32;
        let covers = |a: u16| u32::from(addr) <= u32::from(a) && u32::from(a) < end;
        // On 0020/0021 the mask places the manufacturer at 0101h (resource
        // `DeviceManufacturerId`, local access); mask 0025 keeps it in the
        // device object only and its programs write the whole system table.
        if self.profile.mask() != 0x0025 && (covers(MANUFACTURER) || covers(MANUFACTURER + 1)) {
            return Err(DeviceError::LoadControl(format!(
                "memory write at {addr:04X}h of {n} octet(s) covers the product manufacturer at \
                 0101h, which a download never overwrites (KNX 9/4/1 §5.1.2.12.5.1)"
            )));
        }
        let bcu2 = self.bcu2.as_ref().ok_or(DeviceError::NotConnected)?;
        if (addr == RUN_ERROR || addr == SYSTEM_STATUS) && n == 1 {
            // The `RunError` and `ProgrammingMode` resources (Write =
            // Configuration) live outside every segment.
            if addr == SYSTEM_STATUS {
                self.set_prog_mode(payload[0] & 0x01 != 0);
            }
            self.memory.seed(u32::from(addr), &payload);
        } else {
            let alloc =
                bcu2.allocation_at(addr, n)
                    .copied()
                    .ok_or(super::MemoryError::OutOfSegment {
                        addr: u32::from(addr),
                        len: n,
                    })?;
            if self.access_level > alloc.access & 0x0F {
                return Err(DeviceError::Unauthorized {
                    level: self.access_level,
                });
            }
            if self.load_state(alloc.lsm) != Some(LoadState::Loading) {
                return Err(DeviceError::LoadControl(format!(
                    "memory write to LSM {} while not Loading",
                    alloc.lsm
                )));
            }
            self.memory.write(alloc.lsm, u32::from(addr), &payload)?;
        }
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr: u32::from(addr),
            len: n,
        });
        if self.verify_mode() {
            let mut data = Vec::with_capacity(2 + n);
            data.extend_from_slice(&addr.to_be_bytes());
            data.extend_from_slice(&self.memory.read(u32::from(addr), n));
            let resp = self.respond(tool, 0x240 | (n as u16 & 0x3F), &data);
            return Ok(DeviceReaction {
                responses: vec![resp],
                did_master_reset: false,
            });
        }
        Ok(DeviceReaction::default())
    }

    /// Keeps the individual address in the address table's second and third
    /// octet (0117h, the mask's `IndividualAddress` resource).
    pub(super) fn bcu2_sync_address(&mut self) {
        if self.bcu2.is_some() {
            let ia = self.address.0.to_be_bytes();
            self.memory.seed(u32::from(ADDRESS_TABLE) + 1, &ia);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::event::RecordingSink;
    use crate::device::test_support::{connect, data, mem_write_frame, prop_response_value};
    use crate::device::{PID_LOAD_STATE_CONTROL, ProfileOverrides};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn device() -> Result<Device, String> {
        Device::from_product_with_overrides(
            IndividualAddress::new(1, 1, 7),
            &crate::testfixtures::synthetic_bcu2_product(),
            LoadState::Unloaded,
            ProfileOverrides::default(),
            std::sync::Arc::new(RecordingSink::new()),
        )
    }

    fn authorized() -> Result<Device, Box<dyn std::error::Error>> {
        let mut dev = device()?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        Ok(dev)
    }

    fn pid5(dev: &mut Device, object: u8, record: [u8; 10]) -> Result<u8, DeviceError> {
        let mut payload = vec![object, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
        payload.extend_from_slice(&record);
        let reaction = dev.handle_cemi(&data(dev, 0x3D7, &payload))?;
        Ok(prop_response_value(&reaction)
            .first()
            .copied()
            .unwrap_or(0xFF))
    }

    fn event(code: u8) -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = code;
        r
    }

    fn alloc(start: u16, len: u16, access: u8, mem_type: u8) -> [u8; 10] {
        let [s0, s1] = start.to_be_bytes();
        let [l0, l1] = len.to_be_bytes();
        [0x03, 0x00, s0, s1, l0, l1, access, mem_type, 0x00, 0x00]
    }

    fn segment_control(address: u16, pei: u8, id: [u8; 5]) -> [u8; 10] {
        let [a0, a1] = address.to_be_bytes();
        [0x03, 0x02, a0, a1, pei, id[0], id[1], id[2], id[3], id[4]]
    }

    fn read_prop(dev: &mut Device, object: u8, pid: u8) -> Result<Vec<u8>, DeviceError> {
        let reaction = dev.handle_cemi(&data(dev, 0x3D5, &[object, pid, 0x10, 0x01]))?;
        Ok(prop_response_value(&reaction))
    }

    #[test]
    fn test_build_system2_reports_mask_objects_and_system_table() -> TestResult {
        let mut dev = authorized()?;
        assert_eq!(dev.profile().mask(), 0x0021);
        assert!(dev.profile().is_system2());
        for object in 0u8..=3 {
            assert_eq!(read_prop(&mut dev, object, 1)?, vec![0, object]);
        }
        assert!(read_prop(&mut dev, 4, 1)?.is_empty(), "no object 4");
        assert_eq!(read_prop(&mut dev, 0, 12)?, vec![0x00, 0xFA]);
        assert_eq!(read_prop(&mut dev, 1, 7)?, vec![0x01, 0x16]);
        assert_eq!(dev.memory().read(0x0100, 3), vec![0xFF, 0x00, 0xFA]);
        assert_eq!(dev.memory().read(u32::from(RUN_ERROR), 1), vec![0xFF]);
        assert_eq!(dev.memory().read(0x0116, 3), vec![0x01, 0x11, 0x07]);
        assert_eq!(read_prop(&mut dev, 3, PID_RUN_STATE_CONTROL)?, vec![0]);
        Ok(())
    }

    /// A full download in the corpus shape reaches Loaded on the three LSMs,
    /// and the records land in the system table.
    #[test]
    fn test_bcu2_download_reaches_loaded_and_fills_the_system_table() -> TestResult {
        let mut dev = authorized()?;
        for object in 1u8..=3 {
            pid5(&mut dev, object, event(0x04))?;
        }
        assert_eq!(
            pid5(&mut dev, 1, event(0x01))?,
            LoadState::Loading.to_byte()
        );
        pid5(&mut dev, 1, alloc(0x0116, 0x20, 0x32, 3))?;
        dev.handle_cemi(&mem_write_frame(&dev, 0x0119, &[0x08, 0x01]))?;
        pid5(&mut dev, 1, segment_control(0x0116, 0, [0; 5]))?;
        assert_eq!(pid5(&mut dev, 1, event(0x02))?, LoadState::Loaded.to_byte());

        pid5(&mut dev, 2, event(0x01))?;
        pid5(&mut dev, 2, alloc(0x0136, 0x20, 0x32, 3))?;
        pid5(&mut dev, 2, segment_control(0x0136, 0, [0; 5]))?;
        assert_eq!(pid5(&mut dev, 2, event(0x02))?, LoadState::Loaded.to_byte());
        assert_eq!(read_prop(&mut dev, 2, 7)?, vec![0x01, 0x36]);
        assert_eq!(dev.memory().read(u32::from(ASSOC_TAB_PTR), 1), vec![0x36]);

        pid5(&mut dev, 3, event(0x01))?;
        pid5(&mut dev, 3, alloc(0x00C8, 0x18, 0x32, 1))?;
        pid5(&mut dev, 3, alloc(0x0100, 0x16, 0x32, 3))?;
        pid5(&mut dev, 3, alloc(0x0156, 0x40, 0x32, 3))?;
        dev.handle_cemi(&mem_write_frame(&dev, 0x010A, &[0xFF, 0x00, 0x12]))?;
        pid5(
            &mut dev,
            3,
            segment_control(0x0160, 0, [0x00, 0xFA, 0x2A, 0x01, 0x10]),
        )?;
        pid5(
            &mut dev,
            3,
            [0x03, 0x05, 0x50, 0x81, 0x01, 0x56, 0x00, 0xC8, 0x00, 0xC8],
        )?;
        assert_eq!(pid5(&mut dev, 3, event(0x02))?, LoadState::Loaded.to_byte());

        assert_eq!(
            dev.memory().read(u32::from(APPLICATION_ID), 7),
            vec![0x00, 0xFA, 0x2A, 0x01, 0x10, 0x00, 0x00]
        );
        assert_eq!(
            read_prop(&mut dev, 3, 13)?,
            vec![0x00, 0xFA, 0x2A, 0x01, 0x10]
        );
        assert_eq!(read_prop(&mut dev, 3, 7)?, vec![0x01, 0x56]);
        assert_eq!(dev.memory().read(u32::from(COMMS_TAB_PTR), 1), vec![0x56]);
        assert_eq!(dev.memory().read(0x0119, 2), vec![0x08, 0x01]);
        assert_eq!(read_prop(&mut dev, 3, PID_RUN_STATE_CONTROL)?, vec![1]);
        Ok(())
    }

    #[test]
    fn test_bcu2_allocation_outside_the_memory_map_is_error() -> TestResult {
        let mut dev = authorized()?;
        pid5(&mut dev, 3, event(0x01))?;
        assert!(pid5(&mut dev, 3, alloc(0x4000, 0x10, 0x32, 3)).is_err());
        assert_eq!(dev.load_state(3), Some(LoadState::Error));
        // Only an Unload leaves Error.
        assert_eq!(
            pid5(&mut dev, 3, event(0x04))?,
            LoadState::Unloaded.to_byte()
        );
        Ok(())
    }

    #[test]
    fn test_bcu2_refuses_stack_allocation_and_task_records_on_tables() -> TestResult {
        let mut dev = authorized()?;
        pid5(&mut dev, 3, event(0x01))?;
        assert!(
            pid5(
                &mut dev,
                3,
                [0x03, 0x01, 0x00, 0xE0, 0x00, 0x10, 0, 1, 0, 0]
            )
            .is_err()
        );
        pid5(&mut dev, 1, event(0x01))?;
        assert!(
            pid5(
                &mut dev,
                1,
                [0x03, 0x03, 0x01, 0x1C, 0x01, 0x1D, 0, 0, 0, 0]
            )
            .is_err()
        );
        assert_eq!(dev.load_state(1), Some(LoadState::Error));
        // Relative allocation (03 0B) is not a BCU 2 load control.
        pid5(&mut dev, 2, event(0x01))?;
        assert!(pid5(&mut dev, 2, [0x03, 0x0B, 0, 0, 0, 0x20, 0, 0, 0, 0]).is_err());
        Ok(())
    }

    #[test]
    fn test_bcu2_memory_write_rules() -> TestResult {
        let mut dev = authorized()?;
        pid5(&mut dev, 3, event(0x01))?;
        pid5(&mut dev, 3, alloc(0x0100, 0x16, 0x32, 3))?;
        // Outside every segment.
        assert!(
            dev.handle_cemi(&mem_write_frame(&dev, 0x0200, &[1]))
                .is_err()
        );
        assert_eq!(dev.memory().read(0x0200, 1), vec![0], "refused, not stored");
        // The product manufacturer is never overwritten.
        let over = mem_write_frame(&dev, 0x0100, &[0xFF, 0x12, 0x34]);
        assert!(dev.handle_cemi(&over).is_err());
        assert_eq!(dev.memory().read(0x0101, 2), vec![0x00, 0xFA]);
        // RunError and the system status take writes outside a segment.
        dev.handle_cemi(&mem_write_frame(&dev, RUN_ERROR, &[0x00]))?;
        assert_eq!(dev.memory().read(u32::from(RUN_ERROR), 1), vec![0x00]);
        dev.handle_cemi(&mem_write_frame(&dev, SYSTEM_STATUS, &[0x01]))?;
        assert!(dev.prog_mode());
        Ok(())
    }

    #[test]
    fn test_bcu2_segment_write_level_comes_from_the_access_attributes() -> TestResult {
        let mut dev = device()?;
        connect(&mut dev)?;
        // A wrong key grants level 3, free access.
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0x12, 0x34, 0x56, 0x78]))?;
        assert_eq!(dev.access_level, 3);
        // Level 3 may not drive an LSM.
        assert!(pid5(&mut dev, 3, event(0x01)).is_err());
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        pid5(&mut dev, 3, event(0x01))?;
        pid5(&mut dev, 3, alloc(0x0156, 0x10, 0x30, 3))?; // write level 0
        pid5(&mut dev, 3, alloc(0x0166, 0x10, 0x33, 3))?; // write level 3
        dev.access_level = 3;
        assert!(
            dev.handle_cemi(&mem_write_frame(&dev, 0x0156, &[1]))
                .is_err()
        );
        dev.handle_cemi(&mem_write_frame(&dev, 0x0166, &[1]))?;
        assert_eq!(dev.memory().read(0x0156, 1), vec![0]);
        assert_eq!(dev.memory().read(0x0166, 1), vec![1]);
        Ok(())
    }

    fn runtime() -> Bcu2Runtime {
        let mut product = crate::testfixtures::synthetic_bcu2_product();
        product.abs_segment_steps.clear();
        Bcu2Runtime::new(&product)
    }

    #[test]
    fn test_level_for_key_fresh_device_grants_level_0() {
        let rt = runtime();
        assert_eq!(rt.level_for_key(0xFFFF_FFFF), 0);
        assert_eq!(rt.level_for_key(0x1234_5678), 3);
    }

    #[test]
    fn test_allocation_refusal_checks_region_type_and_overlap() {
        let mut rt = runtime();
        assert_eq!(rt.allocation_refusal(1, 0x0116, 102, 3), None);
        assert_eq!(rt.allocation_refusal(3, 0x00BD, 35, 1), None);
        assert!(
            rt.allocation_refusal(3, 0x00BD, 35, 3).is_some(),
            "wrong memory type"
        );
        assert!(
            rt.allocation_refusal(3, 0x0400, 0x100, 3).is_some(),
            "past 046Fh"
        );
        assert!(
            rt.allocation_refusal(3, 0x0200, 0, 3).is_some(),
            "zero length"
        );
        rt.allocations.push(Allocation {
            lsm: 1,
            start: 0x0116,
            len: 102,
            access: 0x32,
        });
        assert!(
            rt.allocation_refusal(2, 0x017B, 4, 3).is_some(),
            "overlaps LSM 1"
        );
        assert_eq!(rt.allocation_refusal(2, 0x017C, 4, 3), None);
        assert_eq!(rt.allocation_refusal(1, 0x0116, 10, 3), None, "same LSM");
    }

    #[test]
    fn test_new_adds_the_product_allocations_to_the_memory_map() {
        let mut product = crate::testfixtures::synthetic_bcu2_product();
        product.abs_segment_steps = vec![crate::prod::AbsSegmentStep {
            lsm_index: 3,
            seg_type: 0,
            address: 0x0516,
            size: 0x12F,
            access: 0x32,
            mem_type: 3,
            seg_flags: 0,
        }];
        let rt = Bcu2Runtime::new(&product);
        assert_eq!(rt.allocation_refusal(3, 0x0516, 0x12F, 3), None);
        assert!(rt.allocation_refusal(3, 0x0516, 0x130, 3).is_some());
    }
}
