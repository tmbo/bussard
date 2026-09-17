//! Runtime group communication, driven by the device's own flashed tables.
//!
//! After a successful download a System B device comes alive: it routes group
//! telegrams according to the address table (obj1), association table (obj2) and
//! group-object (com-object) table (obj3) that the tool wrote into its memory.
//! This module reconstructs that routing **by reading those tables back out of
//! the device's memory** — never from any external config — so a wrong table
//! written by the tool becomes visibly wrong bus behaviour. That closes the
//! loop: the same bytes the flash wrote are the bytes that drive traffic.
//!
//! # Table layouts (System B, mask 07B0)
//!
//! Each table lives at a base address the device reports via `PID_TABLE_REFERENCE`
//! and begins with a big-endian `u16` entry count:
//!
//! - **Address table** (obj1): `count`, then `count` group addresses (`u16` BE).
//!   The 1-based index into this table is the **TSAP**; TSAP 1 is the first GA.
//! - **Association table** (obj2): `count`, then `count` 4-octet entries, each
//!   `(TSAP: u16 BE, ASAP: u16 BE)`. The TSAP selects a GA from the address
//!   table; the ASAP is the com-object number.
//! - **Group-object table** (obj3): `count`, then `count` descriptor words
//!   (`u16` BE). Word `asap` (1-based) packs the com-object's flags in its high
//!   bits and a DPT size code in its low byte.
//!
//! These layouts are the mirror of what the tool's table read-back and download
//! engine implement, taken from the published KNX interface-object semantics
//! (KNX 3/5/1 Resources), cross-checked against the ETS→KNX-Virtual capture (the
//! address and association tables in `tests/ets_calibration.rs` begin with the
//! `00 05` count word this parser expects).

use std::collections::BTreeMap;

use crate::device::Memory;
use crate::wire::GroupAddress;

/// The com-object flag bits packed into a group-object descriptor word's high
/// bits (KNX 3/5/1 group-object descriptor; the same bit order the tool writes).
///
/// Only the bits the runtime needs are named. Bit positions match the tool's
/// `group_object_word`: comm(10), read(11), write(12), init(13), transmit(14),
/// update(15).
pub mod flag {
    /// Communication enabled — the object participates in group communication.
    pub const COMMUNICATION: u16 = 1 << 10;
    /// Read enabled — the object answers `A_GroupValue_Read` on its GA.
    pub const READ: u16 = 1 << 11;
    /// Write enabled — the object accepts `A_GroupValue_Write` from the bus.
    pub const WRITE: u16 = 1 << 12;
    /// Transmit enabled — the object may send `A_GroupValue_Write` to the bus.
    pub const TRANSMIT: u16 = 1 << 14;
}

/// One com-object's runtime state, reconstructed from the flashed tables.
#[derive(Debug, Clone)]
pub struct ComObject {
    /// The com-object number (ASAP).
    pub asap: u16,
    /// The flag bits (high bits of the group-object descriptor word).
    pub flags: u16,
    /// The DPT size code (low byte of the descriptor word); informational.
    pub size_code: u8,
    /// The group addresses this object is associated with, in table order. The
    /// first is treated as the object's sending GA if it may transmit.
    pub gas: Vec<GroupAddress>,
    /// The object's current value octets (the last written/seeded group payload,
    /// unpacked). Empty until something sets it.
    pub value: Vec<u8>,
}

impl ComObject {
    /// Whether this object accepts `A_GroupValue_Write` from the bus.
    pub fn is_writable(&self) -> bool {
        self.flags & (flag::COMMUNICATION | flag::WRITE) == (flag::COMMUNICATION | flag::WRITE)
    }

    /// Whether this object answers `A_GroupValue_Read` on its GA.
    pub fn is_readable(&self) -> bool {
        self.flags & (flag::COMMUNICATION | flag::READ) == (flag::COMMUNICATION | flag::READ)
    }

    /// Whether this object may transmit `A_GroupValue_Write` to the bus.
    pub fn is_transmitter(&self) -> bool {
        self.flags & (flag::COMMUNICATION | flag::TRANSMIT)
            == (flag::COMMUNICATION | flag::TRANSMIT)
    }
}

/// A device's reconstructed runtime routing table.
#[derive(Debug, Clone, Default)]
pub struct GroupComm {
    /// Com-objects keyed by ASAP (com-object number).
    objects: BTreeMap<u16, ComObject>,
    /// Reverse index: group address → the ASAPs associated with it.
    by_ga: BTreeMap<u16, Vec<u16>>,
}

/// Read a big-endian `u16` table (count word then entries) out of memory,
/// returning the entry bytes (`count * elem_size`), or `None` if the count word
/// is unreadable.
fn read_counted_table(mem: &Memory, base: u16, elem_size: usize) -> Option<Vec<u8>> {
    let count_bytes = mem.read(base, 2);
    let count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]) as usize;
    if count == 0 {
        return Some(Vec::new());
    }
    let total = count * elem_size;
    Some(mem.read(base.wrapping_add(2), total))
}

impl GroupComm {
    /// Reconstruct the routing from the device's flashed tables in `memory`.
    ///
    /// `addr_base`/`assoc_base`/`comobj_base` are the segment bases the device
    /// reports via `PID_TABLE_REFERENCE` for obj1/obj2/obj3. Reads the count word
    /// of each table, then the entries; builds the com-object map from the
    /// group-object descriptors and wires each association's GA onto its ASAP.
    pub fn from_tables(memory: &Memory, addr_base: u16, assoc_base: u16, comobj_base: u16) -> Self {
        // Address table: count then `count` GAs.
        let addr_bytes = read_counted_table(memory, addr_base, 2).unwrap_or_default();
        let addresses: Vec<GroupAddress> = addr_bytes
            .chunks_exact(2)
            .map(|c| GroupAddress(u16::from_be_bytes([c[0], c[1]])))
            .collect();

        // Group-object table: count then `count` descriptor words.
        let go_bytes = read_counted_table(memory, comobj_base, 2).unwrap_or_default();
        let descriptors: Vec<u16> = go_bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();

        let mut objects: BTreeMap<u16, ComObject> = BTreeMap::new();

        // Association table: count then `count` (TSAP, ASAP) pairs.
        let assoc_bytes = read_counted_table(memory, assoc_base, 4).unwrap_or_default();
        for entry in assoc_bytes.chunks_exact(4) {
            let tsap = u16::from_be_bytes([entry[0], entry[1]]);
            let asap = u16::from_be_bytes([entry[2], entry[3]]);
            // TSAP is a 1-based index into the address table.
            let Some(ga) = tsap
                .checked_sub(1)
                .and_then(|i| addresses.get(usize::from(i)))
                .copied()
            else {
                continue;
            };
            // The descriptor word for this ASAP is at 1-based index `asap`.
            let word = asap
                .checked_sub(1)
                .and_then(|i| descriptors.get(usize::from(i)))
                .copied()
                .unwrap_or(0);
            let obj = objects.entry(asap).or_insert_with(|| ComObject {
                asap,
                flags: word & 0xFC00,
                size_code: (word & 0x00FF) as u8,
                gas: Vec::new(),
                value: Vec::new(),
            });
            if !obj.gas.contains(&ga) {
                obj.gas.push(ga);
            }
        }

        let mut by_ga: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
        for obj in objects.values() {
            for ga in &obj.gas {
                by_ga.entry(ga.raw()).or_default().push(obj.asap);
            }
        }

        GroupComm { objects, by_ga }
    }

    /// Whether any routing was reconstructed (the device is linked).
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// The com-objects, keyed by ASAP.
    pub fn objects(&self) -> &BTreeMap<u16, ComObject> {
        &self.objects
    }

    /// The com-object for an ASAP, if present.
    pub fn object(&self, asap: u16) -> Option<&ComObject> {
        self.objects.get(&asap)
    }

    /// The first (sending) GA of a transmitting com-object, if it has one.
    pub fn send_ga(&self, asap: u16) -> Option<GroupAddress> {
        let obj = self.objects.get(&asap)?;
        if !obj.is_transmitter() {
            return None;
        }
        obj.gas.first().copied()
    }

    /// Apply an incoming `A_GroupValue_Write` for `ga` with `payload`: update
    /// every writable com-object associated with that GA to the new value.
    /// Returns the ASAPs that were updated.
    pub fn on_group_write(&mut self, ga: GroupAddress, payload: &[u8]) -> Vec<u16> {
        let mut updated = Vec::new();
        let asaps = self.by_ga.get(&ga.raw()).cloned().unwrap_or_default();
        for asap in asaps {
            if let Some(obj) = self.objects.get_mut(&asap) {
                if obj.is_writable() {
                    obj.value = payload.to_vec();
                    updated.push(asap);
                }
            }
        }
        updated
    }

    /// Answer an `A_GroupValue_Read` for `ga`: the current value of the first
    /// readable com-object associated with that GA, if any.
    pub fn on_group_read(&self, ga: GroupAddress) -> Option<Vec<u8>> {
        let asaps = self.by_ga.get(&ga.raw())?;
        for asap in asaps {
            if let Some(obj) = self.objects.get(asap) {
                if obj.is_readable() {
                    return Some(obj.value.clone());
                }
            }
        }
        None
    }

    /// Seed a com-object's value directly (used by scripted stimulus before the
    /// value is transmitted). No-op if the ASAP is unknown.
    pub fn set_value(&mut self, asap: u16, payload: &[u8]) {
        if let Some(obj) = self.objects.get_mut(&asap) {
            obj.value = payload.to_vec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Memory;

    /// Build a memory image with the three tables at the DA.tp bases, wiring one
    /// writable object (asap 1) and one readable object (asap 2) to two GAs.
    fn seeded_memory() -> Memory {
        let mut mem = Memory::new();
        // Allocate generous segments so writes land in-bounds.
        mem.allocate(1, 0xA000, 64); // address table
        mem.allocate(2, 0xC000, 64); // association table
        mem.allocate(3, 0x8000, 64); // group-object table

        // Address table: 2 GAs — 1/0/1 (0x0801) and 1/0/2 (0x0802).
        let addr: Vec<u8> = [2u16, 0x0801, 0x0802]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        mem.write(1, 0xA000, &addr).expect("addr write");

        // Association table: TSAP1->ASAP1, TSAP2->ASAP2.
        let assoc: Vec<u8> = [2u16, 1, 1, 2, 2]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        mem.write(2, 0xC000, &assoc).expect("assoc write");

        // Group-object table: asap1 = COMM|WRITE, asap2 = COMM|READ.
        let w1 = flag::COMMUNICATION | flag::WRITE;
        let w2 = flag::COMMUNICATION | flag::READ;
        let go: Vec<u8> = [2u16, w1, w2]
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        mem.write(3, 0x8000, &go).expect("go write");
        mem
    }

    #[test]
    fn test_from_tables_reconstructs_routing() {
        let mem = seeded_memory();
        let gc = GroupComm::from_tables(&mem, 0xA000, 0xC000, 0x8000);
        assert_eq!(gc.objects().len(), 2);
        assert!(gc.object(1).expect("asap1").is_writable());
        assert!(gc.object(2).expect("asap2").is_readable());
        assert_eq!(gc.object(1).expect("asap1").gas, vec![GroupAddress(0x0801)]);
    }

    #[test]
    fn test_group_write_updates_writable_object() {
        let mem = seeded_memory();
        let mut gc = GroupComm::from_tables(&mem, 0xA000, 0xC000, 0x8000);
        let updated = gc.on_group_write(GroupAddress(0x0801), &[0x01]);
        assert_eq!(updated, vec![1]);
        assert_eq!(gc.object(1).expect("asap1").value, vec![0x01]);
    }

    #[test]
    fn test_group_read_answers_from_readable_object() {
        let mem = seeded_memory();
        let mut gc = GroupComm::from_tables(&mem, 0xA000, 0xC000, 0x8000);
        // Seed the readable object's value, then read it.
        gc.set_value(2, &[0x2a]);
        assert_eq!(gc.on_group_read(GroupAddress(0x0802)), Some(vec![0x2a]));
        // A GA the device does not listen on returns nothing.
        assert_eq!(gc.on_group_read(GroupAddress(0x0999)), None);
    }
}
