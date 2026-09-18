//! System 7 runtime group communication: parse the S7 on-memory table formats.
//!
//! After a System 7 device reaches Loaded, it self-parses its own written
//! address / association / group-object tables from their absolute memory
//! locations (0x4000 region for LSM 1, 0x4201 region for LSM 2) and participates
//! on the bus. The byte formats differ from System B (spec
//! `docs/system7-spec.md` §7), so this module parses them and produces the same
//! [`crate::device::GroupComm`] runtime the System B path uses, so the bus
//! runtime is shared.
//!
//! # Table layouts (System 7, mask 0705/0701, spec §7)
//!
//! The exact sub-addresses inside the 0x4000 / 0x4201 regions are not fixed by a
//! single public source; this parser follows the spec's byte-exact forms and the
//! Selfbus BIM112 dump. The address table (GrAT) and association table (GrOAT)
//! are packed back-to-back inside their LSM regions in the canonical MDT image.
//!
//! - **Address table (GrAT)** `[CNT:1][own-IA:2 BE][GA1:2 BE]...`. `CNT` counts
//!   2-byte entries **including** the own-IA slot; entry 0 is the device's own
//!   individual address (TSAP 0). TSAP 1..N map to GAs in order.
//! - **Association table (GrOAT)** `[CNT:1][TSAP0:1][ASAP0:1]...`. `CNT` counts
//!   `(TSAP, ASAP)` pairs. TSAP indexes the address table; ASAP is the
//!   group-object number.
//! - **Group-object table** `[CNT:1][RAM-flags ptr:2 BE]` then per object a
//!   4-byte descriptor `[data-ptr:2 BE][CONFIG:1][TYPE:1]`.
//!
//! The CONFIG byte packs the com-object flags in the on-device bit order (spec
//! §7.3, worked example 0xDF): bit7 reserved=1, bit6 Transmit, bit5 segment
//! selector, bit4 Write, bit3 Read, bit2 Communication, bits1-0 priority.

use crate::device::group_comm::{ComObject, GroupComm, flag};
use crate::device::memory::Memory;
use crate::wire::GroupAddress;

/// CONFIG-byte flag bits (spec §7.3, on-device order).
mod config {
    /// Transmit enable (T).
    pub const TRANSMIT: u8 = 1 << 6;
    /// Write enable (W).
    pub const WRITE: u8 = 1 << 4;
    /// Read enable (R).
    pub const READ: u8 = 1 << 3;
    /// Communication enable (C).
    pub const COMMUNICATION: u8 = 1 << 2;
}

/// Map a System 7 CONFIG byte to the runtime [`flag`] bits the shared
/// [`GroupComm`]/[`ComObject`] logic understands.
fn config_to_flags(cfg: u8) -> u16 {
    let mut flags = 0u16;
    if cfg & config::COMMUNICATION != 0 {
        flags |= flag::COMMUNICATION;
    }
    if cfg & config::READ != 0 {
        flags |= flag::READ;
    }
    if cfg & config::WRITE != 0 {
        flags |= flag::WRITE;
    }
    if cfg & config::TRANSMIT != 0 {
        flags |= flag::TRANSMIT;
    }
    flags
}

/// Parses the System 7 table formats out of a device's memory and builds a
/// runtime [`GroupComm`].
pub struct Sys7GroupComm;

impl Sys7GroupComm {
    /// Reconstruct the runtime routing from a System 7 device's flashed tables.
    ///
    /// `addr_base` is the address-table (GrAT) base (LSM 1 region, spec 0x4000),
    /// `assoc_base` the association-table (GrOAT) base (LSM 2 region, spec
    /// 0x4201), and `go_base` the group-object table base. In the canonical MDT
    /// image the group-object table is co-located with the address table in the
    /// LSM 1 region; the caller supplies the exact offsets it wrote.
    pub fn from_tables(
        memory: &Memory,
        addr_base: u16,
        assoc_base: u16,
        go_base: u16,
    ) -> GroupComm {
        let addresses = parse_address_table(memory, addr_base);
        let descriptors = parse_group_object_table(memory, go_base);
        let assoc = parse_association_table(memory, assoc_base);

        let mut gc = GroupComm::default();
        for (tsap, asap) in assoc {
            // TSAP is an index into the address table (entry 0 = own IA, so TSAP
            // 1 is the first GA). Resolve to a GA.
            let Some(ga) = addresses.get(usize::from(tsap)).copied() else {
                continue;
            };
            // TSAP 0 (own IA) is never a group link; skip it defensively.
            if tsap == 0 {
                continue;
            }
            let (flags, type_code) = descriptors
                .get(usize::from(asap))
                .copied()
                .unwrap_or((0u16, 0u8));
            gc.upsert_object(asap as u16, flags, type_code, ga);
        }
        gc
    }
}

/// Parse the address table: `[CNT:1][own-IA:2][GA1:2]...`. Returns the raw
/// 2-byte entries as [`GroupAddress`] values, index 0 = own IA, index k = TSAP k.
fn parse_address_table(memory: &Memory, base: u16) -> Vec<GroupAddress> {
    let base = u32::from(base);
    let cnt = memory.read(base, 1)[0] as usize;
    if cnt == 0 {
        return Vec::new();
    }
    let bytes = memory.read(base.wrapping_add(1), cnt * 2);
    bytes
        .chunks_exact(2)
        .map(|c| GroupAddress(u16::from_be_bytes([c[0], c[1]])))
        .collect()
}

/// Parse the association table: `[CNT:1][TSAP:1][ASAP:1]...`. Returns
/// `(TSAP, ASAP)` pairs.
fn parse_association_table(memory: &Memory, base: u16) -> Vec<(u8, u8)> {
    let base = u32::from(base);
    let cnt = memory.read(base, 1)[0] as usize;
    if cnt == 0 {
        return Vec::new();
    }
    let bytes = memory.read(base.wrapping_add(1), cnt * 2);
    bytes.chunks_exact(2).map(|c| (c[0], c[1])).collect()
}

/// Parse the group-object table: `[CNT:1][RAM-flags ptr:2]` then per object a
/// 4-byte descriptor `[data-ptr:2][CONFIG:1][TYPE:1]`. Returns per-object
/// `(runtime flags, TYPE code)` indexed by ASAP (object number, 0-based).
fn parse_group_object_table(memory: &Memory, base: u16) -> Vec<(u16, u8)> {
    let base = u32::from(base);
    let cnt = memory.read(base, 1)[0] as usize;
    if cnt == 0 {
        return Vec::new();
    }
    // Skip the count octet and the 2-byte RAM-flags pointer, then read cnt
    // 4-byte descriptors.
    let desc_base = base.wrapping_add(3);
    let bytes = memory.read(desc_base, cnt * 4);
    bytes
        .chunks_exact(4)
        .map(|c| {
            let config = c[2];
            let type_code = c[3];
            (config_to_flags(config), type_code)
        })
        .collect()
}

// The shared GroupComm needs an upsert entry point for the S7 parser (the System
// B parser builds it internally). Provided as an extension below.
impl GroupComm {
    /// Insert or update a com-object with `flags` (runtime flag bits), a DPT
    /// `type_code`, and one associated group address. Used by the System 7 table
    /// parser to build the runtime object-by-object. Multiple calls for the same
    /// ASAP accumulate GAs (m:n links).
    pub fn upsert_object(&mut self, asap: u16, flags: u16, type_code: u8, ga: GroupAddress) {
        let obj = self.objects_mut().entry(asap).or_insert_with(|| ComObject {
            asap,
            flags,
            size_code: type_code,
            gas: Vec::new(),
            value: Vec::new(),
        });
        obj.flags = flags;
        obj.size_code = type_code;
        if !obj.gas.contains(&ga) {
            obj.gas.push(ga);
        }
        self.index_ga(ga.raw(), asap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::memory::Memory;

    /// Build a System 7 memory image with the three tables packed in their LSM
    /// regions, wiring one writable object (asap 0) and one readable (asap 1).
    fn seeded_memory() -> Memory {
        let mut mem = Memory::new();
        // LSM 1 region carries the address table and group-object table.
        mem.allocate(1, 0x4000, 512);
        // LSM 2 region carries the association table.
        mem.allocate(2, 0x4201, 512);

        // Address table at 0x4000: CNT=3 (own IA + 2 GAs), own IA 1.1.5,
        // GA1 = 1/0/1 (0x0801), GA2 = 1/0/2 (0x0802).
        let mut addr = vec![3u8];
        addr.extend_from_slice(&0x1105u16.to_be_bytes()); // own IA
        addr.extend_from_slice(&0x0801u16.to_be_bytes()); // TSAP1
        addr.extend_from_slice(&0x0802u16.to_be_bytes()); // TSAP2
        mem.write(1, 0x4000, &addr).expect("addr write");

        // Group-object table at 0x4100 (inside LSM 1 region): CNT=2, RAM-flags
        // ptr 0x0700, then two 4-byte descriptors. asap0 = COMM|WRITE (CONFIG
        // C|W = 0x14), asap1 = COMM|READ (CONFIG C|R = 0x0C).
        let mut go = vec![2u8];
        go.extend_from_slice(&0x0700u16.to_be_bytes());
        go.extend_from_slice(&[0x00, 0x00, 0x14, 0x00]); // asap0 data-ptr, CONFIG, TYPE
        go.extend_from_slice(&[0x00, 0x02, 0x0C, 0x00]); // asap1
        mem.write(1, 0x4100, &go).expect("go write");

        // Association table at 0x4201: CNT=2, (TSAP1,ASAP0), (TSAP2,ASAP1).
        let assoc = vec![2u8, 1, 0, 2, 1];
        mem.write(2, 0x4201, &assoc).expect("assoc write");
        mem
    }

    #[test]
    fn test_parse_address_table() {
        let mem = seeded_memory();
        let addrs = parse_address_table(&mem, 0x4000);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], GroupAddress(0x1105)); // own IA
        assert_eq!(addrs[1], GroupAddress(0x0801));
        assert_eq!(addrs[2], GroupAddress(0x0802));
    }

    #[test]
    fn test_parse_group_object_descriptors() {
        let mem = seeded_memory();
        let descs = parse_group_object_table(&mem, 0x4100);
        assert_eq!(descs.len(), 2);
        // asap0 = COMM|WRITE, asap1 = COMM|READ.
        assert_eq!(descs[0].0, flag::COMMUNICATION | flag::WRITE);
        assert_eq!(descs[1].0, flag::COMMUNICATION | flag::READ);
    }

    #[test]
    fn test_from_tables_reconstructs_routing() {
        let mem = seeded_memory();
        let gc = Sys7GroupComm::from_tables(&mem, 0x4000, 0x4201, 0x4100);
        assert_eq!(gc.objects().len(), 2);
        assert!(gc.object(0).expect("asap0").is_writable());
        assert!(gc.object(1).expect("asap1").is_readable());
        assert_eq!(gc.object(0).expect("asap0").gas, vec![GroupAddress(0x0801)]);
    }

    #[test]
    fn test_config_to_flags_worked_example() {
        // 0xDF = 1101_1111: T set, W set, R set, C set (and reserved/seg bits).
        let flags = config_to_flags(0xDF);
        assert!(flags & flag::TRANSMIT != 0);
        assert!(flags & flag::WRITE != 0);
        assert!(flags & flag::READ != 0);
        assert!(flags & flag::COMMUNICATION != 0);
    }
}
