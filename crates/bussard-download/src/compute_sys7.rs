//! Pure computation of a **System 7** device's loadable link tables from the
//! model — the byte-exact analogue of [`crate::compute`] for mask 0705 / 0701.
//!
//! System 7 tables live in memory (not property arrays) and use different
//! on-memory forms from System B (`[system7-spec §7]`). bussard writes these into
//! the `0x4000` (address + com-object descriptors) and `0x4201` (association +
//! group-object) segments. The three formats:
//!
//! - **Address table (GrAT)** `[CNT:1][own-IA:2 BE][GA:2 BE]…` — `CNT` counts the
//!   own-IA slot plus every GA; entry 0 is the device's own individual address.
//! - **Association table (GrOAT)** `[CNT:1][TSAP:1][ASAP:1]…` — `CNT` pairs, each a
//!   1-byte TSAP (address-table index) and 1-byte ASAP (group-object number).
//! - **Group-object table + descriptors** `[CNT:1][RAM-flags ptr:2 BE]` then a
//!   4-byte descriptor `[data-ptr:2 BE][CONFIG:1][TYPE:1]` per object.
//!
//! These reuse [`crate::compute::compute_tables`] (the TSAP/ASAP ordering is
//! system-agnostic) and [`crate::compute::size_code_from_object_size`] (the TYPE
//! byte is the same KNX length code), but the packing is System-7-specific. The
//! CONFIG/TYPE synthesis and the data-pointer defaults are best-evidence from the
//! spec; every uncertain constant carries an `S7-CAL:` marker.

use bussard_model::GroupAddress;

use crate::compute::{DesiredTables, GroupObjectDescriptor, Priority};

/// Builds the System 7 **address table (GrAT)** image for `0x4000`
/// (`[system7-spec §7.1]`):
///
/// ```text
/// [CNT:1][own-IA:2 BE][GA1:2 BE][GA2:2 BE]…
/// ```
///
/// `CNT` is the number of 2-byte entries **including** the own-IA slot
/// (`1 + tables.addresses.len()`), so it is clamped to `u8`. Entry 0 is
/// `own_ia`; TSAP 1..N map to the sorted GAs in [`DesiredTables::addresses`].
pub fn sys7_address_table(own_ia: u16, tables: &DesiredTables) -> Vec<u8> {
    let count = 1 + tables.addresses.len();
    let mut out = Vec::with_capacity(1 + count * 2);
    out.push(count.min(usize::from(u8::MAX)) as u8);
    out.extend_from_slice(&own_ia.to_be_bytes());
    for ga in &tables.addresses {
        out.extend_from_slice(&ga.raw().to_be_bytes());
    }
    out
}

/// Builds the System 7 **association table (GrOAT)** image for `0x4201`
/// (`[system7-spec §7.2]`):
///
/// ```text
/// [CNT:1][TSAP0:1][ASAP0:1][TSAP1:1][ASAP1:1]…
/// ```
///
/// `CNT` is the number of `(TSAP, ASAP)` pairs. Each TSAP is a 1-byte index into
/// the address table and each ASAP a 1-byte group-object number, taken from
/// [`DesiredTables::associations`] in table order (the ordering is computed by
/// [`crate::compute::compute_tables`], shared with System B).
///
/// `S7-CAL: confirm no 2-byte TSAP/ASAP variant appears in the corpus — 0705
/// allows ~254 GAs which still fits u8, but a large device could in principle
/// need a wider index.`
pub fn sys7_association_table(tables: &DesiredTables) -> Vec<u8> {
    let count = tables.associations.len();
    let mut out = Vec::with_capacity(1 + count * 2);
    out.push(count.min(usize::from(u8::MAX)) as u8);
    for &(tsap, asap) in &tables.associations {
        out.push((tsap & 0xFF) as u8);
        out.push((asap & 0xFF) as u8);
    }
    out
}

/// Synthesizes the System 7 group-object descriptor **CONFIG** byte from a
/// com-object's flags and priority (`[system7-spec §7.3]`).
///
/// On-device bit order (differs from the ETS UI "C R W T U I" order):
///
/// ```text
/// bit 7   reserved, must be 1
/// bit 6   Transmit enable (T)
/// bit 5   Segment selector type (0 = value in user RAM segment)
/// bit 4   Write enable (W)
/// bit 3   Read enable (R)
/// bit 2   Communication enable (C)
/// bits 1-0 transmission priority (11 = low)
/// ```
///
/// `S7-CAL: exact CONFIG synthesis rule + priority codes for bits 1-0 other than
/// 11=low.`
pub fn sys7_config_byte(flags: bussard_model::Flags, priority: Priority) -> u8 {
    use bussard_model::Flags;
    let mut c: u8 = 1 << 7; // bit 7 reserved, must be 1
    if flags.contains(Flags::TRANSMIT) {
        c |= 1 << 6;
    }
    // bit 5 (segment selector) left 0 = value in user RAM segment.
    if flags.contains(Flags::WRITE) {
        c |= 1 << 4;
    }
    if flags.contains(Flags::READ) {
        c |= 1 << 3;
    }
    if flags.contains(Flags::COMMUNICATION) {
        c |= 1 << 2;
    }
    // Priority in bits 1-0. The System-B `Priority::code()` gives the same 2-bit
    // KNX priority codes (00 system, 01 high, 10 alarm, 11 low).
    c |= (priority.code() as u8) & 0b11;
    c
}

/// One System 7 group-object entry as it will be packed: the 4-byte descriptor
/// `[data-ptr:2 BE][CONFIG:1][TYPE:1]` plus the descriptor's ASAP (1-based object
/// number) so [`sys7_group_object_table`] can place it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sys7GroupObject {
    /// The com-object number (ASAP), 1-based; word `asap` in the table.
    pub asap: u16,
    /// The live-value RAM pointer (`data-ptr`), big-endian in the descriptor.
    pub data_ptr: u16,
    /// The synthesized CONFIG byte (see [`sys7_config_byte`]).
    pub config: u8,
    /// The object size / TYPE code (see
    /// [`crate::compute::size_code_from_object_size`]).
    pub type_code: u8,
}

/// Builds the System 7 **group-object table + descriptors** image
/// (`[system7-spec §7.3]`):
///
/// ```text
/// [CNT:1][RAM-flags ptr:2 BE] then per object a 4-byte descriptor:
/// [data-ptr:2 BE][CONFIG:1][TYPE:1]
/// ```
///
/// `CNT` is the descriptor count (the maximum ASAP); descriptors are placed 1-based
/// by ASAP, with zero-filled gaps for unused ASAPs. `ram_flags_ptr` is the base of
/// the per-object RAM-flags table (default `0x0700`, the low-RAM working region).
/// Returns `None` when there are no descriptors (nothing to program).
///
/// `S7-CAL: confirm the RAM-flags pointer default and the data-ptr allocation
/// rule against a live 0705 group-object segment.`
pub fn sys7_group_object_table(ram_flags_ptr: u16, objects: &[Sys7GroupObject]) -> Option<Vec<u8>> {
    let max_asap = objects.iter().map(|o| o.asap).max()?;
    let count = usize::from(max_asap);
    // 1-based descriptor array: descriptor `asap` sits at index `asap - 1`.
    let mut descriptors: Vec<[u8; 4]> = vec![[0u8; 4]; count];
    for o in objects {
        if o.asap == 0 {
            continue;
        }
        let ptr = o.data_ptr.to_be_bytes();
        descriptors[usize::from(o.asap) - 1] = [ptr[0], ptr[1], o.config, o.type_code];
    }
    let mut out = Vec::with_capacity(1 + 2 + count * 4);
    out.push(count.min(usize::from(u8::MAX)) as u8);
    out.extend_from_slice(&ram_flags_ptr.to_be_bytes());
    for d in descriptors {
        out.extend_from_slice(&d);
    }
    Some(out)
}

/// Builds System 7 group-object descriptors from a device's group-object
/// descriptors (as computed for System B by
/// [`crate::compute::descriptors_for_linked_objects`]) plus a per-object data
/// pointer.
///
/// `data_ptr_for` maps a 1-based ASAP to its live-value RAM pointer; on real 0705
/// devices these come from the product data / `HawkConfigurationData`. When the
/// caller has no per-object pointer it may return a constant placeholder — the
/// pointer only affects the runtime value location, not the table's structure.
pub fn sys7_group_objects(
    descriptors: &[GroupObjectDescriptor],
    mut data_ptr_for: impl FnMut(u16) -> u16,
) -> Vec<Sys7GroupObject> {
    descriptors
        .iter()
        .map(|d| Sys7GroupObject {
            asap: d.asap,
            data_ptr: data_ptr_for(d.asap),
            config: sys7_config_byte(d.flags, d.priority),
            type_code: d.size_code,
        })
        .collect()
}

/// A convenience helper: the own individual address of a device as a raw `u16`,
/// for the address table's entry 0.
pub fn own_ia_raw(ia: bussard_model::IndividualAddress) -> u16 {
    ia.raw()
}

/// Re-export so callers building a System 7 address table can name the GA type.
pub type Ga = GroupAddress;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::{Priority, compute_tables};
    use bussard_model::schema::Link;

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("a valid group address")
    }

    fn link(object: u16, send: Option<&str>, listen: &[&str]) -> Link {
        Link {
            object,
            name: None,
            send: send.map(ga),
            listen: listen.iter().map(|s| ga(s)).collect(),
        }
    }

    #[test]
    fn test_sys7_address_table_golden_bytes() {
        // Two objects, three unique GAs: 1/0/1 (0x0801), 1/0/2 (0x0802),
        // 2/0/1 (0x1001). Sorted ascending. Own IA 1.1.5 = 0x1105.
        let links = vec![
            link(1, Some("1/0/1"), &["2/0/1"]),
            link(2, Some("1/0/2"), &[]),
        ];
        let tables = compute_tables(&links);
        let own_ia = 0x1105u16;
        let img = sys7_address_table(own_ia, &tables);
        // CNT = 1 (own IA) + 3 GAs = 4. Then own IA, then GAs ascending.
        assert_eq!(
            img,
            vec![
                0x04, // CNT
                0x11, 0x05, // own IA 1.1.5
                0x08, 0x01, // 1/0/1
                0x08, 0x02, // 1/0/2
                0x10, 0x01, // 2/0/1
            ]
        );
    }

    #[test]
    fn test_sys7_association_table_golden_bytes() {
        // Object 1 sends 1/0/1 and listens 2/0/1; object 2 sends 1/0/2.
        // GA table sorted: [1/0/1, 1/0/2, 2/0/1] → TSAPs 1,2,3.
        // Associations (block 1 then block 2): (tsap 1, asap 1), (tsap 2, asap 2),
        // (tsap 3, asap 1).
        let links = vec![
            link(1, Some("1/0/1"), &["2/0/1"]),
            link(2, Some("1/0/2"), &[]),
        ];
        let tables = compute_tables(&links);
        let img = sys7_association_table(&tables);
        assert_eq!(
            img,
            vec![
                0x03, // CNT = 3 pairs
                0x01, 0x01, // (tsap 1, asap 1)
                0x02, 0x02, // (tsap 2, asap 2)
                0x03, 0x01, // (tsap 3, asap 1)
            ]
        );
    }

    #[test]
    fn test_sys7_config_byte_worked_example() {
        use bussard_model::Flags;
        // C+R+W+T set, priority low: reserved(1<<7) | T(1<<6) | W(1<<4) | R(1<<3)
        // | C(1<<2) | low(0b11) = 0xDF — the spec's worked example.
        let flags = Flags::COMMUNICATION | Flags::READ | Flags::WRITE | Flags::TRANSMIT;
        assert_eq!(sys7_config_byte(flags, Priority::Low), 0xDF);
        // Communication-only, low priority: reserved | C | low = 0x87.
        assert_eq!(sys7_config_byte(Flags::COMMUNICATION, Priority::Low), 0x87);
    }

    #[test]
    fn test_sys7_group_object_table_golden_bytes() {
        // Two objects. obj1: data-ptr 0x075C, CONFIG 0xDF, TYPE 0x03 (4 bit) —
        // the real BIM112 dump descriptor `07 5C DF 03`. obj2: data-ptr 0x0760,
        // CONFIG 0x87, TYPE 0x00 (1 bit).
        let objects = vec![
            Sys7GroupObject {
                asap: 1,
                data_ptr: 0x075C,
                config: 0xDF,
                type_code: 0x03,
            },
            Sys7GroupObject {
                asap: 2,
                data_ptr: 0x0760,
                config: 0x87,
                type_code: 0x00,
            },
        ];
        let img = sys7_group_object_table(0x0700, &objects).expect("a table");
        assert_eq!(
            img,
            vec![
                0x02, // CNT = 2 objects
                0x07, 0x00, // RAM-flags ptr 0x0700
                0x07, 0x5C, 0xDF, 0x03, // obj1 descriptor
                0x07, 0x60, 0x87, 0x00, // obj2 descriptor
            ]
        );
    }

    #[test]
    fn test_sys7_group_object_table_zero_fills_gaps() {
        // Only ASAP 3 present → CNT 3, descriptors 1 and 2 zero-filled.
        let objects = vec![Sys7GroupObject {
            asap: 3,
            data_ptr: 0x0710,
            config: 0x84,
            type_code: 0x07,
        }];
        let img = sys7_group_object_table(0x0700, &objects).expect("a table");
        assert_eq!(
            img,
            vec![
                0x03, // CNT = 3 (max ASAP)
                0x07, 0x00, // RAM-flags ptr
                0x00, 0x00, 0x00, 0x00, // gap ASAP 1
                0x00, 0x00, 0x00, 0x00, // gap ASAP 2
                0x07, 0x10, 0x84, 0x07, // ASAP 3 descriptor
            ]
        );
    }

    #[test]
    fn test_sys7_group_objects_builds_descriptors() {
        use bussard_model::Flags;
        let descriptors = vec![GroupObjectDescriptor {
            asap: 1,
            flags: Flags::COMMUNICATION | Flags::WRITE,
            size_code: 0,
            priority: Priority::Low,
        }];
        let objs = sys7_group_objects(&descriptors, |_asap| 0x0700);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].asap, 1);
        assert_eq!(objs[0].data_ptr, 0x0700);
        // CONFIG: reserved | W(1<<4) | C(1<<2) | low(0b11) = 0x80|0x10|0x04|0x03 = 0x97.
        assert_eq!(objs[0].config, 0x97);
        assert_eq!(objs[0].type_code, 0);
    }

    #[test]
    fn test_empty_group_object_table_is_none() {
        assert!(sys7_group_object_table(0x0700, &[]).is_none());
    }
}
