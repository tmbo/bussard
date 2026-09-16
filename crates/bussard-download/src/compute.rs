//! Pure computation of a System B device's loadable tables from the model.
//!
//! Given one device's `links.yaml` entries, this produces the two tables ETS
//! would download: the **group-address table** (sorted unique GAs) and the
//! **association table** (`(TSAP, ASAP)` pairs). Everything here is a pure
//! function of the model — no bus, no I/O — so it is exhaustively unit-tested,
//! including a golden test against the reference device's real tables.
//!
//! # The ordering convention (evidence)
//!
//! The convention was reverse-engineered from the reference actuator's live
//! tables (a Jung 23024, mask 07B0, whose `links.yaml` is an ETS-import ground
//! truth) and reproduces them **byte-for-byte** once the four known ghost links
//! are removed (see the golden test in `tests/`):
//!
//! - **Group-address table**: every GA any com-object on the device is linked to,
//!   **sorted ascending by raw 16-bit value**, de-duplicated. The TSAP of a GA is
//!   its 1-based index in this table (`addresses[0]` is TSAP 1), matching the read
//!   side in [`bussard_mgmt::tables`].
//! - **Association table**: two concatenated blocks, each iterated over the
//!   com-objects in **ascending object-number order** (the ASAP *is* the ETS
//!   com-object number):
//!   - **Block 1 — the primary link of each object**: for every object, its
//!     *first* GA (the `send` GA if it has one, else its first `listen` GA)
//!     yields one `(tsap, asap)` entry.
//!   - **Block 2 — the extra links**: for every object, each of its *remaining*
//!     GAs (the 2nd, 3rd… `listen`) yields one further `(tsap, asap)` entry.
//!
//!   Because both blocks iterate objects ascending, the ASAP column is
//!   non-decreasing within each block — the shape seen in the live association
//!   table. An object with no GA at all contributes nothing.

use std::collections::BTreeMap;

use bussard_model::GroupAddress;
use bussard_model::schema::Link;
use bussard_prod::ResolvedComObject;

/// The two loadable tables computed for one device, ready to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredTables {
    /// The group-address table: sorted unique GAs. `addresses[0]` is TSAP 1.
    pub addresses: Vec<GroupAddress>,
    /// The association table as `(tsap, asap)` pairs, in table order.
    ///
    /// `tsap` is the 1-based index into [`addresses`](Self::addresses); `asap`
    /// is the com-object number.
    pub associations: Vec<(u16, u16)>,
}

impl DesiredTables {
    /// The group-address table size (element count word plus this many elements).
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// The association table size.
    pub fn association_count(&self) -> usize {
        self.associations.len()
    }

    /// The address table serialised as `PID_TABLE` element octets (big-endian
    /// `u16` per GA), ready for [`bussard_mgmt::write_table`]. Excludes the
    /// element-count word (the writer prepends it).
    pub fn address_elements(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.addresses.len() * 2);
        for ga in &self.addresses {
            out.extend_from_slice(&ga.raw().to_be_bytes());
        }
        out
    }

    /// The association table serialised as `PID_TABLE` element octets (4 octets
    /// per entry, big-endian `tsap` then `asap`). Excludes the element-count
    /// word.
    pub fn association_elements(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.associations.len() * 4);
        for &(tsap, asap) in &self.associations {
            out.extend_from_slice(&tsap.to_be_bytes());
            out.extend_from_slice(&asap.to_be_bytes());
        }
        out
    }
}

/// The GAs of one com-object, in association order: the `send` GA first (if
/// any), then the `listen` GAs in their model order.
///
/// A GA that appears both as `send` and `listen` on the same object is kept only
/// once, at its first position, so it maps to a single association entry.
fn object_gas(link: &Link) -> Vec<GroupAddress> {
    let mut gas: Vec<GroupAddress> = Vec::new();
    if let Some(send) = link.send {
        gas.push(send);
    }
    for &ga in &link.listen {
        if !gas.contains(&ga) {
            gas.push(ga);
        }
    }
    gas
}

/// Computes the desired tables for one device from its `links.yaml` entries.
///
/// `links` is the slice of [`Link`] for a single device (as stored in
/// `Model::links.links`). The ordering convention is documented on the module.
///
/// Multiple links for the same object number are merged (their GAs concatenated
/// in link order, then send-first / dedup applied per the merged view) so a
/// hand-split `links.yaml` produces the same tables as a consolidated one.
pub fn compute_tables(links: &[Link]) -> DesiredTables {
    // Merge links per object, preserving first-seen GA order, send-first.
    // BTreeMap keeps objects in ascending order — the ASAP iteration order.
    let mut per_object: BTreeMap<u16, Vec<GroupAddress>> = BTreeMap::new();
    for link in links {
        let gas = object_gas(link);
        let entry = per_object.entry(link.object).or_default();
        for ga in gas {
            if !entry.contains(&ga) {
                entry.push(ga);
            }
        }
    }
    // Drop objects that ended up with no GA (nothing to associate).
    per_object.retain(|_, gas| !gas.is_empty());

    // Group-address table: sorted unique GAs across all objects.
    let mut all_gas: Vec<GroupAddress> = per_object.values().flatten().copied().collect();
    all_gas.sort_unstable();
    all_gas.dedup();
    let addresses = all_gas;

    // TSAP lookup: 1-based index into the address table.
    let tsap_of: BTreeMap<GroupAddress, u16> = addresses
        .iter()
        .enumerate()
        .map(|(i, ga)| (*ga, (i + 1) as u16))
        .collect();

    // Association table: block 1 (each object's first GA), then block 2 (the
    // rest), both iterating objects ascending.
    let mut associations: Vec<(u16, u16)> = Vec::new();
    for (&object, gas) in &per_object {
        if let Some(first) = gas.first() {
            associations.push((tsap_of[first], object));
        }
    }
    for (&object, gas) in &per_object {
        for ga in gas.iter().skip(1) {
            associations.push((tsap_of[ga], object));
        }
    }

    DesiredTables {
        addresses,
        associations,
    }
}

/// Prepends the big-endian `u16` element-count word to a serialised table body,
/// producing the full memory image a `WriteRelMem` streams.
///
/// The read side (`bussard_mgmt::tables`) documents word 0 of every loadable
/// table's memory image as the entry count; the flash path writes raw memory
/// (not the `PID_TABLE` property array `bussard apply` uses, which prepends the
/// count itself), so the count word must be part of the streamed bytes here.
/// `count` is truncated to `u16` — no real table approaches 65 535 entries.
pub fn table_image_with_count(count: usize, elements: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + elements.len());
    out.extend_from_slice(&(count as u16).to_be_bytes());
    out.extend_from_slice(elements);
    out
}

/// One com-object's group-object-table descriptor input: its ASAP (com-object
/// number) and the effective flags/size the descriptor encodes.
#[derive(Debug, Clone, Copy)]
pub struct GroupObjectDescriptor {
    /// The com-object number (ASAP), the 1-based index into the table.
    pub asap: u16,
    /// The effective com-object flags.
    pub flags: bussard_model::Flags,
    /// The object size code (see [`size_code_from_object_size`]).
    pub size_code: u8,
}

/// Builds the group-object table (obj3, object type 9) memory image from the
/// device's linked com-objects.
///
/// # ⚠️ Unverified byte format
///
/// This is a **best-effort clean-room encoder**. The read side documents the
/// System B group-object table as "word 0 = entry count; word `asap` = a packed
/// big-endian `u16` descriptor (low byte = DPT size code, high bits =
/// comm/read/write/transmit/update flags)", and this function encodes exactly
/// that: a 2-byte count word followed by one 2-byte descriptor per com-object,
/// indexed 1-based by ASAP (gaps zero-filled). **But an ETS→KNX-Virtual capture
/// of the DA.tp device sends a 148-byte obj3 body for 7 com-objects (~21
/// octets/object), not the ~16 bytes this 2-byte-per-object layout produces** —
/// so the real System B realisation is a wider per-object record this encoder
/// does not reproduce. The image is therefore structurally plausible but almost
/// certainly not byte-compatible with what a real System B device expects; a
/// live wire-diff against ETS is required to reverse-engineer the true record
/// format. Until then the flash still *programs* obj3 (right object, right
/// sequence) with this placeholder body, so the structure can be validated
/// end-to-end and the content corrected from the diff.
///
/// `descriptors` need not be sorted; entries are placed by ASAP. Returns `None`
/// when there are no descriptors (nothing to program).
pub fn compute_group_object_table(descriptors: &[GroupObjectDescriptor]) -> Option<Vec<u8>> {
    let max_asap = descriptors.iter().map(|d| d.asap).max()?;
    let count = usize::from(max_asap);
    // 1-based table: word 0 is the count, words 1..=max_asap are descriptors.
    let mut words: Vec<u16> = vec![0u16; count];
    for d in descriptors {
        if d.asap == 0 {
            continue;
        }
        // Packed descriptor: low byte = size code, high byte = flags.
        let word = (u16::from(d.flags.bits()) << 8) | u16::from(d.size_code);
        words[usize::from(d.asap) - 1] = word;
    }
    let mut body = Vec::with_capacity(count * 2);
    for w in words {
        body.extend_from_slice(&w.to_be_bytes());
    }
    Some(table_image_with_count(count, &body))
}

/// Maps an ETS `ObjectSize` string (e.g. `"1 Bit"`, `"1 Byte"`, `"4 Bit"`) to
/// the KNX group-object descriptor size code (0 = 1 bit, 1 = 2 bits … per the
/// standard's size-code table), defaulting to `0` (1 bit) when unrecognised.
///
/// This is the inverse of the read side's size decoding; like the table itself
/// it is unverified against a real device and exists so the descriptor carries a
/// plausible size until the format is confirmed on the wire.
pub fn size_code_from_object_size(object_size: Option<&str>) -> u8 {
    // The KNX size-code table (3/5/1) enumerates: 1 bit, 2 bits, 3 bits, 4 bits,
    // 5 bits, 6 bits, 7 bits, 1 byte, 2 bytes, 3 bytes, 4 bytes, 6 bytes, 8
    // bytes, 10 bytes, 14 bytes — codes 0..=14 in that order.
    const TABLE: [&str; 15] = [
        "1 bit", "2 bit", "3 bit", "4 bit", "5 bit", "6 bit", "7 bit", "1 byte", "2 byte",
        "3 byte", "4 byte", "6 byte", "8 byte", "10 byte", "14 byte",
    ];
    let Some(raw) = object_size else { return 0 };
    // Normalise: lower-case, singularise "bytes"/"bits" to "byte"/"bit".
    let norm = raw
        .to_ascii_lowercase()
        .replace("bytes", "byte")
        .replace("bits", "bit");
    let norm = norm.trim();
    TABLE
        .iter()
        .position(|entry| *entry == norm)
        .map(|i| i as u8)
        .unwrap_or(0)
}

/// Builds group-object descriptors from a device's resolved com-objects,
/// restricted to those the device is actually linked to (`linked_objects`).
///
/// ETS only registers a group-object-table entry for a com-object that is bound
/// to at least one GA; an unlinked object contributes nothing. `linked_objects`
/// is the set of com-object numbers that appear in the device's `links.yaml`
/// (i.e. the ASAPs the association table references).
pub fn descriptors_for_linked_objects(
    com_objects: &[ResolvedComObject<'_>],
    linked_objects: &std::collections::BTreeSet<u16>,
) -> Vec<GroupObjectDescriptor> {
    com_objects
        .iter()
        .filter(|c| linked_objects.contains(&c.number()))
        .map(|c| GroupObjectDescriptor {
            asap: c.number(),
            flags: c.flags(),
            size_code: size_code_from_object_size(c.object_size()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
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
    fn empty_links_produce_empty_tables() {
        let t = compute_tables(&[]);
        assert!(t.addresses.is_empty());
        assert!(t.associations.is_empty());
        assert!(t.address_elements().is_empty());
        assert!(t.association_elements().is_empty());
    }

    #[test]
    fn single_send_object() {
        let t = compute_tables(&[link(38, Some("1/2/3"), &[])]);
        assert_eq!(t.addresses, vec![ga("1/2/3")]);
        assert_eq!(t.associations, vec![(1, 38)]);
    }

    #[test]
    fn addresses_are_sorted_and_deduplicated() {
        // Two objects listening to overlapping, out-of-order GAs.
        let t = compute_tables(&[
            link(20, None, &["1/2/2", "1/2/0"]),
            link(21, None, &["1/2/1", "1/2/0"]),
        ]);
        // Sorted unique: 1/2/0, 1/2/1, 1/2/2.
        assert_eq!(t.addresses, vec![ga("1/2/0"), ga("1/2/1"), ga("1/2/2")]);
    }

    #[test]
    fn shared_ga_across_objects_gets_one_address_two_associations() {
        // Both objects listen to the same GA 1/3/2 as their extra link.
        let t = compute_tables(&[
            link(114, None, &["1/2/8", "1/3/2"]),
            link(161, None, &["1/2/12", "1/3/2"]),
        ]);
        // Address table: 1/2/8, 1/2/12, 1/3/2 (sorted).
        assert_eq!(t.addresses, vec![ga("1/2/8"), ga("1/2/12"), ga("1/3/2")]);
        // TSAPs: 1/2/8=1, 1/2/12=2, 1/3/2=3.
        // Block 1 (first GA per object): (1,114), (2,161).
        // Block 2 (extras): (3,114), (3,161).
        assert_eq!(t.associations, vec![(1, 114), (2, 161), (3, 114), (3, 161)]);
    }

    #[test]
    fn send_goes_first_then_listen() {
        // An object with both a send and a listen: send is the primary link.
        let t = compute_tables(&[link(5, Some("2/0/0"), &["3/0/0"])]);
        // Address table sorted: 2/0/0 (tsap 1), 3/0/0 (tsap 2).
        assert_eq!(t.addresses, vec![ga("2/0/0"), ga("3/0/0")]);
        // Block 1: first GA is the send (2/0/0 → tsap 1). Block 2: listen 3/0/0.
        assert_eq!(t.associations, vec![(1, 5), (2, 5)]);
    }

    #[test]
    fn tsap_dedup_a_send_that_also_listens() {
        // Pathological but legal: same GA as send and listen — one entry only.
        let t = compute_tables(&[link(7, Some("1/1/1"), &["1/1/1"])]);
        assert_eq!(t.addresses, vec![ga("1/1/1")]);
        assert_eq!(t.associations, vec![(1, 7)]);
    }

    #[test]
    fn objects_are_iterated_in_ascending_number_order() {
        // Provide out-of-order objects; block 1 must come out ascending.
        let t = compute_tables(&[
            link(100, Some("5/0/0"), &[]),
            link(3, Some("5/0/1"), &[]),
            link(50, Some("5/0/2"), &[]),
        ]);
        // Addresses sorted: 5/0/0(t1) 5/0/1(t2) 5/0/2(t3).
        // Block1 ascending objects: (t2,3),(t3,50),(t1,100).
        assert_eq!(t.associations, vec![(2, 3), (3, 50), (1, 100)]);
    }

    #[test]
    fn merges_split_links_for_one_object() {
        // Two link entries for object 9: merged into one association view.
        let t = compute_tables(&[link(9, Some("1/0/0"), &[]), link(9, None, &["1/0/1"])]);
        assert_eq!(t.addresses, vec![ga("1/0/0"), ga("1/0/1")]);
        assert_eq!(t.associations, vec![(1, 9), (2, 9)]);
    }

    #[test]
    fn serialisation_is_big_endian() {
        let t = compute_tables(&[link(20, Some("1/2/0"), &[])]);
        // 1/2/0 raw = (1<<11)|(2<<8)|0 = 0x0A00.
        assert_eq!(t.address_elements(), vec![0x0A, 0x00]);
        // association (tsap 1, asap 20) = 00 01 00 14.
        assert_eq!(t.association_elements(), vec![0x00, 0x01, 0x00, 0x14]);
    }

    #[test]
    fn test_table_image_with_count_prepends_be_count() {
        assert_eq!(
            table_image_with_count(3, &[0xAA, 0xBB]),
            vec![0x00, 0x03, 0xAA, 0xBB]
        );
    }

    #[test]
    fn test_size_code_from_object_size_maps_known_sizes() {
        assert_eq!(size_code_from_object_size(Some("1 Bit")), 0);
        assert_eq!(size_code_from_object_size(Some("4 Bit")), 3);
        assert_eq!(size_code_from_object_size(Some("1 Byte")), 7);
        assert_eq!(size_code_from_object_size(Some("2 Bytes")), 8);
        // Unknown / absent default to 1-bit (code 0).
        assert_eq!(size_code_from_object_size(Some("weird")), 0);
        assert_eq!(size_code_from_object_size(None), 0);
    }

    #[test]
    fn test_compute_group_object_table_places_by_asap() {
        use bussard_model::Flags;
        // Objects 1 and 3 present, object 2 absent (a gap, zero-filled).
        let descs = [
            GroupObjectDescriptor {
                asap: 1,
                flags: Flags::COMMUNICATION | Flags::WRITE,
                size_code: 0,
            },
            GroupObjectDescriptor {
                asap: 3,
                flags: Flags::COMMUNICATION | Flags::TRANSMIT,
                size_code: 7,
            },
        ];
        let table = compute_group_object_table(&descs).unwrap();
        // count word = 3 (max asap), then 3 descriptor words.
        // obj1: flags = C|W = 0b0000_0101 = 0x05, size 0 -> 0x0500.
        // obj2: absent -> 0x0000.
        // obj3: flags = C|T = 0b0000_1001 = 0x09, size 7 -> 0x0907.
        assert_eq!(table, vec![0x00, 0x03, 0x05, 0x00, 0x00, 0x00, 0x09, 0x07]);
    }

    #[test]
    fn test_compute_group_object_table_empty_is_none() {
        assert!(compute_group_object_table(&[]).is_none());
    }
}
