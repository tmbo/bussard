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
}
