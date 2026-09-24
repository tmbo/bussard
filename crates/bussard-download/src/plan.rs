//! Diffing the desired tables (from the model) against a device's live tables.
//!
//! [`plan`] takes the live [`DeviceTables`] read back over the bus and the
//! [`DesiredTables`] computed from the model and produces a [`PlanReport`]: the
//! `(object, GA)` links that stay, that are added, and that are removed, plus the
//! resulting table sizes and the sequence of load operations `apply` will run.
//!
//! Like `bussard reconstruct`, the diff compares **GA sets per object** — the
//! send/listen direction is not recoverable from the address + association
//! tables alone (it lives in the group object table's flags), so a model `send:`
//! and a model `listen:` are treated alike here. That is safe because the tables
//! this module writes are exactly the address + association tables, which encode
//! only the GA-to-object mapping, not the direction.

use std::collections::BTreeSet;

use bussard_mgmt::tables::DeviceTables;
use bussard_model::GroupAddress;

use crate::compute::DesiredTables;

/// One `(object, GA)` link in the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectGa {
    /// The com-object number.
    pub object: u16,
    /// The group address.
    pub ga: GroupAddress,
}

/// One table object's load operation in the apply sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStep {
    /// Open the address table for writing, replace it, complete the load.
    AddressTable,
    /// Open the association table for writing, replace it, complete the load.
    AssociationTable,
}

impl std::fmt::Display for LoadStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadStep::AddressTable => write!(f, "group address table"),
            LoadStep::AssociationTable => write!(f, "association table"),
        }
    }
}

/// The result of diffing model against device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanReport {
    /// Links present both on the device and in the model (unchanged).
    pub unchanged: Vec<ObjectGa>,
    /// Links the model has that the device does not (to be written).
    pub additions: Vec<ObjectGa>,
    /// Links the device has that the model does not (to be removed).
    pub removals: Vec<ObjectGa>,
    /// The resulting group-address table size after apply.
    pub resulting_address_count: usize,
    /// The resulting association table size after apply.
    pub resulting_association_count: usize,
    /// The current group-address table size on the device.
    pub current_address_count: usize,
    /// The current association table size on the device.
    pub current_association_count: usize,
    /// The load operations `apply` will execute, in order.
    pub load_steps: Vec<LoadStep>,
}

impl PlanReport {
    /// Whether the plan changes anything on the device.
    pub fn is_noop(&self) -> bool {
        self.additions.is_empty() && self.removals.is_empty()
    }
}

/// Diffs `desired` (from the model) against `live` (read from the device).
///
/// The comparison is over `(object, GA)` pairs. `desired` carries the tables in
/// their canonical order; `live` carries the device's current resolved links.
pub fn plan(live: &DeviceTables, desired: &DesiredTables) -> PlanReport {
    // Device pairs: from the resolved associations (object == ASAP).
    let device_pairs: BTreeSet<ObjectGa> = live
        .resolved
        .iter()
        .map(|l| ObjectGa {
            object: l.object,
            ga: l.ga,
        })
        .collect();

    // Desired pairs: reconstruct (object, GA) from the computed association
    // table (asap == object) resolved through the desired address table.
    let desired_pairs: BTreeSet<ObjectGa> = desired
        .associations
        .iter()
        .filter_map(|&(tsap, asap)| {
            let ga = tsap
                .checked_sub(1)
                .and_then(|i| desired.addresses.get(usize::from(i)))?;
            Some(ObjectGa {
                object: asap,
                ga: *ga,
            })
        })
        .collect();

    let unchanged: Vec<ObjectGa> = device_pairs.intersection(&desired_pairs).copied().collect();
    let additions: Vec<ObjectGa> = desired_pairs.difference(&device_pairs).copied().collect();
    let removals: Vec<ObjectGa> = device_pairs.difference(&desired_pairs).copied().collect();

    // The op sequence: address table then association table. See the ordering
    // rationale in `apply` — both tables are unloaded and rewritten wholesale in
    // one connection, so no intermediate state can orphan a TSAP.
    let load_steps = if additions.is_empty() && removals.is_empty() {
        Vec::new()
    } else {
        vec![LoadStep::AddressTable, LoadStep::AssociationTable]
    };

    PlanReport {
        unchanged,
        additions,
        removals,
        resulting_address_count: desired.address_count(),
        resulting_association_count: desired.association_count(),
        current_address_count: live.addresses.len(),
        current_association_count: live.associations.len(),
        load_steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_mgmt::tables::{DeviceTables, ResolvedLink, TableSource};

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("a valid test group address")
    }

    fn live_tables(resolved: &[(u16, &str)]) -> DeviceTables {
        let resolved: Vec<ResolvedLink> = resolved
            .iter()
            .map(|&(object, g)| ResolvedLink { object, ga: ga(g) })
            .collect();
        let mut addresses: Vec<GroupAddress> = resolved.iter().map(|l| l.ga).collect();
        addresses.sort_unstable();
        addresses.dedup();
        DeviceTables {
            mask: 0x07B0,
            addresses,
            associations: Vec::new(),
            resolved,
            sources: vec![("addresses", TableSource::Property)],
            notes: Vec::new(),
        }
    }

    fn desired(pairs: &[(u16, &str)]) -> DesiredTables {
        use bussard_model::schema::Link;
        let mut by_obj: std::collections::BTreeMap<u16, Vec<GroupAddress>> = Default::default();
        for &(o, g) in pairs {
            by_obj.entry(o).or_default().push(ga(g));
        }
        let links: Vec<Link> = by_obj
            .into_iter()
            .map(|(object, gas)| Link {
                object,
                name: None,
                send: None,
                listen: gas,
            })
            .collect();
        crate::compute::compute_tables(&links)
    }

    #[test]
    fn identical_tables_are_a_noop() {
        let live = live_tables(&[(20, "1/2/0"), (21, "1/2/1")]);
        let want = desired(&[(20, "1/2/0"), (21, "1/2/1")]);
        let report = plan(&live, &want);
        assert!(report.is_noop());
        assert_eq!(report.unchanged.len(), 2);
        assert!(report.additions.is_empty());
        assert!(report.removals.is_empty());
        assert!(report.load_steps.is_empty());
    }

    #[test]
    fn additions_and_removals_are_detected() {
        // Device has (20 → 1/2/0) and a ghost (59 → 4/2/12); model wants
        // (20 → 1/2/0) and a new (21 → 1/2/1).
        let live = live_tables(&[(20, "1/2/0"), (59, "4/2/12")]);
        let want = desired(&[(20, "1/2/0"), (21, "1/2/1")]);
        let report = plan(&live, &want);
        assert!(!report.is_noop());
        assert_eq!(
            report.unchanged,
            vec![ObjectGa {
                object: 20,
                ga: ga("1/2/0")
            }]
        );
        assert_eq!(
            report.additions,
            vec![ObjectGa {
                object: 21,
                ga: ga("1/2/1")
            }]
        );
        assert_eq!(
            report.removals,
            vec![ObjectGa {
                object: 59,
                ga: ga("4/2/12")
            }]
        );
        assert_eq!(
            report.load_steps,
            vec![LoadStep::AddressTable, LoadStep::AssociationTable]
        );
    }

    #[test]
    fn ghost_removal_only() {
        // The 1.1.4 shape: device has an extra ghost link the model dropped.
        let live = live_tables(&[(20, "1/2/0"), (59, "4/2/12")]);
        let want = desired(&[(20, "1/2/0")]);
        let report = plan(&live, &want);
        assert!(report.additions.is_empty());
        assert_eq!(report.removals.len(), 1);
        assert_eq!(report.resulting_address_count, 1);
        assert_eq!(report.current_address_count, 2);
    }
}
