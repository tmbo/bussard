//! Executing a plan over the bus: the load-state download sequence.
//!
//! [`apply_tables`] drives the write side of [`bussard_mgmt::load`] against a
//! live (or mock) System B device: it opens both loadable table objects, writes
//! the new address and association tables, completes the loads, and verifies the
//! result by reading the tables back and comparing them byte-for-byte to the
//! desired tables.
//!
//! # Op-sequence ordering (decision + rationale)
//!
//! The two tables are coupled: the **association table**'s TSAP column indexes
//! the **group-address table**. A naive "shrink the address table, then fix up
//! the associations" ordering opens a window where the live association table
//! references address slots that no longer exist (or now hold a different GA) —
//! an orphaned-TSAP hazard, especially on a shrink (the 1.1.4 ghost-removal
//! case).
//!
//! The safe order chosen here is **open-both, write-both, complete-address-then-
//! association** within a single connection:
//!
//! 1. `StartLoading` the **association** table (→ `Loading`).
//! 2. `StartLoading` the **address** table (→ `Loading`).
//! 3. Write the new **address** table (count word + elements).
//! 4. Write the new **association** table (count word + elements). Its TSAPs now
//!    index the just-written address content.
//! 5. `LoadCompleted` the **address** table (→ `Loaded`).
//! 6. `LoadCompleted` the **association** table (→ `Loaded`).
//!
//! Both objects are in `Loading` before either is written, so no
//! partially-updated table is ever *active*: a device evaluates group telegrams
//! against a table only in the `Loaded` state (thelsing `table_object.cpp`:
//! `saveMemory()` runs on `LoadCompleted`; a `Loading` object is inactive).
//! Completing the address table before the association table guarantees the
//! association table is only activated once the address table it points into is
//! already valid. This mirrors what ETS does for a differential link download.
//!
//! # Failure handling
//!
//! There is no clean rollback mid-write: once an object is in `Loading`, a
//! failure leaves it unloaded/inactive until re-applied. [`apply_tables`] never
//! swallows an error — every failure surfaces with the object and step that
//! failed. `bussard apply` prints the backup path and recovery guidance loudly
//! on any error, so a half-applied device is never left silent. Recovery is
//! re-running `apply` (idempotent — the tables are rewritten wholesale) or ETS.

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    self, LoadControl, LoadState, WriteError, read_load_state, write_load_control, write_table,
};
use bussard_mgmt::tables::{OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, PID_OBJECT_TYPE, read_tables};

use crate::compute::DesiredTables;

/// One octet-width per table element.
const ADDRESS_ELEM_SIZE: usize = 2;
const ASSOCIATION_ELEM_SIZE: usize = 4;

/// The interface-object indexes located on the device for the two tables.
#[derive(Debug, Clone, Copy)]
pub struct TableObjectIndexes {
    /// Object index of the group-address table (object type 1).
    pub address: u8,
    /// Object index of the association table (object type 2).
    pub association: u8,
}

/// What the post-write verification found.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    /// The address-table object's final load state (must be `Loaded`).
    pub address_state: LoadState,
    /// The association-table object's final load state (must be `Loaded`).
    pub association_state: LoadState,
    /// Whether the read-back address table equals the desired one.
    pub addresses_match: bool,
    /// Whether the read-back association table equals the desired one.
    pub associations_match: bool,
}

impl VerifyOutcome {
    /// The whole apply verified: both loaded and both byte-equal to desired.
    pub fn ok(&self) -> bool {
        self.address_state == LoadState::Loaded
            && self.association_state == LoadState::Loaded
            && self.addresses_match
            && self.associations_match
    }
}

/// Discovers the two table objects' indexes by probing `PID_OBJECT_TYPE`.
///
/// Mirrors the read side's discovery (contiguously-indexed interface objects,
/// first empty read ends the sweep).
pub async fn discover_table_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<TableObjectIndexes, WriteError> {
    let mut address = None;
    let mut association = None;
    for index in 0..16u8 {
        let payload = bussard_mgmt::apci::encode_property_value_read(index, PID_OBJECT_TYPE, 1, 1);
        let (resp_apci, data) = l4
            .request(bussard_mgmt::apci::A_PROPERTY_VALUE_READ, &payload)
            .await?;
        if resp_apci != bussard_mgmt::apci::A_PROPERTY_VALUE_RESPONSE {
            break;
        }
        let Some(resp) = bussard_mgmt::apci::decode_property_value_response(&data) else {
            break;
        };
        if resp.count == 0 || resp.data.len() < 2 {
            break;
        }
        let ot = u16::from_be_bytes([resp.data[0], resp.data[1]]);
        if ot == OT_ADDRESS_TABLE && address.is_none() {
            address = Some(index);
        }
        if ot == OT_ASSOCIATION_TABLE && association.is_none() {
            association = Some(index);
        }
    }
    match (address, association) {
        (Some(address), Some(association)) => Ok(TableObjectIndexes {
            address,
            association,
        }),
        _ => Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "device is missing the address or association table object".to_string(),
            },
        )),
    }
}

/// Writes `desired` to the device and verifies the result.
///
/// Runs the ordered download sequence (see the module docs), then reads both
/// tables back and compares them byte-for-byte to `desired`. Returns the
/// [`VerifyOutcome`]; the caller treats `!ok()` as a hard failure.
///
/// This is the only function that mutates the device. It is exercised by the
/// mock-device tests and, in production, only from `bussard apply` after a plan
/// has been shown, confirmed, and backed up.
pub async fn apply_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
    desired: &DesiredTables,
) -> Result<VerifyOutcome, WriteError> {
    let addr_elems = desired.address_elements();
    let assoc_elems = desired.association_elements();

    // 1 + 2: open both tables for writing.
    write_load_control(l4, objects.association, LoadControl::StartLoading).await?;
    write_load_control(l4, objects.address, LoadControl::StartLoading).await?;

    // 3: write the address table.
    write_table(l4, objects.address, ADDRESS_ELEM_SIZE, &addr_elems).await?;

    // 4: write the association table (TSAPs now index the new address content).
    write_table(l4, objects.association, ASSOCIATION_ELEM_SIZE, &assoc_elems).await?;

    // 5: complete the address load first (activate the GA table).
    let address_state = write_load_control(l4, objects.address, LoadControl::LoadCompleted).await?;

    // 6: complete the association load (activate the associations).
    let association_state =
        write_load_control(l4, objects.association, LoadControl::LoadCompleted).await?;

    // Verify: read both tables back and compare to the desired ones.
    let read_back = read_tables(l4)
        .await
        .map_err(|e| WriteError::Mgmt(map_tables_err(e)))?;

    let addresses_match = read_back.addresses == desired.addresses;
    let associations_match = read_back.associations == desired.associations;

    Ok(VerifyOutcome {
        address_state,
        association_state,
        addresses_match,
        associations_match,
    })
}

/// Reads both table objects' current load states — used by callers that want to
/// confirm a device is healthy before/after a write.
pub async fn read_states<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
) -> Result<(LoadState, LoadState), WriteError> {
    let a = read_load_state(l4, objects.address).await?;
    let b = read_load_state(l4, objects.association).await?;
    Ok((a, b))
}

/// Collapses a [`bussard_mgmt::tables::TablesError`] from the read-back into an
/// [`bussard_mgmt::MgmtError`] for the write-side error type.
fn map_tables_err(e: bussard_mgmt::tables::TablesError) -> bussard_mgmt::MgmtError {
    use bussard_mgmt::tables::TablesError;
    match e {
        TablesError::Mgmt(m) => m,
        other => bussard_mgmt::MgmtError::MalformedResponse {
            // Fold the underlying tables-error detail into the reason so the
            // caller's message carries it. Keep the address for context.
            address: address_of(&other),
            reason: format!("verification read-back failed: {other}"),
        },
    }
}

/// Best-effort extraction of the device address from a tables error for the
/// remapped verification failure.
fn address_of(e: &bussard_mgmt::tables::TablesError) -> bussard_model::IndividualAddress {
    use bussard_mgmt::tables::TablesError;
    match e {
        TablesError::UnsupportedMask { address, .. }
        | TablesError::TableUnreadable { address, .. } => *address,
        TablesError::Mgmt(_) => "0.0.0".parse().expect("valid zero address"),
    }
}

/// Re-export for callers that drive the load machine directly (tests).
pub use load::PID_LOAD_STATE_CONTROL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_outcome_requires_everything() {
        let base = VerifyOutcome {
            address_state: LoadState::Loaded,
            association_state: LoadState::Loaded,
            addresses_match: true,
            associations_match: true,
        };
        assert!(base.ok());

        let mut bad = base.clone();
        bad.address_state = LoadState::Error;
        assert!(!bad.ok());

        let mut bad = base.clone();
        bad.associations_match = false;
        assert!(!bad.ok());
    }
}
