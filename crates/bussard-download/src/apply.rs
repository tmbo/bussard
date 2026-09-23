//! Executing a plan over the bus: the load-state download sequence.
//!
//! [`apply_tables`] drives the write side of [`bussard_mgmt::load`] against a
//! live (or mock) System B device: it opens both loadable table objects,
//! allocates a backing segment for each, streams the new address and association
//! table images into those segments, completes the loads, and verifies the result
//! by reading the tables back and comparing them byte-for-byte to the desired
//! tables.
//!
//! # How a table is realised: allocate + memory write, never `PID_TABLE`
//!
//! A loadable table lives in the object's **allocated segment**, not in a
//! writable property array. `PID_TABLE` (PID 23) is readable on most devices,
//! but it is not a download path.
//!
//! This cost a field session to learn (issue #89 campaign). `bussard apply`
//! against a Jung F50 push-button module (52911ST, application
//! `M-0004_A-D141-22`) failed: the device **rejected** the
//! `A_PropertyValue_Write` to `PID_TABLE` with a zero-count response — it wrote
//! nothing and echoed no elements (`wrote [00, 04], device echoed []`). Two
//! independent ETS captures then confirmed ETS never uses that path: for a Jung
//! F50 sibling at 1.1.18 and for the KNX Virtual DA.tp, ETS follows each
//! `StartLoading` with a 10-octet `AdditionalLoadControls` / `LdCtrlRelSegment`
//! write (size = the 2-octet count word plus `n * elem_size`), reads
//! `PID_TABLE_REFERENCE` for the placement, streams the image with
//! `A_Memory_Write` / `A_MemoryExtended_Write`, and only then sends
//! `LoadCompleted`. Only the lenient KNX Virtual stack *also* accepts property
//! writes to `PID_TABLE`, which is why bussard's mock and the simulator let the
//! bug through until both were taught the real behaviour.
//!
//! The image written into a segment is the count word followed by the elements
//! (`table_image`) — the same layout [`read_tables`]'s memory path reads back,
//! so the verification agrees whichever path the device serves.
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
//! 0. Read `PID_MAX_APDU_LENGTH` once (ETS's first operation in every session)
//!    so the image writes below are chunked to the device's APDU budget.
//! 1. `StartLoading` the **association** table (→ `Loading`).
//! 2. Allocate its segment (`LdCtrlRelSegment`, sized `2 + 4 * associations`) and
//!    read the placement from `PID_TABLE_REFERENCE`.
//! 3. `StartLoading` the **address** table (→ `Loading`).
//! 4. Allocate its segment (sized `2 + 2 * addresses`) and read its placement.
//! 5. Write the new **address** image (count word + elements) into its segment
//!    with `A_Memory_Write` / `A_MemoryExtended_Write`, chunked to the negotiated
//!    APDU.
//! 6. Write the new **association** image the same way. Its TSAPs now index the
//!    just-written address content.
//! 7. `LoadCompleted` the **address** table (→ `Loaded`).
//! 8. `LoadCompleted` the **association** table (→ `Loaded`).
//!
//! The allocation sits immediately after each `StartLoading` because that is
//! where ETS puts it in both captures, and because the standard only dispatches
//! `AdditionalLoadControls` from the `Loading` state.
//!
//! Both objects are in `Loading` before either is written, so no
//! partially-updated table is ever *active*: a device evaluates group telegrams
//! against a table only in the `Loaded` state (per the KNX load-state machine in
//! KNX Spec 3/5/1, a table object persists and activates its content on
//! `LoadCompleted`; a `Loading` object is inactive).
//! Completing the address table before the association table guarantees the
//! association table is only activated once the address table it points into is
//! already valid. This mirrors what ETS does for a differential link download.
//!
//! # Failure handling
//!
//! There is no clean rollback mid-write: once an object is in `Loading`, a
//! failure leaves it unloaded/inactive until re-applied. [`apply_tables`] never
//! swallows an error — every failure surfaces with the object and step that
//! failed. A device that refuses the allocation (segment too large, out of
//! memory) drops the object into `Error`, which surfaces before a single octet of
//! table content is sent. `bussard apply` prints the backup path and recovery
//! guidance loudly on any error, so a half-applied device is never left silent.
//! Recovery is re-running `apply` (idempotent — the tables are rewritten
//! wholesale) or ETS.

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    self, LoadControl, LoadState, WriteError, allocate_segment, read_load_state,
    write_load_control, write_memory_chunked,
};
use bussard_mgmt::tables::{OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, read_tables};

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
/// The sweep is [`bussard_mgmt::probe_object_types`], the same walk the read side
/// and the flash engine use — contiguously-indexed interface objects, ending at
/// the first index that answers "no object here".
pub async fn discover_table_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<TableObjectIndexes, WriteError> {
    let objects = bussard_mgmt::probe_object_types(l4).await?;
    let first = |want: u16| {
        objects
            .iter()
            .find(|&&(_, ot)| ot == want)
            .map(|&(index, _)| index)
    };
    match (first(OT_ADDRESS_TABLE), first(OT_ASSOCIATION_TABLE)) {
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
    apply_tables_secured(l4, objects, desired, None).await
}

/// [`apply_tables`] for a KNX Data Secure device (issue #156): with
/// `security`, the security object is reprogrammed for the new address table
/// (group key table indices follow it) after both table images are written and
/// before either table is completed, so the device never activates tables whose
/// keys point at the wrong entries. See
/// [`program_security_object`](crate::security::program_security_object).
pub async fn apply_tables_secured<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
    desired: &DesiredTables,
    security: Option<&crate::security::SecurityInputs>,
) -> Result<VerifyOutcome, WriteError> {
    let addr_elems = desired.address_elements();
    let assoc_elems = desired.association_elements();

    // 0: negotiate the APDU size before any table write (issue #116).
    negotiate_session_apdu(l4).await?;

    // 1 + 2: open both tables for writing, each followed by its `RelSegment`
    // allocation (ETS allocates right after each StartLoading — both captures).
    write_load_control(l4, objects.association, LoadControl::StartLoading).await?;
    let assoc_seg = allocate_table_segment(l4, objects.association, &assoc_elems).await?;
    write_load_control(l4, objects.address, LoadControl::StartLoading).await?;
    let addr_seg = allocate_table_segment(l4, objects.address, &addr_elems).await?;

    // 3: write the address table into its segment.
    write_table_image(l4, addr_seg, ADDRESS_ELEM_SIZE, &addr_elems).await?;

    // 4: write the association table (TSAPs now index the new address content).
    write_table_image(l4, assoc_seg, ASSOCIATION_ELEM_SIZE, &assoc_elems).await?;
    // 4b (Data Secure): reprogram the security object for the new address table.
    if let Some(inputs) = security {
        crate::security::program_security_object(l4, &desired.addresses, inputs).await?;
    }

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

/// Reads `PID_MAX_APDU_LENGTH` (device object, PID 56) once for this session so
/// the table writes are chunked to the device's real APDU budget.
///
/// ETS opens every download session with this property read, then streams the
/// tables in chunks sized to it (228 octets per `A_MemoryExtended_Write` on a
/// device advertising 233). Without it, the connection stays at the
/// standard-frame floor and a table above 0xFFFF goes out in 12-octet chunks
/// (issue #116). The value is cached on the connection, so calling this again
/// (the CLI already negotiates right after authorize) costs no telegram. A device
/// without the property keeps the conservative chunk sizes; only a dead
/// connection is an error.
pub async fn negotiate_session_apdu<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<u16>, WriteError> {
    l4.negotiate_max_apdu().await.map_err(WriteError::Mgmt)
}

/// The memory image of a loadable table: the big-endian `u16` element count
/// followed by the elements — the layout `PID_TABLE_REFERENCE` points at and
/// [`read_tables`]'s memory path reads back.
fn table_image(elem_size: usize, elements: &[u8]) -> Vec<u8> {
    debug_assert!(elem_size > 0 && elements.len() % elem_size == 0);
    let count = (elements.len() / elem_size) as u16;
    let mut image = Vec::with_capacity(2 + elements.len());
    image.extend_from_slice(&count.to_be_bytes());
    image.extend_from_slice(elements);
    image
}

/// Allocates the backing segment of a table object for `elements`: one
/// `AdditionalLoadControls` / `LdCtrlRelSegment` write sized to the whole image
/// (count word + elements), exactly as ETS does after every `StartLoading` of a
/// table object. The device places the segment and reports it through
/// `PID_TABLE_REFERENCE`.
async fn allocate_table_segment<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elements: &[u8],
) -> Result<load::SegmentAllocation, WriteError> {
    let size = (2 + elements.len()) as u32;
    allocate_segment(l4, object_index, size, None).await
}

/// Writes a table image (count word + elements) into its allocated segment with
/// `A_Memory_Write` / `A_MemoryExtended_Write`, chunked to the negotiated APDU.
async fn write_table_image<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    segment: load::SegmentAllocation,
    elem_size: usize,
    elements: &[u8],
) -> Result<(), WriteError> {
    let image = table_image(elem_size, elements);
    write_memory_chunked(l4, segment.address, &image, |_| {}).await
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
