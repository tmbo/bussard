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
//! # The partial download of the three tables (issue #1095)
//!
//! With the group-object table image known (product data, a link change),
//! `apply` runs the System B partial download "Group Communication" (KNX
//! 03_05_03 §3.9.3.5, the master data's `ProcedureSubType="grp"`), the one
//! ETS runs for a link change: unload the group-object,
//! association and address tables, reload all three (the group-object table
//! even when its image is unchanged), complete them and restart. The order is
//! on [`write_group_tables`]; the evidence is `captures/synthetic/syn-minimal/apply`
//! and `captures/synthetic/syn-secure/apply`. The sequence below remains for
//! a device without product data, whose group-object table bussard cannot
//! build.
//!
//! # Op-sequence ordering without product data (decision + rationale)
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
use crate::object_table::ObjectTableOutcome;

/// One octet-width per table element.
const ADDRESS_ELEM_SIZE: usize = 2;
/// Format 1 (`PDT_GENERIC_04`, Resources §4.17.5.2.5); the write path checks
/// the device's format before it writes.
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
    /// The group-object table write, when the write carried one (issues
    /// #540, #1095): its load state and whether it read back as written.
    pub object_table: Option<ObjectTableOutcome>,
    /// The group-object table's load state read after a write that did not
    /// load it (issue #1095): a device does not communicate while it is not
    /// `Loaded`. `None` when the write loaded it or the device has none.
    pub object_table_state: Option<LoadState>,
    /// The restart that ends the partial download of the three tables.
    pub restart: TableRestart,
}

impl VerifyOutcome {
    /// The whole apply verified: both loaded and both byte-equal to desired,
    /// a written group-object table loaded and read back as written, and an
    /// untouched one still `Loaded`. The restart is not part of it: it is
    /// sent only after this holds, and reported on its own.
    pub fn ok(&self) -> bool {
        self.address_state == LoadState::Loaded
            && self.association_state == LoadState::Loaded
            && self.addresses_match
            && self.associations_match
            && self
                .object_table
                .as_ref()
                .is_none_or(ObjectTableOutcome::ok)
            && self
                .object_table_state
                .is_none_or(|s| s == LoadState::Loaded)
    }
}

/// The restart that ends the partial download of the three tables
/// (`LdCtrlRestart`, issue #1095).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TableRestart {
    /// No restart belongs to the write (link tables alone, a reload of the
    /// group-object table alone, or a write that did not verify).
    #[default]
    NotDue,
    /// Due, and left to the parameter download that follows and restarts
    /// the device itself ([`SystemBLoad::defer_restart`]).
    Deferred,
    /// Sent in the write session. The device answers again at the earliest
    /// after `process_wait` (a confirmed restart's announced process time,
    /// zero for the basic one).
    Sent {
        /// How long the device said it needs.
        process_wait: std::time::Duration,
    },
    /// Due but not sent, refused or not confirmed: why. The device holds
    /// the tables, but the procedure is unfinished until it restarts.
    NotSent(String),
}

/// Whether `app` has memory above `0xFFFF` written and read with
/// `A_UserMemory_*` rather than `A_MemoryExtended_*`: it does not announce
/// `SupportsExtendedMemoryServices`, and ETS then uses the user-memory
/// services (issue #472; Configuration Procedures 03_05_03 §3.5.1.4). The one
/// rule the flash, `apply`, `backup` and the MCP tools share; no application
/// (no product data) keeps the extended service, as before.
pub fn uses_user_memory(app: Option<&bussard_product::ApplicationProgram>) -> bool {
    app.is_some_and(|app| !app.supports_extended_memory_services)
}

/// What a System B write loads besides the address and association tables.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBLoad<'a> {
    /// The KNX Data Secure security object to reprogram for the new address
    /// table (issue #156). Written inside the link-table download, so only
    /// when the link tables are loaded.
    pub security: Option<&'a crate::security::SecurityInputs>,
    /// The group-object table image the full flash writes (see
    /// [`crate::object_table`]). With the link tables it selects the partial
    /// download of the three tables (issue #1095); with
    /// [`SystemBLoad::keep_tables`] it is reloaded alone (issue #540).
    pub object_table: Option<&'a [u8]>,
    /// The link tables already hold the model: load only the group-object
    /// table, and read the link tables back unchanged.
    pub keep_tables: bool,
    /// The application does not announce extended memory services: a table
    /// above `0xFFFF` is written and read with `A_UserMemory_*` (issue #472).
    pub user_memory_above_64k: bool,
    /// The partial download ends with the confirmed restart (master reset,
    /// erase code 1) instead of the basic one: the application's
    /// [`crate::flash::restart_form`].
    pub confirmed_restart: bool,
    /// A parameter download follows and restarts the device itself: the
    /// partial download leaves its restart to it ([`TableRestart::Deferred`]).
    pub defer_restart: bool,
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
/// With [`SystemBLoad::security`] (a KNX Data Secure device, issue #156), the
/// security object is reprogrammed for the new address table (group key table
/// indices follow it) after both table images are written and before either
/// table is completed, so the device never activates tables whose keys point
/// at the wrong entries. See
/// [`program_security_object`](crate::security::program_security_object).
///
/// Three shapes, chosen by `load`:
///
/// - The link tables change and the group-object table image is given: the
///   partial download of the three tables ([`write_group_tables`], issue
///   #1095), ending with its restart in this session
///   ([`VerifyOutcome::restart`]).
/// - [`SystemBLoad::keep_tables`]: the group-object table, when given, is
///   reloaded alone in its own `StartLoading` / `LoadCompleted` bracket
///   ([`crate::object_table::write_object_table`], issue #540), and the link
///   tables are read back unchanged.
/// - No group-object table image (no product data, `restore`): the address
///   and association tables alone, in the order of the module docs. A
///   group-object table a failed download left not `Loaded` refuses it
///   before anything is sent, and the read-back includes its load state.
///
/// This is the only function that mutates the device. It is exercised by the
/// mock-device tests and, in production, only from `bussard apply` after a plan
/// has been shown, confirmed, and backed up.
pub async fn apply_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
    desired: &DesiredTables,
    load: SystemBLoad<'_>,
) -> Result<VerifyOutcome, WriteError> {
    // 0: negotiate the APDU size before any table write (issue #116).
    negotiate_session_apdu(l4).await?;
    l4.set_user_memory_above_64k(load.user_memory_above_64k);

    match (load.object_table, load.keep_tables) {
        // A link change with the group-object table image: the partial
        // download of the three tables (issue #1095).
        (Some(image), false) => {
            let index = object_table_index(l4).await?;
            let group = GroupTables {
                objects,
                object_table: index,
                object_image: image,
            };
            write_group_tables(l4, group, desired, load).await
        }
        // The link tables stay: the group-object table is reloaded alone
        // (issue #540), the link tables read back unchanged.
        (image, true) => {
            let (object_table, object_table_state) = match image {
                Some(image) => {
                    let index = object_table_index(l4).await?;
                    let written = crate::object_table::write_object_table(l4, index, image).await?;
                    (Some(written), None)
                }
                None => (None, object_table_state(l4).await?.map(|(_, s)| s)),
            };
            let (address_state, association_state) = read_states(l4, objects).await?;
            let read_back = read_tables(l4)
                .await
                .map_err(|e| WriteError::Mgmt(map_tables_err(e)))?;
            Ok(VerifyOutcome {
                address_state,
                association_state,
                addresses_match: read_back.addresses == desired.addresses,
                associations_match: read_back.associations == desired.associations,
                object_table,
                object_table_state,
                restart: TableRestart::NotDue,
            })
        }
        // No product data: the link tables alone, as before #1095.
        (None, false) => write_link_tables(l4, objects, desired, load.security).await,
    }
}

/// The address and association table download of the module docs, with the
/// security object between the images and the completions.
async fn write_link_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
    desired: &DesiredTables,
    security: Option<&crate::security::SecurityInputs>,
) -> Result<VerifyOutcome, WriteError> {
    let addr_elems = desired.address_elements();
    let assoc_elems = desired.association_elements();
    // The group-object table must be `Loaded`: a partial download that
    // failed after its `Unload` leaves it unloaded, and the link tables alone
    // would not bring the device back (issue #1095). Refused before anything
    // is sent.
    if let Some((index, state)) = object_table_state(l4).await?
        && state != LoadState::Loaded
    {
        return Err(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!(
                    "the group-object table (object {index}) is {state}, not Loaded: a table \
                 download that failed after its Unload left it so, and writing the link \
                 tables alone would leave the device silent; nothing was written. Apply from \
                 your project with the device's product data, or flash it"
                ),
            },
        ));
    }
    let security_program = preflight(l4, objects, desired, security).await?;

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
    if let Some(program) = &security_program {
        crate::security::write_security_program(l4, program).await?;
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
    let object_table_state = object_table_state(l4).await?.map(|(_, s)| s);

    Ok(VerifyOutcome {
        address_state,
        association_state,
        addresses_match,
        associations_match,
        object_table: None,
        object_table_state,
        restart: TableRestart::NotDue,
    })
}

/// What both table downloads check before anything is sent: the Data Secure
/// program against the table capacities (issue #537), so a program the
/// device cannot hold is refused with every object still loaded, and the
/// association table's format (format 1, four octets; Resources
/// §4.17.5.2.5, issue #545).
async fn preflight<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: TableObjectIndexes,
    desired: &DesiredTables,
    security: Option<&crate::security::SecurityInputs>,
) -> Result<Option<crate::security::SecurityProgram>, WriteError> {
    let security_program = match security {
        Some(inputs) => {
            Some(crate::security::prepare_security_program(l4, &desired.addresses, inputs).await?)
        }
        None => None,
    };
    let pdt = bussard_mgmt::tables::read_association_pdt(l4, objects.association).await;
    bussard_mgmt::tables::check_association_pdt(l4.target(), pdt).map_err(|e| {
        WriteError::Mgmt(bussard_mgmt::MgmtError::MalformedResponse {
            address: l4.target(),
            reason: e.to_string(),
        })
    })?;
    Ok(security_program)
}

/// The group-object table object and its load state, `None` when the device
/// lists no group-object table (type 9).
async fn object_table_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<(u8, LoadState)>, WriteError> {
    match crate::object_table::find_object_table(l4).await? {
        Some(index) => Ok(Some((index, read_load_state(l4, index).await?))),
        None => Ok(None),
    }
}

/// The group-object table (interface object type 9) of the device, refused
/// when the device has none.
async fn object_table_index<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<u8, WriteError> {
    crate::object_table::find_object_table(l4)
        .await?
        .ok_or_else(|| {
            WriteError::Mgmt(bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "device is missing the group-object table object (type 9)".to_string(),
            })
        })
}

/// The three table objects of the partial download and the group-object
/// table image it writes.
#[derive(Debug, Clone, Copy)]
struct GroupTables<'a> {
    /// The address and association table objects.
    objects: TableObjectIndexes,
    /// The group-object table object.
    object_table: u8,
    /// The group-object table image (count word and descriptors).
    object_image: &'a [u8],
}

/// The partial download of the address, association and group-object tables
/// (issue #1095): KNX 03_05_03 §3.9.3.5, Partial Download "Group
/// Communication", which every `knx_master.xml` declares for the System B
/// masks as `ProcedureSubType="grp"` and ETS runs for a link change
/// (`captures/synthetic/syn-minimal/apply`, ETS 6.4.1):
///
/// 1. `Unload` the group-object, association and address tables (LSM 3, 2,
///    1); on a Data Secure device the security object's `Unload` follows.
/// 2. `StartLoading` and `LdCtrlRelSegment` of the group-object table, the
///    address table, then the association table.
/// 3. The group-object table image, then the association table image
///    (`LdCtrlWriteRelMem` 3, 2). A Data Secure device's security object is
///    loaded next ([`crate::security::load_security_program`]), between the
///    association and the address table, where
///    `captures/synthetic/syn-secure/apply` has it.
/// 4. The address table image (`LdCtrlWriteRelMem` 1).
/// 5. `LoadCompleted` of the group-object, association and address tables.
/// 6. The three tables read back and compared with what was written. When
///    all of it verified, the restart that ends the procedure
///    (`LdCtrlRestart`), in this session and in the application's form
///    ([`SystemBLoad::confirmed_restart`]), unless a parameter download
///    follows and restarts the device ([`SystemBLoad::defer_restart`]). The
///    caller waits for the device and reads it back.
///
/// Every refusal that needs no write (the security program's capacity, the
/// association table format) comes before the first `Unload`.
async fn write_group_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    group: GroupTables<'_>,
    desired: &DesiredTables,
    load: SystemBLoad<'_>,
) -> Result<VerifyOutcome, WriteError> {
    let objects = group.objects;
    let addr_elems = desired.address_elements();
    let assoc_elems = desired.association_elements();
    let security_program = preflight(l4, objects, desired, load.security).await?;

    // 1: unload the three tables, then the security object.
    write_load_control(l4, group.object_table, LoadControl::Unload).await?;
    write_load_control(l4, objects.association, LoadControl::Unload).await?;
    write_load_control(l4, objects.address, LoadControl::Unload).await?;
    if security_program.is_some() {
        crate::security::security_transition(l4, LoadControl::Unload)
            .await
            .map_err(|err| crate::security::left_not_loaded(l4.target(), err))?;
    }

    // 2 + 3: open each table with its allocation, write the group-object and
    // association images, then load the security object. Until it is loaded
    // a failure leaves a Data Secure device deaf on its secured addresses,
    // and the error says so (issue #534).
    let opened: Result<load::SegmentAllocation, WriteError> = async {
        write_load_control(l4, group.object_table, LoadControl::StartLoading).await?;
        let object_seg = allocate_segment(
            l4,
            group.object_table,
            group.object_image.len() as u32,
            0,
            0,
        )
        .await?;
        write_load_control(l4, objects.address, LoadControl::StartLoading).await?;
        let addr_seg = allocate_table_segment(l4, objects.address, &addr_elems).await?;
        write_load_control(l4, objects.association, LoadControl::StartLoading).await?;
        let assoc_seg = allocate_table_segment(l4, objects.association, &assoc_elems).await?;
        write_memory_chunked(l4, object_seg.address, group.object_image, |_| {}).await?;
        write_table_image(l4, assoc_seg, ASSOCIATION_ELEM_SIZE, &assoc_elems).await?;
        if let Some(program) = &security_program {
            crate::security::load_security_program(l4, program).await?;
        }
        Ok(addr_seg)
    }
    .await;
    let addr_seg = match opened {
        Ok(seg) => seg,
        Err(err) if security_program.is_some() => {
            return Err(crate::security::left_not_loaded(l4.target(), err));
        }
        Err(err) => return Err(err),
    };

    // 4: the address image.
    write_table_image(l4, addr_seg, ADDRESS_ELEM_SIZE, &addr_elems).await?;

    // 5: complete the three loads.
    let object_state =
        write_load_control(l4, group.object_table, LoadControl::LoadCompleted).await?;
    let association_state =
        write_load_control(l4, objects.association, LoadControl::LoadCompleted).await?;
    let address_state = write_load_control(l4, objects.address, LoadControl::LoadCompleted).await?;

    // 6: read all three back; restart only what verified.
    let read_back = read_tables(l4)
        .await
        .map_err(|e| WriteError::Mgmt(map_tables_err(e)))?;
    let entries = crate::object_table::table_entry_count(group.object_image);
    let object_back =
        crate::object_table::read_object_table_at(l4, group.object_table, entries).await?;
    let mut outcome = VerifyOutcome {
        address_state,
        association_state,
        addresses_match: read_back.addresses == desired.addresses,
        associations_match: read_back.associations == desired.associations,
        object_table: Some(ObjectTableOutcome {
            state: object_state,
            matches: object_back.matches(group.object_image),
            entries,
        }),
        object_table_state: None,
        restart: TableRestart::NotDue,
    };
    outcome.restart = match (outcome.ok(), load.defer_restart) {
        (false, _) => TableRestart::NotDue,
        (true, true) => TableRestart::Deferred,
        (true, false) => send_restart(l4, load.confirmed_restart).await,
    };
    Ok(outcome)
}

/// Sends the restart that ends the partial download, in the write session
/// as ETS does: the bare `A_Restart`, or the confirmed one (master reset,
/// erase code 1, KNX 03_05_02 §3.7.1.2.3) whose `A_Restart_Response`
/// announces the process time ([`bussard_mgmt::restart_process_wait`]). A
/// restart that could not be sent, was refused or was not answered is
/// [`TableRestart::NotSent`], never a silent success.
async fn send_restart<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    confirmed: bool,
) -> TableRestart {
    if !confirmed {
        let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
        return match l4.send_data_unacked(apci, &payload).await {
            Ok(()) => TableRestart::Sent {
                process_wait: std::time::Duration::ZERO,
            },
            Err(err) => TableRestart::NotSent(format!("the restart could not be sent: {err}")),
        };
    }
    match bussard_mgmt::master_reset(l4, bussard_mgmt::apci::ERASE_CODE_CONFIRMED_RESTART, 0).await
    {
        Ok(response) => TableRestart::Sent {
            process_wait: bussard_mgmt::restart_process_wait(&response),
        },
        Err(err @ WriteError::RestartRefused { .. }) => {
            TableRestart::NotSent(format!("the device refused the restart: {err}"))
        }
        Err(err) => TableRestart::NotSent(format!("the restart was not confirmed: {err}")),
    }
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
pub(crate) async fn negotiate_session_apdu<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<u16>, WriteError> {
    l4.negotiate_max_apdu().await.map_err(WriteError::Mgmt)
}

/// The memory image of a loadable table: the big-endian `u16` element count
/// followed by the elements — the layout `PID_TABLE_REFERENCE` points at and
/// [`read_tables`]'s memory path reads back.
fn table_image(elem_size: usize, elements: &[u8]) -> Vec<u8> {
    debug_assert!(elem_size > 0 && elements.len().is_multiple_of(elem_size));
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
    allocate_segment(l4, object_index, size, 0x00, 0x00).await
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
pub(crate) async fn read_states<Ch: L4Channel>(
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
        | TablesError::UnsupportedAssociationFormat { address } => *address,
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
            object_table: None,
            object_table_state: None,
            restart: TableRestart::NotDue,
        };
        assert!(base.ok());

        let mut bad = base.clone();
        bad.object_table = Some(ObjectTableOutcome {
            state: LoadState::Loaded,
            matches: false,
            entries: 3,
        });
        assert!(!bad.ok());

        let mut bad = base.clone();
        bad.address_state = LoadState::Error;
        assert!(!bad.ok());

        let mut bad = base.clone();
        bad.associations_match = false;
        assert!(!bad.ok());
    }
}
