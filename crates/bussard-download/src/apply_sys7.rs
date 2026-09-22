//! Writing the model's link tables to a **System 7** (mask 0705 / 0701) device —
//! the write side of `bussard apply` for the family [`crate::apply`] does not
//! serve.
//!
//! System B opens two loadable interface objects and writes them as property
//! arrays. System 7 has no such objects: the tables are absolute memory regions
//! driven by two of the three parallel load-state machines
//! (`[system7-spec §2/§3]`):
//!
//! - **LSM 1** owns the `0x4000` region — the address table (GrAT) followed by
//!   the group-object descriptor table;
//! - **LSM 2** owns the `0x4201` region — the association table (GrOAT).
//!
//! So an `apply` here is the same shape as a download, restricted to the two
//! table LSMs: `Unload` both, `StartLoading` both, allocate each region as an
//! absolute Data segment, stream the images in 12-octet `A_Memory_Write` chunks
//! with a read-back verify per chunk, commit a `TaskSegment` descriptor, and
//! `LoadCompleted`. The parameter LSM (3) and the application image are never
//! touched — that is the whole point of the incremental path: a link change must
//! not reset parameters (issue #91).
//!
//! # Op-sequence ordering (decision + rationale)
//!
//! The same coupling as System B: the association table's TSAP column indexes the
//! address table, so a window where one is active against the other's old content
//! would orphan TSAPs. Both LSMs are therefore opened before either region is
//! written, and the address LSM is completed first:
//!
//! 1. `Unload` LSM 2, `Unload` LSM 1 — tear both down (spec §3, every corpus
//!    download unloads before loading).
//! 2. `StartLoading` LSM 2, `StartLoading` LSM 1 — both inactive and writable.
//! 3. Allocate + stream the **0x4000** region (new address table + the device's
//!    own group-object descriptors, relocated — see below).
//! 4. Allocate + stream the **0x4201** region (the association table, whose TSAPs
//!    now index the just-written address content).
//! 5. `TaskSegment` + `LoadCompleted` on LSM 1 (activate the address table).
//! 6. `TaskSegment` + `LoadCompleted` on LSM 2 (activate the associations).
//!
//! A device evaluates group telegrams against a table only in the `Loaded` state
//! (KNX 3/5/1 load-state machine), so no partially-updated table is ever active.
//!
//! # Why the whole 0x4000 region is rewritten, not just the address table
//!
//! The `0x4000` region holds the address table **and** the group-object
//! descriptor table, packed back to back (`[system7-spec §2.3]`: "address /
//! com-object descriptors"). The descriptor table's base therefore moves whenever
//! the address table's entry count changes. Writing only a longer address table
//! would bury the descriptors; writing only a shorter one would leave them
//! stranded at the old offset. `apply` reads the descriptors first
//! ([`crate::tables_sys7`]) and re-writes them verbatim at their new offset, so a
//! link change never disturbs what the download put there.
//! `S7-CAL: confirm the group-object table is co-located after the GrAT in the
//! 0x4000 region (rather than at a fixed sub-address) against a live 0705
//! read-back.`
//!
//! # Restart: not issued
//!
//! Every full System 7 download ends with a restart (`[corpus: 47/49]`,
//! `[system7-spec §6]`), but a restart is **not** part of table activation. The
//! KNX load-state machine activates a table object's content on `LoadCompleted`
//! (§4.1: `Loading --LoadCompleted--> Loaded`), and the corpus restart is the
//! terminal step of a procedure that also rewrote the **application and parameter
//! image** — the thing that genuinely needs a re-init. A table-only write leaves
//! the application untouched, so bussard does not restart: the device keeps
//! running, which is the entire value of the incremental path over a full flash.
//! `S7-CAL: confirm a real 0705/0701 device re-parses its GrAT/GrOAT on
//! LoadCompleted alone, with no restart — no capture of a table-only download
//! exists (ETS always rewrites the parameter image too).`

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{LoadControl, LoadState, WriteError, read_memory, write_memory};
use bussard_mgmt::sys7::{S7_SUB_ALLOC_DATA, encode_alloc_segment, encode_task_segment};
use bussard_mgmt::{LsmAccess, Sys7Profile, alloc_attr_octets};

use crate::compute::DesiredTables;
use crate::compute_sys7::{
    SYS7_ADDRESS_REGION_LEN, SYS7_ASSOCIATION_REGION_LEN, sys7_address_table,
    sys7_association_table,
};
use crate::tables_sys7::{Sys7LiveTables, read_region};

/// The load-state machine that owns the `0x4000` address-table region
/// (`[system7-spec §3]`).
pub const SYS7_ADDRESS_LSM: u8 = 1;
/// The load-state machine that owns the `0x4201` association-table region
/// (`[system7-spec §3]`).
pub const SYS7_ASSOCIATION_LSM: u8 = 2;

/// Applying the System 7 tables failed.
#[derive(Debug, thiserror::Error)]
pub enum Sys7ApplyError {
    /// The computed image does not fit the memory region it must live in.
    #[error(
        "the computed System 7 {table} image is {len} octets but its region at {base:#06X} holds only {capacity} — refusing to write past the segment"
    )]
    RegionOverflow {
        /// Which region (`address`, `association`).
        table: &'static str,
        /// The region base.
        base: u16,
        /// The image length.
        len: usize,
        /// The region's capacity in octets.
        capacity: usize,
    },
    /// A written chunk did not read back as written.
    #[error(
        "the System 7 {table} image did not read back as written at {addr:#06X} (wrote {expected:02X?}, read {got:02X?})"
    )]
    VerifyMismatch {
        /// Which image.
        table: &'static str,
        /// The chunk address.
        addr: u16,
        /// What was written.
        expected: Vec<u8>,
        /// What the device answered.
        got: Vec<u8>,
    },
    /// An underlying management / load error.
    #[error(transparent)]
    Write(#[from] WriteError),
}

/// The two region images `apply` will write, computed from the model and the
/// device's live group-object descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sys7TableImages {
    /// Where the LSM 1 region starts on this device ([`Sys7LiveTables::address_base`]).
    pub address_base: u16,
    /// Where the LSM 2 region starts on this device
    /// ([`Sys7LiveTables::association_base`]).
    pub association_base: u16,
    /// The whole LSM 1 region image: the new address table followed by the
    /// device's own group-object descriptor table, relocated to its new offset.
    pub address_region: Vec<u8>,
    /// How many leading octets of `address_region` are the address table itself.
    pub address_table_len: usize,
    /// The `0x4201` association-table image.
    pub association_image: Vec<u8>,
    /// The group-object table's base before and after, when the address table's
    /// length moved it. `None` when it did not move (or the device has none).
    pub group_object_moved: Option<(u16, u16)>,
}

/// What the post-write verification found.
#[derive(Debug, Clone)]
pub struct Sys7VerifyOutcome {
    /// LSM 1's final load state (must be [`LoadState::Loaded`]).
    pub address_state: LoadState,
    /// LSM 2's final load state (must be [`LoadState::Loaded`]).
    pub association_state: LoadState,
    /// Whether the `0x4000` region read back byte-for-byte.
    pub addresses_match: bool,
    /// Whether the `0x4201` region read back byte-for-byte.
    pub associations_match: bool,
}

impl Sys7VerifyOutcome {
    /// The whole apply verified: both LSMs loaded and both regions byte-equal.
    pub fn ok(&self) -> bool {
        self.address_state == LoadState::Loaded
            && self.association_state == LoadState::Loaded
            && self.addresses_match
            && self.associations_match
    }
}

/// Computes the two region images from the model's desired tables and the
/// device's live state.
///
/// `own_ia` goes into address-table slot 0 (TSAP 0, `[system7-spec §7.1]`) and is
/// the **address bussard is talking to**, not the value decoded off the device:
/// a System 7 download streams the product's static segment image, which carries
/// whatever own-IA slot the vendor shipped (commonly `0x0000`), and `A_Memory`
/// is the only thing that ever fixes it up. Writing the connected address is the
/// only value that can be right.
///
/// The group-object descriptors are carried over verbatim from `live` at their
/// new offset (see the module docs). Both images are refused if they do not fit
/// their region.
pub fn sys7_table_images(
    live: &Sys7LiveTables,
    desired: &DesiredTables,
    own_ia: u16,
) -> Result<Sys7TableImages, Sys7ApplyError> {
    let address_table = sys7_address_table(own_ia, desired);
    let address_table_len = address_table.len();
    let mut address_region = address_table;
    address_region.extend_from_slice(&live.group_object_image);
    if address_region.len() > SYS7_ADDRESS_REGION_LEN {
        return Err(Sys7ApplyError::RegionOverflow {
            table: "address",
            base: live.address_base,
            len: address_region.len(),
            capacity: SYS7_ADDRESS_REGION_LEN,
        });
    }

    let association_image = sys7_association_table(desired);
    if association_image.len() > SYS7_ASSOCIATION_REGION_LEN {
        return Err(Sys7ApplyError::RegionOverflow {
            table: "association",
            base: live.association_base,
            len: association_image.len(),
            capacity: SYS7_ASSOCIATION_REGION_LEN,
        });
    }

    let new_go_base = live.address_base.wrapping_add(address_table_len as u16);
    let group_object_moved = (!live.group_object_image.is_empty()
        && new_go_base != live.group_object_base)
        .then_some((live.group_object_base, new_go_base));

    Ok(Sys7TableImages {
        address_base: live.address_base,
        association_base: live.association_base,
        address_region,
        address_table_len,
        association_image,
        group_object_moved,
    })
}

/// Writes the two table regions to a System 7 device and verifies the result.
///
/// Runs the ordered sequence in the module docs on an **already authorized**
/// layer-4 connection (System 7 gates memory access behind `A_Authorize`), then
/// re-reads both regions and both LSM states. The caller treats
/// `!outcome.ok()` as a hard failure.
///
/// This is the only function here that mutates the device. It is exercised by the
/// mock-device tests and, in production, only from `bussard apply` after a plan
/// has been shown, confirmed and backed up.
pub async fn apply_sys7_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    lsm: &LsmAccess,
    profile: &Sys7Profile,
    images: &Sys7TableImages,
    task_marker: [u8; 4],
) -> Result<Sys7VerifyOutcome, Sys7ApplyError> {
    // 1: tear both table LSMs down.
    lsm.drive(l4, SYS7_ASSOCIATION_LSM, LoadControl::Unload)
        .await?;
    lsm.drive(l4, SYS7_ADDRESS_LSM, LoadControl::Unload).await?;

    // 2: open both before either is written (the orphaned-TSAP guard).
    lsm.drive(l4, SYS7_ASSOCIATION_LSM, LoadControl::StartLoading)
        .await?;
    lsm.drive(l4, SYS7_ADDRESS_LSM, LoadControl::StartLoading)
        .await?;

    // 3: the LSM 1 region — allocate exactly what will be written, then stream.
    alloc_region(
        l4,
        lsm,
        profile,
        SYS7_ADDRESS_LSM,
        images.address_base,
        images.address_region.len(),
    )
    .await?;
    write_verified(l4, "address", images.address_base, &images.address_region).await?;

    // 4: the LSM 2 region — its TSAPs index the content just written.
    alloc_region(
        l4,
        lsm,
        profile,
        SYS7_ASSOCIATION_LSM,
        images.association_base,
        images.association_image.len(),
    )
    .await?;
    write_verified(
        l4,
        "association",
        images.association_base,
        &images.association_image,
    )
    .await?;

    // 5: finalize and activate the address table first.
    lsm.send_control(
        l4,
        SYS7_ADDRESS_LSM,
        &encode_task_segment(images.address_base, task_marker),
    )
    .await?;
    let address_state = lsm
        .drive(l4, SYS7_ADDRESS_LSM, LoadControl::LoadCompleted)
        .await?;

    // 6: then the association table.
    lsm.send_control(
        l4,
        SYS7_ASSOCIATION_LSM,
        &encode_task_segment(images.association_base, task_marker),
    )
    .await?;
    let association_state = lsm
        .drive(l4, SYS7_ASSOCIATION_LSM, LoadControl::LoadCompleted)
        .await?;

    // Verify by reading both regions back off the loaded device.
    let addr_back = read_region(l4, images.address_base, images.address_region.len()).await?;
    let assoc_back =
        read_region(l4, images.association_base, images.association_image.len()).await?;

    Ok(Sys7VerifyOutcome {
        address_state,
        association_state,
        addresses_match: addr_back == images.address_region,
        associations_match: assoc_back == images.association_image,
    })
}

/// Sends the absolute Data-segment allocation record for one table region
/// (`[system7-spec §4.2]`), sized to exactly the image about to be streamed.
///
/// Allocating the written span (rather than the whole region) keeps the device's
/// own bound check honest: nothing outside the image is claimed, so a later read
/// of a stale byte past the table is out of segment on a device that enforces it.
async fn alloc_region<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    lsm: &LsmAccess,
    profile: &Sys7Profile,
    index: u8,
    base: u16,
    len: usize,
) -> Result<(), WriteError> {
    let mem_type = profile.eeprom_mem_type;
    let (seg_flags, checksum_ctrl) = alloc_attr_octets(mem_type);
    let record = encode_alloc_segment(
        S7_SUB_ALLOC_DATA,
        base,
        len.min(usize::from(u16::MAX)) as u16,
        seg_flags,
        mem_type,
        checksum_ctrl,
    );
    lsm.send_control(l4, index, &record).await
}

/// Streams `image` to `base` in 12-octet `A_Memory_Write` chunks, reading each
/// chunk back and comparing before the next one goes out
/// (`[system7-spec §6]`: `A_Memory_Write` is unconfirmed, so read-back is the
/// only verification).
///
/// A differential link write is tiny (tens of octets), so the doubled exchange
/// count is cheap insurance against a device that silently drops or truncates a
/// chunk — and it fails at the offending chunk rather than after the whole table
/// has been streamed on top of it.
async fn write_verified<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    table: &'static str,
    base: u16,
    image: &[u8],
) -> Result<(), Sys7ApplyError> {
    let chunk = usize::from(l4.max_memory_chunk()).max(1);
    let mut offset = 0usize;
    while offset < image.len() {
        let take = chunk.min(image.len() - offset);
        let at = base.wrapping_add(offset as u16);
        let piece = &image[offset..offset + take];
        write_memory(l4, u32::from(at), piece).await?;
        let got = read_memory(l4, u32::from(at), take as u8).await?;
        if got != piece {
            return Err(Sys7ApplyError::VerifyMismatch {
                table,
                addr: at,
                expected: piece.to_vec(),
                got,
            });
        }
        offset += take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::compute_tables;
    use bussard_mgmt::tables::DeviceTables;
    use bussard_model::schema::Link;

    fn live(own_ia: u16, go_image: Vec<u8>, go_base: u16) -> Sys7LiveTables {
        Sys7LiveTables {
            tables: DeviceTables {
                mask: 0x0705,
                addresses: Vec::new(),
                associations: Vec::new(),
                resolved: Vec::new(),
                sources: Vec::new(),
                notes: Vec::new(),
            },
            address_base: crate::compute_sys7::SYS7_ADDRESS_TABLE_ADDR,
            association_base: crate::compute_sys7::SYS7_ASSOCIATION_TABLE_ADDR,
            own_ia,
            group_object_base: go_base,
            group_object_image: go_image,
            group_objects: Vec::new(),
        }
    }

    fn desired_one_link() -> DesiredTables {
        compute_tables(&[Link {
            object: 1,
            name: None,
            send: Some("1/0/1".parse().expect("a GA")),
            listen: Vec::new(),
        }])
    }

    #[test]
    fn test_sys7_table_images_relocates_the_group_object_table() {
        // The device had an empty address table (CNT 1, own IA only) with its
        // group-object table at 0x4003; the model adds one GA, so the address
        // table grows by two octets and the descriptors move with it.
        let go = vec![0x01, 0x07, 0x00, 0x07, 0x5C, 0xDF, 0x03];
        let live = live(0x1105, go.clone(), 0x4003);
        let images = sys7_table_images(&live, &desired_one_link(), 0x1105).expect("images");
        assert_eq!(images.address_table_len, 5, "CNT + own IA + one GA");
        assert_eq!(images.group_object_moved, Some((0x4003, 0x4005)));
        assert_eq!(
            &images.address_region[..5],
            &[0x01 + 1, 0x11, 0x05, 0x08, 0x01]
        );
        assert_eq!(
            &images.address_region[5..],
            &go[..],
            "the descriptors are carried over verbatim at their new offset"
        );
        assert_eq!(images.association_image, vec![0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_sys7_table_images_refuses_an_oversized_region() {
        // A group-object table that already fills the region leaves no room for a
        // growing address table: refuse rather than write past 0x4201.
        let live = live(0x1105, vec![0u8; SYS7_ADDRESS_REGION_LEN], 0x4001);
        let err = sys7_table_images(&live, &desired_one_link(), 0x1105)
            .expect_err("an oversized region is refused");
        assert!(
            matches!(
                err,
                Sys7ApplyError::RegionOverflow {
                    table: "address",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn test_verify_outcome_requires_everything() {
        let base = Sys7VerifyOutcome {
            address_state: LoadState::Loaded,
            association_state: LoadState::Loaded,
            addresses_match: true,
            associations_match: true,
        };
        assert!(base.ok());
        let mut bad = base.clone();
        bad.association_state = LoadState::Error;
        assert!(!bad.ok());
        let mut bad = base.clone();
        bad.addresses_match = false;
        assert!(!bad.ok());
    }
}
