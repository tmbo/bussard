//! Reading a **System 7** (mask 0705 / 0701) device's live link tables back over
//! the bus — the read side of `bussard plan` / `apply` / `reconstruct` for the
//! family [`bussard_mgmt::tables`] does not serve.
//!
//! System B exposes its loadable tables as interface-object property arrays.
//! System 7 does not: it is memory-mapped and absolute-addressed, and the tables
//! live at fixed 16-bit addresses (`[system7-spec §2.2/§2.3]`, `[corpus: 49/49]`)
//!
//! - `0x4000` — the LSM 1 table region: the address table (GrAT) followed by the
//!   group-object descriptor table;
//! - `0x4201` — the LSM 2 table region: the association table (GrOAT).
//!
//! So this module reads raw memory with `A_Memory_Read` in 12-octet chunks (the
//! System 7 standard-frame floor, `[system7-spec §6]`) and decodes it with the
//! very decoders that invert the synthesizers in [`crate::compute_sys7`] — one
//! definition of the byte layout for both directions.
//!
//! # Bounding every read
//!
//! Each table starts with a one-octet `CNT`. A count octet a download never wrote
//! (`0xFF` on virgin EEPROM) or a read at the wrong base would otherwise make
//! bussard pull a kilobyte of neighbouring device memory and decode noise as
//! links. Every read here is therefore two-phase: fetch `CNT`, ask
//! [`crate::compute_sys7`] for the span it implies **bounded by the region's own
//! size**, and refuse an absurd count before a single further octet is read.
//!
//! # The addresses are the corpus defaults, not product data
//!
//! `plan` / `apply` / `reconstruct` run without a `.knxprod`: there is no
//! `HawkConfigurationData` and no segment `Address` attribute to resolve the
//! table bases from, so this reader uses the corpus-wide defaults `0x4000` and
//! `0x4201` (`[corpus: 49/49]`, `[system7-spec §2.3]`). Every MDT / Theben /
//! Zennio app in the corpus places its tables there, but a device whose product
//! puts them elsewhere reads back as an empty table set rather than as links —
//! it is never mis-decoded, because a count that does not fit the region is
//! refused and an unwritten region reads back as `CNT = 0`. Pointing the reader
//! at a product-resolved base is the follow-up (`S7-CAL:` / issue #49 M1.5);
//! until then a device with no readable tables at these bases must be programmed
//! with `bussard flash`.
//!
//! The result is a [`bussard_mgmt::tables::DeviceTables`] — the same shape the
//! System B reader produces — so `plan`, the `reconstruct` report and the
//! `apply` backup all work on System 7 unchanged.
//!
//! Everything here is **read-only on the bus**.

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{WriteError, read_memory, read_table_reference};
use bussard_mgmt::tables::{DeviceTables, ResolvedLink, TableSource};
use bussard_mgmt::{MaskProfile, apci};
use bussard_model::IndividualAddress;

use crate::compute_sys7::{
    SYS7_ADDRESS_REGION_LEN, SYS7_ADDRESS_TABLE_ADDR, SYS7_ASSOCIATION_REGION_LEN,
    SYS7_ASSOCIATION_TABLE_ADDR, SYS7_COUNT_LEN, SYS7_GROUP_OBJECT_HEADER_LEN, Sys7DecodeError,
    Sys7GroupObject, decode_sys7_address_table, decode_sys7_association_table,
    decode_sys7_group_object_table, sys7_address_table_span, sys7_association_table_span,
    sys7_group_object_table_span,
};

/// Reading a System 7 device's tables failed.
#[derive(Debug, thiserror::Error)]
pub enum Sys7TablesError {
    /// The device is not System 7 (mask `x705` / `x701`).
    #[error(
        "{address} reports mask {mask:04X}: not a System 7 device (the System 7 table reader speaks mask 0705 / 0701)"
    )]
    NotSystem7 {
        /// The device.
        address: IndividualAddress,
        /// The mask version it reported.
        mask: u16,
    },
    /// A table image on the device could not be decoded.
    #[error("{address}: {source}")]
    Decode {
        /// The device.
        address: IndividualAddress,
        /// What was wrong with the image.
        source: Sys7DecodeError,
    },
    /// An underlying management error (absent, NAK, disconnect, malformed).
    #[error(transparent)]
    Mgmt(#[from] WriteError),
}

/// Everything read back from a live System 7 device's table regions.
///
/// [`Sys7LiveTables::tables`] is the System-B-shaped view `plan` and the
/// `reconstruct` report consume; the remaining fields carry the System 7 specifics
/// `apply` needs to rewrite the LSM 1 region without disturbing the device's
/// group-object descriptors.
#[derive(Debug, Clone)]
pub struct Sys7LiveTables {
    /// The decoded tables in the shared [`DeviceTables`] shape.
    pub tables: DeviceTables,
    /// Where the LSM 1 region (address table) starts: the device's
    /// `PID_TABLE_REFERENCE` of object 1, else [`SYS7_ADDRESS_TABLE_ADDR`].
    pub address_base: u16,
    /// Where the LSM 2 region (association table) starts: the device's
    /// `PID_TABLE_REFERENCE` of object 2, else [`SYS7_ASSOCIATION_TABLE_ADDR`].
    /// The Jung 0705 products place it at `0x41FF`, right after a 511-octet
    /// address segment; the constant assumed 513 (issue #89, 1.1.32).
    pub association_base: u16,
    /// The device's own individual address, from address-table entry 0 (TSAP 0).
    pub own_ia: u16,
    /// Where the group-object descriptor table starts: immediately after the
    /// address table inside the LSM 1 region.
    pub group_object_base: u16,
    /// The group-object table image exactly as read
    /// (`[CNT:1][RAM-flags ptr:2][descriptor:4]…`), or empty when the device has
    /// none. `apply` re-writes these bytes verbatim at their new offset when the
    /// address table changes length.
    pub group_object_image: Vec<u8>,
    /// The decoded group-object descriptors (1-based by ASAP, gaps preserved).
    pub group_objects: Vec<Sys7GroupObject>,
}

/// Reads and decodes a System 7 device's address, group-object and association
/// tables.
///
/// The caller owns an authorized layer-4 connection (System 7 gates memory access
/// behind `A_Authorize`, `[system7-spec §6]`). The mask is re-read here and
/// refused unless it is System 7, so this can never be pointed at a System B
/// device by accident.
pub async fn read_sys7_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Sys7LiveTables, Sys7TablesError> {
    let address = l4.target();
    let mask = device_descriptor(l4).await?;
    if !MaskProfile::from_mask(mask).is_system_7() {
        return Err(Sys7TablesError::NotSystem7 { address, mask });
    }

    let mut notes = Vec::new();

    // The table regions live where the device says they do: each table object's
    // `PID_TABLE_REFERENCE` names its segment start (the Jung 0705 devices expose
    // PID 7 on objects 1 and 2). The spec constants are only the fallback for a
    // device that does not answer.
    let address_base = table_base(l4, 1, SYS7_ADDRESS_TABLE_ADDR, &mut notes).await;
    let association_base = table_base(l4, 2, SYS7_ASSOCIATION_TABLE_ADDR, &mut notes).await;

    // --- LSM 1 region: address table, then the group-object table ---
    let addr_image = read_counted_table(
        l4,
        address_base,
        SYS7_ADDRESS_REGION_LEN,
        sys7_address_table_span,
    )
    .await?;
    let (own_ia, addresses) = decode_sys7_address_table(&addr_image, SYS7_ADDRESS_REGION_LEN)
        .map_err(|source| Sys7TablesError::Decode { address, source })?;

    if own_ia != address.raw() {
        // The own-IA slot (TSAP 0) is the device's individual address. A System 7
        // download streams the product's static segment image, which carries the
        // vendor's placeholder there, so a freshly flashed device commonly reads
        // back `0000` until something writes the real one. Worth reporting, never
        // worth refusing.
        notes.push(format!(
            "the address table's own-IA slot reads {own_ia:04X}, not {address} \
             ({:04X}) — a vendor placeholder a table write will correct",
            address.raw()
        ));
    }

    // The group-object descriptor table sits immediately after the address table
    // in the same LSM 1 region (`[system7-spec §2.3/§7]`: the 0x4000 region holds
    // "address / com-object descriptors"). Its base therefore moves with the
    // address table's length — which is exactly why `apply` rewrites the whole
    // region rather than the address table alone.
    // `S7-CAL: confirm the group-object table's placement inside the 0x4000
    // region (co-located after the GrAT vs a fixed sub-address) against a live
    // 0705 read-back.`
    let group_object_base = address_base.wrapping_add(addr_image.len() as u16);
    let go_capacity = SYS7_ADDRESS_REGION_LEN.saturating_sub(addr_image.len());
    let (group_object_image, group_objects) = if go_capacity >= SYS7_GROUP_OBJECT_HEADER_LEN {
        match read_counted_table(
            l4,
            group_object_base,
            go_capacity,
            sys7_group_object_table_span,
        )
        .await
        {
            Ok(image) => match decode_sys7_group_object_table(&image, go_capacity) {
                Ok((_ram_ptr, objects)) => (image, objects),
                Err(err) => {
                    notes.push(format!(
                        "group-object table at {group_object_base:#06X} not decodable ({err}); \
                         its descriptors are left untouched"
                    ));
                    (Vec::new(), Vec::new())
                }
            },
            Err(Sys7TablesError::Decode { source, .. }) => {
                notes.push(format!(
                    "group-object table at {group_object_base:#06X} not decodable ({source}); \
                     its descriptors are left untouched"
                ));
                (Vec::new(), Vec::new())
            }
            Err(err) => return Err(err),
        }
    } else {
        notes.push(format!(
            "no room for a group-object table after the {}-octet address table",
            addr_image.len()
        ));
        (Vec::new(), Vec::new())
    };

    // --- LSM 2 region: the association table ---
    let assoc_image = read_counted_table(
        l4,
        association_base,
        SYS7_ASSOCIATION_REGION_LEN,
        sys7_association_table_span,
    )
    .await?;
    let associations = decode_sys7_association_table(&assoc_image, SYS7_ASSOCIATION_REGION_LEN)
        .map_err(|source| Sys7TablesError::Decode { address, source })?;

    // Resolve (TSAP, ASAP) into (com-object, GA). Three kinds of entry are not
    // links and are counted, not turned into one:
    //
    // - **TSAP 0** is the own-IA slot (`[system7-spec §7.1]`), never a group link;
    // - an **unprogrammed GA slot** — `0x0000` (`0/0/0` is not assignable) or any
    //   value with D15 set (reserved, `[system7-spec §7.1]`). This is what keeps
    //   virgin memory from being read back as links: an erased EEPROM region is
    //   all `0xFF`, so its count octet claims 255 entries (which the region
    //   genuinely has room for) and every slot reads `0xFFFF` — a reserved-bit
    //   value, not a group address. A blank flash region reads all-zero and hits
    //   the same guard from the other side;
    // - a TSAP **past the address table** is a dangling entry.
    //
    // Each kind gets one summary note rather than one note per entry, so an
    // unprogrammed device produces a readable report, not 255 lines.
    let mut resolved = Vec::with_capacity(associations.len());
    let (mut own_ia_slots, mut unprogrammed, mut dangling) = (0usize, 0usize, 0usize);
    for &(tsap, asap) in &associations {
        if tsap == 0 {
            own_ia_slots += 1;
            continue;
        }
        match addresses.get(usize::from(tsap - 1)) {
            Some(ga) if ga.raw() == 0 || ga.raw() & 0x8000 != 0 => unprogrammed += 1,
            Some(ga) => resolved.push(ResolvedLink {
                object: asap,
                ga: *ga,
            }),
            None => {
                let _ = asap;
                dangling += 1;
            }
        }
    }
    if own_ia_slots > 0 {
        notes.push(format!(
            "{own_ia_slots} association entry/entries with TSAP 0 (the own-IA slot) skipped"
        ));
    }
    if unprogrammed > 0 {
        notes.push(format!(
            "{unprogrammed} association entry/entries point at an unprogrammed \
             address-table slot (0000, or a reserved D15); skipped"
        ));
    }
    if dangling > 0 {
        notes.push(format!(
            "{dangling} association entry/entries point past the {}-entry address \
             table; skipped",
            addresses.len()
        ));
    }

    Ok(Sys7LiveTables {
        tables: DeviceTables {
            mask,
            addresses,
            associations,
            resolved,
            sources: vec![
                ("addresses", TableSource::Memory),
                ("associations", TableSource::Memory),
            ],
            notes,
        },
        own_ia,
        group_object_base,
        group_object_image,
        group_objects,
    })
}

/// Reads one `CNT`-prefixed System 7 table at `base`, bounded by `capacity`.
///
/// Two phases: the count octet first, then exactly the span it declares. `span_of`
/// is the table's own span function from [`crate::compute_sys7`], which refuses a
/// count the region cannot hold before any further octet is read.
async fn read_counted_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    base: u16,
    capacity: usize,
    span_of: fn(u8, usize) -> Result<usize, Sys7DecodeError>,
) -> Result<Vec<u8>, Sys7TablesError> {
    let address = l4.target();
    let head = read_memory(l4, u32::from(base), SYS7_COUNT_LEN as u8).await?;
    let cnt = head
        .first()
        .copied()
        .ok_or_else(|| Sys7TablesError::Mgmt(empty_read(l4, base)))?;
    let span =
        span_of(cnt, capacity).map_err(|source| Sys7TablesError::Decode { address, source })?;
    read_region(l4, base, span).await.map_err(Into::into)
}

/// Reads `len` octets at `base` in 12-octet chunks (the System 7 standard-frame
/// memory-read cap, `[system7-spec §6]`).
pub async fn read_region<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    base: u16,
    len: usize,
) -> Result<Vec<u8>, WriteError> {
    let chunk = usize::from(l4.max_memory_chunk()).max(1);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let take = chunk.min(len - out.len());
        let at = base.wrapping_add(out.len() as u16);
        let piece = read_memory(l4, u32::from(at), take as u8).await?;
        if piece.len() < take {
            return Err(empty_read(l4, at));
        }
        out.extend_from_slice(&piece[..take]);
    }
    Ok(out)
}

/// The error for a memory read that came back short or empty.
fn empty_read<Ch: L4Channel>(l4: &Layer4Connection<Ch>, at: u16) -> WriteError {
    WriteError::Mgmt(bussard_mgmt::MgmtError::MalformedResponse {
        address: l4.target(),
        reason: format!("A_Memory_Read at {at:#06X} returned fewer octets than requested"),
    })
}

/// Reads the device descriptor (mask version) on an open connection.
/// The start of a table object's segment as the device reports it through
/// `PID_TABLE_REFERENCE`, or `default` (with a note) when the property is not
/// readable or names an address outside the System 7 table window.
async fn table_base<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    default: u16,
    notes: &mut Vec<String>,
) -> u16 {
    match read_table_reference(l4, object_index).await {
        Ok(base) if (0x4000..0x8000).contains(&base) => base as u16,
        Ok(base) => {
            notes.push(format!(
                "object {object_index} reports table reference {base:#06X}, outside the \
                 System 7 table window; using {default:#06X}"
            ));
            default
        }
        Err(_) => {
            notes.push(format!(
                "object {object_index} has no readable PID_TABLE_REFERENCE; using {default:#06X}"
            ));
            default
        }
    }
}

async fn device_descriptor<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<u16, Sys7TablesError> {
    let (req_apci, payload) = apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4
        .request(req_apci, &payload)
        .await
        .map_err(|e| Sys7TablesError::Mgmt(WriteError::Mgmt(e)))?;
    if resp_apci & apci::APCI_SELECTOR_MASK != apci::A_DEVICE_DESCRIPTOR_RESPONSE || data.len() < 2
    {
        return Err(Sys7TablesError::Mgmt(WriteError::Mgmt(
            bussard_mgmt::MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!(
                    "expected A_DeviceDescriptor_Response, got APCI {resp_apci:#05X} with \
                     {} octet(s)",
                    data.len()
                ),
            },
        )));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}
