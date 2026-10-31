//! Reading a **System 7** (mask 0705 / 0701) device's live link tables back over
//! the bus — the read side of `bussard plan` / `apply` / `reconstruct` for the
//! family [`bussard_mgmt::tables`] does not serve.
//!
//! System B exposes its loadable tables as interface-object property arrays.
//! System 7 does not: it is memory-mapped and absolute-addressed, and the tables
//! live at fixed 16-bit addresses (`[system7-spec §2.2/§2.3]`, `[corpus: 49/49]`)
//!
//! - `0x4000` — the LSM 1 table region: the address table (GrAT);
//! - `0x4201` — the LSM 2 table region: the association table (GrOAT).
//!
//! The group-object descriptor table is not in either region. A System 7
//! program declares it (`<ComObjectTable>`) in an application segment of its
//! own: the Ekinex EK-E72 at `0x41D8`, the Jung `A-2088` at `0x43FF`. The octets
//! behind the address table are the unused rest of its segment (the EK-E72's
//! read `08 05 08 06 …`, never descriptors), so they are neither decoded nor
//! carried along.
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
//! # Where the tables are
//!
//! The device's own `PID_TABLE_REFERENCE` (objects 1 and 2) wins: the Jung 0705
//! devices answer it. A device that does not answer is read where its product's
//! load procedure allocates LSM 1 and LSM 2 ([`crate::sys7_table_bases`], passed
//! to [`read_sys7_tables_at`]), as ETS takes them from the product: most MDT /
//! Theben / Zennio programs use `0x4000` / `0x4201`, but the Jung and Siemens
//! 0705 programs put the association table at `0x41FF` and the MDT
//! `M-0083_A-0041-14` (0701) at `0x4041`. Without a product (`reconstruct`, a
//! backup) the corpus defaults `0x4000` and `0x4201` are the last resort
//! (`[corpus: 49/49]` of the first sample, `[system7-spec §2.3]`). A wrong base is
//! never mis-decoded as a link set past the region, because a count that does
//! not fit the region is refused and an unwritten region reads back as
//! `CNT = 0`, but it does read the wrong octets as the table (#369).
//!
//! A product with `DynamicTableManagement` (the Jung `A-2088`, the Theben
//! Meteodata) has no fixed association base: ETS writes the association table
//! directly behind the address table (#383), so without the device's answer
//! it is read where the address table ends.
//!
//! # How far the address table may grow
//!
//! The address table may fill its LSM 1 segment and no more: the product's
//! segment size, else up to the association table the device reports or the
//! product places. A declared group-object table inside that span ends it
//! too. When none of these is known (no product data, and a device that does
//! not answer `PID_TABLE_REFERENCE`), the segment's end is unknown: the corpus
//! region would reach past the EK-E72's group-object table at `0x41D8`, so the
//! table is bounded at its current length and a plan says so.
//! [`Sys7LiveTables::address_capacity`] carries the bound, and both the read
//! and `apply` refuse a table past it.
//!
//! # The group-object table
//!
//! Read where the product declares it ([`Sys7TableBases::object_table`]),
//! for the communication flags `apply` keeps in step with the links. Without
//! product data its place is unknown and it is not read. A read the device
//! refuses, or an image that does not decode, leaves the flags unchecked with
//! a note; the address and association tables are still read.
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

use crate::flash::Sys7TableBases;

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
    /// `PID_TABLE_REFERENCE` of object 2, else the product's base, the end of
    /// the address table for a packed product, or [`SYS7_ASSOCIATION_TABLE_ADDR`].
    /// The Jung 0705 products place it at `0x41FF`, right after a 511-octet
    /// address segment; the constant assumed 513 (issue #89, 1.1.32).
    pub association_base: u16,
    /// Set when the product packs the association table directly behind the
    /// address table (`DynamicTableManagement`,
    /// [`Sys7TableBases::packed_end`]): a write moves it with the address
    /// table's length, and both tables end before this address.
    pub packed_end: Option<u16>,
    /// The device's own individual address, from address-table entry 0 (TSAP 0).
    pub own_ia: u16,
    /// The most octets the address table may take at [`Self::address_base`]
    /// (see the module docs): the product's LSM 1 segment size, else the gap
    /// to the association table, else the table's current length.
    pub address_capacity: usize,
    /// The most octets the association table may take at
    /// [`Self::association_base`] when it does not move with the address table:
    /// the product's LSM 2 segment size, else the region constant, and never
    /// past a declared group-object table.
    pub association_capacity: usize,
    /// Where the group-object descriptor table starts, as the product declares
    /// it ([`Sys7TableBases::object_table`]). `None` without product data: the
    /// table was not read.
    pub group_object_base: Option<u16>,
    /// The group-object table image exactly as read
    /// (`[CNT:1][RAM-flags ptr:2][descriptor:4]…`), or empty when it was not read.
    pub group_object_image: Vec<u8>,
    /// The decoded group-object descriptors, descriptor `k` for com-object `k`.
    pub group_objects: Vec<Sys7GroupObject>,
    /// The application identity a write's TaskSegment records carry, from the
    /// product ([`Sys7TableBases::task_identity`]); `None` without product data.
    pub task_identity: Option<bussard_mgmt::Sys7TaskIdentity>,
    /// The product's LSM 1 segment op ([`Sys7TableBases::address_segment`]):
    /// the allocation record a write sends for the address table.
    pub address_segment: Option<crate::flash::Sys7SegmentOp>,
    /// The product's LSM 2 segment op
    /// ([`Sys7TableBases::association_segment`]).
    pub association_segment: Option<crate::flash::Sys7SegmentOp>,
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
    read_sys7_tables_at(l4, Sys7TableBases::default()).await
}

/// [`read_sys7_tables`] with the table bases the device's product allocates
/// ([`crate::sys7_table_bases`]) as the fallback when the device does not
/// answer `PID_TABLE_REFERENCE`, in place of the corpus defaults. A product
/// that puts its association table at `0x41FF` otherwise reads back from
/// `0x4201`, two octets into the table, and a write would land there too.
pub async fn read_sys7_tables_at<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    bases: Sys7TableBases,
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
    let address_base = table_base(
        l4,
        1,
        bases.address.unwrap_or(SYS7_ADDRESS_TABLE_ADDR),
        &mut notes,
    )
    .await;
    // A product with `DynamicTableManagement` keeps its association table
    // directly behind the address table (issue #383), so without the device's
    // answer its base follows from the address table read below.
    let association_fallback = match (bases.packed_end, bases.association) {
        (Some(_), _) => "the address table's end".to_string(),
        (None, Some(at)) => format!("{at:#06X}"),
        (None, None) => format!("{SYS7_ASSOCIATION_TABLE_ADDR:#06X}"),
    };
    let association_device = device_table_base(l4, 2, &association_fallback, &mut notes).await;
    // Where the association table is known to start: the device's answer or the
    // product's base. The corpus default is only a guess.
    let association_known = association_device.or(bases.association);
    let association_reported = if bases.packed_end.is_some() {
        association_device
    } else {
        Some(association_known.unwrap_or(SYS7_ASSOCIATION_TABLE_ADDR))
    };

    // --- LSM 1 region: the address table ---
    let declared_capacity = address_capacity(address_base, association_known, bases);
    let read_capacity = declared_capacity.unwrap_or(SYS7_ADDRESS_REGION_LEN);
    let addr_image =
        read_counted_table(l4, address_base, read_capacity, sys7_address_table_span).await?;
    let (own_ia, addresses) = decode_sys7_address_table(&addr_image, read_capacity)
        .map_err(|source| Sys7TablesError::Decode { address, source })?;
    // Without product data, and with a device that does not report its
    // association table, the end of the address segment is unknown: the corpus
    // region reaches past a group-object table the EK-E72 keeps at 0x41D8. The
    // table may then be rewritten at its current length but not grown.
    let address_capacity = match declared_capacity {
        Some(capacity) => capacity,
        None => {
            notes.push(format!(
                "the address table's segment end is unknown (no product data, and the device \
                 does not report its association table), so a write may not grow it past its \
                 current {} entries; pin the device's product to add group addresses",
                addresses.len()
            ));
            addr_image.len()
        }
    };

    if own_ia != address.raw() {
        // The own-IA slot (TSAP 0) is the device's individual address. Neither
        // ETS nor bussard (`flash` and `apply`, issue #588) ever writes it, so a
        // device keeps whatever its segment held, commonly the vendor's
        // placeholder `0000`. Worth reporting, never worth refusing.
        notes.push(format!(
            "the address table's own-IA slot reads {own_ia:04X}, not {address} \
             ({:04X}); ETS and bussard leave that slot to the device",
            address.raw()
        ));
    }

    let address_end = address_base.wrapping_add(addr_image.len() as u16);
    let association_base = association_reported.unwrap_or(address_end);

    // --- the group-object table, where the product declares it ---
    let (group_object_base, group_object_image, group_objects) = match bases.object_table {
        Some(at) => {
            let read = read_counted_table(
                l4,
                at,
                SYS7_GROUP_OBJECT_TABLE_MAX,
                sys7_group_object_table_span,
            )
            .await;
            // The tables bussard writes are the address and association
            // tables; this one only feeds the communication flags. A device that
            // refuses the read (an access level, a range it does not map) must
            // not take the plain table read down with it, so any failure here
            // becomes a note and the flags go unchecked.
            let decoded = match read {
                Ok(image) => decode_sys7_group_object_table(&image, SYS7_GROUP_OBJECT_TABLE_MAX)
                    .map(|(_ram_ptr, objects)| (image, objects))
                    .map_err(|err| format!("not decodable ({err})")),
                Err(Sys7TablesError::Decode { source, .. }) => {
                    Err(format!("not decodable ({source})"))
                }
                Err(err) => Err(format!("not readable ({err})")),
            };
            match decoded {
                Ok((image, objects)) => (Some(at), image, objects),
                Err(why) => {
                    notes.push(format!(
                        "group-object table at {at:#06X} {why}; communication flags are \
                         not checked"
                    ));
                    (None, Vec::new(), Vec::new())
                }
            }
        }
        None => (None, Vec::new(), Vec::new()),
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
            group_objects: group_object_image.first().map(|c| u16::from(*c)),
        },
        own_ia,
        address_capacity,
        association_capacity: association_capacity(association_base, bases),
        address_base,
        association_base,
        packed_end: bases.packed_end,
        group_object_base,
        group_object_image,
        group_objects,
        task_identity: bases.task_identity,
        address_segment: bases.address_segment,
        association_segment: bases.association_segment,
    })
}

/// The most octets a group-object table can take: `CNT` is one octet, so 255
/// descriptors of 4 octets behind the 3-octet header.
const SYS7_GROUP_OBJECT_TABLE_MAX: usize = SYS7_GROUP_OBJECT_HEADER_LEN + 255 * 4;

/// How many octets the address table at `address_base` may take (see the module
/// docs): the product's LSM 1 segment, else up to the association table the
/// device or the product places (`association`). A packed product's two tables
/// share the span to [`Sys7TableBases::packed_end`]. A declared group-object
/// table inside the span ends it. `None` when nothing bounds the segment: the
/// caller then keeps the table at its current length.
fn address_capacity(
    address_base: u16,
    association: Option<u16>,
    bases: Sys7TableBases,
) -> Option<usize> {
    let base = usize::from(address_base);
    let gap_to = |end: u16| usize::from(end).checked_sub(base).filter(|n| *n > 0);
    let capacity = match bases.packed_end {
        Some(end) => gap_to(end),
        None => bases
            .address_size
            .map(usize::from)
            .or_else(|| association.and_then(gap_to)),
    };
    match (capacity, bases.object_table.and_then(gap_to)) {
        (Some(capacity), Some(to_objects)) => Some(capacity.min(to_objects)),
        (capacity, to_objects) => capacity.or(to_objects),
    }
}

/// The bound on the association table at `base` (see
/// [`Sys7LiveTables::association_capacity`]).
fn association_capacity(base: u16, bases: Sys7TableBases) -> usize {
    let segment = bases
        .association_size
        .map_or(SYS7_ASSOCIATION_REGION_LEN, usize::from);
    let to_objects = bases
        .object_table
        .and_then(|end| usize::from(end).checked_sub(usize::from(base)))
        .filter(|n| *n > 0);
    to_objects.map_or(segment, |gap| segment.min(gap))
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
    let fallback = format!("{default:#06X}");
    device_table_base(l4, object_index, &fallback, notes)
        .await
        .unwrap_or(default)
}

/// The start of a table object's segment as the device reports it through
/// `PID_TABLE_REFERENCE`, or `None` when the property is not readable (the
/// normal shape for a device or mock without PID 7 on its table objects,
/// silently) or names an address outside the System 7 table window (with a
/// note naming `fallback`, what the caller uses instead).
async fn device_table_base<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    fallback: &str,
    notes: &mut Vec<String>,
) -> Option<u16> {
    match read_table_reference(l4, object_index).await {
        Ok(base) if (0x4000..0x8000).contains(&base) => Some(base as u16),
        Ok(base) => {
            notes.push(format!(
                "object {object_index} reports table reference {base:#06X}, outside the \
                 System 7 table window; using {fallback}"
            ));
            None
        }
        Err(_) => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bases() -> Sys7TableBases {
        Sys7TableBases::default()
    }

    #[test]
    fn test_association_capacity_takes_the_product_segment() {
        let e72 = Sys7TableBases {
            association_size: Some(235),
            object_table: Some(0x41D8),
            ..Default::default()
        };
        assert_eq!(association_capacity(0x40ED, e72), 235);
    }

    #[test]
    fn test_association_capacity_stops_at_the_group_object_table() {
        let declared = Sys7TableBases {
            object_table: Some(0x41D8),
            ..Default::default()
        };
        assert_eq!(association_capacity(0x40ED, declared), 0x41D8 - 0x40ED);
    }

    #[test]
    fn test_association_capacity_falls_back_to_the_region() {
        assert_eq!(
            association_capacity(0x4201, Sys7TableBases::default()),
            SYS7_ASSOCIATION_REGION_LEN
        );
    }

    #[test]
    fn test_address_capacity_takes_the_product_segment() {
        // The EK-E72: 237 octets at 0x4000, the association table right behind.
        let e72 = Sys7TableBases {
            address_size: Some(237),
            object_table: Some(0x41D8),
            ..bases()
        };
        assert_eq!(address_capacity(0x4000, Some(0x40ED), e72), Some(237));
    }

    #[test]
    fn test_address_capacity_stops_at_the_association_table() {
        // No product segment size: the association table bounds it.
        assert_eq!(address_capacity(0x4000, Some(0x40ED), bases()), Some(237));
    }

    #[test]
    fn test_address_capacity_is_unknown_without_a_bound() {
        // No product data and no usable association base: the caller keeps the
        // table at its current length rather than assume the corpus region.
        assert_eq!(address_capacity(0x4000, None, bases()), None);
        assert_eq!(address_capacity(0x4000, Some(0x3F00), bases()), None);
    }

    #[test]
    fn test_address_capacity_ends_at_a_declared_object_table() {
        // A group-object table declared inside the address segment ends it, so a
        // longer address table can never run into the descriptors.
        let inside = Sys7TableBases {
            address_size: Some(0x201),
            object_table: Some(0x4040),
            ..bases()
        };
        assert_eq!(address_capacity(0x4000, None, inside), Some(0x40));
        // It bounds the table on its own too.
        let only_objects = Sys7TableBases {
            object_table: Some(0x41D8),
            ..bases()
        };
        assert_eq!(address_capacity(0x4000, None, only_objects), Some(0x1D8));
    }

    #[test]
    fn test_address_capacity_shares_a_packed_span() {
        let packed = Sys7TableBases {
            packed_end: Some(0x43FE),
            address_size: Some(31),
            ..bases()
        };
        assert_eq!(address_capacity(0x4000, None, packed), Some(0x3FE));
    }
}
