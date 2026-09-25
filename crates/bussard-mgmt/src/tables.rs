//! System B (mask `07B0`) table read-back: group-address and association
//! tables via interface-object properties.
//!
//! This module implements the read side of KNX "loadable table objects" — the
//! on-device tables ETS downloads when it programs group communication. On
//! System B devices these are exposed as interface objects addressed by
//! **object index** through `A_PropertyValue_Read`:
//!
//! - the **group address table** (object type 1) lists every GA the device is
//!   subscribed to,
//! - the **association table** (object type 2) maps those GAs (by table index,
//!   the *TSAP*) to com-objects (by group-object-table index, the *ASAP*),
//! - the **group object table** (object type 9) holds per-com-object flags and
//!   sizes; its layout is manufacturer/profile-dependent, so this module only
//!   counts its entries and otherwise skips it gracefully.
//!
//! # On-device layout (evidence)
//!
//! The layouts implemented here follow the published KNX interface-object
//! property semantics (EN 50090 / KNX standard 3/4/1 "Interface Objects" +
//! 3/5/1 "Resources"), cross-checked against live captures from a real System B
//! (mask 07B0) device. Only published-spec layout facts and observed wire
//! behaviour inform this module. Evidence:
//!
//! - **Property arrays** (KNX 3/4/1, `A_PropertyValue_Read` semantics): reading
//!   a property with `start = 0, count = 1` returns the current number of
//!   elements as a big-endian `u16`; the elements themselves are 1-based, read
//!   from `start = 1` upward.
//! - **Group address table** (object type 1, KNX 3/5/1 "Address Table Object"):
//!   a big-endian `u16` array whose word 0 is the **entry count** — *not* the
//!   device's own individual address (that convention belongs to older
//!   realisation types). Word `tsap` holds the GA, so **TSAPs are 1-based** and
//!   TSAP 1 is the first GA.
//! - **Association table** (object type 2, KNX 3/5/1 "Association Table
//!   Object"): word 0 is the entry count; each entry is 4 octets, big-endian
//!   **TSAP first, then ASAP** (entry `idx` occupies words `2·idx+1` and
//!   `2·idx+2`). TSAP indexes the group address table (1-based, as above); ASAP
//!   indexes the group object table, also 1-based.
//! - **ASAP → com-object number**: the ASAP **is** the ETS com-object number
//!   (`object = asap`, no offset). Verified live against a Jung 23024 actuator
//!   (mask 07B0) whose links are an ETS-import ground truth: the read
//!   ASAPs 20, 21, 22, 38, … align GA-for-GA with the model's object numbers,
//!   while an `asap - 1` mapping shifts every single pair off by one. (A device
//!   stack's internal 1-based array storage is a private implementation detail,
//!   not the ETS numbering domain the wire exposes.)
//! - **`PID_TABLE` vs memory**: `PID_TABLE` is the *global* PID **23** (KNX
//!   3/5/1 global property table; PID 52 is `PID_KNX_INDIVIDUAL_ADDRESS` of the
//!   IP parameter object, not a table PID). Loadable table content is primarily
//!   served through **memory**: element 1 of `PID_TABLE_REFERENCE` (7) answers
//!   the table's memory address (the same address domain `A_Memory_Read`
//!   serves) and the table blob starts with the big-endian `u16` entry count
//!   followed by the entries. The element count is read from `PID_TABLE`
//!   element 0 first. The entries then come from memory when one span read at
//!   the negotiated memory chunk takes fewer requests than `PID_TABLE` reads of
//!   15 elements (issue #223), with the memory count word checked against the
//!   property count; a missing reference, a refused read or a mismatch falls back
//!   to the property array. A device that exposes no `PID_TABLE` count reads the
//!   count from memory too. [`DeviceTables::sources`] reports which path worked.
//! - **Group object table** (object type 9, KNX 3/5/1): word 0 is the entry
//!   count; word `asap` is a packed big-endian `u16` descriptor (low byte = DPT
//!   size code, high bits = comm/read/write/transmit/update flags). Only the
//!   count is read here; the per-entry decode (and with it the send/listen
//!   distinction) is out of scope, so the table is skipped gracefully when
//!   unreadable.
//!
//! # Wire encodings (why this module drives [`Layer4Connection`] directly)
//!
//! Two management services embed request parameters in the **low bits of the
//! APCI octet** rather than in payload octets:
//!
//! - `A_DeviceDescriptor_Read`: the descriptor type occupies the low 6 APCI
//!   bits; the request carries **no** payload octet. Verified live against the
//!   Jung 23024: a request with an extra `0x00` payload octet is T_ACKed and
//!   then answered with `T_Disconnect` (present but refusing), while the
//!   correct one-octet APDU is answered with `A_DeviceDescriptor_Response`
//!   `07B0`.
//! - `A_Memory_Read`: the octet count occupies the low 6 APCI bits, followed
//!   by exactly two address octets; the response echoes the count in its APCI
//!   low bits followed by address + data octets.
//!
//! Both encodings are produced by the shared [`crate::apci`] helpers, through the
//! crate's single descriptor reader ([`crate::connection::read_device_descriptor`])
//! and single memory module ([`crate::memory`]) — the same ones
//! [`DeviceConnection`](crate::DeviceConnection) and the download engine use — so
//! every path agrees on the wire form. A table whose `PID_TABLE_REFERENCE` points
//! above `0xFFFF` is read with `A_MemoryExtended_Read` instead of the plain
//! service; the selection is per address, inside [`crate::memory`]. This module drives a borrowed [`Layer4Connection`] directly
//! (rather than a [`DeviceConnection`](crate::DeviceConnection)) because
//! `read_tables` operates on the caller's live connection.
//!
//! Everything here is **read-only** on the bus and preserves the crate's
//! absent-vs-refusing distinction: transport-level failures surface as
//! [`MgmtError`]; a device that answers but does not expose a readable table
//! surfaces as [`TablesError::TableUnreadable`].

use crate::connection::{L4Channel, Layer4Connection, property_request};
use crate::error::{MgmtError, SilenceKind};
use bussard_model::{GroupAddress, IndividualAddress};

// --- Identifiers not (yet) in `apci.rs` ---
// Defined locally per the standard's interface-object resource definitions;
// dedup into `apci.rs` later.

/// `PID_OBJECT_TYPE` (1) — the interface object's type, a `u16` per element.
///
/// Re-exported from [`crate::connection`], which owns the discovery walk that
/// reads it.
pub use crate::connection::PID_OBJECT_TYPE;
/// `PID_TABLE_REFERENCE` (7) — memory address of a loadable table.
pub const PID_TABLE_REFERENCE: u8 = 7;
/// `PID_TABLE` (23) — the loadable table exposed as a property array.
///
/// 23 is the global "Table" PID (KNX 3/5/1 global property definitions); it is
/// **not** 52, which is `PID_KNX_INDIVIDUAL_ADDRESS` of the IP parameter object.
pub const PID_TABLE: u8 = 23;

/// Object type of the device object.
pub const OT_DEVICE: u16 = 0;
/// Object type of the group address table.
pub const OT_ADDRESS_TABLE: u16 = 1;
/// Object type of the association table.
pub const OT_ASSOCIATION_TABLE: u16 = 2;
/// Object type of the application program.
pub const OT_APPLICATION_PROGRAM: u16 = 3;
/// Object type of the group object table.
pub const OT_GROUP_OBJECT_TABLE: u16 = 9;

/// Which read path produced a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSource {
    /// Read as a `PID_TABLE` property array.
    Property,
    /// Read from memory via `PID_TABLE_REFERENCE`.
    Memory,
}

impl std::fmt::Display for TableSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TableSource::Property => write!(f, "property (PID_TABLE)"),
            TableSource::Memory => write!(f, "memory (PID_TABLE_REFERENCE)"),
        }
    }
}

/// One association resolved against the address table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLink {
    /// The com-object number (equals the association's ASAP — see the module
    /// docs on the ASAP domain).
    pub object: u16,
    /// The group address the com-object is linked to.
    pub ga: GroupAddress,
}

/// Everything read back from one device's tables.
#[derive(Debug, Clone)]
pub struct DeviceTables {
    /// The mask version the device reported (always `0x07B0` on success).
    pub mask: u16,
    /// The group address table, in table order (`addresses[0]` is TSAP 1).
    pub addresses: Vec<GroupAddress>,
    /// The raw association table as `(tsap, asap)` pairs, in table order.
    pub associations: Vec<(u16, u16)>,
    /// The associations resolved to com-object → GA links.
    pub resolved: Vec<ResolvedLink>,
    /// Which path produced each table: `(table name, source)`.
    pub sources: Vec<(&'static str, TableSource)>,
    /// Human-readable notes (group-object-table status, skipped entries, …).
    pub notes: Vec<String>,
}

/// Errors from table read-back, wrapping the management-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum TablesError {
    /// The device is not System B; only mask `07B0` is supported for now.
    #[error(
        "{address} reports mask {mask:04X}: unsupported (`bussard reconstruct` speaks the System B family / mask x7B0 only for now)"
    )]
    UnsupportedMask {
        /// The device.
        address: IndividualAddress,
        /// The mask version it reported.
        mask: u16,
    },

    /// The device answered but a required table could not be read on any path.
    #[error("{address}: {reason}")]
    TableUnreadable {
        /// The device.
        address: IndividualAddress,
        /// Which table failed, and how.
        reason: String,
    },

    /// An underlying management error (absent, NAK, disconnect, malformed).
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
}

/// Result alias for table read-back.
pub type Result<T> = std::result::Result<T, TablesError>;

/// Reads a System B device's group-address and association tables and resolves
/// them to com-object → GA links.
///
/// Reads the device descriptor first and refuses non-`07B0` masks with
/// [`TablesError::UnsupportedMask`]. Discovery is dynamic: object indexes are
/// probed for `PID_OBJECT_TYPE` to locate the tables — nothing is hardcoded to
/// a fixed index. Each table's count comes from `PID_TABLE`; its entries come
/// from `PID_TABLE_REFERENCE` + memory when that takes fewer requests, from the
/// `PID_TABLE` property array otherwise or when the memory read is refused (see
/// `read_table`); `sources` records which path worked.
pub async fn read_tables<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<DeviceTables> {
    let address = l4.target();
    let mask = device_descriptor(l4).await?;
    // Route the mask gate through the central profile seam. Today only System B
    // has a table reader; System 7 (issue #49) will branch here on
    // `profile.uses_memory_mapped_tables()` / `profile.requires_authorize()`.
    let profile = crate::MaskProfile::from_mask(mask);
    if !profile.tables_supported() {
        return Err(TablesError::UnsupportedMask { address, mask });
    }

    // Size the `PID_TABLE` reads from the device's max APDU (issue #194): a
    // no-op when the caller already negotiated or seeded it, one property read
    // otherwise. A device without the property keeps the standard-frame floor;
    // a dead connection surfaces on the next read.
    let _ = l4.negotiate_max_apdu().await;
    let objects = discover_objects(l4).await?;
    let mut notes = Vec::new();
    let mut sources = Vec::new();

    let addr_index = find_object(&objects, OT_ADDRESS_TABLE).ok_or_else(|| {
        TablesError::TableUnreadable {
            address,
            reason: format!(
                "no group address table object (type {OT_ADDRESS_TABLE}) among {} interface object(s)",
                objects.len()
            ),
        }
    })?;
    let assoc_index = find_object(&objects, OT_ASSOCIATION_TABLE).ok_or_else(|| {
        TablesError::TableUnreadable {
            address,
            reason: format!(
                "no association table object (type {OT_ASSOCIATION_TABLE}) among {} interface object(s)",
                objects.len()
            ),
        }
    })?;

    // Group address table: 2-octet elements, each one GA.
    let (addr_bytes, addr_source) = read_table(l4, addr_index, 2, "group address table").await?;
    sources.push(("addresses", addr_source));
    let addresses: Vec<GroupAddress> = addr_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| GroupAddress::from_raw(u16::from_be_bytes(*c)))
        .collect();

    // Association table: 4-octet elements, big-endian (TSAP, ASAP).
    let (assoc_bytes, assoc_source) = read_table(l4, assoc_index, 4, "association table").await?;
    sources.push(("associations", assoc_source));
    let associations: Vec<(u16, u16)> = assoc_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u16::from_be_bytes([c[2], c[3]]),
            )
        })
        .collect();

    // Group object table: nice-to-have. Count its entries if readable (either
    // path); its per-entry descriptors are not decoded — see the module docs.
    match find_object(&objects, OT_GROUP_OBJECT_TABLE) {
        Some(go_index) => match group_object_count(l4, go_index).await? {
            Some((count, source)) => notes.push(format!(
                "group object table: {count} entr{} via {source} (descriptors not decoded — send/listen direction unavailable)",
                if count == 1 { "y" } else { "ies" }
            )),
            None => notes.push(
                "group object table present but not readable on either path; skipped".to_string(),
            ),
        },
        None => notes.push("no group object table interface object; skipped".to_string()),
    }

    // Resolve: TSAP is a 1-based index into the address table; the ASAP is the
    // ETS com-object number itself (see the module docs — verified live).
    let mut resolved = Vec::with_capacity(associations.len());
    for &(tsap, asap) in &associations {
        let Some(ga) = tsap
            .checked_sub(1)
            .and_then(|i| addresses.get(usize::from(i)))
        else {
            notes.push(format!(
                "association (tsap {tsap}, asap {asap}) points outside the {}-entry address table; skipped",
                addresses.len()
            ));
            continue;
        };
        resolved.push(ResolvedLink {
            object: asap,
            ga: *ga,
        });
    }

    Ok(DeviceTables {
        mask,
        addresses,
        associations,
        resolved,
        sources,
        notes,
    })
}

// --- Correctly-encoded management procedures (see the module docs) ---

/// Reads the device descriptor type 0 (mask version) through the crate's single
/// descriptor reader, [`crate::connection::read_device_descriptor`].
///
/// A connection seeded with a mask the caller read and verified on this same
/// device (issue #209, [`Layer4Connection::seed`]) answers from the seed.
async fn device_descriptor<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<u16> {
    if let Some(mask) = l4.seeded_mask() {
        return Ok(mask);
    }
    Ok(crate::connection::read_device_descriptor(l4).await?)
}

/// Reads `count` elements of a property starting at element `start`.
///
/// Returns the raw value octets; an empty vec means the device reported zero
/// elements (property or object absent / not readable at that index).
async fn read_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    start: u16,
    count: u8,
) -> Result<Vec<u8>> {
    let resp = property_request(l4, object_index, property_id, start, count).await?;
    if resp.count == 0 {
        return Ok(Vec::new());
    }
    Ok(resp.data)
}

/// Reads a `len`-octet span of device memory starting at the 24-bit `addr`,
/// through the crate's single memory module.
///
/// [`crate::memory::read_memory_range`] loops over as many telegrams as the
/// negotiated max-APDU allows and picks the plain `A_Memory_Read` or the
/// `A_MemoryExtended_Read` from the address itself, so a table that lives above
/// `0xFFFF` — the 07B0 actuators whose segments sit in `0xf000..0x1aad3` — is read
/// back instead of refused (issue #80).
async fn read_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    len: usize,
) -> Result<Vec<u8>> {
    crate::memory::read_memory_range(l4, addr, len)
        .await
        .map_err(|e| memory_error(l4.target(), e))
}

/// Folds a memory-layer [`crate::load::WriteError`] into a [`TablesError`]: a
/// management error passes through unchanged, anything else (an out-of-range
/// span) becomes an unreadable table naming the reason.
fn memory_error(address: IndividualAddress, err: crate::load::WriteError) -> TablesError {
    match err {
        crate::load::WriteError::Mgmt(m) => TablesError::Mgmt(m),
        other => TablesError::TableUnreadable {
            address,
            reason: other.to_string(),
        },
    }
}

// --- Discovery and table assembly ---

/// Probes interface-object indexes `0..16` for `PID_OBJECT_TYPE`, returning the
/// discovered `(object index, object type)` pairs in index order.
///
/// A thin wrapper over [`crate::connection::probe_object_types`], the crate's one
/// interface-object discovery, in this module's error type. See that function for
/// the sweep's range and its tolerance at the end of the object list; an empty
/// result (nothing readable even at index 0) is distinguished by the caller.
pub async fn discover_interface_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<(u8, u16)>> {
    Ok(crate::connection::probe_object_types(l4).await?)
}

/// Discovers the interface objects and fails if none is readable at all.
///
/// Wraps [`discover_interface_objects`] with the read side's requirement that at
/// least one object be present (an empty sweep means the device did not answer
/// `PID_OBJECT_TYPE` even at index 0).
async fn discover_objects<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<Vec<(u8, u16)>> {
    let objects = discover_interface_objects(l4).await?;
    if objects.is_empty() {
        return Err(TablesError::TableUnreadable {
            address: l4.target(),
            reason: "no interface objects discoverable (PID_OBJECT_TYPE unreadable at index 0)"
                .to_string(),
        });
    }
    Ok(objects)
}

/// The object index of the first object with the given type, if any.
fn find_object(objects: &[(u8, u16)], object_type: u16) -> Option<u8> {
    objects
        .iter()
        .find(|&&(_, t)| t == object_type)
        .map(|&(index, _)| index)
}

/// Best-effort element count of the group object table, trying the property
/// path then the memory path. `None` means neither is readable — the caller
/// skips the table with a note rather than failing (it is a nice-to-have).
async fn group_object_count<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<Option<(u16, TableSource)>> {
    if let Some(count) = read_element_count(l4, object_index).await? {
        return Ok(Some((count, TableSource::Property)));
    }
    let refbytes = read_property(l4, object_index, PID_TABLE_REFERENCE, 1, 1).await?;
    let Some(table_addr) = decode_table_reference(&refbytes) else {
        return Ok(None);
    };
    let count_bytes = read_memory(l4, table_addr, 2).await?;
    if count_bytes.len() < 2 {
        return Ok(None);
    }
    Ok(Some((
        u16::from_be_bytes([count_bytes[0], count_bytes[1]]),
        TableSource::Memory,
    )))
}

/// Decodes a `PID_TABLE_REFERENCE` value: 2 octets on some profiles, 4 on
/// others; the address is the trailing big-endian word either way.
fn decode_table_reference(refbytes: &[u8]) -> Option<u32> {
    match refbytes {
        [hi, lo] => Some(u32::from(u16::from_be_bytes([*hi, *lo]))),
        [a, b, c, d] => Some(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => None,
    }
}

/// Reads a table's element count: `PID_TABLE` element 0 as a big-endian `u16`.
///
/// Returns `Ok(None)` when the property is not readable (the response reported
/// zero elements) — the caller then falls back or skips.
async fn read_element_count<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<Option<u16>> {
    let data = read_property(l4, object_index, PID_TABLE, 0, 1).await?;
    if data.len() < 2 {
        return Ok(None);
    }
    Ok(Some(u16::from_be_bytes([data[0], data[1]])))
}

/// Reads a whole table: the element count from `PID_TABLE` element 0, then the
/// elements from memory when that takes fewer requests, from the `PID_TABLE`
/// property array otherwise (issue #223).
///
/// - **Memory path** ([`read_counted_table_via_memory`]): `PID_TABLE_REFERENCE`
///   names the table's address and one span read at the negotiated memory chunk
///   (the `A_MemoryExtended_Read`/`A_Memory_Read` helpers the flash read-compare
///   uses) returns the count word and every entry. Taken only when it is
///   estimated to need fewer requests than the property path, so a small table
///   (the 1.1.12 address table has 3 entries) keeps its old frames exactly.
/// - **Property path** ([`read_table_via_property`]): the elements from index 1
///   upward, up to 15 per request.
/// - A device without a readable `PID_TABLE` count goes to the memory path with
///   the count read from memory ([`read_table_via_memory`]), as before.
///
/// The memory path falls back to the property path on a missing or zero
/// reference, a refused, malformed or unanswered memory read, or a count word
/// that disagrees with the `PID_TABLE` count, so the result is the one the
/// property path returns whenever the two could differ.
///
/// Returns the concatenated element octets (`count × elem_size`) and which
/// path produced them.
async fn read_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    what: &str,
) -> Result<(Vec<u8>, TableSource)> {
    let Some(count) = read_element_count(l4, object_index).await? else {
        let bytes = read_table_via_memory(l4, object_index, elem_size, what).await?;
        return Ok((bytes, TableSource::Memory));
    };
    let count = usize::from(count);
    if let Some(bytes) =
        read_counted_table_via_memory(l4, object_index, elem_size, count, what).await?
    {
        return Ok((bytes, TableSource::Memory));
    }
    let bytes = read_table_via_property(l4, object_index, elem_size, count, what).await?;
    Ok((bytes, TableSource::Property))
}

/// Elements per `PID_TABLE` read on this connection: the negotiated property
/// octet budget over the element size, within the 4-bit count field.
fn property_chunk_elements<Ch: L4Channel>(l4: &Layer4Connection<Ch>, elem_size: usize) -> usize {
    (usize::from(l4.max_property_read_octets()) / elem_size.max(1))
        .clamp(1, MAX_PROPERTY_READ_ELEMENTS)
}

/// The fast path for a table whose `PID_TABLE` count is known: resolve
/// `PID_TABLE_REFERENCE`, read the count word and the `count × elem_size`
/// entries in one span at the negotiated memory chunk, and check the count word
/// against `count`.
///
/// `Ok(None)` sends the caller to the property path: the memory read would not
/// save a request, the reference is missing, zero or malformed, the device
/// refused or did not answer a read, or the count word disagrees. Only a
/// transport failure is an `Err`.
async fn read_counted_table_via_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    count: usize,
    what: &str,
) -> Result<Option<Vec<u8>>> {
    if count == 0 {
        return Ok(None);
    }
    let span = 2 + count * elem_size;
    let property_reads = count.div_ceil(property_chunk_elements(l4, elem_size));
    // The best chunk either memory service could carry; the exact one depends on
    // the address, known only after the reference read.
    let best_chunk = usize::from(l4.max_memory_chunk())
        .max(usize::from(l4.max_extended_memory_chunk()))
        .clamp(1, usize::from(u8::MAX));
    if 1 + span.div_ceil(best_chunk) >= property_reads {
        return Ok(None);
    }

    let before = l4.numbered_exchanges();
    let refbytes = match read_property(l4, object_index, PID_TABLE_REFERENCE, 1, 1).await {
        Ok(bytes) => bytes,
        Err(err) => return refusal(l4, before, err, what, "PID_TABLE_REFERENCE read"),
    };
    let Some(table_addr) = decode_table_reference(&refbytes).filter(|&a| a != 0) else {
        tracing::debug!(
            target = %l4.target(),
            "{what}: no usable PID_TABLE_REFERENCE ({} octet(s)); reading PID_TABLE",
            refbytes.len()
        );
        return Ok(None);
    };
    let chunk = crate::memory::chunk_for(l4, table_addr, span);
    if span.div_ceil(chunk) >= property_reads {
        return Ok(None);
    }

    let before = l4.numbered_exchanges();
    let bytes = match crate::memory::read_memory_range(l4, table_addr, span).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let err = memory_error(l4.target(), err);
            return refusal(l4, before, err, what, "memory read");
        }
    };
    let stored = bytes
        .get(..2)
        .map(|w| usize::from(u16::from_be_bytes([w[0], w[1]])));
    if stored != Some(count) || bytes.len() != span {
        tracing::debug!(
            target = %l4.target(),
            "{what}: memory count word {stored:?} disagrees with PID_TABLE count {count}; \
             reading PID_TABLE"
        );
        return Ok(None);
    }
    Ok(Some(bytes[2..].to_vec()))
}

/// Folds a device-level refusal of a fast-path read into `Ok(None)` (the caller
/// falls back to the property path) and passes a transport failure through.
///
/// A refusal is a malformed or off-service answer (a zero-octet memory
/// response, a non-zero `A_MemoryExtended_Read` return code), an out-of-range
/// span, or a request the device `T_ACK`ed but never answered: that one keeps
/// the connection usable for the fallback, as [`Layer4Connection::authorize`]
/// does. A disconnect, a NAK or a device that never acknowledged is an `Err`.
fn refusal<Ch: L4Channel, T>(
    l4: &mut Layer4Connection<Ch>,
    before: u32,
    err: TablesError,
    what: &str,
    step: &str,
) -> Result<Option<T>> {
    let fallback = match &err {
        TablesError::Mgmt(MgmtError::MalformedResponse { .. })
        | TablesError::TableUnreadable { .. } => true,
        TablesError::Mgmt(
            MgmtError::NoResponse { .. }
            | MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            },
        ) if l4.numbered_exchanges() > before => {
            l4.reopen_after_unanswered();
            true
        }
        _ => false,
    };
    if !fallback {
        return Err(err);
    }
    tracing::debug!(target = %l4.target(), "{what}: {step} refused ({err}); reading PID_TABLE");
    Ok(None)
}

/// The property-array path for a table of `count` elements (read from element
/// 0 by the caller): the elements from index 1 upward in APDU-sized chunks.
async fn read_table_via_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    count: usize,
    what: &str,
) -> Result<Vec<u8>> {
    // Scale the per-read element count to the device's negotiated max APDU (issue
    // #58): a capable device reads more elements per round-trip, fewer round-trips
    // for a large table. Falls back to the conservative octet budget when
    // `PID_MAX_APDU_LENGTH` was never negotiated or was unreadable.
    let mut chunk_elems = property_chunk_elements(l4, elem_size);

    let mut bytes = Vec::with_capacity(count * elem_size);
    let mut next: usize = 1; // property array elements are 1-based
    while next <= count {
        let want = chunk_elems.min(count - next + 1);
        let data = read_property(l4, object_index, PID_TABLE, next as u16, want as u8).await?;
        // The device may return fewer elements than asked; advance by what
        // actually arrived. An empty or short answer mid-table is a refusal.
        let got = data.len() / elem_size;
        if (got == 0 || data.len() % elem_size != 0) && want > 1 {
            // A device that refuses a multi-element read (a zero-count or
            // ragged answer) may still serve the elements one at a time, as
            // the MCB table reads found on a real device (issue #89): fall
            // back to `count = 1` for the rest of this table.
            tracing::debug!(
                target = %l4.target(),
                "{what}: PID_TABLE refused a {want}-element read at element {next}; \
                 reading one element per request"
            );
            chunk_elems = 1;
            continue;
        }
        if got == 0 || data.len() % elem_size != 0 {
            return Err(TablesError::TableUnreadable {
                address: l4.target(),
                reason: format!(
                    "{what}: PID_TABLE read at element {next} returned {} octet(s) (expected a multiple of {elem_size})",
                    data.len()
                ),
            });
        }
        bytes.extend_from_slice(&data);
        next += got;
    }
    Ok(bytes)
}

/// The most elements one `A_PropertyValue_Read` can ask for: its count field is
/// 4 bits wide.
const MAX_PROPERTY_READ_ELEMENTS: usize = 15;

/// The memory fallback: `PID_TABLE_REFERENCE` names the table's address; the
/// table starts with a big-endian `u16` entry count followed by the entries.
async fn read_table_via_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let address = l4.target();
    let refbytes = read_property(l4, object_index, PID_TABLE_REFERENCE, 1, 1).await?;
    let table_addr =
        decode_table_reference(&refbytes).ok_or_else(|| TablesError::TableUnreadable {
            address,
            reason: if refbytes.is_empty() {
                format!("{what}: neither PID_TABLE nor PID_TABLE_REFERENCE is readable")
            } else {
                format!(
                    "{what}: PID_TABLE_REFERENCE returned {} octet(s), expected 2 or 4",
                    refbytes.len()
                )
            },
        })?;
    // No 16-bit ceiling here: `read_memory` selects `A_MemoryExtended_Read` for an
    // address above `0xFFFF`, which is exactly where the 07B0 actuators keep their
    // tables (`0xf000..0x1aad3`). Refusing them was the reconstruct/apply
    // verification failure in issue #80.
    let count_bytes = read_memory(l4, table_addr, 2).await?;
    if count_bytes.len() < 2 {
        return Err(TablesError::TableUnreadable {
            address,
            reason: format!("{what}: memory read of the table size word came back short"),
        });
    }
    let count = usize::from(u16::from_be_bytes([count_bytes[0], count_bytes[1]]));

    let total = count * elem_size;
    // The entries start after the 2-octet count word. `read_memory` chunks the span
    // by the negotiated max APDU (issue #58) and bounds it against the 24-bit
    // extended-memory space, so the only address arithmetic left here is the +2.
    let entries_addr = table_addr
        .checked_add(2)
        .ok_or_else(|| TablesError::TableUnreadable {
            address,
            reason: format!("{what}: table reference {table_addr:#X} is at the top of memory"),
        })?;
    let bytes = read_memory(l4, entries_addr, total).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_object_returns_first_index_of_type() {
        let objects = vec![
            (0u8, OT_DEVICE),
            (1, OT_ADDRESS_TABLE),
            (2, OT_ASSOCIATION_TABLE),
            (3, OT_APPLICATION_PROGRAM),
            (4, OT_GROUP_OBJECT_TABLE),
        ];
        assert_eq!(find_object(&objects, OT_ADDRESS_TABLE), Some(1));
        assert_eq!(find_object(&objects, OT_GROUP_OBJECT_TABLE), Some(4));
        assert_eq!(find_object(&objects, 7), None);
    }

    #[test]
    fn table_source_display_names_the_path() {
        assert_eq!(TableSource::Property.to_string(), "property (PID_TABLE)");
        assert_eq!(
            TableSource::Memory.to_string(),
            "memory (PID_TABLE_REFERENCE)"
        );
    }

    #[test]
    fn table_reference_decodes_two_and_four_octet_forms() {
        assert_eq!(decode_table_reference(&[0x40, 0x00]), Some(0x4000));
        assert_eq!(
            decode_table_reference(&[0x00, 0x01, 0x40, 0x00]),
            Some(0x1_4000)
        );
        assert_eq!(decode_table_reference(&[]), None);
        assert_eq!(decode_table_reference(&[0x01, 0x02, 0x03]), None);
    }
}
