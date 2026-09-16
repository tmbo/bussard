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
//!   (mask 07B0) whose `links.yaml` is an ETS-import ground truth: the read
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
//!   followed by the entries. Reading `PID_TABLE` as a property array is
//!   attempted first (standard semantics, some stacks expose it); a device that
//!   does not expose it (e.g. one whose group object table registers no
//!   `PID_TABLE`) falls back to the memory path, and [`DeviceTables::sources`]
//!   reports which path worked.
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
//! Both encodings are produced by the shared [`apci::encode_device_descriptor_read`]
//! and [`apci::encode_memory_read`] helpers — the same ones
//! [`DeviceConnection`](crate::DeviceConnection) uses — so the two paths agree on
//! the wire form. This module drives a borrowed [`Layer4Connection`] directly
//! (rather than a [`DeviceConnection`](crate::DeviceConnection)) because
//! `read_tables` operates on the caller's live connection.
//!
//! Everything here is **read-only** on the bus and preserves the crate's
//! absent-vs-refusing distinction: transport-level failures surface as
//! [`MgmtError`]; a device that answers but does not expose a readable table
//! surfaces as [`TablesError::TableUnreadable`].

use crate::apci::{self, MAX_MEMORY_READ_LEN};
use crate::connection::{L4Channel, Layer4Connection, property_request};
use crate::error::{MgmtError, descriptor_response_reason, raw_response_detail};
use bussard_model::{GroupAddress, IndividualAddress};

// --- Identifiers not (yet) in `apci.rs` ---
// Defined locally per the standard's interface-object resource definitions;
// dedup into `apci.rs` later.

/// `PID_OBJECT_TYPE` (1) — the interface object's type, a `u16` per element.
pub const PID_OBJECT_TYPE: u8 = 1;
/// `PID_TABLE_REFERENCE` (7) — memory address of a loadable table.
pub const PID_TABLE_REFERENCE: u8 = 7;
/// `PID_TABLE` (23) — the loadable table exposed as a property array.
///
/// 23 is the global "Table" PID (KNX 3/5/1 global property definitions); it is
/// **not** 52, which is `PID_KNX_INDIVIDUAL_ADDRESS` of the IP parameter object.
pub const PID_TABLE: u8 = 23;

/// The 10-bit APCI selector mask for services that embed data in the low 6
/// APCI bits (`A_DeviceDescriptor_*`, `A_Memory_*`). Re-exported from
/// [`apci::APCI_SELECTOR_MASK`] for local readability.
const APCI_SELECTOR_MASK: u16 = apci::APCI_SELECTOR_MASK;
/// `A_DeviceDescriptor_Response` selector (low 6 bits = descriptor type).
const APCI_DEVICE_DESCRIPTOR_RESPONSE: u16 = apci::A_DEVICE_DESCRIPTOR_RESPONSE;

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

/// How many object indexes discovery probes before giving up.
///
/// The sweep runs `0..MAX_OBJECT_INDEX`. This must cover the application-program
/// object, which on some System B devices sits at index 12–15 (past the address
/// / association / group-object tables), so a budget of 16 is required — a
/// tighter 0..12 budget silently misses those devices' app object.
const MAX_OBJECT_INDEX: u8 = 16;

/// How many value octets we ask for per `A_PropertyValue_Read`, sized so the
/// response (4-octet header + data) fits the conservative 15-octet APDU every
/// System B device supports.
const MAX_PROPERTY_READ_OCTETS: usize = 8;

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
/// a fixed index. Each table is read via the `PID_TABLE` property array,
/// falling back to `PID_TABLE_REFERENCE` + memory reads; `sources` records
/// which path worked.
pub async fn read_tables<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<DeviceTables> {
    let address = l4.target();
    let mask = device_descriptor(l4).await?;
    if !crate::is_system_b(mask) {
        return Err(TablesError::UnsupportedMask { address, mask });
    }

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
        .chunks_exact(2)
        .map(|c| GroupAddress::from_raw(u16::from_be_bytes([c[0], c[1]])))
        .collect();

    // Association table: 4-octet elements, big-endian (TSAP, ASAP).
    let (assoc_bytes, assoc_source) = read_table(l4, assoc_index, 4, "association table").await?;
    sources.push(("associations", assoc_source));
    let associations: Vec<(u16, u16)> = assoc_bytes
        .chunks_exact(4)
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

/// Reads the device descriptor type 0 (mask version).
///
/// The descriptor type lives in the low 6 APCI bits and the request carries
/// **no** payload octet (see the module docs on wire encodings).
async fn device_descriptor<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<u16> {
    let (req_apci, payload) = apci::encode_device_descriptor_read(0);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    // Accept any A_DeviceDescriptor_Response of >= 2 octets. The descriptor type
    // rides in the response's low APCI bits (echoing the requested type 0); a
    // type-2 response is longer, and some interfaces (observed on the KNX Virtual
    // IP/TP interface) answer type 0 with **extra** trailing payload. Both are
    // legal: the mask version is the leading big-endian word, so we read the
    // first two octets and ignore any tail. We do NOT loosen the selector check —
    // a wrong service, or a short (< 2 octet) answer, is still rejected, now with
    // the raw APCI + payload bytes so the frame is captured without a sniffer.
    if resp_apci & APCI_SELECTOR_MASK != APCI_DEVICE_DESCRIPTOR_RESPONSE || data.len() < 2 {
        return Err(TablesError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: descriptor_response_reason(resp_apci, &data),
        }));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
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

/// Reads `len` octets of device memory starting at `addr`.
///
/// The octet count lives in the low 6 APCI bits of both request and response
/// (see the module docs on wire encodings); the payload is address-only.
async fn read_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    len: u8,
) -> Result<Vec<u8>> {
    let (req_apci, payload) = apci::encode_memory_read(addr, len);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    let resp = apci::decode_memory_response(resp_apci, &data).ok_or_else(|| {
        TablesError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "unexpected memory response ({})",
                raw_response_detail(resp_apci, &data)
            ),
        })
    })?;
    Ok(resp.data)
}

// --- Discovery and table assembly ---

/// Probes interface-object indexes `0..16` for `PID_OBJECT_TYPE`, returning the
/// discovered `(object index, object type)` pairs in index order.
///
/// This is the single, canonical interface-object discovery for the management
/// layer. Interface objects are contiguously indexed, so the sweep ends at the
/// first index whose `PID_OBJECT_TYPE` read comes back empty (zero elements) or
/// is answered with a non-property service — both mean "no object here". The
/// range spans a full `0..16` so a device whose application-program object sits
/// at index 12–15 is still found (a tighter budget silently misses it).
///
/// Only a genuine transport failure propagates as an error; an empty/short/
/// off-service *terminating* read is the normal end-of-list signal and simply
/// stops the sweep. An empty result (nothing readable even at index 0) is
/// distinguished by the caller.
///
/// This is the seam the read side (`read_tables`) and the download engine's
/// apply / flash paths share, so all three probe the same correct range and
/// terminate identically.
pub async fn discover_interface_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<(u8, u16)>> {
    let mut objects = Vec::new();
    for index in 0..MAX_OBJECT_INDEX {
        let data = read_property(l4, index, PID_OBJECT_TYPE, 1, 1).await?;
        if data.len() < 2 {
            break;
        }
        objects.push((index, u16::from_be_bytes([data[0], data[1]])));
    }
    Ok(objects)
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
    let Some(table_addr) = decode_table_reference(&refbytes).and_then(|a| u16::try_from(a).ok())
    else {
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

/// Reads a whole table, preferring the `PID_TABLE` property array and falling
/// back to `PID_TABLE_REFERENCE` + memory reads.
///
/// Returns the concatenated element octets (`count × elem_size`) and which
/// path produced them.
async fn read_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    what: &str,
) -> Result<(Vec<u8>, TableSource)> {
    match read_table_via_property(l4, object_index, elem_size, what).await? {
        Some(bytes) => Ok((bytes, TableSource::Property)),
        None => {
            let bytes = read_table_via_memory(l4, object_index, elem_size, what).await?;
            Ok((bytes, TableSource::Memory))
        }
    }
}

/// The property-array path: element count from element 0, then elements from
/// index 1 upward in APDU-sized chunks.
///
/// Returns `Ok(None)` when `PID_TABLE` is not readable at all (element-count
/// read reports zero elements), signalling the caller to fall back.
async fn read_table_via_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    what: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(count) = read_element_count(l4, object_index).await? else {
        return Ok(None);
    };
    let count = usize::from(count);
    let chunk_elems = (MAX_PROPERTY_READ_OCTETS / elem_size).max(1);

    let mut bytes = Vec::with_capacity(count * elem_size);
    let mut next: usize = 1; // property array elements are 1-based
    while next <= count {
        let want = chunk_elems.min(count - next + 1);
        let data = read_property(l4, object_index, PID_TABLE, next as u16, want as u8).await?;
        // The device may return fewer elements than asked; advance by what
        // actually arrived. An empty or short answer mid-table is a refusal.
        let got = data.len() / elem_size;
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
    Ok(Some(bytes))
}

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
    let table_addr = u16::try_from(table_addr).map_err(|_| TablesError::TableUnreadable {
        address,
        reason: format!(
            "{what}: table reference {table_addr:#X} exceeds the 16-bit A_Memory_Read address space"
        ),
    })?;

    let count_bytes = read_memory(l4, table_addr, 2).await?;
    if count_bytes.len() < 2 {
        return Err(TablesError::TableUnreadable {
            address,
            reason: format!("{what}: memory read of the table size word came back short"),
        });
    }
    let count = usize::from(u16::from_be_bytes([count_bytes[0], count_bytes[1]]));

    let total = count * elem_size;
    let mut bytes = Vec::with_capacity(total);
    let mut offset: usize = 0;
    while offset < total {
        let want = (total - offset).min(usize::from(MAX_MEMORY_READ_LEN));
        // Compute the full read address in usize FIRST, then bound it to the
        // 16-bit A_Memory_Read space — `offset` can reach hundreds of KiB, so
        // truncating it to u16 before the checked_add would wrap past the guard.
        let addr = usize::from(table_addr)
            .checked_add(2)
            .and_then(|a| a.checked_add(offset))
            .and_then(|a| u16::try_from(a).ok())
            .ok_or_else(|| TablesError::TableUnreadable {
                address,
                reason: format!("{what}: table extends past the 16-bit address space"),
            })?;
        let data = read_memory(l4, addr, want as u8).await?;
        if data.is_empty() {
            return Err(TablesError::TableUnreadable {
                address,
                reason: format!("{what}: memory read at {addr:#06X} came back empty"),
            });
        }
        offset += data.len();
        bytes.extend_from_slice(&data);
    }
    bytes.truncate(total);
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
