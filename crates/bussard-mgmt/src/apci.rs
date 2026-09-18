//! Application-layer (APCI) service constants and codecs for the management
//! services bussard uses.
//!
//! Every management procedure is a request APCI carried in a numbered
//! connected data telegram (NDT) and a matching response APCI carried back the
//! same way. This module holds the 10-bit APCI constants and the pure
//! encode/decode of each service's payload. It is I/O-free and unit-tested per
//! service.
//!
//! The wire structure follows the published KNX application-layer specification
//! (EN 50090 / the KNX standard 3/3/7 "Application Layer") and the Wireshark
//! KNX/KNXnet-IP dissector's public field definitions, cross-checked against
//! live captures from real devices. No GPL source was consulted or copied.

/// `A_DeviceDescriptor_Read` — request the device's descriptor (mask version).
pub const A_DEVICE_DESCRIPTOR_READ: u16 = 0x300;
/// `A_DeviceDescriptor_Response`.
pub const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;

/// The 10-bit APCI selector mask for the services that embed request/response
/// parameters in the **low 6 bits of the APCI** rather than in payload octets
/// (`A_DeviceDescriptor_*`, `A_Memory_*`, `A_Restart`). Masking an observed APCI
/// with this yields the bare service selector, so a response can be validated
/// against the service it belongs to regardless of the low-bit parameter.
pub const APCI_SELECTOR_MASK: u16 = 0x3C0;

/// `A_Authorize_Request` — present an access key to unlock a management session.
///
/// A connection-oriented management session on a device that expects
/// authorization must present a key before any configuration read/write; ETS
/// sends this as the **first** operation after the device-descriptor read (a
/// RawCap of a real ETS download to KNX Virtual, issue #52 finding #1, decoded
/// 409 frames: `A_Authorize_Request` with the free-access key `FF FF FF FF`
/// precedes every configuration access). The payload is a reserved `0x00` octet
/// followed by the 4-byte key, big-endian — see [`encode_authorize_request`].
pub const A_AUTHORIZE_REQUEST: u16 = 0x3D1;
/// `A_Authorize_Response` — the device's answer to [`A_AUTHORIZE_REQUEST`],
/// carrying a single granted access-level octet (0 = highest). Decoded by
/// [`decode_authorize_response`].
pub const A_AUTHORIZE_RESPONSE: u16 = 0x3D2;
/// `A_Key_Write` — set the access key for a level (constant for completeness;
/// bussard does not implement key management, only free-access authorization).
pub const A_KEY_WRITE: u16 = 0x3D3;
/// `A_Key_Response` — the device's answer to [`A_KEY_WRITE`] (constant only, no
/// implementation).
pub const A_KEY_RESPONSE: u16 = 0x3D4;

/// The free-access key `FF FF FF FF`: the "no key required / highest available
/// access" key ETS presents to an unkeyed device. bussard authorizes every
/// management connection with this by default; a project that set a BCU key uses
/// `--bcu-key` to pass the real key instead.
pub const FREE_ACCESS_KEY: u32 = 0xFFFF_FFFF;

/// `A_PropertyValue_Read` — read a property of an interface object.
pub const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
/// `A_PropertyValue_Response`.
pub const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
/// `A_PropertyValue_Write` — write a property of an interface object.
///
/// Same 4-octet addressing header as `A_PropertyValue_Read` (object index, PID,
/// count/start), followed by the new value octets. The device answers with an
/// `A_PropertyValue_Response` echoing the *stored* value (per the KNX
/// application layer: the write's confirmation is a read-back response), so the
/// writer validates by comparing the echoed octets to what it sent.
pub const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;

/// `A_Memory_Read` — read device memory.
pub const A_MEMORY_READ: u16 = 0x200;
/// `A_Memory_Response`.
pub const A_MEMORY_RESPONSE: u16 = 0x240;
/// `A_Memory_Write` — write device memory.
///
/// Same low-6-bits-count framing as `A_Memory_Read`: the octet count lives in
/// the **low 6 bits of the APCI**, and the payload is `[addr_hi, addr_lo,
/// data…]`. A device optionally answers with an `A_Memory_Response` echoing the
/// stored octets (the "verify mode" some System B devices support), but that
/// echo is optional and not cross-stack reliable; bussard verifies every write
/// by an independent `A_Memory_Read` read-back compare instead. See
/// [`encode_memory_write`] and [`crate::device::DeviceConnection::write_memory`].
pub const A_MEMORY_WRITE: u16 = 0x280;

/// `A_MemoryExtended_Write` — write device memory at a **24-bit** address.
///
/// The System B *extended* memory service ETS drives every capable 07B0 device
/// with (verified against four real ETS6 downloads: ABB BE/S16, Jung
/// Schaltaktor-24 and Heizungsaktor-6, Jung Tastsensor — see
/// `scratchpad/ets-analysis/sysb-{a,c}.md`). Unlike plain [`A_MEMORY_WRITE`], the
/// octet count is a full **payload** octet (not the 6-bit APCI field), and the
/// address is **3 octets big-endian**, so it reaches segment bases such as the
/// Jung actuators' `0xf000..0x16000` and writes running to `0x1aad3` that a
/// 16-bit `A_Memory_Write` cannot represent. Payload:
/// `[count][addr_hi, addr_mid, addr_lo][data…]`. Encoded by
/// [`encode_memory_extended_write`]. The device confirms inline with an
/// [`A_MEMORY_EXTENDED_WRITE_RESPONSE`] carrying a return code and the echoed
/// address — no separate `A_Memory_Read` read-back is needed.
pub const A_MEMORY_EXTENDED_WRITE: u16 = 0x1FB;
/// `A_MemoryExtended_Write_Response` — the inline confirmation of an
/// [`A_MEMORY_EXTENDED_WRITE`]. Payload: `[return_code][addr_hi, addr_mid,
/// addr_lo]`, where `return_code == 0x00` means the write was stored. Decoded by
/// [`decode_memory_extended_response`].
pub const A_MEMORY_EXTENDED_WRITE_RESPONSE: u16 = 0x1FC;
/// `A_MemoryExtended_Read` — read device memory at a **24-bit** address. Payload:
/// `[count][addr_hi, addr_mid, addr_lo]`. The verify counterpart of
/// [`A_MEMORY_EXTENDED_WRITE`] for addresses above the 16-bit space; encoded by
/// [`encode_memory_extended_read`].
pub const A_MEMORY_EXTENDED_READ: u16 = 0x1FD;
/// `A_MemoryExtended_Read_Response` — the answer to an [`A_MEMORY_EXTENDED_READ`].
/// Payload: `[return_code][addr_hi, addr_mid, addr_lo][data…]`. Decoded by
/// [`decode_memory_extended_response`].
pub const A_MEMORY_EXTENDED_READ_RESPONSE: u16 = 0x1FE;

/// The largest memory address the extended memory service can carry: a 24-bit
/// (3-octet) address, `0xFF_FFFF`. A write or read whose top address exceeds this
/// is refused rather than truncated.
pub const MAX_MEMORY_ADDRESS: u32 = 0x00FF_FFFF;

/// The fixed APDU overhead of an `A_MemoryExtended_Write`/`_Read` telegram, in
/// octets, on top of the memory data: the 2-octet APCI, the 1-octet count and the
/// 3-octet address. The largest data run that fits a device advertising
/// `max_apdu` NPDU octets on the extended service is
/// `max_apdu - EXTENDED_MEMORY_APDU_OVERHEAD` (see
/// [`extended_memory_chunk_for_apdu`]). Verified against ETS: a device advertising
/// `PID_MAX_APDU=233` gets 228-octet chunks (`233 - 5`), one at `55` gets 50.
const EXTENDED_MEMORY_APDU_OVERHEAD: u8 = 5;

/// The maximum number of data octets a single `A_MemoryExtended_Write`/`_Read`
/// may carry: **228**, matching the largest chunk ETS emits (a device advertising
/// `PID_MAX_APDU=233`). Unlike the plain service the count is a full octet, so the
/// ceiling is the extended-frame budget rather than the 6-bit APCI field; 228 is
/// the largest value observed in the captures and a safe cap.
pub const MAX_EXTENDED_MEMORY_LEN: u16 = 228;

/// `A_Restart` — restart the device.
pub const A_RESTART: u16 = 0x380;

/// `A_Restart` with the **master-reset** restart-type bit set (`A_Restart | 1`).
///
/// The 10-bit A_Restart APCI carries the restart type in its low bit: `0` (=
/// [`A_RESTART`]) is a basic restart, `1` (this value) is a master reset. A
/// master-reset request appends an `EraseCode` octet and a `ChannelNumber`
/// octet; unlike a basic restart it is confirmed by an `A_Restart_Response`
/// ([`A_RESTART_RESPONSE`]) before the device reboots. Clean-room encoding from
/// the published KNX spec (A_Restart / DM_Restart: restart-type bit, erase code,
/// channel number) and the XKNX MIT reference; verified against a real
/// ETS→KNX-Virtual capture whose master reset carried `EraseCode=4 ChannelNumber=0`.
pub const A_RESTART_MASTER_RESET: u16 = 0x381;

/// `A_Restart_Response` — the device's answer to a master-reset `A_Restart`.
///
/// The response APCI is **`0x3A1`**, distinct from the master-reset *request*
/// (`0x381` = [`A_RESTART_MASTER_RESET`]). This was confirmed against the DA.tp
/// capture (`shared-with-windows/dumpfile.pcap`, issue #49 errata): the tool
/// sends `43 81 04 00` (request: APCI 0x381, erase=4, channel=0) and the device
/// answers `43 a1 00 00 00` (response: APCI 0x3A1, error=0, process-time 0). The
/// earlier value `0x381` collided with the request APCI, so a request could not
/// be told from its response by APCI alone; the capture settles it.
///
/// The payload is an error-code octet followed by a 2-byte big-endian *process
/// time* (the minimum time to wait before the device is reachable again). A zero
/// error code means the master reset was accepted; a non-zero code is an error
/// (`0x01` = access denied, `0x02` = unsupported erase code, `0x03` = invalid
/// channel number, per the KNX spec — see [`crate::load`]). The capture only ever
/// showed error `0x00` (success), so the non-zero mapping remains spec-derived.
pub const A_RESTART_RESPONSE: u16 = 0x3A1;

/// `A_IndividualAddress_Read` — broadcast: which device is in programming mode?
pub const A_INDIVIDUAL_ADDRESS_READ: u16 = 0x100;
/// `A_IndividualAddress_Response`.
pub const A_INDIVIDUAL_ADDRESS_RESPONSE: u16 = 0x140;

/// `A_IndividualAddress_Write` — broadcast: set the individual address of the
/// device currently in programming mode. Payload is the 2-byte new address.
/// Only a device in programming mode accepts it; no response is defined.
pub const A_INDIVIDUAL_ADDRESS_WRITE: u16 = 0x0C0;

/// `A_IndividualAddressSerialNumber_Read` — broadcast: ask the device with a
/// given 6-byte KNX serial number to report its individual address. Payload is
/// the 6-byte serial number.
pub const A_INDIVIDUAL_ADDRESS_SERIAL_READ: u16 = 0x3DC;
/// `A_IndividualAddressSerialNumber_Response` — the serial-addressed device's
/// answer; its individual address is the frame source, and the payload echoes
/// the 6-byte serial number followed by 2 reserved (domain-address) octets.
pub const A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE: u16 = 0x3DD;
/// `A_IndividualAddressSerialNumber_Write` — broadcast: set the individual
/// address of the device with a given serial number, without a button press.
/// Payload is the 6-byte serial number followed by the 2-byte new address (and
/// 4 reserved zero octets).
pub const A_INDIVIDUAL_ADDRESS_SERIAL_WRITE: u16 = 0x3DE;

// --- Standardised interface-object / property identifiers ---

/// The device object is always interface object index 0.
pub const DEVICE_OBJECT_INDEX: u8 = 0;
/// `PID_PROGMODE` — the device object's 1-byte programming-mode flag. Bit 0 is
/// the programming-mode bit: writing `0x00` clears programming mode, exactly as
/// ETS does after an individual-address assignment. Lives on the device object
/// (index 0).
pub const PID_PROGMODE: u8 = 54;
/// `PID_SERIAL_NUMBER` — 6-byte KNX serial number.
pub const PID_SERIAL_NUMBER: u8 = 11;
/// `PID_MANUFACTURER_ID` — 2-byte KNX manufacturer id.
pub const PID_MANUFACTURER_ID: u8 = 12;
/// `PID_ORDER_INFO` — manufacturer order/reference string.
pub const PID_ORDER_INFO: u8 = 15;
/// `PID_HARDWARE_TYPE` — 6-byte hardware type identifier.
pub const PID_HARDWARE_TYPE: u8 = 78;
/// `PID_MAX_APDU_LENGTH` — the largest APDU (NPDU length) the device accepts, as
/// a big-endian octet count on the device object (index 0). ETS reads this once
/// per session and scales its `A_Memory_Write`/`A_Memory_Read` and property
/// chunks to it; bussard does the same (issue #58). A device that does not expose
/// it is treated as the conservative standard-frame floor.
pub const PID_MAX_APDU_LENGTH: u8 = 56;

/// The fixed APDU overhead of an `A_Memory_Write`/`A_Memory_Read` telegram, in
/// octets, on top of the memory data: the 2-octet APCI plus the 2-octet address.
/// The on-wire NPDU length is `MEMORY_APDU_OVERHEAD + data_len`, so the largest
/// data run that fits a device advertising `max_apdu` NPDU octets is
/// `max_apdu - MEMORY_APDU_OVERHEAD` (see [`memory_chunk_for_apdu`]).
const MEMORY_APDU_OVERHEAD: u8 = 3;

/// The conservative memory-chunk cap (octets) used when the device's
/// `PID_MAX_APDU_LENGTH` is unknown or unreadable: 12 data octets keeps the
/// `A_Memory_Write`/`A_Memory_Read` telegram inside a KNX **standard** (short)
/// frame (NPDU length `3 + 12 = 15`, the 4-bit LG ceiling), which every device
/// accepts. Real hardware whose max APDU is 15 MUST get this — a 63-octet chunk
/// would force an extended frame such a device may reject.
pub const CONSERVATIVE_MEMORY_CHUNK: u8 = 12;

/// The conservative property-read data cap (octets) used when the device's
/// `PID_MAX_APDU_LENGTH` is unknown: 8 value octets plus the 4-octet
/// `A_PropertyValue_Response` header fits the 15-octet standard-frame APDU every
/// System B device supports.
pub const CONSERVATIVE_PROPERTY_READ_OCTETS: u8 = 8;

/// The fixed APDU overhead of an `A_PropertyValue_Response`, in octets, on top of
/// the value data: the 2-octet APCI plus the 4-octet property header
/// (object index, PID, count/start-hi, start-lo).
const PROPERTY_RESPONSE_OVERHEAD: u8 = 6;

/// The memory data-octet cap for a device advertising `max_apdu` NPDU octets.
///
/// Returns `min(max_apdu - MEMORY_APDU_OVERHEAD, MAX_MEMORY_WRITE_LEN)`, and
/// never less than 1. A device advertising the standard-frame floor (15) yields
/// 12 — a standard frame; a capable device (e.g. KNX Virtual's 66) yields the
/// 63-octet ceiling. Callers pass the value the device reported via
/// [`PID_MAX_APDU_LENGTH`]; when that read fails they use
/// [`CONSERVATIVE_MEMORY_CHUNK`] instead.
pub fn memory_chunk_for_apdu(max_apdu: u16) -> u8 {
    let usable = max_apdu.saturating_sub(u16::from(MEMORY_APDU_OVERHEAD));
    let capped = usable.min(u16::from(MAX_MEMORY_WRITE_LEN));
    (capped as u8).max(1)
}

/// The extended-memory data-octet cap for a device advertising `max_apdu` NPDU
/// octets: `min(max_apdu - EXTENDED_MEMORY_APDU_OVERHEAD, MAX_EXTENDED_MEMORY_LEN)`,
/// never less than 1.
///
/// This scales `A_MemoryExtended_Write`/`_Read` chunks to the device's negotiated
/// `PID_MAX_APDU_LENGTH`, matching ETS: a device advertising `233` yields 228, one
/// at `55` yields 50. Unlike [`memory_chunk_for_apdu`] the count is a full octet
/// (not the 6-bit APCI field), so the ceiling is the 228-octet extended-frame cap
/// rather than 63.
pub fn extended_memory_chunk_for_apdu(max_apdu: u16) -> u16 {
    let usable = max_apdu.saturating_sub(u16::from(EXTENDED_MEMORY_APDU_OVERHEAD));
    usable.clamp(1, MAX_EXTENDED_MEMORY_LEN)
}

/// The property-read value-octet cap for a device advertising `max_apdu` NPDU
/// octets: `max_apdu - PROPERTY_RESPONSE_OVERHEAD`, at least 1. A device at the
/// standard-frame floor (15) yields 9; capable devices scale up, so fewer
/// `A_PropertyValue_Read` round-trips read a large table.
pub fn property_read_octets_for_apdu(max_apdu: u16) -> u8 {
    let usable = max_apdu.saturating_sub(u16::from(PROPERTY_RESPONSE_OVERHEAD));
    // Clamp to a sane ceiling: the response count field is a 4-bit element count
    // at the property layer, but the octet budget here is bounded by the extended
    // frame anyway; 63 is a safe, generous cap mirroring the memory ceiling.
    let capped = usable.min(u16::from(MAX_MEMORY_READ_LEN));
    (capped as u8).max(1)
}

/// The maximum number of data octets a single `A_Memory_Read` / `A_Memory_Write`
/// may carry.
///
/// This is **63**, matching what ETS uses on a System B device (verified against
/// an ETS→KNX-Virtual capture: every configuration write is a 63-octet
/// `A_Memory_Write`). 63 is the natural ceiling for two reasons:
///
/// - The count field is the **low 6 bits of the APCI**, so 63 is the largest
///   value it can encode at all.
/// - The resulting telegram — `2 APCI octets + [addr_hi, addr_lo] + 63 data` = 67
///   octets of TPDU, NPDU length 66 — is an **extended** L_Data frame (the
///   standard/short frame tops out at NPDU length 15). bussard now emits extended
///   frames automatically when the APDU exceeds the short-frame ceiling (see
///   [`bussard_transport::cemi::CemiFrame::encode`]), and 66 sits exactly at the
///   KNX-Virtual device's advertised `PID_MAX_APDU_LENGTH` of 66 octets.
///
/// The old value was **12**, chosen to keep every write inside a short frame.
/// That forced a 256-octet object write into ~22 write+read-back exchanges, which
/// exhausted the device's per-connection L4 budget mid-write on real hardware.
/// At 63 octets the same object is a handful of exchanges — matching ETS's
/// framing and removing the L4 sequence wrap for this workload.
pub const MAX_MEMORY_READ_LEN: u8 = 63;

/// The maximum number of data octets a single `A_Memory_Write` may carry. Same
/// 63-octet ceiling as [`MAX_MEMORY_READ_LEN`]; see that constant for the full
/// rationale (ETS parity, the 6-bit count field, and extended-frame framing).
pub const MAX_MEMORY_WRITE_LEN: u8 = 63;

/// Encodes the `A_PropertyValue_Read` payload (object index, PID, count/start).
///
/// Layout: `[object_index] [property_id] [count(4b)<<4 | start_hi(4b)] [start_lo]`.
/// `count` is 1–15; `start` is a 12-bit element index (usually 1 for the first
/// element).
pub fn encode_property_value_read(
    object_index: u8,
    property_id: u8,
    count: u8,
    start: u16,
) -> Vec<u8> {
    let count = count & 0x0f;
    let start = start & 0x0fff;
    vec![
        object_index,
        property_id,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ]
}

/// Encodes an `A_PropertyValue_Write` payload: the same 4-octet header as
/// [`encode_property_value_read`] (object index, PID, count/start) followed by
/// the new value octets.
///
/// `count` is the number of *elements* being written (1–15) and `start` the
/// 12-bit element index; `value` carries the raw element octets. Writing a
/// property-array element 0 with a `u16` count sets the array's element count
/// (mirroring the read side, where element 0 is the count — see
/// [`crate::tables`]); writing elements from index 1 upward sets the elements.
pub fn encode_property_value_write(
    object_index: u8,
    property_id: u8,
    count: u8,
    start: u16,
    value: &[u8],
) -> Vec<u8> {
    let mut payload = encode_property_value_read(object_index, property_id, count, start);
    payload.extend_from_slice(value);
    payload
}

/// A parsed `A_PropertyValue_Read` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyValueRead {
    /// Interface object index.
    pub object_index: u8,
    /// Property id.
    pub property_id: u8,
    /// Number of elements requested.
    pub count: u8,
    /// Start element index.
    pub start: u16,
}

/// Decodes an `A_PropertyValue_Read` request payload. Returns `None` if shorter
/// than the 4-byte header. (The device side / tests use this to interpret a
/// request; the client side builds requests with [`encode_property_value_read`].)
pub fn decode_property_value_read(payload: &[u8]) -> Option<PropertyValueRead> {
    if payload.len() < 4 {
        return None;
    }
    Some(PropertyValueRead {
        object_index: payload[0],
        property_id: payload[1],
        count: (payload[2] >> 4) & 0x0f,
        start: (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16,
    })
}

/// The parsed header of an `A_PropertyValue_Response`, plus its data octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyValueResponse {
    /// Interface object index echoed back.
    pub object_index: u8,
    /// Property id echoed back.
    pub property_id: u8,
    /// Number of elements returned (0 means the property/object is absent).
    pub count: u8,
    /// Start element index echoed back.
    pub start: u16,
    /// The property value octets.
    pub data: Vec<u8>,
}

/// Decodes an `A_PropertyValue_Response` payload.
///
/// Returns `None` if the payload is shorter than the 4-byte header.
pub fn decode_property_value_response(payload: &[u8]) -> Option<PropertyValueResponse> {
    if payload.len() < 4 {
        return None;
    }
    let object_index = payload[0];
    let property_id = payload[1];
    let count = (payload[2] >> 4) & 0x0f;
    let start = (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16;
    Some(PropertyValueResponse {
        object_index,
        property_id,
        count,
        start,
        data: payload[4..].to_vec(),
    })
}

/// Encodes an `A_DeviceDescriptor_Read` request: the descriptor type lives in
/// the **low 6 bits of the APCI** and the request carries **no** payload octet.
///
/// Returns the `(apci, payload)` pair to send. `descriptor_type` is masked to 6
/// bits. A strict device (verified live against a Jung 23024, see the
/// `tables` module docs) `T_Disconnect`s the over-long form that puts the type
/// in a separate payload octet, so this centralised helper is the correct form.
pub fn encode_device_descriptor_read(descriptor_type: u8) -> (u16, Vec<u8>) {
    (
        A_DEVICE_DESCRIPTOR_READ | u16::from(descriptor_type & 0x3f),
        Vec::new(),
    )
}

/// Encodes an `A_Restart` request. The restart variant (0 = basic restart) is
/// carried in the **low 6 bits of the APCI** with an empty payload.
pub fn encode_restart(variant: u8) -> (u16, Vec<u8>) {
    (A_RESTART | u16::from(variant & 0x3f), Vec::new())
}

/// Encodes a **master-reset** `A_Restart` request: APCI [`A_RESTART_MASTER_RESET`]
/// with a 2-octet payload `[erase_code, channel_number]`.
///
/// This is the wire realisation of an `LdCtrlMasterReset` op. The device answers
/// with an [`A_RESTART_RESPONSE`] (decode with [`decode_restart_response`]) and
/// then reboots, dropping the connection. Clean-room from the published KNX spec
/// and the XKNX MIT reference.
pub fn encode_master_reset(erase_code: u8, channel_number: u8) -> (u16, Vec<u8>) {
    (A_RESTART_MASTER_RESET, vec![erase_code, channel_number])
}

/// Decodes an `A_Restart_Response` payload into its error code.
///
/// The payload is `[error_code, process_time_hi, process_time_lo]`; only the
/// error code gates success (`0` = accepted). A short payload (some devices omit
/// the process-time octets) is tolerated: the first octet is the error code, and
/// an empty payload is treated as error code `0` (accepted), since the device's
/// mere act of answering the master reset is the acknowledgement. Returns the
/// error-code octet.
pub fn decode_restart_response(payload: &[u8]) -> u8 {
    payload.first().copied().unwrap_or(0)
}

/// Encodes an `A_Authorize_Request` payload: a reserved `0x00` octet followed by
/// the 4-byte `key`, big-endian.
///
/// The wire form is exactly the 5 octets `[00, key_be…]` — verified against a
/// RawCap of an ETS download to KNX Virtual (issue #52 finding #1), where the
/// free-access request decoded to `[00 ff ff ff ff]`. The request APCI is
/// [`A_AUTHORIZE_REQUEST`]; the caller sends `(A_AUTHORIZE_REQUEST, payload)`.
/// Pass [`FREE_ACCESS_KEY`] for an unkeyed device.
pub fn encode_authorize_request(key: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    payload.push(0x00); // reserved
    payload.extend_from_slice(&key.to_be_bytes());
    payload
}

/// Decodes an `A_Authorize_Response` payload into the granted access **level**
/// octet.
///
/// The response carries a single level octet (`0` = highest access; a non-zero
/// level means the key granted only limited access). Returns `None` if the
/// payload is empty. The captured free-access response was `[00]` (level 0). The
/// caller validates the response APCI is [`A_AUTHORIZE_RESPONSE`] separately.
pub fn decode_authorize_response(payload: &[u8]) -> Option<u8> {
    payload.first().copied()
}

/// Encodes an `A_Memory_Read` request: the octet count lives in the **low 6
/// bits of the APCI**, followed by exactly the two address octets.
///
/// Returns the `(apci, payload)` pair to send. `count` is clamped to
/// [`MAX_MEMORY_READ_LEN`]. This is the strict, spec-correct framing; the older
/// form that put the count in a leading payload octet is refused by strict
/// System B devices.
pub fn encode_memory_read(addr: u16, count: u8) -> (u16, Vec<u8>) {
    let count = count.min(MAX_MEMORY_READ_LEN) & 0x3f;
    (
        A_MEMORY_READ | u16::from(count),
        addr.to_be_bytes().to_vec(),
    )
}

/// Encodes an `A_Memory_Response`: the octet count lives in the **low 6 bits of
/// the APCI**, followed by the two address octets and then the data.
///
/// Returns the `(apci, payload)` pair. Used by device-side mocks and tests.
pub fn encode_memory_response(addr: u16, data: &[u8]) -> (u16, Vec<u8>) {
    let count = (data.len().min(usize::from(MAX_MEMORY_READ_LEN)) as u8) & 0x3f;
    let mut payload = addr.to_be_bytes().to_vec();
    payload.extend_from_slice(&data[..usize::from(count)]);
    (A_MEMORY_RESPONSE | u16::from(count), payload)
}

/// The parsed header of an `A_Memory_Response`, plus its data octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryResponse {
    /// Number of octets returned.
    pub count: u8,
    /// The memory address the data starts at.
    pub addr: u16,
    /// The memory octets.
    pub data: Vec<u8>,
}

/// Decodes an `A_Memory_Response`, given the response APCI and its payload.
///
/// The octet count lives in the **low 6 bits of `resp_apci`**; the payload is
/// `[addr_hi] [addr_lo] data…`. Returns `None` if the APCI selector is not
/// `A_Memory_Response`, the payload is shorter than the 2-byte address header,
/// or the payload holds fewer data octets than the count advertises.
pub fn decode_memory_response(resp_apci: u16, payload: &[u8]) -> Option<MemoryResponse> {
    if resp_apci & APCI_SELECTOR_MASK != A_MEMORY_RESPONSE {
        return None;
    }
    if payload.len() < 2 {
        return None;
    }
    let count = (resp_apci & 0x3f) as u8;
    let addr = u16::from_be_bytes([payload[0], payload[1]]);
    let data = &payload[2..];
    if data.len() < usize::from(count) {
        return None;
    }
    Some(MemoryResponse {
        count,
        addr,
        data: data[..usize::from(count)].to_vec(),
    })
}

/// Encodes an `A_Memory_Write` request: the octet count lives in the **low 6
/// bits of the APCI**, followed by the two address octets and then the data.
///
/// Returns the `(apci, payload)` pair to send. `data` must be at most
/// [`MAX_MEMORY_WRITE_LEN`] octets; longer slices are truncated to that limit
/// (callers chunk larger ranges — see
/// [`crate::device::DeviceConnection::write_memory`]). The framing is the strict,
/// spec-correct mirror of [`encode_memory_read`]: count in the APCI low bits,
/// never in a leading payload octet.
pub fn encode_memory_write(addr: u16, data: &[u8]) -> (u16, Vec<u8>) {
    let count = (data.len().min(usize::from(MAX_MEMORY_WRITE_LEN)) as u8) & 0x3f;
    let mut payload = addr.to_be_bytes().to_vec();
    payload.extend_from_slice(&data[..usize::from(count)]);
    (A_MEMORY_WRITE | u16::from(count), payload)
}

/// A parsed `A_Memory_Write` request: the target address and the data octets.
///
/// The mock device and tests use this to interpret a write; the client side
/// builds writes with [`encode_memory_write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryWrite {
    /// Number of octets written.
    pub count: u8,
    /// The memory address the data starts at.
    pub addr: u16,
    /// The memory octets to store.
    pub data: Vec<u8>,
}

/// Decodes an `A_Memory_Write` request, given the request APCI and its payload.
///
/// The octet count lives in the **low 6 bits of `req_apci`**; the payload is
/// `[addr_hi] [addr_lo] data…`. Returns `None` if the APCI selector is not
/// `A_Memory_Write`, the payload is shorter than the 2-byte address header, or
/// the payload holds fewer data octets than the count advertises.
pub fn decode_memory_write(req_apci: u16, payload: &[u8]) -> Option<MemoryWrite> {
    if req_apci & APCI_SELECTOR_MASK != A_MEMORY_WRITE {
        return None;
    }
    if payload.len() < 2 {
        return None;
    }
    let count = (req_apci & 0x3f) as u8;
    let addr = u16::from_be_bytes([payload[0], payload[1]]);
    let data = &payload[2..];
    if data.len() < usize::from(count) {
        return None;
    }
    Some(MemoryWrite {
        count,
        addr,
        data: data[..usize::from(count)].to_vec(),
    })
}

/// Encodes an `A_MemoryExtended_Write` request: APCI [`A_MEMORY_EXTENDED_WRITE`]
/// with payload `[count][addr_hi, addr_mid, addr_lo][data…]`.
///
/// Returns the `(apci, payload)` pair to send. Unlike [`encode_memory_write`] the
/// count is a **full payload octet** and the address is **3 octets big-endian**,
/// so this reaches the 24-bit space. `data` must be at most
/// [`MAX_EXTENDED_MEMORY_LEN`] octets; longer slices are truncated to that limit
/// (callers chunk larger ranges). `addr` is masked to 24 bits.
pub fn encode_memory_extended_write(addr: u32, data: &[u8]) -> (u16, Vec<u8>) {
    let count = data.len().min(usize::from(MAX_EXTENDED_MEMORY_LEN)) as u8;
    let mut payload = Vec::with_capacity(4 + usize::from(count));
    payload.push(count);
    payload.extend_from_slice(&addr_3_octets_be(addr));
    payload.extend_from_slice(&data[..usize::from(count)]);
    (A_MEMORY_EXTENDED_WRITE, payload)
}

/// Encodes an `A_MemoryExtended_Read` request: APCI [`A_MEMORY_EXTENDED_READ`]
/// with payload `[count][addr_hi, addr_mid, addr_lo]`.
///
/// Returns the `(apci, payload)` pair to send. `count` is clamped to
/// [`MAX_EXTENDED_MEMORY_LEN`]; `addr` is masked to 24 bits. The verify
/// counterpart of [`encode_memory_extended_write`] for addresses above the 16-bit
/// space.
pub fn encode_memory_extended_read(addr: u32, count: u16) -> (u16, Vec<u8>) {
    let count = count.min(MAX_EXTENDED_MEMORY_LEN) as u8;
    let mut payload = Vec::with_capacity(4);
    payload.push(count);
    payload.extend_from_slice(&addr_3_octets_be(addr));
    (A_MEMORY_EXTENDED_READ, payload)
}

/// The low 24 bits of `addr` as a 3-octet big-endian array.
fn addr_3_octets_be(addr: u32) -> [u8; 3] {
    let a = addr & MAX_MEMORY_ADDRESS;
    [(a >> 16) as u8, (a >> 8) as u8, a as u8]
}

/// A parsed `A_MemoryExtended_Write`/`_Read` request: the count, the 24-bit
/// address and (for a write) the data octets.
///
/// The device-side sim and tests use this to interpret a request; the client side
/// builds requests with [`encode_memory_extended_write`] /
/// [`encode_memory_extended_read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMemoryRequest {
    /// Number of octets to write/read.
    pub count: u8,
    /// The 24-bit memory address the operation starts at.
    pub addr: u32,
    /// The data octets (empty for a read request).
    pub data: Vec<u8>,
}

/// Decodes an `A_MemoryExtended_Write` or `A_MemoryExtended_Read` request payload
/// `[count][addr_hi, addr_mid, addr_lo][data…]`.
///
/// `is_write` selects whether the trailing `count` data octets are required (a
/// write carries them; a read does not). Returns `None` if the payload is shorter
/// than the 4-octet `[count][addr:3]` header, or, for a write, holds fewer data
/// octets than `count` advertises.
pub fn decode_memory_extended_request(
    payload: &[u8],
    is_write: bool,
) -> Option<ExtendedMemoryRequest> {
    if payload.len() < 4 {
        return None;
    }
    let count = payload[0];
    let addr = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
    let data = &payload[4..];
    if is_write {
        if data.len() < usize::from(count) {
            return None;
        }
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: data[..usize::from(count)].to_vec(),
        })
    } else {
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: Vec::new(),
        })
    }
}

/// A parsed `A_MemoryExtended_*_Response`: the return code, the echoed 24-bit
/// address and (for a read response) the data octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMemoryResponse {
    /// The device's return code: `0x00` means success.
    pub return_code: u8,
    /// The 24-bit address the device echoed back.
    pub addr: u32,
    /// The data octets (empty for a write-response).
    pub data: Vec<u8>,
}

/// Encodes an `A_MemoryExtended_Write_Response`: APCI
/// [`A_MEMORY_EXTENDED_WRITE_RESPONSE`] with payload
/// `[return_code][addr_hi, addr_mid, addr_lo]`. Used by device-side mocks/tests.
pub fn encode_memory_extended_write_response(return_code: u8, addr: u32) -> (u16, Vec<u8>) {
    let mut payload = Vec::with_capacity(4);
    payload.push(return_code);
    payload.extend_from_slice(&addr_3_octets_be(addr));
    (A_MEMORY_EXTENDED_WRITE_RESPONSE, payload)
}

/// Encodes an `A_MemoryExtended_Read_Response`: APCI
/// [`A_MEMORY_EXTENDED_READ_RESPONSE`] with payload
/// `[return_code][addr_hi, addr_mid, addr_lo][data…]`. Used by device-side
/// mocks/tests.
pub fn encode_memory_extended_read_response(
    return_code: u8,
    addr: u32,
    data: &[u8],
) -> (u16, Vec<u8>) {
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.push(return_code);
    payload.extend_from_slice(&addr_3_octets_be(addr));
    payload.extend_from_slice(data);
    (A_MEMORY_EXTENDED_READ_RESPONSE, payload)
}

/// Decodes an `A_MemoryExtended_Write_Response` or `A_MemoryExtended_Read_Response`
/// payload, given its response APCI.
///
/// The payload is `[return_code][addr_hi, addr_mid, addr_lo][data…]`; the data
/// tail is present only on a read-response. Returns `None` if the APCI is neither
/// extended-memory response, or the payload is shorter than the 4-octet
/// `[code][addr:3]` header.
pub fn decode_memory_extended_response(
    resp_apci: u16,
    payload: &[u8],
) -> Option<ExtendedMemoryResponse> {
    if resp_apci != A_MEMORY_EXTENDED_WRITE_RESPONSE && resp_apci != A_MEMORY_EXTENDED_READ_RESPONSE
    {
        return None;
    }
    if payload.len() < 4 {
        return None;
    }
    Some(ExtendedMemoryResponse {
        return_code: payload[0],
        addr: u32::from_be_bytes([0, payload[1], payload[2], payload[3]]),
        data: payload[4..].to_vec(),
    })
}

/// Decodes an `A_DeviceDescriptor_Response` payload into the 16-bit mask
/// version (descriptor type 0).
///
/// The response carries the descriptor type in the low 6 bits of the APCI (0
/// here) followed by two mask-version octets. Returns `None` if fewer than two
/// octets are present.
pub fn decode_device_descriptor_response(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

/// Decodes an `A_IndividualAddress_Response`: the answering device's own
/// individual address is the destination of the frame, so this response carries
/// no payload. This helper exists for symmetry and documentation.
pub const A_INDIVIDUAL_ADDRESS_RESPONSE_LEN: usize = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_value_read_roundtrips_through_response() {
        let req = encode_property_value_read(DEVICE_OBJECT_INDEX, PID_MANUFACTURER_ID, 1, 1);
        assert_eq!(req, vec![0x00, 12, 0x10, 0x01]);

        // A synthetic response: object 0, PID 12, count 1, start 1, data 00 04.
        let resp_payload = vec![0x00, 12, 0x10, 0x01, 0x00, 0x04];
        let parsed = decode_property_value_response(&resp_payload).unwrap();
        assert_eq!(parsed.object_index, 0);
        assert_eq!(parsed.property_id, 12);
        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.start, 1);
        assert_eq!(parsed.data, vec![0x00, 0x04]);
    }

    #[test]
    fn property_value_write_shares_the_read_header() {
        // Write 1 element of object 1 / PID 23 at start 1 with value 0x1234.
        let w = encode_property_value_write(1, 23, 1, 1, &[0x12, 0x34]);
        assert_eq!(w, vec![0x01, 23, 0x10, 0x01, 0x12, 0x34]);
        // The header is byte-identical to a read of the same addressing.
        let r = encode_property_value_read(1, 23, 1, 1);
        assert_eq!(&w[..4], &r[..]);
        // The device echoes the stored value in an A_PropertyValue_Response; the
        // response parser reads it back with the same header layout.
        let parsed = decode_property_value_response(&w).unwrap();
        assert_eq!(parsed.object_index, 1);
        assert_eq!(parsed.property_id, 23);
        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.start, 1);
        assert_eq!(parsed.data, vec![0x12, 0x34]);
    }

    #[test]
    fn property_response_count_zero_means_absent() {
        let resp_payload = vec![0x00, 78, 0x00, 0x01];
        let parsed = decode_property_value_response(&resp_payload).unwrap();
        assert_eq!(parsed.count, 0);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn property_response_too_short_is_none() {
        assert!(decode_property_value_response(&[0x00, 12, 0x10]).is_none());
    }

    #[test]
    fn memory_read_encodes_count_in_apci_and_clamps() {
        // Count lives in the APCI low bits; the payload is address-only.
        let (apci, payload) = encode_memory_read(0x0060, 4);
        assert_eq!(apci, A_MEMORY_READ | 4);
        assert_eq!(payload, vec![0x00, 0x60]);
        // Over-long counts clamp to MAX_MEMORY_READ_LEN.
        let (apci, _) = encode_memory_read(0x0100, 200);
        assert_eq!((apci & 0x3f) as u8, MAX_MEMORY_READ_LEN);
    }

    #[test]
    fn authorize_request_is_reserved_byte_then_key_be() {
        // Free-access request: the captured wire form is [00 FF FF FF FF].
        let payload = encode_authorize_request(FREE_ACCESS_KEY);
        assert_eq!(payload, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(FREE_ACCESS_KEY, 0xFFFF_FFFF);
        // A concrete keyed value encodes big-endian after the reserved octet.
        let keyed = encode_authorize_request(0x0011_2233);
        assert_eq!(keyed, vec![0x00, 0x00, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn authorize_response_decodes_level_octet() {
        // The captured free-access response was [00] = granted level 0.
        assert_eq!(decode_authorize_response(&[0x00]), Some(0));
        // A non-zero level (insufficient access) decodes to that level.
        assert_eq!(decode_authorize_response(&[0x03]), Some(3));
        // A trailing tail is ignored; only the first octet is the level.
        assert_eq!(decode_authorize_response(&[0x00, 0xAA]), Some(0));
        // An empty payload is not a level.
        assert_eq!(decode_authorize_response(&[]), None);
    }

    #[test]
    fn device_descriptor_read_has_empty_payload() {
        let (apci, payload) = encode_device_descriptor_read(0);
        assert_eq!(apci, A_DEVICE_DESCRIPTOR_READ);
        assert!(payload.is_empty());
    }

    #[test]
    fn restart_carries_variant_in_apci() {
        let (apci, payload) = encode_restart(0);
        assert_eq!(apci, A_RESTART);
        assert!(payload.is_empty());
    }

    #[test]
    fn master_reset_encodes_erase_code_and_channel() {
        // The master-reset restart-type bit is the low bit of the A_Restart APCI;
        // the payload is [erase_code, channel_number]. The KNX-Virtual capture
        // carried EraseCode=4, ChannelNumber=0.
        let (apci, payload) = encode_master_reset(4, 0);
        assert_eq!(apci, A_RESTART_MASTER_RESET);
        assert_eq!(apci, A_RESTART | 1);
        assert_eq!(payload, vec![0x04, 0x00]);
    }

    #[test]
    fn restart_response_error_code_is_the_first_octet() {
        // [error_code, process_time_hi, process_time_lo]: zero = accepted.
        assert_eq!(decode_restart_response(&[0x00, 0x00, 0x64]), 0);
        // A non-zero error code is surfaced.
        assert_eq!(decode_restart_response(&[0x04, 0x00, 0x00]), 4);
        // An empty payload is treated as accepted (the device answered at all).
        assert_eq!(decode_restart_response(&[]), 0);
    }

    #[test]
    fn memory_response_roundtrips_via_apci() {
        // Response: count 3 in the APCI, payload = addr + data.
        let (apci, payload) = encode_memory_response(0x0060, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(apci, A_MEMORY_RESPONSE | 3);
        assert_eq!(payload, vec![0x00, 0x60, 0xAA, 0xBB, 0xCC]);
        let parsed = decode_memory_response(apci, &payload).unwrap();
        assert_eq!(parsed.count, 3);
        assert_eq!(parsed.addr, 0x0060);
        assert_eq!(parsed.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn memory_response_rejects_wrong_apci_or_short_payload() {
        // Wrong selector.
        assert!(decode_memory_response(A_PROPERTY_VALUE_RESPONSE, &[0x00, 0x60]).is_none());
        // Too short for the address header.
        assert!(decode_memory_response(A_MEMORY_RESPONSE | 1, &[0x00]).is_none());
        // Count advertises more data than present.
        assert!(decode_memory_response(A_MEMORY_RESPONSE | 3, &[0x00, 0x60, 0xAA]).is_none());
    }

    #[test]
    fn memory_write_encodes_count_in_apci() {
        // Count in the APCI low bits; payload = addr + data (no leading count octet).
        let (apci, payload) = encode_memory_write(0x4000, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(apci, A_MEMORY_WRITE | 3);
        assert_eq!(payload, vec![0x40, 0x00, 0xAA, 0xBB, 0xCC]);
        // Over-long writes truncate to MAX_MEMORY_WRITE_LEN.
        let big = vec![0x11u8; 200];
        let (apci, payload) = encode_memory_write(0x0100, &big);
        assert_eq!((apci & 0x3f) as u8, MAX_MEMORY_WRITE_LEN);
        assert_eq!(payload.len(), 2 + usize::from(MAX_MEMORY_WRITE_LEN));
    }

    #[test]
    fn memory_write_roundtrips_through_decode() {
        let (apci, payload) = encode_memory_write(0x4010, &[0x01, 0x02, 0x03, 0x04]);
        let parsed = decode_memory_write(apci, &payload).unwrap();
        assert_eq!(parsed.count, 4);
        assert_eq!(parsed.addr, 0x4010);
        assert_eq!(parsed.data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn memory_write_decode_rejects_wrong_apci_or_short_payload() {
        // Wrong selector (a memory READ is not a WRITE).
        assert!(decode_memory_write(A_MEMORY_READ | 3, &[0x40, 0x00, 0xAA, 0xBB, 0xCC]).is_none());
        // Too short for the address header.
        assert!(decode_memory_write(A_MEMORY_WRITE | 1, &[0x40]).is_none());
        // Count advertises more data than present.
        assert!(decode_memory_write(A_MEMORY_WRITE | 3, &[0x40, 0x00, 0xAA]).is_none());
    }

    #[test]
    fn device_descriptor_response_reads_mask() {
        // System B mask 0x07B0.
        assert_eq!(
            decode_device_descriptor_response(&[0x07, 0xB0]),
            Some(0x07B0)
        );
        assert!(decode_device_descriptor_response(&[0x07]).is_none());
    }

    #[test]
    fn device_descriptor_response_accepts_extra_trailing_payload() {
        // The mask version is the leading big-endian word; a legal descriptor
        // response may carry more (a type-2 descriptor is longer, and the KNX
        // Virtual IP/TP interface was observed answering type 0 with extra
        // trailing octets). We read the mask and ignore the tail rather than
        // rejecting the frame.
        assert_eq!(
            decode_device_descriptor_response(&[0x07, 0xB0, 0x00, 0x11, 0x22]),
            Some(0x07B0)
        );
    }

    #[test]
    fn memory_chunk_scales_with_max_apdu() {
        // KNX Virtual advertises 66 → the 63-octet ceiling.
        assert_eq!(memory_chunk_for_apdu(66), MAX_MEMORY_WRITE_LEN);
        assert_eq!(memory_chunk_for_apdu(66), 63);
        // A device at the standard-frame floor (15) → 12 data octets, which keeps
        // the telegram a standard frame (NPDU 3 + 12 = 15). This is the correctness
        // case: such a device must NOT be handed a 63-octet extended-frame chunk.
        assert_eq!(memory_chunk_for_apdu(15), 12);
        assert_eq!(memory_chunk_for_apdu(15), CONSERVATIVE_MEMORY_CHUNK);
        // A large advertised value is still capped at the 6-bit APCI ceiling.
        assert_eq!(memory_chunk_for_apdu(255), MAX_MEMORY_WRITE_LEN);
        // A pathologically small value never underflows below 1.
        assert_eq!(memory_chunk_for_apdu(0), 1);
        assert_eq!(memory_chunk_for_apdu(3), 1);
    }

    #[test]
    fn memory_extended_write_encodes_count_then_3byte_addr() {
        // Payload is [count][addr:3 BE][data]; the address reaches the 24-bit space.
        let (apci, payload) = encode_memory_extended_write(0x01_6000, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(apci, A_MEMORY_EXTENDED_WRITE);
        assert_eq!(payload, vec![0x03, 0x01, 0x60, 0x00, 0xAA, 0xBB, 0xCC]);
        // Over-long writes truncate to MAX_EXTENDED_MEMORY_LEN.
        let big = vec![0x11u8; 300];
        let (_, payload) = encode_memory_extended_write(0x10_0000, &big);
        assert_eq!(payload[0], MAX_EXTENDED_MEMORY_LEN as u8);
        assert_eq!(payload.len(), 4 + usize::from(MAX_EXTENDED_MEMORY_LEN));
    }

    #[test]
    fn memory_extended_read_encodes_count_then_3byte_addr() {
        let (apci, payload) = encode_memory_extended_read(0x01_7805, 8);
        assert_eq!(apci, A_MEMORY_EXTENDED_READ);
        assert_eq!(payload, vec![0x08, 0x01, 0x78, 0x05]);
    }

    #[test]
    fn memory_extended_write_roundtrips_through_decode() {
        // Top address 0x1aad3 (past u16) survives the 3-octet round-trip.
        let (_, payload) = encode_memory_extended_write(0x01_AAD3, &[1, 2, 3, 4]);
        let parsed = decode_memory_extended_request(&payload, true).unwrap();
        assert_eq!(parsed.count, 4);
        assert_eq!(parsed.addr, 0x01_AAD3);
        assert_eq!(parsed.data, vec![1, 2, 3, 4]);
        // The read form carries no data tail.
        let (_, payload) = encode_memory_extended_read(0x0F_0000, 12);
        let parsed = decode_memory_extended_request(&payload, false).unwrap();
        assert_eq!(parsed.count, 12);
        assert_eq!(parsed.addr, 0x0F_0000);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn memory_extended_request_rejects_short_or_truncated() {
        // Shorter than [count][addr:3].
        assert!(decode_memory_extended_request(&[0x03, 0x01, 0x60], true).is_none());
        // Write count advertises more data than present.
        assert!(decode_memory_extended_request(&[0x03, 0x01, 0x60, 0x00, 0xAA], true).is_none());
    }

    #[test]
    fn memory_extended_write_response_confirms_return_code_and_addr() {
        let (apci, payload) = encode_memory_extended_write_response(0x00, 0x01_6000);
        assert_eq!(apci, A_MEMORY_EXTENDED_WRITE_RESPONSE);
        assert_eq!(payload, vec![0x00, 0x01, 0x60, 0x00]);
        let parsed = decode_memory_extended_response(apci, &payload).unwrap();
        assert_eq!(parsed.return_code, 0);
        assert_eq!(parsed.addr, 0x01_6000);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn memory_extended_read_response_carries_data() {
        let (apci, payload) = encode_memory_extended_read_response(0x00, 0x0F_0000, &[0xDE, 0xAD]);
        assert_eq!(apci, A_MEMORY_EXTENDED_READ_RESPONSE);
        let parsed = decode_memory_extended_response(apci, &payload).unwrap();
        assert_eq!(parsed.return_code, 0);
        assert_eq!(parsed.addr, 0x0F_0000);
        assert_eq!(parsed.data, vec![0xDE, 0xAD]);
        // A non-extended-response APCI is rejected.
        assert!(decode_memory_extended_response(A_MEMORY_RESPONSE, &payload).is_none());
    }

    #[test]
    fn extended_memory_chunk_scales_with_max_apdu() {
        // The two capture APDU sizes: 233 -> 228, 55 -> 50.
        assert_eq!(extended_memory_chunk_for_apdu(233), 228);
        assert_eq!(extended_memory_chunk_for_apdu(55), 50);
        // Capped at the 228 ceiling and never below 1.
        assert_eq!(
            extended_memory_chunk_for_apdu(1000),
            MAX_EXTENDED_MEMORY_LEN
        );
        assert_eq!(extended_memory_chunk_for_apdu(0), 1);
    }

    #[test]
    fn property_read_octets_scales_with_max_apdu() {
        // 66 → 60 value octets (66 - 6 header), capped at 63.
        assert_eq!(property_read_octets_for_apdu(66), 60);
        // Standard-frame floor 15 → 9 octets.
        assert_eq!(property_read_octets_for_apdu(15), 9);
        // Never underflows.
        assert_eq!(property_read_octets_for_apdu(0), 1);
        assert_eq!(property_read_octets_for_apdu(6), 1);
    }
}
