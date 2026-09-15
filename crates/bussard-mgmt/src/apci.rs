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
//! (EN 50090 / the KNX standard); thelsing/knx (C++, permitted device-side
//! reference) describes what the peer expects. No GPL sources were consulted.

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

/// `A_PropertyValue_Read` — read a property of an interface object.
pub const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
/// `A_PropertyValue_Response`.
pub const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;

/// `A_Memory_Read` — read device memory.
pub const A_MEMORY_READ: u16 = 0x200;
/// `A_Memory_Response`.
pub const A_MEMORY_RESPONSE: u16 = 0x240;

/// `A_Restart` — restart the device.
pub const A_RESTART: u16 = 0x380;

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
/// `PID_SERIAL_NUMBER` — 6-byte KNX serial number.
pub const PID_SERIAL_NUMBER: u8 = 11;
/// `PID_MANUFACTURER_ID` — 2-byte KNX manufacturer id.
pub const PID_MANUFACTURER_ID: u8 = 12;
/// `PID_ORDER_INFO` — manufacturer order/reference string.
pub const PID_ORDER_INFO: u8 = 15;
/// `PID_HARDWARE_TYPE` — 6-byte hardware type identifier.
pub const PID_HARDWARE_TYPE: u8 = 78;

/// The maximum number of data octets a single `A_Memory_Read` may request. The
/// count field is 6 bits but the practical per-telegram limit on TP1 is 12.
pub const MAX_MEMORY_READ_LEN: u8 = 12;

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
    fn device_descriptor_response_reads_mask() {
        // System B mask 0x07B0.
        assert_eq!(
            decode_device_descriptor_response(&[0x07, 0xB0]),
            Some(0x07B0)
        );
        assert!(decode_device_descriptor_response(&[0x07]).is_none());
    }
}
