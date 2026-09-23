//! The **extended** property services: interface objects addressed by object
//! *type* and *instance* rather than by object index (issue #156).
//!
//! KNX Data Secure devices expose their security interface object (object type
//! 17) through these services, and ETS programs it with them in every secured
//! download: `A_FunctionPropertyExt_Command` drives the object's load-state
//! machine, `A_PropertyExtValue_WriteCon` writes the group key table, the
//! individual-address table and the group-object security flags. The plain
//! `A_PropertyValue_*` services address an object by its index and carry a
//! 4-bit element count; these carry a 16-bit object type, a 12-bit instance, a
//! 12-bit property id, a full count octet and a 16-bit start index.
//!
//! # Wire layout (CONFIRMED from the decrypted ETS capture)
//!
//! Every request starts with the same 5-octet object header:
//!
//! ```text
//! [object_type:16][object_instance:12 | property_id:12]
//! ```
//!
//! The capture `secure-1-1-12.pcapng` (ETS 6.4.1, Jung 52911ST, decrypted with
//! the project keyring) carries, for the security object instance 1:
//!
//! | service | plain APDU |
//! |---|---|
//! | `A_FunctionPropertyExt_Command` PID 5 (Unload) | `01 d4 00 11 00 10 05 04 00 00 00 00 00 00 00 00 00` |
//! | `A_FunctionPropertyExt_State_Response` | `01 d6 00 11 00 10 05 00 00` |
//! | `A_PropertyExtValue_WriteCon` PID 54, count 1, index 0 | `01 ce 00 11 00 10 36 01 00 00 00 00` |
//! | `A_PropertyExtValue_WriteConResponse` | `01 cf 00 11 00 10 36 01 00 00 00` |
//! | `A_PropertyExtValue_WriteCon` PID 61, count 211, index 1 | `01 ce 00 11 00 10 3d d3 00 01 …211 octets` |
//!
//! So a value service continues with `[count:8][start:16]` and then the data;
//! the write-con response carries `[count][start]` and a return code; the
//! function-property state response carries a return code and then the data.
//! A return code of `0x00` is success.
//!
//! The `A_PropertyExtDescription_*` layout is not in the capture. It follows the
//! published KNX application layer (KNX 3/3/7): the read carries a 4-bit
//! description type and a 12-bit property index after the header, and the
//! response adds a 4-octet datapoint type, the PDT octet with the write-enable
//! bit, a 12-bit maximum element count and the access-level octet (INFERRED).
//!
//! Key material: the group key table (PID 53) and the tool key (PID 56) are
//! written with these services. Nothing in this module logs a value, and the
//! error messages name the service, object and property, never the data.
//!
//! Clean-room: derived from the decrypted capture and the published KNX
//! specification structure. No GPL KNX source was consulted.

use bussard_model::IndividualAddress;

use crate::connection::{L4Channel, Layer4Connection};
use crate::error::{MgmtError, Result};

/// `A_PropertyExtValue_Read`.
pub const A_PROPERTY_EXT_VALUE_READ: u16 = 0x1CC;
/// `A_PropertyExtValue_Response`.
pub const A_PROPERTY_EXT_VALUE_RESPONSE: u16 = 0x1CD;
/// `A_PropertyExtValue_WriteCon`: a write the device confirms with a return code.
pub const A_PROPERTY_EXT_VALUE_WRITE_CON: u16 = 0x1CE;
/// `A_PropertyExtValue_WriteConResponse`.
pub const A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE: u16 = 0x1CF;
/// `A_PropertyExtValue_WriteUnCon`: an unconfirmed write (not used by bussard).
pub const A_PROPERTY_EXT_VALUE_WRITE_UNCON: u16 = 0x1D0;
/// `A_PropertyExtDescription_Read`.
pub const A_PROPERTY_EXT_DESCRIPTION_READ: u16 = 0x1D2;
/// `A_PropertyExtDescription_Response`.
pub const A_PROPERTY_EXT_DESCRIPTION_RESPONSE: u16 = 0x1D3;
/// `A_FunctionPropertyExt_Command`.
pub const A_FUNCTION_PROPERTY_EXT_COMMAND: u16 = 0x1D4;
/// `A_FunctionPropertyExt_State_Read`.
pub const A_FUNCTION_PROPERTY_EXT_STATE_READ: u16 = 0x1D5;
/// `A_FunctionPropertyExt_State_Response`: the answer to both the command and
/// the state read.
pub const A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE: u16 = 0x1D6;

/// Interface object type 17: the KNX Data Secure security interface object.
pub const OT_SECURITY: u16 = 17;
/// Security object `PID_LOAD_STATE_CONTROL` (5): its load-state machine, driven
/// with `A_FunctionPropertyExt_Command` and the 10-octet load-control value.
pub const PID_SECURITY_LOAD_STATE_CONTROL: u16 = 5;
/// Security object `PID_SECURITY_MODE` (51).
pub const PID_SECURITY_MODE: u16 = 51;
/// Security object `PID_P2P_KEY_TABLE` (52).
pub const PID_P2P_KEY_TABLE: u16 = 52;
/// Security object `PID_GRP_KEY_TABLE` (53): 18-octet elements, the address
/// table index (2 octets) followed by the 16-octet group key.
pub const PID_GRP_KEY_TABLE: u16 = 53;
/// Security object `PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE` (54).
pub const PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE: u16 = 54;
/// Security object `PID_TOOL_KEY` (56).
pub const PID_TOOL_KEY: u16 = 56;
/// Security object `PID_SEQUENCE_NUMBER_SENDING` (59).
pub const PID_SEQUENCE_NUMBER_SENDING: u16 = 59;
/// Security object `PID_GO_SECURITY_FLAGS` (61): one octet per group object,
/// element `n` belonging to group object number `n`.
pub const PID_GO_SECURITY_FLAGS: u16 = 61;

/// The octets an `A_PropertyExtValue_WriteCon` adds to its data on the length
/// the device budgets (`PID_MAX_APDU_LENGTH`): the low APCI octet, the 5-octet
/// object header and `[count][start:16]`. CONFIRMED: ETS writes 211 elements
/// per telegram to a device advertising 233 under Data Secure
/// (`233 - 13 - 9 = 211`).
pub const PROPERTY_EXT_WRITE_OVERHEAD: u16 = 9;

/// The object header every extended property service starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyExtAddress {
    /// The interface object type (e.g. [`OT_SECURITY`]).
    pub object_type: u16,
    /// The 1-based instance of that object type (12 bits).
    pub object_instance: u16,
    /// The property id (12 bits).
    pub property_id: u16,
}

impl PropertyExtAddress {
    /// Addresses property `property_id` of instance 1 of the security object.
    pub fn security(property_id: u16) -> Self {
        PropertyExtAddress {
            object_type: OT_SECURITY,
            object_instance: 1,
            property_id,
        }
    }

    /// The 5-octet header: object type, then instance and PID packed as 12 bits
    /// each. Out-of-range instance or PID bits are masked to 12 bits.
    pub fn encode(&self) -> [u8; 5] {
        let packed =
            (u32::from(self.object_instance & 0x0FFF) << 12) | u32::from(self.property_id & 0x0FFF);
        let t = self.object_type.to_be_bytes();
        [
            t[0],
            t[1],
            (packed >> 16) as u8,
            (packed >> 8) as u8,
            packed as u8,
        ]
    }

    /// Parses the 5-octet header, or `None` when fewer octets are present.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let h = payload.get(..5)?;
        let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
        Some(PropertyExtAddress {
            object_type: u16::from_be_bytes([h[0], h[1]]),
            object_instance: (packed >> 12) as u16,
            property_id: (packed & 0x0FFF) as u16,
        })
    }
}

impl std::fmt::Display for PropertyExtAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "object type {} instance {} PID {}",
            self.object_type, self.object_instance, self.property_id
        )
    }
}

/// Encodes an `A_PropertyExtValue_Read` payload: header, count, start index.
/// A read of `count = 1, start = 0` asks for the property's element count.
pub fn encode_property_ext_value_read(addr: &PropertyExtAddress, count: u8, start: u16) -> Vec<u8> {
    let mut out = addr.encode().to_vec();
    out.push(count);
    out.extend_from_slice(&start.to_be_bytes());
    out
}

/// Encodes an `A_PropertyExtValue_WriteCon` (or `_WriteUnCon`) payload: the
/// read header followed by the element data.
pub fn encode_property_ext_value_write(
    addr: &PropertyExtAddress,
    count: u8,
    start: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut out = encode_property_ext_value_read(addr, count, start);
    out.extend_from_slice(data);
    out
}

/// A parsed `A_PropertyExtValue_Read` / `_Response` / `_WriteCon` payload.
#[derive(Clone, PartialEq, Eq)]
pub struct PropertyExtValue {
    /// The object header.
    pub addr: PropertyExtAddress,
    /// The element count.
    pub count: u8,
    /// The start index.
    pub start: u16,
    /// The element data (empty on a read).
    pub data: Vec<u8>,
}

impl std::fmt::Debug for PropertyExtValue {
    // The data may be a key table: never format it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropertyExtValue")
            .field("addr", &self.addr)
            .field("count", &self.count)
            .field("start", &self.start)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Decodes a value-service payload (`A_PropertyExtValue_Read`, `_Response`,
/// `_WriteCon`, `_WriteUnCon`): header, count, start, data. `None` when the
/// 8-octet header is incomplete.
pub fn decode_property_ext_value(payload: &[u8]) -> Option<PropertyExtValue> {
    let addr = PropertyExtAddress::decode(payload)?;
    let rest = payload.get(5..8)?;
    Some(PropertyExtValue {
        addr,
        count: rest[0],
        start: u16::from_be_bytes([rest[1], rest[2]]),
        data: payload.get(8..).unwrap_or_default().to_vec(),
    })
}

/// Encodes an `A_PropertyExtValue_Response` payload (device side / mocks).
pub fn encode_property_ext_value_response(
    addr: &PropertyExtAddress,
    count: u8,
    start: u16,
    data: &[u8],
) -> Vec<u8> {
    encode_property_ext_value_write(addr, count, start, data)
}

/// A parsed `A_PropertyExtValue_WriteConResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyExtWriteConResponse {
    /// The object header echoed back.
    pub addr: PropertyExtAddress,
    /// The element count echoed back.
    pub count: u8,
    /// The start index echoed back.
    pub start: u16,
    /// The return code; `0x00` is success.
    pub return_code: u8,
}

/// Encodes an `A_PropertyExtValue_WriteConResponse` payload (device side).
pub fn encode_property_ext_write_con_response(
    addr: &PropertyExtAddress,
    count: u8,
    start: u16,
    return_code: u8,
) -> Vec<u8> {
    let mut out = encode_property_ext_value_read(addr, count, start);
    out.push(return_code);
    out
}

/// Decodes an `A_PropertyExtValue_WriteConResponse`: header, count, start and
/// the return code. `None` when shorter than 9 octets.
pub fn decode_property_ext_write_con_response(
    payload: &[u8],
) -> Option<PropertyExtWriteConResponse> {
    let v = decode_property_ext_value(payload)?;
    Some(PropertyExtWriteConResponse {
        addr: v.addr,
        count: v.count,
        start: v.start,
        return_code: *payload.get(8)?,
    })
}

/// Encodes an `A_PropertyExtDescription_Read` payload: the header, then the
/// 4-bit description type (0) and the 12-bit property index. With a non-zero
/// PID the index is ignored by the device; with PID 0 it selects the property.
pub fn encode_property_ext_description_read(
    addr: &PropertyExtAddress,
    property_index: u16,
) -> Vec<u8> {
    let mut out = addr.encode().to_vec();
    out.extend_from_slice(&(property_index & 0x0FFF).to_be_bytes());
    out
}

/// A parsed `A_PropertyExtDescription_Response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyExtDescription {
    /// The object header (with the resolved PID).
    pub addr: PropertyExtAddress,
    /// The description type (upper 4 bits of the index word).
    pub description_type: u8,
    /// The property index.
    pub property_index: u16,
    /// The datapoint type, main number (16 bits).
    pub dpt_main: u16,
    /// The datapoint type, sub number (16 bits).
    pub dpt_sub: u16,
    /// Whether the property is writable.
    pub write_enable: bool,
    /// The property data type (PDT, 6 bits).
    pub pdt: u8,
    /// The maximum number of elements (12 bits); 0 means "no such property".
    pub max_elements: u16,
    /// The read access level (upper nibble of the access octet).
    pub read_level: u8,
    /// The write access level (lower nibble).
    pub write_level: u8,
}

/// Encodes an `A_PropertyExtDescription_Response` payload (device side / mocks).
pub fn encode_property_ext_description_response(desc: &PropertyExtDescription) -> Vec<u8> {
    let mut out = desc.addr.encode().to_vec();
    let index_word =
        (u16::from(desc.description_type & 0x0F) << 12) | (desc.property_index & 0x0FFF);
    out.extend_from_slice(&index_word.to_be_bytes());
    out.extend_from_slice(&desc.dpt_main.to_be_bytes());
    out.extend_from_slice(&desc.dpt_sub.to_be_bytes());
    out.push(if desc.write_enable { 0x80 } else { 0x00 } | (desc.pdt & 0x3F));
    out.extend_from_slice(&(desc.max_elements & 0x0FFF).to_be_bytes());
    out.push((desc.read_level << 4) | (desc.write_level & 0x0F));
    out
}

/// Decodes an `A_PropertyExtDescription_Response` (15 octets, see the module
/// docs; INFERRED from the KNX application layer, not yet seen in a capture).
pub fn decode_property_ext_description_response(payload: &[u8]) -> Option<PropertyExtDescription> {
    let addr = PropertyExtAddress::decode(payload)?;
    let p = payload.get(5..15)?;
    let index_word = u16::from_be_bytes([p[0], p[1]]);
    Some(PropertyExtDescription {
        addr,
        description_type: (index_word >> 12) as u8,
        property_index: index_word & 0x0FFF,
        dpt_main: u16::from_be_bytes([p[2], p[3]]),
        dpt_sub: u16::from_be_bytes([p[4], p[5]]),
        write_enable: p[6] & 0x80 != 0,
        pdt: p[6] & 0x3F,
        max_elements: u16::from_be_bytes([p[7], p[8]]) & 0x0FFF,
        read_level: p[9] >> 4,
        write_level: p[9] & 0x0F,
    })
}

/// Encodes an `A_FunctionPropertyExt_Command` (or `_State_Read`) payload: the
/// header followed by the function's input data.
pub fn encode_function_property_ext(addr: &PropertyExtAddress, data: &[u8]) -> Vec<u8> {
    let mut out = addr.encode().to_vec();
    out.extend_from_slice(data);
    out
}

/// A parsed `A_FunctionPropertyExt_Command` (device side).
#[derive(Clone, PartialEq, Eq)]
pub struct FunctionPropertyExtCommand {
    /// The object header.
    pub addr: PropertyExtAddress,
    /// The input data.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for FunctionPropertyExtCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionPropertyExtCommand")
            .field("addr", &self.addr)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Decodes an `A_FunctionPropertyExt_Command` / `_State_Read` payload.
pub fn decode_function_property_ext(payload: &[u8]) -> Option<FunctionPropertyExtCommand> {
    Some(FunctionPropertyExtCommand {
        addr: PropertyExtAddress::decode(payload)?,
        data: payload.get(5..).unwrap_or_default().to_vec(),
    })
}

/// A parsed `A_FunctionPropertyExt_State_Response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPropertyExtState {
    /// The object header echoed back.
    pub addr: PropertyExtAddress,
    /// The return code; `0x00` is success.
    pub return_code: u8,
    /// The function's output data (for the security load-state machine: the
    /// new load state).
    pub data: Vec<u8>,
}

/// Encodes an `A_FunctionPropertyExt_State_Response` payload (device side).
pub fn encode_function_property_ext_state_response(
    addr: &PropertyExtAddress,
    return_code: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut out = addr.encode().to_vec();
    out.push(return_code);
    out.extend_from_slice(data);
    out
}

/// Decodes an `A_FunctionPropertyExt_State_Response`: header, return code,
/// data. `None` when shorter than 6 octets.
pub fn decode_function_property_ext_state_response(
    payload: &[u8],
) -> Option<FunctionPropertyExtState> {
    Some(FunctionPropertyExtState {
        addr: PropertyExtAddress::decode(payload)?,
        return_code: *payload.get(5)?,
        data: payload.get(6..).unwrap_or_default().to_vec(),
    })
}

/// The largest element count one `A_PropertyExtValue_WriteCon` may carry for
/// elements of `element_size` octets on `l4`, from the negotiated APDU budget
/// minus the Data Secure overhead (see
/// [`Layer4Connection::effective_max_apdu`]). At least 1, at most 255.
pub fn max_write_elements<Ch: L4Channel>(l4: &Layer4Connection<Ch>, element_size: usize) -> usize {
    let budget = usize::from(
        l4.effective_max_apdu()
            .saturating_sub(PROPERTY_EXT_WRITE_OVERHEAD),
    );
    (budget / element_size.max(1)).clamp(1, usize::from(u8::MAX))
}

/// A response detail that never echoes value octets: the APCI, the length and
/// at most the 8-octet header.
fn header_detail(apci: u16, payload: &[u8]) -> String {
    let head: Vec<String> = payload.iter().take(8).map(|b| format!("{b:02X}")).collect();
    format!(
        "APCI {apci:#06X}, {} octet(s), header [{}]",
        payload.len(),
        head.join(" ")
    )
}

fn malformed(address: IndividualAddress, reason: String) -> MgmtError {
    MgmtError::MalformedResponse { address, reason }
}

/// Reads `count` elements from `start` with `A_PropertyExtValue_Read`,
/// validating the response service and the echoed object header.
///
/// A response with count 0 is the device refusing the read (no such property
/// or access denied) and surfaces as [`MgmtError::ServiceRejected`].
pub async fn read_property_ext<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    count: u8,
    start: u16,
) -> Result<PropertyExtValue> {
    let payload = encode_property_ext_value_read(&addr, count, start);
    let (resp_apci, data) = l4.request(A_PROPERTY_EXT_VALUE_READ, &payload).await?;
    if resp_apci != A_PROPERTY_EXT_VALUE_RESPONSE {
        return Err(malformed(
            l4.target(),
            format!(
                "expected A_PropertyExtValue_Response ({})",
                header_detail(resp_apci, &data)
            ),
        ));
    }
    let resp = decode_property_ext_value(&data).ok_or_else(|| {
        malformed(
            l4.target(),
            format!(
                "A_PropertyExtValue_Response too short ({})",
                header_detail(resp_apci, &data)
            ),
        )
    })?;
    if resp.addr != addr || resp.start != start {
        return Err(malformed(
            l4.target(),
            format!(
                "A_PropertyExtValue_Response for {} start {} does not answer {addr} start {start}",
                resp.addr, resp.start
            ),
        ));
    }
    if resp.count == 0 {
        return Err(MgmtError::ServiceRejected {
            address: l4.target(),
            service: "A_PropertyExtValue_Read",
            target: addr.to_string(),
            return_code: None,
        });
    }
    Ok(resp)
}

/// Reads a property's current element count (`count = 1, start = 0`).
pub async fn read_property_ext_element_count<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
) -> Result<u16> {
    let resp = read_property_ext(l4, addr, 1, 0).await?;
    match resp.data.as_slice() {
        [hi, lo, ..] => Ok(u16::from_be_bytes([*hi, *lo])),
        [b] => Ok(u16::from(*b)),
        [] => Err(malformed(
            l4.target(),
            format!("element count of {addr} came back empty"),
        )),
    }
}

/// Writes `count` elements from `start` with `A_PropertyExtValue_WriteCon` and
/// checks the device's confirmation: the echoed header, count and start, and a
/// zero return code. A non-zero return code is [`MgmtError::ServiceRejected`].
pub async fn write_property_ext_con<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    count: u8,
    start: u16,
    data: &[u8],
) -> Result<()> {
    let payload = encode_property_ext_value_write(&addr, count, start, data);
    let (resp_apci, resp) = l4.request(A_PROPERTY_EXT_VALUE_WRITE_CON, &payload).await?;
    if resp_apci != A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE {
        return Err(malformed(
            l4.target(),
            format!(
                "expected A_PropertyExtValue_WriteConResponse ({})",
                header_detail(resp_apci, &resp)
            ),
        ));
    }
    let conf = decode_property_ext_write_con_response(&resp).ok_or_else(|| {
        malformed(
            l4.target(),
            format!(
                "A_PropertyExtValue_WriteConResponse too short ({})",
                header_detail(resp_apci, &resp)
            ),
        )
    })?;
    if conf.addr != addr || conf.start != start || conf.count != count {
        return Err(malformed(
            l4.target(),
            format!(
                "A_PropertyExtValue_WriteConResponse for {} count {} start {} does not confirm \
                 {addr} count {count} start {start}",
                conf.addr, conf.count, conf.start
            ),
        ));
    }
    if conf.return_code != 0 {
        return Err(MgmtError::ServiceRejected {
            address: l4.target(),
            service: "A_PropertyExtValue_WriteCon",
            target: format!("{addr} start {start} count {count}"),
            return_code: Some(conf.return_code),
        });
    }
    Ok(())
}

/// Writes `data` (a run of `element_size`-octet elements) from element `start`
/// with as many `A_PropertyExtValue_WriteCon` telegrams as the negotiated APDU
/// needs (see [`max_write_elements`]), the way ETS writes `PID_GO_SECURITY_FLAGS`
/// in 211-element chunks. `on_chunk` is called with the elements written so far.
pub async fn write_property_ext_chunked<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    start: u16,
    element_size: usize,
    data: &[u8],
    mut on_chunk: impl FnMut(usize),
) -> Result<()> {
    let element_size = element_size.max(1);
    if data.len() % element_size != 0 {
        return Err(malformed(
            l4.target(),
            format!(
                "refusing to write {} octets to {addr}: not a whole number of {element_size}-octet \
                 elements",
                data.len()
            ),
        ));
    }
    let per = max_write_elements(l4, element_size);
    let mut index = start;
    let mut done = 0usize;
    for chunk in data.chunks(per * element_size) {
        let count = chunk.len() / element_size;
        write_property_ext_con(l4, addr, count as u8, index, chunk).await?;
        done += count;
        index = index.saturating_add(count as u16);
        on_chunk(done);
    }
    Ok(())
}

/// Reads a property description with `A_PropertyExtDescription_Read`.
pub async fn read_property_ext_description<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    property_index: u16,
) -> Result<PropertyExtDescription> {
    let payload = encode_property_ext_description_read(&addr, property_index);
    let (resp_apci, data) = l4
        .request(A_PROPERTY_EXT_DESCRIPTION_READ, &payload)
        .await?;
    if resp_apci != A_PROPERTY_EXT_DESCRIPTION_RESPONSE {
        return Err(malformed(
            l4.target(),
            format!(
                "expected A_PropertyExtDescription_Response ({})",
                header_detail(resp_apci, &data)
            ),
        ));
    }
    decode_property_ext_description_response(&data).ok_or_else(|| {
        malformed(
            l4.target(),
            format!(
                "A_PropertyExtDescription_Response too short ({})",
                header_detail(resp_apci, &data)
            ),
        )
    })
}

/// Sends `A_FunctionPropertyExt_Command` and returns the device's state
/// response, checking the echoed header and a zero return code.
pub async fn function_property_ext_command<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    data: &[u8],
) -> Result<FunctionPropertyExtState> {
    function_property_ext_request(l4, A_FUNCTION_PROPERTY_EXT_COMMAND, addr, data).await
}

/// Sends `A_FunctionPropertyExt_State_Read` and returns the state response.
pub async fn function_property_ext_state_read<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    data: &[u8],
) -> Result<FunctionPropertyExtState> {
    function_property_ext_request(l4, A_FUNCTION_PROPERTY_EXT_STATE_READ, addr, data).await
}

async fn function_property_ext_request<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    req_apci: u16,
    addr: PropertyExtAddress,
    data: &[u8],
) -> Result<FunctionPropertyExtState> {
    let payload = encode_function_property_ext(&addr, data);
    let (resp_apci, resp) = l4.request(req_apci, &payload).await?;
    if resp_apci != A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE {
        return Err(malformed(
            l4.target(),
            format!(
                "expected A_FunctionPropertyExt_State_Response ({})",
                header_detail(resp_apci, &resp)
            ),
        ));
    }
    let state = decode_function_property_ext_state_response(&resp).ok_or_else(|| {
        malformed(
            l4.target(),
            format!(
                "A_FunctionPropertyExt_State_Response too short ({})",
                header_detail(resp_apci, &resp)
            ),
        )
    })?;
    if state.addr != addr {
        return Err(malformed(
            l4.target(),
            format!(
                "A_FunctionPropertyExt_State_Response for {} does not answer {addr}",
                state.addr
            ),
        ));
    }
    if state.return_code != 0 {
        return Err(MgmtError::ServiceRejected {
            address: l4.target(),
            service: if req_apci == A_FUNCTION_PROPERTY_EXT_COMMAND {
                "A_FunctionPropertyExt_Command"
            } else {
                "A_FunctionPropertyExt_State_Read"
            },
            target: addr.to_string(),
            return_code: Some(state.return_code),
        });
    }
    Ok(state)
}

/// Drives the security object's load-state machine with `control` (ETS sends
/// the 10-octet load-control value through `A_FunctionPropertyExt_Command`
/// PID 5) and returns the load state the device reports.
///
/// CONFIRMED from the capture: `04 00…` (Unload) answers state `00`
/// (Unloaded), `01 00…` (StartLoading) answers `02` (Loading) and `02 00…`
/// (LoadCompleted) answers `01` (Loaded).
pub async fn security_load_control<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    control: crate::load::LoadControl,
) -> Result<crate::load::LoadState> {
    let addr = PropertyExtAddress::security(PID_SECURITY_LOAD_STATE_CONTROL);
    let state = function_property_ext_command(l4, addr, &control.encode_full()).await?;
    let octet = state.data.first().copied().ok_or_else(|| {
        malformed(
            l4.target(),
            "the security object's load-control answer carried no load state".to_string(),
        )
    })?;
    Ok(crate::load::LoadState::from_octet(octet))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string (test helper; the fixtures are capture bytes).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// The payload of a captured plain APDU: the two APCI octets stripped.
    fn payload(apdu: &str) -> Vec<u8> {
        hex(apdu)[2..].to_vec()
    }

    // Every fixture below is the decrypted plain APDU of a NON-key frame of
    // `secure-1-1-12.pcapng` (ETS 6.4.1 secured download of 1.1.12).

    #[test]
    fn test_encode_function_property_ext_security_unload_matches_capture() {
        let addr = PropertyExtAddress::security(PID_SECURITY_LOAD_STATE_CONTROL);
        let got =
            encode_function_property_ext(&addr, &crate::load::LoadControl::Unload.encode_full());
        assert_eq!(got, payload("01d4001100100504000000000000000000"));
    }

    #[test]
    fn test_encode_function_property_ext_start_and_complete_match_capture() {
        let addr = PropertyExtAddress::security(PID_SECURITY_LOAD_STATE_CONTROL);
        assert_eq!(
            encode_function_property_ext(
                &addr,
                &crate::load::LoadControl::StartLoading.encode_full()
            ),
            payload("01d4001100100501000000000000000000")
        );
        assert_eq!(
            encode_function_property_ext(
                &addr,
                &crate::load::LoadControl::LoadCompleted.encode_full()
            ),
            payload("01d4001100100502000000000000000000")
        );
    }

    #[test]
    fn test_encode_function_property_ext_security_mode_matches_capture() {
        // Activation: PID 51 (SECURITY_MODE) with 3 octets.
        let addr = PropertyExtAddress::security(PID_SECURITY_MODE);
        assert_eq!(
            encode_function_property_ext(&addr, &[0x00, 0x00, 0x01]),
            payload("01d40011001033000001")
        );
    }

    #[test]
    fn test_decode_function_property_ext_state_response_from_capture() -> Result<()> {
        let cases = [
            ("01d600110010050000", 0x00u8),
            ("01d600110010050002", 0x02),
            ("01d600110010050001", 0x01),
        ];
        for (apdu, state) in cases {
            let parsed = decode_function_property_ext_state_response(&payload(apdu))
                .ok_or_else(|| malformed(IndividualAddress::from_raw(0), apdu.to_string()))?;
            assert_eq!(
                parsed.addr,
                PropertyExtAddress::security(PID_SECURITY_LOAD_STATE_CONTROL)
            );
            assert_eq!(parsed.return_code, 0);
            assert_eq!(parsed.data, vec![state]);
            assert_eq!(
                encode_function_property_ext_state_response(&parsed.addr, 0, &[state]),
                payload(apdu)
            );
        }
        Ok(())
    }

    #[test]
    fn test_encode_property_ext_value_write_ia_table_clear_matches_capture() {
        let addr = PropertyExtAddress::security(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE);
        assert_eq!(
            encode_property_ext_value_write(&addr, 1, 0, &[0x00, 0x00]),
            payload("01ce00110010360100000000")
        );
    }

    #[test]
    fn test_encode_property_ext_value_write_sequence_matches_capture() {
        // PID 59 (SEQUENCE_NUMBER_SENDING): a sequence number, not a key.
        let addr = PropertyExtAddress::security(PID_SEQUENCE_NUMBER_SENDING);
        assert_eq!(
            encode_property_ext_value_write(&addr, 1, 1, &hex("00400c10a974")),
            payload("01ce001100103b01000100400c10a974")
        );
    }

    #[test]
    fn test_encode_property_ext_value_write_go_flags_header_matches_capture() {
        let addr = PropertyExtAddress::security(PID_GO_SECURITY_FLAGS);
        let got = encode_property_ext_value_write(&addr, 211, 1, &[0u8; 211]);
        assert_eq!(&got[..8], &payload("01ce001100103dd30001")[..]);
        assert_eq!(got.len(), 8 + 211);
        let last = encode_property_ext_value_write(&addr, 67, 1267, &[0u8; 67]);
        assert_eq!(&last[..8], &payload("01ce001100103d4304f3")[..]);
    }

    #[test]
    fn test_decode_property_ext_write_con_response_from_capture() -> Result<()> {
        let cases = [
            (
                "01cf001100103601000000",
                PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                1u8,
                0u16,
            ),
            ("01cf001100103dd3000100", PID_GO_SECURITY_FLAGS, 211, 1),
            ("01cf001100103d4304f300", PID_GO_SECURITY_FLAGS, 67, 1267),
            ("01cf001100103b01000100", PID_SEQUENCE_NUMBER_SENDING, 1, 1),
        ];
        for (apdu, pid, count, start) in cases {
            let parsed = decode_property_ext_write_con_response(&payload(apdu))
                .ok_or_else(|| malformed(IndividualAddress::from_raw(0), apdu.to_string()))?;
            assert_eq!(parsed.addr, PropertyExtAddress::security(pid));
            assert_eq!(parsed.count, count);
            assert_eq!(parsed.start, start);
            assert_eq!(parsed.return_code, 0);
            assert_eq!(
                encode_property_ext_write_con_response(&parsed.addr, count, start, 0),
                payload(apdu)
            );
        }
        Ok(())
    }

    #[test]
    fn test_property_ext_address_round_trips_wide_fields() -> Result<()> {
        let addr = PropertyExtAddress {
            object_type: 0x1234,
            object_instance: 0xABC,
            property_id: 0xDEF,
        };
        let enc = addr.encode();
        assert_eq!(enc, [0x12, 0x34, 0xAB, 0xCD, 0xEF]);
        let back = PropertyExtAddress::decode(&enc)
            .ok_or_else(|| malformed(IndividualAddress::from_raw(0), "decode".to_string()))?;
        assert_eq!(back, addr);
        Ok(())
    }

    #[test]
    fn test_property_ext_value_read_round_trips() -> Result<()> {
        let addr = PropertyExtAddress::security(PID_GO_SECURITY_FLAGS);
        let req = encode_property_ext_value_read(&addr, 1, 0);
        assert_eq!(req, hex("001100103d010000"));
        let resp = encode_property_ext_value_response(&addr, 1, 0, &[0x05, 0x35]);
        let parsed = decode_property_ext_value(&resp)
            .ok_or_else(|| malformed(IndividualAddress::from_raw(0), "decode".to_string()))?;
        assert_eq!(parsed.data, vec![0x05, 0x35]);
        assert_eq!(parsed.start, 0);
        Ok(())
    }

    #[test]
    fn test_property_ext_description_round_trips() -> Result<()> {
        let desc = PropertyExtDescription {
            addr: PropertyExtAddress::security(PID_GO_SECURITY_FLAGS),
            description_type: 0,
            property_index: 7,
            dpt_main: 0,
            dpt_sub: 0,
            write_enable: true,
            pdt: 0x11,
            max_elements: 1333,
            read_level: 3,
            write_level: 0,
        };
        let enc = encode_property_ext_description_response(&desc);
        assert_eq!(enc.len(), 15);
        let back = decode_property_ext_description_response(&enc)
            .ok_or_else(|| malformed(IndividualAddress::from_raw(0), "decode".to_string()))?;
        assert_eq!(back, desc);
        assert_eq!(
            encode_property_ext_description_read(&desc.addr, 7),
            hex("001100103d0007")
        );
        Ok(())
    }

    #[test]
    fn test_memory_extended_write_matches_secured_capture() -> Result<()> {
        // A_MemoryExtended_Write of 2 octets at 0x0160A6 (a parameter write of
        // the secured download) and its confirmation.
        let (apci, body) = crate::apci::encode_memory_extended_write(0x0160A6, &[0x11, 0x11]);
        assert_eq!(apci, crate::apci::A_MEMORY_EXTENDED_WRITE);
        assert_eq!(body, payload("01fb020160a61111"));
        let (apci, body) =
            crate::apci::encode_memory_extended_write(0x00F000, &hex("000300050006032f"));
        assert_eq!(apci, crate::apci::A_MEMORY_EXTENDED_WRITE);
        assert_eq!(body, payload("01fb0800f000000300050006032f"));
        let resp = crate::apci::decode_memory_extended_response(
            crate::apci::A_MEMORY_EXTENDED_WRITE_RESPONSE,
            &payload("01fc000160a6"),
        )
        .ok_or_else(|| malformed(IndividualAddress::from_raw(0), "decode".to_string()))?;
        assert_eq!(resp.return_code, 0);
        assert_eq!(resp.addr, 0x0160A6);
        Ok(())
    }

    #[test]
    fn test_secured_chunk_sizes_match_ets() {
        // The device advertises PID_MAX_APDU_LENGTH = 233. Plain: 228-octet
        // extended memory chunks. Secured: ETS writes 215-octet memory chunks
        // and 211-element GO-flag chunks.
        let inner = 233 - crate::connection::SECURE_APDU_OVERHEAD;
        assert_eq!(crate::apci::extended_memory_chunk_for_apdu(233), 228);
        assert_eq!(crate::apci::extended_memory_chunk_for_apdu(inner), 215);
        assert_eq!(inner - PROPERTY_EXT_WRITE_OVERHEAD, 211);
    }

    #[test]
    fn test_short_payloads_decode_to_none() {
        assert!(PropertyExtAddress::decode(&[0x00, 0x11, 0x00, 0x10]).is_none());
        assert!(decode_property_ext_value(&hex("0011001005")).is_none());
        assert!(decode_property_ext_write_con_response(&hex("0011001036010000")).is_none());
        assert!(decode_function_property_ext_state_response(&hex("0011001005")).is_none());
    }

    #[test]
    fn test_property_ext_value_debug_never_prints_data() {
        let v = PropertyExtValue {
            addr: PropertyExtAddress::security(PID_GRP_KEY_TABLE),
            count: 1,
            start: 1,
            data: vec![0xAB; 18],
        };
        let s = format!("{v:?}");
        assert!(!s.contains("171"), "{s}");
        assert!(!s.to_lowercase().contains("ab, ab"), "{s}");
        assert!(s.contains("data_len: 18"), "{s}");
    }
}
