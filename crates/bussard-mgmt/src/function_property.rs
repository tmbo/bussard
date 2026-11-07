//! The plain function property services (KNX 3/3/7 §3.4.7): call a function
//! property of an interface object addressed by its index, and read the
//! state it answers.
//!
//! `A_FunctionPropertyCommand` carries the object index, the property id and
//! the function's input; the device answers `A_FunctionPropertyState_Response`
//! with the object index, the property id, a return code and the function's
//! output (§3.4.7.1). Return code 00h is success, any other value an error;
//! a response without a return code means the property is not a function
//! property (§3.4.7.3).
//!
//! ETS calls object 5 PID 52 with `04` and then `10` in the downloads of the
//! Berker and Hager 0701 programs (`LdCtrlInvokeFunctionProp`, issue #946):
//!
//! | frame | octets after the APCI |
//! |---|---|
//! | `A_FunctionPropertyCommand` | `05 34 04` |
//! | `A_FunctionPropertyState_Response` | `05 34 00` |
//!
//! (`captures/ets-sweep/M-0006_A-E00D-01-28AB-O0009/plain-defaults/ets.pcapng`,
//! frames 176 and 183.)

use crate::connection::{L4Channel, Layer4Connection};
use crate::error::{MgmtError, Result};

/// `A_FunctionPropertyCommand` (KNX 3/3/7 §3.4.7.1).
pub const A_FUNCTION_PROPERTY_COMMAND: u16 = 0x2C7;
/// `A_FunctionPropertyState_Read` (KNX 3/3/7 §3.4.7.2).
pub const A_FUNCTION_PROPERTY_STATE_READ: u16 = 0x2C8;
/// `A_FunctionPropertyState_Response`: the answer to both.
pub const A_FUNCTION_PROPERTY_STATE_RESPONSE: u16 = 0x2C9;

/// Encodes an `A_FunctionPropertyCommand` (or `_State_Read`) payload: the
/// object index, the property id and the function's input.
pub fn encode_function_property(object_index: u8, prop_id: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(object_index);
    out.push(prop_id);
    out.extend_from_slice(data);
    out
}

/// A parsed `A_FunctionPropertyState_Response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPropertyState {
    /// The object index echoed back.
    pub object_index: u8,
    /// The property id echoed back.
    pub prop_id: u8,
    /// The return code; `None` when the device answered without one, which
    /// says the property is not a function property (§3.4.7.3).
    pub return_code: Option<u8>,
    /// The function's output data.
    pub data: Vec<u8>,
}

/// Decodes an `A_FunctionPropertyState_Response` payload: object index,
/// property id, then the optional return code and data. `None` when shorter
/// than the two header octets.
pub fn decode_function_property_state(payload: &[u8]) -> Option<FunctionPropertyState> {
    Some(FunctionPropertyState {
        object_index: *payload.first()?,
        prop_id: *payload.get(1)?,
        return_code: payload.get(2).copied(),
        data: payload.get(3..).unwrap_or_default().to_vec(),
    })
}

/// Sends `A_FunctionPropertyCommand` to `object_index`/`prop_id` with `data`
/// as the function's input and returns the state the device answers.
///
/// # Errors
///
/// [`MgmtError::MalformedResponse`] for an answer that is not an
/// `A_FunctionPropertyState_Response` for this object and property;
/// [`MgmtError::ServiceRejected`] for a non-zero return code, or for an
/// answer without one (the property is not a function property); a missing
/// answer or a transport failure as [`Layer4Connection::request`].
pub async fn function_property_command<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    prop_id: u8,
    data: &[u8],
) -> Result<FunctionPropertyState> {
    let payload = encode_function_property(object_index, prop_id, data);
    let (resp_apci, resp) = l4.request(A_FUNCTION_PROPERTY_COMMAND, &payload).await?;
    let target = format!("object {object_index} PID {prop_id}");
    if resp_apci != A_FUNCTION_PROPERTY_STATE_RESPONSE {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "expected A_FunctionPropertyState_Response to the command on {target}, got APCI \
                 {resp_apci:#06X} ({} octet(s))",
                resp.len()
            ),
        });
    }
    let state =
        decode_function_property_state(&resp).ok_or_else(|| MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "A_FunctionPropertyState_Response for {target} too short ({} octet(s))",
                resp.len()
            ),
        })?;
    if state.object_index != object_index || state.prop_id != prop_id {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "A_FunctionPropertyState_Response for object {} PID {} does not answer {target}",
                state.object_index, state.prop_id
            ),
        });
    }
    match state.return_code {
        Some(0) => Ok(state),
        return_code => Err(MgmtError::ServiceRejected {
            address: l4.target(),
            service: "A_FunctionPropertyCommand",
            target: match return_code {
                Some(_) => target,
                None => format!("{target} (not a function property: no return code)"),
            },
            return_code,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_function_property_matches_the_capture() {
        // Frame 176 of the M-0006_A-E00D-01 capture: `05 34 04`.
        assert_eq!(encode_function_property(5, 52, &[0x04]), [0x05, 0x34, 0x04]);
    }

    #[test]
    fn test_decode_function_property_state_variants() {
        assert_eq!(
            decode_function_property_state(&[0x05, 0x34, 0x00]),
            Some(FunctionPropertyState {
                object_index: 5,
                prop_id: 52,
                return_code: Some(0),
                data: Vec::new(),
            })
        );
        // Not a function property: no return code, no data (§3.4.7.3).
        assert_eq!(
            decode_function_property_state(&[0x05, 0x34]).map(|s| s.return_code),
            Some(None)
        );
        assert_eq!(
            decode_function_property_state(&[0x05, 0x34, 0x01, 0xAA]).map(|s| s.data),
            Some(vec![0xAA])
        );
        assert_eq!(decode_function_property_state(&[0x05]), None);
    }
}
