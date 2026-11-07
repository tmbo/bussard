//! Function property calls in a load procedure (issue #946).
//!
//! `LdCtrlInvokeFunctionProp` calls a function property of an interface
//! object with the op's `InlineData` as its input. ETS sends it as one
//! `A_FunctionPropertyCommand` (object by index, KNX 3/3/7 §3.4.7.1) or
//! `A_FunctionPropertyExt_Command` (object by type, §3.4.8.1) and waits for
//! the state response, whose return code 00h is success (§3.4.7.3). From the
//! sweep captures of 2026-11-07:
//!
//! - the Berker/Hager 0701 programs call object 5 PID 52 with `04`
//!   (`full,grp`) and `10` (`full,par`) after the `PID_HARDWARE_TYPE` compare
//!   and before the unloads; the device answers `05 34 00`
//!   (`captures/ets-sweep/M-0006_A-E00D-01-28AB-O0009/plain-defaults`,
//!   frames 176/183 and 212/219, `ops.txt` ops 10 and 12);
//! - the Hager 07B0 programs call object 6 PID 52 the same way inside the
//!   merged download (`M-0009_A-501A-10-8E53`, ops 28 and 30);
//! - a Gira 07B0 program names the object by type: ETS sends
//!   `A_FunctionPropertyExt_Command` type 65281 instance 1 PID 208 data `FF`
//!   and gets return code 0 (`M-0008_A-E000-10-89B0-O0077`).
//!
//! After each plain call ETS also reads the description of PID 53 of the
//! same object; nothing it does depends on the answer, so bussard does not
//! send it.

use super::plan_props::prop_object;
use super::{FlashStep, PlanError, PropObject};
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::function_property::function_property_command;
use bussard_mgmt::load::WriteError;
use bussard_mgmt::property_ext::{PropertyExtAddress, function_property_ext_command};
use bussard_prod::application::LoadOp;

/// The largest PID the extended property services carry (12 bits, KNX 3/3/7
/// §3.4.8).
const MAX_EXT_PID: u32 = 0x0FFF;

/// Lowers an `LdCtrlInvokeFunctionProp` to [`FlashStep::InvokeFunctionProp`].
///
/// # Errors
///
/// [`PlanError::UnsupportedOp`] for a call without a `PropId`, or one whose
/// object index or PID does not fit the service that carries it (8-bit index
/// and PID on the plain service; 16-bit type, 12-bit instance and 12-bit PID
/// on the extended one).
pub(super) fn lower_invoke_function_prop(step: usize, op: &LoadOp) -> Result<FlashStep, PlanError> {
    let refuse = |what: String| PlanError::UnsupportedOp {
        op: format!("LdCtrlInvokeFunctionProp {what} (step {step})"),
    };
    let LoadOp::InvokeFunctionProp {
        obj_idx,
        obj_type,
        occurrence,
        prop_id,
        inline_data,
    } = op
    else {
        return Err(refuse("expected".to_string()));
    };
    let prop_id = prop_id.ok_or_else(|| refuse("without a PropId".to_string()))?;
    let object = prop_object(step, *obj_idx, *obj_type, *occurrence)
        .map_err(|e| refuse(format!("naming an object bussard cannot address: {e}")))?;
    match object {
        PropObject::Index(index) => {
            if index > u32::from(u8::MAX) {
                return Err(refuse(format!(
                    "on object {index}, past the 8-bit index A_FunctionPropertyCommand carries"
                )));
            }
            if prop_id > u32::from(u8::MAX) {
                return Err(refuse(format!(
                    "on PID {prop_id}, past the 8-bit PID A_FunctionPropertyCommand carries"
                )));
            }
        }
        PropObject::Type { .. } => {
            if prop_id > MAX_EXT_PID {
                return Err(refuse(format!(
                    "on PID {prop_id}, past the 12-bit PID A_FunctionPropertyExt_Command carries"
                )));
            }
        }
    }
    Ok(FlashStep::InvokeFunctionProp {
        object,
        prop_id,
        data: inline_data.clone().unwrap_or_default(),
    })
}

/// Executes an `LdCtrlInvokeFunctionProp`: calls `object`/`prop_id` with
/// `data` and requires return code 00h in the device's state response.
///
/// # Errors
///
/// [`WriteError::TargetOutOfRange`] for an object index or PID the service
/// cannot carry (nothing is sent); a non-zero return code, a response without
/// one (the property is not a function property), a response for another
/// object or property, no response, or a transport failure. Each fails the flash; none is retried
/// on another service, since a refused call is the device's answer.
pub async fn invoke_function_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
    prop_id: u32,
    data: &[u8],
) -> Result<(), WriteError> {
    let out_of_range = |detail: String| WriteError::TargetOutOfRange {
        address: l4.target(),
        detail,
    };
    match object {
        PropObject::Index(index) => {
            let index = u8::try_from(index)
                .map_err(|_| out_of_range(format!("object index {index} (8 bits)")))?;
            let pid = u8::try_from(prop_id)
                .map_err(|_| out_of_range(format!("PID {prop_id} (8 bits)")))?;
            function_property_command(l4, index, pid, data).await?;
        }
        PropObject::Type {
            object_type,
            occurrence,
        } => {
            let property_id = u16::try_from(prop_id)
                .ok()
                .filter(|pid| u32::from(*pid) <= MAX_EXT_PID)
                .ok_or_else(|| out_of_range(format!("PID {prop_id} (12 bits)")))?;
            let addr = PropertyExtAddress {
                object_type,
                object_instance: occurrence.saturating_add(1),
                property_id,
            };
            function_property_ext_command(l4, addr, data).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn op(obj_idx: Option<u32>, obj_type: Option<u32>, prop_id: Option<u32>) -> LoadOp {
        LoadOp::InvokeFunctionProp {
            obj_idx,
            obj_type,
            occurrence: None,
            prop_id,
            inline_data: Some(vec![0x04]),
        }
    }

    #[test]
    fn test_lower_invoke_function_prop_by_index_and_type() -> TestResult {
        assert_eq!(
            lower_invoke_function_prop(3, &op(Some(5), None, Some(52)))?,
            FlashStep::InvokeFunctionProp {
                object: PropObject::Index(5),
                prop_id: 52,
                data: vec![0x04],
            }
        );
        assert_eq!(
            lower_invoke_function_prop(3, &op(None, Some(65281), Some(208)))?,
            FlashStep::InvokeFunctionProp {
                object: PropObject::Type {
                    object_type: 65281,
                    occurrence: 0,
                },
                prop_id: 208,
                data: vec![0x04],
            }
        );
        Ok(())
    }

    #[test]
    fn test_lower_invoke_function_prop_by_type_takes_a_12_bit_pid() -> TestResult {
        assert!(matches!(
            lower_invoke_function_prop(3, &op(None, Some(65281), Some(0x0FFF)))?,
            FlashStep::InvokeFunctionProp {
                prop_id: 0x0FFF,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_lower_invoke_function_prop_refusals() {
        for bad in [
            op(Some(5), None, None),
            op(Some(256), None, Some(52)),
            op(Some(5), None, Some(256)),
            op(None, Some(70_000), Some(52)),
            op(None, Some(65281), Some(0x1000)),
        ] {
            assert!(
                matches!(
                    lower_invoke_function_prop(4, &bad),
                    Err(PlanError::UnsupportedOp { .. })
                ),
                "{bad:?}"
            );
        }
    }
}
