//! Property operations in load procedures (issue #390): the lowering of
//! `LdCtrlWriteProp` and `LdCtrlCompareProp` shared by the System 7 planner and
//! the property-only planner, the `<choose>` guards of a load procedure, and
//! the planner for a procedure that holds nothing but property operations (the
//! Jung IPS 300 SREG, mask 0021).
//!
//! The value an `LdCtrlWriteProp` writes is its `InlineData` when it carries
//! one, else the value the program's property-located parameters compose
//! ([`bussard_prod::compute_property_values`]), as ETS resolves it from the
//! project. A write whose value neither source supplies is refused; nothing is
//! guessed.

use super::{AppIdentity, FlashPlan, FlashStep, PlanError, PropObject};
use bussard_prod::application::{ApplicationProgram, LoadOp, LoadProcedure};
use bussard_prod::dynamic::{DynamicConfig, WhenTest};
use bussard_prod::{PropertyObjectRef, PropertyValues};
use std::collections::BTreeMap;

/// The mask whose property-only procedures bussard plans although it does
/// not download the family (System 1 realisation type 0021, the Jung IPS 300
/// SREG KNX IP interface, issue #390).
pub(super) const PROPERTY_ONLY_MASK: u16 = 0x0021;

/// The interface object type of the device object: always interface object
/// 0 (KNX 3/5/1), so an op naming it by type is addressed by index.
const OT_DEVICE: u32 = 0;

/// Whether `op` decides nothing but property access or the session around it,
/// the operations a property-only procedure may hold.
fn is_property_op(op: &LoadOp) -> bool {
    matches!(
        op,
        LoadOp::Connect
            | LoadOp::Disconnect
            | LoadOp::Restart
            | LoadOp::WriteProp { .. }
            | LoadOp::CompareProp { .. }
    )
}

/// Whether `app`'s load procedure is property-only: every op of every block
/// is a property operation (or a session boundary or restart) and at least one
/// writes or compares a property. The mask gate opens for such a procedure on
/// a family bussard does not otherwise download (mask 0021, issue #390): it
/// touches no memory and no load-state machine.
pub(crate) fn is_property_only(app: &ApplicationProgram) -> bool {
    let ops = || app.load_procedures.iter().flat_map(|p| p.ops.iter());
    ops().next().is_some()
        && ops().all(is_property_op)
        && ops().any(|op| matches!(op, LoadOp::WriteProp { .. } | LoadOp::CompareProp { .. }))
}

/// Whether the branch `guard` names is taken under `config`.
fn branch_taken(
    app: &ApplicationProgram,
    lp: &LoadProcedure,
    guard: &bussard_prod::application::LoadGuard,
    config: &DynamicConfig,
    step: usize,
) -> Result<bool, PlanError> {
    let choose = lp
        .chooses
        .get(guard.choose)
        .ok_or_else(|| PlanError::UndecidableCondition {
            step,
            reason: "the op names a <choose> the procedure does not hold".to_string(),
        })?;
    let raw = config
        .value(app, None, &choose.param_ref_id)
        .ok_or_else(|| PlanError::UndecidableCondition {
            step,
            reason: format!("parameter ref {} has no value", choose.param_ref_id),
        })?;
    let value: i64 = raw
        .trim()
        .parse()
        .map_err(|_| PlanError::UndecidableCondition {
            step,
            reason: format!(
                "parameter ref {} holds `{raw}`, not a number a <when> test can compare",
                choose.param_ref_id
            ),
        })?;
    if let Some(WhenTest::Unknown(test)) = choose
        .tests
        .iter()
        .find(|t| matches!(t, WhenTest::Unknown(_)))
    {
        return Err(PlanError::UndecidableCondition {
            step,
            reason: format!(
                "the <choose> on {} has a <when test=\"{test}\"> bussard does not understand",
                choose.param_ref_id
            ),
        });
    }
    let Some(test) = choose.tests.get(guard.branch) else {
        return Ok(false);
    };
    Ok(match test {
        WhenTest::Default => !choose.tests.iter().any(|t| t.matches(value)),
        other => other.matches(value),
    })
}

/// The ops of `lp` whose `<choose>` branches `config` takes, in order. A
/// procedure without `<choose>` returns all of its ops.
fn taken_ops(
    app: &ApplicationProgram,
    lp: &LoadProcedure,
    config: &DynamicConfig,
) -> Result<Vec<LoadOp>, PlanError> {
    let mut out = Vec::with_capacity(lp.ops.len());
    for (i, op) in lp.ops.iter().enumerate() {
        let mut taken = true;
        for guard in lp.guards_of(i) {
            if !branch_taken(app, lp, guard, config, i + 1)? {
                taken = false;
                break;
            }
        }
        if taken {
            out.push(op.clone());
        }
    }
    Ok(out)
}

/// The self-contained op sequence of `app` (no master-template splice) with
/// each `<choose>` decided under `config`: [`super::plan::assemble_ops`]'s
/// block selection (merged blocks in `MergeId` order, else the richest block),
/// each block filtered to the branches taken.
///
/// # Errors
///
/// [`PlanError::UndecidableCondition`] when a `<choose>` cannot be decided.
pub(super) fn guarded_ops(
    app: &ApplicationProgram,
    config: &DynamicConfig,
) -> Result<Vec<LoadOp>, PlanError> {
    let mut out = Vec::new();
    for lp in super::plan::self_contained_blocks(app) {
        out.extend(taken_ops(app, lp, config)?);
    }
    Ok(out)
}

/// How an op names its object: by index when it carries `ObjIdx`, else by
/// `ObjType` and `Occurrence`, the device object by index 0.
fn prop_object(
    step: usize,
    obj_idx: Option<u32>,
    obj_type: Option<u32>,
    occurrence: Option<u32>,
) -> Result<PropObject, PlanError> {
    match (obj_idx, obj_type) {
        (Some(index), _) => Ok(PropObject::Index(index)),
        (None, Some(OT_DEVICE)) if occurrence.unwrap_or(0) == 0 => Ok(PropObject::Index(0)),
        (None, Some(object_type)) => {
            let object_type =
                u16::try_from(object_type).map_err(|_| PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!("object type {object_type} exceeds 16 bits"),
                })?;
            let occurrence = u16::try_from(occurrence.unwrap_or(0))
                .ok()
                .filter(|o| *o < 0x0FFF)
                .ok_or_else(|| PlanError::UnsupportedWriteProp {
                    step,
                    reason: format!(
                        "occurrence {} of object type {object_type} exceeds the 12-bit \
                         instance the extended property services carry",
                        occurrence.unwrap_or(0)
                    ),
                })?;
            Ok(PropObject::Type {
                object_type,
                occurrence,
            })
        }
        // Neither: the device object, as the System B lowering has always
        // read an op without an object.
        (None, None) => Ok(PropObject::Index(0)),
    }
}

/// The parameter-composed value of the property `object`/`prop_id` names,
/// from `values` ([`bussard_prod::compute_property_values`]).
fn parameter_value(
    values: &PropertyValues,
    obj_idx: Option<u32>,
    obj_type: Option<u32>,
    occurrence: Option<u32>,
    prop_id: u32,
) -> Option<&Vec<u8>> {
    let by_index = obj_idx.and_then(|i| values.get(&(PropertyObjectRef::Index(i), prop_id)));
    let by_type = obj_type.and_then(|t| {
        values.get(&(
            PropertyObjectRef::Type {
                object_type: t,
                occurrence: occurrence.unwrap_or(0),
            },
            prop_id,
        ))
    });
    by_index.or(by_type)
}

/// Lowers an `LdCtrlWriteProp` with its `Count` and `Verify` (the System 7
/// and property-only planners; the System B planner keeps its own lowering).
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the value has no source, does not
/// split into `Count` whole elements, or the object or property id does not
/// fit the services that address it.
pub(super) fn lower_write_prop(
    step: usize,
    op: &LoadOp,
    values: &PropertyValues,
) -> Result<FlashStep, PlanError> {
    let LoadOp::WriteProp {
        obj_idx,
        obj_type,
        prop_id,
        inline_data,
        start_element,
        count,
        verify,
        occurrence,
    } = op
    else {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: "not an LdCtrlWriteProp".to_string(),
        });
    };
    let prop_id = prop_id.ok_or_else(|| PlanError::UnsupportedWriteProp {
        step,
        reason: "the op names no PropId".to_string(),
    })?;
    let object = prop_object(step, *obj_idx, *obj_type, *occurrence)?;
    let name = format!("{object} PID {prop_id}");
    let value = match inline_data.as_ref().filter(|d| !d.is_empty()) {
        Some(data) => data.clone(),
        None => parameter_value(values, *obj_idx, *obj_type, *occurrence, prop_id)
            .cloned()
            .ok_or_else(|| PlanError::UnsupportedWriteProp {
                step,
                reason: format!(
                    "the write to {name} carries no InlineData and no parameter of the \
                     program is located in that property, so bussard has no value to write"
                ),
            })?,
    };
    let count = count.unwrap_or(1).max(1);
    let count = u16::try_from(count)
        .ok()
        .filter(|c| *c <= u16::from(u8::MAX))
        .ok_or_else(|| PlanError::UnsupportedWriteProp {
            step,
            reason: format!("the write to {name} has Count {count}, more than 255 elements"),
        })?;
    if !value.len().is_multiple_of(usize::from(count)) {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!(
                "the {}-octet value for {name} does not split into Count {count} whole elements",
                value.len()
            ),
        });
    }
    let start_element = start_element
        .and_then(|e| u16::try_from(e).ok())
        .unwrap_or(1)
        .max(1);
    if let PropObject::Index(index) = object
        && index > u32::from(u8::MAX)
    {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!("object index {index} exceeds the 8-bit index the services address"),
        });
    }
    let pid_limit = match object {
        PropObject::Index(_) => u32::from(u8::MAX),
        PropObject::Type { .. } => 0x0FFF,
    };
    if prop_id > pid_limit {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: format!("property id {prop_id} exceeds what the property services address"),
        });
    }
    Ok(FlashStep::WriteProp {
        object,
        prop_id,
        value,
        start_element,
        count,
        verify: verify.unwrap_or(false),
    })
}

/// Lowers an `LdCtrlCompareProp`.
///
/// # Errors
///
/// [`PlanError::UnsupportedWriteProp`] when the op names an object the
/// services cannot address.
pub(super) fn lower_compare_prop(step: usize, op: &LoadOp) -> Result<FlashStep, PlanError> {
    let LoadOp::CompareProp {
        obj_idx,
        obj_type,
        prop_id,
        inline_data,
        mask,
        occurrence,
        ..
    } = op
    else {
        return Err(PlanError::UnsupportedWriteProp {
            step,
            reason: "not an LdCtrlCompareProp".to_string(),
        });
    };
    Ok(FlashStep::CompareProp {
        object: prop_object(step, *obj_idx, *obj_type, *occurrence)?,
        prop_id: prop_id.unwrap_or(0),
        expected: inline_data.clone(),
        mask: mask.clone(),
    })
}

/// Plans a property-only procedure ([`is_property_only`]): its compares and
/// writes, in order, and a restart when the procedure asks for one. Nothing
/// is loaded, so the plan carries no images.
///
/// # Errors
///
/// [`PlanError::NoProcedure`] for an empty procedure, and the lowering errors
/// of [`lower_write_prop`] and [`lower_compare_prop`].
pub(super) fn plan_flash_properties(
    app: &ApplicationProgram,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    memo: &bussard_prod::dynamic::DynamicMemo<'_, ApplicationProgram>,
) -> Result<FlashPlan, PlanError> {
    let app_mask = app
        .mask_version
        .clone()
        .ok_or_else(|| PlanError::MissingAppMask(app.id.clone()))?;
    let config = memo.evaluate_for(app, overrides);
    let ops = guarded_ops(app, &config)?;
    if ops.is_empty() {
        return Err(PlanError::NoProcedure(app.id.clone()));
    }
    let values = bussard_prod::compute_property_values(app, &config).map_err(|e| {
        PlanError::UnsupportedWriteProp {
            step: 0,
            reason: format!("composing the property values from the parameters: {e}"),
        }
    })?;
    let mut steps = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let step = i + 1;
        match op {
            LoadOp::Connect | LoadOp::Disconnect => {}
            LoadOp::Restart => steps.push(FlashStep::Restart),
            LoadOp::WriteProp { .. } => steps.push(lower_write_prop(step, op, &values)?),
            LoadOp::CompareProp { .. } => steps.push(lower_compare_prop(step, op)?),
            other => {
                return Err(PlanError::UnsupportedOp {
                    op: format!("{other:?}"),
                });
            }
        }
    }
    Ok(FlashPlan {
        identity: AppIdentity {
            id: app.id.clone(),
            name: app.name.clone(),
            application_number: app.application_number,
            application_version: app.application_version,
            mask_version: app_mask,
        },
        device_mask,
        steps,
        images: BTreeMap::new(),
        param_images: BTreeMap::new(),
        spliced_from_template: false,
        sys7: None,
        confirmed_restart: false,
        baseline: BTreeMap::new(),
        placed: BTreeMap::new(),
        unwritten: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::application::parse_application_program;
    use bussard_prod::dynamic::DynamicMemo;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// An MDT 0705-shaped procedure: a label write guarded by `P-18 >= 3`, a
    /// default branch, and a 0701-shaped inline `Count="2"` write.
    fn guarded_app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-0083_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-0705" Name="G">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-0083_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="9" /></ParameterType>
            <ParameterType Id="M-0083_A-1_PT-t" Name="t"><TypeText SizeInBit="32" /></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-0083_A-1_P-18" Name="mode" ParameterType="M-0083_A-1_PT-u8" Value="1" />
            <Parameter Id="M-0083_A-1_P-36" Name="label" ParameterType="M-0083_A-1_PT-t" Value="Off">
             <Property ObjectIndex="6" PropertyId="60" Offset="0" BitOffset="0" />
            </Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-0083_A-1_P-18_R-8" RefId="M-0083_A-1_P-18" />
            <ParameterRef Id="M-0083_A-1_P-36_R-36" RefId="M-0083_A-1_P-36" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <choose ParamRefId="M-0083_A-1_P-18_R-8">
              <when test="&gt;=3">
               <LdCtrlWriteProp ObjIdx="6" PropId="60" Verify="false" />
              </when>
              <when default="true">
               <LdCtrlCompareProp InlineData="01" ObjIdx="0" PropId="19" />
              </when>
             </choose>
             <LdCtrlWriteProp ObjIdx="3" PropId="204" Count="2" Verify="false" InlineData="00004000000076FF0000" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        Ok(parse_application_program("M-0083_A-1", xml.as_bytes())?)
    }

    fn ops_for(app: &ApplicationProgram, mode: &str) -> Result<Vec<LoadOp>, PlanError> {
        let memo = DynamicMemo::new(app);
        let overrides = BTreeMap::from([("P-18_R-8".to_string(), mode.to_string())]);
        guarded_ops(app, &memo.evaluate_for(app, &overrides))
    }

    #[test]
    fn test_guarded_ops_takes_the_matching_branch() -> TestResult {
        let app = guarded_app()?;
        let taken = ops_for(&app, "3")?;
        assert!(taken.iter().any(|op| matches!(
            op,
            LoadOp::WriteProp {
                prop_id: Some(60),
                ..
            }
        )));
        assert!(
            !taken
                .iter()
                .any(|op| matches!(op, LoadOp::CompareProp { .. }))
        );
        Ok(())
    }

    #[test]
    fn test_guarded_ops_takes_the_default_branch() -> TestResult {
        let app = guarded_app()?;
        let taken = ops_for(&app, "1")?;
        assert!(!taken.iter().any(|op| matches!(
            op,
            LoadOp::WriteProp {
                prop_id: Some(60),
                ..
            }
        )));
        assert!(
            taken
                .iter()
                .any(|op| matches!(op, LoadOp::CompareProp { .. }))
        );
        // The unguarded ops always run.
        assert_eq!(taken.len(), 4);
        Ok(())
    }

    #[test]
    fn test_guarded_ops_refuses_a_value_it_cannot_compare() -> TestResult {
        let app = guarded_app()?;
        assert!(matches!(
            ops_for(&app, "three"),
            Err(PlanError::UndecidableCondition { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_takes_the_parameter_value_and_the_count() -> TestResult {
        let app = guarded_app()?;
        let memo = DynamicMemo::new(&app);
        let config = memo.evaluate_for(&app, &BTreeMap::new());
        let values = bussard_prod::compute_property_values(&app, &config)?;
        let ops = ops_for(&app, "3")?;
        let label = ops
            .iter()
            .find(|op| {
                matches!(
                    op,
                    LoadOp::WriteProp {
                        prop_id: Some(60),
                        ..
                    }
                )
            })
            .ok_or("the label write is taken")?;
        assert_eq!(
            lower_write_prop(2, label, &values)?,
            FlashStep::WriteProp {
                object: PropObject::Index(6),
                prop_id: 60,
                value: b"Off\0".to_vec(),
                start_element: 1,
                count: 1,
                verify: false,
            }
        );
        let inline = ops
            .iter()
            .find(|op| {
                matches!(
                    op,
                    LoadOp::WriteProp {
                        prop_id: Some(204),
                        ..
                    }
                )
            })
            .ok_or("the inline write is unguarded")?;
        match lower_write_prop(3, inline, &values)? {
            FlashStep::WriteProp { count, value, .. } => {
                assert_eq!(count, 2);
                assert_eq!(value.len(), 10);
            }
            other => return Err(format!("expected WriteProp, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_lower_write_prop_refuses_a_value_that_does_not_split_into_count() -> TestResult {
        let op = LoadOp::WriteProp {
            obj_idx: Some(3),
            obj_type: None,
            prop_id: Some(204),
            inline_data: Some(vec![0; 9]),
            start_element: None,
            count: Some(2),
            verify: None,
            occurrence: None,
        };
        assert!(matches!(
            lower_write_prop(1, &op, &PropertyValues::new()),
            Err(PlanError::UnsupportedWriteProp { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_is_property_only_needs_a_property_op() -> TestResult {
        let app = guarded_app()?;
        assert!(is_property_only(&app));
        let mut connect_only = app.clone();
        for lp in &mut connect_only.load_procedures {
            lp.ops
                .retain(|op| matches!(op, LoadOp::Connect | LoadOp::Disconnect));
        }
        assert!(!is_property_only(&connect_only));
        Ok(())
    }
}
