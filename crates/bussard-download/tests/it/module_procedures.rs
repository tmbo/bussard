//! Module load procedures (issue #959): a `<LoadProcedure>` of a
//! `<ModuleDef>` runs once per reached module instance, in place of the
//! application procedure's `<LdCtrlMerge>`, with its `BaseObjIdx` resolved
//! against the instance's arguments. The shape is the Hager
//! `M-0009_A-E0EE-10-ADF8`'s, whose module op `ObjIdx="0" PropId="208"
//! BaseObjIdx="MD-1_A-1"` ETS ran as a description read of object 6 PID 208
//! for the one instance its defaults reach (`plain-defaults` sweep capture,
//! `ops.txt` op 35).

use std::collections::BTreeMap;

use bussard_download::{FlashStep, PlanError, PropObject};
use bussard_product::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::TestResult;

use crate::support::plan_flash_default;

/// A 07B0 program whose `MergeId="4"` procedure holds `marker`, with one
/// module definition (`BaseObjectIndex` argument `A-1`) whose procedure
/// writes PID 208 of object 0 relative to it. The selector `P-1` reaches the
/// instance with base 6 (value 1, the default) or both instances, bases 6
/// and 7 (value 2).
fn module_app(marker: &str) -> TestResult<ApplicationProgram> {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="M-0009_A-1" MaskVersion="MV-07B0" Name="m" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Parameters><Parameter Id="M-0009_A-1_P-1" Name="sel" Value="1" /></Parameters>
       <ParameterRefs><ParameterRef Id="M-0009_A-1_P-1_R-1" RefId="M-0009_A-1_P-1" /></ParameterRefs>
       <LoadProcedures>
        <LoadProcedure MergeId="4">
         <LdCtrlLoad LsmIdx="0" />
         {marker}
         <LdCtrlLoadCompleted LsmIdx="0" />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
      <ModuleDefs>
       <ModuleDef Id="M-0009_A-1_MD-1" Name="MeteringSensor">
        <Arguments><Argument Id="M-0009_A-1_MD-1_A-1" Name="BaseObjectIndex" /></Arguments>
        <Static>
         <LoadProcedures>
          <LoadProcedure MergeId="4">
           <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="0" PropId="208" Count="164" Verify="false" InlineData="" BaseObjIdx="M-0009_A-1_MD-1_A-1" />
          </LoadProcedure>
         </LoadProcedures>
        </Static>
        <Dynamic><ParameterBlock Id="M-0009_A-1_MD-1_PB-1" /></Dynamic>
       </ModuleDef>
      </ModuleDefs>
      <Dynamic>
       <ChannelIndependentBlock>
        <ParameterBlock Id="M-0009_A-1_PB-1"><ParameterRefRef RefId="M-0009_A-1_P-1_R-1" /></ParameterBlock>
       </ChannelIndependentBlock>
       <choose ParamRefId="M-0009_A-1_P-1_R-1">
        <when test="&gt;=1">
         <Module Id="M-0009_A-1_MD-1_M-5" RefId="M-0009_A-1_MD-1"><NumericArg RefId="M-0009_A-1_MD-1_A-1" Value="6" /></Module>
        </when>
        <when test="2">
         <Module Id="M-0009_A-1_MD-1_M-1" RefId="M-0009_A-1_MD-1"><NumericArg RefId="M-0009_A-1_MD-1_A-1" Value="7" /></Module>
        </when>
       </choose>
      </Dynamic>
     </ApplicationProgram></KNX>"#
    );
    Ok(parse_application_program("M-0009_A-1", xml.as_bytes())?)
}

const MARKER: &str = r#"<LdCtrlMerge AppliesTo="full,par" MergeId="4" />"#;

/// The property steps of the plan of `app` with the selector at `sel`.
fn property_steps(app: &ApplicationProgram, sel: &str) -> Result<Vec<FlashStep>, PlanError> {
    let overrides = BTreeMap::from([("P-1_R-1".to_string(), sel.to_string())]);
    let plan = plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    Ok(plan
        .steps
        .into_iter()
        .filter(|s| {
            matches!(
                s,
                FlashStep::WriteProp { .. } | FlashStep::DescribeProp { .. }
            )
        })
        .collect())
}

#[test]
fn test_plan_flash_runs_a_module_procedure_at_its_instance_object() -> TestResult {
    let app = module_app(MARKER)?;
    // No parameter is placed in the property and the op's InlineData is
    // empty: ETS read the description of object 6 PID 208 and wrote nothing.
    assert_eq!(
        property_steps(&app, "1")?,
        [FlashStep::DescribeProp {
            object: PropObject::Index(6),
            prop_id: 208,
        }]
    );
    // Each reached instance runs the procedure at its own base, in walk
    // order; none runs it at object 0.
    assert_eq!(
        property_steps(&app, "2")?,
        [
            FlashStep::DescribeProp {
                object: PropObject::Index(6),
                prop_id: 208,
            },
            FlashStep::DescribeProp {
                object: PropObject::Index(7),
                prop_id: 208,
            },
        ]
    );
    // No instance reached: the module procedure does not run.
    assert_eq!(property_steps(&app, "0")?, []);
    Ok(())
}

#[test]
fn test_plan_flash_refuses_a_module_procedure_without_its_marker() -> TestResult {
    let app = module_app("")?;
    match property_steps(&app, "1") {
        Err(PlanError::ModuleProcedure(e)) => {
            assert_eq!(e.module, "MD-1_M-5");
            Ok(())
        }
        other => Err(format!("expected a module-procedure refusal, got {other:?}").into()),
    }
}
