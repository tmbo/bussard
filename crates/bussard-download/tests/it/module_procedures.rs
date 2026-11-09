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
use bussard_product::application::LoadOp;
use bussard_product::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::TestResult;

use crate::support::plan_flash_default;

/// A 07B0 program whose `MergeId="4"` procedure holds `marker`, with one
/// module definition (`BaseObjectIndex` argument `A-1`) whose procedure
/// writes PID 208 of object 0 relative to it. The selector `P-1` reaches the
/// instance with base 6 (value 1, the default) or both instances, bases 6
/// and 7 (value 2).
fn module_app(marker: &str) -> TestResult<ApplicationProgram> {
    module_app_with(marker, "MV-07B0", METERING_OPS)
}

/// The module op of the Hager `M-0009_A-E0EE-10-ADF8` (line 1088 of its
/// application XML).
const METERING_OPS: &str = r#"<LdCtrlWriteProp AppliesTo="full,par" ObjIdx="0" PropId="208" Count="164" Verify="false" InlineData="" BaseObjIdx="M-0009_A-1_MD-1_A-1" />"#;

/// [`module_app`] with another mask and other module ops.
fn module_app_with(marker: &str, mask: &str, module_ops: &str) -> TestResult<ApplicationProgram> {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="M-0009_A-1" MaskVersion="{mask}" Name="m" LoadProcedureStyle="MergedProcedure">
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
          <LoadProcedure MergeId="4">{module_ops}</LoadProcedure>
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
    property_steps_with(app, sel, 0x07B0, None)
}

/// [`property_steps`] for the device mask `mask`, spliced into `template`.
fn property_steps_with(
    app: &ApplicationProgram,
    sel: &str,
    mask: u16,
    template: Option<&[LoadOp]>,
) -> Result<Vec<FlashStep>, PlanError> {
    let overrides = BTreeMap::from([("P-1_R-1".to_string(), sel.to_string())]);
    let plan = plan_flash_default(
        app,
        "1.1.1",
        mask,
        &overrides,
        &BTreeMap::new(),
        template,
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
            unwritten: None,
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
                unwritten: None,
            },
            FlashStep::DescribeProp {
                object: PropObject::Index(7),
                prop_id: 208,
                unwritten: None,
            },
        ]
    );
    // No instance reached: the module procedure does not run.
    assert_eq!(property_steps(&app, "0")?, []);
    Ok(())
}

/// A master template that splices `MergeId="4"` between a load and its
/// completion.
fn template_with(merge: &str) -> Vec<LoadOp> {
    vec![
        LoadOp::Load {
            lsm_idx: Some(0),
            obj_type: None,
            occurrence: None,
        },
        LoadOp::Merge {
            merge_id: Some(merge.to_string()),
        },
        LoadOp::LoadCompleted {
            lsm_idx: Some(0),
            obj_type: None,
            occurrence: None,
        },
    ]
}

#[test]
fn test_plan_flash_splices_a_module_procedure_at_the_template_marker() -> TestResult {
    // No application marker: the template's marker of the MergeId takes the
    // instance's procedure, as it takes an application block.
    let app = module_app("")?;
    let template = template_with("4");
    assert_eq!(
        property_steps_with(&app, "1", 0x07B0, Some(&template))?,
        [FlashStep::DescribeProp {
            object: PropObject::Index(6),
            prop_id: 208,
            unwritten: None,
        }]
    );
    Ok(())
}

#[test]
fn test_plan_flash_refuses_a_module_procedure_without_any_marker() -> TestResult {
    let app = module_app("")?;
    let template = template_with("7");
    match property_steps_with(&app, "1", 0x07B0, Some(&template)) {
        Err(PlanError::ModuleProcedure(e)) => {
            assert_eq!(e.module, "MD-1_M-5");
            assert!(e.reason.contains("master template"), "{e}");
            Ok(())
        }
        other => Err(format!("expected a module-procedure refusal, got {other:?}").into()),
    }
}

#[test]
fn test_plan_flash_refuses_an_unsupported_mask_before_the_module_procedures() -> TestResult {
    // The family gate answers first, even for a procedure bussard could not
    // resolve.
    let ops =
        r#"<LdCtrlWriteProp ObjIdx="0" PropId="208" Count="1" BaseOffset="M-0009_A-1_MD-1_A-1" />"#;
    let app = module_app_with(MARKER, "MV-0010", ops)?;
    match property_steps_with(&app, "1", 0x0010, None) {
        Err(PlanError::NotSystemB { .. }) => Ok(()),
        other => Err(format!("expected the family refusal, got {other:?}").into()),
    }
}

#[test]
fn test_plan_flash_refuses_a_shifted_countless_write_past_its_declaration() -> TestResult {
    // A declaration of the module's own procedure, without a base, and a
    // count-less write the instance shifts to element 1 + 6: past the
    // declared MaxElements, which the declared-write rule refuses (#945). A
    // write with a Count is not bounded by MaxElements: ETS wrote the
    // `BaseStartElement` writes of `M-0008_A-C02A-21-B6D8-O007C` from
    // element 50 against a declaration of one element (ops 102 to 105).
    let ops = r#"
        <LdCtrlDeclarePropDesc ObjIdx="10" PropId="208" PropType="PDT_GENERIC_01" MaxElements="2" />
        <LdCtrlWriteProp ObjIdx="10" PropId="208" StartElement="1" InlineData="00" BaseStartElement="M-0009_A-1_MD-1_A-1" />"#;
    let app = module_app_with(MARKER, "MV-07B0", ops)?;
    match property_steps(&app, "1") {
        Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
            assert!(reason.contains("starts at element 7"), "{reason}");
            Ok(())
        }
        other => Err(format!("expected the declared-write refusal, got {other:?}").into()),
    }
}

#[test]
fn test_plan_flash_refuses_a_companion_with_module_procedures() -> TestResult {
    let mut app = module_app(MARKER)?;
    let mut companion = module_app(MARKER)?;
    companion.id = "M-0009_A-2".to_string();
    app.companion_programs.push(companion);
    match property_steps(&app, "1") {
        Err(PlanError::ModuleProcedure(e)) => {
            assert_eq!(e.module, "M-0009_A-2");
            Ok(())
        }
        other => Err(format!("expected a module-procedure refusal, got {other:?}").into()),
    }
}

/// A System B program whose procedure holds a `<choose>` (so the planner
/// keeps octets) and a module procedure bussard cannot resolve.
fn kept_octets_app() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="M-0009_A-1" MaskVersion="MV-07B0" Name="m" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Parameters><Parameter Id="M-0009_A-1_P-1" Name="sel" Value="1" /></Parameters>
       <ParameterRefs><ParameterRef Id="M-0009_A-1_P-1_R-1" RefId="M-0009_A-1_P-1" /></ParameterRefs>
       <LoadProcedures>
        <LoadProcedure MergeId="4">
         <choose ParamRefId="M-0009_A-1_P-1_R-1">
          <when test="1"><LdCtrlLoad LsmIdx="0" /></when>
         </choose>
         <LdCtrlMerge MergeId="4" />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
      <ModuleDefs>
       <ModuleDef Id="M-0009_A-1_MD-1" Name="m">
        <Arguments><Argument Id="M-0009_A-1_MD-1_A-1" Name="BaseObjectIndex" /></Arguments>
        <Static>
         <LoadProcedures>
          <LoadProcedure MergeId="4">
           <LdCtrlWriteProp ObjIdx="0" PropId="208" Count="1" BaseOffset="M-0009_A-1_MD-1_A-1" />
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
       <Module Id="M-0009_A-1_MD-1_M-5" RefId="M-0009_A-1_MD-1"><NumericArg RefId="M-0009_A-1_MD-1_A-1" Value="6" /></Module>
      </Dynamic>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program("M-0009_A-1", xml.as_bytes())?)
}

#[test]
fn test_kept_octets_returns_the_module_procedure_refusal() -> TestResult {
    let app = kept_octets_app()?;
    let memo = bussard_product::dynamic::DynamicMemo::new(&app);
    match bussard_download::flash::kept_octets(&app, &BTreeMap::new(), &memo) {
        Err(PlanError::ModuleProcedure(e)) => {
            assert!(e.reason.contains("BaseOffset"), "{e}");
            Ok(())
        }
        other => Err(format!("expected a module-procedure refusal, got {other:?}").into()),
    }
}

#[test]
fn test_decode_parameters_marks_the_decode_incomplete_without_kept_octets() -> TestResult {
    let app = kept_octets_app()?;
    let memo = bussard_product::dynamic::DynamicMemo::new(&app);
    let decoded = bussard_download::decode_parameters(
        &app,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &memo,
    );
    let why = decoded
        .incomplete
        .ok_or("the decode is not marked incomplete")?;
    assert!(why.contains("BaseOffset"), "{why}");
    Ok(())
}

#[test]
fn test_plan_flash_refuses_a_module_procedure_it_cannot_resolve() -> TestResult {
    let ops =
        r#"<LdCtrlWriteProp ObjIdx="0" PropId="208" Count="1" BaseObjIdx="M-0009_A-1_MD-1_A-9" />"#;
    let app = module_app_with(MARKER, "MV-07B0", ops)?;
    match property_steps(&app, "1") {
        Err(PlanError::ModuleProcedure(e)) => {
            assert_eq!(e.module, "MD-1_M-5");
            Ok(())
        }
        other => Err(format!("expected a module-procedure refusal, got {other:?}").into()),
    }
}
