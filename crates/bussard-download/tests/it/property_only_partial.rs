//! The parameter-only download of a program whose parameters all live in
//! interface-object properties (issue #944, the Hager 07B0 shape): the
//! `par` procedure's partial download on the object its `par` allocation
//! names, around every property the parameters are placed in, as ETS sends
//! it (the `run=params` row of the ETS sweep's E804 capture, #572 A.4).

use std::collections::BTreeMap;

use bussard_download::{
    FlashStep, PartialPlanError, PropObject, Session, changed_properties, flash,
    planned_parameter_regions, read_checked_properties, read_parameter_regions,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_product::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::consts::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

/// A synthetic property-only 07B0 program (bussard's own work, MIT): object
/// 10 PID 52 holds "Delay" (octet 0, default 5) and "Level" (octet 1,
/// default 9); the allocation is stated `full` (Mode 1) and `par` (Mode 0).
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard property-only test app" LoadProcedureStyle="ProductDefault"
            MinEtsVersion="5.0">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="dly" Text="Delay" ParameterType="M-00FA_A-0002_PT-0" Value="5"><Property ObjectIndex="10" PropertyId="52" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="lvl" Text="Level" ParameterType="M-00FA_A-0002_PT-0" Value="9"><Property ObjectIndex="10" PropertyId="52" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" Mode="1" Fill="0" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" Mode="0" Fill="0" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full,par" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

fn app() -> TestResult<ApplicationProgram> {
    Ok(parse_application_program(
        "M-00FA_A-0002",
        APP_XML.as_bytes(),
    )?)
}

fn plan_of(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> TestResult<bussard_download::FlashPlan> {
    Ok(plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}

#[tokio::test]
async fn test_parameters_only_of_a_property_only_program_writes_the_property() -> TestResult {
    let app = app()?;
    let defaults = plan_of(&app, &BTreeMap::new())?;
    let overrides = BTreeMap::from([("P-1_R-2".to_string(), "20".to_string())]);
    let plan = plan_of(&app, &overrides)?;
    assert!(!plan.has_parameter_memory());

    let device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(10, 52, 1, &[0, 0]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(
        &mut bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    // The device holds the defaults.
    let outcome = flash(
        &mut session,
        &defaults,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    assert!(outcome.ok(), "{outcome:?}");

    // No parameter memory to read; the property differs from the model.
    let regions = read_parameter_regions(session.l4(), &plan, &[]).await;
    assert!(regions.is_empty(), "{regions:?}");
    let properties = read_checked_properties(session.l4(), &plan, &app).await;
    let changed = changed_properties(&properties);
    assert_eq!(changed.len(), 1, "{properties:?}");
    assert_eq!(changed[0].device, Some(vec![0x05, 0x09]));

    // The partial download: the bracket on the application object around
    // the declared property write, no memory write.
    let partial = plan.parameters_only(&regions)?;
    assert!(partial.is_parameters_only());
    assert_eq!(partial.changed_octets(), 0);
    let shape: Vec<&str> = partial
        .steps
        .iter()
        .map(|s| match s {
            FlashStep::Unload { .. } => "unload",
            FlashStep::StartLoading { .. } => "start",
            FlashStep::AllocateSegment { .. } => "allocate",
            FlashStep::DeclareProp { .. } => "declare",
            FlashStep::WriteProp { .. } => "write-prop",
            FlashStep::LoadCompleted { .. } => "complete",
            FlashStep::Restart => "restart",
            FlashStep::WriteRelMem { .. } | FlashStep::WriteMem { .. } => "memory",
            _ => "other",
        })
        .collect();
    assert_eq!(
        shape,
        [
            "unload",
            "start",
            "allocate",
            "declare",
            "write-prop",
            "complete",
            "restart"
        ],
        "{:?}",
        partial.steps
    );
    assert!(partial.steps.iter().any(|s| matches!(
        s,
        FlashStep::WriteProp {
            object: PropObject::Index(10),
            prop_id: 52,
            ..
        }
    )));

    let outcome = flash(
        &mut session,
        &partial,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    assert!(outcome.ok(), "{outcome:?}");
    let after = read_checked_properties(session.l4(), &plan, &app).await;
    let _ = session.into_disconnect().await;
    assert!(changed_properties(&after).is_empty(), "{after:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(dev.property(10, 52), Some(&[0x05, 0x14][..]));
    Ok(())
}

/// The `par` allocation line of [`APP_XML`].
const PAR_ALLOCATION: &str =
    r#"<LdCtrlRelSegment LsmIdx="4" Size="6" Mode="0" Fill="0" AppliesTo="par" />"#;

/// [`APP_XML`] with its `par` allocation line replaced by `with`.
fn plan_with_par_allocation(with: &str) -> TestResult<bussard_download::FlashPlan> {
    assert!(APP_XML.contains(PAR_ALLOCATION));
    let xml = APP_XML.replace(PAR_ALLOCATION, with);
    let app = parse_application_program("M-00FA_A-0002", xml.as_bytes())?;
    plan_of(&app, &BTreeMap::new())
}

#[test]
fn test_parameters_only_of_a_property_only_program_without_par_allocation_is_refused() -> TestResult
{
    // No `par` allocation: no load to write the properties in.
    let plan = plan_with_par_allocation("")?;
    assert_eq!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::NoParAllocation)
    );
    Ok(())
}

#[test]
fn test_parameters_only_of_a_property_only_program_refuses_a_par_allocation_of_another_size()
-> TestResult {
    let plan = plan_with_par_allocation(
        r#"<LdCtrlRelSegment LsmIdx="4" Size="8" Mode="0" Fill="0" AppliesTo="par" />"#,
    )?;
    assert_eq!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::NoParAllocation)
    );
    Ok(())
}

/// A program with a memory parameter ("Delay", segment RS-2 on the
/// application object) and a property parameter on another object ("Level",
/// object 10 PID 52): the shape of `M-0009_A-E802-13-7620` (issue #938).
const MIXED_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard mixed test app" LoadProcedureStyle="ProductDefault"
            MinEtsVersion="5.0">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="dly" Text="Delay" ParameterType="M-00FA_A-0002_PT-0" Value="5"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="lvl" Text="Level" ParameterType="M-00FA_A-0002_PT-0" Value="9"><Property ObjectIndex="10" PropertyId="52" Offset="0" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="1" Verify="false" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

#[test]
fn test_parameters_only_writes_a_property_parameter_off_the_lsm_object() -> TestResult {
    let app = parse_application_program("M-00FA_A-0002", MIXED_APP_XML.as_bytes())?;
    let overrides = BTreeMap::from([("P-1_R-2".to_string(), "20".to_string())]);
    let plan = plan_of(&app, &overrides)?;
    assert!(plan.has_parameter_memory());
    let partial = plan.parameters_only(&planned_parameter_regions(&plan))?;
    // The memory write and the write of object 10 PID 52, which sits on no
    // object the load bracket names.
    assert!(
        partial
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::WriteRelMem { .. })),
        "{:?}",
        partial.steps
    );
    assert!(
        partial.steps.iter().any(|s| matches!(
            s,
            FlashStep::WriteProp {
                object: PropObject::Index(10),
                prop_id: 52,
                value,
                ..
            } if value == &vec![0x14]
        )),
        "{:?}",
        partial.steps
    );
    Ok(())
}

/// Review of #1011: a write the full flash leaves out as held after the
/// parameter reset (issue #951) is written by the parameter-only download,
/// which resets nothing, and still counts as a parameter property.
#[test]
fn test_parameters_only_writes_a_held_property() -> TestResult {
    let app = app()?;
    let mut plan = plan_of(&app, &BTreeMap::new())?;
    for step in &mut plan.steps {
        if let FlashStep::WriteProp {
            object,
            prop_id,
            value,
            start_element,
            count,
            verify,
            from_parameters,
        } = step
        {
            *step = FlashStep::FactoryHeldProp {
                object: *object,
                prop_id: *prop_id,
                value: value.clone(),
                start_element: *start_element,
                count: *count,
                verify: *verify,
                from_parameters: *from_parameters,
                describe: false,
            };
        }
    }
    assert!(
        !plan
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::WriteProp { .. }))
    );
    assert_eq!(plan.parameter_properties().len(), 1);
    let partial = plan.parameters_only(&Default::default())?;
    assert!(partial.steps.iter().any(|s| matches!(
        s,
        FlashStep::WriteProp {
            object: PropObject::Index(10),
            prop_id: 52,
            ..
        }
    )));
    assert!(
        !partial
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::FactoryHeldProp { .. }))
    );
    Ok(())
}

/// Issue #1014: a parameter-only download reads the description of an
/// undeclared property the master data gives no type before its first write,
/// as the full download does (the full download's connection rule; no
/// capture of a parameter-only download shows it).
#[test]
fn test_parameters_only_reads_the_description_of_an_undeclared_property() -> TestResult {
    let xml = APP_XML.replace(
        r#"<LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />"#,
        "",
    );
    let app = parse_application_program("M-00FA_A-0002", xml.as_bytes())?;
    let plan = plan_of(&app, &BTreeMap::new())?;
    let describe = FlashStep::DescribeProp {
        object: PropObject::Index(10),
        prop_id: 52,
        unwritten: None,
    };
    let reads_before_write = |steps: &[FlashStep]| -> Vec<usize> {
        steps
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == describe)
            .map(|(i, _)| i)
            .filter(|i| {
                matches!(
                    steps.get(i + 1),
                    Some(FlashStep::WriteProp {
                        object: PropObject::Index(10),
                        prop_id: 52,
                        ..
                    })
                )
            })
            .collect()
    };
    assert_eq!(reads_before_write(&plan.steps).len(), 1, "{:?}", plan.steps);
    let partial = plan.parameters_only(&Default::default())?;
    assert_eq!(
        reads_before_write(&partial.steps).len(),
        1,
        "{:?}",
        partial.steps
    );
    assert_eq!(partial.steps.iter().filter(|s| **s == describe).count(), 1);
    Ok(())
}

#[test]
fn test_with_property_values_sets_the_parameter_property_writes() -> TestResult {
    // A restore of a property-only program (issue #944): the backup's value
    // replaces the model's in the parameter property write, nothing else.
    let app = app()?;
    let plan = plan_of(&app, &BTreeMap::new())?;
    let partial = plan.parameters_only(&BTreeMap::new())?;
    let values = BTreeMap::from([((PropObject::Index(10), 52, 1), vec![0x07, 0x08])]);
    let restored = partial.with_property_values(&values);
    let writes = |p: &bussard_download::FlashPlan| -> Vec<Vec<u8>> {
        p.steps
            .iter()
            .filter_map(|s| match s {
                FlashStep::WriteProp {
                    object: PropObject::Index(10),
                    prop_id: 52,
                    value,
                    ..
                } => Some(value.clone()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(writes(&partial), vec![vec![0x05, 0x09]]);
    assert_eq!(writes(&restored), vec![vec![0x07, 0x08]]);
    assert_eq!(restored.steps.len(), partial.steps.len());
    Ok(())
}

/// The `MergeId` 4 block of [`par_app_xml`]'s default: the Hager
/// `M-0009_A-E802-13-7620` shape (bussard's own synthetic data, issue
/// #1052): a link reset (`full,grp`, erase code 6), a parameter reset
/// (`full,par`, erase code 5), object 9 PID 208 from fixed data, and object
/// 10 PID 52 from "Delay" and "Level".
pub(crate) const E802_MERGE_4: &str = r#"
                <LdCtrlMasterReset AppliesTo="full,grp" EraseCode="6" ChannelNumber="0" />
                <LdCtrlMasterReset AppliesTo="full,par" EraseCode="5" ChannelNumber="0" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="9" PropId="208" Count="2" Verify="false" InlineData="0102" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="9" PropId="208" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />"#;

/// A merged property-only 07B0 program whose `<LoadProcedures>` are
/// `procedures` (bussard's own synthetic data, issue #1052): object 10 PID
/// 52 holds "Delay" (default 5) and "Level" (default 9).
pub(crate) fn par_app_xml(procedures: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0003" ApplicationNumber="3" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard par procedure test app"
            LoadProcedureStyle="MergedProcedure" MinEtsVersion="5.0">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0003_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0003_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0003_P-0" Name="dly" Text="Delay" ParameterType="M-00FA_A-0003_PT-0" Value="5"><Property ObjectIndex="10" PropertyId="52" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0003_P-1" Name="lvl" Text="Level" ParameterType="M-00FA_A-0003_PT-0" Value="9"><Property ObjectIndex="10" PropertyId="52" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0003_P-0_R-1" RefId="M-00FA_A-0003_P-0" />
              <ParameterRef Id="M-00FA_A-0003_P-1_R-2" RefId="M-00FA_A-0003_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0003_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0003_O-1_R-1" RefId="M-00FA_A-0003_O-1" />
            </ComObjectRefs>
            <LoadProcedures>{procedures}
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0003_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0003_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0003_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0003_O-1_R-1" />
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#
    )
}

/// The E802-shaped procedures: an empty `MergeId` 2 and [`E802_MERGE_4`].
pub(crate) fn e802_procedures() -> String {
    format!(
        r#"
              <LoadProcedure MergeId="2" />
              <LoadProcedure MergeId="4">{E802_MERGE_4}
              </LoadProcedure>"#
    )
}

/// The program of `procedures`, parsed.
pub(crate) fn par_app(procedures: &str) -> TestResult<ApplicationProgram> {
    Ok(parse_application_program(
        "M-00FA_A-0003",
        par_app_xml(procedures).as_bytes(),
    )?)
}

/// The full plan of `app` spliced into the built-in 07B0 template, as
/// `flash` builds it (with the parameter-only procedure it carries).
pub(crate) fn par_plan(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> TestResult<bussard_download::FlashPlan> {
    let template = bussard_product::master::MasterTemplate::builtin_for_mask("07B0")
        .ok_or("a built-in 07B0 template")?;
    let tables = bussard_download::build_table_images(
        None,
        ia("1.1.1")?,
        app,
        overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    let mut plan = plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )?;
    let par = bussard_product::master::MasterTemplate::builtin_par_for_mask("07B0")
        .ok_or("a built-in 07B0 par procedure")?;
    bussard_download::add_par_procedure(
        &mut plan,
        app,
        "1.1.1",
        overrides,
        &BTreeMap::new(),
        Some(&par.ops),
        &tables,
        &BTreeMap::new(),
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    Ok(plan)
}

/// The steps of `plan` in words, the ones a parameter-only test compares.
pub(crate) fn shape(plan: &bussard_download::FlashPlan) -> Vec<String> {
    plan.steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::ReadTableReference { obj_idx } => Some(format!("table-ref {obj_idx}")),
            FlashStep::CompareTableReference { obj_idx } => Some(format!("same-ref {obj_idx}")),
            FlashStep::Unload { target, .. } => Some(format!("unload {}", target.unwrap_or(0))),
            FlashStep::StartLoading { target } => Some(format!("start {}", target.unwrap_or(0))),
            FlashStep::AllocateSegment { target, size, .. } => {
                Some(format!("allocate {} {size}", target.unwrap_or(0)))
            }
            FlashStep::MasterReset { erase_code, .. } => Some(format!("reset {erase_code}")),
            FlashStep::WriteProp {
                object: PropObject::Index(i),
                prop_id,
                start_element,
                ..
            } => Some(format!("write {i}/{prop_id}@{start_element}")),
            FlashStep::FactoryHeldProp {
                object: PropObject::Index(i),
                prop_id,
                ..
            } => Some(format!("held {i}/{prop_id}")),
            FlashStep::LoadImageProp {
                obj_idx, prop_id, ..
            } => Some(format!("mcb {obj_idx}/{prop_id}")),
            FlashStep::LoadCompleted { target } => {
                Some(format!("complete {}", target.unwrap_or(0)))
            }
            FlashStep::Restart => Some("restart".to_string()),
            FlashStep::WriteRelMem { .. } | FlashStep::WriteMem { .. } => {
                Some("memory".to_string())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn test_parameters_only_runs_the_par_procedure_without_par_allocation() -> TestResult {
    // ETS's partial download of M-0009_A-E802-13-7620 (sweep capture
    // `params-partial/b-partial-param`): the base pointer read (op 25), obj4
    // Unload and StartLoading (26, 27), no allocation, the base pointer check
    // (28), the `full,par` reset (29) and not the `full,grp` one, the MergeId
    // 4 property writes, PID 13 (353), LoadCompleted (354), restart (355).
    let app = par_app(&e802_procedures())?;
    let overrides = BTreeMap::from([("P-1_R-2".to_string(), "20".to_string())]);
    let plan = par_plan(&app, &overrides)?;
    let partial = plan.parameters_only(&BTreeMap::new())?;
    assert_eq!(
        shape(&partial),
        [
            "table-ref 4",
            "unload 4",
            "start 4",
            "same-ref 4",
            "reset 5",
            "write 9/208@1",
            "write 10/52@1",
            "write 4/13@1",
            "complete 4",
            "restart"
        ],
        "{:?}",
        partial.steps
    );
    assert!(partial.resets_parameters_first());
    // The captured shape: nothing to flag as unconfirmed.
    assert!(partial.par_procedure_unconfirmed().is_empty());
    // The read-back covers the fixed write as well as the parameters'.
    let checked: Vec<(PropObject, u32)> = plan
        .checked_properties()
        .iter()
        .map(|p| (p.object, p.prop_id))
        .collect();
    assert!(
        checked.contains(&(PropObject::Index(9), 208)),
        "{checked:?}"
    );
    assert!(
        checked.contains(&(PropObject::Index(10), 52)),
        "{checked:?}"
    );
    Ok(())
}

#[test]
fn test_parameters_only_refuses_a_par_procedure_that_drops_a_segment() -> TestResult {
    // A `full`-only allocation on object 4: the par procedure unloads it and
    // allocates nothing, so the object would load again without its memory.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="2"><LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" /></LoadProcedure>
              <LoadProcedure MergeId="4">{E802_MERGE_4}
              </LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    assert_eq!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::DropsSegment { object: 4, size: 6 })
    );
    Ok(())
}

#[test]
fn test_parameters_only_refuses_a_reset_that_erases_what_it_does_not_write_back() -> TestResult {
    // Erase code 4 resets the application program, which a parameter-only
    // download does not load again.
    let app = par_app(&e802_procedures().replace(
        r#"AppliesTo="full,par" EraseCode="5""#,
        r#"AppliesTo="full,par" EraseCode="4""#,
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    assert!(matches!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::ResetLosesState { erase_code: 4, .. })
    ));
    Ok(())
}

#[test]
fn test_parameters_only_keeps_a_held_write_after_the_reset() -> TestResult {
    // A catalogue LoadedImage holding object 9's value after the parameter
    // reset (issue #951): the par procedure leaves the write out as held, as
    // the full download does, and the executor writes it only when the
    // device holds something else.
    let mut app = par_app(&e802_procedures())?;
    app.factory_properties = vec![bussard_product::application::FactoryProperty {
        object: 9,
        prop_id: 208,
        start: 0,
        data: vec![1, 2],
        mask: Vec::new(),
    }];
    let plan = par_plan(&app, &BTreeMap::new())?;
    let partial = plan.parameters_only(&BTreeMap::new())?;
    let steps = shape(&partial);
    assert!(steps.contains(&"held 9/208".to_string()), "{steps:?}");
    assert_eq!(
        partial.par_procedure_unconfirmed(),
        ["a write left out as held after the parameter reset (#951)"]
    );
    assert!(!steps.contains(&"write 9/208@1".to_string()), "{steps:?}");
    Ok(())
}

#[test]
fn test_parameters_only_par_procedure_leaves_out_mergeid_1() -> TestResult {
    // The par procedure has no MergeId 1: its `full,par` write is not sent,
    // as ETS does not send E804's MergeId 1 write in its partial download.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="1"><LdCtrlWriteProp AppliesTo="full,par" ObjIdx="9" PropId="51" Verify="false" InlineData="01" /></LoadProcedure>
              <LoadProcedure MergeId="4">{E802_MERGE_4}
              </LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    assert!(shape(&plan).contains(&"write 9/51@1".to_string()));
    let partial = plan.parameters_only(&BTreeMap::new())?;
    assert!(!shape(&partial).contains(&"write 9/51@1".to_string()));
    Ok(())
}

#[test]
fn test_parameters_only_par_procedure_sends_only_the_par_range_of_a_property() -> TestResult {
    // Two writes to one property: elements 1 and 2 `full` only, 3 and 4
    // `full,par`. The par procedure sends the second alone.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="4">{E802_MERGE_4}
                <LdCtrlWriteProp AppliesTo="full" ObjIdx="11" PropId="208" StartElement="1" Count="2" Verify="false" InlineData="0101" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="11" PropId="208" StartElement="3" Count="2" Verify="false" InlineData="0202" />
              </LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let full = shape(&plan);
    assert!(full.contains(&"write 11/208@1".to_string()), "{full:?}");
    let partial = shape(&plan.parameters_only(&BTreeMap::new())?);
    assert!(
        partial.contains(&"write 11/208@3".to_string()),
        "{partial:?}"
    );
    assert!(
        !partial.contains(&"write 11/208@1".to_string()),
        "{partial:?}"
    );
    Ok(())
}

#[test]
fn test_parameters_only_par_procedure_runs_mergeid_7_without_applies_to() -> TestResult {
    // The E804 shape (#1038): a MergeId 1 write and a MergeId 7 write without
    // AppliesTo, and a `par` allocation in Mode 0. ETS's partial download
    // sends the MergeId 7 write and its MCB checks, not the MergeId 1 one.
    let app = par_app(
        r#"
              <LoadProcedure MergeId="1"><LdCtrlWriteProp ObjIdx="9" PropId="51" Verify="false" InlineData="01" /></LoadProcedure>
              <LoadProcedure MergeId="2">
                <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
                <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6" Mode="0" Fill="0" />
              </LoadProcedure>
              <LoadProcedure MergeId="4">
                <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />
              </LoadProcedure>
              <LoadProcedure MergeId="7">
                <LdCtrlLoadImageProp ObjIdx="4" PropId="27" />
                <LdCtrlWriteProp ObjIdx="9" PropId="51" Verify="false" InlineData="02" />
              </LoadProcedure>"#,
    )?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let partial = plan.parameters_only(&BTreeMap::new())?;
    assert_eq!(
        shape(&partial),
        [
            "table-ref 4",
            "unload 4",
            "start 4",
            "allocate 4 6",
            "same-ref 4",
            "write 10/52@1",
            "write 4/13@1",
            "complete 4",
            "mcb 4/27",
            "write 9/51@1",
            "restart"
        ],
        "{:?}",
        partial.steps
    );
    // The code image is not rewritten (a differential download); the MCB
    // check compares it.
    assert!(partial.steps.iter().any(|s| matches!(
        s,
        FlashStep::LoadImageProp {
            obj_idx: 4,
            image: Some(_),
            ..
        }
    )));
    Ok(())
}

#[test]
fn test_parameters_only_par_procedure_brackets_object_5_with_application_program_2() -> TestResult {
    // A MergeId 5 block loads Application Program 2: the par procedure runs
    // object 5's rows as the master states them.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="4">{E802_MERGE_4}
              </LoadProcedure>
              <LoadProcedure MergeId="5"><LdCtrlWriteProp AppliesTo="full,par" ObjIdx="12" PropId="208" Verify="false" InlineData="05" /></LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let partial_plan = plan.parameters_only(&BTreeMap::new())?;
    assert_eq!(
        partial_plan.par_procedure_unconfirmed(),
        ["object 5 (Application Program 2) loaded with object 4"]
    );
    let partial = shape(&partial_plan);
    for step in [
        "table-ref 5",
        "unload 5",
        "start 5",
        "same-ref 5",
        "write 12/208@1",
        "complete 5",
    ] {
        assert!(partial.contains(&step.to_string()), "{step}: {partial:?}");
    }
    Ok(())
}

#[test]
fn test_parameters_only_without_par_allocation_off_the_template_is_still_refused() -> TestResult {
    // The same blocks planned without the master template: no par procedure
    // frames them, so there is no load to write them in.
    let app = par_app(&e802_procedures())?;
    let plan = plan_of(&app, &BTreeMap::new())?;
    assert_eq!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::NoParAllocation)
    );
    Ok(())
}

/// The E804-shaped procedures (#1038): a MergeId 1 write and a MergeId 7
/// write without `AppliesTo`, a `par` allocation in Mode 0, the code image,
/// and MergeId 7's MCB checks of the address table and object 4.
pub(crate) const E804_PROCEDURES: &str = r#"
              <LoadProcedure MergeId="1"><LdCtrlWriteProp ObjIdx="9" PropId="51" Verify="false" InlineData="01" /></LoadProcedure>
              <LoadProcedure MergeId="2">
                <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
                <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6" Mode="0" Fill="0" />
              </LoadProcedure>
              <LoadProcedure MergeId="4">
                <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
                <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="10" PropId="52" PropType="PDT_UNSIGNED_CHAR" MaxElements="2" ReadAccess="0" WriteAccess="0" Writable="true" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10" PropId="52" Count="2" Verify="false" />
              </LoadProcedure>
              <LoadProcedure MergeId="7">
                <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
                <LdCtrlLoadImageProp ObjIdx="4" PropId="27" />
                <LdCtrlWriteProp ObjIdx="9" PropId="51" Verify="false" InlineData="02" />
              </LoadProcedure>"#;

#[test]
fn test_parameters_only_par_procedure_writes_a_code_image_its_allocation_refills() -> TestResult {
    // A MergeId 2 allocation without `AppliesTo` in Mode 1: the par procedure
    // allocates object 4 with the fill bit set, the device refills the
    // segment, so the code image is written as the procedure says.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="2"><LdCtrlRelSegment LsmIdx="4" Size="6" Mode="1" Fill="0" /></LoadProcedure>
              <LoadProcedure MergeId="4">
                <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" Verify="true" />{E802_MERGE_4}
              </LoadProcedure>
              <LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="4" PropId="27" /></LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let partial = shape(&plan.parameters_only(&BTreeMap::new())?);
    assert!(partial.contains(&"allocate 4 6".to_string()), "{partial:?}");
    assert!(partial.contains(&"memory".to_string()), "{partial:?}");
    // In Mode 0 (the E804 shape) the image is kept and not rewritten.
    let app = par_app(E804_PROCEDURES)?;
    let partial = shape(&par_plan(&app, &BTreeMap::new())?.parameters_only(&BTreeMap::new())?);
    assert!(!partial.contains(&"memory".to_string()), "{partial:?}");
    Ok(())
}

#[test]
fn test_parameters_only_par_procedure_runs_auto_all_and_empty_applies_to() -> TestResult {
    // `auto`, `all` and an empty `AppliesTo` run in every download, the
    // par procedure included; `full` does not.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="4">{E802_MERGE_4}
                <LdCtrlWriteProp AppliesTo="auto" ObjIdx="11" PropId="1" Verify="false" InlineData="01" />
                <LdCtrlWriteProp AppliesTo="all" ObjIdx="11" PropId="2" Verify="false" InlineData="02" />
                <LdCtrlWriteProp AppliesTo="" ObjIdx="11" PropId="3" Verify="false" InlineData="03" />
                <LdCtrlWriteProp AppliesTo="full" ObjIdx="11" PropId="4" Verify="false" InlineData="04" />
              </LoadProcedure>"#
    ))?;
    let partial = shape(&par_plan(&app, &BTreeMap::new())?.parameters_only(&BTreeMap::new())?);
    for pid in 1..=3 {
        assert!(
            partial.contains(&format!("write 11/{pid}@1")),
            "{pid}: {partial:?}"
        );
    }
    assert!(
        !partial.contains(&"write 11/4@1".to_string()),
        "{partial:?}"
    );
    Ok(())
}

#[test]
fn test_checked_properties_keep_what_overlapping_writes_leave() -> TestResult {
    // Elements 1 to 4 of object 11 PID 208, then element 3 again: the
    // read-back expects 01 02 on 1..=2, 09 on 3, 04 on 4.
    let app = par_app(&format!(
        r#"
              <LoadProcedure MergeId="4">{E802_MERGE_4}
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="11" PropId="208" StartElement="1" Count="4" Verify="false" InlineData="01020304" />
                <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="11" PropId="208" StartElement="3" Count="1" Verify="false" InlineData="09" />
              </LoadProcedure>"#
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let ranges: Vec<(u16, u16, Vec<u8>)> = plan
        .checked_properties()
        .into_iter()
        .filter(|p| (p.object, p.prop_id) == (PropObject::Index(11), 208))
        .map(|p| (p.start_element, p.count, p.model))
        .collect();
    assert_eq!(
        ranges,
        [(1, 2, vec![1, 2]), (4, 1, vec![4]), (3, 1, vec![9])],
        "{ranges:?}"
    );
    Ok(())
}

#[test]
fn test_parameters_only_on_another_system_b_mask_takes_its_master_par_procedure() -> TestResult {
    // A 17B0 program: bussard carries no par procedure for that mask. Without
    // one in the product's master data the cut of the complete download runs,
    // as before (the E804 shape, its `par` allocation); with one, the
    // procedure runs.
    let xml = par_app_xml(E804_PROCEDURES).replace("MV-07B0", "MV-17B0");
    let app = parse_application_program("M-00FA_A-0003", xml.as_bytes())?;
    let template = bussard_product::master::MasterTemplate::builtin_for_mask("07B0")
        .ok_or("a 07B0 template standing in for the 17B0 master's")?;
    let tables = bussard_download::build_table_images(
        None,
        ia("1.1.1")?,
        &app,
        &BTreeMap::new(),
        &bussard_product::dynamic::DynamicMemo::new(&app),
    );
    let mut plan = plan_flash_default(
        &app,
        "1.1.1",
        0x17B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )?;
    assert_eq!(
        bussard_product::MasterTemplate::builtin_par_for_mask("17B0"),
        None
    );
    let memo = bussard_product::dynamic::DynamicMemo::new(&app);
    bussard_download::add_par_procedure(
        &mut plan,
        &app,
        "1.1.1",
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &tables,
        &BTreeMap::new(),
        &memo,
    );
    let cut = plan.parameters_only(&BTreeMap::new())?;
    assert!(cut.procedure_kind() != bussard_download::ProcedureKind::ParametersByPar);
    assert!(shape(&cut).contains(&"allocate 4 6".to_string()));
    // The product's master declares the par procedure for 17B0.
    let master_par =
        bussard_product::master::MasterTemplate::builtin_par_for_mask("07B0").ok_or("par ops")?;
    bussard_download::add_par_procedure(
        &mut plan,
        &app,
        "1.1.1",
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&master_par.ops),
        &tables,
        &BTreeMap::new(),
        &memo,
    );
    let par = plan.parameters_only(&BTreeMap::new())?;
    assert!(par.procedure_kind() == bussard_download::ProcedureKind::ParametersByPar);
    assert!(shape(&par).contains(&"table-ref 4".to_string()));
    Ok(())
}

#[test]
fn test_parameters_only_refuses_a_parameter_the_par_procedure_does_not_write() -> TestResult {
    // The parameters' property is written `full` only: the parameter-only
    // procedure would reset it and never write it back. Refused, naming it.
    let app = par_app(&e802_procedures().replace(
        r#"<LdCtrlWriteProp AppliesTo="full,par" ObjIdx="10""#,
        r#"<LdCtrlWriteProp AppliesTo="full" ObjIdx="10""#,
    ))?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    match plan.parameters_only(&BTreeMap::new()) {
        Err(PartialPlanError::ParameterNotInProcedure { property }) => {
            assert!(property.contains("PID 52"), "{property}");
        }
        other => return Err(format!("expected a refusal: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_parameters_only_gates_the_steps_the_par_procedure_runs() -> TestResult {
    // A function property call the complete download makes (`full`) is not
    // sent by the parameter-only procedure, so it refuses nothing; one the
    // procedure makes (`par`) has no captured parameter-only form: refused.
    let call = |applies: &str| {
        format!(
            r#"
              <LoadProcedure MergeId="4">{E802_MERGE_4}
                <LdCtrlInvokeFunctionProp AppliesTo="{applies}" ObjIdx="11" PropId="60" InlineData="01" />
              </LoadProcedure>"#
        )
    };
    let full = par_plan(&par_app(&call("full"))?, &BTreeMap::new())?;
    assert!(full.parameters_only(&BTreeMap::new()).is_ok());
    let par = par_plan(&par_app(&call("full,par"))?, &BTreeMap::new())?;
    assert!(matches!(
        par.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::UncapturedStep { .. })
    ));
    Ok(())
}

#[test]
fn test_checked_properties_mark_the_fixed_writes() -> TestResult {
    // Object 9's `InlineData` write is checked but is no parameter change.
    let app = par_app(&e802_procedures())?;
    let plan = par_plan(&app, &BTreeMap::new())?;
    let mut checked = plan.checked_properties();
    for p in &mut checked {
        p.device = Some(vec![0xEE; p.model.len()]);
    }
    let changed = bussard_download::changed_parameter_properties(&checked);
    assert!(
        changed.iter().all(|p| p.prop_id == 52),
        "only the parameter property is a parameter change: {changed:?}"
    );
    assert!(checked.iter().any(|p| p.fixed && p.prop_id == 208));
    Ok(())
}

/// [`par_app_xml`] of `procedures` with a second code segment on object 5
/// (Application Program 2).
pub(crate) fn par_app_with_ap2(procedures: &str) -> TestResult<ApplicationProgram> {
    let xml = par_app_xml(procedures).replace(
        "</RelativeSegment>\n            </Code>",
        "</RelativeSegment>\n              <RelativeSegment Id=\"M-00FA_A-0003_RS-2\" Size=\"4\" LoadStateMachine=\"5\" Offset=\"0\"><Data>CQkJCQ==</Data></RelativeSegment>\n            </Code>",
    );
    assert!(xml.contains("RS-2"));
    Ok(parse_application_program("M-00FA_A-0003", xml.as_bytes())?)
}

/// Application Program 2 with its own code image, kept by the parameter-only
/// procedure (Mode 0), and MergeId 7's MCB check of object 5.
pub(crate) fn ap2_procedures() -> String {
    format!(
        r#"
              <LoadProcedure MergeId="3">
                <LdCtrlRelSegment AppliesTo="full" LsmIdx="5" Size="4" Mode="1" Fill="0" />
                <LdCtrlRelSegment AppliesTo="par" LsmIdx="5" Size="4" Mode="0" Fill="0" />
              </LoadProcedure>
              <LoadProcedure MergeId="4">{E802_MERGE_4}
              </LoadProcedure>
              <LoadProcedure MergeId="5"><LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="5" Offset="0" Size="4" Verify="true" /></LoadProcedure>
              <LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="5" PropId="27" /></LoadProcedure>"#
    )
}

/// The E802 blocks with a MergeId 2 allocation of object 4 without
/// `AppliesTo` in Mode 1 (the device refills the segment) and `write` as the
/// code segment's write; `check` adds MergeId 7's MCB check of object 4.
fn refilled_procedures(write: &str, check: bool) -> String {
    let check = if check {
        r#"<LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="4" PropId="27" /></LoadProcedure>"#
    } else {
        ""
    };
    format!(
        r#"
              <LoadProcedure MergeId="2"><LdCtrlRelSegment LsmIdx="4" Size="6" Mode="1" Fill="0" /></LoadProcedure>
              <LoadProcedure MergeId="4">
                {write}{E802_MERGE_4}
              </LoadProcedure>
              {check}"#
    )
}

#[test]
fn test_parameters_only_refuses_a_refilled_segment_it_does_not_rewrite_and_check() -> TestResult {
    // (b) The code write is `full` only: the par procedure refills object 4
    // and nothing writes it again. Refused, naming the segment.
    let full_only =
        r#"<LdCtrlWriteRelMem AppliesTo="full" ObjIdx="4" Offset="0" Size="6" Verify="true" />"#;
    let plan = par_plan(
        &par_app(&refilled_procedures(full_only, true))?,
        &BTreeMap::new(),
    )?;
    match plan.parameters_only(&BTreeMap::new()) {
        Err(PartialPlanError::RefilledSegmentUnwritten {
            object: 4,
            segment,
            rewritten: false,
        }) => assert_eq!(segment, "M-00FA_A-0003_RS-1"),
        other => return Err(format!("expected a refusal: {other:?}").into()),
    }
    // (a) The code write names object 0 and binds to object 4's allocation:
    // written again, and with MergeId 7's check compared, so accepted; the
    // check compares the image (not a bare read).
    let objidx_0 = r#"<LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" Verify="true" />"#;
    let plan = par_plan(
        &par_app(&refilled_procedures(objidx_0, true))?,
        &BTreeMap::new(),
    )?;
    let partial = plan.parameters_only(&BTreeMap::new())?;
    assert!(shape(&partial).contains(&"memory".to_string()));
    let checks: Vec<&FlashStep> = partial
        .steps
        .iter()
        .filter(|s| matches!(s, FlashStep::LoadImageProp { .. }))
        .collect();
    assert!(
        checks
            .iter()
            .any(|s| matches!(s, FlashStep::LoadImageProp { image: Some(_), .. })),
        "{checks:?}"
    );
    // Without a check of it, the rewritten segment is not compared: refused.
    let plan = par_plan(
        &par_app(&refilled_procedures(objidx_0, false))?,
        &BTreeMap::new(),
    )?;
    assert!(matches!(
        plan.parameters_only(&BTreeMap::new()).err(),
        Some(PartialPlanError::RefilledSegmentUnwritten {
            rewritten: true,
            ..
        })
    ));
    Ok(())
}
