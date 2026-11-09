//! The parameter-only download of a program whose parameters all live in
//! interface-object properties (issue #944, the Hager 07B0 shape): the
//! `par` procedure's partial download on the object its `par` allocation
//! names, around every property the parameters are placed in. The service
//! refuses to send it to a device until the ETS capture of #572 A.4 confirms
//! the sequence; this test keeps the download itself exercised on the mock.

use std::collections::BTreeMap;

use bussard_download::{
    FlashStep, PartialPlanError, PropObject, Session, changed_properties, flash,
    planned_parameter_regions, read_parameter_properties, read_parameter_regions,
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
    let properties = read_parameter_properties(session.l4(), &plan, &app).await;
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
    let after = read_parameter_properties(session.l4(), &plan, &app).await;
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
