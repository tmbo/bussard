//! A merged 07B0 program without group objects (issue #840, ekinex
//! `M-00B6_A-4945-10-C905-O00C5`, KNX IP interface secure): ETS allocates the
//! 2-octet empty table on objects 1 to 3, writes no octet of any of them, and
//! reads each table object's own MCB (`captures/ets-sweep/.../plain-defaults/
//! ops.txt` of 2026-11-04). The flash does the same against a mock device.

use std::collections::BTreeMap;

use bussard_download::{FlashOptions, FlashStep, Session, build_table_images, flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::mcb_entry;
use bussard_testkit::consts::{
    A_MEMORY_WRITE, A_PROPERTY_VALUE_READ, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM,
    OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

/// The shape of `A-4945`: no `<ComObject>`, the parameter segment on LSM 4,
/// the MCB checks of the table objects in `MergeId` 7.
const XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/20">
 <ApplicationProgram Id="M-00FA_A-0002-10-ABCD" ApplicationNumber="2" ApplicationVersion="16"
    MaskVersion="MV-07B0" Name="IP" LoadProcedureStyle="MergedProcedure">
  <Static>
   <Code>
    <RelativeSegment Id="M-00FA_A-0002-10-ABCD_RS-04-00000" Size="4" LoadStateMachine="4" Offset="0"><Data>AQIDBA==</Data></RelativeSegment>
   </Code>
   <AddressTable MaxEntries="200" />
   <AssociationTable MaxEntries="200" />
   <ComObjectTable />
   <LoadProcedures>
    <LoadProcedure MergeId="2">
     <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="4" Mode="1" Fill="0" />
    </LoadProcedure>
    <LoadProcedure MergeId="7">
     <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
     <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
     <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
    </LoadProcedure>
   </LoadProcedures>
  </Static>
 </ApplicationProgram></KNX>"#;

#[tokio::test]
async fn test_flash_program_without_group_objects_writes_no_table() -> TestResult {
    let app = bussard_prod::parse_application_program("M-00FA_A-0002-10-ABCD", XML.as_bytes())?;
    let template =
        bussard_prod::MasterTemplate::builtin_for_mask("07B0").ok_or("a built-in 07B0 template")?;
    let overrides = BTreeMap::new();
    let tables = build_table_images(
        None,
        ia("1.1.1")?,
        &app,
        &overrides,
        &bussard_prod::dynamic::DynamicMemo::new(&app),
    );
    let plan = plan_flash_default(
        &app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )
    .map_err(|e| e.to_string())?;
    assert!(
        !plan
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::WriteRelMem { .. })),
        "{:?}",
        plan.steps
    );

    // The sim's answer to ETS: an empty segment on every table object.
    let empty = mcb_entry(&[], 0xFF);
    let mut device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5]);
    for obj in 1..=3 {
        device = device.with_property(obj, 27, 8, &empty);
    }
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.1")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, &plan, FlashOptions::default(), |_| {}).await;
    let _ = session.into_disconnect().await;
    let outcome = outcome?;
    assert!(outcome.ok(), "{outcome:?}");

    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert!(
        !dev.requests.iter().any(|(apci, _)| *apci == A_MEMORY_WRITE),
        "no table octet is written"
    );
    // Each table's MCB is read on its own object, not on object 4.
    let mcb_reads: Vec<u8> = dev
        .requests
        .iter()
        .filter(|(apci, data)| *apci == A_PROPERTY_VALUE_READ && data.get(1) == Some(&27))
        .filter_map(|(_, data)| data.first().copied())
        .collect();
    assert_eq!(mcb_reads, vec![1, 2, 3]);
    Ok(())
}
