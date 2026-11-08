//! Load-state controls naming their object by type (issue #961): the Gira Eco
//! program `M-0008_A-C02A-21-B6D8-O007C` drives its vendor object type 40960
//! with `LdCtrlUnload/Load/LoadCompleted ObjType="40960"`, and ETS sends each
//! as `A_FunctionPropertyExt_Command` type 40960 instance 1 PID 5 (sweep
//! capture of 2026-11-07, `ops.txt` ops 61, 62, 117). The flash sends the
//! same against a mock device and reads the object's load state back after
//! the flash.

use std::collections::BTreeMap;

use bussard_download::{FlashOptions, FlashPlan, Session, flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::{LoadState, mcb_entry};
use bussard_testkit::consts::{
    A_FUNCTION_PROPERTY_EXT_STATE_READ, A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE, LE_LOAD_COMPLETED,
    LE_START_LOADING, LE_UNLOAD, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE,
    OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

/// A merged 07B0 program without code whose MergeId 6 block loads object
/// type 40960 by type, as the Gira Eco's does.
const XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/20">
 <ApplicationProgram Id="M-00FA_A-0003-10-ABCD" ApplicationNumber="3" ApplicationVersion="16"
    MaskVersion="MV-07B0" Name="Typed" LoadProcedureStyle="MergedProcedure">
  <Static>
   <AddressTable MaxEntries="200" />
   <AssociationTable MaxEntries="200" />
   <ComObjectTable />
   <LoadProcedures>
    <LoadProcedure MergeId="6">
     <LdCtrlUnload AppliesTo="all" ObjType="40960" />
     <LdCtrlLoad AppliesTo="all" ObjType="40960" />
     <LdCtrlLoadCompleted AppliesTo="all" ObjType="40960" />
    </LoadProcedure>
    <LoadProcedure MergeId="7">
     <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
     <LdCtrlLoadImageProp ObjIdx="2" PropId="27" />
     <LdCtrlLoadImageProp ObjIdx="3" PropId="27" />
    </LoadProcedure>
   </LoadProcedures>
  </Static>
 </ApplicationProgram></KNX>"#;

fn plan() -> Result<FlashPlan, BoxError> {
    let app = bussard_product::parse_application_program("M-00FA_A-0003-10-ABCD", XML.as_bytes())?;
    let template = bussard_product::MasterTemplate::builtin_for_mask("07B0")
        .ok_or("a built-in 07B0 template")?;
    let tables = BTreeMap::from([(1, vec![0, 0]), (2, vec![0, 0]), (3, vec![0, 0])]);
    Ok(plan_flash_default(
        &app,
        "1.1.1",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )
    .map_err(|e| e.to_string())?)
}

/// The device: the four System B objects, an empty table image on 1 to 3,
/// a writable PID 13 on object 4 and the typed object 40960 instance 1.
fn device() -> Result<MockDevice, BoxError> {
    let empty = mcb_entry(&[0, 0], 0xFF);
    let mut device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_typed_load_object(40960, 1);
    for obj in 1..=3 {
        device = device.with_property(obj, 27, 8, &empty);
    }
    Ok(device)
}

async fn run(device: MockDevice) -> Result<(bussard_download::FlashOutcome, MockDevice), BoxError> {
    let plan = plan()?;
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
    let outcome = flash(&mut session, &plan, FlashOptions::default(), |_| {}).await;
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    Ok((outcome?, dev))
}

#[tokio::test]
async fn test_flash_drives_a_typed_load_state_machine_and_reads_it_back() -> TestResult {
    let (outcome, dev) = run(device()?).await?;
    assert!(outcome.ok(), "{outcome:?}");
    assert_eq!(
        dev.typed_load_events,
        [
            (40960, 1, LE_UNLOAD),
            (40960, 1, LE_START_LOADING),
            (40960, 1, LE_LOAD_COMPLETED),
        ]
    );
    assert_eq!(outcome.typed_object_states, [(40960, 0, LoadState::Loaded)]);
    // The read-back is its own request after the completion's answer.
    let state_reads = dev
        .requests
        .iter()
        .filter(|(apci, _)| *apci == A_FUNCTION_PROPERTY_EXT_STATE_READ)
        .count();
    assert_eq!(state_reads, 1);
    Ok(())
}

#[tokio::test]
async fn test_flash_fails_when_the_typed_object_reads_back_unloaded() -> TestResult {
    // The completion answers Loaded, the read-back Unloaded: the flash must
    // not report success on the command's own answer.
    let device = device()?.with_hook(|_, apci, data| {
        (apci == A_FUNCTION_PROPERTY_EXT_STATE_READ).then(|| {
            let mut out = data.get(..5).unwrap_or_default().to_vec();
            out.extend_from_slice(&[0, 0]);
            Reaction::Answer(A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE, out)
        })
    });
    let (outcome, _) = run(device).await?;
    assert!(!outcome.ok(), "{outcome:?}");
    assert_eq!(
        outcome.typed_object_states,
        [(40960, 0, LoadState::Unloaded)]
    );
    Ok(())
}
