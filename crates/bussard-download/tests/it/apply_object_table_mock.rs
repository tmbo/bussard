//! Issue #540: a System B `apply` that links an object the last flash left
//! unlinked reloads the group-object table, so the object's Communication
//! flag is set and the device acts on the new link.
//!
//! The application is synthetic (bussard's own, no vendor data): three
//! com-objects and a load procedure that writes the address, association and
//! group-object tables (objects 1, 2, 3) the way a merged System B procedure
//! does. The full flash plan for the model before the edit (object 2 without a
//! link) gives the group-object table a flashed device holds; the plan for the
//! model after the edit (object 2 linked) gives the image `apply` must write.
//! Both come from [`bussard_download::build_table_images`], the builder
//! `flash` uses. The device is the testkit [`MockDevice::system_b`] on a
//! loopback mock gateway.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_download::{
    FlashPlan, SystemBLoad, apply_tables_with, build_table_images, check_object_table,
    compute_tables, discover_table_objects, object_table_image, plan_flash,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_model::schema::{Link, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_prod::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::{BoxError, MockDevice, MockGateway, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x54;

/// `A_PropertyValue_Write` and `PID_LOAD_STATE_CONTROL`, from the spec.
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const PID_LOAD_STATE_CONTROL: u8 = 5;
/// The load events of `PID_LOAD_STATE_CONTROL` (KNX 3/5/1).
const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;

/// The Communication flag of a group-object descriptor word (bit 10).
const COMMUNICATION: u16 = 1 << 10;

const APP_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
 <ApplicationProgram Id="M-00FA_A-0540" ApplicationNumber="540" ApplicationVersion="1"
    MaskVersion="MV-07B0" Name="bussard object table test app" LoadProcedureStyle="MergedProcedure">
  <Static>
   <Code>
    <RelativeSegment Id="M-00FA_A-0540_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
   </Code>
   <ComObjects>
    <ComObject Id="M-00FA_A-0540_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    <ComObject Id="M-00FA_A-0540_O-2" Number="2" ObjectSize="1 Bit" CommunicationFlag="Enabled" ReadFlag="Enabled" WriteFlag="Enabled" />
    <ComObject Id="M-00FA_A-0540_O-3" Number="3" ObjectSize="1 Byte" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
   </ComObjects>
   <ComObjectRefs>
    <ComObjectRef Id="M-00FA_A-0540_O-1_R-1" RefId="M-00FA_A-0540_O-1" />
    <ComObjectRef Id="M-00FA_A-0540_O-2_R-2" RefId="M-00FA_A-0540_O-2" />
    <ComObjectRef Id="M-00FA_A-0540_O-3_R-3" RefId="M-00FA_A-0540_O-3" />
   </ComObjectRefs>
   <LoadProcedures>
    <LoadProcedure>
     <LdCtrlConnect />
     <LdCtrlUnload LsmIdx="1" />
     <LdCtrlUnload LsmIdx="2" />
     <LdCtrlUnload LsmIdx="3" />
     <LdCtrlUnload LsmIdx="4" />
     <LdCtrlLoad LsmIdx="1" />
     <LdCtrlRelSegment LsmIdx="1" Size="2" Mode="0" Fill="0" />
     <LdCtrlWriteRelMem ObjIdx="1" Offset="0" Size="2" />
     <LdCtrlLoadCompleted LsmIdx="1" />
     <LdCtrlLoad LsmIdx="2" />
     <LdCtrlRelSegment LsmIdx="2" Size="2" Mode="0" Fill="0" />
     <LdCtrlWriteRelMem ObjIdx="2" Offset="0" Size="2" />
     <LdCtrlLoadCompleted LsmIdx="2" />
     <LdCtrlLoad LsmIdx="3" />
     <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
     <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="2" />
     <LdCtrlLoadCompleted LsmIdx="3" />
     <LdCtrlLoad LsmIdx="4" />
     <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
     <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="6" AppliesTo="full" />
     <LdCtrlLoadCompleted LsmIdx="4" />
     <LdCtrlRestart />
     <LdCtrlDisconnect />
    </LoadProcedure>
   </LoadProcedures>
  </Static>
 </ApplicationProgram></KNX>"#;

fn app() -> TestResult<ApplicationProgram> {
    Ok(parse_application_program(
        "M-00FA_A-0540",
        APP_XML.as_bytes(),
    )?)
}

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.20".parse()?)
}

/// The model's links for the device: `(object, sending group address)`.
fn links(pairs: &[(u16, &str)]) -> Result<Vec<Link>, BoxError> {
    pairs
        .iter()
        .map(|&(object, ga)| {
            Ok(Link {
                object,
                name: None,
                send: Some(ga.parse::<GroupAddress>()?),
                listen: Vec::new(),
            })
        })
        .collect()
}

/// A model holding only the device's links.
fn model(pairs: &[(u16, &str)]) -> Result<Model, BoxError> {
    Ok(Model {
        config: Default::default(),
        groups: Default::default(),
        links: Links {
            links: BTreeMap::from([(target()?, links(pairs)?)]),
        },
        devices: BTreeMap::new(),
    })
}

/// The full flash plan `flash` builds for the device from `model`.
fn flash_plan(app: &ApplicationProgram, model: &Model) -> TestResult<FlashPlan> {
    let overrides = BTreeMap::new();
    let images = build_table_images(Some(model), target()?, app, &overrides);
    Ok(plan_flash(
        app,
        &target()?.to_string(),
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &images,
    )?)
}

/// Descriptor word `object` (1-based) of a group-object table image.
fn word(image: &[u8], object: usize) -> u16 {
    image
        .get(2 * object..2 * object + 2)
        .map_or(0, |w| u16::from_be_bytes([w[0], w[1]]))
}

/// A table image: the count word, then the elements.
fn table(elements: &[u8], elem_size: usize) -> Vec<u8> {
    let mut out = ((elements.len() / elem_size) as u16).to_be_bytes().to_vec();
    out.extend_from_slice(elements);
    out
}

#[tokio::test]
async fn test_apply_tables_with_sets_the_communication_flag_of_a_newly_linked_object() -> TestResult
{
    let app = app()?;
    let before = model(&[(1, "1/0/1")])?;
    let after = model(&[(1, "1/0/1"), (2, "1/0/2")])?;
    let flashed = flash_plan(&app, &before)?;
    let wanted = flash_plan(&app, &after)?;
    let flashed_image = object_table_image(&flashed)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    let wanted_image = object_table_image(&wanted)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    // The flash without a link left object 2's Communication flag off; the
    // model with the link wants it on.
    assert_eq!(word(&flashed_image, 2) & COMMUNICATION, 0);
    assert_ne!(word(&wanted_image, 2) & COMMUNICATION, 0);

    // The device as that flash left it.
    let old = compute_tables(&links(&[(1, "1/0/1")])?);
    let loads: Arc<Mutex<Vec<(u8, u8)>>> = Arc::default();
    let sink = Arc::clone(&loads);
    let device = MockDevice::system_b(target()?)
        .with_table(1, &table(&old.address_elements(), 2))
        .with_table(2, &table(&old.association_elements(), 4))
        .with_table(3, &flashed_image)
        .with_hook(move |_, apci, data| {
            if apci == A_PROPERTY_VALUE_WRITE
                && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
                && let (Some(&object), Some(&event)) = (data.first(), data.get(4))
                && let Ok(mut log) = sink.lock()
            {
                log.push((object, event));
            }
            None
        });
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, "0.0.255".parse()?).await?;

    // The plan names the change: object 2's flag goes on.
    let check = check_object_table(&mut l4, &wanted)
        .await
        .ok_or("the plan compares the group-object table")?;
    let change = check.change().ok_or("the device's table differs")?;
    assert!(
        change.objects.iter().any(|c| c.object == 2 && c.enables()),
        "{change:?}"
    );

    // The write: the group-object table first, then the link tables.
    let objects = discover_table_objects(&mut l4).await?;
    let desired = compute_tables(&links(&[(1, "1/0/1"), (2, "1/0/2")])?);
    let outcome = apply_tables_with(
        &mut l4,
        objects,
        &desired,
        SystemBLoad {
            object_table: Some(&wanted_image),
            ..SystemBLoad::default()
        },
    )
    .await?;
    let _ = l4.disconnect().await;
    assert!(outcome.ok(), "{outcome:?}");
    let reload = outcome
        .object_table
        .as_ref()
        .ok_or("the outcome reports the reload")?;
    assert!(reload.ok(), "{reload:?}");

    // The device holds the model's table, object 2 communicating.
    let devices = gw.devices()?;
    let device = devices.first().ok_or("the device")?;
    let held = device
        .table_image(3)
        .ok_or("a group-object table segment")?;
    assert_eq!(held, wanted_image);
    assert_ne!(word(&held, 2) & COMMUNICATION, 0);
    assert_eq!(device.load_state(3), 1, "the object table is Loaded");

    // Object 3 is opened and completed before either link table is opened.
    let loads = loads.lock().map_err(|_| "load log poisoned")?.clone();
    assert_eq!(
        loads.first(),
        Some(&(3, LE_START_LOADING)),
        "the object table loads first: {loads:?}"
    );
    let completed = loads
        .iter()
        .position(|&l| l == (3, LE_LOAD_COMPLETED))
        .ok_or("the object table is completed")?;
    let link_start = loads
        .iter()
        .position(|&(o, e)| o != 3 && e == LE_START_LOADING)
        .ok_or("the link tables are loaded")?;
    assert!(completed < link_start, "{loads:?}");
    Ok(())
}

/// A reload alone (the links already match, an older `apply` left the flag
/// off): only the group-object table is loaded, the link tables are read
/// back unchanged.
#[tokio::test]
async fn test_apply_tables_with_keep_tables_loads_only_the_object_table() -> TestResult {
    let app = app()?;
    let pairs = [(1, "1/0/1"), (2, "1/0/2")];
    let wanted = flash_plan(&app, &model(&pairs)?)?;
    let wanted_image = object_table_image(&wanted)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    // The device's table lacks object 2's flag; its link tables match.
    let mut stale = wanted_image.clone();
    let off = word(&stale, 2) & !COMMUNICATION;
    stale[4..6].copy_from_slice(&off.to_be_bytes());
    let tables = compute_tables(&links(&pairs)?);
    let loads: Arc<Mutex<Vec<(u8, u8)>>> = Arc::default();
    let sink = Arc::clone(&loads);
    let device = MockDevice::system_b(target()?)
        .with_table(1, &table(&tables.address_elements(), 2))
        .with_table(2, &table(&tables.association_elements(), 4))
        .with_table(3, &stale)
        .with_hook(move |_, apci, data| {
            if apci == A_PROPERTY_VALUE_WRITE
                && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
                && let (Some(&object), Some(&event)) = (data.first(), data.get(4))
                && let Ok(mut log) = sink.lock()
            {
                log.push((object, event));
            }
            None
        });
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, "0.0.255".parse()?).await?;
    let objects = discover_table_objects(&mut l4).await?;
    let outcome = apply_tables_with(
        &mut l4,
        objects,
        &tables,
        SystemBLoad {
            object_table: Some(&wanted_image),
            keep_tables: true,
            ..SystemBLoad::default()
        },
    )
    .await?;
    let _ = l4.disconnect().await;
    assert!(outcome.ok(), "{outcome:?}");
    let loads = loads.lock().map_err(|_| "load log poisoned")?.clone();
    assert!(loads.iter().all(|&(o, _)| o == 3), "{loads:?}");
    let devices = gw.devices()?;
    let device = devices.first().ok_or("the device")?;
    assert_eq!(device.table_image(3), Some(wanted_image));
    Ok(())
}
