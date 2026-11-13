//! Issue #540: a System B `apply` that links an object the last flash left
//! unlinked reloads the group-object table, so the object's Communication
//! flag is set and the device acts on the new link. With a link change the
//! table is reloaded by the master data's partial download of the three
//! tables, in ETS's order (issue #1095).
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

use bussard_download::apply::apply_tables;
use bussard_download::apply::discover_table_objects;
use bussard_download::object_table::object_table_image;
use bussard_download::{
    FlashPlan, SystemBLoad, TableRestart, build_table_images, check_object_table, compute_tables,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_model::schema::{Link, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_product::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

const CHANNEL: u8 = 0x54;

/// `A_PropertyValue_Write` and `PID_LOAD_STATE_CONTROL`, from the spec.
const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
const PID_LOAD_STATE_CONTROL: u8 = 5;
/// The load events of `PID_LOAD_STATE_CONTROL` (KNX 3/5/1).
const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;
/// `A_Memory_Write` (KNX 3/3/7), the APCI with its length bits cleared.
const A_MEMORY_WRITE: u16 = 0x280;

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
    let images = build_table_images(
        Some(model),
        target()?,
        app,
        &overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    Ok(plan_flash_default(
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
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;

    // The plan names the change: object 2's flag goes on.
    let check = check_object_table(&mut l4, &wanted)
        .await
        .ok_or("the plan compares the group-object table")?;
    let change = check.change().ok_or("the device's table differs")?;
    assert!(
        change.objects.iter().any(|c| c.object == 2 && c.enables()),
        "{change:?}"
    );

    // The write: the master data's partial download of the three tables.
    let objects = discover_table_objects(&mut l4).await?;
    let desired = compute_tables(&links(&[(1, "1/0/1"), (2, "1/0/2")])?);
    let outcome = apply_tables(
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
    // The read-back: both link tables and the group-object table as written.
    assert!(outcome.ok(), "{outcome:?}");
    assert!(outcome.addresses_match && outcome.associations_match);
    let reload = outcome
        .object_table
        .as_ref()
        .ok_or("the outcome reports the reload")?;
    assert!(reload.ok(), "{reload:?}");
    assert_eq!(
        outcome.restart,
        TableRestart::Sent {
            process_wait: Duration::ZERO
        },
        "the partial download ends with its restart, in the write session"
    );

    // The device holds the model's table, object 2 communicating.
    let devices = gw.devices()?;
    let device = devices.first().ok_or("the device")?;
    let held = device
        .table_image(3)
        .ok_or("a group-object table segment")?;
    assert_eq!(held, wanted_image);
    assert_ne!(word(&held, 2) & COMMUNICATION, 0);
    assert_eq!(device.load_state(3), 1, "the object table is Loaded");
    assert_eq!(device.restarts, 1, "one basic restart");

    // ETS's order (issue #1095, `captures/synthetic/syn-minimal/apply`):
    // unload 3, 2, 1; open 3, 1, 2 each with its allocation; complete 3, 2, 1.
    let loads = loads.lock().map_err(|_| "load log poisoned")?.clone();
    assert_eq!(
        loads,
        vec![
            (3, LE_UNLOAD),
            (2, LE_UNLOAD),
            (1, LE_UNLOAD),
            (3, LE_START_LOADING),
            (3, LE_ADDITIONAL),
            (1, LE_START_LOADING),
            (1, LE_ADDITIONAL),
            (2, LE_START_LOADING),
            (2, LE_ADDITIONAL),
            (3, LE_LOAD_COMPLETED),
            (2, LE_LOAD_COMPLETED),
            (1, LE_LOAD_COMPLETED),
        ]
    );
    Ok(())
}

/// The partial download's read-back finds the group-object table the device
/// acknowledged and did not store: the outcome is not ok, and the device is
/// not restarted (issue #1095; a silent success is the P1 of CLAUDE.md).
#[tokio::test]
async fn test_apply_tables_with_a_dropped_object_table_write_does_not_verify() -> TestResult {
    let app = app()?;
    let before = model(&[(1, "1/0/1")])?;
    let after = model(&[(1, "1/0/1"), (2, "1/0/2")])?;
    let flashed_image = object_table_image(&flash_plan(&app, &before)?)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    let wanted_image = object_table_image(&flash_plan(&app, &after)?)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    let old = compute_tables(&links(&[(1, "1/0/1")])?);
    let base = bussard_testkit::device::segment_base_for(3);
    let device = MockDevice::system_b(target()?)
        .with_table(1, &table(&old.address_elements(), 2))
        .with_table(2, &table(&old.association_elements(), 4))
        .with_table(3, &flashed_image)
        .with_hook(move |_, apci, data| {
            // A memory write into the group-object table's segment: the
            // transport acknowledges it, the device keeps the old table.
            let address = u32::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
            (apci & 0x3F0 == A_MEMORY_WRITE && (base..base + 0x800).contains(&address))
                .then_some(Reaction::Ack)
        });
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let objects = discover_table_objects(&mut l4).await?;
    let desired = compute_tables(&links(&[(1, "1/0/1"), (2, "1/0/2")])?);
    let outcome = apply_tables(
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
    // The link tables verified; the group-object table did not.
    assert!(outcome.addresses_match && outcome.associations_match);
    let reload = outcome
        .object_table
        .as_ref()
        .ok_or("the outcome reports the reload")?;
    assert!(!reload.matches, "{reload:?}");
    assert!(!outcome.ok(), "{outcome:?}");
    assert_eq!(
        outcome.restart,
        TableRestart::NotDue,
        "no restart after a write that did not verify"
    );
    let devices = gw.devices()?;
    let device = devices.first().ok_or("the device")?;
    assert_eq!(device.restarts, 0);
    assert_ne!(device.table_image(3), Some(wanted_image));
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
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let objects = discover_table_objects(&mut l4).await?;
    let outcome = apply_tables(
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

/// Issue #1095: a partial download that failed after its Unloads leaves the
/// group-object table unloaded. The documented go-back (`restore`, the link
/// tables alone, no group-object image) must not report the device verified
/// while it does not communicate: it refuses before anything is sent, and
/// the group-object table stays as the failure left it.
#[tokio::test]
async fn test_restore_after_a_download_failed_past_the_unloads_fails_loudly() -> TestResult {
    let app = app()?;
    let before = model(&[(1, "1/0/1")])?;
    let after = model(&[(1, "1/0/1"), (2, "1/0/2")])?;
    let flashed_image = object_table_image(&flash_plan(&app, &before)?)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    let wanted_image = object_table_image(&flash_plan(&app, &after)?)
        .ok_or("the flash plan writes the group-object table")?
        .to_vec();
    let old = compute_tables(&links(&[(1, "1/0/1")])?);
    // The device refuses the group-object table's StartLoading: the download
    // stops after the three Unloads.
    let device = MockDevice::system_b(target()?)
        .with_table(1, &table(&old.address_elements(), 2))
        .with_table(2, &table(&old.association_elements(), 4))
        .with_table(3, &flashed_image)
        .with_hook(move |_, apci, data| {
            (apci == A_PROPERTY_VALUE_WRITE
                && data.first() == Some(&3)
                && data.get(1) == Some(&PID_LOAD_STATE_CONTROL)
                && data.get(4) == Some(&LE_START_LOADING))
            .then_some(Reaction::Nak)
        });
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let (device_ia, tool) = (target()?, "0.0.255".parse()?);
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        device_ia,
        tool,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let objects = discover_table_objects(&mut l4).await?;
    let desired = compute_tables(&links(&[(1, "1/0/1"), (2, "1/0/2")])?);
    let failed = apply_tables(
        &mut l4,
        objects,
        &desired,
        SystemBLoad {
            object_table: Some(&wanted_image),
            ..SystemBLoad::default()
        },
    )
    .await;
    assert!(failed.is_err(), "the download stops: {failed:?}");
    let _ = l4.disconnect().await;
    let unloaded = gw.devices()?.first().ok_or("the device")?.load_state(3);
    assert_ne!(unloaded, 1, "the group-object table is no longer Loaded");

    // The restore: the backup's link tables alone.
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        device_ia,
        tool,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let restored = apply_tables(&mut l4, objects, &old, SystemBLoad::default()).await;
    let _ = l4.disconnect().await;
    let err = restored.err().ok_or("the restore must fail, not verify")?;
    assert!(err.to_string().contains("group-object table"), "{err}");
    let devices = gw.devices()?;
    let device = devices.first().ok_or("the device")?;
    assert_eq!(device.load_state(3), unloaded, "nothing was sent");
    Ok(())
}
