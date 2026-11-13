//! A parameter segment without `<Data>` whose allocation keeps the memory
//! (`Mode` 0) is written where a declared parameter occupies it, and
//! nowhere else (issue #1084, owner decision 2026-11-13).
//!
//! ETS's download of `syn-relseg-dataless`
//! (`captures/synthetic/syn-relseg-dataless/defaults/ops.txt`, op 25) writes
//! octets 0 to 2 of the 16-octet segment and never 3 to 15; the device keeps
//! what it held there (Configuration Procedures 03_05_03 §3.5.1.2). The
//! twin `syn-relseg-dataless-hidden` adds a hidden 16-bit parameter at
//! octets 3 and 4, which the download writes too, so its write covers
//! octets 0 to 4. Every flash here ends with the read-back.

use std::collections::BTreeMap;

use bussard_download::{
    Connector, FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, Session,
    build_table_images, flash, read_parameter_regions, regions_memory, template_ops_for,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::{LoadState, WriteError};
use bussard_product::application::ApplicationProgram;
use bussard_testkit::consts::{
    A_MEMORY_WRITE, A_PROPERTY_VALUE_READ, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM,
    OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::builtin_template::zip_synthetic;
use crate::support::plan_flash_default;

/// Where the mock places object 4's segment.
const BASE: u32 = 0x6000;

/// The `delay` parameter (16 bits at octets 1 and 2), app-relative.
const DELAY: &str = "P-2_R-2";

/// The synthetic product and its application.
fn product(name: &str) -> TestResult<(bussard_product::ProductData, tempfile::TempDir)> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join(format!("{name}.knxprod"));
    zip_synthetic(name, &path).map_err(|e| e.to_string())?;
    Ok((bussard_product::read_knxprod(&path)?, tmp))
}

/// The full download of `app` for 1.1.1 under `overrides`.
fn plan_of(
    product: &bussard_product::ProductData,
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> TestResult<FlashPlan> {
    let template = template_ops_for(product, app).ok_or("a template for 07B0")?;
    let tables = build_table_images(
        None,
        "1.1.1".parse()?,
        app,
        overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )
    .map_err(|e| e.to_string().into())
}

/// A System B device of 1.1.1 with the objects the product loads.
fn device() -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_segment_base(4, BASE))
}

/// Runs `plan` on the device behind `gw` over a new connection.
async fn run(gw: &MockGateway, plan: &FlashPlan) -> TestResult<Result<FlashOutcome, WriteError>> {
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(
        &mut bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, plan, FlashOptions::default(), |_| {}).await;
    let _ = session.into_disconnect().await;
    Ok(outcome)
}

/// The parameter regions of `full` as the device behind `session` holds
/// them.
async fn regions<C: Connector>(
    session: &mut Session<C>,
    full: &FlashPlan,
) -> bussard_download::ParamRegions {
    read_parameter_regions(session.l4(), full, &[]).await
}

/// The plain memory writes the device saw into `[from, to)`: address and
/// length of each.
fn writes_into(dev: &MockDevice, from: u32, to: u32) -> Vec<(u32, usize)> {
    dev.requests
        .iter()
        .filter(|(apci, data)| apci & !0x3F == A_MEMORY_WRITE && data.len() >= 2)
        .map(|(_, data)| {
            (
                u32::from(u16::from_be_bytes([data[0], data[1]])),
                data.len() - 2,
            )
        })
        .filter(|&(addr, _)| (from..to).contains(&addr))
        .collect()
}

/// The parameter image the plan writes to object 4.
fn parameter_image(plan: &FlashPlan) -> TestResult<Vec<u8>> {
    let image = plan
        .steps
        .iter()
        .find_map(|s| match s {
            FlashStep::WriteRelMem { image, .. } if image.kind == ImageKind::Parameters => {
                Some(image)
            }
            _ => None,
        })
        .ok_or("a parameter write")?;
    Ok(plan
        .image_bytes(&image.segment_id)
        .ok_or("the image")?
        .to_vec())
}

#[test]
fn test_plan_flash_dataless_segment_writes_what_ets_writes() -> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless")?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new())?;
    let kept = plan.kept();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(kept[0].unoccupied);
    assert_eq!((kept[0].object, kept[0].allocated), (4, 16));
    // ETS: op 25, `mem-write 0x6000 len=3`; octets 3 to 15 never written.
    assert_eq!(kept[0].ranges, vec![(3, 16)]);
    Ok(())
}

#[tokio::test]
async fn test_flash_dataless_segment_writes_only_the_occupied_octets() -> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless-hidden")?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new())?;
    let image = parameter_image(&plan)?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    let outcome = run(&gw, &plan).await??;
    assert!(outcome.ok(), "{outcome:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    // The two parameters and the hidden one (octets 3 and 4, at the image's
    // value): one write, nothing past it.
    assert_eq!(writes_into(&dev, BASE, BASE + 16), vec![(BASE, 5)]);
    assert_eq!(dev.read_mem(BASE, 5), image[..5].to_vec());
    assert_eq!(dev.read_mem(BASE + 5, 11), vec![0; 11], "never written");
    Ok(())
}

#[tokio::test]
async fn test_flash_dataless_segment_keeps_what_the_device_held() -> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless-hidden")?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new())?;
    let image = parameter_image(&plan)?;
    // A programmed device: another download left 0x77 in the whole segment.
    let held = device()?.with_memory(BASE, &[0x77; 16]);
    let gw = MockGateway::builder().device(held).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(
        &mut bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, &plan, FlashOptions::default(), |_| {}).await?;
    assert!(outcome.ok(), "the flash verifies: {outcome:?}");
    // The independent read-back decodes every parameter from the device.
    let after = regions(&mut session, &plan).await;
    let _ = session.into_disconnect().await;
    let readings = bussard_download::param_plan::non_default_parameters(
        app,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &regions_memory(&after),
    );
    assert!(readings.is_empty(), "{readings:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(writes_into(&dev, BASE, BASE + 16), vec![(BASE, 5)]);
    assert_eq!(dev.read_mem(BASE, 5), image[..5].to_vec());
    assert_eq!(dev.read_mem(BASE + 5, 11), vec![0x77; 11], "not touched");
    Ok(())
}

#[tokio::test]
async fn test_flash_dataless_segment_fails_when_a_written_octet_reads_back_wrong() -> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless-hidden")?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new())?;
    // The device stores the parameter write with its first octet flipped
    // and acknowledges it.
    let faulty = device()?.with_hook(|dev: &mut MockDevice, apci: u16, data: &[u8]| {
        let at = data
            .get(..2)
            .map(|a| u32::from(u16::from_be_bytes([a[0], a[1]])));
        if apci & !0x3F != A_MEMORY_WRITE || at != Some(BASE) {
            return None;
        }
        for (i, b) in data[2..].iter().enumerate() {
            let b = if i == 0 { !b } else { *b };
            dev.memory.insert(BASE + i as u32, b);
        }
        Some(Reaction::Ack)
    });
    let gw = MockGateway::builder().device(faulty).start().await?;
    let failed = match run(&gw, &plan).await? {
        Ok(outcome) => !outcome.ok(),
        Err(_) => true,
    };
    assert!(
        failed,
        "a written octet that reads back wrong fails the flash"
    );
    Ok(())
}

#[tokio::test]
async fn test_parameters_only_and_restore_leave_the_unoccupied_octets_alone() -> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless-hidden")?;
    let app = product.applications.first().ok_or("one application")?;
    let defaults = plan_of(&product, app, &BTreeMap::new())?;
    let held = device()?.with_memory(BASE, &[0x77; 16]);
    let gw = MockGateway::builder().device(held).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(
        &mut bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    let options = FlashOptions::default;
    assert!(
        flash(&mut session, &defaults, options(), |_| {})
            .await?
            .ok()
    );
    let backup = regions_memory(&regions(&mut session, &defaults).await);

    // The project changes the delay: a parameter-only download writes it.
    let changed = BTreeMap::from([(DELAY.to_string(), "20".to_string())]);
    let full = plan_of(&product, app, &changed)?;
    let partial = full.parameters_only(&regions(&mut session, &full).await)?;
    assert!(
        partial.unwritten_bits().is_empty(),
        "no model value where no parameter lives: {:?}",
        partial.unwritten_bits()
    );
    gw.with_device(ia("1.1.1")?, |d| d.requests.clear())?;
    let outcome = flash(&mut session, &partial, options(), |_| {}).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(writes_into(&dev, BASE, BASE + 16), vec![(BASE + 1, 2)]);
    assert_eq!(dev.read_mem(BASE + 1, 2), vec![0, 20]);
    assert_eq!(dev.read_mem(BASE + 5, 11), vec![0x77; 11]);

    // The restore puts the backup's delay back, and nothing else.
    let partial = full.parameters_only(&regions(&mut session, &full).await)?;
    let restore = partial.restoring(&backup, &bussard_product::PlacedOctets::new());
    assert!(
        restore.unwritten_bits().is_empty(),
        "{:?}",
        restore.unwritten_bits()
    );
    gw.with_device(ia("1.1.1")?, |d| d.requests.clear())?;
    let outcome = flash(&mut session, &restore, options(), |_| {}).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let after = regions_memory(&regions(&mut session, &defaults).await);
    let _ = session.into_disconnect().await;
    assert_eq!(after, backup, "the read-back holds the backup");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(writes_into(&dev, BASE, BASE + 16), vec![(BASE + 1, 2)]);
    assert_eq!(dev.read_mem(BASE + 5, 11), vec![0x77; 11]);
    Ok(())
}

/// The faulty device of [`test_flash_dataless_segment_fails_when_a_written_octet_reads_back_wrong`],
/// storing octet `wrong` of the parameter write flipped.
fn faulty_device(wrong: usize) -> TestResult<MockDevice> {
    Ok(
        device()?.with_hook(move |dev: &mut MockDevice, apci: u16, data: &[u8]| {
            let at = data
                .get(..2)
                .map(|a| u32::from(u16::from_be_bytes([a[0], a[1]])));
            if apci & !0x3F != A_MEMORY_WRITE || at != Some(BASE) {
                return None;
            }
            for (i, b) in data[2..].iter().enumerate() {
                let b = if i == wrong { !b } else { *b };
                dev.memory.insert(BASE + i as u32, b);
            }
            Some(Reaction::Ack)
        }),
    )
}

/// Review of PR #1121 finding 1: the MCB is not compared, the write is not
/// in verify mode (`Verify="false"`), so the read-back covers every octet
/// written, the hidden parameter's (octets 3 and 4) included.
#[tokio::test]
async fn test_flash_dataless_segment_fails_when_a_hidden_parameter_octet_reads_back_wrong()
-> TestResult {
    let (product, _tmp) = product("syn-relseg-dataless-hidden")?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new())?;
    let gw = MockGateway::builder()
        .device(faulty_device(4)?)
        .start()
        .await?;
    let failed = match run(&gw, &plan).await? {
        Ok(outcome) => !outcome.ok(),
        Err(_) => true,
    };
    assert!(
        failed,
        "a hidden parameter's octet that reads back wrong fails the flash"
    );
    // On a sound device the same read-back is one read of the 5 octets
    // written, where the spot check read 4.
    let gw = MockGateway::builder().device(device()?).start().await?;
    assert!(run(&gw, &plan).await??.ok());
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    let reads: Vec<&Vec<u8>> = dev
        .requests
        .iter()
        .filter(|(apci, data)| apci & !0x0F == 0x200 && data.get(..2) == Some(&[0x60, 0x00]))
        .map(|(_, data)| data)
        .collect();
    assert_eq!(reads.len(), 1, "{reads:?}");
    Ok(())
}

/// Review of PR #1121 finding 5: the MCB check of a segment the device
/// keeps octets of reads the object the check names (a companion segment
/// on object 5), not the application object.
#[tokio::test]
async fn test_flash_dataless_segment_reads_the_mcb_of_the_object_it_names() -> TestResult {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-1_A-C" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Companion" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code><RelativeSegment Id="M-1_A-C_RS-05" Size="8" LoadStateMachine="5" Offset="0" /></Code>
       <ParameterTypes><ParameterType Id="M-1_A-C_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
       <Parameters><Parameter Id="M-1_A-C_P-0" Name="a" ParameterType="M-1_A-C_PT-0" Value="7"><Memory CodeSegment="M-1_A-C_RS-05" Offset="1" BitOffset="0" /></Parameter></Parameters>
       <LoadProcedures><LoadProcedure>
         <LdCtrlUnload LsmIdx="5" /><LdCtrlLoad LsmIdx="5" />
         <LdCtrlRelSegment LsmIdx="5" Size="8" Mode="0" Fill="0" />
         <LdCtrlWriteRelMem ObjIdx="5" Offset="0" Size="8" />
         <LdCtrlLoadCompleted LsmIdx="5" />
         <LdCtrlLoadImageProp ObjIdx="5" PropId="27" />
         <LdCtrlRestart />
       </LoadProcedure></LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    let app = bussard_product::application::parse_application_program("M-1_A-C", xml.as_bytes())?;
    let plan = plan_flash_default(
        &app,
        "1.1.1",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    assert_eq!(plan.kept().len(), 1, "{:?}", plan.kept());
    // An MCB whose CRC matches nothing bussard wrote: read, not compared.
    let mcb = [0, 0, 0, 8, 0, 0xFF, 0x12, 0x34];
    let dev = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
            OT_APPLICATION_PROGRAM,
        ])
        .with_segment_base(5, BASE)
        .with_property(4, 27, 8, &mcb)
        .with_property(5, 27, 8, &mcb);
    let gw = MockGateway::builder().device(dev).start().await?;
    // Object 4, the application object the mock reports, is not this
    // program's: only object 5 is loaded.
    let outcome = run(&gw, &plan).await??;
    assert!(
        outcome.object_states.contains(&(5, LoadState::Loaded)),
        "{outcome:?}"
    );
    assert!(outcome.spot_checks_match, "{outcome:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    let mcb_reads: Vec<u8> = dev
        .requests
        .iter()
        .filter(|(apci, data)| *apci == A_PROPERTY_VALUE_READ && data.get(1) == Some(&27))
        .filter_map(|(_, data)| data.first().copied())
        .collect();
    assert_eq!(mcb_reads, vec![5], "the MCB of object 5, as ETS reads it");
    assert_eq!(writes_into(&dev, BASE, BASE + 8), vec![(BASE + 1, 1)]);
    Ok(())
}
