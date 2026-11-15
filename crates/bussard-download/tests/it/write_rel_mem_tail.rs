//! A parameter whose last octet lies past the `LdCtrlWriteRelMem` `Size` is
//! planned when the filled allocation already holds that octet (issue
//! #1065).
//!
//! The synthetic `syn-writerelmem-tail` allocates its 16-octet segment
//! with `Mode` 1, `Fill` 0 and writes 15 octets; the 32-bit `marker`
//! (`C3 00 00 00`) sits at octets 12 to 15, the shape of the Gira push-button
//! rockers `M-0008_A-1161-23-518D-O000A` and `A-1162-21-2E13-O000A`, where
//! ETS wrote `C3` and nothing past the write. The ETS capture of this
//! product (`captures/synthetic/syn-writerelmem-tail`) writes octets 0 to 12
//! and leaves 13 to 15 to the fill. The device holds octet 15 from
//! the fill; the flash's read-back samples the octets the sparse write left
//! to the fill, so a device that ignores the fill fails the flash.

use std::collections::BTreeMap;

use bussard_download::{
    FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, ParamRegions, Session, flash,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::WriteError;
use bussard_testkit::consts::{
    A_MEMORY_WRITE, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::{plan_synthetic_07b0, synthetic_product};

/// Where the mock places object 4's segment.
const BASE: u32 = 0x6000;

/// The plan of `syn-writerelmem-tail` at its defaults.
fn plan() -> TestResult<FlashPlan> {
    let (product, _tmp) = synthetic_product("syn-writerelmem-tail")?;
    let app = product.applications.first().ok_or("one application")?;
    plan_synthetic_07b0(&product, app, &BTreeMap::new())
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

/// Runs `plan` on `device` and hands back the outcome and the device.
async fn run(
    device: MockDevice,
    plan: &FlashPlan,
) -> TestResult<(Result<FlashOutcome, WriteError>, MockDevice)> {
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
    let outcome = flash(&mut session, plan, FlashOptions::default(), |_| {}).await;
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    Ok((outcome, dev))
}

/// The highest octet of the segment a memory write touched.
fn last_written_octet(dev: &MockDevice) -> Option<u32> {
    dev.requests
        .iter()
        .filter(|(apci, data)| apci & !0x3F == A_MEMORY_WRITE && data.len() >= 2)
        .map(|(_, data)| {
            (
                u32::from(u16::from_be_bytes([data[0], data[1]])),
                (data.len() - 2) as u32,
            )
        })
        .filter(|&(addr, len)| len > 0 && (BASE..BASE + 16).contains(&addr))
        .map(|(addr, len)| addr + len - 1 - BASE)
        .max()
}

#[tokio::test]
async fn test_flash_write_rel_mem_tail_held_by_the_fill_reads_back() -> TestResult {
    let plan = plan()?;
    let (outcome, dev) = run(device()?, &plan).await?;
    let outcome = outcome?;
    assert!(outcome.ok(), "the flash verifies: {outcome:?}");
    // ETS wrote these 13 octets at 0x6000 and nothing else of the segment
    // (captures/synthetic/syn-writerelmem-tail/defaults, image.json): the
    // write stops at the `C3` that starts the marker, octets 13 to 15 stay
    // at the Mode 1 fill 0.
    let ets = bussard_model::text::from_hex("01012c000000000000000000c3")?;
    assert_eq!(dev.read_mem(BASE, 13), ets);
    assert_eq!(dev.read_mem(BASE + 13, 3), vec![0x00; 3]);
    let last = last_written_octet(&dev).ok_or("a memory write")?;
    assert_eq!(last, 12, "wrote up to octet {last}, ETS up to octet 12");
    Ok(())
}

#[tokio::test]
async fn test_flash_write_rel_mem_tail_without_the_fill_fails_the_read_back() -> TestResult {
    let plan = plan()?;
    // A device that ignores the fill flag: it holds the fill everywhere but
    // at octet 15, the held tail no step writes. Only the read-back of that
    // octet can find it.
    let mut held = [0u8; 16];
    held[15] = 0x77;
    let faulty = device()?.with_withheld_fill().with_memory(BASE, &held);
    let (outcome, dev) = run(faulty, &plan).await?;
    assert_eq!(
        dev.read_mem(BASE + 15, 1),
        vec![0x77],
        "nothing wrote octet 15"
    );
    // The held tail is read back right after the write, before the
    // restart: the flash fails there, naming the octet.
    match outcome {
        Err(err) => assert!(err.to_string().contains("memory verify failed"), "{err}"),
        Ok(outcome) => {
            return Err(format!("a device without the fill verified: {outcome:?}").into());
        }
    }
    assert_eq!(dev.restarts, 0, "the check runs before the restart");
    Ok(())
}

/// The MCB check of object 4 compares the device's CRC over the whole
/// allocation with the image, held tail included (issue #1065): the image
/// is kept whole, so the check passes against a device that filled.
#[tokio::test]
async fn test_flash_write_rel_mem_tail_mcb_covers_the_allocation() -> TestResult {
    let mut plan = plan()?;
    let image = plan
        .steps
        .iter()
        .find_map(|s| match s {
            FlashStep::WriteRelMem { image, .. } if image.kind == ImageKind::Parameters => {
                Some(image.clone())
            }
            _ => None,
        })
        .ok_or("a parameter write")?;
    assert_eq!(image.len, 15, "the step writes the op's Size");
    assert_eq!(
        plan.image_bytes(&image.segment_id).map(<[u8]>::len),
        Some(16)
    );
    let restart = plan
        .steps
        .iter()
        .rposition(|s| matches!(s, FlashStep::Restart | FlashStep::MasterReset { .. }))
        .ok_or("the plan restarts")?;
    plan.steps.insert(
        restart,
        FlashStep::LoadImageProp {
            obj_idx: 4,
            prop_id: 27,
            count: 1,
            image: Some(image),
            advisory: false,
        },
    );
    let (outcome, _) = run(device()?.with_mcb_tables(), &plan).await?;
    let outcome = outcome?;
    assert!(
        outcome.ok(),
        "the MCB check and the read-back pass: {outcome:?}"
    );
    Ok(())
}

/// The plan records the held tail on its write step (issue #1065): range,
/// fill, filled by the step's own allocation, and the octets of the
/// device-managed `marker` (`Access="None"`, octets 12 to 15).
#[test]
fn test_plan_flash_write_rel_mem_tail_is_plan_state() -> TestResult {
    let plan = plan()?;
    let tails: Vec<(usize, &bussard_download::HeldTail)> = plan.held_tails().collect();
    assert_eq!(tails.len(), 1, "{tails:?}");
    let (index, tail) = tails[0];
    assert!(matches!(
        &plan.steps[index],
        FlashStep::WriteRelMem { image, .. } if image.len == 15 && image.offset == 0
    ));
    assert_eq!(
        (tail.start, tail.end, tail.fill, tail.filled),
        (15, 16, 0, true)
    );
    assert_eq!(tail.managed.iter().copied().collect::<Vec<_>>(), vec![15]);
    assert!(plan.kept().is_empty());
    Ok(())
}

/// A write whose tail the plan leaves to the allocation is refused before
/// a byte goes out when the allocation fills nothing (issue #1065).
#[tokio::test]
async fn test_flash_write_rel_mem_tail_without_a_filling_allocation_fails() -> TestResult {
    let mut plan = plan()?;
    for step in &mut plan.steps {
        if let FlashStep::AllocateSegment {
            target: Some(4),
            fill,
            ..
        } = step
        {
            *fill = bussard_download::flash::SegmentFill::NONE;
        }
    }
    let (outcome, dev) = run(device()?, &plan).await?;
    match outcome {
        Err(WriteError::HeldTailNotFilled { start, end, .. }) => {
            assert_eq!((start, end), (15, 16));
        }
        other => return Err(format!("expected HeldTailNotFilled, got {other:?}").into()),
    }
    assert_eq!(
        last_written_octet(&dev),
        None,
        "nothing written to object 4"
    );
    Ok(())
}

/// What [`reflash_parameters_only`] hands back: the cut, the regions read,
/// the parameter-only download's outcome (when `run` and the cut planned)
/// and the device after it.
type Reflashed = (
    Result<FlashPlan, bussard_download::PartialPlanError>,
    ParamRegions,
    Option<FlashOutcome>,
    MockDevice,
);

/// Full flash, then the device's application rewrites octet 15 with
/// `octet_15`; reads the parameter regions back, cuts the parameter-only
/// download and, with `run`, sends it.
async fn reflash_parameters_only(
    full: &FlashPlan,
    octet_15: u8,
    run: bool,
) -> TestResult<Reflashed> {
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(
        &mut bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, full, FlashOptions::default(), |_| {}).await?;
    assert!(outcome.ok(), "the full flash verifies: {outcome:?}");
    gw.with_device(ia("1.1.1")?, |d| d.memory.insert(BASE + 15, octet_15))?;
    let regions = bussard_download::read_parameter_regions(session.l4(), full, &[]).await;
    let partial = full.parameters_only(&regions);
    let outcome = match (&partial, run) {
        (Ok(partial), true) => {
            Some(flash(&mut session, partial, FlashOptions::default(), |_| {}).await?)
        }
        _ => None,
    };
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    Ok((partial, regions, outcome, dev))
}

/// The parameter-only download keeps the memory (`Mode` 0): nothing fills
/// and nothing writes the held tail. The read-back reads the tail from the
/// device; octet 15 belongs to the device-managed `marker`, so what the
/// device holds there is kept: no pending change, no failure (issue #1065).
#[tokio::test]
async fn test_parameters_only_write_rel_mem_tail_is_device_held() -> TestResult {
    let full = plan()?;
    let (partial, regions, outcome, dev) = reflash_parameters_only(&full, 0x77, true).await?;
    // The tail is read from the device, not made up.
    let region = regions.values().next().ok_or("a parameter region")?;
    assert_eq!(region.bytes.len(), 16);
    assert_eq!(region.bytes[15], 0x77);
    let partial = partial?;
    assert_eq!(partial.changed_octets(), 0);
    assert!(partial.held_tails().all(|(_, t)| !t.filled));
    let outcome = outcome.ok_or("the parameter-only download ran")?;
    assert!(
        outcome.ok(),
        "the parameter-only download verifies: {outcome:?}"
    );
    assert_eq!(
        dev.read_mem(BASE + 15, 1),
        vec![0x77],
        "kept as the device holds it"
    );
    Ok(())
}

/// A tail octet that is not device-managed is compared: where the device
/// holds another value than the model, the parameter-only download is
/// refused, since only a complete download fills it (issue #1065).
#[tokio::test]
async fn test_parameters_only_write_rel_mem_tail_differs_is_refused() -> TestResult {
    let mut full = plan()?;
    for step in &mut full.steps {
        if let FlashStep::WriteRelMem {
            held_tail: Some(tail),
            ..
        } = step
        {
            tail.managed.clear();
        }
    }
    let (partial, ..) = reflash_parameters_only(&full, 0x77, false).await?;
    match partial {
        Err(bussard_download::PartialPlanError::HeldTailDiffers {
            octet,
            device,
            model,
            ..
        }) => assert_eq!((octet, device, model), (15, 0x77, 0)),
        other => return Err(format!("expected HeldTailDiffers, got {other:?}").into()),
    }
    // The same device holding the fill: no change, no refusal.
    let (partial, ..) = reflash_parameters_only(&full, 0x00, false).await?;
    assert_eq!(partial?.changed_octets(), 0);
    Ok(())
}

/// The synthetic product's application program (bussard's own work, MIT).
const XML: &str = include_str!(
    "../../../../tests-support/synthetic-products/syn-writerelmem-tail/xml/M-00FA/M-00FA_A-272A-10-0000.xml"
);

/// The mask's parameter-only procedure (issue #1052) keeps the memory: with
/// the complete download's allocation `AppliesTo="full"` (`Mode` 1) and a
/// `par` one in `Mode` 0, as the Gira rockers state them, the `par`
/// procedure's write of the segment has no filling allocation. The tail is
/// device-held there, and `parameters_only` plans by that procedure (issue
/// #1065: it failed with `ParProcedure` before).
#[test]
fn test_parameters_only_by_par_procedure_keeps_the_tail() -> TestResult {
    let from = r#"<LdCtrlRelSegment LsmIdx="4" Size="16" Mode="1" Fill="0" />"#;
    assert!(XML.contains(from));
    let xml = XML.replace(
        from,
        r#"<LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="16" Mode="1" Fill="0" /><LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="16" Mode="0" Fill="0" />"#,
    );
    let app = bussard_product::application::parse_application_program(
        "M-00FA_A-272A-10-0000",
        xml.as_bytes(),
    )?;
    let template =
        bussard_product::master::MasterTemplate::builtin_for_mask("07B0").ok_or("07B0 template")?;
    let par = bussard_product::master::MasterTemplate::builtin_par_for_mask("07B0")
        .ok_or("07B0 par procedure")?;
    let memo = bussard_product::dynamic::DynamicMemo::new(&app);
    let tables =
        bussard_download::build_table_images(None, "1.1.1".parse()?, &app, &BTreeMap::new(), &memo);
    let mut full = crate::support::plan_flash_default(
        &app,
        "1.1.1",
        0x07B0,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )?;
    bussard_download::add_par_procedure(
        &mut full,
        &app,
        "1.1.1",
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&par.ops),
        &tables,
        &BTreeMap::new(),
        &memo,
    );
    let regions = bussard_download::planned_parameter_regions(&full);
    let region = regions.values().next().ok_or("a parameter region")?;
    assert_eq!(region.bytes.len(), 16, "the planned region covers the tail");
    let partial = full.parameters_only(&regions)?;
    assert_eq!(
        partial.procedure_kind(),
        bussard_download::ProcedureKind::ParametersByPar
    );
    assert_eq!(partial.changed_octets(), 0);
    let tails: Vec<_> = partial.held_tails().map(|(_, t)| t.clone()).collect();
    assert_eq!(tails.len(), 1, "{tails:?}");
    assert!(!tails[0].filled);
    assert_eq!((tails[0].start, tails[0].end, tails[0].fill), (15, 16, 0));
    Ok(())
}
