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
    FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, Session, flash,
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

/// The plan records the held tail per write step (issue #1065): segment,
/// write length, range and fill, independent of any kept octets.
#[test]
fn test_plan_flash_write_rel_mem_tail_is_plan_state() -> TestResult {
    let plan = plan()?;
    let tails = plan.held_tails();
    assert_eq!(tails.len(), 1, "{tails:?}");
    let tail = &tails[0];
    assert_eq!(
        (tail.offset, tail.len, tail.start, tail.end, tail.fill),
        (0, 15, 15, 16, 0)
    );
    assert!(plan.kept().is_empty());
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
    assert_eq!(plan.held_tail_of(&image), Some(tail));
    // Another write of the same segment with another length has none.
    let other = bussard_download::ImageRef {
        len: 16,
        ..image.clone()
    };
    assert_eq!(plan.held_tail_of(&other), None);
    Ok(())
}

/// The parameter-only download keeps the memory (`Mode` 0): nothing fills
/// and nothing writes the held tail, so whatever the device holds there is
/// kept, never a pending change, never a failure (issue #1065).
#[tokio::test]
async fn test_parameters_only_write_rel_mem_tail_is_device_held() -> TestResult {
    let full = plan()?;
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
    let outcome = flash(&mut session, &full, FlashOptions::default(), |_| {}).await?;
    assert!(outcome.ok(), "the full flash verifies: {outcome:?}");
    // Something rewrote the held octet since (the application at start).
    gw.with_device(ia("1.1.1")?, |d| d.memory.insert(BASE + 15, 0x77))?;
    let regions = bussard_download::read_parameter_regions(session.l4(), &full, &[]).await;
    let partial = full.parameters_only(&regions)?;
    // No pending change for the octet it cannot write.
    assert_eq!(partial.changed_octets(), 0);
    let outcome = flash(&mut session, &partial, FlashOptions::default(), |_| {}).await?;
    let _ = session.into_disconnect().await;
    assert!(
        outcome.ok(),
        "the parameter-only download verifies: {outcome:?}"
    );
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(
        dev.read_mem(BASE + 15, 1),
        vec![0x77],
        "kept as the device holds it"
    );
    Ok(())
}
