//! A parameter whose last octet lies past the `LdCtrlWriteRelMem` `Size` is
//! planned when the filled allocation already holds that octet (issue
//! #1065).
//!
//! The synthetic `syn-writerelmem-tail` allocates its 16-octet segment
//! with `Mode` 1, `Fill` 0 and writes 15 octets; the 32-bit `marker`
//! (`C3 00 00 00`) sits at octets 12 to 15, the shape of the Gira push-button
//! rockers `M-0008_A-1161-23-518D-O000A` and `A-1162-21-2E13-O000A`, where
//! ETS wrote `C3` and nothing past the write. The device holds octet 15 from
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
    // The marker is on the device, its last octet from the fill.
    assert_eq!(dev.read_mem(BASE + 12, 4), vec![0xC3, 0x00, 0x00, 0x00]);
    // Nothing past the write's 15 octets was written.
    let last = last_written_octet(&dev).ok_or("a memory write")?;
    assert!(last < 15, "wrote octet {last}");
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
    let failed = match outcome {
        Ok(outcome) => !outcome.ok(),
        Err(_) => true,
    };
    assert!(
        failed,
        "a device without the fill at the held tail must not verify"
    );
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
