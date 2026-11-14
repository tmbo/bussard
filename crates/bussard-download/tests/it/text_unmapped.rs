//! A text default with a character no candidate code page holds, in a
//! program that declares no `TextParameterEncoding`, is written with `?`
//! for that character (issue #1065).
//!
//! ETS 6 wrote `3F 00 00` for the default `℃` of the KNX Smart Touch S3
//! `M-0085_A-0098-12-75FF`. The synthetic `syn-text-unmapped` carries the
//! 14-octet default "Temp ℃" at octet 3 of its parameter segment, and one
//! probe per character class for the capture that settles the rule. Until
//! that capture, the probes whose octet depends on the code page refuse the
//! defaults; the tests set them to ASCII. The flash ends with the read-back,
//! and the device holds the octets the plan wrote.

use std::collections::BTreeMap;

use bussard_download::{FlashOptions, FlashPlan, FlashStep, ImageKind, Session, flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_testkit::consts::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::{plan_synthetic_07b0, synthetic_product};

/// Where the mock places object 4's segment.
const BASE: u32 = 0x6000;

/// "Temp ?" in the 14-octet field, NUL-padded.
const TEXT: &[u8; 14] = b"Temp ?\0\0\0\0\0\0\0\0";

/// The probes (parameters 12 to 20) whose character has an octet in one
/// candidate code page but not in another, or lies beyond U+FFFF: refused
/// until the capture shows what ETS writes.
const UNSETTLED_PROBES: std::ops::RangeInclusive<u32> = 12..=20;

/// The plan of `syn-text-unmapped`, the unsettled probes set to ASCII.
fn plan() -> TestResult<FlashPlan> {
    let (product, _tmp) = synthetic_product("syn-text-unmapped")?;
    let app = product.applications.first().ok_or("one application")?;
    let overrides: BTreeMap<String, String> = UNSETTLED_PROBES
        .map(|n| (format!("P-{n}_R-{n}"), "AxZ".to_string()))
        .collect();
    plan_synthetic_07b0(&product, app, &overrides)
}

#[test]
fn test_plan_flash_unsettled_probe_refuses_at_the_defaults() -> TestResult {
    let (product, _tmp) = synthetic_product("syn-text-unmapped")?;
    let app = product.applications.first().ok_or("one application")?;
    let err = plan_synthetic_07b0(&product, app, &BTreeMap::new())
        .err()
        .ok_or("the defaults planned")?;
    assert!(err.to_string().contains("issue #416"), "{err}");
    Ok(())
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
fn test_plan_flash_unmapped_text_character_is_a_question_mark() -> TestResult {
    let image = parameter_image(&plan()?)?;
    assert_eq!(image.get(3..17), Some(&TEXT[..]));
    Ok(())
}

#[tokio::test]
async fn test_flash_unmapped_text_character_reads_back() -> TestResult {
    let plan = plan()?;
    let device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_segment_base(4, BASE);
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
    let outcome = flash(&mut session, &plan, FlashOptions::default(), |_| {}).await?;
    let _ = session.into_disconnect().await;
    assert!(outcome.ok(), "the flash verifies: {outcome:?}");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(dev.read_mem(BASE + 3, 14), TEXT.to_vec());
    Ok(())
}
