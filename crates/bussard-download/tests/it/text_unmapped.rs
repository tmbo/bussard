//! A text default of a program that declares no `TextParameterEncoding` is
//! written in Windows-1252 with Windows' best fit, `?` per UTF-16 code unit
//! for the rest (issue #1065).
//!
//! The synthetic `syn-text-unmapped` carries "Temp ℃" at octet 3 of its
//! parameter segment and one probe per character class from octet 17 on.
//! ETS 6.4.1 downloaded it (`captures/synthetic/syn-text-unmapped/defaults`,
//! VM session 6, 2026-11-14); the plan's parameter image is the segment ETS
//! wrote, octet for octet. The flash ends with the read-back, and the device
//! holds the octets the plan wrote.

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

/// The plan of `syn-text-unmapped` at its defaults.
fn plan() -> TestResult<FlashPlan> {
    let (product, _tmp) = synthetic_product("syn-text-unmapped")?;
    let app = product.applications.first().ok_or("one application")?;
    plan_synthetic_07b0(&product, app, &BTreeMap::new())
}

/// The parameter segment ETS wrote at 0x6000 in the capture.
fn captured_segment() -> TestResult<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../captures/synthetic/syn-text-unmapped/defaults/image.json");
    let image: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let hex = image["regions"]
        .as_array()
        .ok_or("regions")?
        .iter()
        .find(|r| r["start"].as_u64() == Some(0x6000))
        .and_then(|r| r["hex"].as_str())
        .ok_or("the region at 0x6000")?;
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .ok_or_else(|| "odd hex".into())
                .and_then(|h| u8::from_str_radix(h, 16).map_err(Into::into))
        })
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
fn test_plan_flash_unmapped_text_character_is_a_question_mark() -> TestResult {
    let image = parameter_image(&plan()?)?;
    assert_eq!(image.get(3..17), Some(&TEXT[..]));
    // Every probe as ETS wrote it: the whole segment equals the capture.
    assert_eq!(image, captured_segment()?);
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
