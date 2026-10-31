//! Verify mode on System B (issue #705): ETS reads `obj0/PID_DEVICE_CONTROL`
//! and writes bit 2 when it is clear before the first plain `A_Memory_Write`
//! of a `Verify="true"` load control (house captures of 1.1.45 and 1.1.51),
//! then expects an `A_Memory_Response` echo after every write. The synthetic
//! `syn-minimal` (07B0, built-in template) writes its parameter segment with
//! `Verify="false"` and its tables with `Verify="true"`: ETS reads the
//! property before the group-object table write (`captures/synthetic/
//! syn-minimal/defaults/ops.txt`).

use std::collections::BTreeMap;

use bussard_download::{
    FlashOptions, FlashPlan, FlashStep, ImageKind, Session, build_table_images, flash, plan_flash,
    template_ops_for,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_prod::application::ApplicationProgram;
use bussard_testkit::consts::{
    A_MEMORY_RESPONSE, A_MEMORY_WRITE, A_PROPERTY_VALUE_WRITE, OT_ADDRESS_TABLE,
    OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::builtin_template::zip_synthetic;

/// The product and its application, read from the zipped synthetic XML.
fn product() -> TestResult<(bussard_prod::ProductData, tempfile::TempDir)> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_synthetic("syn-minimal", &path).map_err(|e| e.to_string())?;
    Ok((bussard_prod::read_knxprod(&path)?, tmp))
}

/// The System B plan of `app` for 1.1.1, spliced into the built-in 07B0
/// template the stub master leaves bussard with.
fn plan_of(
    product: &bussard_prod::ProductData,
    app: &ApplicationProgram,
) -> Result<FlashPlan, Box<dyn std::error::Error>> {
    let template = template_ops_for(product, app).ok_or("a template for 07B0")?;
    let overrides = BTreeMap::new();
    let tables = build_table_images(None, "1.1.1".parse()?, app, &overrides);
    Ok(plan_flash(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
}

/// The plan's steps from the first `EnableVerifyMode` on.
fn verify_mode_steps(plan: &FlashPlan) -> Vec<usize> {
    plan.steps
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, FlashStep::EnableVerifyMode))
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn test_plan_flash_switches_verify_mode_on_before_the_first_verified_write() -> TestResult {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app).map_err(|e| e.to_string())?;
    let at = verify_mode_steps(&plan);
    assert_eq!(at.len(), 1, "{:?}", plan.steps);
    // Right ahead of the group-object table write (the template's first
    // `Verify="true"` write), after the parameter write (`Verify="false"`).
    match plan.steps.get(at[0] + 1) {
        Some(FlashStep::WriteRelMem { image, target, .. }) => {
            assert_eq!(image.kind, ImageKind::Table);
            assert_eq!(*target, Some(3));
        }
        other => return Err(format!("expected the obj3 table write, got {other:?}").into()),
    }
    let parameters_at = plan
        .steps
        .iter()
        .position(|s| {
            matches!(s, FlashStep::WriteRelMem { image, .. } if image.kind == ImageKind::Parameters)
        })
        .ok_or("the parameter write")?;
    assert!(parameters_at < at[0], "{:?}", plan.steps);
    Ok(())
}

#[test]
fn test_plan_flash_leaves_verify_mode_alone_on_extended_memory_applications() -> TestResult {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    // ETS writes these with A_MemoryExtended_Write and never touches the
    // property (`syn-user-memory-extmem`, the house's Data Secure apps).
    let mut extended = app.clone();
    extended.supports_extended_memory_services = true;
    let plan = plan_of(&product, &extended).map_err(|e| e.to_string())?;
    assert!(verify_mode_steps(&plan).is_empty(), "{:?}", plan.steps);
    let mut secure = app.clone();
    secure.is_secure_enabled = true;
    let plan = plan_of(&product, &secure).map_err(|e| e.to_string())?;
    assert!(verify_mode_steps(&plan).is_empty(), "{:?}", plan.steps);
    Ok(())
}

/// A System B device of 1.1.1 with the objects syn-minimal loads.
fn device() -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        // PID_PROGRAM_VERSION, written by the template.
        .with_writable_property(4, 13, 5, &[0; 5]))
}

/// Flashes syn-minimal onto `device` and returns the outcome (or the error)
/// and the device afterwards.
async fn flash_onto(
    device: MockDevice,
) -> TestResult<(
    Result<bussard_download::FlashOutcome, bussard_mgmt::WriteError>,
    MockDevice,
)> {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app).map_err(|e| e.to_string())?;
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.1")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(&mut session, &plan, FlashOptions::default(), |_| {}).await;
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    Ok((outcome, dev))
}

/// How many `A_PropertyValue_Write`s of obj0 PID 14 the device saw.
fn device_control_writes(dev: &MockDevice) -> usize {
    dev.requests
        .iter()
        .filter(|(apci, data)| *apci == A_PROPERTY_VALUE_WRITE && data.get(..2) == Some(&[0, 14]))
        .count()
}

#[tokio::test]
async fn test_flash_sets_verify_mode_and_compares_the_echoes() -> TestResult {
    // The device holds 00, as 1.1.45 and 1.1.51 answered ETS.
    let (outcome, dev) = flash_onto(device()?.with_verify_mode_control(0x00)).await?;
    let outcome = outcome?;
    assert!(outcome.ok(), "{outcome:?}");
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    assert_eq!(device_control_writes(&dev), 1);
    assert_eq!(dev.property(0, 14), Some(&[0x04][..]));
    // The parameter segment (Verify="false") goes out before the switch, as
    // in ETS's capture; every table write after it is echoed.
    let first_on = dev
        .writes_in_verify_mode
        .iter()
        .position(|on| *on)
        .ok_or("no write in verify mode")?;
    assert!(first_on > 0, "{:?}", dev.writes_in_verify_mode);
    assert!(
        dev.writes_in_verify_mode[first_on..].iter().all(|on| *on),
        "{:?}",
        dev.writes_in_verify_mode
    );
    let echoes = outcome.verify_echoes.ok_or("verify echoes counted")?;
    assert_eq!(
        echoes.echoes_compared,
        (dev.writes_in_verify_mode.len() - first_on) as u64
    );
    assert_eq!(echoes.echoes_compared, echoes.chunks_written);
    Ok(())
}

#[tokio::test]
async fn test_flash_leaves_verify_mode_alone_when_already_on() -> TestResult {
    // knx-sim's System B model answers 04: ETS reads and writes nothing.
    let mut dev = device()?.with_verify_mode_control(0x04);
    // Keep the bit across the T_Connect, as the sim does.
    dev.verify_mode_control = false;
    let (outcome, dev) = flash_onto(dev).await?;
    let outcome = outcome?;
    assert!(outcome.ok(), "{outcome:?}");
    assert_eq!(device_control_writes(&dev), 0);
    let echoes = outcome.verify_echoes.ok_or("verify echoes counted")?;
    assert!(echoes.echoes_compared > 0, "{echoes:?}");
    assert_eq!(echoes.echoes_compared, echoes.chunks_written);
    Ok(())
}

#[tokio::test]
async fn test_flash_without_device_control_writes_unechoed_and_warns() -> TestResult {
    // A device without PID_DEVICE_CONTROL and without the echo.
    let (outcome, dev) = flash_onto(device()?.without_memory_write_echo()).await?;
    let outcome = outcome?;
    assert!(outcome.ok(), "{outcome:?}");
    assert_eq!(device_control_writes(&dev), 0);
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.contains("no readable PID_DEVICE_CONTROL")),
        "{:?}",
        outcome.warnings
    );
    assert_eq!(outcome.verify_echoes, None);
    Ok(())
}

#[tokio::test]
async fn test_flash_fails_on_an_echo_that_differs() -> TestResult {
    // In verify mode the device echoes a different first octet.
    let dev = device()?
        .with_verify_mode_control(0x00)
        .with_hook(|dev, apci, data| {
            if apci & 0x3C0 != A_MEMORY_WRITE || data.len() < 3 || !dev.verify_mode() {
                return None;
            }
            let mut echo = data.to_vec();
            if let Some(b) = echo.get_mut(2) {
                *b ^= 0xFF;
            }
            let count = (data.len() - 2) as u16 & 0x3F;
            Some(Reaction::Answer(A_MEMORY_RESPONSE | count, echo))
        });
    let (outcome, _dev) = flash_onto(dev).await?;
    match outcome {
        Err(e) => assert!(
            e.to_string().to_lowercase().contains("echo"),
            "expected the echo mismatch, got {e}"
        ),
        Ok(outcome) => return Err(format!("expected a failure, got {outcome:?}").into()),
    }
    Ok(())
}
