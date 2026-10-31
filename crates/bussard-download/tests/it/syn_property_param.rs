//! A parameter placed in an interface-object property instead of memory
//! (issue #669): the synthetic product `syn-property-param` (07B0,
//! `MergedProcedure`) places an 8-bit parameter (default 90, `5A`) by
//! `<Property ObjectIndex="4" PropertyId="201">` and writes it with an
//! `LdCtrlWriteProp ObjIdx="4" PropId="201"` without `InlineData`. ETS 6.4.1
//! wrote `5A` to object 4 PID 201 (`captures/synthetic/syn-property-param`);
//! the System B plan must carry that write and the flash must land it.

use std::collections::BTreeMap;

use bussard_download::{
    FlashStep, PlanError, PropObject, Session, build_table_images, flash, plan_flash,
    read_property_value, template_ops_for,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_prod::application::ApplicationProgram;
use bussard_testkit::consts::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::builtin_template::zip_synthetic;

/// The application-relative id of the property-placed parameter's ref.
const TERRITORY_REF: &str = "P-3_R-3";

/// The product and its application, read from the zipped synthetic XML.
fn product() -> TestResult<(bussard_prod::ProductData, tempfile::TempDir)> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-property-param.knxprod");
    zip_synthetic("syn-property-param", &path).map_err(|e| e.to_string())?;
    Ok((bussard_prod::read_knxprod(&path)?, tmp))
}

/// The System B plan of `app` for 1.1.1 under `overrides`, spliced into the
/// built-in 07B0 template the stub master leaves bussard with.
fn plan_of(
    product: &bussard_prod::ProductData,
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> Result<bussard_download::FlashPlan, Box<dyn std::error::Error>> {
    let template = template_ops_for(product, app).ok_or("a template for 07B0")?;
    let tables = build_table_images(None, "1.1.1".parse()?, app, overrides);
    Ok(plan_flash(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
}

/// The plan's writes to object 4 PID 201.
fn territory_writes(plan: &bussard_download::FlashPlan) -> Vec<&FlashStep> {
    plan.steps
        .iter()
        .filter(|s| {
            matches!(
                s,
                FlashStep::WriteProp {
                    object: PropObject::Index(4),
                    prop_id: 201,
                    ..
                }
            )
        })
        .collect()
}

#[test]
fn test_plan_flash_writes_the_property_placed_parameter() -> TestResult {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new()).map_err(|e| e.to_string())?;
    assert_eq!(
        territory_writes(&plan),
        vec![&FlashStep::WriteProp {
            object: PropObject::Index(4),
            prop_id: 201,
            value: vec![0x5A],
            start_element: 1,
            count: 1,
            verify: false,
            from_parameters: true,
        }],
        "ETS wrote 5A to object 4 PID 201"
    );
    // In the application's MergeId 4 block, after the segment write, as ETS.
    let write_at = plan
        .steps
        .iter()
        .position(|s| matches!(s, FlashStep::WriteProp { prop_id: 201, .. }))
        .ok_or("the write")?;
    let segment_at = plan
        .steps
        .iter()
        .position(|s| matches!(s, FlashStep::WriteRelMem { .. }))
        .ok_or("the segment write")?;
    assert!(segment_at < write_at, "{:?}", plan.steps);
    Ok(())
}

#[test]
fn test_plan_flash_writes_the_overridden_property_value() -> TestResult {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    let overrides = BTreeMap::from([(TERRITORY_REF.to_string(), "7".to_string())]);
    let plan = plan_of(&product, app, &overrides).map_err(|e| e.to_string())?;
    match territory_writes(&plan).as_slice() {
        [FlashStep::WriteProp { value, .. }] => assert_eq!(value, &vec![0x07]),
        other => return Err(format!("expected one write, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_plan_flash_refuses_a_bare_write_prop_no_parameter_supplies() -> TestResult {
    let (product, _tmp) = product()?;
    let mut app = product
        .applications
        .first()
        .ok_or("one application")?
        .clone();
    for param in app.parameters.values_mut() {
        param.property = None;
    }
    match plan_of(&product, &app, &BTreeMap::new()) {
        Err(e) => match e.downcast_ref::<PlanError>() {
            Some(PlanError::UnsupportedWriteProp { reason, .. }) => {
                assert!(reason.contains("object 4 PID 201"), "{reason}");
            }
            _ => return Err(format!("expected UnsupportedWriteProp, got {e}").into()),
        },
        Ok(plan) => return Err(format!("expected a refusal, got {:?}", plan.steps).into()),
    }
    Ok(())
}

#[tokio::test]
async fn test_flash_writes_and_reads_back_the_property_placed_parameter() -> TestResult {
    let (product, _tmp) = product()?;
    let app = product.applications.first().ok_or("one application")?;
    let plan = plan_of(&product, app, &BTreeMap::new()).map_err(|e| e.to_string())?;
    let device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        // PID_PROGRAM_VERSION, written by the template.
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_writable_property(4, 201, 1, &[0xFF]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.1")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    assert!(outcome.ok(), "{outcome:?}");
    // The independent read-back the write commands end with: the device holds
    // the model's value.
    let held = read_property_value(session.l4(), PropObject::Index(4), 201, 1, 1, 1).await?;
    let _ = session.into_disconnect().await;
    assert_eq!(held, vec![0x5A]);
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(dev.property(4, 201), Some(&[0x5A][..]));
    Ok(())
}
