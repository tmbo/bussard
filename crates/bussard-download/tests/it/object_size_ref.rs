//! A com-object whose own `ObjectSize` has no value field type code
//! (`LegacyVarData`) is planned when its ref states a size that has one
//! (issue #1065).
//!
//! The synthetic `syn-object-size-ref` is `syn-minimal` with object 2
//! declared `LegacyVarData` and its only ref `14 Bytes`, the shape of the Jung
//! `M-0004_A-1111-11-A356-O000A` object 7. A `ComObjectRef` attribute
//! overrides the `ComObject` one, so the descriptor takes code 14. The flash
//! ends with the read-back, and the group-object table the device holds is
//! the planned one.

use std::collections::BTreeMap;

use bussard_download::{
    FlashOptions, FlashPlan, FlashStep, ImageKind, Session, build_table_images, flash,
    template_ops_for,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_testkit::consts::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::builtin_template::zip_synthetic;
use crate::support::plan_flash_default;

/// Where the mock places the group-object table (object 3).
const TABLE_BASE: u32 = 0x8000;

/// The plan of `syn-object-size-ref` at its defaults.
fn plan() -> TestResult<FlashPlan> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-object-size-ref.knxprod");
    zip_synthetic("syn-object-size-ref", &path).map_err(|e| e.to_string())?;
    let product = bussard_product::read_knxprod(&path)?;
    let app = product.applications.first().ok_or("one application")?;
    let template = template_ops_for(&product, app).ok_or("a template for 07B0")?;
    let overrides = BTreeMap::new();
    let tables = build_table_images(
        None,
        "1.1.1".parse()?,
        app,
        &overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )
    .map_err(|e| e.to_string().into())
}

/// The group-object table the plan writes to object 3.
fn group_object_table(plan: &FlashPlan) -> TestResult<Vec<u8>> {
    let image = plan
        .steps
        .iter()
        .find_map(|s| match s {
            FlashStep::WriteRelMem {
                image,
                target: Some(3),
                ..
            } if image.kind == ImageKind::Table => Some(image),
            _ => None,
        })
        .ok_or("a group-object table write")?;
    Ok(plan
        .image_bytes(&image.segment_id)
        .ok_or("the image")?
        .to_vec())
}

#[test]
fn test_plan_flash_legacy_var_data_object_takes_its_ref_size() -> TestResult {
    let table = group_object_table(&plan()?)?;
    // Count word, then the descriptors of objects 1 and 2 (number 0 has no
    // table entry); object 2's type octet carries code 14 (14 octets), the
    // ref's size.
    assert_eq!(table.get(..2), Some(&[0x00, 0x02][..]), "{table:02x?}");
    let object_2 = table.get(4..6).ok_or("object 2")?;
    assert_eq!(object_2[1] & 0x3F, 14, "{table:02x?}");
    Ok(())
}

#[tokio::test]
async fn test_flash_legacy_var_data_object_reads_back_the_table() -> TestResult {
    let plan = plan()?;
    let table = group_object_table(&plan)?;
    let device = MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_segment_base(3, TABLE_BASE)
        .with_segment_base(4, 0x6000);
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
    assert_eq!(dev.read_mem(TABLE_BASE, table.len()), table);
    Ok(())
}
