//! Test-only tooling shared by the integration tests: the product-corpus
//! conformance sweep (moved out of the library, issue #897) and the corpus
//! file walk.

pub mod corpus;
pub mod sweep;

use std::collections::BTreeMap;

use bussard_download::{FlashPlan, PlanError};
use bussard_product::ApplicationProgram;
use bussard_product::application::LoadOp;

/// [`bussard_download::plan_flash`] with no object flags and a fresh Dynamic
/// memo, the inputs most planner tests share.
pub fn plan_flash_default(
    app: &ApplicationProgram,
    device: &str,
    device_mask: u16,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    template_ops: Option<&[LoadOp]>,
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> Result<FlashPlan, PlanError> {
    bussard_download::plan_flash(
        app,
        device,
        device_mask,
        overrides,
        base_offsets,
        template_ops,
        table_images,
        &BTreeMap::new(),
        &bussard_product::dynamic::DynamicMemo::new(app),
    )
}

/// The synthetic product `name` from `tests-support/synthetic-products/`,
/// its committed XML zipped with the stub master and read back; the
/// directory holding the zip goes with it.
pub fn synthetic_product(
    name: &str,
) -> bussard_testkit::TestResult<(bussard_product::ProductData, tempfile::TempDir)> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join(format!("{name}.knxprod"));
    crate::builtin_template::zip_synthetic(name, &path).map_err(|e| e.to_string())?;
    Ok((bussard_product::read_knxprod(&path)?, tmp))
}

/// The full download of the 07B0 `app` of `product` for 1.1.1 under
/// `overrides`, spliced into the built-in 07B0 template the stub master
/// leaves bussard with, with the table images of no model.
pub fn plan_synthetic_07b0(
    product: &bussard_product::ProductData,
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> bussard_testkit::TestResult<FlashPlan> {
    let template = bussard_download::template_ops_for(product, app).ok_or("a template for 07B0")?;
    let tables = bussard_download::build_table_images(
        None,
        "1.1.1".parse()?,
        app,
        overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    Ok(plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
}
