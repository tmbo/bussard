//! Test-only tooling shared by the integration tests: the product-corpus
//! conformance sweep (moved out of the library, issue #897) and the corpus
//! file walk.

pub mod corpus;
pub mod sweep;

use std::collections::BTreeMap;

use bussard_download::{FlashPlan, PlanError};
use bussard_prod::ApplicationProgram;
use bussard_prod::application::LoadOp;

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
        &bussard_prod::dynamic::DynamicMemo::new(app),
    )
}
