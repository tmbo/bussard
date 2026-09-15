//! `Hardware.xml` parsing lives in the shared `bussard-ets` layer; this module
//! re-exports it. `.knxprod` reading keys the parsed hardware by order number
//! (via [`Hardware::order_to_apps`]); the join stays per Hardware2Program within
//! each `<Hardware>` block, so a catalogue part is never attributed the wrong
//! application. See [`bussard_ets::hardware`].

pub use bussard_ets::hardware::{Hardware, ProductInfo, parse_hardware};

/// Historical name for the parsed `Hardware.xml`; `.knxprod` reading only needs
/// the order-number join, which [`Hardware::order_to_apps`] carries.
pub type HardwareCatalog = Hardware;
