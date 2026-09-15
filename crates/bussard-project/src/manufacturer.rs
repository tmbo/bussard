//! ApplicationProgram parsing lives in the shared `bussard-ets` layer; this
//! module re-exports the pieces `.knxproj` import needs. `build.rs` uses the
//! com-object table (base + ref, with the module `BaseNumber` reference), the
//! Dynamic-section channel defs, and the module argument ids. See
//! [`bussard_ets::application`].

pub use bussard_ets::application::{ApplicationProgram, parse_application_program};

// Only `build.rs`'s unit tests construct a `ChannelDef` directly.
#[cfg(test)]
pub use bussard_ets::application::ChannelDef;
