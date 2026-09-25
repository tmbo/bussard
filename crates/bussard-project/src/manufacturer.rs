//! ApplicationProgram parsing lives in the shared `bussard-ets` layer; this
//! module re-exports the pieces `.knxproj` import needs. `build.rs` uses the
//! com-object table (base + ref, with the module `BaseNumber` reference), the
//! Dynamic-section channel defs, and the module argument ids. See
//! [`bussard_ets::application`].

pub use bussard_ets::application::ApplicationProgram;

// Only `build.rs`'s unit tests construct a `ChannelDef` directly or parse a
// program with the default language.
#[cfg(test)]
pub use bussard_ets::application::{ChannelDef, parse_application_program};
