//! `Hardware.xml` parsing lives in the shared `bussard-ets` layer; this module
//! re-exports it. `.knxproj` import keys by `Hardware2Program` id (a device's
//! `Hardware2ProgramRefId` resolves directly to its app refs via
//! [`Hardware::hardware2program`]) and reads product identity from
//! [`Hardware::products`]. See [`bussard_ets::hardware`].

pub use bussard_ets::hardware::{Hardware, parse_hardware};
