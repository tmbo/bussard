//! Core KNX domain model for bussard.
//!
//! This crate defines the address, DPT and flag types; DPT value codecs; the
//! on-disk YAML schema; the loader/saver; and the validation rules. Everything
//! downstream (transport, monitor, MCP, CLI) builds on these types.
//!
//! All YAML serialization is isolated in [`loader`] so the underlying crate
//! (`serde_norway`) can be swapped without touching the rest of the codebase.

#![warn(missing_docs)]

pub mod address;
pub mod codec;
pub mod dpt;
pub mod flags;
pub mod loader;
pub mod schema;
pub mod validate;

pub use address::{AddressParseError, GroupAddress, IndividualAddress};
pub use codec::{EncodeError, HvacMode, TypedValue, decode, encode};
pub use dpt::{ApduSize, Dpt, DptParseError};
pub use flags::{Flags, FlagsParseError};
pub use loader::{LoadError, LoadedDevice, Model, SaveError};
pub use validate::{Diagnostic, Severity, has_errors, validate};
