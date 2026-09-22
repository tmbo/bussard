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
pub mod change;
pub mod codec;
pub mod dpt;
pub mod flags;
pub mod history;
pub mod loader;
pub mod merge;
pub mod param_model;
pub mod schema;
pub mod validate;

pub use address::{AddressParseError, GroupAddress, IndividualAddress};
pub use change::{Change, ChangeKind, ChangeSet, LinkRole, describe, render_text};
pub use codec::{
    DateTime, EncodeError, Float16RangeError, HvacMode, ParseValueError, Rgbw, TypedValue, decode,
    encode, encode_float16, parse_value,
};
pub use dpt::{ApduSize, Dpt, DptParseError};
pub use flags::{Flags, FlagsParseError};
pub use history::{History, HistoryError, Snapshot, SnapshotId, SnapshotReason};
pub use loader::{LoadError, LoadedDevice, Model, SaveError};
pub use merge::{Conflict, MergeReport, merge};
pub use param_model::{ParamDef, ParamKind, ProductModel, ProductModels};
pub use validate::{Diagnostic, Severity, has_errors, validate, validate_in_dir};
