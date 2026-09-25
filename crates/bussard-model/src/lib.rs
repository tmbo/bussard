//! Core KNX domain model for bussard.
//!
//! This crate defines the address, DPT and flag types; DPT value codecs; the
//! in-memory model; the TOML loader/saver (`docs/model-format.md`); and the
//! validation rules. Everything downstream (transport, monitor, MCP, CLI)
//! builds on these types.
//!
//! All model-file (de)serialization is isolated in [`loader`], [`toml_io`]
//! and the private `files`/`emit` modules.

#![warn(missing_docs)]

pub mod address;
pub mod analysis;
pub mod bundle;
pub mod change;
pub mod codec;
pub mod declare;
pub mod device_view;
pub mod discover;
pub mod doc;
pub mod dpt;
mod emit;
pub mod ets_export;
pub mod facts;
mod file_checks;
mod files;
pub mod flags;
pub mod history;
pub mod lint;
pub mod loader;
pub mod merge;
pub mod param_model;
pub mod reconcile;
pub mod scaffold;
pub mod schema;
pub mod tests_schema;
pub mod toml_io;
pub mod validate;

pub use address::{AddressParseError, GroupAddress, IndividualAddress};
pub use analysis::{ModelAnalysis, analyze};
pub use bundle::{Bundle, BundleError, BundleManifest};
pub use change::{Change, ChangeKind, ChangeSet, LinkRole, describe, name_parameters, render_text};
pub use codec::{
    DateTime, EncodeError, Float16RangeError, HvacMode, ParseValueError, Rgbw, TypedValue, decode,
    encode, encode_float16, parse_value,
};
pub use declare::{DeclaredGroup, declare_used_groups};
pub use discover::{DEFAULT_MODEL_DIR, discover};
pub use doc::{DocError, DocFile, DocFormat, InstallationDoc};
pub use dpt::{ApduSize, Dpt, DptParseError};
pub use ets_export::{to_ets_csv, to_ets_xml};
pub use files::{hidden_mem_key, is_hidden_mem_key, label_mem_key, param_mem_key, slug};
pub use flags::{Flags, FlagsParseError};
pub use history::{History, HistoryError, Snapshot, SnapshotId, SnapshotReason};
pub use lint::{GroupsLint, LintConfig, TopologyLint, lint};
pub use loader::{LoadError, LoadedDevice, Model, SaveError, import_language, load_config};
pub use merge::{Conflict, MergeReport, merge, normalize_spellings};
pub use param_model::{ParamDef, ParamKind, ProductModel, ProductModels};
pub use scaffold::{Plan, PlanRoom, Scheme, scaffold, scaffold_file};
pub use tests_schema::{
    Expectation, TestCase, TestFileError, TestSuite, WriteStep, load_tests, load_tests_in_dir,
};
pub use toml_io::{ParseError, ParseErrorDetail};
pub use validate::{Diagnostic, Severity, has_errors, validate, validate_in_dir};
