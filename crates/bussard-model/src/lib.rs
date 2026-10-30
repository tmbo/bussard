//! Core KNX domain model for bussard.
//!
//! This crate defines the address, DPT and flag types; DPT value codecs; the
//! in-memory model; the TOML loader/saver (`docs/reference/files/`); and the
//! validation rules. Everything downstream (transport, monitor, MCP, CLI)
//! builds on these types.
//!
//! All model-file (de)serialization is isolated in [`loader`], [`toml_io`]
//! and the private `files`/`emit` modules.

#![warn(missing_docs)]

pub mod address;
pub mod analysis;
pub mod blocks;
pub mod bundle;
pub mod capabilities;
pub mod change;
pub mod checklist;
pub mod codec;
pub mod color_codec;
pub mod declare;
pub mod device_view;
pub mod discover;
pub mod doc;
pub mod dotenv;
pub mod dpt;
mod dpt_tables;
pub mod dynamic;
pub mod dynamic_compact;
mod emit;
pub mod ets_export;
pub mod facts;
mod file_checks;
mod files;
pub mod flags;
pub mod history;
pub mod identity;
pub mod keyring_checks;
pub mod keystore_meta;
pub mod knxnet;
pub mod label;
pub mod lint;
pub mod loader;
pub mod lock_products;
pub mod merge;
pub mod param_model;
pub mod reconcile;
pub mod scaffold;
pub mod schema;
pub mod secure_invariants;
pub mod secure_links;
pub mod tests_schema;
pub mod text_codec;
pub mod toml_io;
pub mod validate;

pub use address::{AddressParseError, GroupAddress, IndividualAddress};
pub use analysis::{ModelAnalysis, analyze};
pub use bundle::{Bundle, BundleError, BundleManifest};
pub use change::{
    Change, ChangeKind, ChangeSet, LinkRole, describe, name_parameters, render_text,
    settle_parameters,
};
pub use codec::{
    DateTime, EncodeError, Float16RangeError, HvacMode, ParseValueError, Rgbw, TypedValue, decode,
    encode, encode_float16, encode_float16_raw, parse_value, validity_note,
};
pub use declare::{DeclaredGroup, declare_used_groups};
pub use discover::{DEFAULT_MODEL_DIR, NESTED_MODEL_DIR, discover};
pub use doc::{DocError, DocFile, DocFormat, InstallationDoc};
pub use dpt::{ApduSize, Dpt, DptParseError};
pub use ets_export::{to_ets_csv, to_ets_xml};
pub use files::{
    LOCK_SCHEMA_FINGERPRINT, LOCK_VERSION, hidden_mem_key, is_hidden_mem_key, label_mem_key,
    lock_written_by, param_mem_key, slug,
};
pub use flags::{Flags, FlagsParseError, Priority};
pub use history::{History, HistoryError, Snapshot, SnapshotId, SnapshotReason};
pub use keyring_checks::{KeyringFacts, KeyringStatus, validate_keyring};
pub use keystore_meta::{KEYSTORE_META_FILE, KeyStoreMeta, KeyStoreMetaError, KeyringExport};
pub use lint::{GroupsLint, LintConfig, TopologyLint, lint};
pub use loader::{LoadError, LoadedDevice, Model, SaveError, import_language, load_config};
pub use lock_products::{PinError, PinReport, pin_products, sha256_file, sha256_file_cached};
pub use merge::{Conflict, MergeReport, merge, normalize_spellings};
pub use param_model::{ParamDef, ParamKind, ProductModel, ProductModels};
pub use scaffold::{Plan, PlanRoom, Scheme, scaffold, scaffold_file};
pub use secure_invariants::{rekeyed_by_keys_import, resecured_by_import};
pub use secure_links::{ConflictKind, SecureLinkConflict, secure_link_conflicts};
pub use tests_schema::{
    Expectation, TestCase, TestFileError, TestSuite, WriteStep, load_tests, load_tests_in_dir,
};
pub use toml_io::{ParseError, ParseErrorDetail};
pub use validate::{Diagnostic, Severity, has_errors, validate, validate_in_dir};
