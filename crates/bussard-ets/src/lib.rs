//! Shared ETS-XML primitives used by `bussard-project` (.knxproj) and
//! `bussard-prod` (.knxprod).
//!
//! ETS product and project data is XML packaged in ZIP containers, and both
//! importers need the same low-level building blocks:
//!
//! * [`attrs`] — attribute-map/value helpers and BOM stripping.
//! * [`dpt`] — `DPST`/`DPT` string parsing plus the `ObjectSize` fallback.
//! * [`flags`] — the [`FlagSet`] override chain over ETS flag attributes.
//! * [`translation`] — en-US `<Languages>` resolution.
//! * [`zip_util`] — capped zip-entry reading (a zip-bomb guard, see issue #39).
//! * [`application`] — one streaming ApplicationProgram parser (the superset of
//!   both consumers' needs).
//! * [`hardware`] — one `Hardware.xml` parser, keyed both by `Hardware2Program`
//!   id (for `.knxproj`) and by order number (for `.knxprod`), joined per
//!   Hardware block so order numbers never attribute the wrong application.
//! * [`error`] — the shared [`EtsError`] the XML layer raises; each consumer
//!   wraps it in its own crate error.
//!
//! This is the shared *primitives* layer, not a merged importer: container
//! specifics (AES/PBKDF2, project `0.xml`, `.knxprod` layout, model building)
//! stay in the consuming crates.

#![warn(missing_docs)]

pub mod application;
pub mod attrs;
pub mod dpt;
pub mod error;
pub mod flags;
pub mod hardware;
pub mod translation;
pub mod zip_util;

pub use application::{
    ApplicationProgram, ChannelDef, CodeSegment, ComObject, ComObjectRef, EnumValue, LoadOp,
    LoadProcedure, Memory, Parameter, ParameterRef, ParameterType, ParameterTypeDecl,
    ResolvedComObject, ResolvedParameter, SegmentKind, parse_application_program,
};
pub use attrs::{attr_value, attrs_map, flagset_from, get, strip_bom};
pub use dpt::{dpt_from_object_size, parse_ets_dpt};
pub use error::{EtsError, Result};
pub use flags::{FlagSet, parse_flag_value};
pub use hardware::{Hardware, ProductInfo, parse_hardware};
pub use translation::TranslationCollector;
pub use zip_util::{MAX_ENTRY_SIZE, read_capped, read_entry_opt};
