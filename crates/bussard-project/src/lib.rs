//! bussard's key store: the KNX Secure keys of a project (`.bussard/keys/`),
//! the ETS keyring (`.knxkeys`) import and export.
//!
//! The `.knxproj` import that used to live here is
//! [`bussard_product::import`]. The key store stays a crate of its own because
//! moving it into `bussard-model` would give the model a `bussard-secure`,
//! `quick-xml` and `bussard-product` (attribute helpers) dependency
//! (issue #916).

#![warn(missing_docs)]

mod keyring;
pub mod keystore;

pub use keyring::KeyringError;
pub use keystore::{
    Backbone, ImportReport, KeyStore, KeyStoreError, KeyStoreSummary, SaveOutcome, StoreDevice,
    StoreInterface, StoreRevision, parse_keyring,
};
