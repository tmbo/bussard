//! The key store the surfaces name: [`KeyStore`] and its results.
//!
//! Re-exported from `bussard-project` by name so the surfaces depend on
//! `bussard-service` and `bussard-model` only (issue #916).

pub use bussard_project::{KeyStore, KeyStoreError, parse_keyring};

/// The key store module: its outcomes and constants.
pub mod keystore {
    pub use bussard_project::keystore::{
        AttachOutcome, BackboneChange, ImportReport, KEYSTORE_BACKUP_FILE, KeyStore,
        KeyStoreSummary, SaveOutcome, SerialNumber,
    };
}
