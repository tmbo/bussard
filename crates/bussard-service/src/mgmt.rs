//! The management types and lookups the surfaces name: mask profiles, the
//! manufacturer table, the management error and timeouts.
//!
//! Re-exported from `bussard-mgmt` by name so the surfaces depend on
//! `bussard-service` and `bussard-model` only (issue #916); the management
//! flows themselves are service functions.

pub use bussard_mgmt::{MaskProfile, MgmtError, SourceCheckError, Timeouts, system_type};

/// The APCI constants the surfaces show.
pub mod apci {
    pub use bussard_mgmt::apci::FREE_ACCESS_KEY;
}

/// The manufacturer table.
pub mod manufacturers {
    pub use bussard_mgmt::manufacturers::{display, load_model_dir};
}

/// The table images read from a device.
pub mod tables {
    pub use bussard_mgmt::tables::DeviceTables;
}
