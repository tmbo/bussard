//! The downloader: computes device tables from the model, plans differential
//! changes against the live device state, and applies them over the bus.
//!
//! This is the phase-2 core (docs/DESIGN.md §1-2, §6). It splits into three
//! layers of increasing side-effect:
//!
//! - [`compute`]: pure functions turning one device's `links.yaml` entries into
//!   the desired group-address and association tables. No I/O; exhaustively
//!   tested, including a byte-for-byte golden test against a real device.
//! - [`plan`]: diff the desired tables against the tables read live from the
//!   device (via [`bussard_mgmt::tables`]) into a reviewable [`PlanReport`].
//! - [`apply`]: drive the load-state download sequence over the bus to write the
//!   tables, then verify by reading them back byte-for-byte.
//!
//! The CLI (`bussard plan` / `bussard apply`) is the top edge; safety policy —
//! the 07B0-mask gate, the TTY confirmation, the pre-write backup, the
//! never-run-on-live-bus discipline — lives there and in `bussard-cli`.

pub mod apply;
pub mod compute;
pub mod flash;
pub mod plan;

pub use apply::{
    TableObjectIndexes, VerifyOutcome, apply_tables, discover_table_objects, read_states,
};
pub use compute::{DesiredTables, compute_tables};
pub use flash::{
    AppIdentity, FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, ImageRef, PlanError,
    Progress, discover_application_object, flash, plan_flash, select_application, trace,
};
pub use plan::{LoadStep, ObjectGa, PlanReport, plan};
