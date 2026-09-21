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
pub mod compute_sys7;
pub mod flash;
pub mod plan;
pub mod preflight;
pub mod sweep;

pub use apply::{
    TableObjectIndexes, VerifyOutcome, apply_tables, discover_table_objects, read_states,
};
pub use compute::{
    ChannelConfig, DesiredTables, GroupObjectDescriptor, Priority, app_program_version,
    compute_group_object_table, compute_tables, descriptors_for_linked_objects,
    expand_group_object_descriptors, size_code_from_object_size, table_image_with_count,
};
pub use compute_sys7::{
    Sys7GroupObject, sys7_address_table, sys7_association_table, sys7_config_byte,
    sys7_group_object_table, sys7_group_objects,
};
pub use flash::{
    AppIdentity, Connector, FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, ImageRef,
    PlanError, Progress, Session, SingleConnector, Sys7Context, discover_application_object, flash,
    plan_flash, plan_flash_sys7_with_hawk, select_application, sys7_profile_from_hawk, trace,
};
pub use plan::{LoadStep, ObjectGa, PlanReport, plan};
pub use preflight::{
    Freshness, ResidentObject, ResidentState, assess_freshness, format_app_id, probe_resident_state,
};
pub use sweep::{
    AppSweep, FamilyCoverage, ImageClass, ParseClass, PlanClass, ProductSweep, RankedReason,
    SweepManifest, SweepTotals, classify_application, family_label, manifest_from_products,
    sweep_corpus, sweep_file,
};
