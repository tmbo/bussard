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
//! System 7 (mask 0705 / 0701) has the same three layers in sibling modules,
//! because its tables are absolute memory regions rather than property arrays:
//! [`compute_sys7`] synthesizes and decodes the byte forms, [`tables_sys7`] reads
//! them off a live device, and [`apply_sys7`] drives the two table load-state
//! machines to write them (issue #91).
//!
//! The CLI (`bussard plan` / `bussard apply`) is the top edge; safety policy —
//! the mask-family gate, the TTY confirmation, the pre-write backup, the
//! never-run-on-live-bus discipline — lives there and in `bussard-cli`.

pub mod apply;
pub mod apply_sys7;
pub mod backup;
pub mod compute;
pub mod compute_sys7;
pub mod flash;
pub mod param_decode;
pub mod param_plan;
pub mod plan;
pub mod preflight;
pub mod program;
pub mod security;
pub mod sweep;
pub mod tables_sys7;

pub use apply::{
    TableObjectIndexes, VerifyOutcome, apply_tables, apply_tables_secured, discover_table_objects,
    negotiate_session_apdu, read_states,
};
pub use apply_sys7::{
    SYS7_ADDRESS_LSM, SYS7_ASSOCIATION_LSM, Sys7ApplyError, Sys7TableImages, Sys7VerifyOutcome,
    apply_sys7_tables, sys7_table_images,
};
pub use backup::{
    AssociationEntry, BackupError, BackupManifest, BackupStatus, DeviceBackup, ManifestEntry,
    ParameterBackup, ParameterMemory, ParameterStatus, ResolvedEntry, Sys7Detail, backups_root,
    find_device_backup, has_installation_backup, parameter_backups_dir, read_device_backup,
    read_manifest, write_device_backup, write_manifest, write_parameter_backup,
};
pub use compute::{
    ChannelConfig, DesiredTables, GroupObjectDescriptor, LinkedObject, Priority,
    app_program_version, compute_group_object_table, compute_group_object_table_with_count,
    compute_tables, descriptors_for_linked_objects, dynamic_group_object_descriptors,
    dynamic_group_object_table, expand_group_object_descriptors, group_object_table_count,
    size_code_from_object_size, table_image_with_count,
};
pub use compute_sys7::{
    SYS7_ADDRESS_REGION_LEN, SYS7_ADDRESS_TABLE_ADDR, SYS7_ASSOCIATION_REGION_LEN,
    SYS7_ASSOCIATION_TABLE_ADDR, Sys7DecodeError, Sys7GroupObject, decode_sys7_address_table,
    decode_sys7_association_table, decode_sys7_group_object_table, sys7_address_table,
    sys7_association_table, sys7_config_byte, sys7_group_object_table, sys7_group_objects,
};
pub use flash::{
    AppIdentity, Connector, DeviceFacts, FlashOptions, FlashOutcome, FlashPlan, FlashStep,
    ImageKind, ImageRef, PartialPlanError, PlanError, Progress, Session, SingleConnector,
    Sys7Context, discover_application_object, flash, plan_flash, plan_flash_sys7_with_hawk,
    plan_flash_with_object_flags, same_program, select_application, sys7_profile_from_hawk, trace,
};
pub use param_decode::{DecodedParameters, decode_parameters};
pub use param_plan::{
    CurrentMemory, GroupObjectChange, ParamChange, ParamPlan, ParamReading, ParamRegion,
    ParamRegions, ParamValue, SYS7_NOTE, current_parameter_values, group_object_change,
    non_default_parameters, param_plan, planned_parameter_regions, read_current_parameter_memory,
    read_parameter_regions, regions_memory,
};
pub use plan::{LoadStep, ObjectGa, PlanReport, plan};
pub use preflight::{
    Freshness, ResidentObject, ResidentState, assess_freshness, format_app_id, probe_resident_state,
};
pub use program::{
    LiveRead, LiveReadError, LiveTables, NoLinks, TableWriteSummary, desired_tables_for,
    read_live_tables, render_plan_text, write_pre_write_backup, write_sys7, write_system_b,
    write_system_b_secured, write_tables, write_tables_secured,
};
pub use security::{
    DeviceSecurityView, GO_FLAGS_SECURE, GroupKeyEntry, MAX_SEQUENCE, SecureSenderEntry,
    SecurityInputs, SecurityPlanError, SecurityProgram, build_security_program,
    device_security_view, program_security_object, secured_senders, security_inputs_for,
    sender_table_bytes,
};
pub use sweep::{
    AppSweep, FamilyCoverage, ImageClass, ParseClass, PlanClass, ProductSweep, RankedReason,
    SweepManifest, SweepTotals, classify_application, family_label, manifest_from_products,
    sweep_corpus, sweep_file,
};
pub use tables_sys7::{Sys7LiveTables, Sys7TablesError, read_sys7_tables};
