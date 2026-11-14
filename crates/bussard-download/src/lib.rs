//! The downloader: computes device tables from the model, plans differential
//! changes against the live device state, and applies them over the bus.
//!
//! This is the phase-2 core (dev/DESIGN.md §1-2, §6). It splits into three
//! layers of increasing side-effect:
//!
//! - [`compute`]: pure functions turning one device's links (the object entries of its device file) into
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
pub mod device_plan;
pub mod flash;
pub mod model_params;
pub mod object_table;
pub mod param_decode;
pub mod param_plan;
pub mod param_props;
pub mod plan;
pub mod preflight;
pub mod program;
pub mod security;
pub mod security_diag;
pub mod tables_sys7;

// The corpus file walk of the integration tests' sweep, for the env-gated
// corpus unit tests in `flash`.
#[cfg(test)]
#[path = "../tests/it/support/corpus.rs"]
mod corpus;

pub use apply::{SystemBLoad, TableRestart, uses_user_memory};
pub use apply_sys7::{Sys7TableImages, sys7_flag_writes, sys7_table_images};
pub use backup::{
    BackupError, BackupManifest, BackupStatus, DeviceBackup, ManifestEntry, ParameterBackup,
    ParameterMemory, ParameterStatus, backups_root, find_device_backup, has_installation_backup,
    parameter_backups_dir, read_device_backup, read_parameter_backup, write_device_backup,
    write_manifest,
};
pub use compute::{
    DesiredTables, GroupObjectDescriptor, compute_tables, dynamic_group_object_descriptors,
};
pub use compute_sys7::{Sys7GroupObject, decode_sys7_association_table};
pub use device_plan::{
    ChangeMark, ChangeSubject, DevicePlan, FullImage, ObjectTableWrite, PlanChange, PlanWrites,
    object_changes, sort_changes, state_hash, state_hash_with,
};
pub use flash::{
    Connector, FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, ImageRef,
    LoadControlForm, PartialPlanError, PlanError, Progress, PropObject, PropertyWrite,
    RebootReadiness, RestartForm, RestartKind, Session, Sys7TableBases, add_par_procedure,
    allocation_change, describe_property, discover_application_object, ets_friendly_name, flash,
    knxnet_ip_program, plan_flash, property_write_requests, read_property_value, restart_form,
    select_application, sys7_table_bases, trace, write_property_value,
};
pub use model_params::{
    Sys7Identity, build_table_images, describe_group_object_change, flash_gate, identity_gate,
    linked_object_flags, master_template_ops, model_parameters, needs_sys7_identity,
    par_template_ops_for, parameter_overrides, plan_for_parameters, plan_for_readback, region_rows,
    resolve_by_order_number, runtime_segments, sys7_code_mismatch, sys7_identity, template_ops_for,
    verify_readback, write_parameter_memory_backup,
};
pub use object_table::{
    ObjectTableChange, ObjectTableCheck, check_object_table, find_object_table,
    read_object_table_at, table_entry_count,
};
pub use param_decode::{
    DecodedParameters, OctetOwner, OctetRange, OctetRole, attribute_octets, decode_parameters,
    device_managed_octets,
};
pub use param_plan::{
    CurrentMemory, GroupObjectChange, ParamChange, ParamPlan, ParamReading, ParamRegions,
    ParamValue, SYS7_NOTE, group_object_change, param_plan, planned_parameter_regions,
    read_current_parameter_memory, read_parameter_regions, regions_memory,
};
pub use param_props::{
    ParamProperty, PropertyRange, changed_parameter_properties, changed_properties, held_after,
    masked_equal, read_back_properties, read_checked_properties,
};
pub use plan::{ObjectGa, PlanReport, plan};
pub use preflight::{
    Freshness, ProbeScope, ResidentObject, ResidentState, assess_freshness, format_app_id,
    probe_resident_state,
};
pub use program::{
    LiveRead, LiveTables, desired_tables_for_app, has_no_group_objects, read_live_tables,
    render_full_image_plan_text, render_plan_text, write_pre_write_backup, write_sys7,
    write_system_b, write_tables,
};
pub use security::{
    GroupKeyEntry, SecureSenderEntry, SecurityInputs, SecurityPlanError, SecurityReadback,
    TableCapacity, build_security_program, check_planned_capacity, device_security_view,
    program_security_object, read_security_flags, read_security_object, read_security_sender_table,
    secured_senders, security_inputs_for, sender_table_bytes,
};
pub use security_diag::{
    SecurityDiagnostics, clear_security_diagnostics, read_security_diagnostics,
};
pub use tables_sys7::Sys7LiveTables;
