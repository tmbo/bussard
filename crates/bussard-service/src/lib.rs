//! The service layer between bussard's surfaces and its domain crates.
//!
//! bussard has three surfaces: the `bussard` CLI, the MCP server
//! (`bussard-mcp`) and the viz web server (`bussard-viz`). Each used to
//! orchestrate the domain crates (`bussard-bus`, `bussard-mgmt`,
//! `bussard-model`, `bussard-secure`) on its own, so the safety rules were
//! implemented once per surface and drifted apart (issue #86). This crate holds
//! the one copy of each rule. A surface parses its input, calls in here and
//! renders the result; it does not decide policy.
//!
//! What lives here:
//!
//! - [`BusService`]: a bus connection opened under a [`WritePolicy`]. The
//!   non-loopback write gate ([`bussard_transport::write_gate`], issue #74) is
//!   applied in [`BusService::open`], so a surface that can transmit cannot
//!   forget it.
//! - Management sessions: [`BusService::connect_l4`] and
//!   [`BusService::with_l4`] run the lease, `T_Connect`, KNX Data Secure layer,
//!   authorize and disconnect sequence that every device command needs.
//! - [`secure`]: resolving a KNX Data Secure tool key from an ETS keyring or a
//!   raw test key, and building the management [`SecureLayer`](bussard_mgmt::SecureLayer).
//! - [`write`]: the checked group write (GA, protected-GA check, DPT, encode,
//!   send) with a typed [`WriteRefusal`] that each surface renders in its own
//!   words.
//! - [`group`]: KNX Data Secure group communication: which GAs are secured
//!   ([`group_key_for`]), the secured `GroupValueRead`
//!   ([`BusService::read_group`]) and the sealing behind the secured write.
//! - [`ModelHandle`]: a shared model that reloads itself when the files on disk
//!   change, used by the long-lived MCP and viz servers, and
//!   [`complete_product_models`], which fills in missing product models
//!   before every load and reload.
//! - [`admission`]: whether the devices on a secured group address admit
//!   bussard's tunnel address as a secure sender (PID 54), and the plan change
//!   of `admit_tunnel_senders` (issue #297).
//! - [`assign`]: the assign flow (wait for programming mode, identify, write
//!   the individual address, read back, the device file) behind `bussard
//!   assign`, `adopt` and `knx_add_device` (issue #749).
//! - [`adopt`]: the adopt flow on top of it: the product data shaped into the
//!   device file, and what a KNX Data Secure-activated device records (links,
//!   `secure` flags, the security intent and lock facts).
//! - [`commission`]: the line walk of `bussard commission` and
//!   `knx_commission_line` on the assign steps: the order-number check
//!   before the write, the read-back and the label (issue #753).
//! - [`declare`]: the group addresses the device files use first, declared
//!   in `groups.toml` before `bussard apply` (device and `--line`) and
//!   `knx_apply_device` (both forms) validate (issue #779).
//! - [`describe`]: the interface-object walk and the PID / object-type name
//!   tables shared by `bussard describe` and `knx_describe_device`.
//! - [`backup`]: the device reads behind `bussard backup` and
//!   `knx_backup_device`; [`reconstruct`]: a device's tables diffed against
//!   the model (`bussard reconstruct`, `knx_reconstruct_device`, issue #717).
//! - [`line`](mod@line): the whole-line plan and apply (`bussard plan --line`, `apply
//!   --line`, `knx_plan_device` / `knx_apply_device` with `line`, issue #748);
//!   [`reconstruct_line`]: the line sweep that synthesizes a fresh model
//!   (`bussard reconstruct --line`, `knx_reconstruct_device` with `line`).
//! - [`files`]: importing and exporting model files outside the first setup
//!   (a re-import, bundles, product data, the keyring export, the group plan,
//!   the handover documentation), behind the CLI's `import`,
//!   `import-product`, `keys`, `export`, `export-groups` and `doc` and the
//!   MCP `knx_import_file` and `knx_export` (issues #743, #744).
//! - [`replace`]: the replace flow as a step machine (`bussard replace`,
//!   `knx_replace_device`, issue #751): the identity cross-check against the
//!   model, the assign steps, and the record of the hardware swap.
//! - [`restore`]: replaying a parameter backup (`bussard restore
//!   --parameters`, `knx_restore_parameters`, issue #290).
//! - [`setup`]: a model directory from nothing, the gateway, the skeleton
//!   and the import of an ETS export (`bussard init`, `knx_setup`, issue
//!   #745), and the product store and download step `import` shares.
//! - [`enroll_session`]: the certificate enrolment session (issue #729): the
//!   end-to-end encrypted relay protocol that carries a device certificate
//!   label from a phone into the key store.
//!
//! The crate never prints. Terminal prompts, JSON shapes and HTTP status codes
//! stay with the surfaces.

pub mod admission;
pub mod adopt;
pub mod assign;
pub mod audit;
pub mod backup;
pub mod bus;
pub mod commission;
pub mod declare;
pub mod describe;
pub mod download;
pub mod enroll;
pub mod enroll_session;
pub mod error;
pub mod facts;
pub mod files;
pub mod flash;
pub mod flash_flow;
pub mod group;
pub mod group_security;
/// The one wording per condition every surface reports (issue #228), from
/// the transport crate so the libraries below this one share it.
pub use bussard_transport::guidance;
pub mod identity;
pub mod ip_secure;
pub mod knxnet;
pub mod limit;
pub mod line;
pub mod model_handle;
pub mod params;
pub mod policy;
pub mod program;
pub mod property_plan;
pub mod reconstruct;
pub mod reconstruct_line;
pub mod replace;
pub mod restart;
pub mod restore;
pub mod scan;
pub mod secure;
pub mod security_change;
pub mod security_diag;
pub mod setup;
pub mod status;
pub mod util;
pub mod verify;
pub mod warm;
pub mod write;

pub use bus::{Authorize, BusService, L4Options, Management, SourcePolicy};
pub use enroll::{
    CertificateEnrolment, EnrolError, EnrolOutcome, EnrolStatus, RecordSerialsError, attach_serial,
    attach_serials, enroll_certificate, record_serials,
};
pub use error::ServiceError;
pub use facts::{
    Established, FactsCache, FactsSource, FactsWant, Identified, drift_refusal,
    establish_table_facts, identify, identity_line, seed_of,
};
pub use group::{
    GroupKeys, GroupRead, GroupSendError, SecureGroupError, SecuredSend, group_key_for,
};
pub use model_handle::{ModelHandle, complete_product_models};
pub use policy::WritePolicy;
pub use write::{
    DptOverridePolicy, PreparedWrite, WriteCheck, WriteOutcome, WriteRefusal, WriteValue,
    prepare_group_write, protected_group,
};
