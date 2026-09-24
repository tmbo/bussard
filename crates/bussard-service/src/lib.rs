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
//! - [`ModelHandle`]: a shared model that reloads itself when the files on disk
//!   change, used by the long-lived MCP and viz servers.
//! - [`describe`]: the interface-object walk and the PID / object-type name
//!   tables shared by `bussard describe` and `knx_describe_device`.
//!
//! The crate never prints. Terminal prompts, JSON shapes and HTTP status codes
//! stay with the surfaces.

pub mod bus;
pub mod describe;
pub mod error;
pub mod model_handle;
pub mod policy;
pub mod secure;
pub mod write;

pub use bus::{Authorize, BusService, L4Options, Management, SourcePolicy};
pub use error::ServiceError;
pub use model_handle::ModelHandle;
pub use policy::WritePolicy;
pub use write::{
    DptOverridePolicy, PreparedWrite, WriteCheck, WriteOutcome, WriteRefusal, WriteValue,
    prepare_group_write, protected_group,
};
