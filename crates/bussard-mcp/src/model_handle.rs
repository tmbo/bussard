//! The self-refreshing model handle, shared with the viz server.
//!
//! The implementation lives in [`bussard_service::model_handle`] (issue #86);
//! this module re-exports it under the path the MCP server and its tests use.

pub use bussard_service::model_handle::{ModelHandle, RECHECK_INTERVAL};
