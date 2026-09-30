//! Building the [`bussard_download::DevicePlan`] `plan` and `apply` print, from
//! what one read of the device returned: its live tables and, when product
//! data is at hand, its parameter memory.
//!
//! The builder lives in [`bussard_service::params::build_device_plan`], shared
//! with the MCP programming tier (issue #274).

pub(crate) use bussard_service::params::build_device_plan as build;
