//! The integration tests of `bussard-mcp`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod capabilities;
mod diff_tools;
mod file_tools;
mod guidance;
mod mcp_add_device;
mod mcp_audit;
mod mcp_bus;
mod mcp_commission;
mod mcp_discard_edits;
mod mcp_discard_keys;
mod mcp_enroll;
mod mcp_flash;
mod mcp_flash_sys7;
mod mcp_groups;
mod mcp_ha;
mod mcp_ha_automation;
mod mcp_http;
mod mcp_interface;
mod mcp_learn;
mod mcp_password_form;
mod mcp_program;
mod mcp_replace;
mod mcp_safety_net;
mod mcp_server;
mod model_edit_tools;
mod model_lookup_texts;
mod tools_and_limiter_stress;
