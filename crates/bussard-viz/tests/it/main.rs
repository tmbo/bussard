//! The integration tests of `bussard-viz`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod browser_smoke;
mod enroll_e2e;
mod enroll_relay_cases;
mod fixture_model;
mod http_server;
