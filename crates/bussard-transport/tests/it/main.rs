//! The integration tests of `bussard-transport`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod bus_actor;
mod bus_secure_reconnect;
mod codec_fuzz;
mod device_mgmt;
mod mock_gateway;
mod secure_tunnel;
mod wire_trace_off;
