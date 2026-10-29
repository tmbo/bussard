//! The integration tests of `bussard-mgmt`, linked as one binary.
//!
//! Each module is a former `tests/<module>.rs` file. One binary instead of
//! one per file saves a link against the full dependency graph per file;
//! nextest still runs every test in its own process.

mod al_negative_mock;
mod assign_mock;
mod io_list_mock;
mod knxnet_mock;
mod load_echo_mock;
mod max_apdu_mock;
mod mem_write_mock;
mod mock_device;
mod property_ext_mock;
mod tables_memory_mock;
mod tables_mock;
mod tl_style3_mock;
