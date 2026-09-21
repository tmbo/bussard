//! `knx-sim` — an independent, strict KNX device + bus simulator.
//!
//! This crate recreates the KNX *device* side in software so a flashing /
//! monitoring tool can be exercised against realistic devices without hardware.
//! It is an independent second implementation of the KNX device-management
//! protocol: it shares no code with the tool under test, so a shared
//! misconception cannot hide in both. See `DESIGN.md` for the architecture.
//!
//! Layers:
//! - [`wire`] — independent KNXnet/IP + cEMI + management-APDU codec.
//! - [`prod`] — independent `.knxprod` reader (flash-relevant subset).
//! - [`device`] — one strict System-B device.
//! - [`bus`] — the virtual bus + observable event stream.
//! - [`net`] — the KNXnet/IP tunnelling server frontend.
//! - [`config`] — file-driven installation config.

#![forbid(unsafe_code)]
// Every public item carries a doc comment; the crate-level `[lints]` table in
// Cargo.toml warns on a missing one, and CI's `-D warnings` makes it fail.
#![warn(missing_docs)]

pub mod bus;
pub mod config;
pub mod device;
pub mod net;
pub mod prod;
pub mod run;
pub mod secure;
pub mod testfixtures;
pub mod wire;
