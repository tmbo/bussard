//! Independent KNXnet/IP + cEMI + management-APDU codec.
//!
//! This module is a clean-room encoder/decoder for the KNX wire formats needed
//! to present a tunnelling gateway and speak the device-management protocol. It
//! is built from the published KNX specs, the Wireshark KNX dissector, and real
//! ETS captures — it shares no code with the tool under test.

pub mod address;
pub mod apdu;
pub mod cemi;
pub mod dpt;
pub mod knxnetip;

pub use address::{GroupAddress, IndividualAddress};
pub use apdu::{Apci, Apdu, Tpci};
pub use cemi::{CemiError, CemiLData, MessageCode};
pub use knxnetip::{ConnectionHeader, FrameError, KnxnetIpFrame};
