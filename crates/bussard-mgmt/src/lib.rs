//! KNX layer-4 device management: connection-oriented transport, device
//! descriptor, property and memory access.
//!
//! This crate sits above [`bussard_transport`] and speaks the KNX
//! connection-oriented management protocol to individual devices: it opens a
//! `T_Connect` session, exchanges numbered data telegrams with `T_ACK`
//! acknowledgement (the "style-1 rationalised" state machine), and exposes typed
//! procedures — device descriptor (mask version), property reads (manufacturer,
//! serial, order info), memory reads and restart. A connectionless broadcast
//! helper reports which devices are in programming mode.
//!
//! It is written from scratch under the crate's MIT license from the published
//! KNX transport- and application-layer specification structure (EN 50090 / the
//! KNX standard), with thelsing/knx (C++, device side) as a behavioural
//! reference for what the peer expects. No GPL KNX stacks were used.
//!
//! # The two failure modes that matter
//!
//! Every procedure distinguishes a device that is **absent** (no reaction —
//! [`MgmtError::NoResponse`]) from one that is **present but refusing** (a NAK,
//! disconnect, or malformed answer). `bussard scan` relies on this to tell an
//! unused address apart from a device it could not fully read.
//!
//! # Example
//!
//! ```no_run
//! use bussard_mgmt::DeviceConnection;
//! use bussard_transport::{ConnectionConfig, Transport};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // Open a bus session (a tunnel to a gateway).
//! let gateway = "192.168.1.10:3671".parse().unwrap();
//! let config = ConnectionConfig::tunnel(gateway);
//! let mut bus = Transport::connect(&config).await?;
//!
//! // Connect to device 1.1.4 and read its mask version.
//! let target = "1.1.4".parse().unwrap();
//! let source = "0.0.255".parse().unwrap();
//! let mut device = DeviceConnection::connect(&mut bus, target, source).await?;
//! let mask = device.device_descriptor().await?;
//! println!("mask version: {mask:#06x} ({})", bussard_mgmt::system_type(mask));
//! device.disconnect().await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod apci;
pub mod broadcast;
pub mod connection;
pub mod device;
pub mod error;
pub mod load;
pub mod manufacturers;
pub mod tables;

pub use broadcast::{
    devices_in_programming_mode, devices_in_programming_mode_within,
    read_individual_address_by_serial, read_individual_address_by_serial_within,
    write_individual_address, write_individual_address_by_serial,
};
pub use connection::{L4Channel, Layer4Connection, LeaseChannel, Timeouts};
pub use device::DeviceConnection;
pub use error::{MgmtError, Result, SilenceKind};
pub use load::{
    LD_CTRL_ABS_SEGMENT, LD_CTRL_REL_SEGMENT, LoadControl, LoadState, LoadStateContext,
    MCB_ENTRY_LEN, McbEntry, PID_LOAD_STATE_CONTROL, PID_MCB_TABLE, SegmentAllocation, VerifyMode,
    WriteError, allocate_segment, compare_property, crc16_ccitt, encode_abs_segment,
    encode_rel_segment, mcb_entry, read_load_state, read_mcb_table, read_memory,
    write_load_control, write_memory, write_memory_verified, write_property, write_table,
};
pub use tables::{DeviceTables, ResolvedLink, TableSource, TablesError, read_tables};

/// Whether a mask version belongs to the System B family (`x7B0`).
///
/// The medium lives in the high bits (07 = TP1, 27 = RF, 57 = KNX-IP) while
/// the management stack - interface objects, loadable tables, property
/// access - is shared. bussard's table read/write path applies to the whole
/// family (established against thelsing's BauSystemB, which serves the same
/// stack under 07B0 and 57B0).
pub fn is_system_b(mask: u16) -> bool {
    mask & 0x0FFF == 0x07B0
}

/// Maps a device descriptor mask version to a human-readable KNX system type.
///
/// The mask version reported by `A_DeviceDescriptor_Read` classifies the device
/// medium and system generation, which in turn decides whether links are written
/// via interface-object **properties** (System B) or raw **memory** (older
/// systems). Common masks:
///
/// - `0x07B0` / `0x57B0` / `0x27B0` → System B (TP1 / KNX-IP / RF)
/// - `0x0705`, `0x0701` → System 7
/// - `0x0300`, `0x0310`, `0x0311` → System 2
/// - `0x0010`–`0x0013`, `0x0020`/`0x0021`/`0x0025` → System 1 (BCU1 family)
///
/// The `0x002x` masks are the BCU1-family realisation type reported by some IP
/// interfaces; a live scan found a Jung IP interface reporting `0021` (issue
/// #30). Unknown masks return `"System ?"`.
pub fn system_type(mask: u16) -> &'static str {
    match mask {
        0x07B0 => "System B",
        0x57B0 => "System B (IP)",
        0x27B0 => "System B (RF)",
        0x0705 | 0x0701 | 0x0700 => "System 7",
        0x0300 | 0x0310 | 0x0311 => "System 2",
        // System 1 / BCU1 family: the classic 0x001x masks plus the 0x002x
        // realisation type reported by BCU1-based IP interfaces (a live scan
        // found a Jung IP interface reporting 0021 — issue #30).
        0x0010..=0x0013 | 0x0020 | 0x0021 | 0x0025 => "System 1",
        _ => "System ?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_type_classifies_common_masks() {
        assert_eq!(system_type(0x07B0), "System B");
        assert_eq!(system_type(0x0705), "System 7");
        assert_eq!(system_type(0x0012), "System 1");
        // BCU1-family realisation type reported by a Jung IP interface (#30).
        assert_eq!(system_type(0x0021), "System 1");
        assert_eq!(system_type(0x0020), "System 1");
        assert_eq!(system_type(0x0025), "System 1");
        assert_eq!(system_type(0x0300), "System 2");
        assert_eq!(system_type(0x1234), "System ?");
    }
}
