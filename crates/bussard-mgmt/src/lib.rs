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
//! KNX standard 3/3/x and 3/5/x), the Wireshark KNXnet/IP dissector's public
//! field definitions, and behaviour verified live against real devices (see the
//! module-level notes for the specific captures). No GPL KNX source was consulted
//! or copied.
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
//! let gateway = "192.0.2.10:3671".parse().unwrap();
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
pub mod memory;
pub mod probe;
pub mod profile;
pub mod secure;
pub mod sys7;
pub mod tables;

pub use broadcast::{
    devices_in_programming_mode, devices_in_programming_mode_within,
    read_individual_address_by_serial, read_individual_address_by_serial_within,
    write_individual_address, write_individual_address_by_serial,
};
pub use connection::{
    AuthorizeOutcome, L4Channel, Layer4Connection, LeaseChannel, MAX_OBJECT_INDEX, PID_OBJECT_TYPE,
    PROBE_TIMEOUT, PropertyDesc, Timeouts, describe_object_properties, probe_object_type,
    probe_object_types, read_device_descriptor,
};
pub use device::DeviceConnection;
pub use error::{MgmtError, Result, SilenceKind};
pub use load::{
    LD_CTRL_REL_SEGMENT, LoadControl, LoadState, LoadStateContext, MAX_RESTART_PROCESS_WAIT,
    MCB_ENTRY_LEN, McbEntry, PID_LOAD_STATE_CONTROL, PID_MCB_TABLE, PID_PROGRAM_VERSION,
    SegmentAllocation, WriteError, allocate_segment, compare_property, compare_rel_mem,
    crc16_ccitt, encode_rel_segment, is_connection_death, master_reset, mcb_entry, read_load_state,
    read_mcb_table, read_program_version, read_table_reference, restart_process_wait,
    write_load_control, write_property, write_table,
};
// The memory primitives moved out of `load` into their own module (issue #80);
// every historical `bussard_mgmt::…` and `bussard_mgmt::load::…` path still
// resolves, so no caller had to change.
pub use memory::{
    read_memory, read_memory_range, select_extended_memory, write_memory, write_memory_chunked,
    write_memory_verified,
};
pub use probe::{AddressProbe, probe_own_address, probe_own_address_on};
pub use profile::{
    KnxMedium, LsmRealisation, MaskCapabilities, MaskFamily, MaskProfile, Sys7Profile,
    capability_table,
};
pub use secure::SecureLayer;
pub use sys7::{
    LsmAccess, alloc_attr_octets, encode_alloc_segment, encode_task_ctrl1, encode_task_segment,
    lsm_access_from_profile, task_segment_marker,
};
pub use tables::{
    DeviceTables, ResolvedLink, TableSource, TablesError, discover_interface_objects, read_tables,
};

/// Whether a mask version belongs to the System B family (`x7B0`).
///
/// The medium lives in the high bits (07 = TP1, 27 = RF, 57 = KNX-IP) while
/// the management stack - interface objects, loadable tables, property
/// access - is shared (KNX standard 3/5/1, "System B" profile). bussard's table
/// read/write path applies to the whole family: the same interface-object and
/// loadable-table stack is defined for 07B0 and 57B0 alike.
///
/// This is a thin wrapper over [`MaskProfile::is_system_b`]; the profile is the
/// canonical seam for mask-version-specific behaviour and new code should prefer
/// it (see [`profile`]).
pub fn is_system_b(mask: u16) -> bool {
    MaskProfile::from_mask(mask).is_system_b()
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
///
/// The classification is delegated to [`MaskProfile`]; this wrapper only adds
/// the medium suffix on System B masks (`"System B (IP)"` / `"System B (RF)"`)
/// that some callers print. New code should prefer [`MaskProfile`] and format
/// the medium via [`KnxMedium::label`] as needed.
pub fn system_type(mask: u16) -> &'static str {
    // Preserve the medium-annotated System B labels this function historically
    // returned; every other family comes straight from the profile.
    match mask {
        0x57B0 => "System B (IP)",
        0x27B0 => "System B (RF)",
        _ => MaskProfile::from_mask(mask).system_type(),
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
