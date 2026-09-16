//! Interface objects and their properties.
//!
//! A KNX device exposes its configuration through *interface objects*, each a
//! numbered collection of *properties* addressed by Property ID (PID). Device
//! management reads and writes these with `A_PropertyValue_Read/Write`.
//!
//! Property IDs used by the flash flow (System B):
//!
//! ```text
//!   PID 5   (0x05)  PID_LOAD_STATE_CONTROL   load-state machine control
//!   PID 7   (0x07)  PID_TABLE_REFERENCE      segment base address (read-only)
//!   PID 13  (0x0D)  PID_MCB_TABLE / run-state control (app-id finalize write)
//!   PID 14  (0x0E)  PID_ERROR_CODE
//!   PID 11  (0x0B)  PID_PEI_TYPE / hardware id family (device object)
//!   PID 12  (0x0C)  PID_MANUFACTURER_ID
//!   PID 25  (0x19)  PID_?  (device descriptor family)
//!   PID 54  (0x36)  PID_PROGMODE             programming-mode flag
//!   PID 15  (0x0F)  PID_SERIAL / order id text
//!   PID 78  (0x4E)  PID_?
//!   PID 56  (0x38)  PID_?  (device object identity read at connect)
//! ```
//!
//! The property model here is deliberately small: each property is a raw byte
//! vector with a read-only flag. The device layer maps management verbs onto it
//! and enforces access rules. The exact PID semantics beyond the load flow are
//! not needed to cross-check a flash and are represented as opaque bytes seeded
//! to match the captured device.

use std::collections::BTreeMap;

/// `PID_LOAD_STATE_CONTROL`.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;
/// `PID_TABLE_REFERENCE` — the segment base address of a table object.
pub const PID_TABLE_REFERENCE: u8 = 7;
/// Run-state / app-id finalize property written near the end of a flash.
pub const PID_RUN_STATE_CONTROL: u8 = 0x0D;
/// `PID_PROGMODE` — the programming-mode flag on the device object.
pub const PID_PROGMODE: u8 = 0x36;

/// One property: raw value bytes plus a read-only flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// The property value bytes.
    pub value: Vec<u8>,
    /// Whether writes are rejected.
    pub read_only: bool,
}

impl Property {
    /// A writable property with an initial value.
    pub fn writable(value: Vec<u8>) -> Self {
        Self {
            value,
            read_only: false,
        }
    }

    /// A read-only property with a fixed value.
    pub fn read_only(value: Vec<u8>) -> Self {
        Self {
            value,
            read_only: true,
        }
    }
}

/// A single interface object: a bag of properties keyed by PID.
#[derive(Debug, Clone, Default)]
pub struct InterfaceObject {
    properties: BTreeMap<u8, Property>,
}

impl InterfaceObject {
    /// Create an empty interface object.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a property.
    pub fn set_property(&mut self, pid: u8, prop: Property) {
        self.properties.insert(pid, prop);
    }

    /// Get a property by PID.
    pub fn property(&self, pid: u8) -> Option<&Property> {
        self.properties.get(&pid)
    }

    /// Get a mutable property by PID.
    pub fn property_mut(&mut self, pid: u8) -> Option<&mut Property> {
        self.properties.get_mut(&pid)
    }

    /// Whether this object defines the given PID.
    pub fn has_property(&self, pid: u8) -> bool {
        self.properties.contains_key(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_access() {
        let mut obj = InterfaceObject::new();
        obj.set_property(
            PID_TABLE_REFERENCE,
            Property::read_only(vec![0x00, 0x00, 0x60, 0x00]),
        );
        assert!(obj.has_property(PID_TABLE_REFERENCE));
        assert_eq!(
            obj.property(PID_TABLE_REFERENCE).map(|p| p.value.clone()),
            Some(vec![0x00, 0x00, 0x60, 0x00])
        );
        assert!(
            obj.property(PID_TABLE_REFERENCE)
                .map(|p| p.read_only)
                .unwrap_or(false)
        );
    }
}
