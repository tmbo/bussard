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

/// `PID_OBJECT_TYPE` — the interface-object type (IOT) of an interface object.
///
/// This is a global (IOT-independent) property present on *every* interface
/// object (spec KNX v01.10.01 Resources 03.05.01; ref
/// `knx-device-spec-references.md` §4.2). It is `PDT_UNSIGNED_INT` (2 octets,
/// big-endian). A management tool probes `A_PropertyValue_Read(objIdx, PID 1)`
/// per object index to discover the device's interface-object table, so a
/// spec-correct device must answer it for each object it exposes.
pub const PID_OBJECT_TYPE: u8 = 1;
/// `PID_LOAD_STATE_CONTROL`.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;
/// `PID_TABLE_REFERENCE` — the segment base address of a table object.
pub const PID_TABLE_REFERENCE: u8 = 7;
/// `PID_TABLE` (23) — the global "loadable table as a property array" PID.
///
/// **Read-only on a real device.** A loadable table (group address, association,
/// group object) is realised in the object's allocated *segment*: a tool sizes
/// the segment with an `AdditionalLoadControls` / `LdCtrlRelSegment` write, reads
/// the placement from [`PID_TABLE_REFERENCE`], and streams the image (a
/// big-endian `u16` element count followed by the elements) with
/// `A_Memory_Write` / `A_MemoryExtended_Write`. Writing the table *through*
/// PID 23 is not a download path any real device implements — see
/// `Device::on_property_write`, which refuses it.
pub const PID_TABLE: u8 = 23;
/// `PID_MCB_TABLE` (27) — a loadable object's memory-control-block table. On
/// System B it is a device-computed, read-only array of 8-octet entries, each an
/// integrity block over a stored segment (size + a CRC the device computes). A
/// modern download's `LdCtrlLoadImageProp` step reads it back to verify the
/// written image.
pub const PID_MCB_TABLE: u8 = 27;
/// Run-state / app-id finalize property written near the end of a flash.
pub const PID_RUN_STATE_CONTROL: u8 = 0x0D;
/// `PID_PROGMODE` — the programming-mode flag on the device object.
pub const PID_PROGMODE: u8 = 0x36;

/// Interface-object type (IOT) codes — the value `PID_OBJECT_TYPE` reports.
///
/// From the KNX interface-object type enumeration (spec Resources 03.05.01; ref
/// `knx-device-spec-references.md` §4.1). Only the types a System B device
/// exposes on the flash path are named here.
pub mod iot {
    /// Device object.
    pub const DEVICE: u16 = 0;
    /// Address table object.
    pub const ADDRESS_TABLE: u16 = 1;
    /// Association table object.
    pub const ASSOCIATION_TABLE: u16 = 2;
    /// Application program object.
    pub const APPLICATION_PROGRAM: u16 = 3;
    /// Interface program object.
    pub const INTERFACE_PROGRAM: u16 = 4;
    /// KNX-object association table object.
    pub const KNX_OBJECT_ASSOCIATION_TABLE: u16 = 5;
    /// Group object (com-object) table object. On System B the loadable
    /// com-object table is a distinct interface object of this type (not the
    /// application-program object).
    pub const GROUP_OBJECT_TABLE: u16 = 9;
}

/// `PDT_GENERIC_01` — the generic 1-octet property data type. The simulator
/// reports this for every property it exposes: it stores each property as opaque
/// bytes (see the module docs), so it does not track the real KNX PDT per PID and
/// answers `A_PropertyDescription_Read` with a plausible generic type rather than
/// inventing a specific one. A tool that introspects the device sees the property
/// exists, its element count and access levels — the load-bearing facts — without
/// the sim overclaiming a precise data type it does not model.
pub const PDT_GENERIC_01: u8 = 0x10;

/// A property's on-the-wire *description* — what a device reports in an
/// `A_PropertyDescription_Response` (issue #72): the PID, its data type and
/// writability, its element count and its read/write access levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDescription {
    /// The property id (PID).
    pub pid: u8,
    /// The property data type (PDT) code.
    pub pdt: u8,
    /// Whether the property is writable.
    pub writable: bool,
    /// The maximum number of elements (array length).
    pub max_elements: u16,
    /// The access level required to read (0 = highest access).
    pub read_level: u8,
    /// The access level required to write (0 = highest access; 15 for a
    /// read-only property, which no access level can write).
    pub write_level: u8,
}

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

    /// The PIDs this object defines, in ascending (property-index) order.
    ///
    /// A management tool enumerates an object's properties with
    /// `A_PropertyDescription_Read` by walking the **property index** `1..N`; the
    /// simulator maps 1-based property index `i` to the `i`-th PID in this order.
    /// The device object 0's PID_OBJECT_TYPE (PID 1) sorts first, matching a real
    /// device's convention that the object-type property leads the list.
    pub fn pids(&self) -> Vec<u8> {
        self.properties.keys().copied().collect()
    }

    /// The description of the property at 1-based `property_index`, if any.
    ///
    /// Returns `None` once the index runs past the object's property list — the
    /// terminating signal an enumerating tool reads as `max_elements == 0`. The
    /// simulator reports every property as [`PDT_GENERIC_01`] with a single
    /// element (it stores opaque bytes, so it does not model per-PID arrays), a
    /// read level of 3 (the ETS free-access default), and a write level of 0 for a
    /// writable property or 15 for a read-only one.
    pub fn describe_at_index(&self, property_index: u8) -> Option<PropertyDescription> {
        if property_index == 0 {
            return None;
        }
        let pid = *self.pids().get(usize::from(property_index - 1))?;
        let prop = self.property(pid)?;
        Some(PropertyDescription {
            pid,
            pdt: PDT_GENERIC_01,
            writable: !prop.read_only,
            max_elements: 1,
            read_level: 3,
            write_level: if prop.read_only { 15 } else { 0 },
        })
    }

    /// The description of a specific PID, if this object defines it. Used to
    /// answer an `A_PropertyDescription_Read` addressed by PID rather than index.
    pub fn describe_pid(&self, pid: u8) -> Option<PropertyDescription> {
        let index = self.pids().iter().position(|&p| p == pid)? as u8;
        self.describe_at_index(index + 1)
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

    #[test]
    fn test_describe_at_index_walks_pids_in_order_and_terminates() {
        let mut obj = InterfaceObject::new();
        // PID map is BTreeMap-ordered, so index 1 → PID 1, index 2 → PID 5.
        obj.set_property(PID_OBJECT_TYPE, Property::read_only(vec![0x00, 0x00]));
        obj.set_property(PID_LOAD_STATE_CONTROL, Property::writable(vec![0x00]));

        let d1 = obj.describe_at_index(1).expect("index 1 present");
        assert_eq!(d1.pid, PID_OBJECT_TYPE);
        assert_eq!(d1.pdt, PDT_GENERIC_01);
        assert!(!d1.writable);
        assert_eq!(d1.max_elements, 1);
        assert_eq!(d1.read_level, 3);
        assert_eq!(d1.write_level, 15, "read-only → unwritable level 15");

        let d2 = obj.describe_at_index(2).expect("index 2 present");
        assert_eq!(d2.pid, PID_LOAD_STATE_CONTROL);
        assert!(d2.writable);
        assert_eq!(d2.write_level, 0, "writable → write level 0");

        // Past the end terminates; index 0 is invalid.
        assert!(obj.describe_at_index(3).is_none());
        assert!(obj.describe_at_index(0).is_none());
    }

    #[test]
    fn test_describe_pid_reports_index() {
        let mut obj = InterfaceObject::new();
        obj.set_property(PID_OBJECT_TYPE, Property::read_only(vec![0x00, 0x00]));
        obj.set_property(PID_PROGMODE, Property::writable(vec![0x00]));
        // PID_PROGMODE (0x36) sorts after PID_OBJECT_TYPE (1), so it is index 2.
        let d = obj.describe_pid(PID_PROGMODE).expect("PID present");
        assert_eq!(d.pid, PID_PROGMODE);
        assert!(d.writable);
        assert!(obj.describe_pid(0x99).is_none(), "unknown PID → None");
    }
}
