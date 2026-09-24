//! Device introspection shared by `bussard describe` and the MCP
//! `knx_describe_device` tool (issue #72): the interface-object walk and the
//! human names for object types and property ids.
//!
//! Read-only on the bus: [`walk_objects`] sends `A_PropertyValue_Read` (object
//! discovery) and `A_PropertyDescription_Read` only.

use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE, discover_interface_objects,
};
use bussard_mgmt::{L4Channel, Layer4Connection, MgmtError, PropertyDesc, apci};

/// One interface object and its enumerated property descriptions.
#[derive(Debug, Clone)]
pub struct ObjectDescription {
    /// The interface-object index.
    pub index: u8,
    /// The interface-object type (IOT) code.
    pub object_type: u16,
    /// The object's property descriptions, in index order.
    pub properties: Vec<PropertyDesc>,
}

/// Why the walk failed.
#[derive(Debug, thiserror::Error)]
pub enum DescribeError {
    /// Discovering the interface objects failed.
    #[error("discovering interface objects")]
    Discover(#[source] bussard_mgmt::tables::TablesError),
    /// Enumerating one object's properties failed.
    #[error("enumerating properties of object {index}")]
    Enumerate {
        /// The object index.
        index: u8,
        /// The management error.
        #[source]
        source: MgmtError,
    },
}

/// Discovers a device's interface objects and enumerates each one's property
/// descriptions over an open management session.
///
/// Call [`Layer4Connection::negotiate_max_apdu`] first (best-effort) so the
/// property reads scale to the device's maximum APDU. An empty result after a successful descriptor read usually
/// means a KNX Data Secure device refused the plain walk (issue #155); the
/// caller decides how to report that.
///
/// # Errors
///
/// The first discovery or enumeration failure.
pub async fn walk_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<ObjectDescription>, DescribeError> {
    let objects = discover_interface_objects(l4)
        .await
        .map_err(DescribeError::Discover)?;
    let mut out = Vec::with_capacity(objects.len());
    for (index, object_type) in objects {
        let properties = bussard_mgmt::describe_object_properties(l4, index)
            .await
            .map_err(|source| DescribeError::Enumerate { index, source })?;
        out.push(ObjectDescription {
            index,
            object_type,
            properties,
        });
    }
    Ok(out)
}

/// A human name for a well-known standardised interface-object type
/// (KNX 3/5/1), or `"?"`.
pub fn object_type_name(object_type: u16) -> &'static str {
    match object_type {
        OT_DEVICE => "device",
        OT_ADDRESS_TABLE => "address table",
        OT_ASSOCIATION_TABLE => "association table",
        OT_APPLICATION_PROGRAM => "application program",
        OT_GROUP_OBJECT_TABLE => "group object table",
        _ => "?",
    }
}

/// A human name for a well-known standardised PID (KNX 3/5/1 global properties
/// and the common device-object PIDs bussard already knows), or `"?"`. Only the
/// PIDs bussard names elsewhere are covered; an unknown PID is honestly `"?"`.
pub fn pid_name(pid: u8) -> &'static str {
    match pid {
        1 => "PID_OBJECT_TYPE",
        5 => "PID_LOAD_STATE_CONTROL",
        7 => "PID_TABLE_REFERENCE",
        apci::PID_SERIAL_NUMBER => "PID_SERIAL_NUMBER",
        apci::PID_MANUFACTURER_ID => "PID_MANUFACTURER_ID",
        apci::PID_ORDER_INFO => "PID_ORDER_INFO",
        23 => "PID_TABLE",
        27 => "PID_MCB_TABLE",
        apci::PID_PROGMODE => "PID_PROGMODE",
        apci::PID_MAX_APDU_LENGTH => "PID_MAX_APDU_LENGTH",
        apci::PID_HARDWARE_TYPE => "PID_HARDWARE_TYPE",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_name_known_and_unknown() {
        assert_eq!(pid_name(1), "PID_OBJECT_TYPE");
        assert_eq!(pid_name(11), "PID_SERIAL_NUMBER");
        assert_eq!(pid_name(12), "PID_MANUFACTURER_ID");
        assert_eq!(pid_name(15), "PID_ORDER_INFO");
        assert_eq!(pid_name(54), "PID_PROGMODE");
        assert_eq!(pid_name(56), "PID_MAX_APDU_LENGTH");
        assert_eq!(pid_name(78), "PID_HARDWARE_TYPE");
        assert_eq!(pid_name(200), "?");
    }

    #[test]
    fn test_object_type_name_known_and_unknown() {
        assert_eq!(object_type_name(0), "device");
        assert_eq!(object_type_name(9), "group object table");
        assert_eq!(object_type_name(42), "?");
    }
}
