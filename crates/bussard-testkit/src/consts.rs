//! KNX wire constants the mocks speak, taken from the KNX specification.
//!
//! They are declared here rather than imported from `bussard-mgmt`. That keeps
//! the testkit free of a dependency on the management layer it tests, and a
//! wrong constant in the code under test cannot hide in the mock.

/// `A_IndividualAddress_Write` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_WRITE: u16 = 0x0C0;
/// `A_IndividualAddress_Read` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_READ: u16 = 0x100;
/// `A_IndividualAddress_Response` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_RESPONSE: u16 = 0x140;
/// `A_MemoryExtended_Write`.
pub const A_MEMORY_EXTENDED_WRITE: u16 = 0x1FB;
/// `A_MemoryExtended_WriteResponse`.
pub const A_MEMORY_EXTENDED_WRITE_RESPONSE: u16 = 0x1FC;
/// `A_MemoryExtended_Read`.
pub const A_MEMORY_EXTENDED_READ: u16 = 0x1FD;
/// `A_MemoryExtended_ReadResponse`.
pub const A_MEMORY_EXTENDED_READ_RESPONSE: u16 = 0x1FE;
/// `A_Memory_Read` (the low 6 bits carry the octet count).
pub const A_MEMORY_READ: u16 = 0x200;
/// `A_Memory_Response` (the low 6 bits carry the octet count).
pub const A_MEMORY_RESPONSE: u16 = 0x240;
/// `A_Memory_Write` (the low 6 bits carry the octet count).
pub const A_MEMORY_WRITE: u16 = 0x280;
/// `A_DeviceDescriptor_Read` (the low 6 bits carry the descriptor type).
pub const A_DEVICE_DESCRIPTOR_READ: u16 = 0x300;
/// `A_DeviceDescriptor_Response`.
pub const A_DEVICE_DESCRIPTOR_RESPONSE: u16 = 0x340;
/// `A_Restart` (basic restart, no response).
pub const A_RESTART: u16 = 0x380;
/// `A_Authorize_Request`.
pub const A_AUTHORIZE_REQUEST: u16 = 0x3D1;
/// `A_Authorize_Response`.
pub const A_AUTHORIZE_RESPONSE: u16 = 0x3D2;
/// `A_PropertyValue_Read`.
pub const A_PROPERTY_VALUE_READ: u16 = 0x3D5;
/// `A_PropertyValue_Response`.
pub const A_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
/// `A_PropertyValue_Write`.
pub const A_PROPERTY_VALUE_WRITE: u16 = 0x3D7;
/// `A_PropertyDescription_Read`.
pub const A_PROPERTY_DESCRIPTION_READ: u16 = 0x3D8;
/// `A_PropertyDescription_Response`.
pub const A_PROPERTY_DESCRIPTION_RESPONSE: u16 = 0x3D9;
/// `A_IndividualAddressSerialNumber_Read` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_SERIAL_READ: u16 = 0x3DC;
/// `A_IndividualAddressSerialNumber_Response` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE: u16 = 0x3DD;
/// `A_IndividualAddressSerialNumber_Write` (broadcast).
pub const A_INDIVIDUAL_ADDRESS_SERIAL_WRITE: u16 = 0x3DE;
/// Mask selecting the 4-bit APCI service of the services whose low 6 bits carry
/// data (memory, device descriptor).
pub const APCI_SELECTOR: u16 = 0x3C0;

/// `PID_OBJECT_TYPE`.
pub const PID_OBJECT_TYPE: u8 = 1;
/// `PID_LOAD_STATE_CONTROL`.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;
/// `PID_TABLE_REFERENCE`.
pub const PID_TABLE_REFERENCE: u8 = 7;
/// `PID_SERIAL_NUMBER`.
pub const PID_SERIAL_NUMBER: u8 = 11;
/// `PID_MANUFACTURER_ID`.
pub const PID_MANUFACTURER_ID: u8 = 12;
/// `PID_PROGRAM_VERSION`.
pub const PID_PROGRAM_VERSION: u8 = 13;
/// `PID_ORDER_INFO`.
pub const PID_ORDER_INFO: u8 = 15;
/// `PID_TABLE`.
pub const PID_TABLE: u8 = 23;
/// `PID_PROGMODE`.
pub const PID_PROGMODE: u8 = 54;
/// `PID_MAX_APDU_LENGTH`.
pub const PID_MAX_APDU_LENGTH: u8 = 56;

/// Interface object type: device object.
pub const OT_DEVICE: u16 = 0;
/// Interface object type: group address table.
pub const OT_ADDRESS_TABLE: u16 = 1;
/// Interface object type: group object association table.
pub const OT_ASSOCIATION_TABLE: u16 = 2;
/// Interface object type: application program.
pub const OT_APPLICATION_PROGRAM: u16 = 3;
/// Interface object type: group object table.
pub const OT_GROUP_OBJECT_TABLE: u16 = 9;

/// Load state `Unloaded`.
pub const LS_UNLOADED: u8 = 0;
/// Load state `Loaded`.
pub const LS_LOADED: u8 = 1;
/// Load state `Loading`.
pub const LS_LOADING: u8 = 2;
/// Load event `StartLoading`.
pub const LE_START_LOADING: u8 = 1;
/// Load event `LoadCompleted`.
pub const LE_LOAD_COMPLETED: u8 = 2;
/// Load event `AdditionalLoadControls`.
pub const LE_ADDITIONAL: u8 = 3;
/// Load event `Unload`.
pub const LE_UNLOAD: u8 = 4;
/// `AdditionalLoadControls` subtype `LdCtrlRelSegment`.
pub const SUB_REL_SEGMENT: u8 = 0x0B;

/// The tunnel individual address every mock CONNECT_RESPONSE hands out (1.1.255).
pub const TUNNEL_IA_RAW: u16 = 0x11FF;
