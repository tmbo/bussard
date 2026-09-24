//! The KNX Data Secure **security interface object** (interface object type
//! 17, instance 1) served through the extended property services.
//!
//! A security-activated device keeps its Data Secure configuration in this
//! object: the group key table (PID 53), the security individual address table
//! (PID 54), the tool key (PID 56), the sending sequence number (PID 59) and the
//! group-object security flags (PID 61). ETS loads it with the same load-state
//! machine as any table (PID 5, driven by `A_FunctionPropertyExt_Command`), and
//! writes the tables with `A_PropertyExtValue_WriteCon` while the object is
//! `Loading`.
//!
//! The wire layout is the one a real Jung Data Secure device answered ETS with
//! in a decrypted capture. Every extended service starts with the 5-octet
//! header `[object_type:16][instance:12 | pid:12]`:
//!
//! ```text
//! 0x1D4 FunctionPropertyExt_Command        header data
//! 0x1D5 FunctionPropertyExt_State_Read     header data
//! 0x1D6 FunctionPropertyExt_State_Response header rc data
//! 0x1CC PropertyExtValue_Read              header count start:16
//! 0x1CD PropertyExtValue_Response          header count start:16 data
//! 0x1CE PropertyExtValue_WriteCon          header count start:16 data
//! 0x1CF PropertyExtValue_WriteConResponse  header count start:16 rc
//! 0x1D2 PropertyExtDescription_Read        header [desc_type:4 | index:12]
//! 0x1D3 PropertyExtDescription_Response    header index:16 dpt_main:16 dpt_sub:16
//!                                          [write:1 | pdt:6] max:16 access
//! ```
//!
//! The checks the object applies are plausible device behaviour, not a copy of
//! vendor firmware. Each one is documented where it is made, together with the
//! return code it answers. The object never exposes key bytes: key tables are
//! write-only, and the event summaries ([`ExtReply::summary`]) carry only the
//! service, PID, start, count, return code and load state.
//!
//! Layout: this module holds the wire types, the object state and the service
//! dispatch ([`SecurityObject::handle`]). The per-concern handlers live in
//! `function` (PID 5 load-state machine, PID 51 security mode), `values`
//! (PID 53/54/56/59/61 reads and writes), `description` (the property list)
//! and `admission` (group-key and sender lookups for the secured group path).

mod admission;
mod description;
mod function;
#[cfg(test)]
mod test_support;
mod values;

use crate::wire::apdu::Apci;

/// Interface object type of the security object (KNX IOT 17).
pub const IOT_SECURITY: u16 = 0x0011;

/// The only instance of the security object a device carries.
pub const SECURITY_OBJECT_INSTANCE: u16 = 1;

/// Property ids of the security object that the simulator models.
pub mod pid {
    /// `PID_OBJECT_TYPE`: the interface object type (2 octets, read-only).
    pub const OBJECT_TYPE: u16 = 1;
    /// `PID_LOAD_STATE_CONTROL`: the object's load-state machine.
    pub const LOAD_STATE_CONTROL: u16 = 5;
    /// `PID_SECURITY_MODE`: a function property switching Data Secure on/off.
    pub const SECURITY_MODE: u16 = 51;
    /// `PID_GRP_KEY_TABLE`: 18-octet rows `[address-table index:16][key:16]`.
    pub const GRP_KEY_TABLE: u16 = 53;
    /// `PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE`: 8-octet rows `[IA:16][seq:48]`.
    pub const SECURITY_IA_TABLE: u16 = 54;
    /// `PID_TOOL_KEY`: the 16-octet tool key (write-only).
    pub const TOOL_KEY: u16 = 56;
    /// `PID_SEQUENCE_NUMBER_SENDING`: the device's 6-octet sending sequence.
    pub const SEQUENCE_NUMBER_SENDING: u16 = 59;
    /// `PID_GO_SECURITY_FLAGS`: one octet per group object (element n = GO n).
    pub const GO_SECURITY_FLAGS: u16 = 61;
}

/// Return codes the object answers with (KNX application-layer return codes).
pub mod rc {
    /// The request was carried out.
    pub const SUCCESS: u8 = 0x00;
    /// The request is malformed for this property: wrong data length, a count
    /// of zero, an unknown load event, or a value write to a function property.
    pub const INVALID_COMMAND: u8 = 0xF2;
    /// The request is well formed but the state machine does not allow it
    /// (`LoadCompleted` while not `Loading`).
    pub const IMPOSSIBLE_COMMAND: u8 = 0xF3;
    /// A value is below its range (a group key row naming address-table index 0).
    pub const OUT_OF_MIN_RANGE: u8 = 0xF6;
    /// A value or element index is above its range (beyond the group-object
    /// count, beyond the address-table length, a flag octet above 0x03, a write
    /// that would leave a hole, or a table larger than the device holds).
    pub const OUT_OF_MAX_RANGE: u8 = 0xF7;
    /// A table write while the security object is not `Loading`.
    pub const TEMPORARILY_NOT_AVAILABLE: u8 = 0xF9;
    /// A write to a read-only property.
    pub const ACCESS_READ_ONLY: u8 = 0xFB;
    /// An unknown object type, instance or property id.
    pub const ADDRESS_VOID: u8 = 0xFD;
}

/// The group-object cap used when the device cannot derive its group-object
/// count (no loaded group-object table). 4095 is the largest element count a
/// 12-bit `max_elements` field can describe.
pub const FALLBACK_MAX_GROUP_OBJECTS: u16 = 4095;

/// Capacity of the group key table (rows). A plausible device limit; the real
/// Jung device's capacity is not captured.
pub const MAX_GROUP_KEY_ROWS: u16 = 1024;

/// Capacity of the security individual address table (rows). A plausible device
/// limit; the real device's capacity is not captured.
pub const MAX_IA_TABLE_ROWS: u16 = 64;

/// Size of one group key table row: address-table index (2) + key (16).
const GRP_KEY_ROW: usize = 18;
/// Size of one security IA table row: IA (2) + sequence number (6).
const IA_ROW: usize = 8;
/// Size of one group-object security flag element.
const GO_FLAG: usize = 1;
/// Size of the tool key.
const TOOL_KEY_LEN: usize = 16;
/// Size of the sending sequence number.
const SEQ_LEN: usize = 6;
/// The highest valid group-object security flag: bit 0 and bit 1 are the
/// authentication and confidentiality flags; ETS writes 0x03 for a secured
/// group object and 0x00 for a plain one.
const MAX_GO_FLAG: u8 = 0x03;

/// PDT codes for the property descriptions.
const PDT_CONTROL: u8 = 0x00;
const PDT_UNSIGNED_INT: u8 = 0x04;
const PDT_GENERIC_01: u8 = 0x11;
const PDT_GENERIC_06: u8 = 0x16;
const PDT_GENERIC_08: u8 = 0x18;
const PDT_GENERIC_16: u8 = 0x20;
const PDT_GENERIC_18: u8 = 0x22;
const PDT_FUNCTION: u8 = 0x3E;

/// The security object's load state (the byte PID 5 reports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecLoadState {
    /// `0`: no configuration loaded.
    Unloaded,
    /// `1`: configuration loaded and active.
    Loaded,
    /// `2`: a load is in progress; table writes are accepted.
    Loading,
    /// `3`: a load failed.
    Error,
}

impl SecLoadState {
    /// The load-state byte on the wire.
    pub fn to_byte(self) -> u8 {
        match self {
            SecLoadState::Unloaded => 0,
            SecLoadState::Loaded => 1,
            SecLoadState::Loading => 2,
            SecLoadState::Error => 3,
        }
    }
}

/// Device facts the object needs for its range checks, derived from the
/// device's loaded tables. `None` means "not known", and the check falls back
/// to a generous cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityLimits {
    /// Number of group objects (the loaded group-object table's entry count).
    pub group_objects: Option<u16>,
    /// Number of group addresses in the loaded address table.
    pub address_table_len: Option<u16>,
}

/// A malformed extended-service request: too short to hold its fixed fields.
/// A device drops such a frame without answering.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtServiceError {
    /// The request is shorter than its service's fixed fields.
    #[error("malformed {service}: {detail}")]
    Malformed {
        /// The service name.
        service: &'static str,
        /// What was wrong.
        detail: String,
    },
}

/// The answer to one extended property service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtReply {
    /// The response service.
    pub apci: Apci,
    /// The response payload (everything after the two APCI octets).
    pub data: Vec<u8>,
    /// A key-free one-line description for the event log, starting `SECOBJ`.
    pub summary: String,
}

/// The decoded 5-octet extended-service header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtHeader {
    /// The interface object type.
    pub object_type: u16,
    /// The object instance (12 bits, 1-based).
    pub instance: u16,
    /// The property id (12 bits).
    pub pid: u16,
}

impl ExtHeader {
    /// Decode the header from the first 5 octets of `data`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let h = data.get(..5)?;
        Some(ExtHeader {
            object_type: u16::from_be_bytes([h[0], h[1]]),
            instance: (u16::from(h[2]) << 4) | (u16::from(h[3]) >> 4),
            pid: (u16::from(h[3] & 0x0F) << 8) | u16::from(h[4]),
        })
    }

    /// Encode the header to its 5 octets.
    pub fn encode(self) -> [u8; 5] {
        let [ot_hi, ot_lo] = self.object_type.to_be_bytes();
        [
            ot_hi,
            ot_lo,
            (self.instance >> 4) as u8,
            (((self.instance & 0x0F) as u8) << 4) | ((self.pid >> 8) as u8 & 0x0F),
            (self.pid & 0xFF) as u8,
        ]
    }

    fn is_security_object(self) -> bool {
        self.object_type == IOT_SECURITY && self.instance == SECURITY_OBJECT_INSTANCE
    }
}

/// A table of fixed-size elements, stored contiguously from element 1.
#[derive(Clone, Default)]
struct Table {
    elem_size: usize,
    bytes: Vec<u8>,
}

impl Table {
    fn new(elem_size: usize) -> Self {
        Table {
            elem_size,
            bytes: Vec::new(),
        }
    }

    fn count(&self) -> usize {
        self.bytes.len() / self.elem_size
    }

    /// Overwrite/extend elements `start..start+n` (1-based). The caller has
    /// checked `start <= count + 1`.
    fn write(&mut self, start: u16, data: &[u8]) {
        let off = (usize::from(start) - 1) * self.elem_size;
        let end = off + data.len();
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        self.bytes[off..end].copy_from_slice(data);
    }

    fn truncate(&mut self, count: usize) {
        self.bytes.truncate(count * self.elem_size);
    }

    fn clear(&mut self) {
        self.bytes.clear();
    }
}

/// The security interface object of one activated device.
///
/// `Debug` is implemented by hand and prints only counts and the load state,
/// never key bytes.
#[derive(Clone)]
pub struct SecurityObject {
    load_state: SecLoadState,
    security_mode: u8,
    group_keys: Table,
    ia_table: Table,
    go_flags: Table,
    tool_key_writes: u32,
    seq_sending: [u8; SEQ_LEN],
}

impl std::fmt::Debug for SecurityObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityObject")
            .field("load_state", &self.load_state)
            .field("security_mode", &self.security_mode)
            .field("group_keys", &self.group_keys.count())
            .field("ia_table", &self.ia_table.count())
            .field("go_flags", &self.go_flags.count())
            .field("tool_key_writes", &self.tool_key_writes)
            .finish()
    }
}

impl Default for SecurityObject {
    fn default() -> Self {
        Self::new_activated()
    }
}

impl SecurityObject {
    /// The object of a freshly activated device: `Loaded` (a device that is
    /// already secured has a loaded security configuration), security mode on,
    /// empty tables.
    pub fn new_activated() -> Self {
        SecurityObject {
            load_state: SecLoadState::Loaded,
            security_mode: 1,
            group_keys: Table::new(GRP_KEY_ROW),
            ia_table: Table::new(IA_ROW),
            go_flags: Table::new(GO_FLAG),
            tool_key_writes: 0,
            seq_sending: [0; SEQ_LEN],
        }
    }

    /// The current load state.
    pub fn load_state(&self) -> SecLoadState {
        self.load_state
    }

    /// The current security mode (1 = Data Secure on).
    pub fn security_mode(&self) -> u8 {
        self.security_mode
    }

    /// Number of group-object security flags written.
    pub fn go_flag_count(&self) -> usize {
        self.go_flags.count()
    }

    /// The security flags of group object `n` (1-based), if written.
    pub fn go_flag(&self, n: u16) -> Option<u8> {
        let off = usize::from(n).checked_sub(1)?;
        self.go_flags.bytes.get(off).copied()
    }

    /// How many times the tool key was written.
    pub fn tool_key_writes(&self) -> u32 {
        self.tool_key_writes
    }

    /// Handle one extended property service. Returns `Ok(None)` for an APCI
    /// that is not an extended request service, `Ok(Some(reply))` with the
    /// response to send, or an error for a request too short to answer.
    pub fn handle(
        &mut self,
        apci: Apci,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<Option<ExtReply>, ExtServiceError> {
        let reply = match apci {
            Apci::FunctionPropertyExtCommand => self.on_function_command(data)?,
            Apci::FunctionPropertyExtStateRead => self.on_function_state_read(data)?,
            Apci::PropertyExtValueRead => self.on_value_read(data, limits)?,
            Apci::PropertyExtValueWriteCon => self.on_value_write(data, limits)?,
            Apci::PropertyExtDescriptionRead => self.on_description_read(data, limits)?,
            _ => return Ok(None),
        };
        Ok(Some(reply))
    }

    fn header(service: &'static str, data: &[u8]) -> Result<ExtHeader, ExtServiceError> {
        ExtHeader::parse(data).ok_or(ExtServiceError::Malformed {
            service,
            detail: format!("{} octets, the header needs 5", data.len()),
        })
    }

    fn state_name(&self) -> &'static str {
        match self.load_state {
            SecLoadState::Unloaded => "Unloaded",
            SecLoadState::Loaded => "Loaded",
            SecLoadState::Loading => "Loading",
            SecLoadState::Error => "Error",
        }
    }

    fn describe(&self, service: &str, h: ExtHeader, detail: &str, rc: u8) -> String {
        format!(
            "SECOBJ {service} iot={}/{} pid={}{detail} rc=0x{rc:02x} state={}",
            h.object_type,
            h.instance,
            h.pid,
            self.state_name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::*;

    #[test]
    fn test_ext_header_roundtrip() -> TestResult {
        let bytes = hex("0011 00103d")?;
        let h = ExtHeader::parse(&bytes).ok_or("parse")?;
        assert_eq!((h.object_type, h.instance, h.pid), (0x0011, 1, 61));
        assert_eq!(h.encode().to_vec(), bytes);
        Ok(())
    }

    #[test]
    fn test_unknown_object_or_pid_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        // Object type 0x0012 and instance 2 are address-void.
        assert_eq!(
            cmd(&mut obj, "01d4 0012 001005 01000000000000000000")?,
            hex("01d6 0012 001005 fd")?
        );
        assert_eq!(
            cmd(&mut obj, "01d4 0011 002005 01000000000000000000")?,
            hex("01d6 0011 002005 fd")?
        );
        // Unknown PID 99 on the value services.
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001063 01 0001")?,
            hex("01cd 0011 001063 00 0001")?
        );
        assert_eq!(
            cmd(&mut obj, "01ce 0011 001063 01 0001 00")?,
            hex("01cf 0011 001063 01 0001 fd")?
        );
        assert_eq!(obj.load_state(), SecLoadState::Loaded);
        Ok(())
    }

    #[test]
    fn test_malformed_requests_are_errors() {
        let mut obj = SecurityObject::new_activated();
        let limits = SecurityLimits::default();
        assert!(
            obj.handle(Apci::FunctionPropertyExtCommand, &[0x00, 0x11], limits)
                .is_err()
        );
        assert!(
            obj.handle(
                Apci::PropertyExtValueRead,
                &[0, 0x11, 0, 0x10, 0x3d, 1],
                limits
            )
            .is_err()
        );
        assert!(matches!(
            obj.handle(Apci::PropertyValueRead, &[], limits),
            Ok(None)
        ));
    }

    #[test]
    fn test_summary_carries_no_key_bytes() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, START)?;
        let apdu = hex(&group_key_write(1, 1))?;
        let reply = obj
            .handle(
                Apci::PropertyExtValueWriteCon,
                &apdu[2..],
                SecurityLimits::default(),
            )?
            .ok_or("no reply")?;
        assert_eq!(
            reply.summary,
            "SECOBJ WriteCon iot=17/1 pid=53 start=1 count=1 rc=0x00 state=Loading"
        );
        assert!(!reply.summary.to_lowercase().contains("a5"));
        assert!(!format!("{obj:?}").to_lowercase().contains("a5"));
        Ok(())
    }
}
