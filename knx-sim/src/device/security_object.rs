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

/// One entry of the object's property list, used for description reads.
struct PropDesc {
    pid: u16,
    pdt: u8,
    writable: bool,
    max_elements: u16,
    read_level: u8,
    write_level: u8,
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

    /// Number of rows in the group key table.
    pub fn group_key_rows(&self) -> usize {
        self.group_keys.count()
    }

    /// The address-table index of group key row `row` (1-based), if written.
    /// Only the index is exposed, never the key.
    pub fn group_key_address_index(&self, row: u16) -> Option<u16> {
        let off = usize::from(row).checked_sub(1)? * GRP_KEY_ROW;
        let b = self.group_keys.bytes.get(off..off + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    /// The group key of the first row naming address-table index `index` (the
    /// 1-based TSAP of a group address). Crate-internal: the key only feeds the
    /// group crypto path and is never logged ([`crate::secure::Key16`] redacts).
    pub(crate) fn group_key_for_address_index(&self, index: u16) -> Option<crate::secure::Key16> {
        self.group_keys
            .bytes
            .chunks_exact(GRP_KEY_ROW)
            .find(|row| u16::from_be_bytes([row[0], row[1]]) == index)
            .and_then(|row| <[u8; 16]>::try_from(&row[2..]).ok())
            .map(crate::secure::Key16::new)
    }

    /// Number of rows in the security individual address table.
    pub fn ia_table_rows(&self) -> usize {
        self.ia_table.count()
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

    /// `A_FunctionPropertyExt_Command`. PID 5 drives the load-state machine,
    /// PID 51 sets the security mode. The answer is a State_Response carrying
    /// `[rc][state]`.
    fn on_function_command(&mut self, data: &[u8]) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_FunctionPropertyExt_Command", data)?;
        let body = &data[5..];
        let (rc, state_data, detail): (u8, Vec<u8>, String) = if !h.is_security_object() {
            (rc::ADDRESS_VOID, Vec::new(), String::new())
        } else {
            match h.pid {
                pid::LOAD_STATE_CONTROL => {
                    let (rc, event) = self.apply_load_event(body);
                    (
                        rc,
                        vec![self.load_state.to_byte()],
                        format!(" event={event}"),
                    )
                }
                pid::SECURITY_MODE => {
                    let (rc, service) = self.apply_security_mode(body);
                    (rc, vec![service], format!(" mode={}", self.security_mode))
                }
                // Any other PID is not a function property of this object.
                _ => (rc::ADDRESS_VOID, Vec::new(), String::new()),
            }
        };
        let mut out = h.encode().to_vec();
        out.push(rc);
        out.extend_from_slice(&state_data);
        Ok(ExtReply {
            apci: Apci::FunctionPropertyExtStateResponse,
            data: out,
            summary: self.describe("FunctionCommand", h, &detail, rc),
        })
    }

    /// Apply a 10-octet load-control value to the load-state machine.
    ///
    /// Checks (rc):
    /// - the value must be exactly 10 octets, like every load-control write in
    ///   the capture (`INVALID_COMMAND` otherwise);
    /// - event 0 (no operation) leaves the state alone (`SUCCESS`);
    /// - event 1 StartLoading enters `Loading` from any state (`SUCCESS`);
    /// - event 2 LoadCompleted enters `Loaded` only from `Loading`; from any
    ///   other state the state is kept and the answer is `IMPOSSIBLE_COMMAND`;
    /// - event 4 Unload enters `Unloaded` from any state and clears the group
    ///   key table, the IA table and the GO flags (`SUCCESS`);
    /// - any other event is refused with `INVALID_COMMAND`.
    fn apply_load_event(&mut self, body: &[u8]) -> (u8, &'static str) {
        if body.len() != 10 {
            return (rc::INVALID_COMMAND, "malformed");
        }
        match body[0] {
            0 => (rc::SUCCESS, "NoOperation"),
            1 => {
                self.load_state = SecLoadState::Loading;
                (rc::SUCCESS, "StartLoading")
            }
            2 => {
                if self.load_state == SecLoadState::Loading {
                    self.load_state = SecLoadState::Loaded;
                    (rc::SUCCESS, "LoadCompleted")
                } else {
                    (rc::IMPOSSIBLE_COMMAND, "LoadCompleted")
                }
            }
            4 => {
                self.load_state = SecLoadState::Unloaded;
                self.group_keys.clear();
                self.ia_table.clear();
                self.go_flags.clear();
                (rc::SUCCESS, "Unload")
            }
            _ => (rc::INVALID_COMMAND, "unsupported"),
        }
    }

    /// Apply a PID 51 security-mode command. INFERRED layout: the last two
    /// octets are `[service id][mode]` (the capture's `00 00 01` switches the
    /// mode on and is answered `rc=00 00`, the service id echoed). Service id
    /// must be 0 and mode 0 or 1, otherwise `INVALID_COMMAND`.
    fn apply_security_mode(&mut self, body: &[u8]) -> (u8, u8) {
        let [.., service, mode] = body else {
            return (rc::INVALID_COMMAND, 0);
        };
        if *service != 0 || *mode > 1 {
            return (rc::INVALID_COMMAND, *service);
        }
        self.security_mode = *mode;
        (rc::SUCCESS, *service)
    }

    /// `A_FunctionPropertyExt_State_Read`: PID 5 answers `[rc][state]`, PID 51
    /// answers `[rc][mode]`; anything else answers `ADDRESS_VOID`.
    fn on_function_state_read(&mut self, data: &[u8]) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_FunctionPropertyExt_State_Read", data)?;
        let (rc, state_data) = match (h.is_security_object(), h.pid) {
            (true, pid::LOAD_STATE_CONTROL) => (rc::SUCCESS, vec![self.load_state.to_byte()]),
            (true, pid::SECURITY_MODE) => (rc::SUCCESS, vec![self.security_mode]),
            _ => (rc::ADDRESS_VOID, Vec::new()),
        };
        let mut out = h.encode().to_vec();
        out.push(rc);
        out.extend_from_slice(&state_data);
        Ok(ExtReply {
            apci: Apci::FunctionPropertyExtStateResponse,
            data: out,
            summary: self.describe("FunctionStateRead", h, "", rc),
        })
    }

    /// The element count PID 61 reports: the group-object count when known,
    /// else the number of flags written.
    fn go_flag_elements(&self, limits: SecurityLimits) -> usize {
        limits
            .group_objects
            .map_or(self.go_flags.count(), usize::from)
            .max(self.go_flags.count())
    }

    /// `A_PropertyExtValue_Read`. Start 0 reads the element count (2 octets).
    /// A refused read answers count 0 and no data. Refused: unknown object or
    /// PID, the key tables (PID 53, PID 56: keys are write-only), a count of 0,
    /// and any element past the property's element count.
    fn on_value_read(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtValue_Read", data)?;
        let Some(&[count, s_hi, s_lo]) = data.get(5..8) else {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtValue_Read",
                detail: "missing count/start".into(),
            });
        };
        let start = u16::from_be_bytes([s_hi, s_lo]);
        let value = self.read_value(h, count, start, limits);
        let mut out = h.encode().to_vec();
        let answered = if value.is_some() { count } else { 0 };
        out.push(answered);
        out.extend_from_slice(&start.to_be_bytes());
        if let Some(v) = &value {
            out.extend_from_slice(v);
        }
        let detail = format!(" start={start} count={count}");
        let rc = if value.is_some() {
            rc::SUCCESS
        } else {
            rc::ADDRESS_VOID
        };
        Ok(ExtReply {
            apci: Apci::PropertyExtValueResponse,
            data: out,
            summary: self.describe("ValueRead", h, &detail, rc),
        })
    }

    fn read_value(
        &self,
        h: ExtHeader,
        count: u8,
        start: u16,
        limits: SecurityLimits,
    ) -> Option<Vec<u8>> {
        if !h.is_security_object() || count == 0 {
            return None;
        }
        // Single-element scalar properties: count 1 start 1 (start 0 = count 1).
        let scalar = |v: Vec<u8>| -> Option<Vec<u8>> {
            match (start, count) {
                (0, 1) => Some(1u16.to_be_bytes().to_vec()),
                (1, 1) => Some(v),
                _ => None,
            }
        };
        let table = |bytes: &[u8], elem: usize, elements: usize| -> Option<Vec<u8>> {
            if start == 0 {
                return (count == 1).then(|| (elements as u16).to_be_bytes().to_vec());
            }
            let last = usize::from(start) + usize::from(count) - 1;
            if last > elements {
                return None;
            }
            let mut v = vec![0u8; usize::from(count) * elem];
            let off = (usize::from(start) - 1) * elem;
            let avail = bytes.len().saturating_sub(off).min(v.len());
            v[..avail].copy_from_slice(&bytes[off..off + avail]);
            Some(v)
        };
        match h.pid {
            pid::OBJECT_TYPE => scalar(IOT_SECURITY.to_be_bytes().to_vec()),
            pid::LOAD_STATE_CONTROL => scalar(vec![self.load_state.to_byte()]),
            pid::SECURITY_MODE => scalar(vec![self.security_mode]),
            pid::SEQUENCE_NUMBER_SENDING => scalar(self.seq_sending.to_vec()),
            pid::SECURITY_IA_TABLE => table(&self.ia_table.bytes, IA_ROW, self.ia_table.count()),
            // Unwritten flags within the group-object count read as 0x00.
            pid::GO_SECURITY_FLAGS => {
                table(&self.go_flags.bytes, GO_FLAG, self.go_flag_elements(limits))
            }
            // PID 53 and PID 56 hold keys: write-only, every read is refused.
            _ => None,
        }
    }

    /// `A_PropertyExtValue_WriteCon`, answered with a WriteConResponse
    /// `[count][start:16][rc]`.
    ///
    /// Checks, in order (rc):
    /// 1. unknown object or PID: `ADDRESS_VOID`; PID 1: `ACCESS_READ_ONLY`;
    ///    PID 5 and PID 51 are function properties: `INVALID_COMMAND`;
    /// 2. count 0: `INVALID_COMMAND`;
    /// 3. PID 56 (tool key, 16 octets) and PID 59 (sequence, 6 octets): only
    ///    `count 1 start 1` with the exact length (`INVALID_COMMAND`). Accepted
    ///    in any load state, since real activation writes them outside a load
    ///    bracket. The tool key is only counted, the session key stays as
    ///    configured (changing it is out of scope for the sim);
    /// 4. PID 53/54/61 only while `Loading` (`TEMPORARILY_NOT_AVAILABLE`);
    /// 5. start 0 is an element-count write: count 1, 2 octets, value not above
    ///    the current count (`INVALID_COMMAND` / `OUT_OF_MAX_RANGE`); it
    ///    truncates the table (0 clears it);
    /// 6. `data.len() == count * element size` (`INVALID_COMMAND`);
    /// 7. no holes: `start <= element count + 1`, and the last element within
    ///    the table capacity (group-object count for PID 61) (`OUT_OF_MAX_RANGE`);
    /// 8. PID 61 flag octets 0x00..=0x03 (`OUT_OF_MAX_RANGE`); PID 53 rows name
    ///    an address-table index `>= 1` (`OUT_OF_MIN_RANGE`) and, when the
    ///    address table is known, `<=` its length (`OUT_OF_MAX_RANGE`).
    fn on_value_write(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtValue_WriteCon", data)?;
        if data.len() < 8 {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtValue_WriteCon",
                detail: "missing count/start".into(),
            });
        }
        let count = data[5];
        let start = u16::from_be_bytes([data[6], data[7]]);
        let value = &data[8..];
        let rc = self.write_value(h, count, start, value, limits);
        let mut out = h.encode().to_vec();
        out.push(count);
        out.extend_from_slice(&start.to_be_bytes());
        out.push(rc);
        let detail = format!(" start={start} count={count}");
        Ok(ExtReply {
            apci: Apci::PropertyExtValueWriteConResponse,
            data: out,
            summary: self.describe("WriteCon", h, &detail, rc),
        })
    }

    fn write_value(
        &mut self,
        h: ExtHeader,
        count: u8,
        start: u16,
        value: &[u8],
        limits: SecurityLimits,
    ) -> u8 {
        if !h.is_security_object() {
            return rc::ADDRESS_VOID;
        }
        match h.pid {
            pid::OBJECT_TYPE => return rc::ACCESS_READ_ONLY,
            pid::LOAD_STATE_CONTROL | pid::SECURITY_MODE => return rc::INVALID_COMMAND,
            pid::TOOL_KEY | pid::SEQUENCE_NUMBER_SENDING | pid::GRP_KEY_TABLE => {}
            pid::SECURITY_IA_TABLE | pid::GO_SECURITY_FLAGS => {}
            _ => return rc::ADDRESS_VOID,
        }
        if count == 0 {
            return rc::INVALID_COMMAND;
        }
        match h.pid {
            pid::TOOL_KEY => {
                if start != 1 || count != 1 || value.len() != TOOL_KEY_LEN {
                    return rc::INVALID_COMMAND;
                }
                self.tool_key_writes += 1;
                return rc::SUCCESS;
            }
            pid::SEQUENCE_NUMBER_SENDING => {
                if start != 1 || count != 1 || value.len() != SEQ_LEN {
                    return rc::INVALID_COMMAND;
                }
                self.seq_sending.copy_from_slice(value);
                return rc::SUCCESS;
            }
            _ => {}
        }
        if self.load_state != SecLoadState::Loading {
            return rc::TEMPORARILY_NOT_AVAILABLE;
        }
        let (elem, capacity) = match h.pid {
            pid::GRP_KEY_TABLE => (
                GRP_KEY_ROW,
                limits
                    .address_table_len
                    .map_or(MAX_GROUP_KEY_ROWS, |n| n.min(MAX_GROUP_KEY_ROWS)),
            ),
            pid::SECURITY_IA_TABLE => (IA_ROW, MAX_IA_TABLE_ROWS),
            _ => (
                GO_FLAG,
                limits.group_objects.unwrap_or(FALLBACK_MAX_GROUP_OBJECTS),
            ),
        };
        let table = match h.pid {
            pid::GRP_KEY_TABLE => &mut self.group_keys,
            pid::SECURITY_IA_TABLE => &mut self.ia_table,
            _ => &mut self.go_flags,
        };
        if start == 0 {
            if count != 1 || value.len() != 2 {
                return rc::INVALID_COMMAND;
            }
            let n = usize::from(u16::from_be_bytes([value[0], value[1]]));
            if n > table.count() {
                return rc::OUT_OF_MAX_RANGE;
            }
            table.truncate(n);
            return rc::SUCCESS;
        }
        if value.len() != usize::from(count) * elem {
            return rc::INVALID_COMMAND;
        }
        let last = usize::from(start) + usize::from(count) - 1;
        if usize::from(start) > table.count() + 1 || last > usize::from(capacity) {
            return rc::OUT_OF_MAX_RANGE;
        }
        match h.pid {
            pid::GO_SECURITY_FLAGS => {
                if value.iter().any(|&f| f > MAX_GO_FLAG) {
                    return rc::OUT_OF_MAX_RANGE;
                }
            }
            pid::GRP_KEY_TABLE => {
                for row in value.chunks_exact(GRP_KEY_ROW) {
                    let index = u16::from_be_bytes([row[0], row[1]]);
                    if index == 0 {
                        return rc::OUT_OF_MIN_RANGE;
                    }
                    if limits.address_table_len.is_some_and(|len| index > len) {
                        return rc::OUT_OF_MAX_RANGE;
                    }
                }
            }
            _ => {}
        }
        table.write(start, value);
        rc::SUCCESS
    }

    /// The object's property list, in property-index order (index 1 first).
    fn properties(limits: SecurityLimits) -> [PropDesc; 8] {
        let go_max = limits
            .group_objects
            .unwrap_or(FALLBACK_MAX_GROUP_OBJECTS)
            .min(0x0FFF);
        let d = |pid, pdt, writable, max_elements, read_level, write_level| PropDesc {
            pid,
            pdt,
            writable,
            max_elements,
            read_level,
            write_level,
        };
        [
            d(pid::OBJECT_TYPE, PDT_UNSIGNED_INT, false, 1, 3, 15),
            d(pid::LOAD_STATE_CONTROL, PDT_CONTROL, true, 1, 3, 0),
            d(pid::SECURITY_MODE, PDT_FUNCTION, true, 1, 3, 0),
            // Key tables: not readable at any level (read level 15).
            d(
                pid::GRP_KEY_TABLE,
                PDT_GENERIC_18,
                true,
                MAX_GROUP_KEY_ROWS,
                15,
                0,
            ),
            d(
                pid::SECURITY_IA_TABLE,
                PDT_GENERIC_08,
                true,
                MAX_IA_TABLE_ROWS,
                3,
                0,
            ),
            d(pid::TOOL_KEY, PDT_GENERIC_16, true, 1, 15, 0),
            d(pid::SEQUENCE_NUMBER_SENDING, PDT_GENERIC_06, true, 1, 3, 0),
            d(pid::GO_SECURITY_FLAGS, PDT_GENERIC_01, true, go_max, 3, 0),
        ]
    }

    /// `A_PropertyExtDescription_Read`. A non-zero PID addresses the property
    /// by id; PID 0 addresses it by the 12-bit property index (1-based, the
    /// same convention as the sim's plain description read). An unknown object,
    /// PID or index answers a descriptor with type 0, max 0 and access 0, the
    /// "no property here" signal. DPTs are not modelled and report 0.0.
    fn on_description_read(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtDescription_Read", data)?;
        let Some(idx) = data.get(5..7) else {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtDescription_Read",
                detail: "missing description type / index".into(),
            });
        };
        let desc_type = idx[0] >> 4;
        let req_index = (u16::from(idx[0] & 0x0F) << 8) | u16::from(idx[1]);
        let props = Self::properties(limits);
        let found = if !h.is_security_object() {
            None
        } else if h.pid != 0 {
            props
                .iter()
                .position(|p| p.pid == h.pid)
                .map(|i| (i as u16 + 1, &props[i]))
        } else {
            usize::from(req_index)
                .checked_sub(1)
                .and_then(|i| props.get(i))
                .map(|p| (req_index, p))
        };
        let (index, rh, tail): (u16, ExtHeader, [u8; 8]) = match found {
            Some((index, p)) => {
                let [m_hi, m_lo] = (p.max_elements & 0x0FFF).to_be_bytes();
                (
                    index,
                    ExtHeader { pid: p.pid, ..h },
                    [
                        0,
                        0,
                        0,
                        0,
                        (if p.writable { 0x80 } else { 0 }) | (p.pdt & 0x3F),
                        m_hi,
                        m_lo,
                        ((p.read_level & 0x0F) << 4) | (p.write_level & 0x0F),
                    ],
                )
            }
            None => (req_index, h, [0; 8]),
        };
        let mut out = rh.encode().to_vec();
        out.push((desc_type << 4) | ((index >> 8) as u8 & 0x0F));
        out.push((index & 0xFF) as u8);
        out.extend_from_slice(&tail);
        let rc = if found.is_some() {
            rc::SUCCESS
        } else {
            rc::ADDRESS_VOID
        };
        let detail = format!(" index={index}");
        Ok(ExtReply {
            apci: Apci::PropertyExtDescriptionResponse,
            data: out,
            summary: self.describe("DescriptionRead", rh, &detail, rc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Decode a hex string with optional spaces.
    fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
            .collect()
    }

    /// Feed a plain APDU (2 APCI octets + data, as in the capture) to the
    /// object and return the plain response APDU (2 APCI octets + data).
    fn exchange(
        obj: &mut SecurityObject,
        apdu_hex: &str,
        limits: SecurityLimits,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let apdu = hex(apdu_hex)?;
        let apci10 = (u16::from(apdu[0] & 0x03) << 8) | u16::from(apdu[1]);
        let reply = obj
            .handle(Apci::from_u10(apci10), &apdu[2..], limits)?
            .ok_or("no reply")?;
        let v = reply.apci.to_u10();
        let mut out = vec![(v >> 8) as u8, (v & 0xFF) as u8];
        out.extend_from_slice(&reply.data);
        Ok(out)
    }

    fn cmd(
        obj: &mut SecurityObject,
        apdu_hex: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        exchange(obj, apdu_hex, SecurityLimits::default())
    }

    const UNLOAD: &str = "01d4 0011 001005 04000000000000000000";
    const START: &str = "01d4 0011 001005 01000000000000000000";
    const COMPLETE: &str = "01d4 0011 001005 02000000000000000000";

    /// A PID 61 WriteCon of `count` flag octets (value 0x03) at `start`.
    fn go_flags_write(start: u16, count: u8) -> String {
        format!(
            "01ce 0011 00103d {count:02x} {start:04x} {}",
            "03".repeat(usize::from(count))
        )
    }

    /// A PID 53 WriteCon of one row naming address-table index `index`.
    fn group_key_write(row: u16, index: u16) -> String {
        format!(
            "01ce 0011 001035 01 {row:04x} {index:04x} {}",
            "a5".repeat(16)
        )
    }

    #[test]
    fn test_ext_header_roundtrip() -> TestResult {
        let bytes = hex("0011 00103d")?;
        let h = ExtHeader::parse(&bytes).ok_or("parse")?;
        assert_eq!((h.object_type, h.instance, h.pid), (0x0011, 1, 61));
        assert_eq!(h.encode().to_vec(), bytes);
        Ok(())
    }

    #[test]
    fn test_function_command_load_transitions_match_capture() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(obj.load_state(), SecLoadState::Loaded);
        assert_eq!(cmd(&mut obj, UNLOAD)?, hex("01d6 0011 001005 00 00")?);
        assert_eq!(cmd(&mut obj, START)?, hex("01d6 0011 001005 00 02")?);
        assert_eq!(cmd(&mut obj, COMPLETE)?, hex("01d6 0011 001005 00 01")?);
        assert_eq!(obj.load_state(), SecLoadState::Loaded);
        Ok(())
    }

    #[test]
    fn test_function_command_load_completed_outside_loading_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, UNLOAD)?;
        // LoadCompleted from Unloaded: IMPOSSIBLE_COMMAND, state kept.
        assert_eq!(cmd(&mut obj, COMPLETE)?, hex("01d6 0011 001005 f3 00")?);
        // Unsupported event 3 and a short value: INVALID_COMMAND.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001005 03000000000000000000")?,
            hex("01d6 0011 001005 f2 00")?
        );
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001005 01")?,
            hex("01d6 0011 001005 f2 00")?
        );
        assert_eq!(obj.load_state(), SecLoadState::Unloaded);
        Ok(())
    }

    #[test]
    fn test_function_command_security_mode_matches_capture() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001033 000001")?,
            hex("01d6 0011 001033 00 00")?
        );
        assert_eq!(obj.security_mode(), 1);
        // Mode 2 does not exist.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001033 000002")?,
            hex("01d6 0011 001033 f2 00")?
        );
        Ok(())
    }

    #[test]
    fn test_function_state_read_reports_load_state() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001005 00")?,
            hex("01d6 0011 001005 00 01")?
        );
        cmd(&mut obj, START)?;
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001005")?,
            hex("01d6 0011 001005 00 02")?
        );
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

    /// The full ETS-order load for a 1333-object device: Unload, StartLoading,
    /// clear PID 54, one PID 53 row, PID 61 in 211-element chunks, LoadCompleted.
    #[test]
    fn test_full_ets_sequence_succeeds() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(1333),
            address_table_len: Some(40),
        };
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            exchange(&mut obj, UNLOAD, limits)?,
            hex("01d6 0011 001005 00 00")?
        );
        assert_eq!(
            exchange(&mut obj, START, limits)?,
            hex("01d6 0011 001005 00 02")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001036 01 0000 0000", limits)?,
            hex("01cf 0011 001036 01 0000 00")?
        );
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 7), limits)?,
            hex("01cf 0011 001035 01 0001 00")?
        );
        let mut start = 1u16;
        while start <= 1333 {
            let count = (1334 - start).min(211) as u8;
            let resp = exchange(&mut obj, &go_flags_write(start, count), limits)?;
            let mut want = hex("01cf 0011 00103d")?;
            want.push(count);
            want.extend_from_slice(&start.to_be_bytes());
            want.push(0x00);
            assert_eq!(resp, want, "chunk at start {start}");
            start += u16::from(count);
        }
        // The capture's first and last chunk headers.
        assert_eq!(go_flags_write(1, 0xd3)[..20], *"01ce 0011 00103d d3 ");
        assert_eq!(go_flags_write(1267, 67)[..25], *"01ce 0011 00103d 43 04f3 ");
        assert_eq!(
            exchange(&mut obj, COMPLETE, limits)?,
            hex("01d6 0011 001005 00 01")?
        );
        assert_eq!(obj.go_flag_count(), 1333);
        assert_eq!(obj.go_flag(1333), Some(0x03));
        assert_eq!(obj.group_key_rows(), 1);
        assert_eq!(obj.group_key_address_index(1), Some(7));
        assert_eq!(obj.ia_table_rows(), 0);
        Ok(())
    }

    #[test]
    fn test_table_writes_outside_loading_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        // Loaded: every table write is TEMPORARILY_NOT_AVAILABLE.
        assert_eq!(
            cmd(&mut obj, &go_flags_write(1, 2))?,
            hex("01cf 0011 00103d 02 0001 f9")?
        );
        assert_eq!(
            cmd(&mut obj, &group_key_write(1, 1))?,
            hex("01cf 0011 001035 01 0001 f9")?
        );
        assert_eq!(
            cmd(&mut obj, "01ce 0011 001036 01 0000 0000")?,
            hex("01cf 0011 001036 01 0000 f9")?
        );
        // Tool key and sequence are accepted outside a load bracket.
        let tool_key = format!("01ce 0011 001038 01 0001 {}", "11".repeat(16));
        assert_eq!(
            cmd(&mut obj, &tool_key)?,
            hex("01cf 0011 001038 01 0001 00")?
        );
        assert_eq!(
            cmd(&mut obj, "01ce 0011 00103b 01 0001 000000001234")?,
            hex("01cf 0011 00103b 01 0001 00")?
        );
        assert_eq!(obj.tool_key_writes(), 1);
        Ok(())
    }

    #[test]
    fn test_bad_lengths_and_ranges_refused() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(10),
            address_table_len: Some(5),
        };
        let mut obj = SecurityObject::new_activated();
        exchange(&mut obj, START, limits)?;
        // Count 3 with 2 octets of data.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 03 0001 0303", limits)?,
            hex("01cf 0011 00103d 03 0001 f2")?
        );
        // Count 0.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 00 0001", limits)?,
            hex("01cf 0011 00103d 00 0001 f2")?
        );
        // A PID 53 row one octet short.
        let short = format!("01ce 0011 001035 01 0001 0001 {}", "a5".repeat(15));
        assert_eq!(
            exchange(&mut obj, &short, limits)?,
            hex("01cf 0011 001035 01 0001 f2")?
        );
        // Flag octet 0x04.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 01 0001 04", limits)?,
            hex("01cf 0011 00103d 01 0001 f7")?
        );
        // Beyond the 10 group objects.
        assert_eq!(
            exchange(&mut obj, &go_flags_write(1, 11), limits)?,
            hex("01cf 0011 00103d 0b 0001 f7")?
        );
        // A hole: start 3 on an empty table.
        assert_eq!(
            exchange(&mut obj, &go_flags_write(3, 1), limits)?,
            hex("01cf 0011 00103d 01 0003 f7")?
        );
        // Address-table index 0 and index past the 5-entry address table.
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 0), limits)?,
            hex("01cf 0011 001035 01 0001 f6")?
        );
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 6), limits)?,
            hex("01cf 0011 001035 01 0001 f7")?
        );
        // Element-count write above the current count.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001036 01 0000 0001", limits)?,
            hex("01cf 0011 001036 01 0000 f7")?
        );
        // Tool key of the wrong length; PID 1 is read-only; PID 5 via WriteCon.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001038 01 0001 1122", limits)?,
            hex("01cf 0011 001038 01 0001 f2")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001001 01 0001 0011", limits)?,
            hex("01cf 0011 001001 01 0001 fb")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001005 01 0001 01", limits)?,
            hex("01cf 0011 001005 01 0001 f2")?
        );
        assert_eq!(obj.go_flag_count(), 0);
        assert_eq!(obj.group_key_rows(), 0);
        Ok(())
    }

    #[test]
    fn test_unload_clears_tables() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, START)?;
        cmd(&mut obj, &go_flags_write(1, 4))?;
        cmd(&mut obj, &group_key_write(1, 1))?;
        cmd(&mut obj, "01ce 0011 001036 01 0001 1101 000000000001")?;
        assert_eq!(
            (
                obj.go_flag_count(),
                obj.group_key_rows(),
                obj.ia_table_rows()
            ),
            (4, 1, 1)
        );
        cmd(&mut obj, UNLOAD)?;
        assert_eq!(
            (
                obj.go_flag_count(),
                obj.group_key_rows(),
                obj.ia_table_rows()
            ),
            (0, 0, 0)
        );
        Ok(())
    }

    #[test]
    fn test_key_reads_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, START)?;
        cmd(&mut obj, &group_key_write(1, 1))?;
        // PID 53 (element and count) and PID 56: count 0, no data.
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001035 01 0001")?,
            hex("01cd 0011 001035 00 0001")?
        );
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001035 01 0000")?,
            hex("01cd 0011 001035 00 0000")?
        );
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001038 01 0001")?,
            hex("01cd 0011 001038 00 0001")?
        );
        Ok(())
    }

    #[test]
    fn test_value_reads_of_flags_and_counts() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(5),
            address_table_len: None,
        };
        let mut obj = SecurityObject::new_activated();
        exchange(&mut obj, START, limits)?;
        exchange(&mut obj, "01ce 0011 00103d 02 0001 0301", limits)?;
        // Start 0: the element count is the group-object count.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 01 0000", limits)?,
            hex("01cd 0011 00103d 01 0000 0005")?
        );
        // Unwritten flags within the GO count read as 0x00.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 03 0001", limits)?,
            hex("01cd 0011 00103d 03 0001 030100")?
        );
        // Past the element count: refused.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 02 0005", limits)?,
            hex("01cd 0011 00103d 00 0005")?
        );
        // PID 5 and PID 1 via value read.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 001005 01 0001", limits)?,
            hex("01cd 0011 001005 01 0001 02")?
        );
        assert_eq!(
            exchange(&mut obj, "01cc 0011 001001 01 0001", limits)?,
            hex("01cd 0011 001001 01 0001 0011")?
        );
        Ok(())
    }

    #[test]
    fn test_description_read_by_pid_and_index() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(1333),
            address_table_len: None,
        };
        let mut obj = SecurityObject::new_activated();
        // By PID 61: index 8, dpt 0.0, writable GENERIC_01, max 1333, r3/w0.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 00103d 0000", limits)?,
            hex("01d3 0011 00103d 0008 0000 0000 91 0535 30")?
        );
        // By index 4 (PID 0): the group key table, GENERIC_18, not readable.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001000 0004", limits)?,
            hex("01d3 0011 001035 0004 0000 0000 a2 0400 f0")?
        );
        // Index past the list: the "no property" descriptor.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001000 0009", limits)?,
            hex("01d3 0011 001000 0009 0000 0000 00 0000 00")?
        );
        // The response payload after the APCI is 15 octets.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001005 0000", limits)?.len(),
            2 + 15
        );
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
