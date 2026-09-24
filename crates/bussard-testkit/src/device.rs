//! [`MockDevice`]: a scripted KNX device living on a [`MockGateway`] line.
//!
//! A device answers connected-mode management (`T_Connect`, numbered data,
//! `T_ACK`/`T_NAK`) and broadcast management (individual address read/write,
//! serial-number addressing). Its application layer comes from a builder:
//! descriptor mask, authorize level, a generic property store, memory, and a
//! System B table model (load-state machine, `LdCtrlRelSegment`,
//! `PID_TABLE_REFERENCE`, `PID_TABLE` served from the segment image).
//!
//! Anything a suite needs beyond that goes in a hook
//! ([`MockDevice::with_hook`]). The hook sees every connected-mode request first
//! and may answer it itself.
//!
//! [`MockGateway`]: crate::MockGateway

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use bussard_model::IndividualAddress;

use crate::consts::{
    A_AUTHORIZE_REQUEST, A_AUTHORIZE_RESPONSE, A_DEVICE_DESCRIPTOR_READ,
    A_DEVICE_DESCRIPTOR_RESPONSE, A_INDIVIDUAL_ADDRESS_READ, A_INDIVIDUAL_ADDRESS_RESPONSE,
    A_INDIVIDUAL_ADDRESS_SERIAL_READ, A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE,
    A_INDIVIDUAL_ADDRESS_SERIAL_WRITE, A_INDIVIDUAL_ADDRESS_WRITE, A_MEMORY_EXTENDED_READ,
    A_MEMORY_EXTENDED_READ_RESPONSE, A_MEMORY_EXTENDED_WRITE, A_MEMORY_EXTENDED_WRITE_RESPONSE,
    A_MEMORY_READ, A_MEMORY_RESPONSE, A_MEMORY_WRITE, A_PROPERTY_DESCRIPTION_READ,
    A_PROPERTY_DESCRIPTION_RESPONSE, A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_RESPONSE,
    A_PROPERTY_VALUE_WRITE, A_RESTART, APCI_SELECTOR, LE_ADDITIONAL, LE_LOAD_COMPLETED,
    LE_START_LOADING, LE_UNLOAD, LS_LOADED, LS_LOADING, LS_UNLOADED, OT_ADDRESS_TABLE,
    OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_LOAD_STATE_CONTROL,
    PID_MANUFACTURER_ID, PID_OBJECT_TYPE, PID_ORDER_INFO, PID_PROGMODE, PID_SERIAL_NUMBER,
    PID_TABLE, PID_TABLE_REFERENCE, SUB_REL_SEGMENT,
};

/// A device's reaction to one connected-mode request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reaction {
    /// `T_ACK` the request, then answer with this APCI and payload.
    Answer(u16, Vec<u8>),
    /// `T_ACK` the request without an application-layer answer.
    Ack,
    /// `T_NAK` the request.
    Nak,
    /// Say nothing at all.
    Silent,
}

/// Where `A_Memory_Write` / `A_MemoryExtended_Write` may land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryWritePolicy {
    /// Anywhere in the 24-bit address space.
    Anywhere,
    /// Only wholly inside an allocated segment (System B). A write outside one is
    /// `T_NAK`ed.
    WithinSegments,
}

/// A custom request handler. It runs before the built-in services. Returning
/// `Some` answers the request; `None` falls through to the built-ins.
pub type Hook = Arc<dyn Fn(&mut MockDevice, u16, &[u8]) -> Option<Reaction> + Send + Sync>;

/// One element-array property value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Property {
    elem_size: usize,
    data: Vec<u8>,
    writable: bool,
}

/// A scripted KNX device. Build one with [`MockDevice::new`] and the `with_*`
/// methods, put it on a gateway line, and read its state back afterwards.
#[derive(Clone)]
pub struct MockDevice {
    /// The device's individual address. It changes on an address write.
    pub address: IndividualAddress,
    /// Mask version answered to `A_DeviceDescriptor_Read` type 0.
    pub mask: u16,
    /// Whether the programming button is pressed.
    pub programming: bool,
    /// Keep the programming mode on after an address or `PID_PROGMODE` write
    /// (a stuck button, or KNX Virtual).
    pub stuck_programming: bool,
    /// The 6-octet KNX serial number.
    pub serial: [u8; 6],
    /// The level answered to `A_Authorize_Request`.
    pub authorize_level: u8,
    /// Interface object types by object index.
    pub object_types: Vec<u16>,
    /// Load state per object index (absent means `Unloaded`).
    pub load_states: HashMap<u8, u8>,
    /// Allocated segment per object index: `(base, size)`.
    pub segments: HashMap<u8, (u32, u32)>,
    /// Sparse 24-bit memory.
    pub memory: HashMap<u32, u8>,
    /// Where memory writes may land.
    pub memory_write_policy: MemoryWritePolicy,
    /// Answer `A_Memory_Write` with an `A_Memory_Response` echo (verify mode)
    /// instead of a bare `T_ACK`.
    pub echo_memory_writes: bool,
    /// The group-object table's element count, served as its `PID_TABLE` count.
    pub go_count: u16,
    /// `T_NAK` every memory write into a segment of this object type.
    pub nak_writes_into: Option<u16>,
    /// Never answer any request.
    pub silent: bool,
    /// Connected-mode requests handled, across every connection.
    pub telegrams: usize,
    /// Write services (property or memory) seen, across every connection.
    pub writes: usize,
    /// `A_Restart` requests seen.
    pub restarts: usize,
    /// `T_Connect`s seen.
    pub connects: usize,
    /// Every connected-mode request as `(apci, data)`, in order.
    pub requests: Vec<(u16, Vec<u8>)>,
    /// The device's next outgoing sequence number while connected.
    pub(crate) send_seq: Option<u8>,
    properties: HashMap<(u8, u8), Property>,
    hook: Option<Hook>,
}

impl fmt::Debug for MockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockDevice")
            .field("address", &self.address)
            .field("mask", &format_args!("{:#06x}", self.mask))
            .field("programming", &self.programming)
            .field("telegrams", &self.telegrams)
            .field("writes", &self.writes)
            .field("hook", &self.hook.is_some())
            .finish_non_exhaustive()
    }
}

/// Where a System B table object's segment is placed by `LdCtrlRelSegment`:
/// the address table at `0x4000`, each further object `0x800` above. A real
/// device picks these itself and reports them through `PID_TABLE_REFERENCE`;
/// the mock is deterministic.
pub fn segment_base_for(object_index: u8) -> u32 {
    0x4000 + u32::from(object_index.saturating_sub(1)) * 0x800
}

/// A property-value response payload: the 4-octet header plus `data`.
pub fn prop_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    out.extend_from_slice(data);
    out
}

/// Decodes a property-value read or write header: `(object, pid, count, start)`.
pub fn decode_prop_header(payload: &[u8]) -> Option<(u8, u8, u8, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        payload[0],
        payload[1],
        (payload[2] >> 4) & 0x0f,
        (u16::from(payload[2] & 0x0f) << 8) | u16::from(payload[3]),
    ))
}

impl MockDevice {
    /// A device at `address` with mask `0x07B0` (System B), a device object
    /// only, not in programming mode, authorize level 0, and memory writes
    /// allowed anywhere with a `Memory_Response` echo.
    pub fn new(address: IndividualAddress) -> Self {
        MockDevice {
            address,
            mask: 0x07B0,
            programming: false,
            stuck_programming: false,
            serial: [0; 6],
            authorize_level: 0,
            object_types: vec![OT_DEVICE],
            load_states: HashMap::new(),
            segments: HashMap::new(),
            memory: HashMap::new(),
            memory_write_policy: MemoryWritePolicy::Anywhere,
            echo_memory_writes: true,
            go_count: 0,
            nak_writes_into: None,
            silent: false,
            telegrams: 0,
            writes: 0,
            restarts: 0,
            connects: 0,
            requests: Vec::new(),
            send_seq: None,
            properties: HashMap::new(),
            hook: None,
        }
    }

    /// A System B device with the table objects `[device, address table,
    /// association table, group object table]`. Writes are confined to
    /// allocated segments. Preload tables with [`MockDevice::with_table`].
    pub fn system_b(address: IndividualAddress) -> Self {
        let mut dev = MockDevice::new(address)
            .with_object_types(&[
                OT_DEVICE,
                OT_ADDRESS_TABLE,
                OT_ASSOCIATION_TABLE,
                OT_GROUP_OBJECT_TABLE,
            ])
            .with_memory_write_policy(MemoryWritePolicy::WithinSegments);
        dev.mask = 0x07B0;
        dev
    }

    /// Sets the mask version.
    pub fn with_mask(mut self, mask: u16) -> Self {
        self.mask = mask;
        self
    }

    /// Presses (or releases) the programming button.
    pub fn with_programming(mut self, on: bool) -> Self {
        self.programming = on;
        self
    }

    /// Keeps the programming mode on after it is told to leave it.
    pub fn with_stuck_programming(mut self) -> Self {
        self.stuck_programming = true;
        self.programming = true;
        self
    }

    /// Sets the serial number, also served as `PID_SERIAL_NUMBER` on object 0.
    pub fn with_serial(mut self, serial: [u8; 6]) -> Self {
        self.serial = serial;
        self.with_property(0, PID_SERIAL_NUMBER, 6, &serial)
    }

    /// Serves `PID_MANUFACTURER_ID` on object 0.
    pub fn with_manufacturer(self, manufacturer: u16) -> Self {
        self.with_property(0, PID_MANUFACTURER_ID, 2, &manufacturer.to_be_bytes())
    }

    /// Serves `PID_ORDER_INFO` on object 0 (one element of `order.len()` octets).
    pub fn with_order_info(self, order: &[u8]) -> Self {
        let len = order.len().max(1);
        self.with_property(0, PID_ORDER_INFO, len, order)
    }

    /// Sets the level answered to `A_Authorize_Request`.
    pub fn with_authorize_level(mut self, level: u8) -> Self {
        self.authorize_level = level;
        self
    }

    /// Sets the interface object types by index.
    pub fn with_object_types(mut self, types: &[u16]) -> Self {
        self.object_types = types.to_vec();
        self
    }

    /// Serves a read-only array property: `data` holds elements of `elem_size`
    /// octets. A start=0 read returns the element count.
    pub fn with_property(
        mut self,
        object_index: u8,
        pid: u8,
        elem_size: usize,
        data: &[u8],
    ) -> Self {
        self.properties.insert(
            (object_index, pid),
            Property {
                elem_size: elem_size.max(1),
                data: data.to_vec(),
                writable: false,
            },
        );
        self
    }

    /// Serves a writable array property. Writes replace the addressed elements
    /// and are echoed back.
    pub fn with_writable_property(
        mut self,
        object_index: u8,
        pid: u8,
        elem_size: usize,
        data: &[u8],
    ) -> Self {
        self.properties.insert(
            (object_index, pid),
            Property {
                elem_size: elem_size.max(1),
                data: data.to_vec(),
                writable: true,
            },
        );
        self
    }

    /// Places `bytes` in memory at `addr`.
    pub fn with_memory(mut self, addr: u32, bytes: &[u8]) -> Self {
        for (i, b) in bytes.iter().enumerate() {
            self.memory.insert(addr.wrapping_add(i as u32), *b);
        }
        self
    }

    /// Sets where memory writes may land.
    pub fn with_memory_write_policy(mut self, policy: MemoryWritePolicy) -> Self {
        self.memory_write_policy = policy;
        self
    }

    /// Answers `A_Memory_Write` with a bare `T_ACK` instead of an echo.
    pub fn without_memory_write_echo(mut self) -> Self {
        self.echo_memory_writes = false;
        self
    }

    /// Places a System B table image (count word plus elements) for
    /// `object_index` at [`segment_base_for`] and marks it `Loaded`, as if a
    /// download had run.
    pub fn with_table(mut self, object_index: u8, image: &[u8]) -> Self {
        self.preload_table(object_index, image);
        self
    }

    /// Sets the group-object table's element count.
    pub fn with_go_count(mut self, count: u16) -> Self {
        self.go_count = count;
        self
    }

    /// `T_NAK`s every memory write into a segment of object type `object_type`.
    pub fn with_nak_writes_into(mut self, object_type: u16) -> Self {
        self.nak_writes_into = Some(object_type);
        self
    }

    /// Never answers anything.
    pub fn with_silence(mut self) -> Self {
        self.silent = true;
        self
    }

    /// Installs a custom handler that sees every connected-mode request before
    /// the built-ins.
    pub fn with_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut MockDevice, u16, &[u8]) -> Option<Reaction> + Send + Sync + 'static,
    {
        self.hook = Some(Arc::new(hook));
        self
    }

    /// Places a System B table image; see [`MockDevice::with_table`].
    pub fn preload_table(&mut self, object_index: u8, image: &[u8]) {
        let base = segment_base_for(object_index);
        self.segments
            .insert(object_index, (base, image.len() as u32));
        for (i, b) in image.iter().enumerate() {
            self.memory.insert(base + i as u32, *b);
        }
        self.load_states.insert(object_index, LS_LOADED);
    }

    /// The load state of `object_index`.
    pub fn load_state(&self, object_index: u8) -> u8 {
        self.load_states
            .get(&object_index)
            .copied()
            .unwrap_or(LS_UNLOADED)
    }

    /// Reads `len` octets from `addr` (unset octets read as 0).
    pub fn read_mem(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                self.memory
                    .get(&addr.wrapping_add(i as u32))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }

    /// The segment image of `object_index`, if one is allocated.
    pub fn table_image(&self, object_index: u8) -> Option<Vec<u8>> {
        let &(base, size) = self.segments.get(&object_index)?;
        Some(self.read_mem(base, size as usize))
    }

    /// The current value of an array property from the generic store.
    pub fn property(&self, object_index: u8, pid: u8) -> Option<&[u8]> {
        self.properties
            .get(&(object_index, pid))
            .map(|p| p.data.as_slice())
    }

    /// The object index the segment `addr..addr+len` lies wholly inside, if any.
    fn segment_of(&self, addr: u32, len: usize) -> Option<u8> {
        let end = u64::from(addr) + len as u64;
        self.segments.iter().find_map(|(&oi, &(base, size))| {
            (u64::from(addr) >= u64::from(base) && end <= u64::from(base) + u64::from(size))
                .then_some(oi)
        })
    }

    /// Stores `value` at `addr`, or refuses it per the write policy and faults.
    fn write_mem(&mut self, addr: u32, value: &[u8]) -> bool {
        let segment = self.segment_of(addr, value.len());
        if self.memory_write_policy == MemoryWritePolicy::WithinSegments && segment.is_none() {
            return false;
        }
        if let (Some(oi), Some(faulty)) = (segment, self.nak_writes_into)
            && self.object_types.get(usize::from(oi)) == Some(&faulty)
        {
            return false;
        }
        for (i, b) in value.iter().enumerate() {
            self.memory.insert(addr.wrapping_add(i as u32), *b);
        }
        true
    }

    fn elem_size(&self, object_index: u8) -> usize {
        match self.object_types.get(usize::from(object_index)) {
            Some(&OT_ASSOCIATION_TABLE) => 4,
            _ => 2,
        }
    }

    /// Answers one broadcast request, returning the broadcast answer if any.
    pub fn handle_broadcast(&mut self, apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
        if self.silent {
            return None;
        }
        match apci {
            A_INDIVIDUAL_ADDRESS_READ if self.programming => {
                Some((A_INDIVIDUAL_ADDRESS_RESPONSE, Vec::new()))
            }
            A_INDIVIDUAL_ADDRESS_WRITE if self.programming && data.len() >= 2 => {
                self.address = IndividualAddress::from_raw(u16::from_be_bytes([data[0], data[1]]));
                if !self.stuck_programming {
                    self.programming = false;
                }
                None
            }
            A_INDIVIDUAL_ADDRESS_SERIAL_READ if data.len() >= 6 && data[..6] == self.serial => {
                let mut payload = self.serial.to_vec();
                payload.extend_from_slice(&[0, 0]);
                Some((A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE, payload))
            }
            A_INDIVIDUAL_ADDRESS_SERIAL_WRITE if data.len() >= 8 && data[..6] == self.serial => {
                self.address = IndividualAddress::from_raw(u16::from_be_bytes([data[6], data[7]]));
                None
            }
            _ => None,
        }
    }

    /// Answers one connected-mode request against the device state.
    pub fn handle_request(&mut self, apci: u16, data: &[u8]) -> Reaction {
        if self.silent {
            return Reaction::Silent;
        }
        self.telegrams += 1;
        self.requests.push((apci, data.to_vec()));
        if let Some(hook) = self.hook.clone()
            && let Some(reaction) = hook(self, apci, data)
        {
            return reaction;
        }

        if apci == A_AUTHORIZE_REQUEST {
            return Reaction::Answer(A_AUTHORIZE_RESPONSE, vec![self.authorize_level]);
        }
        if apci == A_DEVICE_DESCRIPTOR_READ && data.is_empty() {
            return Reaction::Answer(
                A_DEVICE_DESCRIPTOR_RESPONSE,
                self.mask.to_be_bytes().to_vec(),
            );
        }
        if apci == A_RESTART {
            self.restarts += 1;
            return Reaction::Ack;
        }
        if apci & APCI_SELECTOR == A_MEMORY_READ {
            return self.memory_read(apci, data);
        }
        if apci & APCI_SELECTOR == A_MEMORY_WRITE {
            return self.memory_write(data);
        }
        match apci {
            A_MEMORY_EXTENDED_READ => self.memory_extended_read(data),
            A_MEMORY_EXTENDED_WRITE => self.memory_extended_write(data),
            A_PROPERTY_VALUE_READ => self.property_read(data),
            A_PROPERTY_VALUE_WRITE => self.property_write(data),
            A_PROPERTY_DESCRIPTION_READ => {
                // "No such property": type 0, zero elements, access 0.
                let mut payload = data.iter().copied().take(3).collect::<Vec<u8>>();
                payload.resize(3, 0);
                payload.extend_from_slice(&[0, 0, 0, 0]);
                Reaction::Answer(A_PROPERTY_DESCRIPTION_RESPONSE, payload)
            }
            _ => Reaction::Silent,
        }
    }

    fn memory_read(&self, apci: u16, data: &[u8]) -> Reaction {
        let count = usize::from(apci & 0x3f);
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&self.read_mem(u32::from(addr), count));
        Reaction::Answer(A_MEMORY_RESPONSE | (count as u16 & 0x3f), payload)
    }

    fn memory_write(&mut self, data: &[u8]) -> Reaction {
        self.writes += 1;
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let value = data[2..].to_vec();
        if !self.write_mem(u32::from(addr), &value) {
            return Reaction::Nak;
        }
        if !self.echo_memory_writes {
            return Reaction::Ack;
        }
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&value);
        Reaction::Answer(A_MEMORY_RESPONSE | (value.len() as u16 & 0x3f), payload)
    }

    fn memory_extended_read(&self, data: &[u8]) -> Reaction {
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = usize::from(data[0]);
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut payload = vec![0x00, data[1], data[2], data[3]];
        payload.extend_from_slice(&self.read_mem(addr, count));
        Reaction::Answer(A_MEMORY_EXTENDED_READ_RESPONSE, payload)
    }

    fn memory_extended_write(&mut self, data: &[u8]) -> Reaction {
        self.writes += 1;
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = usize::from(data[0]);
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        if data.len() < 4 + count || !self.write_mem(addr, &data[4..4 + count]) {
            return Reaction::Nak;
        }
        Reaction::Answer(
            A_MEMORY_EXTENDED_WRITE_RESPONSE,
            vec![0x00, data[1], data[2], data[3]],
        )
    }

    fn property_read(&self, data: &[u8]) -> Reaction {
        let Some((oi, pid, count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let answer = |n: u8, bytes: &[u8]| {
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, n, start, bytes),
            )
        };
        if pid == PID_OBJECT_TYPE {
            return match self.object_types.get(usize::from(oi)) {
                Some(ot) => answer(1, &ot.to_be_bytes()),
                None => answer(0, &[]),
            };
        }
        let is_table_object = self
            .object_types
            .get(usize::from(oi))
            .is_some_and(|&ot| ot != OT_DEVICE);
        if pid == PID_LOAD_STATE_CONTROL && is_table_object {
            return answer(1, &[self.load_state(oi)]);
        }
        if pid == PID_TABLE_REFERENCE && is_table_object {
            let base = self.segments.get(&oi).map(|&(b, _)| b).unwrap_or(0);
            return answer(1, &base.to_be_bytes());
        }
        if pid == PID_TABLE && is_table_object {
            return self.table_read(oi, count, start);
        }
        if let Some(prop) = self.properties.get(&(oi, pid)) {
            let total = prop.data.len() / prop.elem_size;
            if start == 0 {
                return answer(1, &(total as u16).to_be_bytes());
            }
            let idx = usize::from(start);
            if idx > total {
                return answer(0, &[]);
            }
            let want = usize::from(count).clamp(1, total - idx + 1);
            let from = (idx - 1) * prop.elem_size;
            return answer(want as u8, &prop.data[from..from + want * prop.elem_size]);
        }
        answer(0, &[])
    }

    fn table_read(&self, oi: u8, count: u8, start: u16) -> Reaction {
        let answer = |n: u8, first: u16, bytes: &[u8]| {
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, PID_TABLE, n, first, bytes),
            )
        };
        if self.object_types.get(usize::from(oi)) == Some(&OT_GROUP_OBJECT_TABLE) {
            return if start == 0 {
                answer(1, 0, &self.go_count.to_be_bytes())
            } else {
                answer(0, start, &[])
            };
        }
        let elem_size = self.elem_size(oi);
        let Some(image) = self.table_image(oi) else {
            return answer(0, start, &[]);
        };
        if image.len() < 2 {
            return answer(0, start, &[]);
        }
        let stored = usize::from(u16::from_be_bytes([image[0], image[1]]));
        let total = stored.min((image.len() - 2) / elem_size);
        if start == 0 {
            return answer(1, 0, &(total as u16).to_be_bytes());
        }
        let idx = usize::from(start);
        if idx > total {
            return answer(0, start, &[]);
        }
        let want = usize::from(count).clamp(1, total - idx + 1);
        let from = 2 + (idx - 1) * elem_size;
        answer(want as u8, start, &image[from..from + want * elem_size])
    }

    fn property_write(&mut self, data: &[u8]) -> Reaction {
        self.writes += 1;
        let Some((oi, pid, count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = data[4..].to_vec();
        let answer = |n: u8, bytes: &[u8]| {
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, n, start, bytes),
            )
        };
        if pid == PID_LOAD_STATE_CONTROL {
            return self.load_control(oi, start, &value);
        }
        if oi == 0 && pid == PID_PROGMODE {
            if value.first() == Some(&0) && !self.stuck_programming {
                self.programming = false;
            } else if value.first().is_some_and(|v| v & 1 == 1) {
                self.programming = true;
            }
            return answer(1, &[u8::from(self.programming)]);
        }
        if let Some(prop) = self.properties.get_mut(&(oi, pid))
            && prop.writable
            && start >= 1
        {
            let from = (usize::from(start) - 1) * prop.elem_size;
            let end = from + value.len();
            if prop.data.len() < end {
                prop.data.resize(end, 0);
            }
            prop.data[from..end].copy_from_slice(&value);
            return answer(count, &value);
        }
        // Anything else (including a PID_TABLE write) is refused with a
        // zero-count response, as a real System B device does.
        answer(0, &[])
    }

    fn load_control(&mut self, oi: u8, start: u16, value: &[u8]) -> Reaction {
        let answer = |state: u8| {
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, PID_LOAD_STATE_CONTROL, 1, start, &[state]),
            )
        };
        let event = value.first().copied().unwrap_or(0);
        // LdCtrlRelSegment: allocate a fresh segment of the requested size.
        if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
            if self.load_state(oi) == LS_LOADING {
                let size = if value.len() >= 6 {
                    u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                } else {
                    0
                };
                if let Some(&(old_base, old_size)) = self.segments.get(&oi) {
                    for i in 0..old_size {
                        self.memory.remove(&old_base.wrapping_add(i));
                    }
                }
                self.segments.insert(oi, (segment_base_for(oi), size));
            }
            return answer(self.load_state(oi));
        }
        let new_state = match event {
            LE_START_LOADING => LS_LOADING,
            LE_LOAD_COMPLETED => LS_LOADED,
            LE_UNLOAD => LS_UNLOADED,
            _ => self.load_state(oi),
        };
        self.load_states.insert(oi, new_state);
        answer(new_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxError;

    fn device() -> Result<MockDevice, BoxError> {
        Ok(MockDevice::system_b("1.1.4".parse()?)
            .with_table(1, &[0x00, 0x01, 0x0A, 0x00])
            .with_manufacturer(0x00C5))
    }

    #[test]
    fn test_handle_request_answers_descriptor_and_counts() -> Result<(), BoxError> {
        let mut dev = device()?;
        let reaction = dev.handle_request(A_DEVICE_DESCRIPTOR_READ, &[]);
        assert_eq!(
            reaction,
            Reaction::Answer(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0])
        );
        assert_eq!(dev.telegrams, 1);
        Ok(())
    }

    #[test]
    fn test_handle_request_serves_table_count_and_elements() -> Result<(), BoxError> {
        let mut dev = device()?;
        let count = dev.handle_request(A_PROPERTY_VALUE_READ, &[1, PID_TABLE, 0x10, 0x00]);
        assert_eq!(
            count,
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(1, PID_TABLE, 1, 0, &[0, 1])
            )
        );
        let elem = dev.handle_request(A_PROPERTY_VALUE_READ, &[1, PID_TABLE, 0x10, 0x01]);
        assert_eq!(
            elem,
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                prop_response(1, PID_TABLE, 1, 1, &[0x0A, 0x00])
            )
        );
        Ok(())
    }

    #[test]
    fn test_handle_request_refuses_writes_outside_segments() -> Result<(), BoxError> {
        let mut dev = device()?;
        assert_eq!(
            dev.handle_request(A_MEMORY_WRITE | 1, &[0x10, 0x00, 0xFF]),
            Reaction::Nak
        );
        assert_eq!(dev.writes, 1);
        Ok(())
    }

    #[test]
    fn test_handle_broadcast_address_write_leaves_programming() -> Result<(), BoxError> {
        let mut dev = MockDevice::new("15.15.255".parse()?).with_programming(true);
        assert_eq!(
            dev.handle_broadcast(A_INDIVIDUAL_ADDRESS_READ, &[]),
            Some((A_INDIVIDUAL_ADDRESS_RESPONSE, vec![]))
        );
        dev.handle_broadcast(A_INDIVIDUAL_ADDRESS_WRITE, &[0x11, 0x07]);
        assert_eq!(dev.address.to_string(), "1.1.7");
        assert!(!dev.programming);
        Ok(())
    }

    #[test]
    fn test_hook_answers_before_builtins() -> Result<(), BoxError> {
        let mut dev = device()?
            .with_hook(|_, apci, _| (apci == A_DEVICE_DESCRIPTOR_READ).then_some(Reaction::Nak));
        assert_eq!(
            dev.handle_request(A_DEVICE_DESCRIPTOR_READ, &[]),
            Reaction::Nak
        );
        Ok(())
    }
}
