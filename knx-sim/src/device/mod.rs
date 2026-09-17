//! A strict, independent KNX System-B device.
//!
//! The device holds its memory map, interface objects and per-object load-state
//! machines, and implements the device side of the management protocol exactly
//! and strictly. It is driven one management APDU at a time via
//! [`Device::handle_apdu`], which returns the response APDU(s) to send back and
//! records observations on the event stream.

mod interface_object;
mod lsm;
mod memory;

pub use interface_object::{
    InterfaceObject, PID_LOAD_STATE_CONTROL, PID_OBJECT_TYPE, PID_PROGMODE, PID_RUN_STATE_CONTROL,
    PID_TABLE_REFERENCE, Property, iot,
};
pub use lsm::{LoadEvent, LoadState, LoadStateMachine};
pub use memory::{Memory, MemoryError, Segment};

use std::collections::BTreeMap;

use crate::bus::event::{Event, EventSink};
use crate::prod::{LoadableObject, ProductData};
use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, IndividualAddress, MessageCode, Tpci};

/// How a device reacted to one inbound telegram.
#[derive(Debug, Default)]
pub struct DeviceReaction {
    /// Response telegrams to send back toward the tool (already framed as cEMI
    /// `L_Data.ind`).
    pub responses: Vec<CemiLData>,
    /// True if the device just performed a master reset and is "rebooting".
    pub did_master_reset: bool,
}

/// The reason the device rejected a management telegram. A strict device
/// answers most rejections by simply not responding (as a real device would
/// drop a malformed or unauthorized request), but the reason is surfaced for
/// tests and the event log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceError {
    /// A management verb arrived without an open transport connection.
    #[error("management telegram with no open connection")]
    NotConnected,
    /// A write was attempted without sufficient authorization.
    #[error("unauthorized: access level {level} insufficient")]
    Unauthorized {
        /// The current access level.
        level: u8,
    },
    /// A property access referenced an unknown object or PID.
    #[error("no property: object {object} pid {pid}")]
    NoProperty {
        /// The object index.
        object: u8,
        /// The PID.
        pid: u8,
    },
    /// A write to a read-only property.
    #[error("property object {object} pid {pid} is read-only")]
    ReadOnlyProperty {
        /// The object index.
        object: u8,
        /// The PID.
        pid: u8,
    },
    /// A load-state control write was invalid.
    #[error("load-state control rejected: {0}")]
    LoadControl(String),
    /// A memory write was rejected by the memory model.
    #[error("memory rejected: {0}")]
    Memory(#[from] MemoryError),
    /// The APDU was malformed for its service.
    #[error("malformed {service}: {detail}")]
    Malformed {
        /// The service name.
        service: String,
        /// What was wrong.
        detail: String,
    },
}

/// One loadable object's runtime state: its LSM plus its assigned segment base.
#[derive(Debug, Clone)]
struct ObjectState {
    lsm: LoadStateMachine,
    /// The segment base this object reports via `PID_TABLE_REFERENCE`.
    base: u16,
    #[allow(dead_code)] // retained for logging / future viz
    descriptor: LoadableObject,
}

/// A strict System-B KNX device.
pub struct Device {
    address: IndividualAddress,
    /// Interface objects keyed by object index (0 = device object).
    objects: BTreeMap<u8, InterfaceObject>,
    /// Loadable-object runtime state keyed by LSM index.
    loadables: BTreeMap<u8, ObjectState>,
    memory: Memory,
    /// Access level (0 = highest/unlocked). Starts locked at 15 until authorize.
    access_level: u8,
    connected: bool,
    /// Sequence number for the next connected response.
    tx_seq: u8,
    events: std::sync::Arc<dyn EventSink>,
}

/// Deterministic segment bases matching the ETS→KNX-Virtual capture for the
/// DA.tp product, so a tool that reads `PID_TABLE_REFERENCE` gets a stable,
/// real-looking map. Objects not listed fall back to a generated base.
fn default_base_for(lsm_index: u8) -> u16 {
    match lsm_index {
        1 => 0xA000, // address table
        2 => 0xC000, // association table
        3 => 0x8000, // com-object table
        4 => 0x6000, // application segment
        other => 0x6000u16.wrapping_add((other as u16) << 12),
    }
}

/// The interface-object type (IOT) reported via `PID_OBJECT_TYPE` for a given
/// interface-object index on a System B device.
///
/// A management tool discovers the interface-object table by probing
/// `A_PropertyValue_Read(objIdx, PID 1)` for each index and reading back the
/// IOT. On the calibration target (KNX-Virtual, mask 07B0) the observed layout
/// is index n → IOT n for the first five objects:
/// `[0:device, 1:address-table, 2:association-table, 3:application-program,
/// 4:interface-program]` (spec Resources 03.05.01 §4.1; ref
/// `knx-device-spec-references.md` §4.1). Indices beyond that fall back to the
/// index value itself, which is what a linearly-numbered System B table yields.
fn object_type_for(object_index: u8) -> u16 {
    match object_index {
        0 => iot::DEVICE,
        1 => iot::ADDRESS_TABLE,
        2 => iot::ASSOCIATION_TABLE,
        3 => iot::APPLICATION_PROGRAM,
        4 => iot::INTERFACE_PROGRAM,
        5 => iot::KNX_OBJECT_ASSOCIATION_TABLE,
        other => other as u16,
    }
}

impl Device {
    /// Build a device at `address` from parsed product data, with an initial
    /// load state applied to every loadable object.
    pub fn from_product(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Self {
        let mut objects: BTreeMap<u8, InterfaceObject> = BTreeMap::new();
        let mut loadables: BTreeMap<u8, ObjectState> = BTreeMap::new();

        // Device object (index 0): seed the identity properties ETS reads during
        // a flash, with the exact values the real KNX-Virtual DA.tp device
        // returned in dumpfile.pcap so a tool's pre-flash probing sees a
        // plausible, consistent device.
        //   PID 0x0B (11) PID_SERIAL_NUMBER / hardware id → 00 fa 00 25 00 00
        //   PID 0x0C (12) PID_MANUFACTURER_ID            → 00 fa
        //   PID 0x0E (14) PID_DEVICE_CONTROL             → 04
        //   PID 0x0F (15) PID_ORDER_INFO ("DA.tp")       → 20 44 41 2e 74 70 ...
        //   PID 0x19 (25) PID_VERSION                    → 48 00
        //   PID 0x38 (56) PID_MAX_APDU_LENGTH            → 00 42
        //   PID 0x4E (78) PID_HARDWARE_TYPE              → 00 00 00 00 00 54
        //   PID 0x36 (54) PID_PROGMODE                   → 00 (writable)
        let mut device_object = InterfaceObject::new();
        // PID_OBJECT_TYPE (PID 1) reports this object's interface-object type.
        // The device object is IOT 0. A tool discovers the object table by
        // reading PID 1 on each index, so every object must answer it.
        device_object.set_property(
            PID_OBJECT_TYPE,
            Property::read_only(object_type_for(0).to_be_bytes().to_vec()),
        );
        device_object.set_property(PID_PROGMODE, Property::writable(vec![0x00]));
        device_object.set_property(
            0x0B,
            Property::read_only(vec![0x00, 0xfa, 0x00, 0x25, 0x00, 0x00]),
        );
        device_object.set_property(0x0C, Property::read_only(vec![0x00, 0xfa]));
        device_object.set_property(0x0E, Property::writable(vec![0x04]));
        device_object.set_property(
            0x0F,
            Property::read_only(vec![
                0x20, 0x44, 0x41, 0x2e, 0x74, 0x70, 0x00, 0x00, 0x00, 0x00,
            ]),
        );
        device_object.set_property(0x19, Property::read_only(vec![0x48, 0x00]));
        device_object.set_property(0x38, Property::read_only(vec![0x00, 0x42]));
        device_object.set_property(
            0x4E,
            Property::read_only(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x54]),
        );
        objects.insert(0, device_object);

        // A System B device also exposes a KNX-object association table
        // (interface-object type 5). ETS issues Unload on object 5 during a
        // flash even when the product's tables leave it empty, so the device
        // must have a load-state machine for it. Add it if the product did not.
        let mut all_objects: Vec<LoadableObject> = product.objects.clone();
        if !all_objects.iter().any(|o| o.lsm_index == 5) {
            all_objects.push(LoadableObject {
                lsm_index: 5,
                name: "knx-object association table".into(),
                max_size: None,
                image: Vec::new(),
            });
        }

        for obj in &all_objects {
            let base = default_base_for(obj.lsm_index);
            let mut io = InterfaceObject::new();
            // PID_OBJECT_TYPE (PID 1) reports this object's interface-object
            // type so a tool can discover the object table by index.
            io.set_property(
                PID_OBJECT_TYPE,
                Property::read_only(object_type_for(obj.lsm_index).to_be_bytes().to_vec()),
            );
            io.set_property(
                PID_LOAD_STATE_CONTROL,
                Property::writable(vec![initial_state.to_byte()]),
            );
            // PID_TABLE_REFERENCE is a 4-byte value; the base is the low 16 bits.
            io.set_property(
                PID_TABLE_REFERENCE,
                Property::read_only(vec![0x00, 0x00, (base >> 8) as u8, (base & 0xFF) as u8]),
            );
            // PID 0x0D (PID_PROGRAM_VERSION / run-state / app-id) is written near
            // the end of a flash to stamp the application id (ETS writes
            // `00 fa 25 00 10` on object 4). Seed it writable.
            io.set_property(PID_RUN_STATE_CONTROL, Property::writable(vec![0x00; 5]));
            // PID 0x0E (PID_ERROR_CODE) is read during the flow; seed readable.
            io.set_property(0x0E, Property::writable(vec![0x00]));
            objects.insert(obj.lsm_index, io);
            loadables.insert(
                obj.lsm_index,
                ObjectState {
                    lsm: LoadStateMachine::new(initial_state),
                    base,
                    descriptor: obj.clone(),
                },
            );
        }

        Self {
            address,
            objects,
            loadables,
            memory: Memory::new(),
            access_level: 15,
            connected: false,
            tx_seq: 0,
            events,
        }
    }

    /// The device's individual address.
    pub fn address(&self) -> IndividualAddress {
        self.address
    }

    /// The current load state of a loadable object (by LSM index).
    pub fn load_state(&self, lsm_index: u8) -> Option<LoadState> {
        self.loadables.get(&lsm_index).map(|o| o.lsm.state())
    }

    /// Read-only view of device memory (for tests/observability).
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    fn emit(&self, event: Event) {
        self.events.emit(event);
    }

    /// Handle a full inbound cEMI telegram, updating state and producing
    /// responses. Control frames (T_Connect/T_Disconnect/T_ACK) are handled
    /// here; data telegrams are dispatched to [`Device::handle_apdu`].
    pub fn handle_cemi(&mut self, cemi: &CemiLData) -> Result<DeviceReaction, DeviceError> {
        if cemi.tpdu.is_empty() {
            return Ok(DeviceReaction::default());
        }
        let tpci = Tpci::from_byte(cemi.tpdu[0]);
        match tpci {
            Tpci::Connect => {
                self.connected = true;
                self.tx_seq = 0;
                // Authorization is NOT reset on connect. In the ETS capture the
                // tool authorizes once (Phase A) and, after the pre-flash basic
                // restart + reconnect (Phase C), issues PID5/memory writes with
                // no re-authorize. A real device with the free-access key granted
                // stays at level 0 until a key is set, so the grant persists
                // across a basic restart within the session.
                Ok(DeviceReaction::default())
            }
            Tpci::Disconnect => {
                self.connected = false;
                Ok(DeviceReaction::default())
            }
            Tpci::Ack(_) => Ok(DeviceReaction::default()),
            Tpci::Nak(_) => Ok(DeviceReaction::default()),
            Tpci::DataUnnumbered | Tpci::DataConnected(_) => {
                let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
                    service: "APDU".into(),
                    detail: "too short".into(),
                })?;
                self.handle_apdu(cemi, &apdu)
            }
        }
    }

    /// Build a connected `L_Data.ind` response back toward `dest` (the tool).
    fn respond(&mut self, to: IndividualAddress, apci10: u16, data: &[u8]) -> CemiLData {
        let seq = self.tx_seq;
        self.tx_seq = (self.tx_seq + 1) & 0x0F;
        let tpdu = Apdu::encode_connected(seq, apci10, data);
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu,
        }
    }

    /// Dispatch a management APDU. Returns response telegrams.
    fn handle_apdu(
        &mut self,
        cemi: &CemiLData,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if !self.connected {
            return Err(DeviceError::NotConnected);
        }
        let tool = cemi.source;
        match apdu.apci {
            Apci::AuthorizeRequest => self.on_authorize(tool, apdu),
            Apci::PropertyValueRead => self.on_property_read(tool, apdu),
            Apci::PropertyValueWrite => self.on_property_write(tool, apdu),
            Apci::MemoryRead(_) => self.on_memory_read(tool, apdu),
            Apci::MemoryWrite(_) => self.on_memory_write(tool, apdu),
            Apci::DeviceDescriptorRead(t) => self.on_device_descriptor_read(tool, t),
            Apci::Restart => self.on_restart(tool, apdu),
            // A_RestartMasterReset (0x381) decodes as RestartResponse in the raw
            // APCI table; route it to the restart handler too.
            Apci::RestartResponse => self.on_restart(tool, apdu),
            // A property-description read: answer with a minimal descriptor so a
            // tool that probes before writing does not stall. Not load-critical.
            Apci::PropertyDescriptionRead => Ok(DeviceReaction::default()),
            _ => Ok(DeviceReaction::default()),
        }
    }

    fn on_authorize(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // A_Authorize_Request: data = [reserved, key(4)]. Any key unlocks to
        // level 0 in this model (the capture uses FF FF FF FF).
        if apdu.data.len() < 5 {
            return Err(DeviceError::Malformed {
                service: "A_Authorize".into(),
                detail: "expected 5 data bytes".into(),
            });
        }
        self.access_level = 0;
        self.emit(Event::AuthChanged {
            device: self.address,
            level: 0,
        });
        // Response: A_Authorize_Response with the granted level byte.
        let resp = self.respond(tool, 0x3D2, &[self.access_level]);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Decode the object/pid/count/start header shared by property verbs.
    /// Layout: `[obj, pid, (count<<4)|(start_hi), start_lo, value...]`.
    fn property_header(apdu: &Apdu) -> Result<(u8, u8, u8, u16, usize), DeviceError> {
        if apdu.data.len() < 4 {
            return Err(DeviceError::Malformed {
                service: "A_PropertyValue".into(),
                detail: "header too short".into(),
            });
        }
        let object = apdu.data[0];
        let pid = apdu.data[1];
        let count = apdu.data[2] >> 4;
        let start = (((apdu.data[2] & 0x0F) as u16) << 8) | apdu.data[3] as u16;
        Ok((object, pid, count, start, 4))
    }

    fn on_property_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let (object, pid, count, start, _) = Self::property_header(apdu)?;
        // PID_LOAD_STATE_CONTROL read-back returns the LIVE load state as a
        // single octet (the 10-octet load-event value is write-only). The state
        // lives in the load-state machine, not the seeded property, so a read
        // must reflect the current LSM state — otherwise a tool that reads PID 5
        // to verify a StartLoading/LoadCompleted sees a stale value and stalls.
        // (Spec Resources 03.05.01 §4.23.2; ref `knx-device-spec-references.md`
        // §2.1/§2.3.)
        let value = if pid == PID_LOAD_STATE_CONTROL {
            self.load_state(object).map(|s| vec![s.to_byte()])
        } else {
            self.objects
                .get(&object)
                .and_then(|o| o.property(pid))
                .map(|p| p.value.clone())
        };
        match value {
            Some(value) => {
                // Response echoes obj/pid/count/start then the value.
                let mut data = vec![
                    object,
                    pid,
                    (count << 4) | ((start >> 8) as u8 & 0x0F),
                    (start & 0xFF) as u8,
                ];
                data.extend_from_slice(&value);
                let resp = self.respond(tool, 0x3D6, &data);
                Ok(DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                })
            }
            // Unknown object or PID: the spec-mandated error signal for a
            // property read is an A_PropertyValue_Response that echoes the
            // header with nr_of_elem = 0 and no data (KNX App-Layer 03.03.07
            // §3.4.4.2; ref `knx-device-spec-references.md` §4.4). This is what
            // lets a tool distinguish "no such object/property" (e.g. the end
            // of the interface-object table while probing PID_OBJECT_TYPE) from
            // a dropped telegram, so it must be a real response, not silence.
            None => Ok(DeviceReaction {
                responses: vec![self.respond(
                    tool,
                    0x3D6,
                    &[object, pid, (start >> 8) as u8 & 0x0F, (start & 0xFF) as u8],
                )],
                did_master_reset: false,
            }),
        }
    }

    fn on_property_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let (object, pid, count, start, hdr) = Self::property_header(apdu)?;
        let value = &apdu.data[hdr..];

        // Writes require authorization (level 0).
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }

        // PID_LOAD_STATE_CONTROL drives the load-state machine.
        if pid == PID_LOAD_STATE_CONTROL {
            return self.on_load_state_write(tool, object, count, start, value);
        }

        let io = self
            .objects
            .get_mut(&object)
            .ok_or(DeviceError::NoProperty { object, pid })?;
        let prop = io
            .property_mut(pid)
            .ok_or(DeviceError::NoProperty { object, pid })?;
        if prop.read_only {
            return Err(DeviceError::ReadOnlyProperty { object, pid });
        }
        prop.value = value.to_vec();
        self.emit(Event::PropertyWritten {
            device: self.address,
            object,
            pid,
        });
        // Response echoes obj/pid/count/start + the written value.
        let mut data = vec![
            object,
            pid,
            (count << 4) | ((start >> 8) as u8 & 0x0F),
            (start & 0xFF) as u8,
        ];
        data.extend_from_slice(value);
        let resp = self.respond(tool, 0x3D6, &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    fn on_load_state_write(
        &mut self,
        tool: IndividualAddress,
        object: u8,
        count: u8,
        start: u16,
        value: &[u8],
    ) -> Result<DeviceReaction, DeviceError> {
        let state = self
            .loadables
            .get_mut(&object)
            .ok_or(DeviceError::NoProperty {
                object,
                pid: PID_LOAD_STATE_CONTROL,
            })?;
        let event =
            LoadEvent::decode(value).map_err(|e| DeviceError::LoadControl(e.to_string()))?;
        // On allocation, wire the segment into memory at the object's base.
        let new_state = match state.lsm.apply(event) {
            Ok(s) => s,
            Err(e) => {
                // Strict: report Error state back, surface rejection.
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object,
                    state: LoadState::Error.to_byte(),
                });
                return Err(DeviceError::LoadControl(e.to_string()));
            }
        };
        if let LoadEvent::AllocRelSegment { size } = event {
            let base = state.base;
            self.memory.allocate(object, base, size);
        }
        self.emit(Event::LoadStateChanged {
            device: self.address,
            object,
            state: new_state.to_byte(),
        });
        // The write response reports the resulting load state as the value.
        let mut data = vec![
            object,
            PID_LOAD_STATE_CONTROL,
            (count << 4) | ((start >> 8) as u8 & 0x0F),
            (start & 0xFF) as u8,
        ];
        data.push(new_state.to_byte());
        let resp = self.respond(tool, 0x3D6, &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    fn on_memory_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let n = apdu.memory_count() as usize;
        if apdu.data.len() < 2 {
            return Err(DeviceError::Malformed {
                service: "A_MemoryRead".into(),
                detail: "missing address".into(),
            });
        }
        let addr = u16::from_be_bytes([apdu.data[0], apdu.data[1]]);
        let bytes = self.memory.read(addr, n);
        // A_MemoryResponse: apci 0x240 | count, then addr(2), then data.
        let mut data = Vec::with_capacity(2 + bytes.len());
        data.extend_from_slice(&addr.to_be_bytes());
        data.extend_from_slice(&bytes);
        let resp = self.respond(tool, 0x240 | (n as u16 & 0x3F), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    fn on_memory_write(
        &mut self,
        _tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }
        let n = apdu.memory_count() as usize;
        if apdu.data.len() < 2 + n {
            return Err(DeviceError::Malformed {
                service: "A_MemoryWrite".into(),
                detail: "payload shorter than declared count".into(),
            });
        }
        let addr = u16::from_be_bytes([apdu.data[0], apdu.data[1]]);
        let payload = &apdu.data[2..2 + n];
        // Determine which object owns this address: strict — the address must be
        // inside exactly one open segment, and that object must be Loading.
        let seg = self
            .memory
            .segment_at(addr)
            .ok_or(MemoryError::OutOfSegment { addr, len: n })?;
        let owner = seg.owner;
        if self.load_state(owner) != Some(LoadState::Loading) {
            return Err(DeviceError::LoadControl(format!(
                "memory write to object {owner} while not Loading"
            )));
        }
        self.memory.write(owner, addr, payload)?;
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr,
            len: n,
        });
        // A_MemoryWrite is not acknowledged at the application layer in the
        // captured flow (the tool relies on the transport T_ACK), so no APDU
        // response is produced.
        Ok(DeviceReaction::default())
    }

    fn on_device_descriptor_read(
        &mut self,
        tool: IndividualAddress,
        dtype: u8,
    ) -> Result<DeviceReaction, DeviceError> {
        // Descriptor type 0 → mask version. System B is mask 0x07B0.
        let mask: u16 = 0x07B0;
        let resp = self.respond(tool, 0x340 | (dtype as u16 & 0x3F), &mask.to_be_bytes());
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    fn on_restart(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // A_Restart classification (KNX App-Layer 03.03.07 §3.4.2.2; ref
        // knx-device-spec-references.md §5):
        //   * APCI 0x380 with NO payload  = Basic Restart: reboot, drop the L4
        //     connection, unconfirmed. It does NOT erase loaded tables. Both the
        //     pre-flash restart and the final post-flash restart ETS sends to the
        //     KNX-Virtual device are this bare form (verified in dumpfile.pcap:
        //     `4f 80` and `73 80`), so a basic restart must never wipe memory —
        //     otherwise the just-loaded image would be lost.
        //   * APCI 0x381 with `[erase_code][channel]` = Master Reset: confirmed
        //     with A_Restart_Response (0x3A1) carrying `[error_code][process_time]`.
        //     erase codes 0x02..=0x08 erase state; 0x01 (ConfirmedRestart) erases
        //     nothing. Range 0x01..=0x08 is valid; others are refused.
        let is_master_reset = matches!(apdu.apci, Apci::RestartResponse) // 0x381
            || apdu.apci_raw == 0x381;

        let mut responses = Vec::new();

        if is_master_reset {
            let erase_code = apdu.data.first().copied().unwrap_or(0x01);
            let channel = apdu.data.get(1).copied().unwrap_or(0);
            // Strict: reject reserved erase codes (0x00, 0x09..=0xFF).
            let error_code: u8 = if (0x01..=0x08).contains(&erase_code) {
                0x00 // success
            } else {
                0x02 // unsupported erase code
            };
            // NOTE on erase semantics: in the ETS→KNX-Virtual capture the tool
            // issues A_RestartMasterReset with erase code 0x04 (ResetApplication-
            // Program) *mid-flash*, right after allocating object 4's segment,
            // and the subsequent writes to that segment still succeed with no
            // re-allocation. So on this real device the master reset does NOT
            // discard the in-progress load; it reboots and confirms only. The
            // simulator models that observed behavior: object state is cleared by
            // the explicit Unload load-event, not by the restart. (A device that
            // truly erased here would fail the capture.)
            let _ = channel;
            // A_Restart_Response (0x3A1): [error_code][process_time:2].
            responses.push(self.respond(tool, 0x3A1, &[error_code, 0x00, 0x00]));
        }

        // Every restart drops the transport connection (side effect of reboot).
        self.connected = false;
        self.emit(Event::Restarted {
            device: self.address,
            master_reset: is_master_reset,
        });
        Ok(DeviceReaction {
            responses,
            did_master_reset: is_master_reset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::event::RecordingSink;
    use crate::prod::read_knxprod_bytes;

    /// Build a DA.tp device, or `Ok(None)` if the (un-committed) fixture is
    /// absent so the caller can skip.
    fn da_tp_device() -> Result<Option<Device>, Box<dyn std::error::Error>> {
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            eprintln!("SKIP: DA.tp fixture not present");
            return Ok(None);
        };
        let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
        let sink = std::sync::Arc::new(RecordingSink::new());
        Ok(Some(Device::from_product(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Loaded,
            sink,
        )))
    }

    fn connect(dev: &mut Device) -> Result<(), DeviceError> {
        let cemi = CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress::new(0, 0, 0),
            dest: dev.address().raw(),
            tpdu: vec![0x80],
        };
        dev.handle_cemi(&cemi)?;
        Ok(())
    }

    fn data(dev: &Device, apci10: u16, payload: &[u8]) -> CemiLData {
        let mut tpdu = vec![0x40 | ((apci10 >> 8) as u8 & 0x03), (apci10 & 0xFF) as u8];
        tpdu.extend_from_slice(payload);
        CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress::new(0, 0, 0),
            dest: dev.address().raw(),
            tpdu,
        }
    }

    #[test]
    fn test_memory_write_without_auth_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Start loading object 4 needs auth too; write should be rejected as
        // unauthorized before any load state work.
        let mw = data(&dev, 0x280 | 4, &[0x60, 0x00, 1, 2, 3, 4]);
        assert!(matches!(
            dev.handle_cemi(&mw),
            Err(DeviceError::Unauthorized { .. })
        ));
        Ok(())
    }

    /// Extract the value bytes from a single A_PropertyValue_Response reaction:
    /// the payload after the 4-byte obj/pid/(count|start_hi)/start_lo header.
    fn prop_response_value(reaction: &DeviceReaction) -> Vec<u8> {
        let resp = &reaction.responses[0];
        // TPDU: [tpci][apci_lo][obj][pid][count|start_hi][start_lo][value...].
        resp.tpdu[6..].to_vec()
    }

    #[test]
    fn test_object_type_discovery_returns_iot_per_index() -> Result<(), Box<dyn std::error::Error>>
    {
        // A tool discovers the interface-object table by reading PID_OBJECT_TYPE
        // (PID 1) on each object index. The device must report each object's
        // IOT: [0:device, 1:address-table, 2:association-table,
        // 3:application-program, 4:interface-program]. This is the exact
        // KNX-Virtual layout the flash driver expects.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let expected: [(u8, u16); 5] = [
            (0, iot::DEVICE),
            (1, iot::ADDRESS_TABLE),
            (2, iot::ASSOCIATION_TABLE),
            (3, iot::APPLICATION_PROGRAM),
            (4, iot::INTERFACE_PROGRAM),
        ];
        for (object, want) in expected {
            // A_PropertyValue_Read obj/pid=1/count=1/start=1.
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[object, 0x01, 0x10, 0x01]))?;
            let value = prop_response_value(&r);
            assert_eq!(
                value,
                want.to_be_bytes(),
                "object {object} reported wrong interface-object type"
            );
        }
        Ok(())
    }

    #[test]
    fn test_property_read_unknown_object_returns_error_signal()
    -> Result<(), Box<dyn std::error::Error>> {
        // Reading PID_OBJECT_TYPE past the end of the object table must return
        // the spec error signal: an A_PropertyValue_Response echoing the header
        // with nr_of_elem = 0 and no value (not silence), so a probing tool can
        // detect the table end rather than time out.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Object 6 does not exist on the DA.tp device.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x06, 0x01, 0x10, 0x01]))?;
        assert_eq!(r.responses.len(), 1, "must respond, not drop");
        let resp = &r.responses[0];
        // TPDU: [tpci][d6][obj=06][pid=01][count|start_hi][start_lo]; count = 0.
        let count = resp.tpdu[4] >> 4;
        assert_eq!(count, 0, "unknown property must report nr_of_elem = 0");
        assert_eq!(resp.tpdu.len(), 6, "error signal carries no value bytes");
        Ok(())
    }

    #[test]
    fn test_authorize_unlocks() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let auth = data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&auth)?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(dev.access_level, 0);
        Ok(())
    }

    #[test]
    fn test_load_flow_reaches_loaded() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        // StartLoading obj4
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
        assert_eq!(dev.load_state(4), Some(LoadState::Loading));
        // Allocate 256
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?;
        assert_eq!(
            dev.memory().segment_of(4).map(|s| (s.base, s.len)),
            Some((0x6000, 256))
        );
        // Memory write at base 0x6000
        dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?;
        // LoadCompleted
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?;
        assert_eq!(dev.load_state(4), Some(LoadState::Loaded));
        Ok(())
    }

    #[test]
    fn test_load_state_read_reflects_live_lsm_state() -> Result<(), Box<dyn std::error::Error>> {
        // A wire read of PID_LOAD_STATE_CONTROL must return the LIVE load state
        // (1 octet), tracking the LSM as it transitions — not a value seeded at
        // construction. A tool verifies StartLoading/LoadCompleted by reading
        // PID 5 back, so a stale answer would stall it. Start Unloaded to make
        // the transitions observable.
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            return Ok(());
        };
        let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
        let mut dev = Device::from_product(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Unloaded,
            std::sync::Arc::new(RecordingSink::new()),
        );
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

        // Reads the single load-state octet from a PID 5 read response.
        let read_state = |dev: &mut Device| -> Result<u8, Box<dyn std::error::Error>> {
            let r = dev.handle_cemi(&data(dev, 0x3D5, &[0x04, 0x05, 0x10, 0x01]))?;
            // TPDU: [tpci][d6][obj][pid][count|start_hi][start_lo][state].
            let state = *r.responses[0]
                .tpdu
                .last()
                .ok_or("empty load-state response")?;
            Ok(state)
        };

        assert_eq!(read_state(&mut dev)?, LoadState::Unloaded.to_byte());
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?; // StartLoading
        assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?; // Alloc 256
        assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
        dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?; // mem write
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?; // LoadCompleted
        assert_eq!(read_state(&mut dev)?, LoadState::Loaded.to_byte());
        Ok(())
    }

    #[test]
    fn test_memory_write_to_wrong_base_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?;
        // Write to 0x8000 (com-object base) while only obj4@0x6000 is open.
        let mw = data(&dev, 0x280 | 4, &[0x80, 0x00, 1, 2, 3, 4]);
        assert!(dev.handle_cemi(&mw).is_err());
        Ok(())
    }
}
