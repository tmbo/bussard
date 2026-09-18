//! A strict, independent KNX System-B device.
//!
//! The device holds its memory map, interface objects and per-object load-state
//! machines, and implements the device side of the management protocol exactly
//! and strictly. It is driven one management APDU at a time via
//! [`Device::handle_apdu`], which returns the response APDU(s) to send back and
//! records observations on the event stream.

mod group_comm;
mod interface_object;
mod lsm;
mod mcb;
mod memory;
pub mod profile;
mod sys7_group_comm;
pub mod sys7_lsm;

pub use group_comm::{ComObject, GroupComm, flag};
pub use interface_object::{
    InterfaceObject, PID_LOAD_STATE_CONTROL, PID_MCB_TABLE, PID_OBJECT_TYPE, PID_PROGMODE,
    PID_RUN_STATE_CONTROL, PID_TABLE_REFERENCE, Property, iot,
};
pub use lsm::{
    LoadEvent, LoadState, LoadStateMachine, Sys7LoadStateMachine, Sys7Step, Sys7TransitionError,
};
pub use mcb::{MCB_ENTRY_LEN, crc16_aug_ccitt, mcb_entry};
pub use memory::{Memory, MemoryError, Segment};
pub use profile::{
    LsmAccess, MaskFamily, MemoryMappedLsm, Profile, Sys7MemoryMap, Sys7Profile, mask_family,
    parse_mask,
};
pub use sys7_group_comm::Sys7GroupComm;
pub use sys7_lsm::{Sys7Event, Sys7EventError};

/// The KNX free-access authorize key: an unkeyed device grants full access to
/// any tool presenting this key (spec section 6).
pub const FREE_ACCESS_KEY: u32 = 0xFFFF_FFFF;

/// The conservative System 7 memory chunk: max 12 data octets per
/// `A_Memory_Write`/`_Read` on a standard frame (spec section 6). A memory op to
/// a System 7 device carrying more than this is refused as a real device refuses.
pub const SYS7_MAX_MEMORY_CHUNK: usize = 12;

use std::collections::BTreeMap;

use crate::bus::event::{Event, EventSink};
use crate::prod::{LoadableObject, ProductData};
use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, GroupAddress, IndividualAddress, MessageCode, Tpci};

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
    /// A telegram violated a System 7 wire constraint (standard frame only, at
    /// most 12 memory octets). A real device refuses such a frame.
    #[error("wire-strictness violation: {detail}")]
    WireStrictness {
        /// What constraint was violated.
        detail: String,
    },
}

/// One loadable object's runtime state: its LSM plus its assigned segment base.
#[derive(Debug, Clone)]
struct ObjectState {
    lsm: LoadStateMachine,
    /// The segment base this object reports via `PID_TABLE_REFERENCE` (up to
    /// 24-bit; a capable 07B0 object places its segment above 0xFFFF).
    base: u32,
    #[allow(dead_code)] // retained for logging / future viz
    descriptor: LoadableObject,
}

/// Construction-time overrides that select and tune a device's mask profile.
///
/// Supplied by the config layer. When `mask` is `None` the mask comes from the
/// product's `MaskVersion`. `lsm_access` and `bcu_key` apply only to a System 7
/// device.
#[derive(Debug, Clone, Default)]
pub struct ProfileOverrides {
    /// An explicit mask override (`"0705"`, `"MV-07B0"`, ...). `None` = use the
    /// product's declared mask.
    pub mask: Option<String>,
    /// The System 7 LSM realisation to present.
    pub lsm_access: profile::LsmAccess,
    /// The System 7 BCU key required for memory access, or `None` for free
    /// access.
    pub bcu_key: Option<u32>,
}

/// The runtime state of a System 7 device's three parallel load-state machines
/// plus the memory-region layout it was built with.
#[derive(Debug, Clone)]
struct Sys7Runtime {
    /// The System 7 sub-profile (mask, LSM access, memory map, key, hw type).
    profile: profile::Sys7Profile,
    /// The three (or more) parallel LSMs, keyed by LSM index (1, 2, 3, [5]).
    lsms: BTreeMap<u8, Sys7LoadStateMachine>,
}

/// A strict KNX device (System B or System 7, per its [`Profile`]).
pub struct Device {
    address: IndividualAddress,
    /// The mask profile: System B or System 7 behaviour.
    profile: Profile,
    /// System 7 runtime (the three LSMs + layout); `None` on a System B device.
    sys7: Option<Sys7Runtime>,
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
    /// The **expected** receive sequence number for the next numbered data
    /// telegram (NDT) from the tool. The KNX style-1 rationalised transport layer
    /// numbers NDTs mod 16; a strict device accepts only the expected sequence,
    /// re-acknowledges (without reprocessing) a retransmit of the one it just
    /// ACKed, and ignores anything else. See [`Device::handle_cemi`].
    rx_seq: u8,
    /// The device's per-connection numbered-exchange budget: after this many
    /// accepted NDTs on **one** L4 connection, the device drops the connection
    /// (stops answering, as a real connection-oriented device does when its
    /// per-connection resource budget is exhausted). `None` = unlimited (the
    /// default, so existing tests and captures are unaffected). Reset per
    /// connection on `T_Connect`. Modelled after the KNX Virtual DA.tp device,
    /// which drops a long-held L4 connection after ~35 exchanges.
    l4_exchange_budget: Option<u32>,
    /// Numbered exchanges accepted on the **current** L4 connection, reset to 0
    /// on every `T_Connect`. Metered against [`Device::l4_exchange_budget`].
    l4_exchanges: u32,
    /// The runtime group-communication routing, reconstructed from the device's
    /// own flashed tables once every loadable object reaches `Loaded`. `None`
    /// while the device is not fully loaded (an unloaded device is silent on the
    /// group side). Rebuilt after each successful download.
    group_comm: Option<group_comm::GroupComm>,
    events: std::sync::Arc<dyn EventSink>,
}

/// Parse the 16-bit manufacturer id from an application id of the form
/// `M-XXXX_A-...` (the KNX product identifier). Returns `None` if the leading
/// token is not `M-<4 hex digits>`.
fn manufacturer_id_from_app(application_id: &str) -> Option<u16> {
    let hex = application_id.strip_prefix("M-")?.get(0..4)?;
    u16::from_str_radix(hex, 16).ok()
}

/// A 10-octet `PID_ORDER_INFO` value derived from the product's manufacturer
/// reference (`M-XXXX`) — a short, product-specific stand-in so a scan does not
/// report every device with the same order string. ASCII, right-padded with
/// zero octets to a fixed 10-octet width.
fn order_info_bytes(application_id: &str) -> Vec<u8> {
    let mref = application_id.split('_').next().unwrap_or(application_id);
    let mut v = mref.as_bytes().to_vec();
    v.truncate(10);
    v.resize(10, 0x00);
    v
}

/// Deterministic segment bases matching the ETS→KNX-Virtual capture for the
/// DA.tp product, so a tool that reads `PID_TABLE_REFERENCE` gets a stable,
/// real-looking map. Objects not listed fall back to a generated base.
fn default_base_for(lsm_index: u8) -> u32 {
    match lsm_index {
        1 => 0xA000, // address table
        2 => 0xC000, // association table
        3 => 0x8000, // com-object table
        4 => 0x6000, // application segment
        other => 0x6000u32.wrapping_add((other as u32) << 12),
    }
}

/// The absolute base address a System 7 LSM index anchors at (spec §2.3): LSM 1
/// → 0x4000 table region, LSM 2 → 0x4201 table region, LSM 3 → 0x4400 parameter
/// image. Other indices fall back to the parameter region. Used for
/// `PID_MCB_TABLE` and the runtime table parse.
fn sys7_region_base(s7: &profile::Sys7Profile, lsm_index: u8) -> u16 {
    match lsm_index {
        1 => s7.memory_map.lsm1_table,
        2 => s7.memory_map.lsm2_table,
        _ => s7.memory_map.lsm3_params,
    }
}

/// A decoded `A_MemoryExtended_*` request: the count, the 24-bit address and (for
/// a write) the data octets.
struct ExtendedMemoryRequest {
    /// Number of octets to write/read.
    count: u8,
    /// The 24-bit memory address.
    addr: u32,
    /// The data octets (empty for a read request).
    data: Vec<u8>,
}

/// Decode an `A_MemoryExtended_Write`/`_Read` payload `[count][addr:3 BE][data]`.
///
/// `is_write` selects whether the trailing `count` data octets are required.
/// Returns `None` if the payload is shorter than the 4-octet `[count][addr:3]`
/// header, or (for a write) holds fewer data octets than `count` advertises. This
/// is the sim's own decoder — the simulator never links a bussard crate.
fn bussard_extended_request(payload: &[u8], is_write: bool) -> Option<ExtendedMemoryRequest> {
    if payload.len() < 4 {
        return None;
    }
    let count = payload[0];
    let addr = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
    let data = &payload[4..];
    if is_write {
        if data.len() < usize::from(count) {
            return None;
        }
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: data[..usize::from(count)].to_vec(),
        })
    } else {
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: Vec::new(),
        })
    }
}

/// The interface-object type (IOT) reported via `PID_OBJECT_TYPE` for a given
/// interface-object index on a System B device.
///
/// A management tool discovers the interface-object table by probing
/// `A_PropertyValue_Read(objIdx, PID 1)` for each index and reading back the
/// IOT, then reads each object's segment base via `PID_TABLE_REFERENCE`. Crucially
/// the object that reports the **application-program** type (3) is the one that
/// owns the application code segment, and the **group-object (com-object) table**
/// is a distinct interface object of type **9** (spec Resources 03.05.01 §4.1;
/// ref `knx-device-spec-references.md` §4.1 — Application Program = 3, Group
/// Object Table = 9).
///
/// This simulator keys each loadable object by its load-state-machine (segment)
/// index, and assigns the DA.tp capture's segment bases (obj4 = application code
/// at 0x6000, obj3 = com-object table at 0x8000, obj1/obj2 the address /
/// association tables). So the object holding the application code (LSM index 4)
/// reports `APPLICATION_PROGRAM`, and the object holding the com-object table
/// (LSM index 3) reports `GROUP_OBJECT_TABLE`. A tool that verifies a segment via
/// `PID_MCB_TABLE` reads it on the object that owns that segment, so this
/// alignment is what makes a modern download's image-integrity check land on the
/// right object.
fn object_type_for(object_index: u8) -> u16 {
    match object_index {
        0 => iot::DEVICE,
        1 => iot::ADDRESS_TABLE,
        2 => iot::ASSOCIATION_TABLE,
        3 => iot::GROUP_OBJECT_TABLE,
        4 => iot::APPLICATION_PROGRAM,
        other => other as u16,
    }
}

impl Device {
    /// Build a device at `address` from parsed product data, with an initial
    /// load state applied to every loadable object. The mask profile comes from
    /// the product's declared `MaskVersion`; System 7 devices default to a
    /// memory-mapped LSM and free access.
    ///
    /// Panics only via [`Device::from_product_with_overrides`] returning `Err`
    /// for an unmodelled mask; `from_product` unwraps that into a System B
    /// fallback so existing callers keep the pre-profile behaviour. Prefer
    /// [`Device::from_product_with_overrides`] for explicit control.
    pub fn from_product(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Self {
        // The pre-profile entry point: derive the profile from the product mask,
        // defaulting to System B when the mask is absent or unmodelled so the
        // DA.tp calibration path is unchanged.
        match Self::from_product_with_overrides(
            address,
            product,
            initial_state,
            ProfileOverrides::default(),
            events.clone(),
        ) {
            Ok(dev) => dev,
            // Fall back to an explicit System B profile for an unmodelled mask,
            // preserving the pre-profile behaviour for callers that pass an
            // exotic product.
            Err(_) => Self::from_product_with_overrides(
                address,
                product,
                initial_state,
                ProfileOverrides {
                    mask: Some("07B0".into()),
                    ..Default::default()
                },
                events,
            )
            .expect("System B fallback always builds"),
        }
    }

    /// Build a device, selecting and tuning its mask profile from `overrides`.
    ///
    /// Returns `Err` with a human reason when the effective mask is a family the
    /// simulator does not model (only System B `0x07B0` and System 7 `0x0705` /
    /// `0x0701` are modelled), because a strict simulator refuses to pretend to
    /// be a device generation it does not implement.
    pub fn from_product_with_overrides(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        overrides: ProfileOverrides,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Result<Self, String> {
        // Resolve the effective mask: override wins, else the product's declared
        // MaskVersion, else default to System B (the DA.tp calibration default).
        let mask = match &overrides.mask {
            Some(s) => {
                profile::parse_mask(s).ok_or_else(|| format!("unparseable mask override {s:?}"))?
            }
            None => profile::parse_mask(&product.mask_version).unwrap_or(0x07B0),
        };
        let profile = match profile::mask_family(mask) {
            profile::MaskFamily::SystemB => Profile::SystemB { mask },
            profile::MaskFamily::System7 => Profile::System7(profile::Sys7Profile {
                mask,
                lsm_access: overrides.lsm_access,
                mm_lsm: profile::MemoryMappedLsm::default(),
                memory_map: profile::Sys7MemoryMap::default(),
                bcu_key: overrides.bcu_key,
                // Prefer the value the app's own CompareProp preflight expects
                // (a factory device holds exactly that); fall back to the
                // derived default only when the procedure carries no compare.
                hardware_type: product
                    .hardware_type_marker
                    .as_deref()
                    .and_then(|m| <[u8; 10]>::try_from(m).ok())
                    .unwrap_or_else(|| profile::default_hardware_type(product.application_number)),
            }),
            profile::MaskFamily::Other => {
                return Err(format!(
                    "mask 0x{mask:04x} is not a modelled family (only System B 07B0 and \
                     System 7 0705/0701 are simulated)"
                ));
            }
        };
        if profile.is_system7() {
            Ok(Self::build_system7(
                address,
                product,
                initial_state,
                profile,
                events,
            ))
        } else {
            Ok(Self::build_system_b(
                address,
                product,
                initial_state,
                profile,
                events,
            ))
        }
    }

    /// Build the System B device (the original construction path).
    fn build_system_b(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        profile: Profile,
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
        // PID_MANUFACTURER_ID (0x0C): derive the 16-bit manufacturer id from the
        // product's `M-XXXX_...` application id so a scan reports the real vendor
        // (e.g. M-0083 → 0x0083) rather than a hardcoded one. Falls back to the
        // DA.tp value when the id is not in that form.
        let mfr = manufacturer_id_from_app(&product.application_id).unwrap_or(0x00fa);
        device_object.set_property(0x0C, Property::read_only(mfr.to_be_bytes().to_vec()));
        device_object.set_property(0x0E, Property::writable(vec![0x04]));
        // PID_ORDER_INFO (0x0F): the leading manufacturer-ref string, padded — a
        // stand-in order string so a scan shows something product-specific rather
        // than every device reading back "DA.tp".
        device_object.set_property(
            0x0F,
            Property::read_only(order_info_bytes(&product.application_id)),
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
            // PID_TABLE_REFERENCE is a 4-byte big-endian value carrying the full
            // segment base — up to 24 bits, so a capable 07B0 object reports a base
            // above 0xFFFF (e.g. 0x00018000) that a tool addresses via the extended
            // memory service.
            io.set_property(
                PID_TABLE_REFERENCE,
                Property::read_only(base.to_be_bytes().to_vec()),
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

        let mut device = Self {
            address,
            profile,
            sys7: None,
            objects,
            loadables,
            memory: Memory::new(),
            access_level: 15,
            connected: false,
            tx_seq: 0,
            rx_seq: 0,
            l4_exchange_budget: None,
            l4_exchanges: 0,
            group_comm: None,
            events,
        };
        // A device constructed already `Loaded` (a previously-programmed device)
        // should come alive immediately from whatever tables its memory holds.
        // Freshly constructed memory is empty, so this is a no-op unless a test
        // pre-seeds it, but it keeps the invariant "Loaded ⇒ routing built".
        // The real path is `refresh_group_comm` after a download's LoadCompleted.
        device.refresh_group_comm();
        device
    }

    /// Build a System 7 device: the device object with a matchable object-0
    /// PID 78, the three (plus optional 5) parallel absolute LSMs, and the
    /// PID_MCB_TABLE-capable loadable objects.
    fn build_system7(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        profile: Profile,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Self {
        let s7 = profile
            .system7()
            .expect("build_system7 requires a System 7 profile")
            .clone();
        let mut objects: BTreeMap<u8, InterfaceObject> = BTreeMap::new();
        let mut loadables: BTreeMap<u8, ObjectState> = BTreeMap::new();

        // Device object (index 0). System 7 is almost pure memory; the one
        // property the download touches is object-0 PID 78 (PID_HARDWARE_TYPE),
        // the MDT preflight CompareProp target (spec §4.6). Seed it to the
        // profile's hardware-type so a correctly-targeted flash matches.
        let mut device_object = InterfaceObject::new();
        device_object.set_property(
            PID_OBJECT_TYPE,
            Property::read_only(object_type_for(0).to_be_bytes().to_vec()),
        );
        device_object.set_property(PID_PROGMODE, Property::writable(vec![0x00]));
        let mfr = manufacturer_id_from_app(&product.application_id).unwrap_or(0x0083);
        device_object.set_property(0x0C, Property::read_only(mfr.to_be_bytes().to_vec()));
        device_object.set_property(
            0x0F,
            Property::read_only(order_info_bytes(&product.application_id)),
        );
        // PID 78 (0x4E) PID_HARDWARE_TYPE: the 10-octet preflight value.
        device_object.set_property(0x4E, Property::read_only(s7.hardware_type.to_vec()));
        // Max-APDU absent or 15 on System 7 (spec section 6). Report 15.
        device_object.set_property(0x38, Property::read_only(vec![0x00, 0x0F]));
        // PID 0x0E (PID_ERROR_CODE): the M2 Jung 0705 capture reads it on object 0
        // (`d5 00 0e 10 01` -> 00) and writes it (`d7 00 0e 10 01 04`) during the
        // download housekeeping; seed it writable so that flow is accepted.
        device_object.set_property(0x0E, Property::writable(vec![0x00]));
        objects.insert(0, device_object);

        // The System 7 LSM index → interface-object type map: LSM 1 = address
        // table, LSM 2 = association table, LSM 3 = application program. The
        // three parallel LSMs are seeded per the product's loadable objects,
        // defaulting to the canonical 1/2/3 set when the product does not enumerate
        // them (System 7 products declare them via load procedure, not objects).
        //
        // Object 4 is seeded too but tear-down-only: the M2 Jung 0705 capture
        // Unloads objects 1..4 up front (`d7 04 05 …` = PID-5 Unload on object 4),
        // though only 1/2/3 are ever loaded. Seeding it lets a real ETS sequence's
        // object-4 Unload be accepted; `refresh_group_comm` only requires 1/2.
        let mut lsm_indices: Vec<u8> = product.objects.iter().map(|o| o.lsm_index).collect();
        for canonical in [1u8, 2, 3, 4] {
            if !lsm_indices.contains(&canonical) {
                lsm_indices.push(canonical);
            }
        }
        lsm_indices.sort_unstable();
        lsm_indices.dedup();

        let mut lsms: BTreeMap<u8, Sys7LoadStateMachine> = BTreeMap::new();
        for lsm_index in lsm_indices {
            let mut io = InterfaceObject::new();
            io.set_property(
                PID_OBJECT_TYPE,
                Property::read_only(object_type_for(lsm_index).to_be_bytes().to_vec()),
            );
            // PID_LOAD_STATE_CONTROL exists for the property-based LSM access
            // variant; its live value is served from the LSM, not this seed.
            io.set_property(
                PID_LOAD_STATE_CONTROL,
                Property::writable(vec![initial_state.to_byte()]),
            );
            io.set_property(0x0E, Property::writable(vec![0x00]));
            objects.insert(lsm_index, io);
            lsms.insert(lsm_index, Sys7LoadStateMachine::new(initial_state));
            // Keep a loadable-object descriptor so PID_MCB_TABLE reads and
            // memory bookkeeping have a home (base is the S7 table anchor).
            let descriptor = product
                .object(lsm_index)
                .cloned()
                .unwrap_or(LoadableObject {
                    lsm_index,
                    name: format!("System 7 LSM {lsm_index}"),
                    max_size: None,
                    image: Vec::new(),
                });
            loadables.insert(
                lsm_index,
                ObjectState {
                    lsm: LoadStateMachine::new(initial_state),
                    base: u32::from(sys7_region_base(&s7, lsm_index)),
                    descriptor,
                },
            );
        }

        let mut device = Self {
            address,
            profile,
            sys7: Some(Sys7Runtime { profile: s7, lsms }),
            objects,
            loadables,
            memory: Memory::new(),
            access_level: 15,
            connected: false,
            tx_seq: 0,
            rx_seq: 0,
            l4_exchange_budget: None,
            l4_exchanges: 0,
            group_comm: None,
            events,
        };
        device.refresh_group_comm();
        device
    }

    /// Sets the device's per-connection numbered-exchange budget (builder-style).
    ///
    /// After `budget` accepted NDTs on one L4 connection the device drops the
    /// connection — stops answering — modelling a real connection-oriented
    /// device's per-connection resource limit (KNX Virtual drops at ~35). `None`
    /// leaves it unlimited (the default). See [`Device::l4_exchange_budget`].
    pub fn with_l4_exchange_budget(mut self, budget: Option<u32>) -> Self {
        self.l4_exchange_budget = budget;
        self
    }

    /// The device's individual address.
    pub fn address(&self) -> IndividualAddress {
        self.address
    }

    /// The current load state of a loadable object (by LSM index). On a System 7
    /// device the state lives in the parallel System 7 LSM; on System B it lives
    /// in the object's `LoadStateMachine`.
    pub fn load_state(&self, lsm_index: u8) -> Option<LoadState> {
        if let Some(s7) = &self.sys7 {
            return s7.lsms.get(&lsm_index).map(|m| m.state());
        }
        self.loadables.get(&lsm_index).map(|o| o.lsm.state())
    }

    /// The device's mask profile (System B or System 7).
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Read-only view of device memory (for tests/observability).
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    /// The reconstructed runtime group-communication routing, if the device is
    /// loaded and linked (for tests/observability).
    pub fn group_comm(&self) -> Option<&group_comm::GroupComm> {
        self.group_comm.as_ref()
    }

    /// The segment base a loadable object reports via `PID_TABLE_REFERENCE`.
    ///
    /// System B table objects (address/association/com-object tables) live in the
    /// low 16-bit region, so the group-comm table parse takes a `u16` base; a
    /// base above 0xFFFF here would be an application segment, not a routing table.
    fn base_of(&self, lsm_index: u8) -> Option<u16> {
        self.loadables.get(&lsm_index).map(|o| o.base as u16)
    }

    /// The 8-octet `PID_MCB_TABLE` entry this object would report: an integrity
    /// block over the bytes currently stored in the object's allocated segment.
    ///
    /// Returns `None` if the object has no allocated segment (nothing written),
    /// which a tool reads as "no MCB entry" — but after a load the segment exists,
    /// so a verify step gets a real CRC over exactly the bytes the download wrote.
    fn mcb_entry_for(&self, object: u8) -> Option<Vec<u8>> {
        // The MCB covers the bytes the tool actually streamed (the loaded image),
        // which may be shorter than the allocated segment — a tool that writes a
        // compact table into a larger allocation must still verify against just
        // those bytes. Use the written span, not the full allocation.
        let bytes = self.memory.written_span(object)?;
        Some(mcb::mcb_entry(&bytes).to_vec())
    }

    /// Rebuild the runtime routing from the device's flashed tables, but only
    /// when the address (obj1), association (obj2) and com-object (obj3) table
    /// objects have all reached `Loaded`. A device that is not fully loaded stays
    /// silent on the group side (`group_comm` becomes `None`).
    ///
    /// This reads obj1/obj2/obj3 straight back out of the device's own memory —
    /// the exact bytes the download wrote — so the routing is self-describing and
    /// a mistake in the written tables shows up as wrong bus behaviour.
    fn refresh_group_comm(&mut self) {
        // System 7: the three LSMs are the tables. Once LSM 1 and 2 are Loaded the
        // device self-parses its own written S7-format tables from the absolute
        // memory anchors (spec §7) and comes alive.
        if let Some(s7) = &self.sys7 {
            let tables_loaded = [1u8, 2]
                .iter()
                .all(|&i| self.load_state(i) == Some(LoadState::Loaded));
            if !tables_loaded {
                self.group_comm = None;
                return;
            }
            let addr_base = s7.profile.memory_map.lsm1_table;
            let assoc_base = s7.profile.memory_map.lsm2_table;
            // The group-object descriptor table follows the address table inside
            // the LSM 1 region (spec §7: the GrAT and GO table are co-located).
            // Its base is the address table's end: [CNT:1][own-IA + GAs: CNT*2].
            // S7-CAL: confirm the group-object table offset within the 0x4000
            // region against a live 0705 capture (co-located vs a fixed sub-addr).
            let addr_cnt = self.memory.read(u32::from(addr_base), 1)[0] as u16;
            let go_base = addr_base.wrapping_add(1).wrapping_add(addr_cnt * 2);
            let gc = sys7_group_comm::Sys7GroupComm::from_tables(
                &self.memory,
                addr_base,
                assoc_base,
                go_base,
            );
            self.group_comm = if gc.is_empty() { None } else { Some(gc) };
            return;
        }
        let tables_loaded = [1u8, 2, 3]
            .iter()
            .all(|&i| self.load_state(i) == Some(LoadState::Loaded));
        if !tables_loaded {
            self.group_comm = None;
            return;
        }
        let (Some(addr_base), Some(assoc_base), Some(comobj_base)) =
            (self.base_of(1), self.base_of(2), self.base_of(3))
        else {
            self.group_comm = None;
            return;
        };
        let gc =
            group_comm::GroupComm::from_tables(&self.memory, addr_base, assoc_base, comobj_base);
        self.group_comm = if gc.is_empty() { None } else { Some(gc) };
    }

    /// Handle an inbound **group** telegram addressed to `ga`, updating the
    /// device's com-objects and producing any response the device must send.
    ///
    /// Returns the response telegrams (an `A_GroupValue_Response` when the device
    /// holds the Read flag on the read GA). A device that is not loaded, not
    /// linked, or not associated with `ga` returns nothing — exactly as a real
    /// device silently ignores group traffic it does not subscribe to.
    pub fn handle_group(&mut self, apci: Apci, ga: GroupAddress, payload: &[u8]) -> Vec<CemiLData> {
        let Some(gc) = self.group_comm.as_mut() else {
            return Vec::new();
        };
        match apci {
            Apci::GroupValueWrite => {
                let updated = gc.on_group_write(ga, payload);
                for asap in updated {
                    self.emit(Event::GroupObjectUpdated {
                        device: self.address,
                        object: asap,
                        ga: ga.raw(),
                    });
                }
                Vec::new()
            }
            Apci::GroupValueRead => match gc.on_group_read(ga) {
                Some(value) => vec![self.group_telegram(Apci::GroupValueResponse, ga, &value)],
                None => Vec::new(),
            },
            // A device ignores responses/writes it did not solicit beyond the
            // write handling above; other services never reach the group path.
            _ => Vec::new(),
        }
    }

    /// Build an outgoing group telegram (`L_Data.ind`) from this device: an
    /// `A_GroupValue_Write`/`_Response` to `ga` carrying `payload`.
    ///
    /// A sub-byte payload (a single octet `<= 0x3F`) is packed into the APCI low
    /// bits (the "small" APDU form), matching how a real device and the tool
    /// encode a 1-bit DPT; anything else rides as separate data octets.
    pub fn group_telegram(&self, apci: Apci, ga: GroupAddress, payload: &[u8]) -> CemiLData {
        let apci10 = apci.to_u10();
        let packable = payload.len() == 1 && payload[0] <= 0x3F;
        let tpdu = if packable {
            // Small form: TPCI DataGroup (0x00) + APCI high bits; second octet is
            // APCI low bits with the 6-bit value packed in.
            vec![
                (apci10 >> 8) as u8 & 0x03,
                ((apci10 & 0xC0) as u8) | (payload[0] & 0x3F),
            ]
        } else {
            let mut t = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
            t.extend_from_slice(payload);
            t
        };
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0xe0, // group destination (bit 7) + hop count 6
            source: self.address,
            dest: ga.raw(),
            tpdu,
        }
    }

    /// Whether the device may transmit on `object`, and if so its sending GA:
    /// used by scripted stimulus to address a periodic transmit.
    pub fn stimulus_send_ga(&self, object: u16) -> Option<GroupAddress> {
        self.group_comm.as_ref().and_then(|gc| gc.send_ga(object))
    }

    /// Seed a transmitting com-object's value and build the group telegram that
    /// pushes it onto the bus, or `None` if the object cannot transmit (not
    /// loaded, not linked, or lacks the Transmit flag). Used by stimulus.
    pub fn emit_stimulus(&mut self, object: u16, payload: &[u8]) -> Option<CemiLData> {
        let ga = self.stimulus_send_ga(object)?;
        if let Some(gc) = self.group_comm.as_mut() {
            gc.set_value(object, payload);
        }
        Some(self.group_telegram(Apci::GroupValueWrite, ga, payload))
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
                // A fresh transport connection resets both sequence counters to 0
                // (KNX style-1 rationalised: T_Connect restarts the numbering).
                self.rx_seq = 0;
                // A fresh connection also resets the per-connection exchange
                // budget: each L4 connection gets its own allowance, so a tool
                // that periodically reconnects (as ETS does) never exhausts it.
                self.l4_exchanges = 0;
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
            Tpci::DataUnnumbered => {
                // Unnumbered (broadcast/individual) data carries no L4 sequence.
                let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
                    service: "APDU".into(),
                    detail: "too short".into(),
                })?;
                self.handle_apdu(cemi, &apdu)
            }
            Tpci::DataConnected(seq) => self.handle_numbered_data(cemi, seq),
        }
    }

    /// Handle a numbered data telegram (NDT) with strict L4 sequence checking.
    ///
    /// KNX style-1 rationalised transport, device side (the mirror of bussard's
    /// `Layer4Connection`):
    ///
    /// - **Expected sequence** (`seq == rx_seq`): process the APDU, advance the
    ///   receive sequence, and acknowledge. Verbs that carry their own
    ///   application-layer response (property read/write, authorize,
    ///   device-descriptor, master-reset) let that response stand as the
    ///   acknowledgement — the response NDT's arrival is what the tool waits on.
    ///   Response-less verbs (`A_MemoryWrite`, a bare `A_Restart`) get an explicit
    ///   `T_ACK(seq)` so the tool is not left retransmitting.
    /// - **Duplicate of the last accepted frame** (`seq == rx_seq - 1` mod 16): a
    ///   retransmit whose `T_ACK` the tool missed. Re-acknowledge with `T_ACK(seq)`
    ///   but do **not** reprocess it (idempotency — reprocessing a memory write or
    ///   double-advancing state would corrupt the session).
    /// - **Anything else** (out of window): ignore silently, exactly as a real
    ///   device does — it neither ACKs nor processes an unexpected sequence, so a
    ///   tool that desynced its send sequence stalls here rather than being
    ///   quietly tolerated. This makes any bussard L4 sequencing bug reproduce
    ///   locally.
    fn handle_numbered_data(
        &mut self,
        cemi: &CemiLData,
        seq: u8,
    ) -> Result<DeviceReaction, DeviceError> {
        let tool = cemi.source;

        // A retransmit of the frame we last accepted: re-ACK, do not reprocess.
        let last_accepted = self.rx_seq.wrapping_sub(1) & 0x0F;
        if seq == last_accepted {
            return Ok(DeviceReaction {
                responses: vec![self.t_ack(tool, seq)],
                did_master_reset: false,
            });
        }

        // Out-of-window sequence: a strict device ignores it entirely.
        if seq != self.rx_seq {
            self.emit(Event::Telegram {
                direction: crate::bus::event::Direction::ToBus,
                cemi: cemi.encode(),
                summary: format!(
                    "DROPPED by {}: out-of-sequence NDT seq {seq} (expected {})",
                    self.address, self.rx_seq
                ),
            });
            return Ok(DeviceReaction::default());
        }

        // Per-connection exchange budget: a real connection-oriented device drops
        // a long-held L4 connection after a bounded number of numbered exchanges
        // (KNX Virtual DA.tp drops at ~35). This expected-sequence NDT is one such
        // exchange; if accepting it would exceed the budget, the device drops the
        // connection instead — it stops answering entirely (silence), exactly as
        // the real device does, so the tool sees "device absent" unless it cycled
        // the connection in time. Reset per connection on T_Connect. `None` =
        // unlimited (the default), leaving existing behaviour unchanged.
        if let Some(budget) = self.l4_exchange_budget {
            if self.l4_exchanges >= budget {
                self.connected = false;
                self.emit(Event::Telegram {
                    direction: crate::bus::event::Direction::ToBus,
                    cemi: cemi.encode(),
                    summary: format!(
                        "DROPPED by {}: L4 exchange budget {budget} exhausted; connection dropped",
                        self.address
                    ),
                });
                return Ok(DeviceReaction::default());
            }
            self.l4_exchanges += 1;
        }

        // Expected sequence: parse, process, advance, acknowledge.
        let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
            service: "APDU".into(),
            detail: "too short".into(),
        })?;
        self.rx_seq = (self.rx_seq + 1) & 0x0F;
        let mut reaction = self.handle_apdu(cemi, &apdu)?;
        if reaction.responses.is_empty() {
            reaction.responses.push(self.t_ack(tool, seq));
        }
        Ok(reaction)
    }

    /// Build a transport-layer `T_ACK(seq)` frame back toward `to`.
    ///
    /// A real device T_ACKs every numbered data telegram at the transport layer,
    /// including an `A_Restart` — which, unlike a property/memory verb, carries no
    /// application-layer response. The management tool waits for that T_ACK before
    /// it considers the restart delivered (see bussard's
    /// `master_reset_via_basic_restart`), so the simulator must emit it before it
    /// reboots and drops the connection, or the tool retransmits into the void.
    fn t_ack(&self, to: IndividualAddress, seq: u8) -> CemiLData {
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu: vec![Tpci::ack_byte(seq)],
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
        // System 7 wire strictness (spec section 6): a memory op to a System 7
        // device must ride a STANDARD frame and carry at most 12 data octets. An
        // extended cEMI frame or a >12-octet memory op is exactly the trap that
        // catches a tool wrongly sending 63-byte chunks; a real device refuses it.
        if self.profile.is_system7()
            && matches!(apdu.apci, Apci::MemoryRead(_) | Apci::MemoryWrite(_))
        {
            let count = apdu.memory_count() as usize;
            if !cemi.is_standard_frame() {
                return Err(DeviceError::WireStrictness {
                    detail: "System 7 memory op on an extended frame".into(),
                });
            }
            if count > SYS7_MAX_MEMORY_CHUNK {
                return Err(DeviceError::WireStrictness {
                    detail: format!(
                        "System 7 memory op count {count} exceeds the {SYS7_MAX_MEMORY_CHUNK}-octet \
                         standard-frame ceiling"
                    ),
                });
            }
        }
        match apdu.apci {
            Apci::AuthorizeRequest => self.on_authorize(tool, apdu),
            Apci::PropertyValueRead => self.on_property_read(tool, apdu),
            Apci::PropertyValueWrite => self.on_property_write(tool, apdu),
            Apci::MemoryRead(_) => self.on_memory_read(tool, apdu),
            Apci::MemoryWrite(_) => self.on_memory_write(tool, apdu),
            Apci::MemoryExtendedWrite => self.on_memory_extended_write(tool, apdu),
            Apci::MemoryExtendedRead => self.on_memory_extended_read(tool, apdu),
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
        // A_Authorize_Request: data = [reserved, key(4 BE)]. On a free-access
        // device any key unlocks to level 0 (the DA.tp capture uses FF FF FF FF).
        // On a keyed System 7 device the presented key must match the configured
        // BCU key (or be the free-access key) to grant level 0; otherwise the
        // device grants the "failed" level 15, and subsequent memory writes are
        // refused as unauthorized.
        if apdu.data.len() < 5 {
            return Err(DeviceError::Malformed {
                service: "A_Authorize".into(),
                detail: "expected 5 data bytes".into(),
            });
        }
        let key = u32::from_be_bytes([apdu.data[1], apdu.data[2], apdu.data[3], apdu.data[4]]);
        let granted = match self.profile.system7().and_then(|p| p.bcu_key) {
            // Keyed device: match the key (free-access key always accepted).
            Some(required) if key != required && key != FREE_ACCESS_KEY => 15,
            _ => 0,
        };
        self.access_level = granted;
        self.emit(Event::AuthChanged {
            device: self.address,
            level: granted,
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
        } else if pid == PID_MCB_TABLE {
            // PID_MCB_TABLE (27) is device-computed: answer with the 8-octet
            // memory-control-block entry (size + CRC-16/AUG-CCITT) over the bytes
            // this object currently holds in its allocated segment. A tool's
            // LdCtrlLoadImageProp verify step reads this back and compares the CRC
            // to the image it streamed, so it must reflect the real stored bytes.
            self.mcb_entry_for(object)
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
            // A System 7 device configured for property-based LSM access decodes
            // the 10-octet load event straight from the PID 5 value and drives the
            // addressed LSM (spec section 5, LsmAccess::Property). A System 7
            // device configured memory-mapped refuses a PID 5 load write — a real
            // memory-mapped device does not accept it, so a tool that used the
            // wrong realisation is caught.
            if let Some(s7) = &self.sys7 {
                if s7.profile.lsm_access == profile::LsmAccess::Property {
                    self.apply_sys7_event(tool, object, value)?;
                    // Property-based LSM write echoes the resulting state.
                    let state = self.load_state(object).unwrap_or(LoadState::Error);
                    let mut data = vec![
                        object,
                        PID_LOAD_STATE_CONTROL,
                        (count << 4) | ((start >> 8) as u8 & 0x0F),
                        (start & 0xFF) as u8,
                    ];
                    data.push(state.to_byte());
                    let resp = self.respond(tool, 0x3D6, &data);
                    return Ok(DeviceReaction {
                        responses: vec![resp],
                        did_master_reset: false,
                    });
                }
                return Err(DeviceError::LoadControl(
                    "System 7 memory-mapped device does not accept a PID 5 load write".into(),
                ));
            }
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
        // Reaching Loaded on a table object may complete the device's group
        // configuration: reconstruct its runtime routing from the freshly-written
        // tables (a no-op until obj1/2/3 are all Loaded). A LoadCompleted that
        // does not finish the set leaves the device silent.
        if new_state == LoadState::Loaded {
            self.refresh_group_comm();
        }
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

    /// Apply a System 7 load event (10-octet record) to the addressed LSM,
    /// wiring the side effects: AbsSegment allocation reserves the memory
    /// segment; TaskSegment commits the descriptor; LoadCompleted may complete
    /// the group configuration. Shared by both LSM-access realisations.
    fn apply_sys7_event(
        &mut self,
        _tool: IndividualAddress,
        lsm_index: u8,
        event_record: &[u8],
    ) -> Result<(), DeviceError> {
        let event = sys7_lsm::Sys7Event::decode(event_record)
            .map_err(|e| DeviceError::LoadControl(e.to_string()))?;
        let s7 = self
            .sys7
            .as_mut()
            .ok_or_else(|| DeviceError::LoadControl("not a System 7 device".into()))?;
        let lsm = s7.lsms.get_mut(&lsm_index).ok_or(DeviceError::NoProperty {
            object: lsm_index,
            pid: PID_LOAD_STATE_CONTROL,
        })?;
        let step = match lsm.apply(event) {
            Ok(s) => s,
            Err(e) => {
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object: lsm_index,
                    state: LoadState::Error.to_byte(),
                });
                return Err(DeviceError::LoadControl(e.to_string()));
            }
        };
        match step {
            Sys7Step::Alloc {
                start,
                length,
                subtype,
            } => {
                // Reserve the absolute segment for this LSM. A subtype-0x02 (Task)
                // record with a base already allocated for the LSM is a descriptor
                // commit rather than a fresh allocation, so only (re)allocate when
                // the address is not already inside the LSM's open segment.
                let start = u32::from(start);
                let already = self
                    .memory
                    .segment_of(lsm_index)
                    .is_some_and(|seg| seg.contains(start, 1));
                if !(subtype == 0x02 && already) {
                    self.memory.allocate(lsm_index, start, length as u32);
                }
            }
            Sys7Step::TaskCommitted { address: _ } => {
                // The descriptor is committed inside the LSM; no memory side effect
                // in the M1 model (the sim treats it as a precondition flag).
            }
            Sys7Step::TaskCtrl1 {
                address: _,
                count: _,
            } => {
                // A task-control-1 entry (spec §4.4, Jung M-0004_A-A011): accepted
                // while Loading with no memory side effect in the M1 model.
            }
            Sys7Step::State(new_state) => {
                self.emit(Event::LoadStateChanged {
                    device: self.address,
                    object: lsm_index,
                    state: new_state.to_byte(),
                });
                if new_state == LoadState::Loaded {
                    self.refresh_group_comm();
                }
            }
            Sys7Step::NoOp => {}
        }
        Ok(())
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
        // System 7 memory-mapped LSM status poll: a read at the status address
        // returns the addressed LSM's live state (spec section 5). The per-LSM
        // status byte is at `status_addr + (lsm_index - 1)`.
        let bytes = if let Some(status) = self.sys7_status_bytes(addr, n) {
            status
        } else {
            self.memory.read(u32::from(addr), n)
        };
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

    /// If `addr` falls in the System 7 memory-mapped LSM status region, return
    /// the `n` status bytes (one live LSM state per octet), else `None`.
    fn sys7_status_bytes(&self, addr: u16, n: usize) -> Option<Vec<u8>> {
        let s7 = self.sys7.as_ref()?;
        if s7.profile.lsm_access != profile::LsmAccess::MemoryMapped {
            return None;
        }
        let base = s7.profile.mm_lsm.status_addr;
        // The status region spans one octet per LSM index starting at `base`
        // (index 1 at base+0). Only serve reads wholly inside that region.
        let region_len = s7.lsms.keys().copied().max().unwrap_or(0) as usize;
        let end = base as u32 + region_len as u32;
        if (addr as u32) < base as u32 || (addr as u32 + n as u32) > end.max(base as u32 + 1) {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let lsm_index = (addr.wrapping_add(i as u16).wrapping_sub(base)) as u8 + 1;
            let state = self
                .load_state(lsm_index)
                .map(|s| s.to_byte())
                .unwrap_or(0x00);
            out.push(state);
        }
        Some(out)
    }

    fn on_memory_write(
        &mut self,
        tool: IndividualAddress,
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

        // System 7 memory-mapped LSM control: a write to the LSM control address
        // is a load-event record, not a segment write (spec section 5). Decode and
        // drive the addressed LSM.
        if let Some(s7) = &self.sys7 {
            if s7.profile.lsm_access == profile::LsmAccess::MemoryMapped
                && addr == s7.profile.mm_lsm.control_addr
            {
                return self.on_sys7_lsm_record(tool, payload);
            }
        }

        // Determine which object owns this address: strict — the address must be
        // inside exactly one open segment, and that object must be Loading.
        let addr32 = u32::from(addr);
        let seg = self
            .memory
            .segment_at(addr32)
            .ok_or(MemoryError::OutOfSegment {
                addr: addr32,
                len: n,
            })?;
        let owner = seg.owner;
        if self.load_state(owner) != Some(LoadState::Loading) {
            return Err(DeviceError::LoadControl(format!(
                "memory write to object {owner} while not Loading"
            )));
        }
        self.memory.write(owner, addr32, payload)?;
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr: addr32,
            len: n,
        });
        // A_MemoryWrite is not acknowledged at the application layer in the
        // captured flow (the tool relies on the transport T_ACK), so no APDU
        // response is produced.
        Ok(DeviceReaction::default())
    }

    /// Handle an `A_MemoryExtended_Write` (APCI 0x1FB): the System B extended
    /// memory service ETS drives every capable 07B0 device with (verified against
    /// four real ETS6 downloads). The payload is `[count][addr:3 BE][data]`, so
    /// this reaches the 24-bit space a plain `A_Memory_Write` cannot. It is
    /// bounded and access-checked exactly like [`on_memory_write`]: the address
    /// must fall inside exactly one open segment whose owner is Loading. Unlike
    /// the plain write it is confirmed **inline** with an
    /// `A_MemoryExtended_Write_Response` (0x1FC) carrying a return code (0 = ok)
    /// and the echoed address, so no separate read-back is needed.
    fn on_memory_extended_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }
        let req = bussard_extended_request(&apdu.data, true).ok_or(DeviceError::Malformed {
            service: "A_MemoryExtended_Write".into(),
            detail: "payload shorter than [count][addr:3] or truncated data".into(),
        })?;
        let addr = req.addr;
        let n = req.data.len();

        // Same strict segment/ownership discipline as the plain write.
        let seg = self
            .memory
            .segment_at(addr)
            .ok_or(MemoryError::OutOfSegment { addr, len: n })?;
        let owner = seg.owner;
        if self.load_state(owner) != Some(LoadState::Loading) {
            return Err(DeviceError::LoadControl(format!(
                "extended memory write to object {owner} while not Loading"
            )));
        }
        self.memory.write(owner, addr, &req.data)?;
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr,
            len: n,
        });
        // Confirm inline: return code 0x00 + echoed 3-octet address.
        let mut data = Vec::with_capacity(4);
        data.push(0x00);
        data.extend_from_slice(&[(addr >> 16) as u8, (addr >> 8) as u8, addr as u8]);
        let resp = self.respond(tool, Apci::MemoryExtendedWriteResponse.to_u10(), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Handle an `A_MemoryExtended_Read` (APCI 0x1FD): read `count` octets at the
    /// 24-bit address and answer with an `A_MemoryExtended_Read_Response` (0x1FE)
    /// carrying `[return_code][addr:3][data]`. The read is served from the sparse
    /// memory (unwritten cells read back as 0x00), modelling verify-on-read for
    /// the tool. No segment gate on reads — a tool verifies freely.
    fn on_memory_extended_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let req = bussard_extended_request(&apdu.data, false).ok_or(DeviceError::Malformed {
            service: "A_MemoryExtended_Read".into(),
            detail: "payload shorter than [count][addr:3]".into(),
        })?;
        let addr = req.addr;
        let bytes = self.memory.read(addr, req.count as usize);
        let mut data = Vec::with_capacity(4 + bytes.len());
        data.push(0x00);
        data.extend_from_slice(&[(addr >> 16) as u8, (addr >> 8) as u8, addr as u8]);
        data.extend_from_slice(&bytes);
        let resp = self.respond(tool, Apci::MemoryExtendedReadResponse.to_u10(), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Apply a System 7 memory-mapped LSM control record (the **11-octet** form
    /// written to the control address, spec section 5). The encoding is confirmed
    /// by the Theben 0701 Meteodata capture:
    /// ```text
    /// [0] (lsm_index << 4) | event_opcode   [1] subtype   [2] 0x00 (addr high)
    /// [3..5] start:2 BE   [5..7] length:2 BE   [7..11] tail
    /// ```
    /// The LSM index is folded into the high nibble of the event byte — there is
    /// NO separate `[lsm][00]` prefix. This is the memory-mapped device side, used
    /// by a device configured `lsm_access: memory` (the Theben 0701 family); the
    /// Jung 0705 family is property-based (`on_sys7_property_lsm`).
    fn on_sys7_lsm_record(
        &mut self,
        tool: IndividualAddress,
        record: &[u8],
    ) -> Result<DeviceReaction, DeviceError> {
        let (lsm_index, event_record) =
            sys7_lsm::decode_memory_lsm_record(record).map_err(|e| DeviceError::Malformed {
                service: "System7 LSM record".into(),
                detail: e.to_string(),
            })?;
        self.apply_sys7_event(tool, lsm_index, &event_record)?;
        // A memory-mapped LSM write is unconfirmed at the application layer (the
        // tool polls the status address); no APDU response.
        Ok(DeviceReaction::default())
    }

    fn on_device_descriptor_read(
        &mut self,
        tool: IndividualAddress,
        dtype: u8,
    ) -> Result<DeviceReaction, DeviceError> {
        // Descriptor type 0 → mask version. A real device reports its true mask;
        // the profile carries it (0x07B0 System B, 0x0705/0x0701 System 7).
        let mask: u16 = self.profile.mask();
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

    /// Build a connected NDT at the device's **currently expected** receive
    /// sequence, so a sequence of `handle_cemi(&data(&dev, ...))` calls carries a
    /// correctly-incrementing L4 sequence (matching what a real tool sends). The
    /// device advances `rx_seq` as it accepts each frame.
    fn data(dev: &Device, apci10: u16, payload: &[u8]) -> CemiLData {
        data_seq(dev, dev.rx_seq, apci10, payload)
    }

    /// Build a connected NDT at an explicit sequence (for out-of-order tests).
    fn data_seq(dev: &Device, seq: u8, apci10: u16, payload: &[u8]) -> CemiLData {
        let mut tpdu = vec![
            0x40 | ((seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
            (apci10 & 0xFF) as u8,
        ];
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
        // 3:group-object-table, 4:application-program]. The object that owns the
        // application code segment (LSM index 4 at base 0x6000) is the
        // application-program object (type 3), and the com-object table (LSM index
        // 3 at 0x8000) is the group-object-table object (type 9) — so a tool's
        // MCB image-integrity read lands on the object that actually holds each
        // segment.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let expected: [(u8, u16); 5] = [
            (0, iot::DEVICE),
            (1, iot::ADDRESS_TABLE),
            (2, iot::ASSOCIATION_TABLE),
            (3, iot::GROUP_OBJECT_TABLE),
            (4, iot::APPLICATION_PROGRAM),
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
    fn test_l4_duplicate_ndt_is_reacked_not_reprocessed() -> Result<(), Box<dyn std::error::Error>>
    {
        // A retransmit of the last-accepted NDT (its T_ACK was lost) must be
        // re-acknowledged with the SAME sequence but NOT reprocessed. We use an
        // authorize at seq 0 (auth -> level 0), then replay the identical seq-0
        // frame: the replay must produce a bare T_ACK(0), not a second authorize
        // response, and must not advance rx_seq.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        assert_eq!(dev.rx_seq, 0);
        let auth = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&auth)?;
        assert_eq!(
            r.responses.len(),
            1,
            "authorize answers with a response NDT"
        );
        assert_eq!(dev.rx_seq, 1, "rx_seq advanced past the accepted frame");

        // Replay the exact same seq-0 frame (a retransmit).
        let replay = data_seq(&dev, 0, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r2 = dev.handle_cemi(&replay)?;
        assert_eq!(r2.responses.len(), 1, "duplicate is re-acknowledged");
        // The re-ACK is a bare transport T_ACK(0), not an application response.
        assert_eq!(r2.responses[0].tpdu, vec![Tpci::ack_byte(0)]);
        assert_eq!(dev.rx_seq, 1, "duplicate must not advance rx_seq");
        Ok(())
    }

    #[test]
    fn test_l4_out_of_sequence_ndt_is_dropped() -> Result<(), Box<dyn std::error::Error>> {
        // An NDT with an unexpected sequence (neither the expected one nor the
        // last-accepted duplicate) is ignored entirely: no response at all, and
        // rx_seq does not move. This is how a real device behaves, so a bussard
        // L4 desync reproduces here rather than being silently tolerated.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Expected seq is 0; send seq 5 (off-window).
        let stray = data_seq(&dev, 5, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&stray)?;
        assert!(
            r.responses.is_empty(),
            "out-of-sequence NDT draws no response"
        );
        assert_eq!(dev.rx_seq, 0, "rx_seq unchanged by an ignored frame");
        assert_eq!(
            dev.access_level, 15,
            "the stray authorize was not processed"
        );
        Ok(())
    }

    #[test]
    fn test_l4_sequence_advances_across_a_wrap() -> Result<(), Box<dyn std::error::Error>> {
        // Drive 18 accepted device-descriptor reads so the receive sequence wraps
        // past 15 back through 0 and 1. Each read is at the expected sequence
        // (data() threads dev.rx_seq), so every one must be accepted and answered,
        // and rx_seq must land at 18 mod 16 = 2.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        for i in 0..18u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "descriptor read {i} must be accepted and answered"
            );
        }
        assert_eq!(dev.rx_seq, 2, "18 accepted NDTs wrap rx_seq to 2");
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_drops_connection_after_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        // A device with a per-connection exchange budget drops the connection —
        // stops answering — once that many numbered exchanges have been accepted on
        // one connection, modelling a real connection-oriented device's
        // per-connection resource limit (KNX Virtual drops at ~35). Set a low
        // budget (3) and drive descriptor reads: the first 3 are answered, the 4th
        // and beyond draw no response and the device is no longer connected.
        let Some(dev) = da_tp_device()? else {
            return Ok(());
        };
        let mut dev = dev.with_l4_exchange_budget(Some(3));
        connect(&mut dev)?;
        for i in 0..3u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "exchange {i} is within budget and must be answered"
            );
        }
        // The 4th exchange exceeds the budget: the device drops the connection.
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert!(
            r.responses.is_empty(),
            "the over-budget exchange must draw no response (connection dropped)"
        );
        assert!(
            !dev.connected,
            "exceeding the budget drops the L4 connection"
        );
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_resets_on_reconnect() -> Result<(), Box<dyn std::error::Error>> {
        // The per-connection budget is per CONNECTION: a fresh T_Connect resets it,
        // so a tool that reconnects before exhausting the budget keeps being
        // served. Drive the budget to exhaustion, then reconnect and confirm the
        // device answers again — the persistent object state is unchanged.
        let Some(dev) = da_tp_device()? else {
            return Ok(());
        };
        let mut dev = dev.with_l4_exchange_budget(Some(2));
        connect(&mut dev)?;
        for _ in 0..2u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(r.responses.len(), 1);
        }
        // Over budget: dropped.
        assert!(
            dev.handle_cemi(&data(&dev, 0x300, &[]))?
                .responses
                .is_empty()
        );
        // Reconnect: a fresh window resets the budget and the device serves again.
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
        assert_eq!(
            r.responses.len(),
            1,
            "a fresh connection resets the budget and the device answers again"
        );
        Ok(())
    }

    #[test]
    fn test_l4_exchange_budget_unlimited_by_default() -> Result<(), Box<dyn std::error::Error>> {
        // The default budget is unlimited: without `with_l4_exchange_budget`, a
        // long run of exchanges on one connection is served in full (existing tests
        // and captures are unaffected).
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        for i in 0..40u16 {
            let r = dev.handle_cemi(&data(&dev, 0x300, &[]))?;
            assert_eq!(
                r.responses.len(),
                1,
                "exchange {i} must be answered under the default unlimited budget"
            );
        }
        assert!(dev.connected, "the connection stays up under no budget");
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

    mod sys7 {
        use super::*;
        use crate::device::profile::LsmAccess;

        /// Build a System 7 device from the synthetic MDT-canonical product (no
        /// fixture needed), at 1.1.5, starting Unloaded.
        fn sys7_device(access: LsmAccess) -> Device {
            let product = crate::testfixtures::synthetic_mdt_sys7_product();
            Device::from_product_with_overrides(
                IndividualAddress::new(1, 1, 5),
                &product,
                LoadState::Unloaded,
                ProfileOverrides {
                    mask: None,
                    lsm_access: access,
                    bcu_key: None,
                },
                std::sync::Arc::new(RecordingSink::new()),
            )
            .expect("System 7 device builds")
        }

        #[test]
        fn test_sys7_profile_selected_from_product_mask() {
            let dev = sys7_device(LsmAccess::MemoryMapped);
            assert!(dev.profile().is_system7());
            assert_eq!(dev.profile().mask(), 0x0705);
            // The three canonical LSMs exist and start Unloaded.
            for lsm in [1u8, 2, 3] {
                assert_eq!(dev.load_state(lsm), Some(LoadState::Unloaded));
            }
        }

        #[test]
        fn test_unmodelled_mask_override_is_refused() {
            // A mask override to an unmodelled family is refused — a strict
            // simulator will not pretend to be a device generation it lacks.
            let product = crate::testfixtures::synthetic_mdt_sys7_product();
            let err = Device::from_product_with_overrides(
                IndividualAddress::new(1, 1, 5),
                &product,
                LoadState::Unloaded,
                ProfileOverrides {
                    mask: Some("0012".into()),
                    ..Default::default()
                },
                std::sync::Arc::new(RecordingSink::new()),
            );
            assert!(err.is_err(), "unmodelled mask must be refused");
        }

        #[test]
        fn test_sys7_pid78_preflight_value_is_readable() -> Result<(), Box<dyn std::error::Error>> {
            // Object-0 PID 78 (PID_HARDWARE_TYPE) serves the 10-octet preflight
            // value the MDT CompareProp matches. App 14 seeds byte 5 = 0x0E.
            let mut dev = sys7_device(LsmAccess::MemoryMapped);
            connect(&mut dev)?;
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x00, 0x4E, 0x10, 0x01]))?;
            let value = prop_response_value(&r);
            assert_eq!(value.len(), 10, "PID 78 is a 10-octet value");
            assert_eq!(value[4], 0x03, "byte 4 is the run-state marker");
            Ok(())
        }

        #[test]
        fn test_sys7_serves_mcb_table_after_load() -> Result<(), Box<dyn std::error::Error>> {
            // A System 7 device serves PID_MCB_TABLE (27) per loadable object,
            // computed over the written segment memory (Jung A-A011 uses
            // LoadImageProp on System 7). Drive LSM 1 to hold real bytes, then read
            // PID 27 and expect an 8-octet integrity block whose CRC matches.
            let mut dev = sys7_device(LsmAccess::MemoryMapped);
            connect(&mut dev)?;
            dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
            // StartLoading + alloc LSM 1 at 0x4000 via the 11-octet memory record
            // (LSM in the high nibble of octet 0, 3-octet start address).
            let start_rec = [0x11u8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
            dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &start_rec))?;
            let alloc_rec = [
                0x13u8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
            ];
            dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &alloc_rec))?;
            // Write 8 bytes into the segment.
            dev.handle_cemi(&mem_write_frame(&dev, 0x4000, &[1, 2, 3, 4, 5, 6, 7, 8]))?;
            // Read PID_MCB_TABLE (27) on object 1.
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x10, 0x01]))?;
            let mcb = prop_response_value(&r);
            assert_eq!(mcb.len(), MCB_ENTRY_LEN, "MCB entry is 8 octets");
            // The size field is the 8 written bytes; the CRC matches an independent
            // computation over those bytes.
            assert_eq!(&mcb[0..4], &[0, 0, 0, 8]);
            let crc = crc16_aug_ccitt(&[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(&mcb[6..8], &crc.to_be_bytes());
            Ok(())
        }

        /// Build a standard-frame A_MemoryWrite NDT at the device's expected seq.
        fn mem_write_frame(dev: &Device, addr: u16, payload: &[u8]) -> CemiLData {
            let apci10 = 0x280 | (payload.len() as u16 & 0x3F);
            let mut d = addr.to_be_bytes().to_vec();
            d.extend_from_slice(payload);
            data(dev, apci10, &d)
        }
    }
}
