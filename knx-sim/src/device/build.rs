//! Device construction: builds the System B and System 7 device cores from a
//! product (interface objects, memory segments, load-state machines).

use std::collections::BTreeMap;

use crate::bus::event::EventSink;
use crate::prod::{LoadableObject, ProductData};
use crate::wire::IndividualAddress;

use super::{
    DEFAULT_RESTART_PROCESS_TIME_S, Device, InterfaceObject, LoadState, LoadStateMachine, Memory,
    ObjectState, PID_LOAD_STATE_CONTROL, PID_OBJECT_TYPE, PID_PROGMODE, PID_RUN_STATE_CONTROL,
    PID_TABLE_REFERENCE, Profile, Property, SecurityObject, Sys7LoadStateMachine, Sys7Runtime, iot,
    profile,
};

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
    /// Build the System B device (the original construction path).
    pub(super) fn build_system_b(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        profile: Profile,
        prog_mode: bool,
        secure: Option<crate::secure::DataSecureSession>,
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
        // Seed PID_PROGMODE consistent with the initial programming-mode bit so a
        // property read agrees with the broadcast-read behaviour.
        device_object.set_property(PID_PROGMODE, Property::writable(vec![u8::from(prog_mode)]));
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
            prog_mode,
            security_object: secure.as_ref().map(|_| SecurityObject::new_activated()),
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
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
    pub(super) fn build_system7(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        profile: Profile,
        prog_mode: bool,
        secure: Option<crate::secure::DataSecureSession>,
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
        device_object.set_property(PID_PROGMODE, Property::writable(vec![u8::from(prog_mode)]));
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
            prog_mode,
            security_object: secure.as_ref().map(|_| SecurityObject::new_activated()),
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            events,
        };
        device.refresh_group_comm();
        device
    }
}
