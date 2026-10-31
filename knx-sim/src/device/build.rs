//! Device construction: builds the System B and System 7 device cores from a
//! product (interface objects, memory segments, load-state machines).

use std::collections::BTreeMap;

use crate::bus::event::EventSink;
use crate::prod::{LoadableObject, ProductData};
use crate::wire::IndividualAddress;

use super::{
    DEFAULT_RESTART_PROCESS_TIME_S, Device, InterfaceObject, LoadState, LoadStateMachine, Memory,
    ObjectState, PID_LOAD_STATE_CONTROL, PID_OBJECT_TYPE, PID_PROGMODE, PID_PROGRAM_VERSION,
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

/// The first `PID_OBJECT_TYPE` of the manufacturer-specific range (KNX
/// Resources 03.05.01: object types 50000 to 65535 are the manufacturer's).
const MANUFACTURER_OBJECT_TYPE_BASE: u16 = 50000;

/// The index of the first interface object beyond the system objects a System
/// B device models (0 device, 1 address table, 2 association table, 3
/// group-object table, 4 application program, 5 KNX-object association
/// table).
const FIRST_APPLICATION_OBJECT: u8 = 6;

/// The `PID_OBJECT_TYPE` of an interface object the device creates only
/// because the application's load procedure addresses it (bussard issue
/// #422). The type a procedure step declares for that index (`ObjType`
/// beside `ObjIdx`) wins. A system index (0 to 5) keeps its system type.
/// Any other object is an application object whose type the product does
/// not say: it reports the manufacturer-specific type `50000 + index`, a
/// value no standard object type uses, so a tool that walks the object table
/// sees an object it does not know rather than a standard one (index 7 as
/// type 7 would claim an LTE address routing table).
fn procedure_object_type(product: &ProductData, object_index: u8) -> u16 {
    if let Some(&(_, object_type)) = product
        .object_types
        .iter()
        .find(|&&(o, _)| o == object_index)
    {
        return object_type;
    }
    if object_index < FIRST_APPLICATION_OBJECT {
        object_type_for(object_index)
    } else {
        MANUFACTURER_OBJECT_TYPE_BASE + u16::from(object_index)
    }
}

/// Seeds the interface objects and properties the application's own load
/// procedure addresses by index, beyond the ones the device already models.
///
/// - Every property an `LdCtrlCompareProp` preflight compares holds the value
///   the compare expects (bussard issue #390: the ABB 0701 programs compare
///   object 3 PID 13, the application object's program version, with their
///   application number). The value under a `<choose>` is the one the
///   product's parameter defaults select (`ProductData::object_compare_props`,
///   picked by the same branch logic as the object-0 identity). A device of
///   that hardware holds them. A property the procedure also writes stays
///   writable.
/// - Every property an `LdCtrlWriteProp` step writes and the device does not
///   already serve is writable and zero, as long as its inline data: the real
///   hardware accepts those writes (an ABB i-bus program writes the PEI type
///   to object 4 or 5 PID 16 before its image, others object 0 PID 52 or 86),
///   and a write the simulated device refused would go unanswered and time
///   the flash out.
///
/// An object the device lacks is created, with a `PID_OBJECT_TYPE` from
/// [`procedure_object_type`], when its index is at least `first_new_object`.
/// System 7 passes 0 (bussard issue #390: the MDT 0705 programs write their
/// label texts to object 6). System B passes [`FIRST_APPLICATION_OBJECT`]
/// (bussard issue #422: the MDT Glass Touch Smart, mask 07B0, compares object
/// 7 PID 162 and writes object 7 PID 161, and ETS reads that property's
/// description before the write); a System B system object the product does
/// not load stays absent, as before.
///
/// The seeded properties are described with the generic PDT of their length
/// ([`Property::sized`]), the one fact the procedure gives about them; a
/// property a step writes with `Count` > 1 is that many elements of the
/// generic PDT of `len / Count` octets ([`Property::with_elements`], bussard
/// issue #692), so ETS, which reads the description first, writes it.
fn seed_procedure_props(
    objects: &mut BTreeMap<u8, InterfaceObject>,
    product: &ProductData,
    first_new_object: u8,
) {
    let addressed = product
        .object_compare_props
        .iter()
        .map(|(object, _, _)| *object)
        .chain(
            product
                .written_props
                .iter()
                .map(|&(object, _, _, _)| object),
        );
    for object in addressed {
        if object >= first_new_object && !objects.contains_key(&object) {
            let mut io = InterfaceObject::new();
            io.set_property(
                PID_OBJECT_TYPE,
                Property::read_only(
                    procedure_object_type(product, object)
                        .to_be_bytes()
                        .to_vec(),
                ),
            );
            objects.insert(object, io);
        }
    }
    for (object, pid, value) in &product.object_compare_props {
        let written = product
            .written_props
            .iter()
            .find(|&&(o, p, _, _)| o == *object && p == *pid);
        if let Some(io) = objects.get_mut(object) {
            let prop = match written {
                Some(&(_, _, _, count)) => Property::writable(value.clone()).with_elements(count),
                None => Property::read_only(value.clone()).sized(),
            };
            io.set_property(*pid, prop);
        }
    }
    for &(object, pid, len, count) in &product.written_props {
        if let Some(io) = objects.get_mut(&object)
            && !io.has_property(pid)
        {
            io.set_property(
                pid,
                Property::writable(vec![0x00; len]).with_elements(count),
            );
        }
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
        // The values the application's own CompareProp preflights expect win
        // over the stand-ins above: a factory device of this hardware holds them.
        for (pid, value) in &product.device_compare_props {
            device_object.set_property(*pid, Property::read_only(value.clone()));
        }
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
            // PID 0x0D (PID_PROGRAM_VERSION, the application id) is written near
            // the end of a flash to stamp the application id (ETS writes
            // `00 fa 25 00 10` on object 4). Seed it writable.
            io.set_property(PID_PROGRAM_VERSION, Property::writable(vec![0x00; 5]));
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

        seed_procedure_props(&mut objects, product, FIRST_APPLICATION_OBJECT);
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
            l4: Default::default(),
            group_comm: None,
            prog_mode,
            security_object: secure
                .as_ref()
                .map(|_| SecurityObject::new_activated().with_capacity(product.security_capacity)),
            knxnet_by_type: None,
            typed_objects: typed_objects_for(product, address, false).1,
            knxnet_slots: 0,
            ip_secure: None,
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            max_allocation: None,
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
        // The values the application's own CompareProp preflights expect win
        // over the stand-ins above: a factory device of this hardware holds them.
        for (pid, value) in &product.device_compare_props {
            device_object.set_property(*pid, Property::read_only(value.clone()));
        }
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
            // The TaskSegment precondition holds for an LSM the product's own
            // procedure finalises with one (the corpus norm, 47/49), or for
            // every LSM when the product carries no such procedure: a vendor
            // procedure that completes an LSM without one is what its
            // hardware accepts (ETS runs it verbatim).
            let lsm = if product
                .task_segment_lsms
                .as_ref()
                .is_none_or(|lsms| lsms.contains(&lsm_index))
            {
                Sys7LoadStateMachine::new(initial_state)
            } else {
                Sys7LoadStateMachine::without_task_segment(initial_state)
            };
            lsms.insert(lsm_index, lsm);
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

        seed_procedure_props(&mut objects, product, 0);
        // The application object always reports a program id (PID 13,
        // `mfr:2 app:2 version:1`, the BimM112 `ApplicationId`): ETS reads it
        // before a download to check the manufacturer, and an absent property
        // failed the ABB Room Master Premium (A-A054, 2026-10-28). A compare
        // step has already seeded it; otherwise report this application.
        if let Some(app) = objects.get_mut(&3)
            && app.property(PID_PROGRAM_VERSION).is_none()
        {
            let manufacturer = product
                .application_id
                .strip_prefix("M-")
                .and_then(|m| m.get(..4))
                .and_then(|m| u16::from_str_radix(m, 16).ok())
                .unwrap_or(0);
            let mut id = manufacturer.to_be_bytes().to_vec();
            id.extend_from_slice(
                &u16::try_from(product.application_number)
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            id.push(u8::try_from(product.application_version).unwrap_or(0));
            app.set_property(PID_PROGRAM_VERSION, Property::read_only(id));
        }
        // The factory memory the product's CompareMem preflights check.
        let mut memory = Memory::new();
        for (address, value) in &product.compare_mems {
            memory.seed(u32::from(*address), value);
        }
        let mut device = Self {
            address,
            profile,
            sys7: Some(Sys7Runtime { profile: s7, lsms }),
            objects,
            loadables,
            memory,
            access_level: 15,
            connected: false,
            tx_seq: 0,
            rx_seq: 0,
            l4_exchange_budget: None,
            l4_exchanges: 0,
            l4: Default::default(),
            group_comm: None,
            prog_mode,
            security_object: secure
                .as_ref()
                .map(|_| SecurityObject::new_activated().with_capacity(product.security_capacity)),
            knxnet_by_type: None,
            typed_objects: typed_objects_for(product, address, false).1,
            knxnet_slots: 0,
            ip_secure: None,
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            max_allocation: None,
            events,
        };
        device.refresh_group_comm();
        device
    }
}

impl Device {
    /// Build a property-only device (bussard issue #390): the Jung IPS 300
    /// SREG KNX IP interface (mask 0021), whose load procedure only compares
    /// and writes properties. Its object-index walk lists a device object and
    /// an address table (as the real 1.1.200 does, bussard issue #393); the
    /// KNXnet/IP parameter object (type 11) and every further object the
    /// procedure names by type are reached by type through the extended
    /// property services. The device object holds what the procedure's
    /// compares expect, and every property it writes is writable.
    pub(super) fn build_property_device(
        address: IndividualAddress,
        product: &ProductData,
        profile: Profile,
        prog_mode: bool,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Self {
        let mut objects: BTreeMap<u8, InterfaceObject> = BTreeMap::new();
        let mut device_object = InterfaceObject::new();
        device_object.set_property(
            PID_OBJECT_TYPE,
            Property::read_only(object_type_for(0).to_be_bytes().to_vec()),
        );
        device_object.set_property(PID_PROGMODE, Property::writable(vec![u8::from(prog_mode)]));
        let mfr = manufacturer_id_from_app(&product.application_id).unwrap_or(0x0004);
        device_object.set_property(0x0C, Property::read_only(mfr.to_be_bytes().to_vec()));
        device_object.set_property(
            0x0F,
            Property::read_only(order_info_bytes(&product.application_id)),
        );
        // PID_MAX_APDU_LENGTH: the IPS 300 SREG answers 00F8 (capture of
        // 2026-10-26).
        device_object.set_property(0x38, Property::read_only(vec![0x00, 0xF8]));
        for (pid, value) in &product.device_compare_props {
            device_object.set_property(*pid, Property::read_only(value.clone()));
        }
        objects.insert(0, device_object);
        let mut address_table = InterfaceObject::new();
        address_table.set_property(
            PID_OBJECT_TYPE,
            Property::read_only(iot::ADDRESS_TABLE.to_be_bytes().to_vec()),
        );
        objects.insert(1, address_table);

        let (knxnet, typed_objects) = typed_objects_for(product, address, true);
        Self {
            address,
            profile,
            sys7: None,
            objects,
            loadables: BTreeMap::new(),
            memory: Memory::new(),
            access_level: 15,
            connected: false,
            tx_seq: 0,
            rx_seq: 0,
            l4_exchange_budget: None,
            l4_exchanges: 0,
            l4: Default::default(),
            group_comm: None,
            prog_mode,
            security_object: None,
            knxnet_by_type: knxnet,
            typed_objects,
            knxnet_slots: 0,
            ip_secure: None,
            secure: None,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            max_allocation: None,
            events,
        }
    }
}

/// The objects a product's load procedure reaches by type (`ObjType`), with
/// the values it compares and the properties it writes (bussard issue #390).
/// The KNXnet/IP parameter object (type 11) is returned apart, and only when
/// `with_knxnet`: a System B or System 7 device gets that one from its
/// `knxnet` option. A vendor object such as the ABB Modbus RTU gateway's type
/// 65281 (PID 207 compared with 01) is seeded on every device kind; ETS
/// describes and reads it before the download (2026-10-28).
fn typed_objects_for(
    product: &ProductData,
    address: IndividualAddress,
    with_knxnet: bool,
) -> (Option<InterfaceObject>, BTreeMap<u16, InterfaceObject>) {
    let mut knxnet = None;
    let mut typed_objects: BTreeMap<u16, InterfaceObject> = BTreeMap::new();
    for typed in &product.typed_props {
        let obj = if typed.object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER {
            if !with_knxnet {
                continue;
            }
            knxnet.get_or_insert_with(|| {
                super::knxnet_object::KnxnetParameters::dhcp(address.raw(), Vec::new()).object()
            })
        } else {
            typed_objects.entry(typed.object_type).or_insert_with(|| {
                let mut io = InterfaceObject::new();
                io.set_property(
                    PID_OBJECT_TYPE,
                    Property::read_only(typed.object_type.to_be_bytes().to_vec()),
                );
                io
            })
        };
        if let Some(value) = &typed.compare {
            obj.set_property(typed.pid, Property::read_only(value.clone()));
        }
        if typed.written {
            match obj.property_mut(typed.pid) {
                Some(prop) => prop.read_only = false,
                None => obj.set_property(typed.pid, Property::writable(vec![0x00])),
            }
        }
    }
    (knxnet, typed_objects)
}

#[cfg(test)]
mod tests {
    use crate::bus::event::RecordingSink;
    use crate::device::profile::LsmAccess;
    use crate::device::test_support::*;
    use crate::device::*;

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
    fn test_system_b_ip_mask_57b0_builds_a_system_b_device() -> Result<(), String> {
        // Mask 57B0 (System B on KNX IP, syn-ip-57b0, bussard issue #389) is
        // modelled as System B and reports its own mask in DD0.
        let mut product = crate::testfixtures::synthetic_mdt_sys7_product();
        product.mask_version = "MV-57B0".into();
        let dev = Device::from_product_with_overrides(
            IndividualAddress::new(1, 1, 5),
            &product,
            LoadState::Unloaded,
            ProfileOverrides::default(),
            std::sync::Arc::new(RecordingSink::new()),
        )?;
        assert!(!dev.profile().is_system7());
        assert_eq!(dev.profile().mask(), 0x57B0);
        Ok(())
    }

    /// A System B device built from `pd` at 1.1.2, connected and authorized.
    fn connected_device(
        pd: &crate::prod::ProductData,
    ) -> Result<Device, Box<dyn std::error::Error>> {
        let mut dev = Device::from_product(
            IndividualAddress::new(1, 1, 2),
            pd,
            LoadState::Unloaded,
            std::sync::Arc::new(RecordingSink::new()),
        );
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        Ok(dev)
    }

    /// The `A_PropertyDescription_Response` payload for `object` / `pid`:
    /// `[obj, pid, index, type, max_hi, max_lo, access]`.
    fn describe(
        dev: &mut Device,
        object: u8,
        pid: u8,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let r = dev.handle_cemi(&data(dev, 0x3D8, &[object, pid, 0]))?;
        Ok(r.responses[0].tpdu[2..].to_vec())
    }

    /// Checks the device has application object 7 as the Glass Touch
    /// procedure addresses it: PID 161 writable and described with one
    /// octet, PID 162 holding `compare`.
    fn assert_object_7(dev: &mut Device, compare: u8) -> Result<(), Box<dyn std::error::Error>> {
        // The object answers the object-type probe with a manufacturer type.
        let r = dev.handle_cemi(&data(dev, 0x3D5, &[7, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50007u16.to_be_bytes().to_vec());
        // PID 161: writable, PDT_GENERIC_01, one element, read 3 / write 0.
        let d = describe(dev, 7, 161)?;
        assert_eq!(d[0..2], [7, 161]);
        assert_ne!(d[2], 0, "the property index is reported");
        assert_eq!(d[3], 0x80 | 0x11, "writable, PDT_GENERIC_01");
        assert_eq!(d[4..6], [0, 1], "one element");
        assert_eq!(d[6], 0x30, "read level 3, write level 0");
        // By index too: the walk reaches PID 161.
        let r = dev.handle_cemi(&data(dev, 0x3D8, &[7, 0, d[2]]))?;
        assert_eq!(r.responses[0].tpdu[2..], d[..]);
        // PID 162 holds the default branch's compare value, read-only.
        let r = dev.handle_cemi(&data(dev, 0x3D5, &[7, 162, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![compare]);
        let d = describe(dev, 7, 162)?;
        assert_eq!(d[3], 0x11, "read-only, PDT_GENERIC_01");
        // The procedure's write is taken and stored.
        let r = dev.handle_cemi(&data(dev, 0x3D7, &[7, 161, 0x10, 0x01, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0x01]);
        Ok(())
    }

    /// The Glass Touch Smart load procedure (`M-0083_A-018C-23-81D7`) with a
    /// device-selection parameter whose default is `device_default`.
    fn glass_touch_app(device_default: &str) -> String {
        format!(
            r#"<KNX><ApplicationProgram Id="M-0083_A-018C-23-81D7" ApplicationNumber="396" ApplicationVersion="35" ProgramType="ApplicationProgram" MaskVersion="MV-07B0"><Static>
          <Code><RelativeSegment Id="RS-04" Offset="0" Size="16" LoadStateMachine="4" /></Code>
          <Parameters><Parameter Id="M-0083_A-018C-23-81D7_P-646" Name="Device" Value="{device_default}" /></Parameters>
          <ParameterRefs><ParameterRef Id="M-0083_A-018C-23-81D7_P-646_R-1" RefId="M-0083_A-018C-23-81D7_P-646" /></ParameterRefs>
          <AddressTable /><AssociationTable /><ComObjectTable />
          <LoadProcedures>
            <LoadProcedure MergeId="4">
              <choose ParamRefId="M-0083_A-018C-23-81D7_P-646_R-1">
                <when test="0 2"><LdCtrlCompareProp AppliesTo="full,par" InlineData="00" ObjIdx="7" PropId="162" /></when>
                <when test="1 3"><LdCtrlCompareProp AppliesTo="full,par" InlineData="01" ObjIdx="7" PropId="162" /></when>
              </choose>
              <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="16" Verify="true" />
              <LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />
            </LoadProcedure>
          </LoadProcedures></Static></ApplicationProgram></KNX>"#
        )
    }

    /// `glass_touch_app` packed as a `.knxprod` and read back.
    fn glass_touch_product(
        device_default: &str,
    ) -> Result<crate::prod::ProductData, Box<dyn std::error::Error>> {
        app_product(&glass_touch_app(device_default))
    }

    /// An application XML packed as a `.knxprod` and read back.
    fn app_product(xml: &str) -> Result<crate::prod::ProductData, Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("M-0083/M-0083_A-018C-23-81D7.xml", options)?;
            zip.write_all(xml.as_bytes())?;
            zip.finish()?;
        }
        Ok(crate::prod::read_knxprod_bytes(buf.get_ref(), None)?)
    }

    #[test]
    fn test_build_counted_write_prop_is_an_array() -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #692: `LdCtrlWriteProp Count="2"` with 10 octets of
        // InlineData (the syn-s7-pid204 shape) is two elements of 5 octets.
        // ETS reads the description first and writes only what fits it.
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />
              <LdCtrlWriteProp ObjIdx="7" PropId="204" Count="2" Verify="false" InlineData="00004440000000448000" />"#,
        );
        let pd = app_product(&xml)?;
        assert!(pd.written_props.contains(&(7, 204, 10, 2)));
        let mut dev = connected_device(&pd)?;
        // Writable PDT_GENERIC_05 (0x15), two elements, read 3 / write 0.
        let d = describe(&mut dev, 7, 204)?;
        assert_eq!(d[3], 0x80 | 0x15, "writable, PDT_GENERIC_05");
        assert_eq!(d[4..6], [0, 2], "two elements");
        assert_eq!(d[6], 0x30);
        // ETS's write: count 2 from index 1, 10 octets, echoed and stored.
        let value = [0x00, 0x00, 0x44, 0x40, 0x00, 0x00, 0x00, 0x44, 0x80, 0x00];
        let mut write = vec![7, 204, 0x20, 0x01];
        write.extend_from_slice(&value);
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        assert_eq!(r.responses[0].tpdu[4], 0x20, "count 2 echoed");
        assert_eq!(prop_response_value(&r), value.to_vec());
        // Read back whole, and element 2 alone.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 204, 0x20, 0x01]))?;
        assert_eq!(prop_response_value(&r), value.to_vec());
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 204, 0x10, 0x02]))?;
        assert_eq!(prop_response_value(&r), value[5..].to_vec());
        // A write past the second element is refused whole (count 0).
        let mut over = vec![7, 204, 0x20, 0x02];
        over.extend_from_slice(&value);
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &over))?;
        assert_eq!(r.responses[0].tpdu[4], 0x00, "zero-count refusal");
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 204, 0x20, 0x01]))?;
        assert_eq!(prop_response_value(&r), value.to_vec(), "unchanged");
        Ok(())
    }

    #[test]
    fn test_build_system_b_creates_the_procedure_application_object()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422 without vendor data: the Glass Touch procedure
        // shape. Default 1 selects the second branch (compare 01); a default
        // no branch tests (255, the real product's) falls back to the first.
        for (default, compare) in [("1", 0x01), ("2", 0x00), ("255", 0x00)] {
            let pd = glass_touch_product(default)?;
            let mut dev = connected_device(&pd)?;
            assert_object_7(&mut dev, compare)?;
            // Object 6 is not invented: no procedure step names it.
            assert!(!dev.objects.contains_key(&6));
        }
        Ok(())
    }

    #[test]
    fn test_build_system_b_uses_the_declared_object_type() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut pd = glass_touch_product("1")?;
        pd.object_types.push((7, 50123));
        let mut dev = connected_device(&pd)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50123u16.to_be_bytes().to_vec());
        Ok(())
    }

    #[test]
    fn test_build_system_b_keeps_absent_system_objects() -> Result<(), Box<dyn std::error::Error>> {
        // A write to a system object the product does not load (object 4 here,
        // with no application segment) creates nothing, as before.
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.mask_version = "MV-07B0".into();
        pd.written_props.push((4, 16, 1, 1));
        let dev = Device::from_product(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Unloaded,
            std::sync::Arc::new(RecordingSink::new()),
        );
        assert!(!dev.objects.contains_key(&4));
        Ok(())
    }

    #[test]
    fn test_build_mdt_glass_touch_has_application_object_7()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(bytes) = crate::testfixtures::mdt_glass_touch_knxprod() else {
            eprintln!(
                "SKIP: MDT Glass Touch product not found at {}",
                crate::testfixtures::corpus_vendor_knxprod_path(
                    "BE-GTSx6Tx-01S_MDT_KP_V23.knxprod"
                )
                .display()
            );
            return Ok(());
        };
        let pd = crate::prod::read_knxprod_bytes(&bytes, Some("M-0083_A-018C-23-81D7"))?;
        assert!(pd.written_props.contains(&(7, 161, 1, 1)));
        let mut dev = connected_device(&pd)?;
        assert!(!dev.profile().is_system7(), "mask 07B0 is System B");
        // The device-selection default (255) matches no branch: the first
        // compare (00) stands.
        assert_object_7(&mut dev, 0x00)?;
        Ok(())
    }
}
