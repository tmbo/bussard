//! Device construction: builds the System B and System 7 device cores from a
//! product (interface objects, memory segments, load-state machines).

use std::collections::BTreeMap;

use crate::bus::event::EventSink;
use crate::prod::{LdCtrl, LoadableObject, ProductData};
use crate::wire::IndividualAddress;

use super::{
    DEFAULT_RESTART_PROCESS_TIME_S, Device, InterfaceObject, LoadState, LoadStateMachine,
    MasterResetSupport, Memory, ObjectState, PID_LOAD_STATE_CONTROL, PID_OBJECT_TYPE, PID_PROGMODE,
    PID_PROGRAM_VERSION, PID_TABLE_REFERENCE, Profile, Property, SecurityObject,
    Sys7LoadStateMachine, Sys7Runtime, iot, profile,
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

/// The end (offset plus size) of the furthest `LdCtrlWriteRelMem` the
/// product's load procedures write into `object`, 0 when none does.
fn rel_mem_extent(product: &ProductData, object: u8) -> u32 {
    product
        .load_procedures
        .iter()
        .flat_map(|p| &p.steps)
        .filter_map(|step| match step {
            LdCtrl::WriteRelMem {
                obj_index,
                offset,
                size,
                ..
            } if *obj_index == object => Some(offset.saturating_add(*size)),
            _ => None,
        })
        .max()
        .unwrap_or(0)
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

/// The last standardized property identifier: PIDs 201
/// to 255 are manufacturer specific (KNX 3/7/3 Standardized Identifier
/// Tables §3.1).
const LAST_STANDARD_PID: u8 = 200;

/// The system objects with a load-state machine every System B device has,
/// as `(index, name)`.
const SYSTEM_B_LSM_OBJECTS: [(u8, &str); 5] = [
    (1, "address table"),
    (2, "association table"),
    (3, "group object table"),
    (4, "application program"),
    (5, "knx-object association table"),
];

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

/// `PID_MAX_APDU_LENGTH` of the device object (KNX 3/5/1).
pub(super) const PID_MAX_APDU_LENGTH: u8 = 0x38;

/// The APDU a tool reserves in front of a property value: the APCI's second
/// octet, the object index, the PID and two octets of count and start index.
/// ETS reported a 20-octet label write as "benötigt: 25" (bussard issue #996).
const PROPERTY_WRITE_HEADER: usize = 5;

/// The standard-frame APDU every device takes, and what ETS assumes when a
/// device has no `PID_MAX_APDU_LENGTH`.
const STANDARD_MAX_APDU: usize = 15;

/// The `PID_MAX_APDU_LENGTH` a System 7 device answers, or `None` when it has
/// none.
///
/// A real System 7 device has none: the Jung 0705 devices of the house
/// (1.1.32, 1.1.40, 1.1.46) and the 0701 at 1.1.202 answer the read with no
/// element (`d6 00 38 00 01`, campaign 2026-09-23, `wire.log` of every device
/// directory), as the Jung 3361-1M did to ETS in the M2 capture (issue #70,
/// `jung-1131-download.pcapng`), and the 0705 mask in `knx_master.xml` names
/// no `MaxApduLength` resource. ETS then assumes 15 octets (its 12-octet
/// `A_Memory_Write` chunks in the M2 capture).
///
/// A product whose procedure writes a property element longer than that
/// (the MDT BE-BZS86.01 writes 20-octet labels in one `A_PropertyValue_Write`)
/// runs on hardware that takes the longer frame, so the device answers the
/// smallest APDU that carries its longest element (bussard issue #996).
fn system7_max_apdu(objects: &BTreeMap<u8, InterfaceObject>, product: &ProductData) -> Option<u16> {
    let needed = product
        .written_props
        .iter()
        .filter_map(|&(object, pid, _, _)| objects.get(&object)?.property(pid))
        .map(|p| PROPERTY_WRITE_HEADER + p.element_size())
        .max()?;
    (needed > STANDARD_MAX_APDU).then(|| u16::try_from(needed).unwrap_or(u16::MAX))
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
/// issue #692), so ETS, which reads the description first, writes it. A
/// written property describes [`super::PRODUCT_WRITE_LEVEL`] (bussard issue
/// #841, [`Property::product_written`]).
fn seed_procedure_props(
    objects: &mut BTreeMap<u8, InterfaceObject>,
    product: &ProductData,
    first_new_object: u8,
) {
    let addressed = product
        .object_compare_props
        .iter()
        .map(|(object, _, _, _)| *object)
        .chain(
            product
                .written_props
                .iter()
                .map(|&(object, _, _, _)| object),
        )
        .chain(product.function_props.iter().map(|&(object, _)| object));
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
    for (object, pid, value, elements) in &product.object_compare_props {
        let written = product
            .written_props
            .iter()
            .find(|&&(o, p, _, _)| o == *object && p == *pid);
        if let Some(io) = objects.get_mut(object) {
            // The state a procedure compares after a load event is the
            // load-state machine's, not a stored value.
            if *pid == PID_LOAD_STATE_CONTROL && io.has_property(PID_LOAD_STATE_CONTROL) {
                continue;
            }
            let prop = match written {
                Some(&(_, _, _, count)) => Property::writable(value.clone())
                    .with_elements(count)
                    .with_write_level(super::PRODUCT_WRITE_LEVEL),
                // The program version (PID 13) is stamped by the tool at the
                // end of every download whether or not the procedure compares
                // it first: an Enertex IP system device compares object 4's
                // PID 13 and ETS then writes it (refused as read-only,
                // 2026-11-04).
                None if *pid == PID_PROGRAM_VERSION => Property::writable(value.clone()),
                None => Property::read_only(value.clone()).with_elements(*elements),
            };
            io.set_property(*pid, prop);
        }
    }
    // A function property the procedure calls (`LdCtrlInvokeFunctionProp`)
    // is `PDT_FUNCTION` (KNX 3/3/7 §3.4.7.3).
    for &(object, pid) in &product.function_props {
        if let Some(io) = objects.get_mut(&object)
            && !io.has_property(pid)
        {
            io.set_property(pid, Property::function());
        }
    }
    for &(object, pid, len, count) in &product.written_props {
        if let Some(io) = objects.get_mut(&object)
            && !io.has_property(pid)
        {
            let pdt = product
                .written_prop_pdts
                .iter()
                .find(|&&(o, p, _)| o == object && p == pid)
                .map(|&(_, _, pdt)| pdt);
            io.set_property(pid, Property::product_written(len, count).with_pdt(pdt));
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
        device_object.set_property(PID_MAX_APDU_LENGTH, Property::read_only(vec![0x00, 0x42]));
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

        // A System B device has its system objects with their load-state
        // machines whatever the product loads into them (KNX 6 Profiles
        // §4.2.10 f: the address table, association table, group object table
        // and application objects of System B), and a KNX-object association
        // table (interface-object type 5). ETS's 07B0 procedure unloads
        // objects 5 to 1 even when the product's tables leave them empty: the
        // Siemens IP Interface Secure (`M-0001_A-7205-03`, no code segment)
        // stopped at "no property: object 4 pid 5" (ETS sweep, 2026-11-05).
        let mut all_objects: Vec<LoadableObject> = product.objects.clone();
        for (lsm_index, name) in SYSTEM_B_LSM_OBJECTS {
            if !all_objects.iter().any(|o| o.lsm_index == lsm_index) {
                all_objects.push(LoadableObject {
                    lsm_index,
                    name: name.into(),
                    max_size: None,
                    image: Vec::new(),
                });
            }
        }
        // An application object the procedure drives through
        // PID_LOAD_STATE_CONTROL events (`LdCtrlWriteProp ObjIdx="8"
        // PropId="5"`, then `LdCtrlCompareProp` of the state it reaches: the
        // Jung Sonos gateway `M-0004_A-B015-21`) has a load-state machine too.
        for &(object, pid, _, _) in &product.written_props {
            if pid == PID_LOAD_STATE_CONTROL
                && object >= FIRST_APPLICATION_OBJECT
                && !all_objects.iter().any(|o| o.lsm_index == object)
            {
                all_objects.push(LoadableObject {
                    lsm_index: object,
                    name: "application object".into(),
                    max_size: None,
                    image: Vec::new(),
                });
            }
        }
        all_objects.sort_by_key(|o| o.lsm_index);

        for obj in &all_objects {
            let base = default_base_for(obj.lsm_index);
            let mut io = InterfaceObject::new();
            // PID_OBJECT_TYPE (PID 1) reports this object's interface-object
            // type so a tool can discover the object table by index.
            io.set_property(
                PID_OBJECT_TYPE,
                Property::read_only(
                    procedure_object_type(product, obj.lsm_index)
                        .to_be_bytes()
                        .to_vec(),
                ),
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
                    mcb_written: None,
                    write_extent: rel_mem_extent(product, obj.lsm_index),
                },
            );
        }

        seed_procedure_props(&mut objects, product, FIRST_APPLICATION_OBJECT);
        // The KNXnet/IP parameter object the procedure writes by type keeps
        // the product's properties on it (a manufacturer PID such as the
        // Siemens IP interfaces' 236); a `knxnet` device option adds them to
        // the object it configures (`Device::with_knxnet`).
        let (knxnet_by_type, mut typed) = typed_objects_for(product, address, true);
        // A vendor object the procedure loads by type (`LdCtrlUnload
        // ObjType="40960"`, the Gira Eco) exists even when no property step
        // names it, and has a load-state machine once indexed.
        for &object_type in &product.typed_lsm_types {
            typed.entry(object_type).or_insert_with(|| {
                let mut io = InterfaceObject::new();
                io.set_property(
                    PID_OBJECT_TYPE,
                    Property::read_only(object_type.to_be_bytes().to_vec()),
                );
                io
            });
        }
        let typed_objects = index_typed_objects(&mut objects, typed);
        fill_index_gaps(&mut objects, product);
        for &object_type in &product.typed_lsm_types {
            let index = objects
                .iter()
                .find(|(_, o)| {
                    o.property(PID_OBJECT_TYPE)
                        .is_some_and(|p| p.value.as_slice() == object_type.to_be_bytes())
                })
                .map(|(i, _)| *i);
            if let Some(index) = index
                && !loadables.contains_key(&index)
            {
                if let Some(io) = objects.get_mut(&index) {
                    io.set_property(
                        PID_LOAD_STATE_CONTROL,
                        Property::writable(vec![initial_state.to_byte()]),
                    );
                }
                loadables.insert(
                    index,
                    ObjectState {
                        lsm: LoadStateMachine::new(initial_state),
                        base: default_base_for(index),
                        descriptor: LoadableObject {
                            lsm_index: index,
                            name: format!("object type {object_type}"),
                            max_size: None,
                            image: Vec::new(),
                        },
                        mcb_written: None,
                        write_extent: rel_mem_extent(product, index),
                    },
                );
            }
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
            l4: Default::default(),
            group_comm: None,
            prog_mode,
            security_object: secure
                .as_ref()
                .map(|_| SecurityObject::new_activated().with_capacity(product.security_capacity)),
            knxnet_by_type,
            typed_objects,
            knxnet_slots: 0,
            ip_secure: None,
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            max_allocation: None,
            master_reset: MasterResetSupport::Supported,
            intermediate_reports: 0,
            intermediate: std::collections::BTreeMap::new(),
            factory_properties: Vec::new(),
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
                    mcb_written: None,
                    write_extent: 0,
                },
            );
        }

        seed_procedure_props(&mut objects, product, 0);
        if let Some(max_apdu) = system7_max_apdu(&objects, product)
            && let Some(device_object) = objects.get_mut(&0)
        {
            device_object.set_property(
                PID_MAX_APDU_LENGTH,
                Property::read_only(max_apdu.to_be_bytes().to_vec()),
            );
        }
        // The application object always reports a program id (PID 13,
        // `mfr:2 app:2 version:1`, the BimM112 `ApplicationId`): ETS reads it
        // before a download to check the manufacturer, and an absent property
        // failed the ABB Room Master Premium (A-A054, 2026-10-28). A compare
        // step has already seeded it; otherwise report this application.
        if let Some(app) = objects.get_mut(&3)
            && app.property(PID_PROGRAM_VERSION).is_none()
        {
            let manufacturer =
                crate::prod::program_manufacturer(&product.application_id).unwrap_or(0);
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
            master_reset: MasterResetSupport::Supported,
            intermediate_reports: 0,
            intermediate: std::collections::BTreeMap::new(),
            factory_properties: Vec::new(),
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
    ///
    /// `secure` gives it the security object and Data Secure session a
    /// System B device gets: the Enertex IP Secure Interface
    /// (`M-00A6_A-0014-10-2517`, mask 0021, `IsSecureEnabled`) is
    /// commissioned by ETS 6.4.1 with an S-A_Sync to it like any Data Secure
    /// device (ETS sweep secure capture of 2026-11-10, bussard issue #423).
    pub(super) fn build_property_device(
        address: IndividualAddress,
        product: &ProductData,
        profile: Profile,
        prog_mode: bool,
        secure: Option<crate::secure::DataSecureSession>,
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
        device_object.set_property(PID_MAX_APDU_LENGTH, Property::read_only(vec![0x00, 0xF8]));
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
            security_object: secure
                .as_ref()
                .map(|_| SecurityObject::new_activated().with_capacity(product.security_capacity)),
            knxnet_by_type: knxnet,
            typed_objects,
            knxnet_slots: 0,
            ip_secure: None,
            secure,
            restart_process_time_s: DEFAULT_RESTART_PROCESS_TIME_S,
            max_allocation: None,
            master_reset: MasterResetSupport::Supported,
            intermediate_reports: 0,
            intermediate: std::collections::BTreeMap::new(),
            factory_properties: Vec::new(),
            events,
        }
    }
}

/// Fills every free index below the highest interface object with a
/// placeholder object that answers only `PID_OBJECT_TYPE`, of the type the
/// product declares for that index, else a manufacturer type
/// ([`procedure_object_type`]).
///
/// A device's interface objects are indexed contiguously from 0: the
/// standard's object scans end at the first index without an object (KNX
/// 3/5/2 §3.28.2 and §3.28.3) and `PID_IO_LIST` lists the types by index
/// behind their count (KNX 3/5/1 §4.3.22). The product data names only the
/// objects its load procedure addresses, so a device built from it alone had
/// gaps: the Hager `M-0009_A-E802-13-7620` addresses objects 0 to 5 and 9 to
/// 31, and a tool's walk stopped at object 6 and never saw 9 to 31 (bussard
/// issue #1073). What a real device keeps at 6 to 8 is not in the product
/// data; the placeholder makes index enumeration behave as on a device.
fn fill_index_gaps(objects: &mut BTreeMap<u8, InterfaceObject>, product: &ProductData) {
    let Some(&last) = objects.keys().next_back() else {
        return;
    };
    for index in 0..last {
        objects
            .entry(index)
            .or_insert_with(|| InterfaceObject::placeholder(procedure_object_type(product, index)));
    }
}

/// Places the objects a System B procedure reaches by type at the lowest free
/// indices from [`FIRST_APPLICATION_OBJECT`] on, and returns what is left
/// (none unless every index is taken). A tool with only the standard
/// property services finds an object of a type by reading `PID_OBJECT_TYPE`
/// of the indices past the system objects: ETS read object 6's PID 1 for the
/// Siemens dimmer `M-0001_A-9839-01`'s type 50215 and stopped when object 6
/// was absent ("Die ausgewählte Geräte-Ressource ist zurzeit nicht
/// verfügbar", ETS sweep, 2026-11-05). The extended property services still
/// reach them by type, as an indexed object whose `PID_OBJECT_TYPE` names it.
fn index_typed_objects(
    objects: &mut BTreeMap<u8, InterfaceObject>,
    typed: BTreeMap<u16, InterfaceObject>,
) -> BTreeMap<u16, InterfaceObject> {
    let mut left = BTreeMap::new();
    for (object_type, io) in typed {
        match (FIRST_APPLICATION_OBJECT..=u8::MAX).find(|i| !objects.contains_key(i)) {
            Some(index) => {
                objects.insert(index, io);
            }
            None => {
                left.insert(object_type, io);
            }
        }
    }
    left
}

/// The objects a product's load procedure reaches by type (`ObjType`), with
/// the values it compares and the properties it writes (bussard issue #390).
/// The KNXnet/IP parameter object (type 11) is returned apart, and only when
/// `with_knxnet`: a System B or System 7 device gets that one from its
/// `knxnet` option. A vendor object such as the ABB Modbus RTU gateway's type
/// 65281 (PID 207 compared with 01) is seeded on every device kind; ETS
/// describes and reads it before the download (2026-10-28). A property of a
/// vendor object a step writes is described as the product declares it
/// ([`Property::product_written`], bussard issue #841): the Enertex PID 211
/// of type 50001 was one octet of `PDT_VARIABLE_LENGTH` at write level 0,
/// and ETS wrote nothing to it (2026-11-04). The KNXnet/IP object describes
/// its own properties (`knxnet_object::refine`).
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
        let knxnet_object = typed.object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER;
        if let Some(value) = &typed.compare {
            let prop = Property::read_only(value.clone());
            obj.set_property(
                typed.pid,
                if knxnet_object {
                    prop
                } else {
                    prop.with_elements(typed.compare_elements)
                },
            );
        }
        if typed.written {
            match obj.property_mut(typed.pid) {
                Some(prop) if knxnet_object => prop.read_only = false,
                Some(prop) => {
                    // A compared value is the property's size.
                    let count = typed.count;
                    *prop = Property::writable(std::mem::take(&mut prop.value))
                        .with_elements(count)
                        .with_write_level(super::PRODUCT_WRITE_LEVEL);
                }
                // A non-standardized PID (201 to 255, KNX 3/7/3 Standardized
                // Identifier Tables §3.1) is the manufacturer's: described as
                // the product declares it. The Siemens IP Interface Secure
                // `M-0001_A-7205-03` stores its unicast TTL (8 bit) in PID
                // 236 of object type 11; ETS describes it first and stopped
                // on the empty description (ETS sweep, 2026-11-05).
                None if knxnet_object && typed.pid > LAST_STANDARD_PID => obj.set_property(
                    typed.pid,
                    Property::product_written(typed.len, typed.count).with_pdt(typed.pdt),
                ),
                None if knxnet_object => {
                    obj.set_property(typed.pid, Property::writable(vec![0x00]))
                }
                None => obj.set_property(
                    typed.pid,
                    Property::product_written(typed.len, typed.count).with_pdt(typed.pdt),
                ),
            }
        }
    }
    // A function property the procedure calls by type
    // (`LdCtrlInvokeFunctionProp ObjType=…`, bussard issue #422).
    for &(object_type, pid) in &product.typed_function_props {
        if object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER {
            continue;
        }
        let obj = typed_objects.entry(object_type).or_insert_with(|| {
            let mut io = InterfaceObject::new();
            io.set_property(
                PID_OBJECT_TYPE,
                Property::read_only(object_type.to_be_bytes().to_vec()),
            );
            io
        });
        if !obj.has_property(pid) {
            obj.set_property(pid, Property::function());
        }
    }
    (knxnet, typed_objects)
}

#[cfg(test)]
mod tests {
    use super::PID_MAX_APDU_LENGTH;
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
        // PID 161: writable, PDT_GENERIC_01, one element, read 3 / write 2
        // (PRODUCT_WRITE_LEVEL, bussard issue #841).
        let d = describe(dev, 7, 161)?;
        assert_eq!(d[0..2], [7, 161]);
        assert_ne!(d[2], 0, "the property index is reported");
        assert_eq!(d[3], 0x80 | 0x11, "writable, PDT_GENERIC_01");
        assert_eq!(d[4..6], [0, 1], "one element");
        assert_eq!(d[6], 0x32, "read level 3, write level 2");
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

    /// A System 7 product (mask 0705) whose load procedure writes object 6's
    /// PIDs 31, 32 and 33 without `InlineData` (the MDT Central Operation
    /// Unit Smart shape, `M-0083_A-0054-14-0D63`, bussard issue #980): PID 31
    /// holds a 20-octet text parameter (`<Property>` placement), PID 32 is
    /// declared `PDT_GENERIC_10` (`LdCtrlDeclarePropDesc`), PID 33 has
    /// neither.
    const LABEL_APP: &str = r#"<KNX><ApplicationProgram Id="M-0083_A-0054-14-0D63" ApplicationNumber="84" ApplicationVersion="20" ProgramType="ApplicationProgram" MaskVersion="MV-0705"><Static>
          <ParameterTypes><ParameterType Id="M-0083_A-0054-14-0D63_PT-String.5F20Byte" Name="String_20Byte"><TypeText SizeInBit="160" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-0083_A-0054-14-0D63_P-832" Name="LabelViewCat" ParameterType="M-0083_A-0054-14-0D63_PT-String.5F20Byte" Text="" Access="None" Value="">
            <Property ObjectIndex="6" PropertyId="31" Offset="0" BitOffset="0" />
          </Parameter></Parameters>
          <AddressTable /><AssociationTable /><ComObjectTable />
          <LoadProcedures><LoadProcedure>
            <LdCtrlDeclarePropDesc ObjIdx="6" PropId="32" PropType="PDT_GENERIC_10" MaxElements="1" ReadAccess="3" WriteAccess="2" Writable="true" />
            <LdCtrlWriteProp ObjIdx="6" PropId="31" Verify="false" />
            <LdCtrlWriteProp ObjIdx="6" PropId="32" Verify="false" />
            <LdCtrlWriteProp ObjIdx="6" PropId="33" Verify="false" />
          </LoadProcedure></LoadProcedures></Static></ApplicationProgram></KNX>"#;

    /// Describes object 6's `pid` on the [`LABEL_APP`] device, checks it is
    /// one writable element of `pdt` holding `len` zero octets, then writes
    /// `len` octets and reads them back.
    fn assert_label_property(
        pid: u8,
        pdt: u8,
        len: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pd = app_product(LABEL_APP)?;
        let mut dev = connected_device(&pd)?;
        assert!(dev.profile().is_system7());
        let d = describe(&mut dev, 6, pid)?;
        assert_eq!(d[3], 0x80 | pdt, "writable, PDT 0x{pdt:02X}");
        assert_eq!(d[4..6], [0, 1], "one element");
        assert_eq!(d[6], 0x32, "read level 3, write level 2");
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[6, pid, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0u8; len]);
        // ETS's write of the whole element (count 1, index 1) is taken.
        let value: Vec<u8> = (1..=u8::try_from(len)?).collect();
        let mut write = vec![6, pid, 0x10, 0x01];
        write.extend_from_slice(&value);
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        assert_eq!(prop_response_value(&r), value);
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[6, pid, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), value);
        Ok(())
    }

    #[test]
    fn test_build_system7_placed_text_parameter_sizes_the_property()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #980: a capture taken with a sim that described the
        // label property as one octet made ETS write one character of it.
        // The parameter placed in it is 20 octets: one PDT_GENERIC_20 element.
        assert_label_property(31, 0x24, 20)
    }

    #[test]
    fn test_build_system7_declared_property_has_the_declared_size()
    -> Result<(), Box<dyn std::error::Error>> {
        // No parameter placed in it: the declaration's PDT_GENERIC_10 sizes it.
        assert_label_property(32, 0x1A, 10)
    }

    /// Reads object 0's PID 56 on a connected device built from `xml` and
    /// returns the response's count/start octets and value.
    fn read_max_apdu(xml: &str) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error>> {
        let pd = app_product(xml)?;
        let mut dev = connected_device(&pd)?;
        assert!(dev.profile().is_system7());
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0, PID_MAX_APDU_LENGTH, 0x10, 0x01]))?;
        assert_eq!(r.responses[0].tpdu[2..4], [0, PID_MAX_APDU_LENGTH]);
        Ok((r.responses[0].tpdu[4], prop_response_value(&r)))
    }

    #[test]
    fn test_system7_max_apdu_absent_like_a_real_0705() -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #996: the house's Jung 0705 devices answer PID 56 with
        // no element (`d6 00 38 00 01`). Without the 20-octet label the
        // longest element the procedure writes is 10 octets, which a
        // standard frame carries.
        let xml = LABEL_APP.replace(
            r#"<LdCtrlWriteProp ObjIdx="6" PropId="31" Verify="false" />"#,
            "",
        );
        let (count_start, value) = read_max_apdu(&xml)?;
        assert_eq!(count_start >> 4, 0, "no element: the property is absent");
        assert!(value.is_empty());
        Ok(())
    }

    #[test]
    fn test_system7_max_apdu_carries_the_longest_written_element()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #996: the MDT BE-BZS86.01 writes a 20-octet label in
        // one A_PropertyValue_Write; ETS needs an APDU of 25 for it.
        let (count_start, value) = read_max_apdu(LABEL_APP)?;
        assert_eq!(count_start >> 4, 1);
        assert_eq!(value, vec![0x00, 25]);
        Ok(())
    }

    #[test]
    fn test_system7_max_apdu_sets_the_memory_chunk() -> Result<(), Box<dyn std::error::Error>> {
        // The APDU of 25 carries 22 octets of A_Memory_Write; without PID 56
        // the standard-frame 12 stay the ceiling.
        assert_eq!(
            connected_device(&app_product(LABEL_APP)?)?.sys7_memory_chunk(),
            22
        );
        let xml = LABEL_APP.replace(
            r#"<LdCtrlWriteProp ObjIdx="6" PropId="31" Verify="false" />"#,
            "",
        );
        assert_eq!(
            connected_device(&app_product(&xml)?)?.sys7_memory_chunk(),
            12
        );
        Ok(())
    }

    #[test]
    fn test_build_system7_unsized_property_keeps_one_octet()
    -> Result<(), Box<dyn std::error::Error>> {
        // Neither a placement nor a declaration: one octet, as before.
        assert_label_property(33, PDT_GENERIC_01, 1)
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
        // Writable PDT_GENERIC_05 (0x15), two elements, read 3 / write 2.
        let d = describe(&mut dev, 7, 204)?;
        assert_eq!(d[3], 0x80 | 0x15, "writable, PDT_GENERIC_05");
        assert_eq!(d[4..6], [0, 2], "two elements");
        assert_eq!(d[6], 0x32);
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

    /// Bussard issue #422: the Siemens `M-0001_A-9A01-03-E6C8` procedure
    /// compares object 4's PID 246 element by element. The sim answered
    /// element 2 with the first compare's 05 (ETS sweep capture
    /// `plain-defaults`, 2026-11-05) and ETS refused the download.
    #[test]
    fn test_build_merges_element_compares_into_an_array() -> Result<(), Box<dyn std::error::Error>>
    {
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4""#,
            r#"<LdCtrlCompareProp ObjIdx="4" PropId="246" InlineData="05" AppliesTo="all" />
              <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="2" InlineData="93" AppliesTo="all" />
              <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="3" InlineData="04" AppliesTo="all" />
              <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="5" InlineData="00" AppliesTo="all" />
              <LdCtrlCompareProp ObjIdx="4" PropId="246" StartElement="6" InlineData="51" AppliesTo="all" />
              <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4""#,
        );
        let pd = app_product(&xml)?;
        let mut dev = connected_device(&pd)?;
        // ETS's description read [d8 04 f6 00]: read-only PDT_GENERIC_01, six
        // elements.
        let d = describe(&mut dev, 4, 246)?;
        assert_eq!(d[3], 0x11, "read-only, PDT_GENERIC_01");
        assert_eq!(d[4..6], [0, 6], "six elements");
        // ETS's reads [d5 04 f6 10 01] and [d5 04 f6 10 02], then the rest.
        for (start, want) in [(1u8, 0x05u8), (2, 0x93), (3, 0x04), (5, 0x00), (6, 0x51)] {
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[4, 246, 0x10, start]))?;
            assert_eq!(prop_response_value(&r), vec![want], "element {start}");
        }
        // Past the sixth element: the zero-count refusal.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[4, 246, 0x10, 7]))?;
        assert_eq!(r.responses[0].tpdu[4], 0x00);
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
            // Object 6 holds only its type (bussard issue #1073): no
            // procedure step names it, and the indices stay contiguous.
            let six = dev.objects.get(&6).ok_or("object 6 missing")?;
            assert!(six.is_placeholder() && six.has_property(PID_OBJECT_TYPE));
        }
        Ok(())
    }

    #[test]
    fn test_fill_index_gaps_makes_the_object_indices_contiguous()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #1073: the Hager `M-0009_A-E802-13-7620` procedure
        // addresses objects 0 to 5 and 9 to 31; a walk of PID_OBJECT_TYPE
        // stopped at object 6 and never reached 9. The same shape here: the
        // procedure names object 9 only.
        let xml = glass_touch_app("1").replace(r#"ObjIdx="7""#, r#"ObjIdx="9""#);
        let pd = app_product(&xml)?;
        let mut dev = connected_device(&pd)?;
        // The walk from 0 finds an object at every index up to 9.
        for index in 0u8..=9 {
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[index, 1, 0x10, 0x01]))?;
            assert_eq!(
                prop_response_value(&r).len(),
                2,
                "object {index} answers its type"
            );
        }
        // The placeholders carry a manufacturer type, and the addressed
        // object keeps its own.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50007u16.to_be_bytes().to_vec());
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[9, 161, 0x10, 0x01, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0x01]);
        // The index after the last object answers no object.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[10, 1, 0x10, 0x01]))?;
        assert_eq!(
            r.responses[0].tpdu[4], 0x00,
            "zero-count answer past the last object"
        );
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
    fn test_build_system_b_has_every_system_lsm_object() -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: a product that loads nothing into object 4 (the
        // Siemens IP Interface Secure has no code segment) still has its
        // load-state machine. ETS's Unload [d7 04 05 10 01 04 00 ..] was
        // refused before (ETS sweep, 2026-11-05).
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.mask_version = "MV-07B0".into();
        pd.objects.retain(|o| o.lsm_index != 4);
        pd.written_props.push((4, 16, 1, 1));
        let mut dev = connected_device(&pd)?;
        for object in 1..=5u8 {
            let mut unload = vec![object, 5, 0x10, 0x01, 0x04];
            unload.extend_from_slice(&[0; 9]);
            let r = dev.handle_cemi(&data(&dev, 0x3D7, &unload))?;
            assert_eq!(
                prop_response_value(&r),
                vec![0x00],
                "object {object} unloaded"
            );
        }
        // The procedure's write to object 4 is taken.
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[4, 16, 0x10, 0x01, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0x01]);
        Ok(())
    }

    #[test]
    fn test_build_system_b_empty_object_has_an_empty_mcb() -> Result<(), Box<dyn std::error::Error>>
    {
        // Bussard issue #422: the Schneider STYAS608D (`M-0009_A-E807-10`) has
        // no code segment; ETS loads object 4 empty and reads its PID 27
        // `[d5 04 1b 10 01]`. The zero-count answer made ETS report a read of
        // a protected memory area (ETS sweep, 2026-11-06).
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.mask_version = "MV-07B0".into();
        pd.objects.retain(|o| o.lsm_index != 4);
        let mut dev = connected_device(&pd)?;
        for event in [0x04u8, 0x01, 0x02] {
            let mut write = vec![4, 5, 0x10, 0x01, event];
            write.extend_from_slice(&[0; 9]);
            dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        }
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[4, 27, 0x10, 0x01]))?;
        // Size 0, the CRC of no octets (CRC-16/AUG-CCITT initial value 1D0F).
        assert_eq!(
            prop_response_value(&r),
            vec![0, 0, 0, 0, 0x00, 0xFF, 0x1D, 0x0F]
        );
        Ok(())
    }

    #[test]
    fn test_build_system_b_never_loaded_empty_object_has_no_mcb()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #1015: the empty image of #422 is the MCB of an object
        // loaded empty. An object that never reached Loaded and holds nothing
        // has no CRC (it is calculated on the transition to Loaded, Resources
        // §4.2.27), so the read answers no element and a tool never takes the
        // re-download skip on a blank device.
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.mask_version = "MV-07B0".into();
        pd.objects.retain(|o| o.lsm_index != 4);
        let mut dev = connected_device(&pd)?;
        assert_eq!(dev.load_state(4), Some(LoadState::Unloaded));
        assert!(dev.mcb_entry(4).is_none());
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[4, 27, 0x10, 0x01]))?;
        // `[obj 04][pid 1b][count 0, start 001]`: no element.
        assert_eq!(&r.responses[0].tpdu[2..6], &[0x04, 0x1B, 0x00, 0x01]);
        Ok(())
    }

    #[test]
    fn test_build_system_b_allocation_covers_the_procedure_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: the Hager TYMS616D (`M-0009_A-E804-10`)
        // allocates 258 octets on object 4 (`LdCtrlRelSegment Size="258"`)
        // and writes 642 (`LdCtrlWriteRelMem Offset="0" Size="642"`). The
        // sim refused ETS's write at 0x60f9+61 and ETS reported "device does
        // not respond" (ETS sweep, 2026-11-07). The frames are ETS's.
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.mask_version = "MV-07B0".into();
        pd.load_procedures.push(crate::prod::LoadProcedure {
            merge_id: Some(4),
            steps: vec![crate::prod::LdCtrl::WriteRelMem {
                obj_index: 4,
                offset: 0,
                size: 642,
                verify: true,
            }],
        });
        let mut dev = connected_device(&pd)?;
        for record in [
            [0x04u8, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x03, 0x0b, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00],
        ] {
            let mut write = vec![4, 5, 0x10, 0x01];
            write.extend_from_slice(&record);
            dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        }
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[4, 7, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0x00, 0x00, 0x60, 0x00]);
        let mut write = vec![0x3d, 0x00, 0x60, 0xf9];
        write.extend_from_slice(&[0x22; 61]);
        let r = dev.handle_cemi(&data(&dev, 0x1FB, &write))?;
        // A_MemoryExtended_WriteResponse, return code 00 (success).
        let resp = r.responses.first().ok_or("no write response")?;
        assert_eq!(&resp.tpdu[1..3], &[0xFC, 0x00]);
        Ok(())
    }

    #[test]
    fn test_build_system_b_application_object_with_a_load_state_machine()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: the Jung Sonos gateway (`M-0004_A-B015-21`)
        // drives object 8 through PID 5 load events and compares the state
        // each one reaches. ETS's first event was refused ("no property:
        // object 8 pid 5", ETS sweep 2026-11-05).
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlWriteProp ObjIdx="8" PropId="5" Verify="false" InlineData="04000000000000000000" AppliesTo="full,par" />
              <LdCtrlCompareProp ObjIdx="8" PropId="5" InlineData="00" AppliesTo="full,par" />
              <LdCtrlWriteProp ObjIdx="8" PropId="5" Verify="false" InlineData="01000000000000000000" AppliesTo="full,par" />
              <LdCtrlCompareProp ObjIdx="8" PropId="5" InlineData="02" AppliesTo="full,par" />
              <LdCtrlWriteProp ObjIdx="8" PropId="71" Count="3" Verify="false" AppliesTo="full,par" />
              <LdCtrlWriteProp ObjIdx="8" PropId="5" Verify="false" InlineData="02000000000000000000" AppliesTo="full,par" />
              <LdCtrlCompareProp ObjIdx="8" PropId="5" InlineData="01" AppliesTo="full,par" />"#,
        );
        let pd = app_product(&xml)?;
        let mut dev = connected_device(&pd)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[8, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50008u16.to_be_bytes().to_vec());
        for (event, state) in [(0x04u8, 0x00u8), (0x01, 0x02), (0x02, 0x01)] {
            let mut write = vec![8, 5, 0x10, 0x01, event];
            write.extend_from_slice(&[0; 9]);
            let r = dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
            assert_eq!(prop_response_value(&r), vec![state], "event {event}");
            // The compare that follows reads the state.
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[8, 5, 0x10, 0x01]))?;
            assert_eq!(prop_response_value(&r), vec![state]);
        }
        Ok(())
    }

    #[test]
    fn test_build_system_b_knxnet_object_fills_the_first_free_index()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: an ise smart connect device (`M-007C_A-0001-10`,
        // IsIPEnabled hardware) has application object 8 from its procedure.
        // The KNXnet/IP parameter object went after it, to 9, and ETS's walk
        // `[d5 06 01 10 01]` met an absent object 6 (ETS sweep, 2026-11-05).
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlWriteProp ObjIdx="8" PropId="5" Verify="false" InlineData="04000000000000000000" AppliesTo="full,par" />
              <LdCtrlWriteProp ObjIdx="8" PropId="71" Count="3" Verify="false" AppliesTo="full,par" />"#,
        );
        let pd = app_product(&xml)?;
        let params = crate::device::knxnet_object::KnxnetParameters::dhcp(0x1101, Vec::new());
        let mut dev = connected_device(&pd)?.with_knxnet_object(&params);
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[6, 1, 0x10, 0x01]))?;
        assert_eq!(
            prop_response_value(&r),
            vec![0x00, 0x0B],
            "object 6 is type 11"
        );
        // The procedure's objects keep their indices.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50007u16.to_be_bytes().to_vec());
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[8, 5, 0x10, 0x01]))?;
        assert_eq!(
            r.responses[0].tpdu[4], 0x10,
            "object 8 has its load-state machine"
        );
        Ok(())
    }

    #[test]
    fn test_build_system_b_ip_interface_keeps_the_manufacturer_pid()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: the Siemens IP Interface Secure
        // (`M-0001_A-7205-03`) writes its unicast TTL, an 8-bit parameter, to
        // PID 236 of object type 11. ETS described it first
        // `[d2 00 0b 00 10 ec 00 00]` and stopped on the empty answer.
        let xml = glass_touch_app("1")
            .replace(
                "<Parameters>",
                r#"<ParameterTypes><ParameterType Id="M-0083_A-018C-23-81D7_PT-8bit" Name="8bit"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-0083_A-018C-23-81D7_P-1" Name="Unicast_TTL" ParameterType="M-0083_A-018C-23-81D7_PT-8bit" Value="128"><Property ObjectType="11" PropertyId="236" Offset="0" BitOffset="0" /></Parameter>"#,
            )
            .replace(
                r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
                r#"<LdCtrlWriteProp AppliesTo="all" ObjType="11" PropId="236" Verify="true" />"#,
            );
        let pd = app_product(&xml)?;
        let params = crate::device::knxnet_object::KnxnetParameters::dhcp(0x1101, Vec::new());
        let mut dev = connected_device(&pd)?.with_knxnet_object(&params);
        // ETS's description read: writable, one element, a PDT.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1D2,
            &[0x00, 0x0B, 0x00, 0x10, 0xEC, 0x00, 0x00],
        ))?;
        let d = &r.responses[0].tpdu;
        assert_eq!(d[1], 0xD3);
        assert_eq!(d[13] & 0x80, 0x80, "writable");
        assert_ne!(d[13] & 0x3F, 0, "a data type");
        assert_eq!(u16::from_be_bytes([d[14], d[15]]), 1, "one element");
        // The write that follows (Verify="true": read back).
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CE,
            &[0x00, 0x0B, 0x00, 0x10, 0xEC, 0x01, 0x00, 0x01, 0x80],
        ))?;
        assert_eq!(r.responses[0].tpdu.last(), Some(&0), "return code 0");
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CC,
            &[0x00, 0x0B, 0x00, 0x10, 0xEC, 0x01, 0x00, 0x01],
        ))?;
        assert_eq!(r.responses[0].tpdu.last(), Some(&0x80));
        // The listed copy has it too.
        let index = dev.knxnet_index().ok_or("listed")?;
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[index, 236, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), vec![0x80]);
        Ok(())
    }

    #[test]
    fn test_build_system_b_loads_a_vendor_object_by_type() -> Result<(), Box<dyn std::error::Error>>
    {
        // Bussard issue #422: the Gira Eco (`M-0008_A-C02A-21`) loads its
        // vendor object type 40960 with load controls by `ObjType`. ETS sent
        // `[d4 a0 00 00 10 05 04 00 ..]` (Unload) and got no answer (ETS
        // sweep, 2026-11-06).
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlUnload AppliesTo="all" ObjType="40960" />
              <LdCtrlLoad AppliesTo="all" ObjType="40960" />
              <LdCtrlDeclarePropDesc ObjType="40960" PropId="69" PropType="PDT_GENERIC_04" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlWriteProp AppliesTo="all" ObjType="40960" PropId="69" Count="25" Verify="true" />
              <LdCtrlWriteProp AppliesTo="all" ObjType="40960" PropId="69" StartElement="176" Count="25" Verify="true" />
              <LdCtrlLoadCompleted AppliesTo="all" ObjType="40960" />"#,
        );
        let pd = app_product(&xml)?;
        assert_eq!(pd.typed_lsm_types, vec![40960]);
        let mut dev = connected_device(&pd)?;
        let event = |e: u8| {
            let mut d = vec![0xA0, 0x00, 0x00, 0x10, 0x05, e];
            d.extend_from_slice(&[0; 9]);
            d
        };
        // Unload, then StartLoading: State_Response [a0 00 00 10 05 00 state].
        for (e, state) in [(0x04u8, 0x00u8), (0x01, 0x02)] {
            let r = dev.handle_cemi(&data(&dev, 0x1D4, &event(e)))?;
            let resp = &r.responses.last().ok_or("an answer")?.tpdu;
            assert_eq!(resp[1], 0xD6, "A_FunctionPropertyExt_State_Response");
            assert_eq!(
                resp[2..],
                [0xA0, 0x00, 0x00, 0x10, 0x05, 0x00, state],
                "event {e}"
            );
        }
        // ETS's read of 14 elements from 1 `[cc a0 00 00 10 45 0e 00 01]`:
        // PID 69 is declared PDT_GENERIC_04 and written up to element 200, so
        // 14 four-octet elements come back (the sim refused it as one element).
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CC,
            &[0xA0, 0x00, 0x00, 0x10, 0x45, 0x0E, 0x00, 0x01],
        ))?;
        let resp = &r.responses.last().ok_or("an answer")?.tpdu;
        assert_eq!(
            resp[2..10],
            [0xA0, 0x00, 0x00, 0x10, 0x45, 0x0E, 0x00, 0x01]
        );
        assert_eq!(resp.len() - 10, 14 * 4);
        // PID 69 at element 176, one 4-octet element, and its read-back.
        let mut write = vec![0xA0, 0x00, 0x00, 0x10, 69, 1, 0, 176];
        write.extend_from_slice(&[1, 2, 3, 4]);
        let r = dev.handle_cemi(&data(&dev, 0x1CE, &write))?;
        assert_eq!(r.responses.last().ok_or("an answer")?.tpdu.last(), Some(&0));
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0xA0, 0x00, 0x00, 0x10, 69, 1, 0, 176]))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu[10..],
            [1, 2, 3, 4]
        );
        // Each answer takes the next transport sequence number; ETS NAKed
        // the answer that skipped one (Gira Eco capture, 2026-11-06).
        let r = dev.handle_cemi(&data(&dev, 0x1D5, &[0xA0, 0x00, 0x00, 0x10, 0x05]))?;
        let resp = r.responses.last().ok_or("an answer")?;
        assert_eq!(resp.tpdu[0] & 0xC0, 0x40, "numbered data");
        let seq = (resp.tpdu[0] >> 2) & 0x0F;
        let r = dev.handle_cemi(&data(&dev, 0x1D4, &event(0x01)))?;
        let next = (r.responses.last().ok_or("an answer")?.tpdu[0] >> 2) & 0x0F;
        assert_eq!(next, (seq + 1) & 0x0F, "no sequence number skipped");
        // LoadCompleted: Loaded; the state read says so too.
        let r = dev.handle_cemi(&data(&dev, 0x1D4, &event(0x02)))?;
        assert_eq!(r.responses.last().ok_or("an answer")?.tpdu[8], 0x01);
        let r = dev.handle_cemi(&data(&dev, 0x1D5, &[0xA0, 0x00, 0x00, 0x10, 0x05]))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu[7..],
            [0x00, 0x01]
        );
        Ok(())
    }

    #[test]
    fn test_build_system_b_calls_a_vendor_function_by_type()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: the Gira IR-Gateway (`M-0008_A-E000-10`)
        // compares PID 207 of type 65281 and calls its PID 208 with FF. ETS
        // sent `[d4 ff 01 00 10 d0 ff]` and got only the T_ACK (ETS sweep,
        // 2026-11-06).
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlCompareProp AppliesTo="all" InlineData="01" ObjType="65281" PropId="207" />
              <LdCtrlInvokeFunctionProp AppliesTo="all" ObjType="65281" PropId="208" InlineData="FF" />"#,
        );
        let pd = app_product(&xml)?;
        assert_eq!(pd.typed_function_props, vec![(65281, 208)]);
        let mut dev = connected_device(&pd)?;
        let r = dev.handle_cemi(&data(&dev, 0x1D4, &[0xFF, 0x01, 0x00, 0x10, 0xD0, 0xFF]))?;
        let resp = &r.responses.last().ok_or("an answer")?.tpdu;
        assert_eq!(resp[1..], [0xD6, 0xFF, 0x01, 0x00, 0x10, 0xD0, 0x00]);
        // The compared property is still a data property.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CC,
            &[0xFF, 0x01, 0x00, 0x10, 0xCF, 0x01, 0x00, 0x01],
        ))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu.last(),
            Some(&0x01)
        );
        Ok(())
    }

    /// The Schneider STXF121 shape (`M-0009_A-E0EE-10-ADF8`): a module
    /// definition writes `ObjIdx="0" PropId="208" Count="164"` relative to its
    /// `BaseObjIdx` argument, instantiated with bases 6 and 7.
    pub(super) const MODULE_APP: &str = r#"<KNX><ApplicationProgram Id="M-0009_A-E0EE-10-ADF8" ApplicationNumber="57582" ApplicationVersion="16" MaskVersion="MV-07B0"><Static>
          <Code><RelativeSegment Id="RS-04" Offset="0" Size="16" LoadStateMachine="4" /></Code>
          <AddressTable /><AssociationTable /><ComObjectTable />
          <LoadProcedures><LoadProcedure MergeId="4">
            <LdCtrlDeclarePropDesc AppliesTo="full,par" ObjIdx="12" PropId="208" PropType="PDT_GENERIC_01" MaxElements="46" ReadAccess="0" WriteAccess="0" Writable="true" />
            <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="12" PropId="208" Count="11" Verify="false" />
          </LoadProcedure></LoadProcedures></Static>
          <ModuleDefs><ModuleDef Id="M-0009_A-E0EE-10-ADF8_MD-1" Name="MeteringSensor">
            <Arguments><Argument Id="M-0009_A-E0EE-10-ADF8_MD-1_A-1" Name="BaseObjectIndex" /><Argument Id="M-0009_A-E0EE-10-ADF8_MD-1_A-4" Name="MeteringSensorId" /></Arguments>
            <Static><LoadProcedures><LoadProcedure MergeId="4">
              <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="0" PropId="208" Count="164" Verify="false" InlineData="" BaseObjIdx="M-0009_A-E0EE-10-ADF8_MD-1_A-1" />
              <LdCtrlWriteProp AppliesTo="full,par" ObjIdx="12" PropId="208" StartElement="12" Verify="false" BaseStartElement="M-0009_A-E0EE-10-ADF8_MD-1_A-4" />
            </LoadProcedure></LoadProcedures></Static>
          </ModuleDef></ModuleDefs>
          <Dynamic>
            <Module Id="M-0009_A-E0EE-10-ADF8_MD-1_M-5" RefId="M-0009_A-E0EE-10-ADF8_MD-1" Name="MS1">
              <NumericArg RefId="M-0009_A-E0EE-10-ADF8_MD-1_A-1" Value="6" /><NumericArg RefId="M-0009_A-E0EE-10-ADF8_MD-1_A-4" Value="0" />
            </Module>
            <Module Id="M-0009_A-E0EE-10-ADF8_MD-1_M-1" RefId="M-0009_A-E0EE-10-ADF8_MD-1" Name="MS2">
              <NumericArg RefId="M-0009_A-E0EE-10-ADF8_MD-1_A-1" Value="7" /><NumericArg RefId="M-0009_A-E0EE-10-ADF8_MD-1_A-4" Value="1" />
            </Module>
          </Dynamic></ApplicationProgram></KNX>"#;

    #[test]
    fn test_build_system_b_module_instance_objects() -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: ETS described object 6's PID 208
        // `[d8 06 d0 00]` and stopped on the empty description (ETS sweep,
        // 2026-11-06).
        let pd = app_product(MODULE_APP)?;
        assert!(pd.written_props.contains(&(6, 208, 164, 164)));
        assert!(pd.written_props.contains(&(7, 208, 164, 164)));
        assert!(
            !pd.written_props
                .iter()
                .any(|&(o, p, _, _)| o == 0 && p == 208)
        );
        let mut dev = connected_device(&pd)?;
        for object in [6u8, 7] {
            let d = describe(&mut dev, object, 208)?;
            assert_eq!(d[3], 0x80 | 0x11, "writable, PDT_GENERIC_01");
            assert_eq!(u16::from_be_bytes([d[4], d[5]]), 164);
        }
        // ETS's chunked write, 15 elements from 1.
        let mut write = vec![6, 208, 0xF0, 0x01];
        write.extend_from_slice(&[0x5A; 15]);
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        assert_eq!(r.responses[0].tpdu[4] >> 4, 15);
        // Object 12 reaches element 13 (12 plus MS2's MeteringSensorId 1).
        let d = describe(&mut dev, 12, 208)?;
        assert!(u16::from_be_bytes([d[4], d[5]]) >= 13);
        Ok(())
    }

    #[test]
    fn test_build_system_b_vendor_object_by_index() -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #422: the Siemens dimmer `M-0001_A-9839-01` writes
        // PID 205 of object type 50215. ETS looked for it with the standard
        // property services, reading object 6's PID 1 [d5 06 01 10 01], and
        // gave up on the zero-count answer (ETS sweep, 2026-11-05).
        let xml = glass_touch_app("1").replace(
            r#"<LdCtrlWriteProp ObjIdx="7" PropId="161" Verify="false" InlineData="01" />"#,
            r#"<LdCtrlWriteProp ObjType="50215" PropId="205" Verify="false" InlineData="5A" AppliesTo="all" />"#,
        );
        let pd = app_product(&xml)?;
        let mut dev = connected_device(&pd)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[6, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50215u16.to_be_bytes().to_vec());
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[6, 205, 0x10, 0x01, 0x5A]))?;
        assert_eq!(prop_response_value(&r), vec![0x5A]);
        // The application object the compares name keeps its index.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[7, 1, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r), 50007u16.to_be_bytes().to_vec());
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
