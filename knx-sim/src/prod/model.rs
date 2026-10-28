//! Parsed model of the flash-relevant parts of a `.knxprod`.

/// The conventional load-state-machine index of the address table.
pub const LSM_ADDRESS_TABLE: u8 = 1;
/// The conventional load-state-machine index of the association table.
pub const LSM_ASSOCIATION_TABLE: u8 = 2;
/// The conventional load-state-machine index of the com-object table.
pub const LSM_COMOBJECT_TABLE: u8 = 3;

/// A `RelativeSegment` — a chunk of the application image tied to one
/// load-state machine, with its declared size and (for the code segment) the
/// decoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeSegment {
    /// The `LoadStateMachine` index this segment belongs to (e.g. 4 = app).
    pub lsm_index: u8,
    /// Declared segment size in bytes.
    pub size: u32,
    /// Offset within the segment (usually 0).
    pub offset: u32,
    /// The decoded application image bytes (from base64 `<Data>`), if present.
    pub data: Vec<u8>,
}

/// A single load-control step inside a `LoadProcedure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdCtrl {
    /// `LdCtrlRelSegment` — allocate a relative segment for `lsm_index` of
    /// `size` bytes (fill/mode carried for fidelity).
    RelSegment {
        /// Load-state-machine index.
        lsm_index: u8,
        /// Segment size in bytes.
        size: u32,
        /// Fill mode byte.
        mode: u8,
        /// Fill value.
        fill: u8,
    },
    /// `LdCtrlWriteRelMem` — write `size` bytes into object `obj_index` at
    /// `offset`, optionally verifying on read-back.
    WriteRelMem {
        /// Object (LSM) index to write.
        obj_index: u8,
        /// Offset within the segment.
        offset: u32,
        /// Number of bytes to write.
        size: u32,
        /// Whether the tool should verify the write by reading it back.
        verify: bool,
    },
    /// `LdCtrlMasterReset` — reset the device with an erase code / channel.
    MasterReset {
        /// Erase code selecting the reset scope.
        erase_code: u8,
        /// Channel number (0 = whole device).
        channel: u8,
    },
}

/// A `LoadProcedure`: an ordered list of load-control steps with a merge id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadProcedure {
    /// The `MergeId` grouping this procedure.
    pub merge_id: Option<u32>,
    /// The ordered control steps.
    pub steps: Vec<LdCtrl>,
}

/// A loadable object the device exposes, keyed by its load-state-machine index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadableObject {
    /// The load-state-machine / interface-object index.
    pub lsm_index: u8,
    /// A human name for logging (e.g. "address table").
    pub name: String,
    /// Declared maximum size in bytes, if the product data states one.
    pub max_size: Option<u32>,
    /// The code image for this object (only the application segment carries
    /// real bytes; the tables are built by the tool at flash time).
    pub image: Vec<u8>,
}

/// The flash-relevant view of one application program from a `.knxprod`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductData {
    /// The application-program id (e.g. `M-00FA_A-2500-10-51CB`).
    pub application_id: String,
    /// The `ApplicationNumber`.
    pub application_number: u32,
    /// The `ApplicationVersion`.
    pub application_version: u32,
    /// The `MaskVersion` reference (e.g. `MV-07B0`).
    pub mask_version: String,
    /// The loadable objects, sorted by LSM index.
    pub objects: Vec<LoadableObject>,
    /// The declared load procedures.
    pub load_procedures: Vec<LoadProcedure>,
    /// The relative segments, keyed by LSM index.
    pub segments: Vec<RelativeSegment>,
    /// The 10-octet object-0 PID 78 (`PID_HARDWARE_TYPE`) value this
    /// application's own `LdCtrlCompareProp` preflight expects. A factory
    /// device holds exactly this value (otherwise its own vendor procedure
    /// could never pass), so the simulated device seeds PID 78 from it.
    /// `None` when the procedure carries no such compare.
    pub hardware_type_marker: Option<Vec<u8>>,
    /// Every device-object (object 0) property the application's own
    /// `LdCtrlCompareProp` preflights expect, as `(PID, value)` from their
    /// `InlineData`: an ABB i-bus program compares `PID_ORDER_INFO` (15) with
    /// its hardware's id. A factory device of that hardware holds exactly
    /// these values, so the simulated device serves them. A compare inside a
    /// `<choose>` counts only when the product's parameter defaults select its
    /// branch (bussard issue #400), else the first compare of that PID does.
    pub device_compare_props: Vec<(u8, Vec<u8>)>,
    /// Every property the application's `LdCtrlWriteProp` steps write, as
    /// `(object index, PID, value length)`. A real device of that hardware
    /// accepts those writes (an ABB i-bus program writes the PEI type to
    /// object 4 or 5 PID 16, others object 0 PID 52 or 86), so the simulated
    /// device seeds each one writable where it lacks it.
    pub written_props: Vec<(u8, u8, usize)>,
    /// The LSM indices the application's load procedures finalise with an
    /// `LdCtrlTaskSegment` (System 7), or `None` when the product carries no
    /// procedure that completes a load (a synthetic product): then every LSM
    /// requires one.
    pub task_segment_lsms: Option<Vec<u8>>,
    /// The memory the application's `LdCtrlCompareMem` preflights expect, as
    /// `(address, the first Size octets of InlineData)`: a Zennio 0701 program
    /// compares its hardware id at `0xB610`. A factory device of that hardware
    /// holds exactly these octets, so the simulated device serves them.
    pub compare_mems: Vec<(u16, Vec<u8>)>,
    /// The properties of interface objects other than the device object that
    /// the application's own `LdCtrlCompareProp` preflights expect, as
    /// `(object index, PID, value)` (bussard issue #390: the ABB 0701 programs
    /// compare the application object's `PID_PROGRAM_VERSION`, object 3 PID
    /// 13, with their application number). A device of that hardware holds
    /// them, so the simulated device serves them.
    pub object_compare_props: Vec<(u8, u8, Vec<u8>)>,
    /// The properties the procedure compares or writes on an object it names by
    /// type (`ObjType`, bussard issue #390: the IPS 300 SREG's KNXnet/IP
    /// parameter object, type 11, and a vendor object, type 50001).
    pub typed_props: Vec<TypedProperty>,
    /// The interface-object type a property step declares for an object it
    /// addresses by index, as `(object index, ObjType)`: a step that carries
    /// both `ObjIdx` and `ObjType` names the type of the object at that index.
    /// The simulated device reports it as that object's `PID_OBJECT_TYPE`
    /// when it creates the object (bussard issue #422).
    pub object_types: Vec<(u8, u16)>,
    /// Whether the application's load procedure holds nothing but property
    /// compares and writes (and the session around them): a property-only
    /// device, the Jung IPS 300 SREG (mask 0021).
    pub property_only: bool,
}

/// A property a load procedure addresses on an object named by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedProperty {
    /// The interface object type.
    pub object_type: u16,
    /// The property id.
    pub pid: u8,
    /// The value an `LdCtrlCompareProp` expects, when the procedure compares it.
    pub compare: Option<Vec<u8>>,
    /// Whether an `LdCtrlWriteProp` writes it.
    pub written: bool,
}

impl ProductData {
    /// Find a loadable object by its LSM index.
    pub fn object(&self, lsm_index: u8) -> Option<&LoadableObject> {
        self.objects.iter().find(|o| o.lsm_index == lsm_index)
    }

    /// Find a relative segment by its LSM index.
    pub fn segment(&self, lsm_index: u8) -> Option<&RelativeSegment> {
        self.segments.iter().find(|s| s.lsm_index == lsm_index)
    }
}
