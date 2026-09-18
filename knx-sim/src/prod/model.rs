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
