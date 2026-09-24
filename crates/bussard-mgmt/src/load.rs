//! System B (mask `07B0`) table **write** side: property writes with read-back
//! validation, the load-state machine for loadable table objects, and chunked
//! `PID_TABLE` element writes.
//!
//! This is the inverse of [`crate::tables`] (the read side). Where that module
//! reads a device's group-address and association tables through interface-object
//! properties, this one drives the standardised **download procedure** that puts
//! new content into those tables: for each table object, transition it through
//! its load state (`StartLoading` → write the table → `LoadCompleted`), then
//! confirm it reached `Loaded`.
//!
//! # The load-state machine (evidence)
//!
//! Loadable interface objects (address table, association table, group object
//! table, application program) each carry a `PID_LOAD_STATE_CONTROL` property
//! (PID **5**). The machine, its states and its control events follow the
//! published KNX interface-object property definitions (EN 50090 / KNX standard
//! 3/5/1 § "Load State Machine" and 3/5/2 "Management Procedures"):
//!
//! - **Reading** `PID_LOAD_STATE_CONTROL` (start 1, count 1) returns a **single
//!   octet**, the current [`LoadState`].
//! - **Writing** `PID_LOAD_STATE_CONTROL` (start 1, count 1) takes a **single
//!   octet**, a [`LoadControl`] event, and drives the transition. The device
//!   then answers an `A_PropertyValue_Response` echoing the property's octet,
//!   which after a control write is the *resulting load state*, not the control
//!   value written — so a load-control write is validated against the expected
//!   next state, not against the value sent.
//! - **Transitions** (KNX 3/5/1 load-state machine):
//!   - `Unloaded --StartLoading--> Loading`
//!   - `Loaded   --StartLoading--> Loading`
//!   - `Loading  --LoadCompleted--> Loaded` (persists the table to non-volatile
//!     memory)
//!   - `Loading  --Unload--> Unloaded`
//!   - `Loaded   --Unload--> Unloaded`
//!   - `Error    --Unload--> Unloaded`
//!
//! A failed load (a bad table, or a device that refuses the written content)
//! leaves the object in `Error`; the only recovery is `Unload` (or ETS).
//!
//! ## Load-control writes carry the full 10-octet value, count 1
//!
//! The load-state machine keys only on the first octet of the
//! `PID_LOAD_STATE_CONTROL` value: `01` = StartLoading, `02` = LoadCompleted,
//! `03 0B …` = the 10-octet `AdditionalLoadControls` relative-segment allocation
//! (segment size, fill, …), `04` = Unload. A single octet suffices to *drive*
//! the machine, but every real ETS download writes the full 10-octet value for
//! the simple transitions too — the trailing nine octets are reserved zero. The
//! ETS→KNX-Virtual DA.tp capture (`shared-with-windows/dumpfile.pcap`) sends
//! `04/01/02 00 00 00 00 00 00 00 00 00` for Unload/StartLoading/LoadCompleted on
//! objects 1–5. [`write_load_control`] therefore emits the 10-octet
//! [`LoadControl::encode_full`] value (element count 1), byte-identical to ETS,
//! for both the load-state transitions and the segment allocation.
//!
//! Growing a table beyond its current backing store is still out of scope: bussard
//! only re-fills a segment the device already sized (via `AdditionalLoadControls`
//! relative-segment allocation), and that is documented as a limitation.
//!
//! # Everything here writes to the bus
//!
//! Unlike [`crate::tables`], these procedures mutate device state. They are only
//! ever driven by `bussard apply`, which first shows a plan, takes confirmation,
//! and writes a backup — see `bussard-download`.

use crate::apci::{self, RestartResponse};
use crate::connection::{L4Channel, Layer4Connection, property_request, property_write_request};
use crate::error::MgmtError;
use crate::tables::{PID_TABLE, PID_TABLE_REFERENCE};
use bussard_model::IndividualAddress;

/// `PID_LOAD_STATE_CONTROL` (5) — the load-state property of a loadable
/// interface object. Reading it yields a [`LoadState`]; writing it a
/// [`LoadControl`] event.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;

/// `PID_PROGRAM_VERSION` (13) — the resident application-program id of a
/// loadable interface object.
///
/// A download stamps it at the end of the load procedure (ETS writes the
/// 5-octet `[manufacturer:2][application number:2][version:1]` value to the
/// application object); reading it back says *which* application a device
/// currently runs. `bussard flash` reads it in its pre-flight to tell a
/// factory-fresh device from a programmed one (issue #79).
pub const PID_PROGRAM_VERSION: u8 = 13;

/// The load state of a loadable interface object, as read from
/// `PID_LOAD_STATE_CONTROL`.
///
/// Encoding per the KNX load-state machine (3/5/1); the current state is read
/// back as the `PID_LOAD_STATE_CONTROL` octet: `Unloaded=0, Loaded=1, Loading=2,
/// Error=3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    /// No valid content; the object is empty (value 0).
    Unloaded,
    /// Content is valid and active (value 1).
    Loaded,
    /// Open for writing; content is being replaced (value 2).
    Loading,
    /// The last load failed; recover with [`LoadControl::Unload`] (value 3).
    Error,
    /// A value outside the standard 0–3 range (forward-compatibility).
    Other(u8),
}

impl LoadState {
    /// Decodes a load-state octet.
    pub fn from_octet(v: u8) -> LoadState {
        match v {
            0 => LoadState::Unloaded,
            1 => LoadState::Loaded,
            2 => LoadState::Loading,
            3 => LoadState::Error,
            other => LoadState::Other(other),
        }
    }

    /// The octet a device reports for this state.
    pub fn octet(self) -> u8 {
        match self {
            LoadState::Unloaded => 0,
            LoadState::Loaded => 1,
            LoadState::Loading => 2,
            LoadState::Error => 3,
            LoadState::Other(v) => v,
        }
    }
}

impl std::fmt::Display for LoadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadState::Unloaded => write!(f, "Unloaded"),
            LoadState::Loaded => write!(f, "Loaded"),
            LoadState::Loading => write!(f, "Loading"),
            LoadState::Error => write!(f, "Error"),
            LoadState::Other(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// A load-control event written to `PID_LOAD_STATE_CONTROL` to drive the load
/// state machine.
///
/// Encoding per the KNX load-state machine (the first control octet):
/// `NoOperation=0, StartLoading=1, LoadCompleted=2, AdditionalLoadControls=3,
/// Unload=4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadControl {
    /// No-op (value 0).
    NoOperation,
    /// Open the object for writing → `Loading` (value 1).
    StartLoading,
    /// Persist and activate the written content → `Loaded` (value 2).
    LoadCompleted,
    /// Begin a 10-octet additional-load-controls structure (value 3). Not used
    /// by this module (see the module docs).
    AdditionalLoadControls,
    /// Discard content → `Unloaded` (value 4).
    Unload,
}

impl LoadControl {
    /// The single control octet written to `PID_LOAD_STATE_CONTROL`.
    pub fn octet(self) -> u8 {
        match self {
            LoadControl::NoOperation => 0,
            LoadControl::StartLoading => 1,
            LoadControl::LoadCompleted => 2,
            LoadControl::AdditionalLoadControls => 3,
            LoadControl::Unload => 4,
        }
    }

    /// Encodes the full 10-octet `PID_LOAD_STATE_CONTROL` value ETS writes for a
    /// simple load-control transition: the control octet in position 0 and nine
    /// reserved zero octets padding the value to the standard
    /// `AdditionalLoadControls` width.
    ///
    /// The load-state machine keys only on the first octet ([`Self::octet`]); the
    /// trailing zeros are reserved. Real ETS downloads — including the
    /// ETS→KNX-Virtual DA.tp capture (`shared-with-windows/dumpfile.pcap`, obj1–5
    /// `Unload`/`StartLoading`/`LoadCompleted` all sent as
    /// `04/01/02 00 00 00 00 00 00 00 00 00`) — write the full 10-octet form for
    /// every transition, so bussard emits it too for byte-parity. The element
    /// count on the wire stays 1 (a single `PDT_CONTROL` element); only the value
    /// width is 10 octets, exactly as the capture shows.
    pub fn encode_full(self) -> [u8; 10] {
        let mut v = [0u8; 10];
        v[0] = self.octet();
        v
    }

    /// The load state a device is expected to reach after this control on a
    /// well-behaved single-object write, or `None` when the resulting state is
    /// not verified.
    ///
    /// `Unload` is deliberately `None`: it is a best-effort reset issued before
    /// re-loading, and some conformant-in-practice stacks (KNX Virtual) leave the
    /// object reporting `Loaded` rather than `Unloaded` after it — exactly as ETS
    /// tolerates, since the following `StartLoading` opens the object from any
    /// state and the terminal `LoadCompleted` (`Some(Loaded)`) is the authoritative
    /// verification. A genuine `Error` after any control is still caught separately.
    pub fn expected_state(self) -> Option<LoadState> {
        match self {
            LoadControl::StartLoading => Some(LoadState::Loading),
            LoadControl::LoadCompleted => Some(LoadState::Loaded),
            LoadControl::Unload
            | LoadControl::NoOperation
            | LoadControl::AdditionalLoadControls => None,
        }
    }
}

impl std::fmt::Display for LoadControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadControl::NoOperation => write!(f, "NoOperation"),
            LoadControl::StartLoading => write!(f, "StartLoading"),
            LoadControl::LoadCompleted => write!(f, "LoadCompleted"),
            LoadControl::AdditionalLoadControls => write!(f, "AdditionalLoadControls"),
            LoadControl::Unload => write!(f, "Unload"),
        }
    }
}

/// Errors from the write side, distinct from the read side's [`crate::tables`].
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The device did not echo back the value we wrote (a mismatch = failure).
    #[error(
        "{address}: property write to object {object_index}/PID {property_id} was not confirmed \
         (wrote {wrote:02X?}, device echoed {echoed:02X?})"
    )]
    WriteNotConfirmed {
        /// The device.
        address: IndividualAddress,
        /// The interface object index.
        object_index: u8,
        /// The property id.
        property_id: u8,
        /// The octets we wrote.
        wrote: Vec<u8>,
        /// The octets the device echoed.
        echoed: Vec<u8>,
    },

    /// A load-control write did not leave the object in the expected state.
    ///
    /// `context` carries optional discovery detail the caller (the flash engine)
    /// folds in: the targeted object's discovered interface-object type and the
    /// full discovered object table. It is appended to the message when present so
    /// a bare "object 3 did not reach Loading" becomes actionable — see
    /// [`LoadStateContext`].
    #[error(
        "{address}: object {object_index} did not reach {expected} after {control} \
         (device reports {actual}){context}"
    )]
    UnexpectedLoadState {
        /// The device.
        address: IndividualAddress,
        /// The interface object index.
        object_index: u8,
        /// The control event written.
        control: LoadControl,
        /// The state we expected the device to reach.
        expected: LoadState,
        /// The state the device actually reports.
        actual: LoadState,
        /// Discovery context (object type + discovered object table), or the
        /// empty default when the primitive was driven without it.
        context: LoadStateContext,
    },

    /// The KNX Data Secure security interface object (type 17) did not reach
    /// the load state a load-control command should leave it in (issue #156).
    #[error(
        "{address}: the Data Secure security object did not reach {expected} after {control} \
         (device reports {actual})"
    )]
    SecurityObjectState {
        /// The device.
        address: IndividualAddress,
        /// The control event sent.
        control: LoadControl,
        /// The state it should have reached.
        expected: LoadState,
        /// The state the device reported.
        actual: LoadState,
    },

    /// The Data Secure security-object program could not be built for the
    /// device (a secured group address without a key, a group object outside
    /// the table). Nothing was written to the security object.
    #[error("{address}: cannot program the Data Secure security object: {reason}")]
    SecurityProgram {
        /// The device.
        address: IndividualAddress,
        /// Why (names addresses and objects, never a key).
        reason: String,
    },

    /// The device has no interface object at `object_index`: its
    /// `PID_LOAD_STATE_CONTROL` access answered with element count 0, the KNX
    /// negative response for a property (or object) the device does not have
    /// (issue #178: the Jung 2308.16REGHM answers `05 05 00 01` for object 5).
    #[error(
        "{address}: object {object_index} absent on the device (PID_LOAD_STATE_CONTROL answered \
         with count 0)"
    )]
    ObjectAbsent {
        /// The device.
        address: IndividualAddress,
        /// The interface object (load-state machine) index the device lacks.
        object_index: u8,
    },

    /// The object went into `Error` during a load — recover with `Unload`/ETS.
    #[error(
        "{address}: object {object_index} entered the load Error state (a bad table or refused \
         content); the object must be re-loaded or repaired with ETS"
    )]
    LoadError {
        /// The device.
        address: IndividualAddress,
        /// The interface object index.
        object_index: u8,
    },

    /// A write into resident memory needs the object `Loaded` and the device
    /// reports another state, so nothing was written (the parameter-only
    /// download, issue #146).
    #[error(
        "{address}: load-state machine {object_index} is {actual}, not Loaded; a parameter-only \
         download writes only into a loaded application, so nothing was written. Program the \
         device with a full `bussard flash --force {address}`"
    )]
    NotLoaded {
        /// The device.
        address: IndividualAddress,
        /// The load-state machine (object) index.
        object_index: u8,
        /// The state the device reports.
        actual: LoadState,
    },

    /// A `LdCtrlLoadImageProp` integrity check failed: the device's
    /// `PID_MCB_TABLE` CRC over the segment it stored does not match the CRC the
    /// tool computed over the bytes it wrote — the image did not land intact.
    #[error(
        "{address}: object {object_index} image integrity check failed — device \
         PID_MCB_TABLE CRC is {device_crc:#06X} but the written image CRC is \
         {expected_crc:#06X} (the segment was not stored intact)"
    )]
    ImagePropMismatch {
        /// The device.
        address: IndividualAddress,
        /// The interface object index whose MCB was checked.
        object_index: u8,
        /// The CRC16-CCITT the tool computed over the bytes it wrote.
        expected_crc: u16,
        /// The CRC16-CCITT the device reported in its `PID_MCB_TABLE`.
        device_crc: u16,
    },

    /// A `LdCtrlCompareProp` verify failed: the device's stored interface-object
    /// property does not match the expected data the vendor procedure declared
    /// (after masking). The flash is aborted — the device is not in the state the
    /// procedure requires (e.g. wrong firmware/hardware variant, or a resource the
    /// application depends on is absent).
    #[error(
        "{address}: object {object_index}/PID {property_id} compare failed — expected \
         {expected:02X?} but device holds {actual:02X?}{mask_note} (the application's \
         LdCtrlCompareProp precondition is not met)"
    )]
    PropCompareMismatch {
        /// The device.
        address: IndividualAddress,
        /// The interface object index whose property was compared.
        object_index: u8,
        /// The property id compared.
        property_id: u8,
        /// The expected bytes (from the op's `InlineData`).
        expected: Vec<u8>,
        /// The bytes the device actually returned (truncated to the expected len).
        actual: Vec<u8>,
        /// A human note naming the mask when one narrowed the comparison.
        mask_note: String,
    },

    /// A `LdCtrlCompareRelMem` verify failed: the device's stored relative
    /// (segment-relative) memory does not match the expected data the vendor
    /// procedure declared (after masking, and after inversion when the op sets
    /// `Invert`). The flash is aborted — the device memory is not in the state the
    /// procedure requires (e.g. wrong firmware/hardware variant, or a resource the
    /// application depends on holds an unexpected value).
    #[error(
        "{address}: object {object_index} relative memory at {addr:#08X} (base {base:#08X} + \
         offset {offset}) compare failed — {sense} {expected:02X?} but device holds \
         {actual:02X?}{mask_note} (the application's LdCtrlCompareRelMem precondition is not met)"
    )]
    RelMemCompareMismatch {
        /// The device.
        address: IndividualAddress,
        /// The interface object index whose segment was compared.
        object_index: u8,
        /// The device-supplied segment base the compare read from (24-bit).
        base: u32,
        /// The vendor offset within that segment.
        offset: u32,
        /// The absolute read address (`base + offset`), up to 24-bit.
        addr: u32,
        /// A human note on the comparison sense ("expected" for a match compare,
        /// "expected to differ from" for an inverted compare).
        sense: &'static str,
        /// The expected bytes (from the op's `InlineData`).
        expected: Vec<u8>,
        /// The bytes the device actually returned (truncated to the expected len).
        actual: Vec<u8>,
        /// A human note naming the mask when one narrowed the comparison.
        mask_note: String,
    },

    /// A write step's resolved target address does not fit the 24-bit
    /// extended-memory address space. The device-supplied segment base plus the
    /// vendor offset (or an absolute address) exceeded `0xFF_FFFF`, which a cast
    /// would silently truncate — streaming the image to the WRONG device memory.
    /// Aborted before any octet is written.
    #[error(
        "{address}: write target address is out of range — {detail} exceeds the 24-bit A_Memory \
         space (max {max:#08X}); aborting rather than truncating and writing to the wrong memory",
        max = crate::apci::MAX_MEMORY_ADDRESS
    )]
    AddressOutOfRange {
        /// The device.
        address: IndividualAddress,
        /// Which components put the address out of range (base+offset / address).
        detail: String,
    },

    /// The device answered a master-reset `A_Restart` with a non-zero error code
    /// in its `A_Restart_Response`: it refused the reset and erased nothing.
    #[error(
        "{address}: device refused the master reset (erase code {erase_code}, channel \
         {channel_number}): A_Restart_Response error code {error_code} ({meaning})",
        meaning = restart_error_meaning(*error_code)
    )]
    RestartRefused {
        /// The device.
        address: IndividualAddress,
        /// The erase code that was requested.
        erase_code: u8,
        /// The channel number that was requested.
        channel_number: u8,
        /// The non-zero error code the device answered.
        error_code: u8,
    },

    /// An underlying management error (absent, NAK, disconnect, malformed).
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
}

/// A readable name for an `A_Restart_Response` error code (KNX spec values).
fn restart_error_meaning(error_code: u8) -> &'static str {
    match error_code {
        0x00 => "accepted",
        0x01 => "access denied",
        0x02 => "unsupported erase code",
        0x03 => "invalid channel number",
        _ => "device-specific error",
    }
}

/// Discovery context attached to an [`WriteError::UnexpectedLoadState`] so a
/// load-state mismatch names *which* object was targeted and what the device's
/// interface-object table actually looks like.
///
/// A bare "object 3 did not reach Loading" is nearly useless in the field: the
/// index alone does not say what object 3 *is*, nor whether the discovery even
/// found the object type it should have. This carries the discovered object
/// type of the targeted index (when it was read) and the full discovered object
/// table (`index → object type`), rendered as a `; ...` suffix on the error.
/// The empty [`Default`] renders nothing, so primitives that are driven without
/// discovery context (the table-apply path) keep their original message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadStateContext {
    /// The discovered interface-object type at the targeted index, if it was
    /// read during discovery (`None` when the index was out of the discovered
    /// range or discovery did not run).
    pub object_type: Option<u16>,
    /// The full discovered object table as `(index, object_type)` pairs, in
    /// index order. Empty when no discovery ran.
    pub object_table: Vec<(u8, u16)>,
}

impl std::fmt::Display for LoadStateContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.object_type.is_none() && self.object_table.is_empty() {
            return Ok(());
        }
        write!(f, " — ")?;
        match self.object_type {
            Some(ot) => write!(
                f,
                "target object has interface-object type {ot} ({})",
                object_type_name(ot)
            )?,
            None => write!(f, "target object type was not discovered")?,
        }
        if !self.object_table.is_empty() {
            let table: Vec<String> = self
                .object_table
                .iter()
                .map(|(idx, ot)| format!("{idx}:{ot}({})", object_type_name(*ot)))
                .collect();
            write!(f, "; discovered object table [{}]", table.join(", "))?;
        }
        Ok(())
    }
}

/// A short human name for a standard KNX interface-object type, for the
/// discovered-object-table rendering. Unknown types render as `"?"`.
fn object_type_name(ot: u16) -> &'static str {
    match ot {
        0 => "device",
        1 => "address-table",
        2 => "association-table",
        3 => "application-program",
        4 => "interface-program",
        _ => "?",
    }
}

/// Result alias for the write side.
pub type Result<T> = std::result::Result<T, WriteError>;

/// Writes a property value and validates the device's echoed read-back.
///
/// Sends `A_PropertyValue_Write` (object index, PID, count, start, value) and
/// reads the `A_PropertyValue_Response` the device answers with. Per the KNX
/// application layer the response echoes the *stored* value, so this compares
/// the echoed octets to `value` and fails with [`WriteError::WriteNotConfirmed`]
/// on any mismatch (a partial echo, a truncated store, or an outright NAK-turned
/// error surfaces here).
///
/// `expected_echo`, when `Some`, overrides what the echo is compared against —
/// used for a load-control write, where the device echoes the *resulting load
/// state* rather than the control octet written.
pub async fn write_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    count: u8,
    start: u16,
    value: &[u8],
    expected_echo: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let resp = property_write_request(l4, object_index, property_id, count, start, value).await?;
    let echoed = resp.data;
    let want = expected_echo.unwrap_or(value);
    // A zero-count response means the device refused the write outright.
    if resp.count == 0 || echoed != want {
        return Err(WriteError::WriteNotConfirmed {
            address: l4.target(),
            object_index,
            property_id,
            wrote: want.to_vec(),
            echoed,
        });
    }
    Ok(echoed)
}

/// Reads the current [`LoadState`] of a loadable object (`PID_LOAD_STATE_CONTROL`
/// element 1, a single octet).
pub async fn read_load_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<LoadState> {
    let resp = property_request(l4, object_index, PID_LOAD_STATE_CONTROL, 1, 1).await?;
    if resp.count == 0 || resp.data.is_empty() {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "load state property is not readable (object {object_index}, count {}, {} octet(s))",
                resp.count,
                resp.data.len()
            ),
        }));
    }
    Ok(LoadState::from_octet(resp.data[0]))
}

/// Reads the resident application-program id (`PID_PROGRAM_VERSION`, element 1)
/// of a loadable object.
///
/// `Ok(None)` means the device answered the read but reports no such property
/// (zero elements, or an empty value) — common on objects that never carry an
/// application id. `Ok(Some(bytes))` is the stored value verbatim; ETS's 5-octet
/// `[manufacturer:2][application number:2][version:1]` layout is the usual shape,
/// but the octets are returned raw so a device with its own length still reads
/// back. A transport failure propagates as [`WriteError`].
pub async fn read_program_version<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<Option<Vec<u8>>> {
    let resp = property_request(l4, object_index, PID_PROGRAM_VERSION, 1, 1).await?;
    if resp.count == 0 || resp.data.is_empty() {
        return Ok(None);
    }
    Ok(Some(resp.data))
}

/// Realises an `LdCtrlMasterReset` op the way ETS→KNX-Virtual does on the wire:
/// as a **bare `A_Restart`** (APCI [`A_RESTART`](crate::apci::A_RESTART) = `0x380`,
/// no payload), not the confirmed master-reset `A_Restart` (`0x381` + erase/channel).
///
/// The ETS→KNX-Virtual DA.tp capture shows the mid-procedure master reset sent as
/// `4f 80` — a numbered `A_Restart` with an empty APDU. The device T_ACKs it at
/// the transport layer and then simply reboots; it sends **no** application-layer
/// `A_Restart_Response`. So this sends the bare restart as a numbered telegram
/// (requiring the transport ACK, since a request that never lands is a real
/// failure) and treats the following silence / disconnect / mid-session drop as
/// the expected accepted outcome — the device is rebooting. The `erase_code` and
/// `channel_number` from the op are accepted for the trace/label but are **not**
/// on the wire in this realisation (a bare `A_Restart` carries no operands); they
/// are logged for diagnosis only.
///
/// Clean-room: encoding and semantics from the published KNX spec (A_Restart) and
/// verified against the real ETS→KNX-Virtual capture (bare `0x380`).
pub async fn master_reset_via_basic_restart<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    _erase_code: u8,
    _channel_number: u8,
) -> Result<()> {
    let (apci, payload) = crate::apci::encode_restart(0);
    // Fire-and-forget: a device reboots on A_Restart and never T_ACKs it (it
    // drops the L4 link immediately), so send without awaiting the ACK — waiting
    // would retransmit and spuriously report the device absent. The caller waits
    // out the reboot and reconnects.
    l4.send_data_unacked(apci, &payload).await?;
    Ok(())
}

/// The longest bussard waits on a device's `A_Restart_Response` process time.
///
/// The process time is a 16-bit count of seconds, so a corrupt or hostile answer
/// could ask for 18 hours. The ETS captures (issue #117) show 8 s for a factory
/// reset and 0 s for a confirmed restart; a minute is well past both.
pub const MAX_RESTART_PROCESS_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to wait after a confirmed master reset before reconnecting: the
/// device's reported process time, capped at [`MAX_RESTART_PROCESS_WAIT`].
pub fn restart_process_wait(response: &RestartResponse) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(response.process_time_s)).min(MAX_RESTART_PROCESS_WAIT)
}

/// Sends a **confirmed master reset**: `A_Restart` with the master-reset
/// restart-type bit (APCI `0x381`) and the two octets `[erase_code,
/// channel_number]`, as a numbered request, and reads the device's
/// `A_Restart_Response` (APCI `0x3A1`).
///
/// This is the ETS wire shape for the factory reset that opens an initial System
/// B download (`4f 81 07 00` answered by `4f a1 00 00 08`, erase code 7) and for
/// the confirmed restart that ends it (erase code 1), both from the issue #117
/// captures. After answering, the device reboots and drops the L4 connection, so
/// the caller must wait [`restart_process_wait`] and reconnect; this function
/// only performs the exchange.
///
/// Returns the decoded response on error code `0`. A non-zero error code is
/// [`WriteError::RestartRefused`]; a response with another APCI is
/// [`MgmtError::MalformedResponse`]; silence surfaces the connection's own error.
///
/// `LdCtrlMasterReset` ops in a load procedure keep using
/// [`master_reset_via_basic_restart`], which is what KNX Virtual expects.
pub async fn master_reset<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    erase_code: u8,
    channel_number: u8,
) -> Result<RestartResponse> {
    let address = l4.target();
    let (apci, payload) = crate::apci::encode_master_reset(erase_code, channel_number);
    let (resp_apci, resp) = l4.request(apci, &payload).await?;
    if resp_apci != crate::apci::A_RESTART_RESPONSE {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address,
            reason: format!(
                "expected A_Restart_Response (APCI {:#05X}) to a master reset, got APCI \
                 {resp_apci:#05X}",
                crate::apci::A_RESTART_RESPONSE
            ),
        }));
    }
    let response = crate::apci::decode_restart_response_full(&resp);
    if response.error_code != 0 {
        return Err(WriteError::RestartRefused {
            address,
            erase_code,
            channel_number,
            error_code: response.error_code,
        });
    }
    Ok(response)
}

/// Reads an interface-object property and compares it byte-for-byte against
/// `expected`, honouring an optional `mask` — the execution of a vendor
/// `LdCtrlCompareProp` op (the verify twin of [`write_property`]).
///
/// Reads element 1 of `property_id` on `object_index` via `A_PropertyValue_Read`
/// (the same primitive [`read_load_state`] and [`read_mcb_table`] use), then
/// compares the first `expected.len()` returned octets against `expected`. When
/// `mask` is `Some`, each position is compared only where the mask byte is
/// non-zero (`0xFF` in ETS data = compare, `0x00` = ignore); a `mask` shorter
/// than `expected` compares every remaining position. On any mismatch this
/// returns [`WriteError::PropCompareMismatch`] with the expected and actual bytes
/// in hex, so a failed precondition aborts the flash loudly with detail.
///
/// A device that answers a zero-count response, or fewer octets than `expected`,
/// is a mismatch too (the precondition property is not readable / not present as
/// declared). Reading the property itself failing surfaces the underlying
/// [`MgmtError`].
pub async fn compare_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    property_id: u8,
    expected: &[u8],
    mask: Option<&[u8]>,
) -> Result<()> {
    let address = l4.target();
    let resp = property_request(l4, object_index, property_id, 1, 1).await?;

    let actual: Vec<u8> = resp.data.iter().take(expected.len()).copied().collect();
    let mask_note = match mask {
        Some(m) => format!(" (mask {m:02X?})"),
        None => String::new(),
    };

    // A refused/short read cannot satisfy the compare: the declared precondition
    // property is not present as the procedure expects.
    let matches = resp.count != 0
        && actual.len() == expected.len()
        && expected.iter().zip(&actual).enumerate().all(|(i, (e, a))| {
            let m = mask.and_then(|m| m.get(i)).copied().unwrap_or(0xFF);
            (e & m) == (a & m)
        });

    if !matches {
        return Err(WriteError::PropCompareMismatch {
            address,
            object_index,
            property_id,
            expected: expected.to_vec(),
            actual,
            mask_note,
        });
    }
    Ok(())
}

/// Whether a `LdCtrlCompareRelMem` comparison passes, given the `expected` bytes,
/// the `actual` bytes the device returned, an optional `mask`, and the `invert`
/// flag.
///
/// - Each position is compared under the mask: `mask[i]` non-zero compares that
///   position, `0x00` ignores it; a mask shorter than `expected` compares every
///   remaining position (`0xFF`).
/// - Without `invert`, `actual` must **equal** `expected` under the mask; with
///   `invert`, it must **differ**.
/// - A short read (`actual` shorter than `expected`) never passes, regardless of
///   sense — the precondition memory is not readable as declared.
fn rel_mem_compare_passes(
    expected: &[u8],
    actual: &[u8],
    mask: Option<&[u8]>,
    invert: bool,
) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let equal_under_mask = expected.iter().zip(actual).enumerate().all(|(i, (e, a))| {
        let m = mask.and_then(|m| m.get(i)).copied().unwrap_or(0xFF);
        (e & m) == (a & m)
    });
    if invert {
        !equal_under_mask
    } else {
        equal_under_mask
    }
}

/// Reads relative (segment-relative) device memory and compares it byte-for-byte
/// against `expected`, honouring an optional `mask` and an `invert` flag — the
/// execution of a vendor `LdCtrlCompareRelMem` op (the memory twin of
/// [`compare_property`] and the verify counterpart of [`write_memory`]).
///
/// The read starts at the absolute address `base + offset`, where `base` is the
/// device-reported segment address the caller resolved from the object's
/// `PID_TABLE_REFERENCE` (exactly as a `WriteRelMem` resolves its write base).
/// `expected.len()` octets are read, in telegrams sized by the device's
/// **negotiated** `PID_MAX_APDU_LENGTH` (issue #80 — a fixed 63 sent an extended
/// frame to a device advertising 15), then compared against `expected`:
///
/// - When `mask` is `Some`, each position is compared only where the mask byte is
///   non-zero (`0xFF` in ETS data = compare, `0x00` = ignore); a `mask` shorter
///   than `expected` compares every remaining position.
/// - When `invert` is `false` (the default), the device memory must **equal**
///   `expected` under the mask.
/// - When `invert` is `true` (`Invert="true"` on the op), the device memory must
///   **differ** from `expected` under the mask — the check passes on a mismatch
///   and fails on an exact match.
///
/// On a failed comparison this returns [`WriteError::RelMemCompareMismatch`] with
/// the resolved address and the expected and actual bytes in hex, so a failed
/// precondition aborts the flash loudly with detail. A device that answers with
/// fewer octets than `expected` (a short/refused read) is a failure too: the
/// precondition memory is not readable as the procedure expects. An empty
/// `expected` is a vacuous pass.
///
/// Clean-room: the `A_Memory_Read`/`A_Memory_Response` framing is the published
/// KNX application layer (KNX Spec 3/3/7 Application Layer); the `InlineData` /
/// `Mask` / `Invert` compare semantics follow the ETS `LdCtrlCompareRelMem`
/// element definition (KNX Spec 3/5/2 Management Procedures), the same mask
/// convention [`compare_property`] applies for `LdCtrlCompareProp`.
pub async fn compare_rel_mem<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    base: u32,
    offset: u32,
    expected: &[u8],
    mask: Option<&[u8]>,
    invert: bool,
) -> Result<()> {
    let address = l4.target();

    if expected.is_empty() {
        return Ok(());
    }

    // Resolve the absolute read address; refuse rather than truncate if base +
    // offset (or the read span) runs past the 24-bit extended-memory space.
    // `read_memory` picks the plain or extended service from the address itself,
    // so a base above 0xFFFF verifies via A_MemoryExtended_Read.
    let start = base
        .checked_add(offset)
        .filter(|&a| a <= apci::MAX_MEMORY_ADDRESS)
        .ok_or_else(|| WriteError::AddressOutOfRange {
            address,
            detail: format!("segment base {base:#X} + offset {offset:#X}"),
        })?;
    u64::from(start)
        .checked_add(expected.len() as u64)
        .filter(|&e| e <= u64::from(apci::MAX_MEMORY_ADDRESS) + 1)
        .ok_or_else(|| WriteError::AddressOutOfRange {
            address,
            detail: format!("read of {} octet(s) from {start:#X}", expected.len()),
        })?;

    // Read the required span in chunks the device actually accepts: the negotiated
    // max-APDU cap for whichever service `read_memory` will pick for this address
    // (issue #58/#80). A fixed 63 here handed a 15-octet-APDU device an extended
    // frame it may reject.
    let chunk = crate::memory::chunk_for(l4, start, expected.len());
    let mut actual: Vec<u8> = Vec::with_capacity(expected.len());
    while actual.len() < expected.len() {
        let want = (expected.len() - actual.len()).min(chunk);
        let addr = start.checked_add(actual.len() as u32).ok_or_else(|| {
            WriteError::AddressOutOfRange {
                address,
                detail: format!("read chunk at {start:#X} + {}", actual.len()),
            }
        })?;
        let got = read_memory(l4, addr, want as u8).await?;
        if got.is_empty() {
            // A device that answers a read with zero octets cannot satisfy the
            // compare: stop and let the length check below report the shortfall.
            break;
        }
        actual.extend_from_slice(&got);
    }
    actual.truncate(expected.len());

    let mask_note = match mask {
        Some(m) => format!(" (mask {m:02X?})"),
        None => String::new(),
    };

    let ok = rel_mem_compare_passes(expected, &actual, mask, invert);

    if !ok {
        return Err(WriteError::RelMemCompareMismatch {
            address,
            object_index,
            base,
            offset,
            addr: start,
            sense: if invert {
                "expected to differ from"
            } else {
                "expected"
            },
            expected: expected.to_vec(),
            actual,
            mask_note,
        });
    }
    Ok(())
}

/// The load state a device reports in the `A_PropertyValue_Response` to a
/// load-control write when the event took effect the conformant way, or `None`
/// for an event whose answer is never trusted on its own.
///
/// Every ETS download in the captures sends one `PID_LOAD_STATE_CONTROL` write
/// per event and continues on this answer without reading PID 5 back (issue
/// #211): the 07B0 pcaps of 1.1.12, 1.1.16, 1.1.5 (Data Secure) carry 20/19/19
/// load-control writes and no PID 5 read, the 0705 pcap of 1.1.52 carries 24.
/// The devices answer `Unload` with `00` (Unloaded), `StartLoading` and the
/// `LdCtrlRelSegment` record with `02` (Loading) and `LoadCompleted` with `01`
/// (Loaded).
fn trusted_echo(control: LoadControl) -> Option<LoadState> {
    match control {
        LoadControl::Unload => Some(LoadState::Unloaded),
        LoadControl::StartLoading | LoadControl::AdditionalLoadControls => Some(LoadState::Loading),
        LoadControl::LoadCompleted => Some(LoadState::Loaded),
        LoadControl::NoOperation => None,
    }
}

/// The resulting load state carried by the answer to a load-control write,
/// when it can stand in for a separate `PID_LOAD_STATE_CONTROL` read: the
/// answer has a non-zero element count, exactly one data octet, and that octet
/// is the state [`trusted_echo`] expects for `control`.
///
/// Anything else (no octet, the 10-octet event echoed back, another state such
/// as KNX Virtual's `Loaded` after `StartLoading`, #47, or `Error`) yields
/// `None` and the caller falls back to the read-back it always did.
pub fn echoed_load_state(
    control: LoadControl,
    response: &crate::apci::PropertyValueResponse,
) -> Option<LoadState> {
    let expected = trusted_echo(control)?;
    match (response.count, response.data.as_slice()) {
        (1.., [octet]) if LoadState::from_octet(*octet) == expected => Some(expected),
        _ => None,
    }
}

/// Writes a load control to a loadable object and confirms the resulting load
/// state.
///
/// The value is the full 10-octet `PID_LOAD_STATE_CONTROL` structure ETS writes
/// ([`LoadControl::encode_full`]): the control octet followed by nine reserved
/// zero octets, element count 1. This is what every real ETS download sends,
/// including the ETS→KNX-Virtual DA.tp capture, so bussard is byte-identical to
/// ETS on these transitions.
///
/// The device answers the write with the *resulting* [`LoadState`]. When that
/// answer is the one octet a conformant device sends for `control` (see
/// [`echoed_load_state`]) it is the confirmation, as for ETS, and no read
/// follows (issue #211). Otherwise the state is read back with
/// [`read_load_state`], the fallback for a stack that answers without a state
/// octet or with an unexpected one. The state is then validated against
/// [`LoadControl::expected_state`]: a device that lands in [`LoadState::Error`]
/// surfaces [`WriteError::LoadError`]; any other mismatch surfaces
/// [`WriteError::UnexpectedLoadState`].
pub async fn write_load_control<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    control: LoadControl,
) -> Result<LoadState> {
    let address = l4.target();
    let control_value = control.encode_full();
    let resp = property_write_request(
        l4,
        object_index,
        PID_LOAD_STATE_CONTROL,
        1,
        1,
        &control_value,
    )
    .await?;
    let state = match echoed_load_state(control, &resp) {
        Some(state) => state,
        None => read_load_state(l4, object_index).await?,
    };
    if state == LoadState::Error {
        return Err(WriteError::LoadError {
            address,
            object_index,
        });
    }
    if let Some(expected) = control.expected_state() {
        // `StartLoading` opens the object for writing: a conformant device reports
        // `Loading`, but some lenient stacks (notably KNX Virtual) snap straight to
        // `Loaded`. Both leave the object open to receive the image, so accept
        // either and rely on the final `LoadCompleted` + MCB CRC verify to confirm
        // the content landed intact. A genuine failure still surfaces as `Error`
        // (rejected above) or `Unloaded`. `LoadCompleted` stays strict — it must
        // reach `Loaded`, which is the success signal.
        let acceptable = match control {
            LoadControl::StartLoading => matches!(state, LoadState::Loading | LoadState::Loaded),
            _ => state == expected,
        };
        if !acceptable {
            return Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual: state,
                context: LoadStateContext::default(),
            });
        }
    }
    Ok(state)
}

// --- Segment allocation via AdditionalLoadControls -------------------------

/// The `AdditionalLoadControls` sub-command for a **relative** (device-placed)
/// segment allocation — "Data Relative Allocation".
///
/// This is the KNX standard's `LdCtrlRelSegment` service (KNX 3/5/2 "Management
/// Procedures", `AdditionalLoadControls` sub-command `0x0B`): the tool asks the
/// device to allocate a backing segment of a given size and the device chooses
/// the address, which is read back afterwards via [`PID_TABLE_REFERENCE`]. The
/// structure carries a big-endian `u32` size at `data[2..6]`, a fill flag at
/// `data[6]` and a fill byte at `data[7]` (see [`encode_rel_segment`]).
pub const LD_CTRL_REL_SEGMENT: u8 = 0x0B;

/// The fill flag `data[6]` of a relative allocation: `0x01` fills the freshly
/// allocated segment with the fill byte, `0x00` leaves it untouched (KNX 3/5/2
/// `LdCtrlRelSegment`).
const LD_CTRL_FILL: u8 = 0x01;

/// Encodes the 10-octet `AdditionalLoadControls` property value for a
/// **relative** segment allocation (`LdCtrlRelSegment`), written to
/// `PID_LOAD_STATE_CONTROL` while the object is in [`LoadState::Loading`].
///
/// Layout (KNX 3/5/2 `LdCtrlRelSegment`):
///
/// | octet | field                | value                                    |
/// |-------|----------------------|------------------------------------------|
/// | 0     | load event           | [`LoadControl::AdditionalLoadControls`] (3) |
/// | 1     | sub-command          | [`LD_CTRL_REL_SEGMENT`] (`0x0B`)         |
/// | 2..6  | size (u32, BE)       | `((data[2]<<24)|…|data[5])`              |
/// | 6     | fill flag            | `0x01` = fill, else no fill              |
/// | 7     | fill byte            | the byte written when the fill flag set  |
/// | 8..10 | reserved (`0x00`)    | pads the structure to the standard 10    |
///
/// The property value is exactly 10 octets. Octets 8–9 are reserved zero in the
/// relative form (only `data[0..8]` is significant); they keep the structure at
/// the standard `AdditionalLoadControls` width so a stricter device that expects
/// the full 10-octet write still accepts it.
pub fn encode_rel_segment(size: u32, fill_byte: Option<u8>) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = LD_CTRL_REL_SEGMENT;
    v[2..6].copy_from_slice(&size.to_be_bytes());
    if let Some(byte) = fill_byte {
        v[6] = LD_CTRL_FILL;
        v[7] = byte;
    }
    v
}

/// The device-reported result of a successful [`allocate_segment`]: the absolute
/// memory address at which the device placed the segment, and the requested size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentAllocation {
    /// The segment's start address, as the device reports it through
    /// `PID_TABLE_REFERENCE` after the allocation. This is the address the
    /// subsequent `A_Memory_Write`s target.
    pub address: u32,
    /// The size (octets) that was requested and allocated.
    pub size: u32,
}

/// Allocates a backing segment for a loadable table object via a
/// **relative** `AdditionalLoadControls` write, and returns the device-reported
/// segment start address.
///
/// Preconditions and sequence (KNX 3/5/2 `LdCtrlRelSegment`):
///
/// 1. The object must already be in [`LoadState::Loading`] — the standard only
///    dispatches `AdditionalLoadControls` from the loading state. The caller
///    opened it with `StartLoading` right before, whose answer confirmed it.
/// 2. Writes the 10-octet [`encode_rel_segment`] structure to
///    `PID_LOAD_STATE_CONTROL`. The device frees any prior backing store and
///    allocates `size` octets, optionally filled; on failure (e.g. maximum table
///    length exceeded) the object goes to [`LoadState::Error`]. In any state but
///    `Loading` the device ignores the record and answers that state.
/// 3. Takes the resulting load state from the write's answer when it is the
///    single `Loading` octet ETS continues on (issue #211; see
///    [`echoed_load_state`]), else reads it back: `Error` means the device
///    **refused** the allocation (out of memory / too large) →
///    [`WriteError::LoadError`]; `Unloaded` means the object was never open →
///    [`WriteError::UnexpectedLoadState`]; `Loading` means success.
/// 4. Reads `PID_TABLE_REFERENCE` element 1 — a big-endian `u32` — which after a
///    successful allocation is the segment's start address (a device reports `0`
///    while `Unloaded`). ETS reads it here too. That address is where the caller
///    writes the table content with
///    [`crate::device::DeviceConnection::write_memory`].
///
/// `fill_byte` mirrors the relative structure's fill flag/byte: `Some(b)` asks
/// the device to pre-fill the segment with `b`, `None` leaves it uninitialised.
///
/// Load-state handling: the object must stay *open* after the allocation write
/// — `Loading` on a conformant device, or `Loaded` on a lenient stack (KNX
/// Virtual snaps straight to `Loaded`, which the read-back fallback accepts).
/// Only `Unloaded` (the write was dropped) or `Error` (the device refused the
/// allocation, e.g. out of memory) fail here; the image's actual integrity is
/// confirmed downstream by the `LdCtrlLoadImageProp` MCB CRC check, so a device
/// that cannot truly hold the segment is caught there rather than by guessing
/// from the load-state octet.
pub async fn allocate_segment<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    size: u32,
    fill_byte: Option<u8>,
) -> Result<SegmentAllocation> {
    let address = l4.target();

    // 1-2. Write the 10-octet relative-allocation structure.
    let structure = encode_rel_segment(size, fill_byte);
    let resp =
        property_write_request(l4, object_index, PID_LOAD_STATE_CONTROL, 1, 1, &structure).await?;

    // 3. A refused allocation drops the object into Error. Otherwise the object
    //    stays open — Loading on a conformant device (the answer carries it), or
    //    Loaded on a lenient stack (KNX Virtual, confirmed by the read-back);
    //    only Unloaded/Error indicate the write was dropped or rejected.
    let state = match echoed_load_state(LoadControl::AdditionalLoadControls, &resp) {
        Some(state) => state,
        None => read_load_state(l4, object_index).await?,
    };
    if state == LoadState::Error {
        return Err(WriteError::LoadError {
            address,
            object_index,
        });
    }
    if !matches!(state, LoadState::Loading | LoadState::Loaded) {
        return Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control: LoadControl::AdditionalLoadControls,
            expected: LoadState::Loading,
            actual: state,
            context: LoadStateContext::default(),
        });
    }

    // 4. Read the device-placed segment address from PID_TABLE_REFERENCE (u32 BE).
    let seg_addr = read_table_reference(l4, object_index).await?;
    Ok(SegmentAllocation {
        address: seg_addr,
        size,
    })
}

/// Reads `PID_TABLE_REFERENCE` element 1 of a loadable object as a big-endian
/// `u32` — the segment's backing memory address (KNX 3/5/1; a device reports `0`
/// while the object is `Unloaded`).
///
/// [`allocate_segment`] reads this to learn where the device placed a
/// freshly-allocated segment; the download engine also reads it directly to
/// resolve the base a [`compare_rel_mem`] reads from, for an object it did not
/// allocate in the current procedure.
pub async fn read_table_reference<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<u32> {
    let resp = property_request(l4, object_index, PID_TABLE_REFERENCE, 1, 1).await?;
    // 4 octets on System B (PDT_UNSIGNED_LONG); System 7 devices answer the
    // 2-octet form (the Jung 0705 presence detectors, issue #89). Either way the
    // address is the trailing big-endian word.
    match (resp.count, resp.data.as_slice()) {
        (c, [a, b, c2, d]) if c > 0 => Ok(u32::from_be_bytes([*a, *b, *c2, *d])),
        (c, [hi, lo]) if c > 0 => Ok(u32::from(u16::from_be_bytes([*hi, *lo]))),
        _ => Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "table reference is not a readable address (object {object_index}, count {}, {} octet(s))",
                resp.count,
                resp.data.len()
            ),
        })),
    }
}

// --- PID_MCB_TABLE (memory control block) + CRC-16/AUG-CCITT ------------------
//
// The `LdCtrlLoadImageProp` op of a modern download procedure integrity-checks a
// freshly-written loadable segment: after the code+parameter image is streamed
// into a loadable object and the object reaches `Loaded`, the object's
// `PID_MCB_TABLE` property (PID 27) carries a *memory control block* describing
// the segment, including a CRC the device computes over the segment's own stored
// bytes. A tool validates its written image by reading that MCB and comparing the
// device's CRC to a CRC it computes independently over the bytes it sent — a
// mismatch means the image did not land intact.
//
// Reference: KNX 3/5/2 "Management Procedures" (`LdCtrlLoadImageProp`) and 3/5/1
// (interface-object property definitions). The System B `PID_MCB_TABLE` (27) is a
// **read-only, device-computed** `PDT_GENERIC_08` (8-octet) property, readable
// while the object is `Loaded`, laid out as:
//
// | octet | field           | value                                           |
// |-------|-----------------|-------------------------------------------------|
// | 0..4  | segment size    | u32 **big-endian**                              |
// | 4     | CRC control     | `0x00` ("always valid")                         |
// | 5     | access          | `0xFF` (read 4 bits + write 4 bits)             |
// | 6..8  | CRC             | CRC-16/AUG-CCITT over the segment bytes — BE    |
//
// The CRC is **CRC-16/AUG-CCITT** (the message is augmented with 16 zero bits
// before reduction): width 16, polynomial `0x1021`, initial value `0xFFFF`, input
// **not** reflected, output **not** reflected, no final XOR. Its catalogued check
// value for the ASCII string `"123456789"` is `0xE5CC` (distinct from
// CRC-16/CCITT-FALSE, which does not augment and checks to `0x29B1`).
//
// bussard mirrors this: `PID_MCB_TABLE` is read (not written) and the tool's own
// [`mcb_entry`]/[`crc16_ccitt`] recompute the same 8 octets over the bytes it
// wrote so [`read_mcb_table`] can confirm the device agrees.

/// `PID_MCB_TABLE` (27) — a loadable object's memory-control-block table, an
/// array of 8-octet entries each describing a segment (size, access, and a
/// CRC-16/AUG-CCITT the device computes over the segment's stored bytes).
/// Read-only and device-computed on System B (KNX 3/5/1).
pub const PID_MCB_TABLE: u8 = 27;

/// The octet width of one `PID_MCB_TABLE` entry (`PDT_GENERIC_08`).
pub const MCB_ENTRY_LEN: usize = 8;

/// Computes the CRC the KNX `PID_MCB_TABLE` uses — **CRC-16/AUG-CCITT**: width
/// 16, polynomial `0x1021`, initial value `0xFFFF`, input and output **not**
/// reflected, no final XOR, with the message augmented by 16 zero bits before
/// reduction.
///
/// The catalogued check value for the ASCII string `"123456789"` is `0xE5CC`.
/// (The function is named `crc16_ccitt` for its `0x1021`/`0xFFFF` CCITT lineage;
/// the augmentation makes it the AUG-CCITT variant, not CCITT-FALSE.)
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    // Bit-at-a-time, appending 16 zero bits (the +2 octets) — the augmentation
    // that defines CRC-16/AUG-CCITT — with the usual `& 0x10000` reduction.
    let mut result: u32 = 0xFFFF;
    let total_bits = 8 * (data.len() + 2);
    for i in 0..total_bits {
        result <<= 1;
        let next_bit = if (i / 8) < data.len() {
            ((data[i / 8] >> (7 - (i % 8))) & 1) as u32
        } else {
            0
        };
        result |= next_bit;
        if result & 0x1_0000 != 0 {
            result ^= 0x1021;
        }
    }
    (result & 0xFFFF) as u16
}

/// Builds the 8-octet `PID_MCB_TABLE` entry a device is expected to report for a
/// segment holding exactly `segment_data`, per the System B layout (KNX 3/5/1):
/// `[size:u32 BE][crc_control=0x00][access=0xFF][crc16:u16 BE]`.
///
/// `crc16` is [`crc16_ccitt`] over `segment_data`; `size` is `segment_data.len()`
/// (the device reports the segment size it stored). Used to validate a
/// `LdCtrlLoadImageProp` step: the tool computes this over the bytes it wrote and
/// compares it to what [`read_mcb_table`] reads back.
pub fn mcb_entry(segment_data: &[u8]) -> [u8; MCB_ENTRY_LEN] {
    let size = segment_data.len() as u32;
    let crc = crc16_ccitt(segment_data);
    let mut v = [0u8; MCB_ENTRY_LEN];
    v[0..4].copy_from_slice(&size.to_be_bytes());
    v[4] = 0x00; // CRC control byte: always valid.
    v[5] = 0xFF; // read/write access.
    v[6..8].copy_from_slice(&crc.to_be_bytes());
    v
}

/// A decoded `PID_MCB_TABLE` entry read from a loadable object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McbEntry {
    /// The segment size the device reports (octets), from entry octets `0..4`.
    pub segment_size: u32,
    /// The CRC control byte (octet 4); `0x00` means "always valid".
    pub crc_control: u8,
    /// The access byte (octet 5).
    pub access: u8,
    /// The CRC16-CCITT the device computed over the segment's stored bytes
    /// (octets `6..8`, big-endian).
    pub crc16: u16,
}

impl McbEntry {
    /// Decodes an 8-octet entry, or `None` if the slice is too short.
    pub fn decode(bytes: &[u8]) -> Option<McbEntry> {
        if bytes.len() < MCB_ENTRY_LEN {
            return None;
        }
        Some(McbEntry {
            segment_size: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            crc_control: bytes[4],
            access: bytes[5],
            crc16: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// Reads a loadable object's `PID_MCB_TABLE` and validates it against the image
/// the tool wrote — the executable form of a `LdCtrlLoadImageProp` step.
///
/// After a loadable object reaches `Loaded`, its `PID_MCB_TABLE` element(s) carry
/// the device's own CRC16-CCITT over the segment bytes it stored. This reads
/// `count` element(s) from `start` and, when `expected` is `Some(bytes)`,
/// confirms the first entry's [`McbEntry::crc16`] equals [`crc16_ccitt`] over
/// `expected` (the bytes the tool streamed). A mismatch surfaces
/// [`WriteError::ImagePropMismatch`]; a device that answers with no readable MCB
/// entry surfaces [`WriteError::WriteNotConfirmed`]-style malformed responses.
///
/// The MCB property is device-computed and read-only on System B, so this never
/// writes it — it reads and checks. `expected` is `None` for objects whose image
/// the tool did not itself write (e.g. an object the procedure names but for
/// which bussard streamed no segment); those entries are read but not
/// CRC-checked, so the step still confirms the property is present.
pub async fn read_mcb_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    start: u16,
    count: u8,
    expected: Option<&[u8]>,
) -> Result<Vec<McbEntry>> {
    let address = l4.target();
    // One element per request, exactly as ETS reads a multi-entry MCB table
    // (`LdCtrlLoadImageProp Count="6"` on the Jung 3361-1MWW capture goes out as
    // six `count=1` reads at index 1..=6). A single `count=6` request was refused
    // by the real device with a zero-count response (issue #89 campaign,
    // 1.1.36): six 8-octet entries do not fit a standard-frame APDU, and the
    // device does not partially answer.
    let mut entries: Vec<McbEntry> = Vec::with_capacity(usize::from(count.max(1)));
    for element in start..start.saturating_add(u16::from(count.max(1))) {
        let resp = property_request(l4, object_index, PID_MCB_TABLE, element, 1).await?;
        if resp.count == 0 || resp.data.len() < MCB_ENTRY_LEN {
            return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
                address,
                reason: format!(
                    "object {object_index} did not answer a readable PID_MCB_TABLE entry {element} (count {}, {} octet(s))",
                    resp.count,
                    resp.data.len()
                ),
            }));
        }
        entries.extend(
            resp.data
                .as_chunks::<MCB_ENTRY_LEN>()
                .0
                .iter()
                .filter_map(|c| McbEntry::decode(c)),
        );
    }
    let first = entries.first().ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address,
            reason: format!("object {object_index} PID_MCB_TABLE has no 8-octet entry"),
        })
    })?;

    if let Some(image) = expected {
        // Each MCB entry covers `segment_size` octets of the object's image, in
        // order: the Jung F50 splits its 6152-octet application into a 6148-octet
        // entry and a 4-octet tail (1.1.18, issue #89), so a CRC over the whole
        // image never matches entry 1. Walk the entries over consecutive slices;
        // when the declared sizes do not fit the image (a device that reports
        // one entry for everything), fall back to the whole image against entry 1.
        let mut offset = 0usize;
        let mut checked = 0usize;
        for entry in &entries {
            let size = entry.segment_size as usize;
            let Some(end) = offset.checked_add(size).filter(|end| *end <= image.len()) else {
                break;
            };
            let want = crc16_ccitt(&image[offset..end]);
            if entry.crc16 != want {
                return Err(WriteError::ImagePropMismatch {
                    address,
                    object_index,
                    expected_crc: want,
                    device_crc: entry.crc16,
                });
            }
            offset = end;
            checked += 1;
        }
        if checked == 0 {
            let want = crc16_ccitt(image);
            if first.crc16 != want {
                return Err(WriteError::ImagePropMismatch {
                    address,
                    object_index,
                    expected_crc: want,
                    device_crc: first.crc16,
                });
            }
        }
    }
    Ok(entries)
}

/// How many table elements to write per `A_PropertyValue_Write`, sized so the
/// request (4-octet header + data) fits the conservative 15-octet APDU every
/// System B device supports. 4-octet association elements are the largest, so
/// chunk by octets and derive the element count per table.
const MAX_PROPERTY_WRITE_OCTETS: usize = 8;

/// Writes a whole `PID_TABLE` property array: the element count into element 0,
/// then the elements from index 1 upward in APDU-sized chunks.
///
/// Mirrors the read side ([`crate::tables`]): element 0 holds the big-endian
/// `u16` count, elements are 1-based. Each chunk is written with
/// [`write_property`] and validated by the device's echo. `elem_size` is the
/// octet width of one element (2 for the address table, 4 for the association
/// table). The object must already be in [`LoadState::Loading`].
///
/// Every write is confirmed via the response echo, so a device that silently
/// drops or truncates a chunk fails loudly rather than leaving a half-written
/// table.
pub async fn write_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    elem_size: usize,
    elements: &[u8],
) -> Result<()> {
    debug_assert!(elem_size > 0 && elements.len().is_multiple_of(elem_size));
    let count = elements.len() / elem_size;

    // Element 0: the big-endian u16 element count. Writing element 0 sets the
    // array length (mirrors the read side, where element 0 *is* the count).
    let count_bytes = (count as u16).to_be_bytes();
    write_property(l4, object_index, PID_TABLE, 1, 0, &count_bytes, None).await?;

    // Elements 1..=count in chunks.
    let chunk_elems = (MAX_PROPERTY_WRITE_OCTETS / elem_size).max(1);
    let mut next: usize = 1; // 1-based
    while next <= count {
        let take = chunk_elems.min(count - next + 1);
        let byte_start = (next - 1) * elem_size;
        let byte_end = byte_start + take * elem_size;
        let chunk = &elements[byte_start..byte_end];
        write_property(
            l4,
            object_index,
            PID_TABLE,
            take as u8,
            next as u16,
            chunk,
            None,
        )
        .await?;
        next += take;
    }
    Ok(())
}

// --- Memory read/write on a Layer4Connection --------------------------------
//
// The memory primitives themselves now live in [`crate::memory`] — one module for
// every memory access bussard makes, after the same helpers had been
// re-implemented here, in `device.rs`, `tables.rs` and `sys7.rs` and drifted apart
// (issue #80). They are re-exported here under their historical names so the
// `bussard_mgmt::load::…` paths callers (and `bussard-download`) already use keep
// resolving.

pub use crate::memory::{
    read_memory, read_memory_range, select_extended_memory, write_memory, write_memory_chunked,
    write_memory_verified,
};

/// Whether an error is a connection-death — a mid-session silence, a dropped ACK,
/// or a momentary no-response (the "device absent"/"disconnected" family) — as
/// opposed to a device-level refusal like a verify mismatch or a load error.
///
/// The flash engine (`bussard-download`) is the caller: when a whole step fails
/// this way it **cycles the L4 connection and re-runs the step**. A
/// connection-oriented device (KNX Virtual) drops the L4 link at a
/// non-deterministic exchange count, but the object's load state and allocated
/// segments are persistent device state that survive the drop, so reconnecting and
/// resuming recovers it. A device-level refusal is never a connection-death, so it
/// is never retried.
///
/// Recovery genuinely needs a **new** connection: [`Layer4Connection`] marks the
/// connection closed before raising any of these, so retrying the same exchange on
/// the same connection can only fail again (issue #80). That is why
/// [`crate::memory::write_memory_chunked`] no longer retries in place and the
/// reconnecting call site owns the recovery.
///
/// A lost **gateway link** counts too (issue #177): a transport error for which
/// [`TransportError::is_link_loss`](bussard_transport::TransportError::is_link_loss)
/// holds (an ACK or heartbeat timeout, a gateway disconnect, a socket error, or
/// a frame dropped while the bus was reconnecting). The tunnel re-establishes
/// itself, and the frames the gateway could not deliver meanwhile are lost, so
/// the caller resumes exactly as after a Layer-4 death. The terminal
/// [`TunnelLost`](bussard_transport::TransportError::TunnelLost), raised once
/// the tunnel's re-establish budget ran out, is not a connection death: there is
/// no bus to resume on.
pub fn is_connection_death(err: &WriteError) -> bool {
    match err {
        WriteError::Mgmt(MgmtError::MidSessionSilence { .. })
        | WriteError::Mgmt(MgmtError::Disconnected { .. })
        | WriteError::Mgmt(MgmtError::NoResponse { .. }) => true,
        WriteError::Mgmt(MgmtError::Transport(e)) => e.is_link_loss(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_state_round_trips_octets() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for (v, s) in [
            (0, LoadState::Unloaded),
            (1, LoadState::Loaded),
            (2, LoadState::Loading),
            (3, LoadState::Error),
        ] {
            assert_eq!(LoadState::from_octet(v), s);
            assert_eq!(s.octet(), v);
        }
        assert_eq!(LoadState::from_octet(9), LoadState::Other(9));
        assert_eq!(LoadState::Other(9).octet(), 9);
        Ok(())
    }

    #[test]
    fn load_control_octets_match_the_standard()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(LoadControl::NoOperation.octet(), 0);
        assert_eq!(LoadControl::StartLoading.octet(), 1);
        assert_eq!(LoadControl::LoadCompleted.octet(), 2);
        assert_eq!(LoadControl::AdditionalLoadControls.octet(), 3);
        assert_eq!(LoadControl::Unload.octet(), 4);
        Ok(())
    }

    #[test]
    fn load_control_encode_full_matches_ets_da_tp_capture()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The ETS→KNX-Virtual DA.tp capture (dumpfile.pcap) writes the full
        // 10-octet PID_LOAD_STATE_CONTROL value for every simple transition:
        // the control octet followed by nine reserved zero octets. These are the
        // exact request payloads seen on objects 1–5 in that capture.
        assert_eq!(
            LoadControl::Unload.encode_full(),
            [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            LoadControl::StartLoading.encode_full(),
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            LoadControl::LoadCompleted.encode_full(),
            [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // Every simple control is exactly 10 octets, matching the standard
        // AdditionalLoadControls width ETS always writes.
        for c in [
            LoadControl::NoOperation,
            LoadControl::StartLoading,
            LoadControl::LoadCompleted,
            LoadControl::AdditionalLoadControls,
            LoadControl::Unload,
        ] {
            assert_eq!(c.encode_full().len(), 10);
            assert_eq!(c.encode_full()[0], c.octet());
            assert!(c.encode_full()[1..].iter().all(|&b| b == 0));
        }
        Ok(())
    }

    #[test]
    fn test_echoed_load_state_accepts_only_the_expected_single_octet()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::apci::PropertyValueResponse;
        let answer = |count: u8, data: &[u8]| PropertyValueResponse {
            object_index: 4,
            property_id: PID_LOAD_STATE_CONTROL,
            count,
            start: 1,
            data: data.to_vec(),
        };
        // The ETS-capture answers (issue #211).
        for (control, octet, state) in [
            (LoadControl::Unload, 0x00, LoadState::Unloaded),
            (LoadControl::StartLoading, 0x02, LoadState::Loading),
            (
                LoadControl::AdditionalLoadControls,
                0x02,
                LoadState::Loading,
            ),
            (LoadControl::LoadCompleted, 0x01, LoadState::Loaded),
        ] {
            assert_eq!(
                echoed_load_state(control, &answer(1, &[octet])),
                Some(state)
            );
        }
        // Everything else falls back to the read-back.
        let start_loading = LoadControl::StartLoading;
        assert_eq!(echoed_load_state(start_loading, &answer(1, &[])), None);
        assert_eq!(echoed_load_state(start_loading, &answer(0, &[0x02])), None);
        assert_eq!(echoed_load_state(start_loading, &answer(1, &[0x01])), None);
        assert_eq!(echoed_load_state(start_loading, &answer(1, &[0x03])), None);
        let event = start_loading.encode_full();
        assert_eq!(echoed_load_state(start_loading, &answer(1, &event)), None);
        assert_eq!(
            echoed_load_state(LoadControl::NoOperation, &answer(1, &[0x00])),
            None
        );
        Ok(())
    }

    #[test]
    fn load_control_expected_states() -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            LoadControl::StartLoading.expected_state(),
            Some(LoadState::Loading)
        );
        assert_eq!(
            LoadControl::LoadCompleted.expected_state(),
            Some(LoadState::Loaded)
        );
        // Unload is a best-effort reset (not verified): KNX Virtual reports
        // Loaded after it, which ETS tolerates and we must too.
        assert_eq!(LoadControl::Unload.expected_state(), None);
        assert_eq!(LoadControl::NoOperation.expected_state(), None);
        assert_eq!(LoadControl::AdditionalLoadControls.expected_state(), None);
        Ok(())
    }

    #[test]
    fn rel_segment_structure_matches_spec_offsets()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // event=3, sub=0x0B, size u32 BE, fill flag + byte, reserved tail
        // (KNX 3/5/2 LdCtrlRelSegment).
        let v = encode_rel_segment(0x0000_0140, Some(0xEE));
        assert_eq!(v.len(), 10);
        assert_eq!(v[0], LoadControl::AdditionalLoadControls.octet());
        assert_eq!(v[1], LD_CTRL_REL_SEGMENT);
        assert_eq!(&v[2..6], &[0x00, 0x00, 0x01, 0x40]); // size 320 big-endian
        assert_eq!(v[6], 0x01); // fill flag set
        assert_eq!(v[7], 0xEE); // fill byte
        assert_eq!(&v[8..10], &[0x00, 0x00]); // reserved

        // No fill: flag and byte are zero.
        let v = encode_rel_segment(0x10, None);
        assert_eq!(&v[2..6], &[0x00, 0x00, 0x00, 0x10]);
        assert_eq!(v[6], 0x00);
        assert_eq!(v[7], 0x00);

        // The Jung LED A-3030 obj4 code-segment allocation is captured as
        // `030b000028c1 01 00 0000`: size 0x28c1, fill flag 0x01, fill byte 0x00.
        // A `Fill="1"` (FillByte default 0) allocation must encode to exactly
        // those first 8 octets, byte-for-byte with the ETS capture.
        let v = encode_rel_segment(0x0000_28C1, Some(0x00));
        assert_eq!(&v[0..8], &[0x03, 0x0B, 0x00, 0x00, 0x28, 0xC1, 0x01, 0x00]);
        Ok(())
    }

    #[test]
    fn connection_death_classified_for_exchange_retry()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The three transient-blip shapes a bounded per-exchange retry recovers from.
        let ia: IndividualAddress = "1.1.4".parse()?;
        assert!(is_connection_death(&WriteError::Mgmt(
            MgmtError::Disconnected { address: ia }
        )));
        assert!(is_connection_death(&WriteError::Mgmt(
            MgmtError::NoResponse { address: ia }
        )));
        assert!(is_connection_death(&WriteError::Mgmt(
            MgmtError::MidSessionSilence {
                address: ia,
                kind: crate::error::SilenceKind::Disconnected,
                exchanges: 7,
                wraps: 0,
            }
        )));
        // A device-level refusal is NOT a connection death — retrying the same
        // write would just fail again, so it must propagate.
        assert!(!is_connection_death(&WriteError::Mgmt(
            MgmtError::MemoryVerifyFailed {
                address: ia,
                addr: 0x4000,
                expected: vec![1],
                got: vec![2],
            }
        )));
        assert!(!is_connection_death(&WriteError::LoadError {
            address: ia,
            object_index: 3,
        }));
        Ok(())
    }

    #[test]
    fn test_is_connection_death_covers_gateway_link_loss()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use bussard_transport::TransportError;
        // Issue #177: a lost gateway link resumes like a Layer-4 death ...
        for e in [
            TransportError::Timeout("TUNNELING_ACK"),
            TransportError::HeartbeatLost,
            TransportError::Disconnected(7),
        ] {
            assert!(is_connection_death(&WriteError::Mgmt(
                MgmtError::Transport(e)
            )));
        }
        // ... but the terminal "could not re-establish" error does not, and
        // neither does a closed connection or a gateway refusal.
        let lost = TransportError::TunnelLost {
            gateway: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 3671),
            budget: std::time::Duration::from_secs(60),
            cause: Box::new(TransportError::Timeout("TUNNELING_ACK")),
        };
        assert!(!is_connection_death(&WriteError::Mgmt(
            MgmtError::Transport(lost)
        )));
        assert!(!is_connection_death(&WriteError::Mgmt(
            MgmtError::Transport(TransportError::Closed)
        )));
        assert!(!is_connection_death(&WriteError::Mgmt(
            MgmtError::Transport(TransportError::GatewayStatus {
                status: 0x29,
                context: "TUNNELING_ACK"
            })
        )));
        Ok(())
    }

    #[test]
    fn displays_are_human_readable() -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert_eq!(LoadState::Loading.to_string(), "Loading");
        assert_eq!(LoadState::Error.to_string(), "Error");
        assert_eq!(LoadControl::StartLoading.to_string(), "StartLoading");
        assert_eq!(LoadControl::LoadCompleted.to_string(), "LoadCompleted");
        Ok(())
    }

    #[test]
    fn empty_load_state_context_renders_nothing()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The table-apply path drives write_load_control without discovery, so an
        // empty context must not alter the original message.
        assert_eq!(LoadStateContext::default().to_string(), "");
        Ok(())
    }

    #[test]
    fn unexpected_load_state_folds_in_discovered_context()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The finding-1 rich error: a load-state failure names the targeted
        // object's type and the full discovered object table.
        let err = WriteError::UnexpectedLoadState {
            address: "1.0.1".parse()?,
            object_index: 3,
            control: LoadControl::StartLoading,
            expected: LoadState::Loading,
            actual: LoadState::Loaded,
            context: LoadStateContext {
                object_type: Some(3),
                object_table: vec![(0, 0), (1, 1), (2, 2), (3, 3)],
            },
        };
        assert_eq!(
            err.to_string(),
            "1.0.1: object 3 did not reach Loading after StartLoading (device reports Loaded) \
             — target object has interface-object type 3 (application-program); discovered \
             object table [0:0(device), 1:1(address-table), 2:2(association-table), \
             3:3(application-program)]"
        );
        Ok(())
    }

    #[test]
    fn crc16_ccitt_matches_the_standard_check_vector()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The catalogued CRC-16/AUG-CCITT check value for "123456789" is 0xE5CC
        // (the augmented CCITT variant the KNX MCB uses; CCITT-FALSE would be
        // 0x29B1).
        assert_eq!(crc16_ccitt(b"123456789"), 0xE5CC);
        // Init value FFFF, empty input (only the two augmenting zero bytes are
        // reduced) -> 0x1D0F.
        assert_eq!(crc16_ccitt(b""), 0x1D0F);
        // A single zero byte.
        assert_eq!(crc16_ccitt(&[0x00]), 0xCC9C);
        Ok(())
    }

    #[test]
    fn mcb_entry_matches_spec_layout() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // [size u32 BE][crc_ctrl=0x00][access=0xFF][crc16 u16 BE], 8 octets
        // (KNX 3/5/1 System B PID_MCB_TABLE).
        let data = b"123456789";
        let e = mcb_entry(data);
        assert_eq!(e.len(), MCB_ENTRY_LEN);
        assert_eq!(&e[0..4], &(data.len() as u32).to_be_bytes()); // size = 9
        assert_eq!(e[4], 0x00); // CRC control: always valid
        assert_eq!(e[5], 0xFF); // access
        assert_eq!(&e[6..8], &0xE5CCu16.to_be_bytes()); // CRC-16/AUG-CCITT of "123456789"

        // Round-trips through the decoder.
        let dec = McbEntry::decode(&e).ok_or("missing value")?;
        assert_eq!(dec.segment_size, 9);
        assert_eq!(dec.crc_control, 0x00);
        assert_eq!(dec.access, 0xFF);
        assert_eq!(dec.crc16, 0xE5CC);
        Ok(())
    }

    #[test]
    fn mcb_decode_rejects_short_slices() -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert!(McbEntry::decode(&[0u8; 7]).is_none());
        assert!(McbEntry::decode(&[0u8; 8]).is_some());
        Ok(())
    }

    #[test]
    fn rel_mem_compare_exact_match_and_mismatch()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // No mask, no invert: equal bytes pass, any difference fails.
        assert!(rel_mem_compare_passes(&[0xFF], &[0xFF], None, false));
        assert!(!rel_mem_compare_passes(&[0xFF], &[0x00], None, false));
        assert!(rel_mem_compare_passes(
            &[0x12, 0x34],
            &[0x12, 0x34],
            None,
            false
        ));
        assert!(!rel_mem_compare_passes(
            &[0x12, 0x34],
            &[0x12, 0x35],
            None,
            false
        ));
        Ok(())
    }

    #[test]
    fn rel_mem_compare_honours_mask() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Mask 0x0F ignores the high nibble: 0xA5 vs 0xB5 match on the low nibble.
        assert!(rel_mem_compare_passes(
            &[0xA5],
            &[0xB5],
            Some(&[0x0F]),
            false
        ));
        // But a low-nibble difference under the mask fails.
        assert!(!rel_mem_compare_passes(
            &[0xA5],
            &[0xB6],
            Some(&[0x0F]),
            false
        ));
        // A 0x00 mask byte ignores that position entirely.
        assert!(rel_mem_compare_passes(
            &[0xAA, 0xBB],
            &[0x11, 0xBB],
            Some(&[0x00, 0xFF]),
            false
        ));
        // A mask shorter than expected compares the remaining positions in full.
        assert!(!rel_mem_compare_passes(
            &[0xAA, 0xBB],
            &[0xAA, 0xCC],
            Some(&[0xFF]),
            false
        ));
        Ok(())
    }

    #[test]
    fn rel_mem_compare_inverts_sense() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Invert: the memory must DIFFER from expected under the mask.
        assert!(rel_mem_compare_passes(&[0xFF], &[0x00], None, true));
        assert!(!rel_mem_compare_passes(&[0xFF], &[0xFF], None, true));
        // Inverted + masked: a low-nibble difference passes, an equal-under-mask fails.
        assert!(rel_mem_compare_passes(
            &[0xA5],
            &[0xB6],
            Some(&[0x0F]),
            true
        ));
        assert!(!rel_mem_compare_passes(
            &[0xA5],
            &[0xB5],
            Some(&[0x0F]),
            true
        ));
        Ok(())
    }

    #[test]
    fn rel_mem_compare_short_read_never_passes()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A short read (fewer octets than expected) fails regardless of sense.
        assert!(!rel_mem_compare_passes(&[0xFF, 0xFF], &[0xFF], None, false));
        assert!(!rel_mem_compare_passes(&[0xFF, 0xFF], &[0xFF], None, true));
        assert!(!rel_mem_compare_passes(&[0xFF], &[], None, false));
        Ok(())
    }
}
