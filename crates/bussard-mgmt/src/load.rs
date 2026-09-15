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
//! (PID **5**). The machine, its states and its control events follow the KNX
//! interface-object property definitions (EN 50090 / KNX standard 3/5/1 §
//! "Load State Machine") as realised by the System B device-side implementation
//! in thelsing/knx (a permitted, non-GPL behavioural reference — semantics only,
//! no code copied):
//!
//! - **Reading** `PID_LOAD_STATE_CONTROL` (start 1, count 1) returns a **single
//!   octet**, the current [`LoadState`] (thelsing `table_object.cpp`: the
//!   property read answers `data[0] = _state`).
//! - **Writing** `PID_LOAD_STATE_CONTROL` (start 1, count 1) takes a **single
//!   octet**, a [`LoadControl`] event, and drives the transition (thelsing
//!   `table_object.cpp`: the property write invokes `loadEvent(data)` with the
//!   event in `data[0]`). The device then answers an `A_PropertyValue_Response`
//!   echoing the property's octet, which after a control write is the *resulting
//!   load state*, not the control value written — so a load-control write is
//!   validated against the expected next state, not against the value sent.
//! - **Transitions** (thelsing `table_object.cpp` `loadEvent*` handlers):
//!   - `Unloaded --StartLoading--> Loading`
//!   - `Loaded   --StartLoading--> Loading`
//!   - `Loading  --LoadCompleted--> Loaded` (persists the table: `saveMemory()`)
//!   - `Loading  --Unload--> Unloaded`
//!   - `Loaded   --Unload--> Unloaded`
//!   - `Error    --Unload--> Unloaded`
//!
//! A failed load (a bad table, or a device that refuses the written content)
//! leaves the object in `Error`; the only recovery is `Unload` (or ETS).
//!
//! ## Single-byte controls suffice for a plain table write
//!
//! The standard defines a 10-octet `AdditionalLoadControls` structure used to
//! *allocate* a table's backing memory (segment type, address, size, …). For a
//! System B device whose table objects already exist and are merely being
//! re-filled — the group-address and association tables of an already-programmed
//! actuator, the bussard use case — the plain single-octet `StartLoading` /
//! `LoadCompleted` controls are sufficient: `StartLoading` opens the object for
//! writing, the `PID_TABLE` element writes replace its content in place, and
//! `LoadCompleted` persists it. thelsing's `loadEventLoading` handles a bare
//! `LoadCompleted` without requiring a preceding `AdditionalLoadControls`
//! (`AdditionalLoadControls` is only consulted to *grow* backing memory). This
//! module therefore emits only single-octet controls; growing a table beyond its
//! current backing store is out of scope and documented as a limitation.
//!
//! # Everything here writes to the bus
//!
//! Unlike [`crate::tables`], these procedures mutate device state. They are only
//! ever driven by `bussard apply`, which first shows a plan, takes confirmation,
//! and writes a backup — see `bussard-download`.

use crate::apci::{self, A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_WRITE};
use crate::connection::{L4Channel, Layer4Connection};
use crate::error::MgmtError;
use crate::tables::PID_TABLE;
use bussard_model::IndividualAddress;

/// `PID_LOAD_STATE_CONTROL` (5) — the load-state property of a loadable
/// interface object. Reading it yields a [`LoadState`]; writing it a
/// [`LoadControl`] event.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;

/// The load state of a loadable interface object, as read from
/// `PID_LOAD_STATE_CONTROL`.
///
/// Encoding per the KNX load-state machine (thelsing `table_object.cpp` reads
/// `_state` back as the property octet): `Unloaded=0, Loaded=1, Loading=2,
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

    /// The load state a device is expected to reach after this control on a
    /// well-behaved single-object write, or `None` when the resulting state is
    /// not fixed (`NoOperation`, `AdditionalLoadControls`).
    pub fn expected_state(self) -> Option<LoadState> {
        match self {
            LoadControl::StartLoading => Some(LoadState::Loading),
            LoadControl::LoadCompleted => Some(LoadState::Loaded),
            LoadControl::Unload => Some(LoadState::Unloaded),
            LoadControl::NoOperation | LoadControl::AdditionalLoadControls => None,
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
    #[error(
        "{address}: object {object_index} did not reach {expected} after {control} \
         (device reports {actual})"
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

    /// An underlying management error (absent, NAK, disconnect, malformed).
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
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
    let payload = apci::encode_property_value_write(object_index, property_id, count, start, value);
    let (resp_apci, data) = l4.request(A_PROPERTY_VALUE_WRITE, &payload).await?;
    if resp_apci != apci::A_PROPERTY_VALUE_RESPONSE {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "expected A_PropertyValue_Response to a property write",
        }));
    }
    let resp = apci::decode_property_value_response(&data).ok_or(WriteError::Mgmt(
        MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "property value response too short",
        },
    ))?;
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
    let payload = apci::encode_property_value_read(object_index, PID_LOAD_STATE_CONTROL, 1, 1);
    let (resp_apci, data) = l4.request(A_PROPERTY_VALUE_READ, &payload).await?;
    if resp_apci != apci::A_PROPERTY_VALUE_RESPONSE {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "expected A_PropertyValue_Response for the load state",
        }));
    }
    let resp = apci::decode_property_value_response(&data).ok_or(WriteError::Mgmt(
        MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "load state response too short",
        },
    ))?;
    if resp.count == 0 || resp.data.is_empty() {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "load state property is not readable",
        }));
    }
    Ok(LoadState::from_octet(resp.data[0]))
}

/// Writes a single-octet load control to a loadable object and confirms the
/// resulting load state.
///
/// The device echoes `PID_LOAD_STATE_CONTROL` after the write, which is the
/// *resulting* [`LoadState`]; this validates it against
/// [`LoadControl::expected_state`]. A device that lands in [`LoadState::Error`]
/// surfaces [`WriteError::LoadError`]; any other mismatch surfaces
/// [`WriteError::UnexpectedLoadState`].
pub async fn write_load_control<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    control: LoadControl,
) -> Result<LoadState> {
    let address = l4.target();
    let control_octet = [control.octet()];
    // Some devices echo the resulting state; some echo nothing meaningful. Write
    // without a strict echo compare, then read the state back to validate — the
    // read-back is the reliable confirmation across stacks.
    let payload = apci::encode_property_value_write(
        object_index,
        PID_LOAD_STATE_CONTROL,
        1,
        1,
        &control_octet,
    );
    let (resp_apci, data) = l4.request(A_PROPERTY_VALUE_WRITE, &payload).await?;
    if resp_apci != apci::A_PROPERTY_VALUE_RESPONSE {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address,
            reason: "expected A_PropertyValue_Response to a load-control write",
        }));
    }
    // Decode is best-effort here; the authoritative state comes from a fresh read.
    let _ = apci::decode_property_value_response(&data);

    let state = read_load_state(l4, object_index).await?;
    if state == LoadState::Error {
        return Err(WriteError::LoadError {
            address,
            object_index,
        });
    }
    if let Some(expected) = control.expected_state() {
        if state != expected {
            return Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual: state,
            });
        }
    }
    Ok(state)
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
    debug_assert!(elem_size > 0 && elements.len() % elem_size == 0);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_state_round_trips_octets() {
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
    }

    #[test]
    fn load_control_octets_match_the_standard() {
        assert_eq!(LoadControl::NoOperation.octet(), 0);
        assert_eq!(LoadControl::StartLoading.octet(), 1);
        assert_eq!(LoadControl::LoadCompleted.octet(), 2);
        assert_eq!(LoadControl::AdditionalLoadControls.octet(), 3);
        assert_eq!(LoadControl::Unload.octet(), 4);
    }

    #[test]
    fn load_control_expected_states() {
        assert_eq!(
            LoadControl::StartLoading.expected_state(),
            Some(LoadState::Loading)
        );
        assert_eq!(
            LoadControl::LoadCompleted.expected_state(),
            Some(LoadState::Loaded)
        );
        assert_eq!(
            LoadControl::Unload.expected_state(),
            Some(LoadState::Unloaded)
        );
        assert_eq!(LoadControl::NoOperation.expected_state(), None);
        assert_eq!(LoadControl::AdditionalLoadControls.expected_state(), None);
    }

    #[test]
    fn displays_are_human_readable() {
        assert_eq!(LoadState::Loading.to_string(), "Loading");
        assert_eq!(LoadState::Error.to_string(), "Error");
        assert_eq!(LoadControl::StartLoading.to_string(), "StartLoading");
        assert_eq!(LoadControl::LoadCompleted.to_string(), "LoadCompleted");
    }
}
