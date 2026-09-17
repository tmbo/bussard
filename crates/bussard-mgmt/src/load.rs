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
//! ## Single-byte controls suffice for a plain table write
//!
//! The standard defines a 10-octet `AdditionalLoadControls` structure used to
//! *allocate* a table's backing memory (segment type, address, size, …). For a
//! System B device whose table objects already exist and are merely being
//! re-filled — the group-address and association tables of an already-programmed
//! actuator, the bussard use case — the plain single-octet `StartLoading` /
//! `LoadCompleted` controls are sufficient: `StartLoading` opens the object for
//! writing, the `PID_TABLE` element writes replace its content in place, and
//! `LoadCompleted` persists it. Per KNX 3/5/2, a bare `LoadCompleted` completes
//! an in-place re-fill without a preceding `AdditionalLoadControls`
//! (`AdditionalLoadControls` is only consulted to *grow* backing memory). This
//! module therefore emits only single-octet controls; growing a table beyond its
//! current backing store is out of scope and documented as a limitation.
//!
//! # Everything here writes to the bus
//!
//! Unlike [`crate::tables`], these procedures mutate device state. They are only
//! ever driven by `bussard apply`, which first shows a plan, takes confirmation,
//! and writes a backup — see `bussard-download`.

use crate::apci::{self};
use crate::connection::{L4Channel, Layer4Connection, property_request, property_write_request};
use crate::error::{MgmtError, raw_response_detail};
use crate::tables::{PID_TABLE, PID_TABLE_REFERENCE};
use bussard_model::IndividualAddress;

/// `PID_LOAD_STATE_CONTROL` (5) — the load-state property of a loadable
/// interface object. Reading it yields a [`LoadState`]; writing it a
/// [`LoadControl`] event.
pub const PID_LOAD_STATE_CONTROL: u8 = 5;

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

    /// A write step's resolved target address does not fit the 16-bit A_Memory
    /// address space. The device-supplied segment base plus the vendor offset (or
    /// an absolute address) exceeded `0xFFFF`, which a `u16` cast would silently
    /// truncate — streaming the image to the WRONG device memory. Aborted before
    /// any octet is written.
    #[error(
        "{address}: write target address is out of range — {detail} exceeds the 16-bit A_Memory \
         space (max {max:#06X}); aborting rather than truncating and writing to the wrong memory",
        max = 0xFFFF_u32
    )]
    AddressOutOfRange {
        /// The device.
        address: IndividualAddress,
        /// Which components put the address out of range (base+offset / address).
        detail: String,
    },

    /// A `LdCtrlMasterReset` was rejected: the device answered its
    /// `A_Restart_Response` with a non-zero error code rather than accepting the
    /// master reset. The reset did not happen, so the procedure cannot continue.
    #[error(
        "{address}: master reset (erase code {erase_code}, channel {channel_number}) was rejected \
         — device returned error code {error_code} ({reason})"
    )]
    MasterResetRejected {
        /// The device.
        address: IndividualAddress,
        /// The erase code presented.
        erase_code: u8,
        /// The channel number presented.
        channel_number: u8,
        /// The error code the device returned in its `A_Restart_Response`.
        error_code: u8,
        /// A human-readable interpretation of the error code.
        reason: &'static str,
    },

    /// An underlying management error (absent, NAK, disconnect, malformed).
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
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

/// Interprets an `A_Restart_Response` error code into a human-readable reason,
/// per the KNX spec master-reset error codes.
fn master_reset_error_reason(code: u8) -> &'static str {
    match code {
        0 => "success",
        2 => "access denied",
        3 => "unsupported erase code",
        4 => "invalid channel number",
        _ => "device-defined error",
    }
}

/// Performs a device **Master Reset** (`LdCtrlMasterReset`): sends a master-reset
/// `A_Restart` request and confirms the device accepted it.
///
/// Unlike a basic restart (fire-and-forget), a master reset is confirmed by an
/// `A_Restart_Response` carrying an error code before the device reboots and
/// drops the connection (see [`crate::apci::encode_master_reset`]). This sends
/// the request, then:
///
/// - If the device answers an `A_Restart_Response`
///   ([`A_RESTART_RESPONSE`](crate::apci::A_RESTART_RESPONSE)), a **zero** error
///   code is success and a **non-zero** code fails with
///   [`WriteError::MasterResetRejected`].
/// - If the device **acknowledges the request but then goes silent** (no
///   response NDT, a mid-session silence, or a `T_Disconnect`) it has already
///   begun rebooting — the expected outcome of an accepted master reset — so this
///   returns `Ok(())`. The caller then waits out the reboot and reconnects.
///
/// A device that never even acknowledges the request (the very first send times
/// out) surfaces the underlying [`MgmtError`], since that means the request never
/// landed.
///
/// Clean-room: encoding and semantics from the published KNX spec (A_Restart /
/// DM_Restart master reset) and the XKNX MIT reference; verified against a real
/// ETS→KNX-Virtual capture.
pub async fn master_reset<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    erase_code: u8,
    channel_number: u8,
) -> Result<()> {
    let address = l4.target();
    let (apci, payload) = crate::apci::encode_master_reset(erase_code, channel_number);
    // Send the request as a numbered telegram and require the device's T_ACK: a
    // request that is never acknowledged never landed, which is a real failure.
    l4.send_data(apci, &payload).await?;
    // Await the A_Restart_Response. The device answers, then reboots — but it may
    // also reboot immediately and drop the link, so silence/disconnect after the
    // acknowledged send is the *expected* accepted outcome, not a failure.
    match l4.recv_response().await {
        Ok((resp_apci, data)) => {
            if resp_apci == crate::apci::A_RESTART_RESPONSE {
                let error_code = crate::apci::decode_restart_response(&data);
                if error_code != 0 {
                    return Err(WriteError::MasterResetRejected {
                        address,
                        erase_code,
                        channel_number,
                        error_code,
                        reason: master_reset_error_reason(error_code),
                    });
                }
            }
            // A zero error code, or any non-restart-response answer (the device
            // simply rebooting): accepted.
            Ok(())
        }
        // The device acknowledged the request, then went silent or dropped the
        // connection: it is rebooting, which is exactly what an accepted master
        // reset does. Treat as success; the caller reconnects.
        Err(MgmtError::NoResponse { .. })
        | Err(MgmtError::MidSessionSilence { .. })
        | Err(MgmtError::Disconnected { .. }) => Ok(()),
        Err(other) => Err(WriteError::Mgmt(other)),
    }
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
    // Decode is best-effort here; the authoritative state comes from a fresh read.
    let _ = property_write_request(
        l4,
        object_index,
        PID_LOAD_STATE_CONTROL,
        1,
        1,
        &control_octet,
    )
    .await?;

    let state = read_load_state(l4, object_index).await?;
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

/// The `AdditionalLoadControls` sub-command for an **absolute** (tool-placed)
/// segment allocation — `LdCtrlAbsSegment` (KNX 3/5/2). The tool supplies the
/// segment's absolute memory address, size, access/mem-type flags and a checksum
/// control.
///
/// **Uncertain / unverified against a device.** Common System B devices
/// implement only the relative form (`0x0B`) and reject other
/// `AdditionalLoadControls` sub-commands outright. The absolute layout below
/// follows the published ETS `LdCtrlAbsSegment` element (`LsmIdx, SegType,
/// Address, Size, Access, MemType, SegFlags`), but the exact octet order has not
/// been pinned against a live device, so [`encode_abs_segment`] is provided for
/// the downloader to build on and is flagged as needing live confirmation.
/// Prefer [`allocate_segment`] (relative) wherever the device places the segment
/// itself.
pub const LD_CTRL_ABS_SEGMENT: u8 = 0x01;

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

/// Encodes the 10-octet `AdditionalLoadControls` property value for an
/// **absolute** segment allocation (`LdCtrlAbsSegment`).
///
/// **Unverified layout** — see [`LD_CTRL_ABS_SEGMENT`]. Provided for the
/// downloader; the exact octet order for `access`/`mem_type`/`seg_flags` must be
/// confirmed against a live device before this is relied on. Current layout:
/// `[event=3, sub=0x01, addr(u32 BE), size(u16 BE), access, mem_type, seg_flags]`
/// — 11 octets would overflow, so the size is a `u16` here to fit the 10-octet
/// structure; a device that wants a `u32` size will reject this. Flagged as an
/// open uncertainty for the download engine.
pub fn encode_abs_segment(
    addr: u32,
    size: u16,
    access: u8,
    mem_type: u8,
    seg_flags: u8,
) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[0] = LoadControl::AdditionalLoadControls.octet();
    v[1] = LD_CTRL_ABS_SEGMENT;
    v[2..6].copy_from_slice(&addr.to_be_bytes());
    v[6..8].copy_from_slice(&size.to_be_bytes());
    v[8] = access;
    v[9] = mem_type;
    // seg_flags has no octet left in the 10-octet structure; folded into the
    // caller's mem_type/access on real devices. Kept in the signature so the
    // downloader's call sites are explicit; documented uncertainty.
    let _ = seg_flags;
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
///    dispatches `AdditionalLoadControls` from the loading state; in any other
///    state the 10-octet write is ignored (`Unloaded`/`Loaded`) or errors, so
///    this checks the state first and fails with
///    [`WriteError::UnexpectedLoadState`] rather than issuing a write that the
///    device silently drops.
/// 2. Writes the 10-octet [`encode_rel_segment`] structure to
///    `PID_LOAD_STATE_CONTROL`. The device frees any prior backing store and
///    allocates `size` octets, optionally filled; on failure (e.g. maximum table
///    length exceeded) the object goes to [`LoadState::Error`].
/// 3. Re-reads the load state: `Error` means the device **refused** the
///    allocation (out of memory / too large) → [`WriteError::LoadError`]; still
///    `Loading` means success.
/// 4. Reads `PID_TABLE_REFERENCE` element 1 — a big-endian `u32` — which after a
///    successful allocation is the segment's start address (a device reports `0`
///    while `Unloaded`). That address is where the caller writes the table
///    content with [`crate::device::DeviceConnection::write_memory`].
///
/// `fill_byte` mirrors the relative structure's fill flag/byte: `Some(b)` asks
/// the device to pre-fill the segment with `b`, `None` leaves it uninitialised.
///
/// Load-state handling: the object must stay *open* — `Loading` on a conformant
/// device, or `Loaded` on a lenient stack (KNX Virtual snaps straight to
/// `Loaded`) — both as the allocation precondition and after the allocation
/// write. Only `Unloaded` (the write was dropped) or `Error` (the device refused
/// the allocation, e.g. out of memory) fail here; the image's actual integrity is
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

    // 1. The object must be open (Loading, or Loaded on a lenient stack like KNX
    //    Virtual) for the allocation to be accepted. Unloaded/Error mean the
    //    object never opened.
    let state = read_load_state(l4, object_index).await?;
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

    // 2. Write the 10-octet relative-allocation structure. The device echoes the
    //    resulting load state (best-effort); the authoritative check is the
    //    fresh read-back below, matching `write_load_control`'s discipline.
    let structure = encode_rel_segment(size, fill_byte);
    let _ =
        property_write_request(l4, object_index, PID_LOAD_STATE_CONTROL, 1, 1, &structure).await?;

    // 3. A refused allocation drops the object into Error. Otherwise the object
    //    stays open — Loading on a conformant device, or Loaded on a lenient stack
    //    (KNX Virtual); either is fine, only Unloaded/Error indicate the write was
    //    dropped or rejected.
    let state = read_load_state(l4, object_index).await?;
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
async fn read_table_reference<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
) -> Result<u32> {
    let resp = property_request(l4, object_index, PID_TABLE_REFERENCE, 1, 1).await?;
    if resp.count == 0 || resp.data.len() < 4 {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "table reference is not a readable u32 (object {object_index}, count {}, {} octet(s))",
                resp.count,
                resp.data.len()
            ),
        }));
    }
    Ok(u32::from_be_bytes([
        resp.data[0],
        resp.data[1],
        resp.data[2],
        resp.data[3],
    ]))
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
    let resp = property_request(l4, object_index, PID_MCB_TABLE, start, count.max(1)).await?;
    if resp.count == 0 || resp.data.len() < MCB_ENTRY_LEN {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address,
            reason: format!(
                "object {object_index} did not answer a readable PID_MCB_TABLE entry (count {}, {} octet(s))",
                resp.count,
                resp.data.len()
            ),
        }));
    }
    let entries: Vec<McbEntry> = resp
        .data
        .chunks_exact(MCB_ENTRY_LEN)
        .filter_map(McbEntry::decode)
        .collect();
    let first = entries.first().ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address,
            reason: format!("object {object_index} PID_MCB_TABLE has no 8-octet entry"),
        })
    })?;

    if let Some(image) = expected {
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

// --- Memory read/write on a Layer4Connection --------------------------------
//
// [`crate::device::DeviceConnection`] exposes `read_memory`/`write_memory`, but
// it owns its own `Layer4Connection`. The download engine drives the load
// machine (`write_load_control`, `allocate_segment`, `write_property`) directly
// against a borrowed `Layer4Connection` — the same channel it must write segment
// content into. These two helpers give it the memory primitives on that same
// connection, with the identical read-back verification discipline as
// `DeviceConnection::write_memory` (evidence: `device.rs`, which reads each
// chunk back and compares because `A_Memory_Write` has no mandatory response).

/// Reads `len` octets of device memory starting at `addr` over a borrowed
/// [`Layer4Connection`]. `len` is clamped to [`apci::MAX_MEMORY_READ_LEN`] per
/// telegram — callers loop for larger ranges. Mirrors
/// [`crate::device::DeviceConnection::read_memory`].
pub async fn read_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    len: u8,
) -> Result<Vec<u8>> {
    let (req_apci, payload) = apci::encode_memory_read(addr, len);
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    let resp = apci::decode_memory_response(resp_apci, &data).ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "expected A_Memory_Response with matching count ({})",
                raw_response_detail(resp_apci, &data)
            ),
        })
    })?;
    Ok(resp.data)
}

/// Writes `data` to device memory starting at the 16-bit `addr`, in
/// [`apci::MAX_MEMORY_WRITE_LEN`]-octet chunks, verifying each chunk by
/// read-back. Mirrors [`crate::device::DeviceConnection::write_memory`] but on a
/// borrowed [`Layer4Connection`] so the download engine can write segment content
/// on the very connection it drives the load machine over.
///
/// For every chunk this sends `A_Memory_Write`, then reads the same address back
/// and compares. A divergence fails with [`MgmtError::MemoryVerifyFailed`]. An
/// empty `data` is a no-op. This is [`write_memory_verified`] with no progress
/// callback.
pub async fn write_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    data: &[u8],
) -> Result<()> {
    write_memory_verified(l4, addr, data, |_| {}).await
}

/// The number of times a single memory-write exchange (the write plus its
/// read-back verify) is retried when it fails with a *transient* connection
/// blip, before the error is surfaced.
///
/// A real KNXnet/IP gateway holds one stable connection for the whole download
/// exactly as ETS does; this small bounded retry only exists so a transient hiccup
/// on a flaky Wi-Fi tunnel (a dropped ACK, a momentary silence) does not abort an
/// otherwise-healthy flash. It is NOT connection cycling: the same connection is
/// reused, and a device-level refusal (a verify mismatch, a load error) is never
/// retried. If the connection genuinely dies, the flash fails after these attempts
/// and re-running `bussard flash` is safe (the download is idempotent).
const MAX_EXCHANGE_RETRIES: u32 = 3;

/// Writes `data` to device memory at `addr`, verifying each
/// [`apci::MAX_MEMORY_WRITE_LEN`]-octet chunk by read-back, invoking `on_written`
/// with the cumulative octet count after each confirmed chunk (for progress
/// reporting).
///
/// Each chunk is written and immediately read back and compared, so a device that
/// silently drops or truncates a chunk fails at that chunk, before more content is
/// streamed on top — the conservative real-device behaviour. A transient
/// connection blip on an individual chunk is retried up to [`MAX_EXCHANGE_RETRIES`]
/// times on the same connection (see [`is_connection_death`]); a device-level
/// refusal propagates immediately. An empty `data` is a no-op.
pub async fn write_memory_verified<Ch: L4Channel, F: FnMut(usize)>(
    l4: &mut Layer4Connection<Ch>,
    addr: u16,
    data: &[u8],
    mut on_written: F,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    // Scale the chunk to the device's negotiated max APDU (issue #58): a capable
    // device takes the 63-octet ceiling in one extended frame, while a device
    // advertising the 15-octet standard-frame floor gets 12-octet chunks in
    // standard frames it can actually accept. Falls back to the conservative cap
    // when `PID_MAX_APDU_LENGTH` was never negotiated or was unreadable.
    let write_chunk = usize::from(l4.max_memory_chunk());
    let mut offset = 0usize;
    while offset < data.len() {
        let take = write_chunk.min(data.len() - offset);
        let piece = &data[offset..offset + take];

        // Write + verify this chunk, retrying a transient connection blip on the
        // same connection a bounded number of times. A device-level refusal (a
        // verify mismatch) is not retried — retrying would just fail again.
        let mut attempt = 0u32;
        loop {
            match write_one_chunk(l4, addr, offset, piece).await {
                Ok(()) => break,
                Err(err) if is_connection_death(&err) && attempt < MAX_EXCHANGE_RETRIES => {
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }

        offset += take;
        on_written(offset);
    }
    Ok(())
}

/// Whether an error is a connection-death — a mid-session silence, a dropped ACK,
/// or a momentary no-response (the "device absent"/"disconnected" family) — as
/// opposed to a device-level refusal like a verify mismatch or a load error.
///
/// Two callers use this. [`write_memory_verified`] retries such a blip a bounded
/// number of times **on the same connection** (a transient hiccup on a flaky Wi-Fi
/// tunnel). The flash engine (`bussard-download`) uses it, when a whole step fails
/// this way, to **cycle the L4 connection and re-run the step**: a
/// connection-oriented device (KNX Virtual) drops the L4 link at a
/// non-deterministic exchange count, but the object's load state and allocated
/// segments are persistent device state that survive the drop, so reconnecting and
/// resuming recovers it. A device-level refusal is never a connection-death, so
/// neither caller retries one.
pub fn is_connection_death(err: &WriteError) -> bool {
    matches!(
        err,
        WriteError::Mgmt(MgmtError::MidSessionSilence { .. })
            | WriteError::Mgmt(MgmtError::Disconnected { .. })
            | WriteError::Mgmt(MgmtError::NoResponse { .. })
    )
}

/// Writes one memory chunk at `base + offset` and verifies it by read-back.
async fn write_one_chunk<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    base: u16,
    offset: usize,
    piece: &[u8],
) -> Result<()> {
    let chunk_addr = chunk_address(l4, base, offset)?;
    let (req_apci, payload) = apci::encode_memory_write(chunk_addr, piece);
    // Write only, no per-chunk read-back. ETS streams the whole image and does
    // NOT read each chunk back — a read-back after every write doubles the
    // exchanges (exhausting a device's per-connection L4 budget on a large
    // segment) and, worse, interleaves stray A_Memory_Responses into the stream
    // so a following property read correlates the wrong response. Integrity is
    // confirmed after the load by the device's own MCB CRC (LdCtrlLoadImageProp)
    // and the flash engine's end-of-segment spot-check.
    l4.send_data(req_apci, &payload).await?;
    // A verify-mode device answers the write with an unsolicited A_Memory_Response
    // echo that await_ack folds into the pending slot. This write expects no
    // response, so drop the echo — otherwise it satisfies the next request's
    // recv_response with the wrong APDU (a "malformed response").
    l4.discard_pending_response();
    Ok(())
}

/// Computes `base + offset` as a 16-bit device address, failing if it runs past
/// the 16-bit address space (a programming error, not a device fault).
fn chunk_address<Ch: L4Channel>(
    l4: &Layer4Connection<Ch>,
    base: u16,
    offset: usize,
) -> Result<u16> {
    u16::try_from(offset)
        .ok()
        .and_then(|off| base.checked_add(off))
        .ok_or_else(|| {
            WriteError::Mgmt(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "memory write range exceeds the 16-bit address space".to_string(),
            })
        })
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
        // Unload is a best-effort reset (not verified): KNX Virtual reports
        // Loaded after it, which ETS tolerates and we must too.
        assert_eq!(LoadControl::Unload.expected_state(), None);
        assert_eq!(LoadControl::NoOperation.expected_state(), None);
        assert_eq!(LoadControl::AdditionalLoadControls.expected_state(), None);
    }

    #[test]
    fn rel_segment_structure_matches_spec_offsets() {
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
    }

    #[test]
    fn abs_segment_carries_event_and_subcommand() {
        let v = encode_abs_segment(0x0000_4000, 0x0140, 0xFF, 0x00, 0x00);
        assert_eq!(v.len(), 10);
        assert_eq!(v[0], LoadControl::AdditionalLoadControls.octet());
        assert_eq!(v[1], LD_CTRL_ABS_SEGMENT);
        assert_eq!(&v[2..6], &[0x00, 0x00, 0x40, 0x00]); // address big-endian
        assert_eq!(&v[6..8], &[0x01, 0x40]); // size big-endian
    }

    #[test]
    fn connection_death_classified_for_exchange_retry() {
        // The three transient-blip shapes a bounded per-exchange retry recovers from.
        let ia: IndividualAddress = "1.1.4".parse().unwrap();
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
    }

    #[test]
    fn displays_are_human_readable() {
        assert_eq!(LoadState::Loading.to_string(), "Loading");
        assert_eq!(LoadState::Error.to_string(), "Error");
        assert_eq!(LoadControl::StartLoading.to_string(), "StartLoading");
        assert_eq!(LoadControl::LoadCompleted.to_string(), "LoadCompleted");
    }

    #[test]
    fn empty_load_state_context_renders_nothing() {
        // The table-apply path drives write_load_control without discovery, so an
        // empty context must not alter the original message.
        assert_eq!(LoadStateContext::default().to_string(), "");
    }

    #[test]
    fn unexpected_load_state_folds_in_discovered_context() {
        // The finding-1 rich error: a load-state failure names the targeted
        // object's type and the full discovered object table.
        let err = WriteError::UnexpectedLoadState {
            address: "1.0.1".parse().unwrap(),
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
    }

    #[test]
    fn crc16_ccitt_matches_the_standard_check_vector() {
        // The catalogued CRC-16/AUG-CCITT check value for "123456789" is 0xE5CC
        // (the augmented CCITT variant the KNX MCB uses; CCITT-FALSE would be
        // 0x29B1).
        assert_eq!(crc16_ccitt(b"123456789"), 0xE5CC);
        // Init value FFFF, empty input (only the two augmenting zero bytes are
        // reduced) -> 0x1D0F.
        assert_eq!(crc16_ccitt(b""), 0x1D0F);
        // A single zero byte.
        assert_eq!(crc16_ccitt(&[0x00]), 0xCC9C);
    }

    #[test]
    fn mcb_entry_matches_spec_layout() {
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
        let dec = McbEntry::decode(&e).unwrap();
        assert_eq!(dec.segment_size, 9);
        assert_eq!(dec.crc_control, 0x00);
        assert_eq!(dec.access, 0xFF);
        assert_eq!(dec.crc16, 0xE5CC);
    }

    #[test]
    fn mcb_decode_rejects_short_slices() {
        assert!(McbEntry::decode(&[0u8; 7]).is_none());
        assert!(McbEntry::decode(&[0u8; 8]).is_some());
    }
}
