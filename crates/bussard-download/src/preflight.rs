//! The pre-flash state probe: is this device factory-fresh? (issue #79)
//!
//! `bussard flash` unloads and rewrites a device's application wholesale and
//! takes **no backup** — it is built on the assumption that the target is
//! factory-fresh, because a fresh device has no prior application to save.
//! Nothing used to check that assumption, so flashing an already-programmed
//! device destroyed its application, parameters and links irrecoverably.
//!
//! This module is the check. It is **read-only**: it drives the same primitives
//! the download engine already uses to read state —
//! [`read_load_state`](bussard_mgmt::read_load_state) /
//! [`read_program_version`](bussard_mgmt::read_program_version) on System B, the
//! [`LsmAccess`](bussard_mgmt::LsmAccess) seam on System 7 — and never writes a
//! load control or a byte of memory. It runs in the CLI's read-only pre-flight
//! phase, *before* the plan is confirmed, so the confirmation can name what is
//! about to be destroyed. It is deliberately NOT inside
//! [`flash`](crate::flash::flash): the flash byte-path is pinned byte-for-byte
//! against the ETS reference captures, and a probe inside it would change the
//! wire sequence of every download.
//!
//! # The rule
//!
//! - **System B** — every interface object the device exposes is discovered by
//!   its `PID_OBJECT_TYPE` (or taken from the device facts). A device is *not*
//!   fresh when an **application** object (interface-object type 3 `application
//!   program` or 4 `interface program`) reports [`LoadState::Loaded`], so the
//!   load state of those objects is read; the other objects are read only when
//!   no application object answers (issue #213). The resident application id is
//!   read from `PID_PROGRAM_VERSION` (PID 13) of the application objects.
//! - **System 7** — the load-state machines (1, 2, 3 and 5) are read through the
//!   plan's `LsmAccess` realisation. A device is not fresh when any LSM reports
//!   `Loaded`. A device with a loaded LSM is then asked for the resident
//!   application's id: `PID_PROGRAM_VERSION` (PID 13) of the application
//!   program object, object 3 (issue #481). KNX 6 Profiles Annex A.2.6 lists it
//!   readable on masks 0701 and 0705, 3/5/1 §4.2.13 defines it as manufacturer
//!   (2), device type (2) and version (1), the five octets the TaskSegment
//!   record carries after the PEI type (3/5/2 §3.31.2), which #485 writes. The
//!   Profiles call the application identification optional on BIM M112 (§4.3
//!   row 8), so a device that does not answer within
//!   [`bussard_mgmt::knxnet::PROBE_RESPONSE_TIMEOUT`] keeps the earlier
//!   verdict: unidentified, decided by the code sample of
//!   [`sys7_identity`](crate::sys7_identity). An id that answers and names
//!   another application is a [`Freshness::Resident`] with that id; one that
//!   matches leaves the code sample to confirm it.
//! - `Unloaded`, `Loading` and `Error` all count as fresh enough to flash: an
//!   interrupted flash leaves an object mid-`Loading`, and re-running `flash` is
//!   the documented recovery path for exactly that.
//! - When **nothing** answers — the device refuses the reads, an older mask does
//!   not expose them, a transient drop — the state is [`Freshness::Unknown`],
//!   not "fresh". The caller refuses on unknown, because "could not read" is not
//!   evidence of an empty device.

use bussard_mgmt::{
    L4Channel, Layer4Connection, LoadState, LsmAccess, MaskProfile, Sys7Profile,
    is_connection_death, lsm_access_from_profile, read_load_state, read_program_version,
};

use crate::flash::AppIdentity;

/// Interface-object type 0: the device object. It carries no load-state
/// machine, so the probe does not read one from it.
const OT_DEVICE: u16 = 0;
/// Interface-object type 3: the application-program object.
const OT_APPLICATION_PROGRAM: u16 = 3;
/// Interface-object type 4: the interface-program (PEI) object. On the merged
/// System B shapes the application segment can live on this object, so it counts
/// as an application object for the freshness decision.
const OT_INTERFACE_PROGRAM: u16 = 4;

/// The load-state machines a System 7 probe reads: the address table (1), the
/// association table (2), the application/parameter region (3) and the optional
/// PEI program (5) — the LSM set the System 7 corpus downloads.
const SYS7_LSMS: [u8; 4] = [1, 2, 3, 5];

/// The System 7 application program object, whose `PID_PROGRAM_VERSION`
/// holds the resident application's id (KNX 6 Profiles Annex A.2.6, issue
/// #481).
const SYS7_APPLICATION_OBJECT: u8 = 3;

/// One loadable object (System B) or load-state machine (System 7) the probe
/// read, with the state it reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentObject {
    /// The device object index (System B) or LSM index (System 7).
    pub index: u8,
    /// The interface-object type, when the probe discovered one (System B).
    /// `None` on System 7, whose LSMs are not interface objects.
    pub object_type: Option<u16>,
    /// The state the object reported.
    pub state: LoadState,
}

impl ResidentObject {
    /// Whether this object carries an application program — the objects whose
    /// `Loaded` state means "this device is programmed".
    pub fn is_application(&self) -> bool {
        match self.object_type {
            // System B: the application-program / interface-program objects.
            Some(ot) => ot == OT_APPLICATION_PROGRAM || ot == OT_INTERFACE_PROGRAM,
            // System 7: every LSM is part of the resident configuration.
            None => true,
        }
    }

    /// A short human label for the object: its index plus what it is.
    pub fn label(&self) -> String {
        let what = match self.object_type {
            Some(OT_DEVICE) => " (device object)",
            Some(1) => " (address table)",
            Some(2) => " (association table)",
            Some(OT_APPLICATION_PROGRAM) => " (application program)",
            Some(OT_INTERFACE_PROGRAM) => " (interface program)",
            Some(5) => " (KNX-object association table)",
            Some(9) => " (group-object table)",
            _ => "",
        };
        match self.object_type {
            Some(_) => format!("object {}{what}", self.index),
            None => format!("LSM {}", self.index),
        }
    }
}

/// What the read-only pre-flight found resident on the device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResidentState {
    /// Every object/LSM whose state the probe managed to read, in probe order.
    pub objects: Vec<ResidentObject>,
    /// The raw interface-object table (`index → PID_OBJECT_TYPE`) the System B
    /// walk discovered, in index order.
    ///
    /// This is the *full* table, including the device object (type 0), whose
    /// load state is deliberately not read and which therefore has no entry in
    /// [`objects`](ResidentState::objects). It is device-stable, so the caller
    /// hands it to the write phase as part of
    /// [`DeviceFacts`](crate::DeviceFacts) instead of walking it again. Empty on
    /// System 7 (whose LSMs are not interface objects) and when the walk failed.
    pub object_table: Vec<(u8, u16)>,
    /// The resident application id (`PID_PROGRAM_VERSION`), when a device object
    /// reported a non-zero one (on System 7, object 3 of a device with a loaded
    /// LSM, issue #481). The all-zero placeholder is treated as absent: it is
    /// what an object carries when no download ever stamped it.
    pub app_id: Option<Vec<u8>>,
    /// The property data type of the association table's `PID_TABLE` (System
    /// B), when the device describes it: `PDT_GENERIC_04` for the four-octet
    /// format 1 bussard writes, `PDT_GENERIC_02` for format 0, which the flash
    /// refuses (Resources §4.17.5.2.5, issue #545).
    pub association_pdt: Option<u8>,
    /// The device's `PID_MANUFACTURER_ID` (object 0, PID 12) on System B, when
    /// it answered: the manufacturer check of the download procedure
    /// (Configuration Procedures §3.5.2 step 04, issue #547).
    pub manufacturer_id: Option<u16>,
    /// Why nothing could be read, when the probe came back empty-handed.
    pub unreadable: Option<String>,
    /// Whether a connection death (a Layer-4 drop or a lost gateway link) cut
    /// the probe short, so `objects` may be incomplete.
    ///
    /// An interrupted probe is never evidence of a fresh device: it also sets
    /// [`unreadable`](ResidentState::unreadable), and the CLI re-runs the
    /// read-only pre-flight on a fresh connection (issue #177).
    pub interrupted: bool,
}

impl ResidentState {
    /// The objects that report [`LoadState::Loaded`] and carry an application.
    pub fn loaded_applications(&self) -> Vec<&ResidentObject> {
        self.objects
            .iter()
            .filter(|o| o.is_application() && o.state == LoadState::Loaded)
            .collect()
    }

    /// Whether the probe read System 7 load-state machines (no interface
    /// object types), rather than System B objects.
    pub fn is_sys7(&self) -> bool {
        !self.objects.is_empty() && self.objects.iter().all(|o| o.object_type.is_none())
    }

    /// Whether the device holds a loaded application.
    pub fn has_loaded_application(&self) -> bool {
        !self.loaded_applications().is_empty()
    }

    /// The resident application id rendered for a human, e.g.
    /// `M-00FA A-2500 v16`, or a hex dump for a non-standard length.
    pub fn app_id_display(&self) -> Option<String> {
        self.app_id.as_deref().map(format_app_id)
    }
}

/// The freshness verdict for a planned flash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// No application object is loaded: the device is factory-fresh (or was left
    /// unloaded / mid-load by an interrupted flash). Flashing is what it is for.
    Fresh,
    /// An application is loaded and its id is **the one being flashed**. A
    /// re-flash of the same application is the documented recovery path, so it
    /// is allowed without `--force` — it is still a full rewrite.
    SameApplication {
        /// The resident id, rendered (`M-00FA A-2500 v16`).
        resident: String,
    },
    /// An application is loaded and it is **not** the one being flashed, or it
    /// could not be identified (no readable `PID_PROGRAM_VERSION`; on System 7
    /// a readable id that matches is confirmed by the code sample too, issue
    /// #481). Flashing destroys it, so this is refused without `--force`.
    Resident {
        /// The resident id when it was readable, else `None` (unidentified).
        resident: Option<String>,
        /// The loaded objects, labelled — e.g. `object 3 (application program)`.
        objects: Vec<String>,
        /// What a check beyond the id found different, when one ran: on
        /// System 7 the code segment and first differing offset of
        /// [`sys7_identity`](crate::sys7_identity), or the
        /// `PID_PROGRAM_VERSION` that names another application (issue #481).
        /// Otherwise `None` from [`assess_freshness`].
        reason: Option<String>,
    },
    /// The device is not one this plan can be written to, whatever it holds:
    /// it reports another manufacturer than the application's (Configuration
    /// Procedures §3.5.2 step 04), or its association table uses a format
    /// bussard does not write. Refused
    /// without `--force` before anything is unloaded; a forced flash still ends
    /// in a read-back that refuses the format, so it cannot pass as verified.
    Mismatch {
        /// What does not match, for the refusal message.
        reason: String,
    },
    /// The device's load state could not be read at all, so freshness is
    /// undetermined. Refused without `--force`: unreadable is not evidence of an
    /// empty device.
    Unknown {
        /// Why the read failed.
        reason: String,
    },
}

impl Freshness {
    /// Whether flashing may proceed without `--force`.
    pub fn allows_flash(&self) -> bool {
        matches!(self, Freshness::Fresh | Freshness::SameApplication { .. })
    }
}

/// A manufacturer id for a message: `Jung (M-0004)`, or `M-1234` when the
/// name is unknown.
fn manufacturer_label(id: u16) -> String {
    match bussard_mgmt::manufacturers::name(id) {
        Some(name) => format!("{name} (M-{id:04X})"),
        None => format!("M-{id:04X}"),
    }
}

/// Renders a `PID_PROGRAM_VERSION` value: the ETS 5-octet
/// `[manufacturer:2][application number:2][version:1]` layout as
/// `M-00FA A-2500 v16`, anything else as hex.
pub fn format_app_id(bytes: &[u8]) -> String {
    if bytes.len() == 5 {
        let manufacturer = u16::from_be_bytes([bytes[0], bytes[1]]);
        let number = u16::from_be_bytes([bytes[2], bytes[3]]);
        format!("M-{manufacturer:04X} A-{number:04X} v{}", bytes[4])
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("")
    }
}

/// How much of a System B device the resident-state probe reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeScope {
    /// The load state and `PID_PROGRAM_VERSION` of the application objects,
    /// the only objects whose state decides the verdict (issue #213). Falls
    /// back to [`Full`](ProbeScope::Full) when the table names no application
    /// object or none of them reports a load state.
    Decisive,
    /// The load state of every interface object but the device object.
    Full,
}

/// Reads what is resident on `l4`'s device, without writing anything.
///
/// Never fails: a device that refuses the reads yields a [`ResidentState`] whose
/// [`unreadable`](ResidentState::unreadable) names the failure, which the caller
/// turns into [`Freshness::Unknown`]. `sys7_lsm` supplies the System 7 LSM
/// realisation the planned flash will drive (`None` on System B).
///
/// On System B it reads what decides the verdict (issue #213): the load state
/// and the application id of the application objects (interface-object types 3
/// and 4). The other objects' states never change the verdict (see the module
/// docs), so they are not read, unless the table names no application object or
/// none of them reports a load state; the probe then reads every object, as
/// [`probe_resident_state_full`] does, so the verdict is the same one the full
/// walk gives. System 7 reads every load-state machine either way.
pub async fn probe_resident_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    device_mask: u16,
    sys7_lsm: Option<&LsmAccess>,
) -> ResidentState {
    probe_with_scope(l4, device_mask, sys7_lsm, ProbeScope::Decisive).await
}

/// [`probe_resident_state`] reading the load state of every interface object
/// (the probe before issue #213). Its verdict is the same; the extra states are
/// for diagnostics and for the tests that prove the two agree.
pub async fn probe_resident_state_full<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    device_mask: u16,
    sys7_lsm: Option<&LsmAccess>,
) -> ResidentState {
    probe_with_scope(l4, device_mask, sys7_lsm, ProbeScope::Full).await
}

/// The probe behind [`probe_resident_state`] and [`probe_resident_state_full`].
async fn probe_with_scope<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    device_mask: u16,
    sys7_lsm: Option<&LsmAccess>,
    scope: ProbeScope,
) -> ResidentState {
    let profile = MaskProfile::from_mask(device_mask);
    if profile.is_system_7() {
        let fallback;
        let access = match sys7_lsm {
            Some(access) => access,
            None => {
                // The same realisation `plan_flash_sys7` resolves for the CLI
                // path: the mask's default profile, with the conformance-harness
                // env override applied, so the probe reads the LSMs exactly
                // where the flash would drive them.
                let mut s7 = profile
                    .sys7_default_profile()
                    .unwrap_or_else(Sys7Profile::corpus_default);
                if let Some(lsm) = crate::flash::sys7_lsm_override() {
                    s7.lsm = lsm;
                }
                fallback = lsm_access_from_profile(&s7);
                &fallback
            }
        };
        probe_sys7(l4, access).await
    } else {
        probe_system_b(l4, scope).await
    }
}

/// An interface-object table: `(index, PID_OBJECT_TYPE)` pairs.
type ObjectTable = Vec<(u8, u16)>;

/// Whether an interface-object type carries an application program.
fn is_application_type(object_type: u16) -> bool {
    object_type == OT_APPLICATION_PROGRAM || object_type == OT_INTERFACE_PROGRAM
}

/// The System B probe: walk the interface objects, read the load state of the
/// objects `scope` names, and read `PID_PROGRAM_VERSION` off the application
/// objects.
async fn probe_system_b<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    scope: ProbeScope,
) -> ResidentState {
    let mut state = ResidentState::default();
    // The same tolerant `PID_OBJECT_TYPE` walk the flash's own discovery uses,
    // so the probe sees exactly the object table the download will act on.
    let objects = match crate::flash::probe_object_types(l4).await {
        Ok(objects) => objects,
        Err(err) => {
            state.interrupted = is_connection_death(&err);
            state.unreadable = Some(format!("interface objects are not discoverable: {err}"));
            return state;
        }
    };
    if objects.is_empty() {
        state.unreadable = Some(
            "the device answered no interface object (PID_OBJECT_TYPE empty at index 0)".into(),
        );
        return state;
    }
    // Keep the raw table: the write phase reuses it instead of re-walking it.
    state.object_table = objects.clone();

    let mut failures: Vec<String> = Vec::new();
    // The device object (type 0) carries no load-state machine; its read is
    // skipped rather than spending an exchange proving it.
    let loadable: Vec<(u8, u16)> = objects
        .iter()
        .copied()
        .filter(|(_, object_type)| *object_type != OT_DEVICE)
        .collect();
    let (first, rest): (ObjectTable, ObjectTable) = match scope {
        ProbeScope::Full => (loadable, Vec::new()),
        ProbeScope::Decisive => loadable
            .into_iter()
            .partition(|(_, object_type)| is_application_type(*object_type)),
    };
    read_objects(l4, &first, &mut state, &mut failures).await;
    // The fallback to the full walk: no application object answered (or the
    // table names none), so the verdict rests on the other objects, as it did
    // before issue #213.
    if state.objects.is_empty() && !state.interrupted && !rest.is_empty() {
        read_objects(l4, &rest, &mut state, &mut failures).await;
        state.objects.sort_by_key(|o| o.index);
    }

    // The manufacturer check of the download procedure (Configuration
    // Procedures §3.5.2 step 04): PID_MANUFACTURER_ID of the device object,
    // read before the flash unloads anything.
    if !state.interrupted {
        state.manufacturer_id = bussard_mgmt::read_manufacturer_id(l4).await.ok().flatten();
    }

    // The association table's entry format (Resources §4.17.5.2.5): one
    // description read after the load states, tolerant of a device that does
    // not describe it.
    if !state.interrupted
        && let Some(&(index, _)) = objects
            .iter()
            .find(|&&(_, object_type)| object_type == bussard_mgmt::tables::OT_ASSOCIATION_TABLE)
    {
        state.association_pdt = bussard_mgmt::tables::read_association_pdt(l4, index).await;
    }

    if state.objects.is_empty() {
        state.unreadable = Some(format!(
            "no object reported a load state ({})",
            failures.join("; ")
        ));
    } else if state.interrupted {
        // A partial walk may have missed the loaded application object.
        state.unreadable = Some(format!(
            "the connection dropped during the probe ({})",
            failures.join("; ")
        ));
    }
    state
}

/// Reads the load state of each of `objects` (and the application id of the
/// application objects) into `state`, stopping at a connection death.
async fn read_objects<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: &[(u8, u16)],
    state: &mut ResidentState,
    failures: &mut Vec<String>,
) {
    for &(index, object_type) in objects {
        match read_load_state(l4, index).await {
            Ok(load_state) => state.objects.push(ResidentObject {
                index,
                object_type: Some(object_type),
                state: load_state,
            }),
            // An object that does not expose a load-state property simply is not
            // loadable; that is normal, not a probe failure. A dropped connection
            // is different: every further read would burn its full timeout on a
            // dead link, so stop and report what was read.
            Err(err) => {
                let dead = is_connection_death(&err);
                failures.push(format!("object {index}: {err}"));
                if dead {
                    state.interrupted = true;
                    return;
                }
            }
        }
        // The application id lives on the application objects. Read it
        // best-effort: an object that does not carry one answers zero elements.
        if is_application_type(object_type)
            && let Ok(Some(value)) = read_program_version(l4, index).await
            && state.app_id.is_none()
            && value.iter().any(|b| *b != 0)
        {
            state.app_id = Some(value);
        }
    }
}

/// The System 7 probe: read each load-state machine through the `LsmAccess`
/// realisation the flash will drive.
async fn probe_sys7<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: &LsmAccess,
) -> ResidentState {
    let mut state = ResidentState::default();
    let mut failures: Vec<String> = Vec::new();
    for lsm in SYS7_LSMS {
        match access.read_state(l4, lsm).await {
            Ok(load_state) => state.objects.push(ResidentObject {
                index: lsm,
                object_type: None,
                state: load_state,
            }),
            // A device without this LSM simply does not answer for it; a dropped
            // connection ends the probe (see the System B walk).
            Err(err) => {
                let dead = is_connection_death(&err);
                failures.push(format!("LSM {lsm}: {err}"));
                if dead {
                    state.interrupted = true;
                    break;
                }
            }
        }
    }
    // The resident application's id (issue #481), only when something is
    // loaded (a fresh device's id decides nothing) and best effort: a device
    // that leaves it unanswered within the probe timeout, or holds the
    // all-zero placeholder, stays unidentified as before.
    if !state.interrupted
        && state.objects.iter().any(|o| o.state == LoadState::Loaded)
        && let Ok(Some(value)) = bussard_mgmt::knxnet::with_probe_timeout(l4, async |l4| {
            read_program_version(l4, SYS7_APPLICATION_OBJECT).await
        })
        .await
        && value.iter().any(|b| *b != 0)
    {
        state.app_id = Some(value);
    }
    if state.objects.is_empty() {
        state.unreadable = Some(format!(
            "no load-state machine answered ({})",
            failures.join("; ")
        ));
    } else if state.interrupted {
        state.unreadable = Some(format!(
            "the connection dropped during the probe ({})",
            failures.join("; ")
        ));
    }
    state
}

/// Whether a System 7 `PID_PROGRAM_VERSION` names another application than
/// `identity`: another manufacturer than the ones the application may carry
/// (its own or, with `LegacyPatchManufacturerIdInTaskSegment`, its
/// `OriginalManufacturer`, which the TaskSegment record then holds), or
/// another application number or version. `false` when either side is too
/// short or incomplete to tell.
fn sys7_id_differs(device_id: &[u8], identity: &AppIdentity) -> bool {
    let Some(planned) = identity.program_version() else {
        return false;
    };
    if device_id.len() < planned.len() {
        return false;
    }
    let manufacturer = u16::from_be_bytes([device_id[0], device_id[1]]);
    !identity.expected_manufacturers().contains(&manufacturer) || device_id[2..5] != planned[2..5]
}

/// Judges a probed [`ResidentState`] against the application about to be
/// flashed.
///
/// See the module docs for the rule. The caller ([`bussard flash`]) refuses a
/// verdict whose [`allows_flash`](Freshness::allows_flash) is false unless
/// `--force` was passed.
pub fn assess_freshness(state: &ResidentState, identity: &AppIdentity) -> Freshness {
    let expected = identity.expected_manufacturers();
    if let Some(device) = state.manufacturer_id
        && !expected.is_empty()
        && !expected.contains(&device)
    {
        let names = expected
            .iter()
            .map(|&m| manufacturer_label(m))
            .collect::<Vec<_>>()
            .join(" or ");
        return Freshness::Mismatch {
            reason: format!(
                "the device reports manufacturer {} (PID_MANUFACTURER_ID), but {} is an \
                 application of {names}",
                manufacturer_label(device),
                identity.id
            ),
        };
    }
    if state.association_pdt == Some(bussard_mgmt::tables::PDT_GENERIC_02) {
        return Freshness::Mismatch {
            reason: "its association table uses format 0 (PDT_GENERIC_02, one-octet TSAP and \
                     ASAP); the download writes format 1 (PDT_GENERIC_04) only"
                .to_string(),
        };
    }
    if let Some(reason) = &state.unreadable {
        return Freshness::Unknown {
            reason: reason.clone(),
        };
    }
    let loaded = state.loaded_applications();
    if loaded.is_empty() {
        return Freshness::Fresh;
    }
    let resident = state.app_id_display();
    if state.is_sys7() {
        // System 7 (issue #481): an id that names another application refuses
        // on its own; a matching one, or none, leaves the verdict to the code
        // sample (`sys7_identity`), as before.
        return match (state.app_id.as_deref(), resident) {
            (Some(device_id), Some(id)) if sys7_id_differs(device_id, identity) => {
                Freshness::Resident {
                    resident: Some(id.clone()),
                    objects: loaded.iter().map(|o| o.label()).collect(),
                    reason: Some(format!(
                        "PID_PROGRAM_VERSION of the application object reports {id}, not {}",
                        identity.id
                    )),
                }
            }
            _ => Freshness::Resident {
                resident: None,
                objects: loaded.iter().map(|o| o.label()).collect(),
                reason: None,
            },
        };
    }
    if let (Some(device_id), Some(planned)) = (state.app_id.as_deref(), identity.program_version())
        && device_id.len() >= planned.len()
        && device_id[..planned.len()] == planned[..]
    {
        return Freshness::SameApplication {
            // `resident` is `Some` whenever `state.app_id` is.
            resident: resident.unwrap_or_default(),
        };
    }
    Freshness::Resident {
        resident,
        objects: loaded.iter().map(|o| o.label()).collect(),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(id: &str, number: Option<u32>, version: Option<u32>) -> AppIdentity {
        AppIdentity {
            id: id.to_string(),
            name: None,
            application_number: number,
            application_version: version,
            mask_version: "07B0".to_string(),
            original_manufacturer: None,
        }
    }

    fn da_tp() -> AppIdentity {
        // KNX Virtual DA.tp: manufacturer 0x00FA, app number 9472 (0x2500),
        // version 16 (0x10) — the capture's `00 fa 25 00 10`.
        identity("M-00FA_A-2500-10-51CB", Some(9472), Some(16))
    }

    fn object(index: u8, object_type: u16, state: LoadState) -> ResidentObject {
        ResidentObject {
            index,
            object_type: Some(object_type),
            state,
        }
    }

    /// Issue #481: the System 7 id of `PID_PROGRAM_VERSION`. Another number
    /// or version, or a manufacturer the application cannot carry, differs;
    /// the `OriginalManufacturer` a legacy TaskSegment writes (`M-0007_A-A002`
    /// writes `00 02 a0 02 13`, the 1.1.44 capture) does not.
    #[test]
    fn test_sys7_id_differs_honours_the_original_manufacturer() {
        let mut bj = identity("M-0007_A-A002-13-73C8-O0002", Some(0xA002), Some(0x13));
        bj.mask_version = "0701".to_string();
        bj.original_manufacturer = Some("M-0002".to_string());
        assert!(!sys7_id_differs(&[0x00, 0x02, 0xA0, 0x02, 0x13], &bj));
        assert!(!sys7_id_differs(&[0x00, 0x07, 0xA0, 0x02, 0x13], &bj));
        assert!(sys7_id_differs(&[0x00, 0x04, 0xA0, 0x02, 0x13], &bj));
        assert!(sys7_id_differs(&[0x00, 0x02, 0xA0, 0x02, 0x14], &bj));
        assert!(sys7_id_differs(&[0x00, 0x02, 0xA0, 0x03, 0x13], &bj));
        // Too short to tell.
        assert!(!sys7_id_differs(&[0x00, 0x02], &bj));
    }

    #[test]
    fn test_assess_freshness_sys7_id_of_another_application_is_resident() {
        let sys7_loaded = |id: Option<Vec<u8>>| ResidentState {
            objects: vec![ResidentObject {
                index: 3,
                object_type: None,
                state: LoadState::Loaded,
            }],
            app_id: id,
            ..ResidentState::default()
        };
        let app = identity("M-0004_A-A011-13-400D-O000A", Some(0xA011), Some(0x13));
        let verdict = assess_freshness(&sys7_loaded(Some(vec![0, 4, 0xA0, 0x12, 0x13])), &app);
        assert!(
            matches!(&verdict, Freshness::Resident { resident: Some(id), reason: Some(_), .. }
                if id == "M-0004 A-A012 v19"),
            "{verdict:?}"
        );
        for id in [Some(vec![0, 4, 0xA0, 0x11, 0x13]), None] {
            let verdict = assess_freshness(&sys7_loaded(id), &app);
            assert!(
                matches!(
                    verdict,
                    Freshness::Resident {
                        resident: None,
                        reason: None,
                        ..
                    }
                ),
                "{verdict:?}"
            );
        }
    }

    #[test]
    fn test_assess_freshness_format_0_association_table_is_a_mismatch() {
        // Resources §4.17.5.2.5: a format-0 association table (PDT_GENERIC_02)
        // does not take the four-octet entries the download writes (#545).
        let state = ResidentState {
            objects: vec![object(3, 3, LoadState::Unloaded)],
            association_pdt: Some(bussard_mgmt::tables::PDT_GENERIC_02),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(matches!(verdict, Freshness::Mismatch { .. }), "{verdict:?}");
        assert!(!verdict.allows_flash());
        // Format 1 is what the download writes.
        let state = ResidentState {
            association_pdt: Some(bussard_mgmt::tables::PDT_GENERIC_04),
            ..state
        };
        assert_eq!(assess_freshness(&state, &da_tp()), Freshness::Fresh);
    }

    #[test]
    fn test_assess_freshness_other_manufacturer_is_a_mismatch() {
        // Configuration Procedures §3.5.2 step 04 (#547): the device's
        // PID_MANUFACTURER_ID must be the application's manufacturer.
        let state = ResidentState {
            objects: vec![object(3, 3, LoadState::Unloaded)],
            manufacturer_id: Some(0x0004),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(matches!(verdict, Freshness::Mismatch { .. }), "{verdict:?}");
        let same = ResidentState {
            manufacturer_id: Some(0x00FA),
            ..state.clone()
        };
        assert_eq!(assess_freshness(&same, &da_tp()), Freshness::Fresh);
        // An application made by another manufacturer also matches that one.
        let oem = AppIdentity {
            original_manufacturer: Some("M-0004".to_string()),
            ..da_tp()
        };
        assert_eq!(assess_freshness(&state, &oem), Freshness::Fresh);
        // No answer: nothing to compare, the check does not refuse.
        let silent = ResidentState {
            manufacturer_id: None,
            ..state
        };
        assert_eq!(assess_freshness(&silent, &da_tp()), Freshness::Fresh);
    }

    #[test]
    fn test_assess_freshness_unloaded_device_is_fresh() {
        let state = ResidentState {
            objects: vec![
                object(1, 1, LoadState::Unloaded),
                object(3, 3, LoadState::Unloaded),
            ],
            ..ResidentState::default()
        };
        assert_eq!(assess_freshness(&state, &da_tp()), Freshness::Fresh);
    }

    #[test]
    fn test_assess_freshness_interrupted_flash_is_fresh() {
        // An object left mid-`Loading` (or in `Error`) by an interrupted flash is
        // not a programmed device: re-running `flash` is the recovery path.
        let state = ResidentState {
            objects: vec![
                object(3, 3, LoadState::Loading),
                object(4, 4, LoadState::Error),
            ],
            ..ResidentState::default()
        };
        assert_eq!(assess_freshness(&state, &da_tp()), Freshness::Fresh);
    }

    #[test]
    fn test_assess_freshness_loaded_table_only_is_fresh() {
        // Only the address table is loaded; no application object is. The
        // freshness decision keys on the application, so this proceeds.
        let state = ResidentState {
            objects: vec![
                object(1, 1, LoadState::Loaded),
                object(3, 3, LoadState::Unloaded),
            ],
            ..ResidentState::default()
        };
        assert_eq!(assess_freshness(&state, &da_tp()), Freshness::Fresh);
    }

    #[test]
    fn test_assess_freshness_same_application_is_allowed() {
        let state = ResidentState {
            objects: vec![object(3, 3, LoadState::Loaded)],
            app_id: Some(vec![0x00, 0xFA, 0x25, 0x00, 0x10]),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert_eq!(
            verdict,
            Freshness::SameApplication {
                resident: "M-00FA A-2500 v16".to_string()
            }
        );
        assert!(verdict.allows_flash());
    }

    #[test]
    fn test_assess_freshness_different_version_is_resident() {
        // The same application at a different version is a different application
        // for this purpose: the download resets parameters wholesale.
        let state = ResidentState {
            objects: vec![object(3, 3, LoadState::Loaded)],
            app_id: Some(vec![0x00, 0xFA, 0x25, 0x00, 0x0A]),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(!verdict.allows_flash());
        match verdict {
            Freshness::Resident {
                resident, objects, ..
            } => {
                assert_eq!(resident.as_deref(), Some("M-00FA A-2500 v10"));
                assert_eq!(objects, vec!["object 3 (application program)".to_string()]);
            }
            other => panic!("expected Resident, got {other:?}"),
        }
    }

    #[test]
    fn test_assess_freshness_loaded_without_app_id_is_unidentified() {
        // Loaded, but nothing stamped `PID_PROGRAM_VERSION` (or it reads back as
        // the all-zero placeholder): the resident application cannot be named, so
        // it must not be silently overwritten.
        let state = ResidentState {
            objects: vec![object(4, 4, LoadState::Loaded)],
            app_id: None,
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(!verdict.allows_flash());
        match verdict {
            Freshness::Resident {
                resident, objects, ..
            } => {
                assert!(resident.is_none());
                assert_eq!(objects, vec!["object 4 (interface program)".to_string()]);
            }
            other => panic!("expected Resident, got {other:?}"),
        }
    }

    #[test]
    fn test_assess_freshness_sys7_loaded_lsm_is_resident() {
        // System 7 exposes no application id, so a loaded LSM is always
        // "resident, unidentified".
        let state = ResidentState {
            objects: vec![ResidentObject {
                index: 3,
                object_type: None,
                state: LoadState::Loaded,
            }],
            ..ResidentState::default()
        };
        match assess_freshness(&state, &da_tp()) {
            Freshness::Resident {
                resident, objects, ..
            } => {
                assert!(resident.is_none());
                assert_eq!(objects, vec!["LSM 3".to_string()]);
            }
            other => panic!("expected Resident, got {other:?}"),
        }
    }

    #[test]
    fn test_assess_freshness_unreadable_is_unknown() {
        let state = ResidentState {
            unreadable: Some("device refused the read".to_string()),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(!verdict.allows_flash());
        assert!(matches!(verdict, Freshness::Unknown { .. }));
    }

    #[test]
    fn test_assess_freshness_incomplete_identity_cannot_match() {
        // An application whose number/version the product data does not carry has
        // no comparable id, so a loaded device is never treated as "the same".
        let state = ResidentState {
            objects: vec![object(3, 3, LoadState::Loaded)],
            app_id: Some(vec![0x00, 0xFA, 0x25, 0x00, 0x10]),
            ..ResidentState::default()
        };
        let verdict = assess_freshness(&state, &identity("M-00FA_A-2500", None, None));
        assert!(!verdict.allows_flash());
    }

    #[test]
    fn test_format_app_id_renders_ets_layout_and_hex() {
        assert_eq!(
            format_app_id(&[0x00, 0xFA, 0x25, 0x00, 0x10]),
            "M-00FA A-2500 v16"
        );
        assert_eq!(format_app_id(&[0xDE, 0xAD]), "DEAD");
    }
}
