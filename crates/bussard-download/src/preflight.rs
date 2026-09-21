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
//!   its `PID_OBJECT_TYPE` and its load state read. A device is *not* fresh when
//!   an **application** object (interface-object type 3 `application program` or
//!   4 `interface program`) reports [`LoadState::Loaded`]. The resident
//!   application id is read from `PID_PROGRAM_VERSION` (PID 13) of those
//!   objects.
//! - **System 7** — the load-state machines (1, 2, 3 and 5) are read through the
//!   plan's `LsmAccess` realisation. A device is not fresh when any LSM reports
//!   `Loaded`. System 7 exposes no application-id property, so a resident
//!   application there can never be *identified* — see [`Freshness::Resident`].
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
    /// The resident application id (`PID_PROGRAM_VERSION`), when a device object
    /// reported a non-zero one. The all-zero placeholder is treated as absent:
    /// it is what an object carries when no download ever stamped it.
    pub app_id: Option<Vec<u8>>,
    /// Why nothing could be read, when the probe came back empty-handed.
    pub unreadable: Option<String>,
}

impl ResidentState {
    /// The objects that report [`LoadState::Loaded`] and carry an application.
    pub fn loaded_applications(&self) -> Vec<&ResidentObject> {
        self.objects
            .iter()
            .filter(|o| o.is_application() && o.state == LoadState::Loaded)
            .collect()
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
    /// could not be identified (no readable `PID_PROGRAM_VERSION`, or System 7,
    /// which has no such property). Flashing destroys it, so this is refused
    /// without `--force`.
    Resident {
        /// The resident id when it was readable, else `None` (unidentified).
        resident: Option<String>,
        /// The loaded objects, labelled — e.g. `object 3 (application program)`.
        objects: Vec<String>,
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

/// Reads what is resident on `l4`'s device, without writing anything.
///
/// Never fails: a device that refuses the reads yields a [`ResidentState`] whose
/// [`unreadable`](ResidentState::unreadable) names the failure, which the caller
/// turns into [`Freshness::Unknown`]. `sys7_lsm` supplies the System 7 LSM
/// realisation the planned flash will drive (`None` on System B).
pub async fn probe_resident_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    device_mask: u16,
    sys7_lsm: Option<&LsmAccess>,
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
        probe_system_b(l4).await
    }
}

/// The System B probe: walk the interface objects, read each one's load state,
/// and read `PID_PROGRAM_VERSION` off the application objects.
async fn probe_system_b<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> ResidentState {
    let mut state = ResidentState::default();
    // The same tolerant `PID_OBJECT_TYPE` walk the flash's own discovery uses,
    // so the probe sees exactly the object table the download will act on.
    let objects = match crate::flash::probe_object_types(l4).await {
        Ok(objects) => objects,
        Err(err) => {
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

    let mut failures: Vec<String> = Vec::new();
    for (index, object_type) in objects {
        // The device object (type 0) carries no load-state machine; skip its
        // read rather than spend an exchange proving it.
        if object_type == OT_DEVICE {
            continue;
        }
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
                    break;
                }
            }
        }
        // The application id lives on the application objects. Read it
        // best-effort: an object that does not carry one answers zero elements.
        if object_type == OT_APPLICATION_PROGRAM || object_type == OT_INTERFACE_PROGRAM {
            if let Ok(Some(value)) = read_program_version(l4, index).await {
                if state.app_id.is_none() && value.iter().any(|b| *b != 0) {
                    state.app_id = Some(value);
                }
            }
        }
    }

    if state.objects.is_empty() {
        state.unreadable = Some(format!(
            "no object reported a load state ({})",
            failures.join("; ")
        ));
    }
    state
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
                    break;
                }
            }
        }
    }
    if state.objects.is_empty() {
        state.unreadable = Some(format!(
            "no load-state machine answered ({})",
            failures.join("; ")
        ));
    }
    state
}

/// Judges a probed [`ResidentState`] against the application about to be
/// flashed.
///
/// See the module docs for the rule. The caller ([`bussard flash`]) refuses a
/// verdict whose [`allows_flash`](Freshness::allows_flash) is false unless
/// `--force` was passed.
pub fn assess_freshness(state: &ResidentState, identity: &AppIdentity) -> Freshness {
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
            unreadable: None,
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
            unreadable: None,
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(!verdict.allows_flash());
        match verdict {
            Freshness::Resident { resident, objects } => {
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
            unreadable: None,
        };
        let verdict = assess_freshness(&state, &da_tp());
        assert!(!verdict.allows_flash());
        match verdict {
            Freshness::Resident { resident, objects } => {
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
            Freshness::Resident { resident, objects } => {
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
            unreadable: None,
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
