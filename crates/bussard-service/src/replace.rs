//! The replace flow (issues #98, #751): put the same product back at the
//! address of a dead device, as `bussard replace` and `knx_replace_device`
//! do.
//!
//! A replacement is the assign, flash and apply steps behind one
//! confirmation, plus the identity cross-check against the model and the
//! record of the hardware swap. This module is the step machine: the order of
//! the steps ([`Replacement::next`]) and the functions each step runs, none
//! of which prints or asks. The CLI keeps its prompts and lines, the MCP tool
//! its questions and JSON (#314).
//!
//! The steps, in the order [`Replacement::next`] walks them:
//!
//! 1. [`Step::CheckGone`]: nothing may answer at the address
//!    ([`crate::assign::probe_occupant`]); a device that still answers is not
//!    a replacement case.
//! 2. [`Step::PressButton`]: the wait for the programming-mode broadcast
//!    ([`crate::assign::wait_for_programming_mode`]).
//! 3. [`Step::Identify`]: what the pressed device is ([`identify`]: mask,
//!    order number, serial, resident application id) and its identity
//!    verdict against the lock ([`Replacement::identity_check`]).
//! 4. [`Step::CrossCheck`]: the refusal when it is another product
//!    ([`Replacement::mismatch`]).
//! 5. [`Step::Confirm`]: the one confirmation, the surface's.
//! 6. [`Step::Assign`]: the address ([`crate::assign::write_address`]) and the
//!    independent read-back at it ([`crate::assign::verify_assignment_with`]),
//!    merged into what was identified ([`assigned`]); the stored device facts
//!    of the old box are dropped ([`forget_facts`]).
//! 7. [`Step::Flash`]: the application, through the flash path of the surface
//!    ([`crate::flash_flow`]); skipped when the replacement keeps its
//!    application (`--no-flash`).
//! 8. [`Step::Apply`]: the model's tables and parameters, through the apply
//!    path of the surface, with its read-back.
//! 9. [`Step::Record`]: `replaced = <RFC3339>` in the device file and the new
//!    hardware's serial number in its `bussard.lock` entry ([`record`]).
//!
//! No step here writes to the bus on its own account: the address write and
//! its read-back are [`crate::assign`]'s, the flash and the apply are the
//! surfaces' existing write paths.

use std::path::{Path, PathBuf};

use bussard_mgmt::apci::{PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::system_type;
use bussard_model::SerialRecord;
use bussard_model::identity::{IdentityCheck, LockIdentity, ReportedIdentity};
use bussard_model::schema::Device;
use bussard_model::{IndividualAddress, Model};

use crate::assign::Verified;
use crate::identity::clean_ascii;
use crate::{Authorize, BusService, L4Options, ServiceError, SourcePolicy};

/// Why a replace step failed.
#[derive(Debug, thiserror::Error)]
pub enum ReplaceError {
    /// The model refuses the replacement; the sentence says why.
    #[error("{0}")]
    Refused(String),
    /// The device file could not be read or written.
    #[error("{what} {path}")]
    Io {
        /// What was done ("reading", "writing").
        what: &'static str,
        /// The file.
        path: String,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// The serial number could not be recorded in the lock.
    #[error(transparent)]
    Serial(#[from] crate::RecordSerialsError),
}

/// One step of a replacement, in the order [`Replacement::next`] walks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing may answer at the address any more.
    CheckGone,
    /// The human presses the programming button on the replacement.
    PressButton,
    /// What the pressed device is.
    Identify,
    /// The pressed device against the model's device file and lock.
    CrossCheck,
    /// The one confirmation for the whole run.
    Confirm,
    /// The address, and its read-back.
    Assign,
    /// The application program.
    Flash,
    /// The model's tables and parameters.
    Apply,
    /// The record in the device file and the lock.
    Record,
    /// The replacement is complete.
    Done,
}

impl Step {
    /// The step as the surfaces name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Step::CheckGone => "check_gone",
            Step::PressButton => "press_button",
            Step::Identify => "identify",
            Step::CrossCheck => "cross_check",
            Step::Confirm => "confirm",
            Step::Assign => "assign",
            Step::Flash => "flash",
            Step::Apply => "apply",
            Step::Record => "record",
            Step::Done => "done",
        }
    }
}

/// What the model says belongs at the address being replaced.
#[derive(Debug, Clone, Default)]
pub struct Expected {
    /// `product.order_number` from the device file.
    pub order_number: Option<String>,
    /// `product.mask` from the device file, parsed as a hex mask version.
    pub mask: Option<u16>,
    /// The raw `product.mask` text, for the message when it does not parse.
    pub mask_text: Option<String>,
    /// The application id `bussard.lock` pins (lock v2, issue #228).
    pub application_id: Option<String>,
    /// `--no-flash`: the pressed device keeps its application, so it must
    /// already run the one the lock pins.
    pub hold_application: bool,
    /// The model's device at the address, for the identity verdict.
    pub device: Option<Device>,
}

impl Expected {
    /// Reads the cross-check values out of the model's device file.
    pub fn from_model(device: &Device) -> Expected {
        let product = device.product.as_ref();
        let mask_text = product.and_then(|p| p.mask.clone());
        Expected {
            order_number: product.and_then(|p| p.order_number.clone()),
            mask: mask_text
                .as_deref()
                .and_then(|m| u16::from_str_radix(m.trim_start_matches("0x"), 16).ok()),
            mask_text,
            application_id: LockIdentity::of(device).application_id,
            hold_application: false,
            device: Some(device.clone()),
        }
    }
}

/// What the device that answered the programming-mode broadcast reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pressed {
    /// The address it currently answers on.
    pub address: IndividualAddress,
    /// Its mask version.
    pub mask: Option<u16>,
    /// Its order number (`PID_ORDER_INFO`).
    pub order: Option<String>,
    /// Its resident application id (`PID_PROGRAM_VERSION`), rendered.
    pub application: Option<String>,
    /// The same id as ten hex digits, as `bussard.lock` spells it.
    pub application_id: Option<String>,
    /// Its serial number.
    pub serial: Option<Vec<u8>>,
}

impl Pressed {
    /// Nothing read yet, at `address`.
    pub fn unread(address: IndividualAddress) -> Pressed {
        Pressed {
            address,
            mask: None,
            order: None,
            application: None,
            application_id: None,
            serial: None,
        }
    }
}

/// One replacement: the address, what the model says belongs there, and the
/// device file the record goes into.
#[derive(Debug, Clone)]
pub struct Replacement {
    /// The address of the dead device.
    pub target: IndividualAddress,
    /// The device's name in the model.
    pub name: String,
    /// What the model says belongs at the address.
    pub expected: Expected,
    /// The device file, `devices/<stem>.toml` under the model directory.
    pub device_file: PathBuf,
}

impl Replacement {
    /// The replacement of `target` in `model` (loaded from `dir`).
    /// `hold_application` (`--no-flash`) keeps the replacement's application.
    ///
    /// # Errors
    ///
    /// The model has no device file for `target`: a replacement puts the
    /// same product back at a known address.
    pub fn from_model(
        model: &Model,
        dir: &Path,
        target: IndividualAddress,
        hold_application: bool,
    ) -> Result<Replacement, ReplaceError> {
        let Some(loaded) = model.devices.get(&target) else {
            return Err(ReplaceError::Refused(format!(
                "the model in {} has no device file for {target}; `replace` puts the *same* \
                 product back at a known address. Use `bussard adopt` for a device the model \
                 does not know.",
                dir.display()
            )));
        };
        let mut expected = Expected::from_model(&loaded.device);
        expected.hold_application = hold_application;
        Ok(Replacement {
            target,
            name: loaded.device.name.clone(),
            expected,
            device_file: dir
                .join("devices")
                .join(format!("{}.toml", loaded.file_stem)),
        })
    }

    /// Whether the replacement gets the application flashed.
    pub fn flashes(&self) -> bool {
        !self.expected.hold_application
    }

    /// The step after `step`: the steps in order, the flash left out when
    /// the replacement keeps its application.
    pub fn next(&self, step: Step) -> Step {
        match step {
            Step::CheckGone => Step::PressButton,
            Step::PressButton => Step::Identify,
            Step::Identify => Step::CrossCheck,
            Step::CrossCheck => Step::Confirm,
            Step::Confirm => Step::Assign,
            Step::Assign if self.flashes() => Step::Flash,
            Step::Assign | Step::Flash => Step::Apply,
            Step::Apply => Step::Record,
            Step::Record | Step::Done => Step::Done,
        }
    }

    /// Every step of this replacement, in order, [`Step::Done`] last.
    pub fn steps(&self) -> Vec<Step> {
        let mut steps = vec![Step::CheckGone];
        while let Some(&last) = steps.last()
            && last != Step::Done
        {
            steps.push(self.next(last));
        }
        steps
    }

    /// The identity verdict of the pressed device against the lock, when it
    /// reported a mask.
    pub fn identity_check(&self, pressed: &Pressed) -> Option<IdentityCheck> {
        let mask = pressed.mask?;
        Some(IdentityCheck::compare(
            self.expected.device.as_ref(),
            ReportedIdentity {
                mask: bussard_model::facts::format_mask(mask),
                application_id: pressed.application_id.clone(),
            },
        ))
    }

    /// The first cross-check failure between the model and what was
    /// pressed ([`mismatch`]).
    pub fn mismatch(&self, pressed: &Pressed) -> Option<String> {
        mismatch(&self.expected, pressed)
    }
}

/// Reads the identity of the device that answered the programming-mode
/// broadcast: mask, order number, serial and resident application id.
///
/// Every read is best-effort: a field that cannot be read is unknown, and an
/// unknown field never satisfies the cross-check by default.
pub async fn identify(
    service: &BusService,
    source: IndividualAddress,
    current: IndividualAddress,
) -> Pressed {
    let mut pressed = Pressed::unread(current);
    // Authorize comes after the descriptor read (below), so the session opens
    // without it.
    let options = L4Options {
        source: SourcePolicy::Known(source),
        authorize: Authorize::Skip,
        ..L4Options::default()
    };
    let _ = service
        .with_l4(current, &options, async |dev| {
            pressed.mask = bussard_mgmt::read_device_descriptor(dev).await.ok();
            if let Err(err) = dev
                .authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
                .await
            {
                tracing::debug!("{current} authorize (free access) did not grant: {err}");
            }
            pressed.order = dev
                .read_device_property(PID_ORDER_INFO)
                .await
                .ok()
                .map(|v| clean_ascii(&v))
                .filter(|s| !s.is_empty());
            pressed.serial = dev
                .read_device_property(PID_SERIAL_NUMBER)
                .await
                .ok()
                .filter(|v| !v.is_empty());
            if let Ok(obj) = bussard_download::discover_application_object(dev).await {
                let id = bussard_mgmt::read_program_version(dev, obj)
                    .await
                    .ok()
                    .flatten();
                pressed.application = id.as_deref().map(bussard_download::format_app_id);
                pressed.application_id = id
                    .as_deref()
                    .map(bussard_model::facts::format_application_id);
            }
            Ok::<_, ServiceError>(())
        })
        .await;
    pressed
}

/// The pressed device after the address write: the read-back at the new
/// address wins where it read a field, the identification fills the rest.
pub fn assigned(pressed: Pressed, verified: &Verified) -> Pressed {
    Pressed {
        address: pressed.address,
        mask: verified.mask.or(pressed.mask),
        order: verified.order.clone().or(pressed.order),
        application: pressed.application,
        application_id: pressed.application_id,
        serial: verified.serial.clone().or(pressed.serial),
    }
}

/// Whether the read-back at the new address is the device that was
/// identified: the same serial and mask wherever both reads have one.
pub fn same_hardware(pressed: &Pressed, verified: &Verified) -> bool {
    let serial = match (&verified.serial, &pressed.serial) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    let mask = match (verified.mask, pressed.mask) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    serial && mask
}

/// Drops the stored device facts of `target` (issue #209): they describe the
/// old box, so the flash and the apply read the replacement's.
pub fn forget_facts(dir: &Path, target: IndividualAddress) {
    let _ = std::fs::remove_file(bussard_model::facts::facts_path(dir, target));
}

/// The first cross-check failure between the model's device file and what was
/// pressed, or `None` when everything the model states matches.
///
/// A field the model does not state is not checked: a device file with no
/// `product:` block has nothing to contradict. A field the model states but the
/// device would not report **is** a failure: "could not read the order number"
/// is not evidence that it matches.
pub fn mismatch(expected: &Expected, pressed: &Pressed) -> Option<String> {
    if let Some(want) = &expected.order_number {
        match &pressed.order {
            Some(got) if order_matches(got, want) => {}
            Some(got) => {
                return Some(format!(
                    "the device reports order number {got:?}, but the model's device file says \
                     {want:?}"
                ));
            }
            None => {
                return Some(format!(
                    "the model's device file says order number {want:?}, but the device would \
                     not report one"
                ));
            }
        }
    }
    if let Some(want) = expected.mask {
        match pressed.mask {
            Some(got) if got == want => {}
            Some(got) => {
                return Some(format!(
                    "the device reports mask {got:04X} ({}), but the model's device file says \
                     {want:04X} ({})",
                    system_type(got),
                    system_type(want)
                ));
            }
            None => {
                return Some(format!(
                    "the model's device file says mask {want:04X}, but the device would not \
                     report one"
                ));
            }
        }
    } else if let Some(text) = &expected.mask_text {
        return Some(format!(
            "the model's device file has an unparseable mask {text:?}; fix it before replacing"
        ));
    }
    // With --no-flash the pressed device keeps its application, which must be
    // the one bussard.lock pins (issue #228, item 5).
    if expected.hold_application
        && let Some(want) = &expected.application_id
        && pressed
            .application_id
            .as_deref()
            .is_none_or(|got| !got.eq_ignore_ascii_case(want))
    {
        return Some(format!(
            "with --no-flash the device keeps its application ({}), but bussard.lock pins \
             application id {want}; drop --no-flash so the replacement is flashed (it runs \
             `bussard flash {}`)",
            pressed.application_id.as_deref().unwrap_or("none resident"),
            pressed.address
        ));
    }
    None
}

/// Whether a read-back order number matches the model's, tolerating case,
/// surrounding whitespace and the abbreviations vendors put in `PID_ORDER_INFO`
/// (the same rule `adopt` uses).
pub fn order_matches(read: &str, want: &str) -> bool {
    let a = read.trim().to_ascii_uppercase();
    let b = want.trim().to_ascii_uppercase();
    !a.is_empty() && !b.is_empty() && (a == b || a.contains(&b) || b.contains(&a))
}

/// What [`record`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The device file that carries `replaced`.
    pub device_file: PathBuf,
    /// The serial number's record in the lock, when the device reported one.
    pub serial: Option<SerialRecord>,
}

/// Records the replacement: `replaced = "<when>"` in the device file
/// ([`record_replacement`]) and the new hardware's serial number in its
/// `bussard.lock` entry (issue #752; the old box's serial goes).
///
/// # Errors
///
/// The device file could not be edited, or the lock could not be saved.
pub fn record(
    dir: &Path,
    replacement: &Replacement,
    serial: Option<&[u8]>,
    when: &str,
) -> Result<Recorded, ReplaceError> {
    let device_file = record_replacement(&replacement.device_file, when)?;
    let serial = match serial.and_then(|s| <[u8; 6]>::try_from(s).ok()) {
        Some(serial) => crate::record_serials(
            dir,
            &[(
                replacement.target,
                bussard_project::keystore::SerialNumber(serial),
            )],
        )?
        .into_iter()
        .next()
        .map(|(_, record)| record),
        None => None,
    };
    Ok(Recorded {
        device_file,
        serial,
    })
}

/// Records `replaced = "<when>"` in the device file, in place.
///
/// This is a targeted line edit rather than a re-serialisation of the model: a
/// device file is hand-edited, comments and all, and rewriting it wholesale to
/// add one key would be a destructive way to record a repair. An existing
/// `replaced` line is updated; otherwise the key is inserted after `address`,
/// where the rest of the device's identity lives.
///
/// # Errors
///
/// The file could not be read or written.
pub fn record_replacement(path: &Path, when: &str) -> Result<PathBuf, ReplaceError> {
    let body = std::fs::read_to_string(path).map_err(|source| ReplaceError::Io {
        what: "reading",
        path: path.display().to_string(),
        source,
    })?;
    let line = format!("replaced = \"{when}\"");
    // Only the top-level keys (before the first `[table]`) are the device's own.
    let is_key = |text: &str, key: &str| {
        text.strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    };
    let lines: Vec<&str> = body.lines().collect();
    let top_len = lines
        .iter()
        .position(|t| t.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
    if let Some(i) = lines[..top_len].iter().position(|t| is_key(t, "replaced")) {
        out[i] = line;
    } else if let Some(i) = lines[..top_len].iter().position(|t| is_key(t, "address")) {
        out.insert(i + 1, line);
    } else {
        // No top-level `address` (an unusual file): still record it at the top
        // level, before the first table.
        out.insert(top_len, line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    std::fs::write(path, text).map_err(|source| ReplaceError::Io {
        what: "writing",
        path: path.display().to_string(),
        source,
    })?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn pressed(order: Option<&str>, mask: Option<u16>) -> Pressed {
        Pressed {
            mask,
            order: order.map(|s| s.to_string()),
            ..Pressed::unread(IndividualAddress::from_raw(0xFFFF))
        }
    }

    fn expected(order: Option<&str>, mask: Option<&str>) -> Expected {
        Expected {
            order_number: order.map(|s| s.to_string()),
            mask: mask.and_then(|m| u16::from_str_radix(m, 16).ok()),
            mask_text: mask.map(|s| s.to_string()),
            ..Expected::default()
        }
    }

    fn replacement(hold_application: bool) -> Result<Replacement, Box<dyn std::error::Error>> {
        Ok(Replacement {
            target: "1.1.4".parse()?,
            name: "Rollladen".to_string(),
            expected: Expected {
                hold_application,
                ..Expected::default()
            },
            device_file: PathBuf::from("devices/1.1.4.toml"),
        })
    }

    #[test]
    fn test_replacement_steps_walk_the_flow_in_order() -> TestResult {
        assert_eq!(
            replacement(false)?.steps(),
            vec![
                Step::CheckGone,
                Step::PressButton,
                Step::Identify,
                Step::CrossCheck,
                Step::Confirm,
                Step::Assign,
                Step::Flash,
                Step::Apply,
                Step::Record,
                Step::Done,
            ]
        );
        let held = replacement(true)?;
        assert!(!held.steps().contains(&Step::Flash));
        assert_eq!(held.next(Step::Assign), Step::Apply);
        Ok(())
    }

    #[test]
    fn test_mismatch_no_flash_needs_the_pinned_application() {
        let mut want = expected(Some("MDT-JAL0410"), Some("07B0"));
        want.application_id = Some("0083004210".to_string());
        want.hold_application = true;
        let mut got = pressed(Some("MDT-JAL0410"), Some(0x07B0));
        got.application_id = Some("0083004211".to_string());
        let problem = mismatch(&want, &got).unwrap_or_default();
        assert!(
            problem.contains("--no-flash") && problem.contains("0083004210"),
            "{problem}"
        );
        got.application_id = Some("0083004210".to_string());
        assert_eq!(mismatch(&want, &got), None);
        // A flashing replacement is not held to the resident application.
        want.hold_application = false;
        got.application_id = Some("0083004211".to_string());
        assert_eq!(mismatch(&want, &got), None);
    }

    #[test]
    fn test_mismatch_accepts_the_same_product() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        assert_eq!(
            mismatch(&want, &pressed(Some("MDT-JAL0410"), Some(0x07B0))),
            None
        );
    }

    #[test]
    fn test_mismatch_refuses_a_different_order_number() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        let problem = mismatch(&want, &pressed(Some("MDT-AKS0416"), Some(0x07B0)));
        match problem {
            Some(text) => {
                assert!(
                    text.contains("MDT-AKS0416") && text.contains("MDT-JAL0410"),
                    "{text}"
                );
            }
            None => panic!("a different order number must be refused"),
        }
    }

    #[test]
    fn test_mismatch_refuses_a_different_mask() {
        let want = expected(Some("MDT-JAL0410"), Some("07B0"));
        let problem = mismatch(&want, &pressed(Some("MDT-JAL0410"), Some(0x0705)));
        assert!(problem.is_some(), "a different mask must be refused");
    }

    #[test]
    fn test_mismatch_refuses_an_unreadable_field_the_model_states() {
        let want = expected(Some("MDT-JAL0410"), None);
        assert!(
            mismatch(&want, &pressed(None, Some(0x07B0))).is_some(),
            "an unreadable order number is not evidence that it matches"
        );
    }

    #[test]
    fn test_mismatch_checks_nothing_the_model_does_not_state() {
        let want = expected(None, None);
        assert_eq!(mismatch(&want, &pressed(None, None)), None);
    }

    #[test]
    fn test_order_matches_is_tolerant_but_not_blind() {
        assert!(order_matches(" mdt-jal0410 ", "MDT-JAL0410"));
        assert!(order_matches("JAL0410", "MDT-JAL0410"));
        assert!(!order_matches("MDT-AKS0416", "MDT-JAL0410"));
        assert!(!order_matches("", "MDT-JAL0410"));
    }

    #[test]
    fn test_same_hardware_compares_serial_and_mask_where_both_read() {
        let mut then = pressed(None, Some(0x07B0));
        then.serial = Some(vec![0, 0xFA, 1, 2, 3, 4]);
        let now = Verified {
            mask: Some(0x07B0),
            serial: Some(vec![0, 0xFA, 1, 2, 3, 4]),
            ..Verified::default()
        };
        assert!(same_hardware(&then, &now));
        let other = Verified {
            serial: Some(vec![0, 0xFA, 9, 9, 9, 9]),
            ..now.clone()
        };
        assert!(!same_hardware(&then, &other));
        assert!(same_hardware(&then, &Verified::default()));
    }

    #[test]
    fn test_record_replacement_inserts_after_address() -> TestResult {
        let dir = std::env::temp_dir().join(format!("bussard-replace-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("1.1.4.toml");
        std::fs::write(
            &path,
            "address = \"1.1.4\"\nname = \"Rollladen\"\n# a comment\n\n[links]\n1.send = \"1/0/0\"\n",
        )?;
        record_replacement(&path, "2026-09-22T10:15:00Z")?;
        let body = std::fs::read_to_string(&path)?;
        assert_eq!(
            body,
            "address = \"1.1.4\"\nreplaced = \"2026-09-22T10:15:00Z\"\nname = \"Rollladen\"\n\
             # a comment\n\n[links]\n1.send = \"1/0/0\"\n"
        );
        // A second replacement updates the line rather than adding another.
        record_replacement(&path, "2026-10-01T08:00:00Z")?;
        let body = std::fs::read_to_string(&path)?;
        assert_eq!(body.matches("replaced =").count(), 1, "{body}");
        assert!(body.contains("2026-10-01T08:00:00Z"), "{body}");
        assert!(
            body.contains("# a comment"),
            "the rest of the file survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
