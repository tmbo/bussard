//! The commission flow (issues #100, #753): bench mode for a whole line, as
//! `bussard commission` runs it at the terminal and `knx_commission_line` in
//! chat.
//!
//! The commissioning-day ritual, once per device the model has on the line:
//! press the programming button, check that the device on the bench really is
//! the product the model expects at that address, write the address, read it
//! back, then stick a label on it. The order-number check is the point: a
//! bench full of identical-looking DIN modules is exactly where the wrong
//! device gets pressed, so the device's order info is read **before** anything
//! is written and a mismatch stops that device only.
//!
//! The steps, in the order a surface runs them:
//!
//! 1. [`LineRun::new`]: the model's devices on the line, in address order.
//! 2. [`probe_line`]: which model addresses already answer
//!    (NM_IndividualAddress_Write step 1, issue #530); [`occupied_status`]
//!    turns each answer into "already present" or a refusal.
//! 3. [`LineRun::advance`] walks the line; per device the surface waits for the
//!    programming button ([`crate::assign::wait_for_programming_mode`]), then
//! 4. [`identify_pressed`] reads what was pressed and checks its order number
//!    against the model ([`OrderCheck`]), writing nothing, and
//! 5. [`assign_pressed`] writes the address, reads the device back at it
//!    independently (with the explicit programming-mode clear ETS does) and
//!    returns the label text ([`label_line`]).
//!
//! Every bus step is a function of [`crate::assign`]; this module only orders
//! them and keeps the line's bookkeeping. Nothing here prints or asks: the CLI
//! keeps its prompts and lines, the MCP tool its questions and JSON (#314).

use std::path::Path;

use bussard_mgmt::manufacturers;
use bussard_model::{IndividualAddress, Model};
use bussard_prod::normalize_order_number;

use crate::assign::{
    AssignError, Occupant, Verified, VerifyError, VerifyKey, identify, probe_occupant,
    still_in_programming_mode, verify_assignment_with, write_address,
};
use crate::{BusService, ServiceError};

/// Why a commission step failed.
#[derive(Debug, thiserror::Error)]
pub enum CommissionError {
    /// The device in programming mode did not answer the identification.
    #[error("connecting to the device in programming mode at {current}")]
    Identify {
        /// Where it answered the programming-mode broadcast.
        current: IndividualAddress,
        /// The cause.
        #[source]
        source: ServiceError,
    },
    /// The address broadcast failed.
    #[error("broadcasting the new individual address")]
    Write(#[source] AssignError),
    /// The read-back at the new address failed or does not match the device
    /// that was identified.
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// One device the model expects on the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Its address in the model.
    pub address: IndividualAddress,
    /// Its name in the model.
    pub name: String,
    /// The order number of its product block, if any.
    pub order_number: Option<String>,
    /// The manufacturer of its product block, if any.
    pub manufacturer: Option<String>,
    /// Its floor, if the model has one.
    pub floor: Option<String>,
    /// Its room, if the model has one.
    pub room: Option<String>,
}

/// The model's devices on `area.line`, in address order.
pub fn targets_on_line(model: &Model, area: u8, line_no: u8) -> Vec<Target> {
    model
        .devices
        .iter()
        .filter(|(ia, _)| ia.area() == area && ia.line() == line_no)
        .map(|(ia, loaded)| {
            let device = &loaded.device;
            let product = device.product.as_ref();
            Target {
                address: *ia,
                name: device.name.clone(),
                order_number: product.and_then(|p| p.order_number.clone()),
                manufacturer: product.and_then(|p| p.manufacturer.clone()),
                floor: device.location.as_ref().and_then(|l| l.floor.clone()),
                room: device.location.as_ref().and_then(|l| l.room.clone()),
            }
        })
        .collect()
}

/// What happened to one device in a commissioning run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// The address was written, verified, and everything asked for was done.
    Commissioned,
    /// The device already answered at its model address, so nothing was pressed.
    AlreadyPresent,
    /// The ceremony stopped for this device, for the stated reason.
    Failed(String),
}

impl Status {
    /// The machine-readable status key (`commissioned`, `present`, `failed`).
    pub fn key(&self) -> &'static str {
        match self {
            Status::Commissioned => "commissioned",
            Status::AlreadyPresent => "present",
            Status::Failed(_) => "failed",
        }
    }

    /// The human cell for a summary table.
    pub fn label(&self) -> String {
        match self {
            Status::Commissioned => "commissioned".to_string(),
            Status::AlreadyPresent => "present (already assigned)".to_string(),
            Status::Failed(detail) => format!("failed: {detail}"),
        }
    }

    /// The reason text for a failure.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Status::Failed(d) => Some(d),
            _ => None,
        }
    }
}

/// One device's row in the run's summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The model address.
    pub address: IndividualAddress,
    /// The model name.
    pub name: String,
    /// The model order number.
    pub order_number: Option<String>,
    /// What happened.
    pub status: Status,
    /// The label line, when the device was commissioned.
    pub label: Option<String>,
}

impl Outcome {
    /// The outcome `status` for `target`, without a label.
    pub fn of(target: &Target, status: Status) -> Outcome {
        Outcome {
            address: target.address,
            name: target.name.clone(),
            order_number: target.order_number.clone(),
            status,
            label: None,
        }
    }

    /// `target` failed for `detail`.
    pub fn failed(target: &Target, detail: String) -> Outcome {
        Outcome::of(target, Status::Failed(detail))
    }

    /// `target` was commissioned; `label` is what goes on it.
    pub fn commissioned(target: &Target, label: String) -> Outcome {
        Outcome {
            label: Some(label),
            ..Outcome::of(target, Status::Commissioned)
        }
    }
}

/// How many devices of a run ended in which state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Commissioned in this run.
    pub commissioned: usize,
    /// Already at their address.
    pub present: usize,
    /// Failed or skipped.
    pub failed: usize,
}

/// What [`LineRun::advance`] hands the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// A device the pre-pass settled ([`probe_line`]): recorded already,
    /// nothing to press.
    Settled(Outcome),
    /// The next device to press, its 1-based position and the line's total.
    Device {
        /// Its 1-based position on the line.
        position: usize,
        /// How many devices the line has.
        total: usize,
        /// The device.
        target: Target,
    },
}

/// The bookkeeping of one commissioning run over a line: the targets, the
/// pre-pass verdicts, the cursor and the outcomes so far. No I/O.
#[derive(Debug, Clone)]
pub struct LineRun {
    /// The line, `area.line`.
    line: String,
    /// The model's devices on it.
    targets: Vec<Target>,
    /// The pre-pass verdicts for the addresses that already answer.
    verdicts: Vec<(IndividualAddress, Status)>,
    /// Where the walk is.
    cursor: usize,
    /// What happened so far, in the order it happened.
    outcomes: Vec<Outcome>,
}

impl LineRun {
    /// A run over the model's devices on `area.line_no`.
    pub fn new(model: &Model, area: u8, line_no: u8) -> LineRun {
        LineRun {
            line: format!("{area}.{line_no}"),
            targets: targets_on_line(model, area, line_no),
            verdicts: Vec::new(),
            cursor: 0,
            outcomes: Vec::new(),
        }
    }

    /// The line, `area.line`.
    pub fn line(&self) -> &str {
        &self.line
    }

    /// The model's devices on the line.
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// Records the pre-pass verdicts ([`probe_line`]).
    pub fn set_verdicts(&mut self, verdicts: Vec<(IndividualAddress, Status)>) {
        self.verdicts = verdicts;
    }

    /// How many devices need the button (no pre-pass verdict).
    pub fn pending(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| !self.verdicts.iter().any(|(a, _)| *a == t.address))
            .count()
    }

    /// The next device: a settled one (recorded here) or one to press.
    /// `None` when the line is walked.
    pub fn advance(&mut self) -> Option<Next> {
        let target = self.targets.get(self.cursor)?.clone();
        self.cursor += 1;
        if let Some((_, status)) = self.verdicts.iter().find(|(a, _)| *a == target.address) {
            let outcome = Outcome::of(&target, status.clone());
            self.outcomes.push(outcome.clone());
            return Some(Next::Settled(outcome));
        }
        Some(Next::Device {
            position: self.cursor,
            total: self.targets.len(),
            target,
        })
    }

    /// Records what happened to the device [`LineRun::advance`] handed out.
    pub fn record(&mut self, outcome: Outcome) {
        self.outcomes.push(outcome);
    }

    /// What happened so far.
    pub fn outcomes(&self) -> &[Outcome] {
        &self.outcomes
    }

    /// The devices the walk has not reached yet.
    pub fn remaining(&self) -> &[Target] {
        self.targets.get(self.cursor..).unwrap_or_default()
    }

    /// The counts of the outcomes so far.
    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        for o in &self.outcomes {
            match o.status {
                Status::Commissioned => totals.commissioned += 1,
                Status::AlreadyPresent => totals.present += 1,
                Status::Failed(_) => totals.failed += 1,
            }
        }
        totals
    }
}

/// The read-only pre-pass: which of `targets`' addresses already answer, and
/// what that means for each ([`occupied_status`]). `on_probe` hears each
/// address before it is probed.
pub async fn probe_line(
    service: &BusService,
    source: IndividualAddress,
    targets: &[Target],
    on_probe: &mut (dyn FnMut(IndividualAddress) + Send),
) -> Vec<(IndividualAddress, Status)> {
    let mut verdicts = Vec::new();
    for target in targets {
        on_probe(target.address);
        if let Some(occupant) = probe_occupant(service, source, target.address).await {
            verdicts.push((target.address, occupied_status(target, &occupant)));
        }
    }
    verdicts
}

/// What an answer at a model address means for that device (issue #530):
/// the modelled device is already there when the order number it reports
/// matches the model's; otherwise another device holds the address, or it
/// cannot be told which, and the device is refused before anything is
/// pressed or written.
pub fn occupied_status(target: &Target, occupant: &Occupant) -> Status {
    match (target.order_number.as_deref(), occupant.order.as_deref()) {
        (Some(expected), Some(read))
            if normalize_order_number(read) == normalize_order_number(expected) =>
        {
            Status::AlreadyPresent
        }
        (Some(expected), Some(read)) => Status::Failed(format!(
            "the address is in use by another device ({}), not the modelled {expected:?} \
             (it reports {read:?}); nothing was written. Re-address or remove that device, \
             then re-run",
            occupant.describe()
        )),
        (Some(expected), None) => Status::Failed(format!(
            "the address is in use ({}) and the device there did not report an order number, \
             so it cannot be told from the modelled {expected:?}; nothing was written",
            occupant.describe()
        )),
        (None, _) => Status::Failed(format!(
            "the address is in use ({}) and the model has no order number to tell whether \
             that is the modelled device; nothing was written",
            occupant.describe()
        )),
    }
}

/// The verdict of the order-number check on the pressed device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderCheck {
    /// The order numbers match (normalised as the product index does).
    Matches,
    /// The model has no order number for the device: nothing to check
    /// against ([`unchecked_warning`] says so).
    NoModelNumber,
    /// The pressed device is not the one the model expects, or it did not
    /// report an order number to check; the sentence names both sides and
    /// says nothing was written.
    Refused(String),
}

/// The hard stop: the pressed device must be the product the model expects.
///
/// Three cases. The order numbers match (normalised the way the product index
/// normalises them): proceed. They differ: refuse, naming both, and nothing is
/// written. The model has no order number: proceed with a warning, because
/// there is nothing to check against; a device that cannot be *read* while the
/// model does expect a number is a refusal, since the check was asked for and
/// could not be made.
pub fn check_order_number(target: &Target, identified: &Verified) -> OrderCheck {
    let Some(expected) = target.order_number.as_deref() else {
        return OrderCheck::NoModelNumber;
    };
    let Some(read) = identified.order.as_deref() else {
        return OrderCheck::Refused(format!(
            "the device in programming mode did not answer an order-number read, so it cannot be \
             verified against the model's {expected:?} for {}; nothing was written. Read it with \
             `bussard scan`, or clear the model's order number if this device cannot report one",
            target.address
        ));
    };
    if normalize_order_number(read) == normalize_order_number(expected) {
        return OrderCheck::Matches;
    }
    OrderCheck::Refused(format!(
        "the device in programming mode reports order number {read:?}, but the model expects \
         {expected:?} for {} ({}); nothing was written. Leave programming mode on this device and \
         press the right one, then re-run",
        target.address, target.name
    ))
}

/// The warning for a device the model has no order number for.
pub fn unchecked_warning(target: &Target) -> String {
    format!(
        "warning: the model has no order number for {}, so the pressed device was not \
         verified against it",
        target.address
    )
}

/// The pressed device, identified at its current address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {
    /// Where it answered the programming-mode broadcast.
    pub current: IndividualAddress,
    /// What it reported (mask, manufacturer, serial, order number).
    pub verified: Verified,
    /// The order-number check against the model.
    pub check: OrderCheck,
}

/// Reads what the device in programming mode at `current` is
/// ([`crate::assign::identify`], in the clear) and checks it against
/// `target`. Read-only: nothing is written whatever the check says.
///
/// # Errors
///
/// The device did not answer the identification.
pub async fn identify_pressed(
    service: &BusService,
    source: IndividualAddress,
    target: &Target,
    current: IndividualAddress,
) -> Result<Identified, CommissionError> {
    let verified = identify(service, source, current, None)
        .await
        .map_err(|source| CommissionError::Identify { current, source })?;
    let check = check_order_number(target, &verified);
    Ok(Identified {
        current,
        verified,
        check,
    })
}

/// The device after its address was written and read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// What it reported: the read-back, completed by the identification
    /// where the read-back left a field empty.
    pub identity: Verified,
    /// Whether the explicit `PID_PROGMODE = 0` clear was confirmed.
    pub programming_mode_cleared: bool,
    /// Whether it still answers the programming-mode broadcast.
    pub still_in_programming_mode: bool,
    /// Warnings the read-back raised.
    pub warnings: Vec<String>,
    /// The label line ([`label_line`]).
    pub label: String,
}

/// Writes `target`'s address to the identified device, reads it back at the
/// new address (clearing programming mode as ETS does) and checks that the
/// device answering there is the one identified (serial and mask), then
/// re-checks the programming-mode broadcast. Call it only for an
/// [`OrderCheck::Matches`] or an accepted [`OrderCheck::NoModelNumber`].
///
/// # Errors
///
/// The broadcast failed, the device did not answer at the new address, or
/// the read-back names another device than the one identified.
pub async fn assign_pressed(
    service: &BusService,
    source: IndividualAddress,
    target: &Target,
    identified: &Identified,
) -> Result<Assigned, CommissionError> {
    write_address(service, source, target.address)
        .await
        .map_err(CommissionError::Write)?;
    let readback =
        verify_assignment_with(service, source, target.address, true, &VerifyKey::default())
            .await?;
    let before = &identified.verified;
    let serial_matches = match (&readback.serial, &before.serial) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    let mask_matches = match (readback.mask, before.mask) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    if !(serial_matches && mask_matches) {
        return Err(VerifyError::Unverified(format!(
            "wrote {} but the device answering there is not the one identified at {} (the \
             read-back reports another serial number or mask); the assignment is unverified",
            target.address, identified.current
        ))
        .into());
    }
    let still = still_in_programming_mode(service, source, target.address).await;
    let identity = Verified {
        mask: readback.mask.or(before.mask),
        manufacturer_id: readback.manufacturer_id.or(before.manufacturer_id),
        serial: readback.serial.clone().or_else(|| before.serial.clone()),
        order: readback.order.clone().or_else(|| before.order.clone()),
        ..readback.clone()
    };
    let label = label_line(target, &identity);
    Ok(Assigned {
        programming_mode_cleared: readback.programming_mode_cleared,
        still_in_programming_mode: still,
        warnings: readback.warnings.clone(),
        identity,
        label,
    })
}

/// Drops the device facts stored for `address`: a new box now answers there,
/// and facts stored for it describe whatever was there before (issue #228,
/// item 5). Best-effort.
pub fn forget_facts(dir: &Path, address: IndividualAddress) {
    let _ = std::fs::remove_file(bussard_model::facts::facts_path(dir, address));
}

/// Builds the label line stuck on the device, e.g.
/// `1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room`.
pub fn label_line(target: &Target, identity: &Verified) -> String {
    let manufacturer = target
        .manufacturer
        .clone()
        .or_else(|| identity.manufacturer_id.map(manufacturers::display));
    let order = target
        .order_number
        .clone()
        .or_else(|| identity.order.clone());
    let product = [manufacturer, order]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let location = [target.floor.clone(), target.room.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" / ");
    [
        target.address.to_string(),
        target.name.clone(),
        product,
        location,
    ]
    .into_iter()
    .filter(|f| !f.is_empty())
    .collect::<Vec<_>>()
    .join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn target() -> Result<Target, Box<dyn std::error::Error>> {
        Ok(Target {
            address: "1.1.7".parse()?,
            name: "Blind actuator".to_string(),
            order_number: Some("JAL-0810.03".to_string()),
            manufacturer: Some("MDT".to_string()),
            floor: Some("Ground floor".to_string()),
            room: Some("Living room".to_string()),
        })
    }

    fn identity(order: Option<&str>) -> Verified {
        Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: order.map(str::to_string),
            ..Verified::default()
        }
    }

    #[test]
    fn test_label_line_matches_the_documented_shape() -> TestResult {
        assert_eq!(
            label_line(&target()?, &identity(Some("JAL-0810.03"))),
            "1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room"
        );
        Ok(())
    }

    #[test]
    fn test_label_line_drops_absent_fields() -> TestResult {
        let mut t = target()?;
        t.manufacturer = None;
        t.floor = None;
        t.room = None;
        // The manufacturer falls back to the id read from the device (0x0083 = MDT).
        assert_eq!(
            label_line(&t, &identity(Some("JAL-0810.03"))),
            "1.1.7  Blind actuator  MDT JAL-0810.03"
        );
        Ok(())
    }

    #[test]
    fn test_check_order_number_accepts_a_match() -> TestResult {
        // Case and surrounding space are normalised, as the product index does.
        assert_eq!(
            check_order_number(&target()?, &identity(Some("  jal-0810.03 "))),
            OrderCheck::Matches
        );
        Ok(())
    }

    #[test]
    fn test_check_order_number_refuses_a_mismatch() -> TestResult {
        let OrderCheck::Refused(msg) =
            check_order_number(&target()?, &identity(Some("AKK-0216.03")))
        else {
            return Err("a mismatch must be refused".into());
        };
        assert!(msg.contains("AKK-0216.03"), "names what was read: {msg}");
        assert!(
            msg.contains("JAL-0810.03"),
            "names what was expected: {msg}"
        );
        assert!(msg.contains("nothing was written"), "{msg}");
        Ok(())
    }

    #[test]
    fn test_check_order_number_refuses_an_unreadable_one() -> TestResult {
        let OrderCheck::Refused(msg) = check_order_number(&target()?, &identity(None)) else {
            return Err("an unverifiable device must be refused".into());
        };
        assert!(msg.contains("did not answer an order-number read"), "{msg}");
        Ok(())
    }

    #[test]
    fn test_check_order_number_without_a_model_number() -> TestResult {
        let mut t = target()?;
        t.order_number = None;
        assert_eq!(
            check_order_number(&t, &identity(None)),
            OrderCheck::NoModelNumber
        );
        Ok(())
    }

    fn occupant(order: Option<&str>) -> Occupant {
        Occupant {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: order.map(str::to_string),
        }
    }

    #[test]
    fn test_occupied_status_the_modelled_device_is_present() -> TestResult {
        // Issue #530: the order number the occupant reports is the model's.
        let status = occupied_status(&target()?, &occupant(Some("jal-0810.03")));
        assert_eq!(status, Status::AlreadyPresent);
        Ok(())
    }

    #[test]
    fn test_occupied_status_refuses_another_device() -> TestResult {
        let status = occupied_status(&target()?, &occupant(Some("AKK-0216.03")));
        let detail = status.detail().unwrap_or_default();
        assert!(detail.contains("in use by another device"), "{detail}");
        assert!(detail.contains("mask 07B0"), "{detail}");
        Ok(())
    }

    #[test]
    fn test_occupied_status_refuses_an_unidentified_occupant() -> TestResult {
        let status = occupied_status(&target()?, &occupant(None));
        assert!(matches!(status, Status::Failed(_)), "{status:?}");
        Ok(())
    }

    #[test]
    fn test_line_run_next_settles_verdicts_and_hands_out_the_rest() -> TestResult {
        let first = target()?;
        let mut second = target()?;
        second.address = "1.1.8".parse()?;
        let mut run = LineRun {
            line: "1.1".to_string(),
            targets: vec![first.clone(), second.clone()],
            verdicts: Vec::new(),
            cursor: 0,
            outcomes: Vec::new(),
        };
        run.set_verdicts(vec![(first.address, Status::AlreadyPresent)]);
        assert_eq!(run.pending(), 1);
        assert!(
            matches!(run.advance(), Some(Next::Settled(o)) if o.status == Status::AlreadyPresent)
        );
        let Some(Next::Device {
            position, total, ..
        }) = run.advance()
        else {
            return Err("the second device must be handed out".into());
        };
        assert_eq!((position, total), (2, 2));
        assert!(run.remaining().is_empty());
        run.record(Outcome::commissioned(&second, "label".to_string()));
        assert_eq!(run.advance(), None);
        assert_eq!(
            run.totals(),
            Totals {
                commissioned: 1,
                present: 1,
                failed: 0
            }
        );
        Ok(())
    }
}
