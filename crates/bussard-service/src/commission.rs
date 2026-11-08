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

use std::collections::BTreeMap;
use std::path::Path;

use bussard_mgmt::manufacturers;
use bussard_model::{IndividualAddress, Model};
use bussard_product::normalize_order_number;

use crate::BusService;
use crate::assign::{Occupant, Verified, VerifyKey, identify, probe_occupant};
use crate::line::{WalkEvent, model_devices_on_line, walk};
use crate::program::assign::{Assign, AssignFlow, Assigned, Stop, completed};
use crate::program::{Event, Observer, Step};

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
    model_devices_on_line(model, area, line_no)
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
    verdicts: BTreeMap<IndividualAddress, Status>,
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
            verdicts: BTreeMap::new(),
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
    pub fn set_verdicts(&mut self, verdicts: BTreeMap<IndividualAddress, Status>) {
        self.verdicts = verdicts;
    }

    /// How many devices need the button (no pre-pass verdict).
    pub fn pending(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| !self.verdicts.contains_key(&t.address))
            .count()
    }

    /// The next device: a settled one (recorded here) or one to press.
    /// `None` when the line is walked.
    pub fn advance(&mut self) -> Option<Next> {
        let target = self.targets.get(self.cursor)?.clone();
        self.cursor += 1;
        if let Some(status) = self.verdicts.get(&target.address) {
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
/// probe start and end ([`walk`]).
pub async fn probe_line(
    service: &BusService,
    source: IndividualAddress,
    targets: &[Target],
    on_probe: &mut (dyn FnMut(WalkEvent<'_, Option<Status>>) + Send),
) -> BTreeMap<IndividualAddress, Status> {
    let addresses: Vec<IndividualAddress> = targets.iter().map(|t| t.address).collect();
    walk(
        &addresses,
        Option::is_some,
        |address| async move {
            let target = targets.iter().find(|t| t.address == address)?;
            let occupant = probe_occupant(service, source, address).await?;
            Some(occupied_status(target, &occupant))
        },
        on_probe,
    )
    .await
    .into_iter()
    .filter_map(|step| Some((step.address, step.outcome?)))
    .collect()
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
            "the address is in use by another device ({}), not the {expected:?} in your project \
             (it reports {read:?}); nothing was written. Re-address or remove that device, \
             then re-run",
            occupant.describe()
        )),
        (Some(expected), None) => Status::Failed(format!(
            "the address is in use ({}) and the device there did not report an order number, \
             so it cannot be told from the {expected:?} in your project; nothing was written",
            occupant.describe()
        )),
        (None, _) => Status::Failed(format!(
            "the address is in use ({}) and your project has no order number to tell whether \
             that is the device in your project; nothing was written",
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
             verified against your project's {expected:?} for {}; nothing was written. Read it with \
             `bussard scan`, or clear your project's order number if this device cannot report one",
            target.address
        ));
    };
    if normalize_order_number(read) == normalize_order_number(expected) {
        return OrderCheck::Matches;
    }
    OrderCheck::Refused(format!(
        "the device in programming mode reports order number {read:?}, but your project expects \
         {expected:?} for {} ({}); nothing was written. Leave programming mode on this device and \
         press the right one, then re-run",
        target.address, target.name
    ))
}

/// The warning for a device the model has no order number for.
pub fn unchecked_warning(target: &Target) -> String {
    format!(
        "warning: your project has no order number for {}, so the pressed device was not \
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
/// [`Stop::Identify`]: the device did not answer the identification.
pub async fn identify_pressed<O: Observer>(
    flow: &AssignFlow<'_>,
    target: &Target,
    current: IndividualAddress,
    observer: &mut O,
) -> Result<Identified, Stop> {
    observer.event(Event::Step(Step::Identify { at: current }));
    let verified = identify(flow.service, flow.source, current, None)
        .await
        .map_err(|source| Stop::Identify { current, source })?;
    let check = check_order_number(target, &verified);
    Ok(Identified {
        current,
        verified,
        check,
    })
}

/// The device after its address was written and read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labelled {
    /// The address write and its read-back.
    pub assigned: Assigned,
    /// What it reported: the read-back, completed by the identification
    /// where the read-back left a field empty.
    pub identity: Verified,
    /// The label line ([`label_line`]).
    pub label: String,
}

/// Writes `target`'s address to the identified device, reads it back at the
/// new address (clearing programming mode as ETS does) and checks that the
/// device answering there is the one identified (serial and mask), then
/// re-checks the programming-mode broadcast ([`AssignFlow::assign`]); the
/// facts stored for the address in `dir` are dropped. Call
/// it only for an [`OrderCheck::Matches`] or an accepted
/// [`OrderCheck::NoModelNumber`].
///
/// # Errors
///
/// The broadcast failed, the device did not answer at the new address, or
/// the read-back names another device than the one identified.
pub async fn assign_pressed<O: Observer>(
    flow: &AssignFlow<'_>,
    dir: &Path,
    target: &Target,
    identified: &Identified,
    observer: &mut O,
) -> Result<Labelled, Stop> {
    let request = Assign {
        current: identified.current,
        target: target.address,
        question: None,
        key: &VerifyKey::default(),
        clear_programming_mode: true,
        identified: Some(&identified.verified),
        refuse_hidden: false,
        require_identified: true,
        forget_facts: Some(dir),
    };
    let assigned = flow
        .assign(&request, observer)
        .await
        .map_err(|stop| match stop {
            Stop::OtherDevice { .. } => Stop::Verify(crate::ServiceError::Refused(format!(
                "wrote {} but the device answering there is not the one identified at {} (the \
                 read-back reports another serial number or mask); the assignment is unverified",
                target.address, identified.current
            ))),
            other => other,
        })?;
    let identity = completed(&assigned.verified, &identified.verified);
    let label = label_line(target, &identity);
    Ok(Labelled {
        assigned,
        identity,
        label,
    })
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

/// A model device as a commissioning result lists it (issue #904).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommissionTarget {
    /// Its address in the project.
    pub address: String,
    /// Its name.
    pub name: String,
    /// Its floor.
    pub floor: Option<String>,
    /// Its room.
    pub room: Option<String>,
    /// The order number its product block names.
    pub order_number: Option<String>,
}

impl CommissionTarget {
    /// `target` as the results list it.
    pub fn of(target: &Target) -> CommissionTarget {
        CommissionTarget {
            address: target.address.to_string(),
            name: target.name.clone(),
            floor: target.floor.clone(),
            room: target.room.clone(),
            order_number: target.order_number.clone(),
        }
    }
}

/// What the identification of a pressed device read.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentifiedDevice {
    /// Where it answered the programming-mode broadcast.
    pub current_address: String,
    /// Its serial, hex.
    pub serial: Option<String>,
    /// Its mask, hex.
    pub mask: Option<String>,
    /// Its manufacturer.
    pub manufacturer: Option<String>,
    /// Its order number.
    pub order_number: Option<String>,
    /// `matches`, `no_model_number` or `refused`.
    pub order_check: String,
}

impl IdentifiedDevice {
    /// What `i` read.
    pub fn of(i: &Identified) -> IdentifiedDevice {
        let v = &i.verified;
        IdentifiedDevice {
            current_address: i.current.to_string(),
            serial: v.serial.as_deref().map(crate::assign::hex),
            mask: v.mask.map(|m| format!("{m:04X}")),
            manufacturer: v.manufacturer_id.map(manufacturers::display),
            order_number: v.order.clone(),
            order_check: match i.check {
                OrderCheck::Matches => "matches",
                OrderCheck::NoModelNumber => "no_model_number",
                OrderCheck::Refused(_) => "refused",
            }
            .to_string(),
        }
    }
}

/// The read-back of a commissioned device at its address.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CommissionReadback {
    /// Whether it read back as the identified device.
    pub verified: bool,
    /// Its mask, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    /// Its serial, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Its order number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// Whether it confirmed leaving programming mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programming_mode_cleared: Option<bool>,
    /// What the human should know.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// One device of a commissioning run: the model device, what happened and
/// its label.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommissionDevice {
    /// The model device.
    #[serde(flatten)]
    pub target: CommissionTarget,
    /// `commissioned`, `present` or `failed`.
    pub status: String,
    /// Why it failed.
    pub detail: Option<String>,
    /// The label line.
    pub label: Option<String>,
    /// What the identification read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identified: Option<IdentifiedDevice>,
    /// `assigned` once its address was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// Where it answered before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The read-back at its address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback: Option<CommissionReadback>,
}

impl CommissionReadback {
    /// The read-back of `labelled`, the device identified as `identified`.
    pub fn of(labelled: &Labelled, identified: &Identified, target: &Target) -> CommissionReadback {
        let mut notes = crate::program::assign::assigned_notes(&labelled.assigned);
        if matches!(identified.check, OrderCheck::NoModelNumber) {
            notes.push(format!(
                "Assigned on the human's word: your project has no order number for {}.",
                target.name
            ));
        }
        let v = &labelled.identity;
        CommissionReadback {
            verified: true,
            mask: v.mask.map(|m| format!("{m:04X}")),
            serial: v.serial.as_deref().map(crate::assign::hex),
            order_number: v.order.clone(),
            programming_mode_cleared: Some(v.programming_mode_cleared),
            notes,
        }
    }
}

impl CommissionDevice {
    /// The row of a device whose address was written (or failed to be,
    /// with a default `readback`) after it was identified at `identified`.
    pub fn assigned(
        target: &Target,
        outcome: &Outcome,
        identified: &Identified,
        readback: CommissionReadback,
    ) -> CommissionDevice {
        CommissionDevice {
            identified: Some(IdentifiedDevice::of(identified)),
            step: Some("assigned".to_string()),
            from: Some(identified.current.to_string()),
            readback: Some(readback),
            ..CommissionDevice::of(target, outcome)
        }
    }

    /// The row of `outcome` for `target`.
    pub fn of(target: &Target, outcome: &Outcome) -> CommissionDevice {
        CommissionDevice {
            target: CommissionTarget::of(target),
            status: outcome.status.key().to_string(),
            detail: outcome.status.detail().map(str::to_string),
            label: outcome.label.clone(),
            identified: None,
            step: None,
            from: None,
            readback: None,
        }
    }
}

/// A commissioning run (`bussard commission --json`, the result of a
/// `knx_commission_line` job) in one shape (issue #904).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommissionReport {
    /// Every device of the line is at its address and nothing stopped the
    /// run.
    pub ok: bool,
    /// Always `done`.
    pub step: String,
    /// The line.
    pub line: String,
    /// The resolved gateway.
    pub gateway: String,
    /// The human stopped the run.
    pub stopped: bool,
    /// Why the run did not go on.
    pub reason: Option<String>,
    /// One row per device the run reached.
    pub devices: Vec<CommissionDevice>,
    /// The label lines, one per commissioned device.
    pub labels: Vec<String>,
    /// The model's devices on the line.
    pub total: usize,
    /// Commissioned in this run.
    pub commissioned: usize,
    /// Already at their address.
    pub present: usize,
    /// Failed or skipped.
    pub failed: usize,
    /// The devices the run did not reach.
    pub not_reached: Vec<CommissionTarget>,
    /// The labels CSV written, when one was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_file: Option<String>,
    /// The names, for the summary.
    #[serde(skip)]
    names: Names,
}

/// The device names of a run by outcome, for the summary.
#[derive(Debug, Clone, Default)]
struct Names {
    /// Commissioned.
    commissioned: Vec<String>,
    /// Already present.
    present: Vec<String>,
    /// Failed.
    failed: Vec<String>,
}

impl CommissionReport {
    /// The report of `run` through `gateway` with the per-device rows
    /// `devices`; `current` is a device the run was on when it ended.
    pub fn new(
        run: &LineRun,
        gateway: &str,
        devices: Vec<CommissionDevice>,
        current: Option<&Target>,
        stopped: bool,
        reason: Option<String>,
    ) -> CommissionReport {
        let totals = run.totals();
        let mut not_reached: Vec<&Target> = current.into_iter().collect();
        not_reached.extend(run.remaining());
        let names = |status: fn(&Status) -> bool| -> Vec<String> {
            run.outcomes()
                .iter()
                .filter(|o| status(&o.status))
                .map(|o| o.name.clone())
                .collect()
        };
        let ok = reason.is_none() && !stopped && totals.failed == 0 && not_reached.is_empty();
        CommissionReport {
            ok,
            step: "done".to_string(),
            line: run.line().to_string(),
            gateway: gateway.to_string(),
            stopped,
            reason,
            devices,
            labels: run
                .outcomes()
                .iter()
                .filter_map(|o| o.label.clone())
                .collect(),
            total: run.targets().len(),
            commissioned: totals.commissioned,
            present: totals.present,
            failed: totals.failed,
            not_reached: not_reached.into_iter().map(CommissionTarget::of).collect(),
            labels_file: None,
            names: Names {
                commissioned: names(|s| matches!(s, Status::Commissioned)),
                present: names(|s| matches!(s, Status::AlreadyPresent)),
                failed: names(|s| matches!(s, Status::Failed(_))),
            },
        }
    }
}

impl crate::report::Report for CommissionReport {
    const SCHEMA: u32 = 2;

    fn summary(&self, _model: &Model) -> Option<String> {
        let mut summary = format!("Line {}: ", self.line);
        summary.push_str(&if self.names.commissioned.is_empty() {
            "no device was commissioned".to_string()
        } else {
            format!("commissioned {}", self.names.commissioned.join(", "))
        });
        if !self.names.present.is_empty() {
            summary.push_str(&format!(
                "; already at their address: {}",
                self.names.present.join(", ")
            ));
        }
        if !self.names.failed.is_empty() {
            summary.push_str(&format!(
                "; not commissioned: {}",
                self.names.failed.join(", ")
            ));
        }
        if !self.not_reached.is_empty() {
            let left: Vec<&str> = self.not_reached.iter().map(|t| t.name.as_str()).collect();
            summary.push_str(&format!(
                "; {} before: {}",
                if self.stopped {
                    "stopped"
                } else {
                    "the run ended"
                },
                left.join(", ")
            ));
        } else if self.stopped {
            summary.push_str("; stopped");
        }
        summary.push('.');
        if let Some(reason) = &self.reason {
            summary.push_str(&format!(" The run did not go on: {reason}."));
        }
        Some(summary)
    }

    fn next_step(&self) -> Option<String> {
        Some(if self.commissioned > 0 {
            "Tell the human the summary and read out `labels`, one per device to stick on it. \
             Only addresses were written: push each commissioned device's links and parameters \
             with knx_plan_device and knx_apply_device (a factory-fresh device needs its \
             application loaded first; the plan says so). Call knx_commission_line again for \
             the devices that were not commissioned."
                .to_string()
        } else {
            "Tell the human the summary. Call knx_commission_line again for the devices that \
             were not commissioned."
                .to_string()
        })
    }
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
            verdicts: BTreeMap::new(),
            cursor: 0,
            outcomes: Vec::new(),
        };
        run.set_verdicts(BTreeMap::from([(first.address, Status::AlreadyPresent)]));
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
