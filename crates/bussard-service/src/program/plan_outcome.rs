//! The plan of a device write in one shape (issue #904): `bussard plan
//! --json` prints [`PlanOutcome`], and `knx_plan_device` returns the same
//! object plus the chat envelope (`summary`, `what_you_will_notice`,
//! `next_step`) its methods produce. A device whose load procedure only
//! writes properties is planned as a [`PropertyPlan`] (issue #390).

use bussard_download::{DevicePlan, ObjectGa, PlanReport};
use bussard_mgmt::tables::DeviceTables;
use bussard_model::identity::IdentityCheck;
use bussard_model::text::capitalize;
use bussard_model::{GroupAddress, IndividualAddress, Model};
use serde::Serialize;

use super::flash::FlashSummary;
use super::outcome::SecurityObject;
use crate::params::{BuiltPlan, OctetAttribution, ParameterChange};
use crate::property_plan::PropertyRow;
use crate::report::{Approval, Report, counted, device_phrase, object_phrase, room_of};
use bussard_model::change::Labels;

/// The most plain change lines `what_you_will_notice` lists.
const MAX_NOTICE_LINES: usize = 20;

/// The most test steps `what_you_will_notice` lists.
const MAX_TEST_STEPS: usize = 5;

/// The parameter half of a plan: what differs, by key, vendor text, device
/// value and project value, and whether it is written.
#[derive(Debug, Clone, Serialize)]
pub struct ParameterPlan {
    /// Whether the parameter memory was compared.
    pub compared: bool,
    /// The parameters that change.
    pub changed: Vec<ParameterChange>,
    /// How many octets the write streams.
    pub octets: usize,
    /// The octet runs written, and the ones left as the device holds them
    /// (`written: false`).
    pub octet_ranges: Vec<OctetAttribution>,
    /// Whether the parameter octets are written.
    pub written: bool,
    /// Why the parameters are not part of the plan.
    pub skipped: Option<String>,
}

impl ParameterPlan {
    /// The parameter half of `built`.
    pub fn of(built: &BuiltPlan) -> ParameterPlan {
        ParameterPlan {
            compared: built.parameters_skipped.is_none() || !built.parameters.is_empty(),
            changed: built.parameters.clone(),
            octets: built.plan.writes.parameter_octets,
            octet_ranges: built.octet_ranges.clone(),
            written: built.partial.is_some(),
            skipped: built.parameters_skipped.clone(),
        }
    }
}

/// The plan of writing the project to one device.
#[derive(Debug, Clone, Serialize)]
pub struct PlanOutcome {
    /// Always `true`: the plan was made.
    pub ok: bool,
    /// `apply` (the table and parameter write) or `flash` (a full
    /// download, issues #303, #750).
    pub method: String,
    /// The full download, for `method: flash`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flash: Option<FlashSummary>,
    /// The device plan in the project's words: `address`, `name`,
    /// `gateway`, `changes`, `channels`, `unchanged_objects`,
    /// `unchanged_parameters`, `writes`, `backup_dir`, `notes`,
    /// `state_hash`.
    #[serde(flatten)]
    pub plan: DevicePlan,
    /// The device's mask, hex.
    pub mask: String,
    /// The system the mask names.
    pub system_type: String,
    /// Whether the device was read under KNX Data Secure.
    pub secured: bool,
    /// The device's identity compared with the lock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
    /// What the security object receives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_object: Option<SecurityObject>,
    /// The device already holds the project: nothing to write.
    pub noop: bool,
    /// The table plan as `bussard plan -v` prints it.
    pub table_plan: String,
    /// The device plan in words, as `bussard plan` prints it.
    pub sentences: String,
    /// The links that stay.
    pub unchanged: Vec<ObjectGa>,
    /// The links the write adds.
    pub additions: Vec<ObjectGa>,
    /// The links the write removes.
    pub removals: Vec<ObjectGa>,
    /// The address table's entry count now.
    pub current_address_count: usize,
    /// The address table's entry count after the write.
    pub resulting_address_count: usize,
    /// The association table's entry count now.
    pub current_association_count: usize,
    /// The association table's entry count after the write.
    pub resulting_association_count: usize,
    /// The load steps the table write runs.
    pub load_steps: Vec<String>,
    /// The parameter half.
    pub parameter_plan: ParameterPlan,
    /// The parameter read-back (issue #119), when product data was
    /// available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<crate::params::Readback>,
    /// The project edits this server session made to the device and has
    /// not written yet (issue #279).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_model_changes: Option<serde_json::Value>,
    /// When the plan was made, RFC 3339.
    pub planned_at: String,
    /// The question and, on the MCP surface, the digest.
    #[serde(flatten)]
    pub approval: Approval,
}

/// What a [`PlanOutcome`] is built from.
pub struct PlanParts<'a> {
    /// The device.
    pub target: IndividualAddress,
    /// The live tables read.
    pub live: &'a DeviceTables,
    /// The table plan.
    pub report: &'a PlanReport,
    /// The device plan with its parameter half.
    pub built: &'a BuiltPlan,
    /// The device plan as shown (notes added).
    pub device_plan: DevicePlan,
    /// Whether the read ran under KNX Data Secure.
    pub secured: bool,
    /// The identity verdict.
    pub identity: Option<IdentityCheck>,
    /// The parameter read-back.
    pub parameters: Option<crate::params::Readback>,
}

impl PlanOutcome {
    /// The plan of `parts`, `method: apply`; the caller sets the flash, the
    /// security object and the digest where it has them.
    pub fn new(parts: PlanParts<'_>) -> PlanOutcome {
        let PlanParts {
            target,
            live,
            report,
            built,
            device_plan,
            secured,
            identity,
            parameters,
        } = parts;
        let tables_noop = report.is_noop()
            && !built.plan.writes.security_object
            && built.plan.writes.communication_flags.is_empty()
            && built.object_table.is_none();
        let noop = tables_noop && built.partial.is_none();
        PlanOutcome {
            ok: true,
            method: "apply".to_string(),
            flash: None,
            mask: format!("{:04X}", live.mask),
            system_type: crate::mgmt::system_type(live.mask).to_string(),
            secured,
            identity,
            security_object: None,
            noop,
            table_plan: bussard_download::render_plan_text(target, live, report),
            sentences: device_plan.render_text(),
            unchanged: report.unchanged.clone(),
            additions: report.additions.clone(),
            removals: report.removals.clone(),
            current_address_count: report.current_address_count,
            resulting_address_count: report.resulting_address_count,
            current_association_count: report.current_association_count,
            resulting_association_count: report.resulting_association_count,
            load_steps: report.load_steps.iter().map(ToString::to_string).collect(),
            parameter_plan: ParameterPlan::of(built),
            parameters,
            pending_model_changes: None,
            planned_at: crate::monitor::timefmt::to_rfc3339(std::time::SystemTime::now()),
            approval: Approval::question((!noop).then(|| device_plan.question())),
            plan: device_plan,
        }
    }

    /// The device, parsed.
    fn target(&self) -> Option<IndividualAddress> {
        self.plan.address.parse().ok()
    }

    /// The links gained or lost as `(object, group address)`.
    fn pairs(list: &[ObjectGa]) -> Vec<(u16, GroupAddress)> {
        list.iter().map(|p| (p.object, p.ga)).collect()
    }

    /// The plain change lines: one per link gained or lost, one per
    /// parameter.
    fn lines(&self, model: &Model, target: IndividualAddress) -> Vec<String> {
        let labels = Labels::plain([model, model]);
        let mut out = Vec::new();
        for (object, ga) in Self::pairs(&self.additions) {
            let verb = if sends(model, target, object) == Some(ga) {
                "now sends to"
            } else {
                "now listens to"
            };
            out.push(format!(
                "{} {verb} {}",
                object_phrase(model, target, object),
                labels.ga(ga)
            ));
        }
        for (object, ga) in Self::pairs(&self.removals) {
            out.push(format!(
                "{} no longer uses {}",
                object_phrase(model, target, object),
                labels.ga(ga)
            ));
        }
        for p in &self.parameter_plan.changed {
            out.push(match &p.device {
                Some(was) => format!("{}: {was} becomes {}", p.name.trim(), p.model),
                None => format!("{} is set to {}", p.name.trim(), p.model),
            });
        }
        out
    }

    /// What to try afterwards, from the links and parameters that change.
    fn to_test(&self, model: &Model, target: IndividualAddress) -> Vec<String> {
        let labels = Labels::plain([model, model]);
        let device = device_phrase(model, target);
        let mut out = Vec::new();
        for (object, ga) in Self::pairs(&self.additions) {
            let what = object_phrase(model, target, object);
            let group = labels.ga(ga);
            out.push(if sends(model, target, object) == Some(ga) {
                format!("Use {what} on {device} and check that {group} responds.")
            } else {
                format!(
                    "Operate {group} (its switch or app) and check that {what} on {device} \
                     reacts."
                )
            });
        }
        for (object, ga) in Self::pairs(&self.removals) {
            out.push(format!(
                "Check that {} on {device} no longer reacts to {}.",
                object_phrase(model, target, object),
                labels.ga(ga)
            ));
        }
        for p in &self.parameter_plan.changed {
            out.push(format!(
                "Check that {} on {device} behaves as set ({}).",
                p.name.trim(),
                p.model
            ));
        }
        if out.is_empty() && !self.noop {
            out.push(format!("Check that {device} works as before."));
        }
        out.truncate(MAX_TEST_STEPS);
        out
    }

    /// The plan's `what_you_will_notice` (issue #306): the device and
    /// room, how long it takes (`last_write_s`: the last verified write of
    /// the device), what keeps working, the changes and what to test.
    pub fn notice(&self, model: &Model, last_write_s: Option<f64>) -> Option<Notice> {
        let target = self.target()?;
        let flash = self.flash.is_some();
        let name = model
            .devices
            .get(&target)
            .map(|d| d.device.name.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| device_phrase(model, target));
        let takes = if flash {
            let (min, max) = crate::flash::DEVICE_OFFLINE_SECONDS;
            format!("{min} to {max} seconds: the device reloads its program and restarts")
        } else {
            match last_write_s {
                Some(s) if s > 0.0 => {
                    format!("about {} seconds, as long as its last write took", s.ceil())
                }
                _ => "usually under 20 seconds; a secured device that restarts takes longer"
                    .to_string(),
            }
        };
        let meanwhile = if flash {
            "Only this device is offline while it reloads: it does not react to switches or \
             send anything until it has restarted. Lights, blinds and the rest of the house \
             keep working."
        } else {
            "Only this device does not react while it is written. Lights, blinds and the rest \
             of the house keep working."
        };
        let mut lines = self.lines(model, target);
        let total = lines.len();
        lines.truncate(MAX_NOTICE_LINES);
        if total > MAX_NOTICE_LINES {
            lines.push(format!("and {} more", total - MAX_NOTICE_LINES));
        }
        Some(Notice {
            device: name,
            room: room_of(model, target),
            takes,
            meanwhile: meanwhile.to_string(),
            backup: "Its current state is backed up first, so the change can be undone."
                .to_string(),
            changes: lines,
            to_test: self.to_test(model, target),
        })
    }
}

/// The object `object` of `target` sends to, when its link says.
fn sends(model: &Model, target: IndividualAddress, object: u16) -> Option<GroupAddress> {
    model
        .links
        .links
        .get(&target)
        .and_then(|links| links.iter().find(|l| l.object == object))
        .and_then(|l| l.send)
}

/// What the human notices when a plan is written (issue #306).
#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    /// The device's name.
    pub device: String,
    /// Its room.
    pub room: Option<String>,
    /// How long it takes.
    pub takes: String,
    /// What keeps working meanwhile.
    pub meanwhile: String,
    /// The backup taken first.
    pub backup: String,
    /// The changes in plain words.
    pub changes: Vec<String>,
    /// What to test afterwards.
    pub to_test: Vec<String>,
}

impl Report for PlanOutcome {
    const SCHEMA: u32 = 2;

    fn summary(&self, model: &Model) -> Option<String> {
        let target = self.target()?;
        let device = device_phrase(model, target);
        if self.noop {
            return Some(format!(
                "{device} already matches your project; nothing to write."
            ));
        }
        let lines = self.lines(model, target);
        let shown: Vec<String> = lines.iter().take(3).cloned().collect();
        let more = lines.len().saturating_sub(shown.len());
        let mut what = shown.join("; ");
        if more > 0 {
            what.push_str(&format!("; and {more} more change(s)"));
        }
        let mut out = if what.is_empty() {
            format!("Writing {device} brings it in line with the model.")
        } else {
            format!("Writing {device}: {what}.")
        };
        if self.flash.is_some() {
            out.push_str(" This needs a full reload of the device's program.");
        }
        out.push_str(" Nothing is written before the human says yes.");
        Some(out)
    }

    fn next_step(&self) -> Option<String> {
        let target = &self.plan.address;
        let p = &self.parameter_plan;
        let (min, max) = crate::flash::DEVICE_OFFLINE_SECONDS;
        let load = self
            .flash
            .as_ref()
            .and_then(|f| f.load_application.as_ref().map(|l| (f, l)));
        Some(if self.noop {
            match &p.skipped {
                Some(why) => format!(
                    "nothing to write over MCP: the links already match your project, and {why}"
                ),
                None if p.octet_ranges.iter().any(|r| !r.written) => "nothing to write: the \
                    device matches your project wherever the configuration places a parameter; \
                    the parameter octets that differ (parameter_plan.octet_ranges with written: \
                    false) are ones ETS does not write in a download either, so they stay as the \
                    device holds them (see notes)"
                    .to_string(),
                None if !p.octet_ranges.is_empty() => "nothing to write: the device already \
                    matches your project; only device-managed parameter octets differ (see notes \
                    and parameter_plan.octet_ranges), and those are not written on their own"
                    .to_string(),
                None => "nothing to write: the device already matches your project".to_string(),
            }
        } else if let Some((flash, load)) = load {
            format!(
                "Show the plan above to the human (every sentence, and \
                 flash.load_application) and say that the application program must be loaded \
                 first: {}. Loading it replaces what {target} runs now, {target} restarts and is \
                 offline for {min} to {max} s, and {} Ask whether to load the application into \
                 {target}. Call knx_apply_device with this plan_digest only after an explicit \
                 yes to loading it; that one call runs the load and the write as one job.",
                load.why,
                if flash.links_after_download {
                    "the model's parameters are written with it and read back; then the links \
                     are written by a table write (this application's download does not write \
                     them) and read back."
                } else {
                    "the model's parameters and links are written with it and read back."
                }
            )
        } else if self.flash.is_some() {
            format!(
                "Show the plan above to the human (every sentence, the com-objects in \
                 flash.objects and the table sizes in flash.tables) and say that this change \
                 needs a full download: {target} restarts and is offline for {min} to {max} s, \
                 and its parameter memory is backed up first. Ask whether to flash {target}. \
                 Call knx_apply_device with this plan_digest only after an explicit yes to \
                 flashing it."
            )
        } else {
            let skipped = p
                .skipped
                .as_ref()
                .map(|why| {
                    format!(
                        " The parameters are not part of this plan ({why}); tell the human that \
                         only the links are written."
                    )
                })
                .unwrap_or_default();
            format!(
                "Show the plan above to the human (every sentence, links and parameters) and \
                 ask whether to write it to {target}. Call knx_apply_device with this \
                 plan_digest only after an explicit yes.{skipped}"
            )
        })
    }
}

/// The plan of a device whose load procedure only writes properties (issue
/// #390): each property, as the device holds it and as the project asks.
#[derive(Debug, Clone, Serialize)]
pub struct PropertyPlan {
    /// Always `true`: the plan was made.
    pub ok: bool,
    /// Always `flash`: `bussard flash` runs the procedure.
    pub method: String,
    /// The device.
    pub address: String,
    /// The resolved gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The device's mask, hex.
    pub mask: String,
    /// The system the mask names.
    pub system_type: String,
    /// Whether the device was read under KNX Data Secure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secured: Option<bool>,
    /// The application whose procedure it is.
    pub application: String,
    /// The device already holds every property.
    pub noop: bool,
    /// The plan in words.
    pub sentences: String,
    /// Each property the procedure writes.
    pub property_procedure: Vec<PropertyRow>,
}

impl PropertyPlan {
    /// The plan of `rows` for `target` (mask `mask`, application `app_id`).
    pub fn new(target: IndividualAddress, mask: u16, app_id: &str, rows: &[PropertyRow]) -> Self {
        PropertyPlan {
            ok: true,
            method: "flash".to_string(),
            address: target.to_string(),
            gateway: None,
            mask: format!("{mask:04X}"),
            system_type: crate::mgmt::system_type(mask).to_string(),
            secured: None,
            application: app_id.to_string(),
            noop: !rows.iter().any(PropertyRow::differs),
            sentences: crate::property_plan::render_text(target, app_id, rows),
            property_procedure: rows.to_vec(),
        }
    }
}

impl Report for PropertyPlan {
    const SCHEMA: u32 = 2;

    fn summary(&self, model: &Model) -> Option<String> {
        let device = self
            .address
            .parse()
            .map(|ia| device_phrase(model, ia))
            .unwrap_or_else(|_| "the device".to_string());
        Some(if self.noop {
            format!("{} already matches; nothing to write.", capitalize(&device))
        } else {
            format!(
                "A plan for {device}{}. Nothing is written before the human says yes.",
                counted(
                    self.property_procedure
                        .iter()
                        .filter(|r| r.differs())
                        .count()
                )
            )
        })
    }
}
