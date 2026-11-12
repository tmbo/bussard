//! Whether bussard supports writing a device (issues #1089, #1097): the
//! verdict of the device-support list ([`bussard_model::supported`]) for a
//! device's application program, and the gate every device write passes.
//!
//! An application is `proven` (bussard wrote a real device with it and the
//! read-back matched), `likely` (computed from the ETS sweep, or a house
//! capture; not confirmed on a real device) or unsupported (a known problem,
//! or not on the list). `proven` and `likely` pass the gate; a plan and the
//! assistant's note say when a device is only `likely`.
//!
//! The verdict is one function, [`verdict`], judged on the application a
//! write builds its image from, so the CLI and the
//! MCP server never decide differently (#314). The gate, [`authorize`],
//! refuses an unsupported device on a non-loopback gateway, the same rule as
//! the write gate (#74): a simulator cannot be bricked, and the knx-sim loop
//! and the sweep keep running for products that are not on the list yet.
//!
//! A write needs a [`SupportGrant`], which only [`authorize`] makes: the
//! download ([`crate::program::flash::FlashExecution`]), the table and
//! parameter write ([`crate::program::apply::ApplyRequest`]), the
//! parameter-only download ([`crate::program::params_only::ParamsWrite`]) and
//! the parameter restore ([`crate::download::ParamWrite`]) each carry one, so
//! a surface cannot reach the bus without the verdict.

use std::fmt;

use bussard_model::IndividualAddress;
use bussard_model::identity::{LockIdentity, application_id_from_ref};
use bussard_model::schema::Device;
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::is_loopback_gateway;
use serde::Serialize;

pub use bussard_model::supported::{
    Category, Evidence, SupportedEntry, SupportedList, application_ref_of,
};

/// Why a device is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// Its application program is not on the list.
    NotListed,
    /// The project pins no application for it, so it is unknown.
    NoProductData,
    /// The list names a known problem (an issue, or the ETS sweep reports it
    /// differing).
    KnownProblem,
}

impl UnsupportedReason {
    /// The reason in words.
    pub fn text(self) -> &'static str {
        match self {
            UnsupportedReason::NotListed => "application not on the list",
            UnsupportedReason::NoProductData => "no product data pinned, application unknown",
            UnsupportedReason::KnownProblem => "known problem",
        }
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// The sentence a plan and the assistant carry for a `likely` device.
pub const NOT_CONFIRMED: &str = "not confirmed on a real device";

/// The verdict of the device-support list for one application program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// The application is `proven` or `likely`: a write passes the gate.
    Supported {
        /// The application id, ten hex digits.
        application_id: String,
        /// The application ref prefix (`M-0004_A-20DE-22`).
        application: String,
        /// The list's name for it.
        name: String,
        /// `proven` or `likely`.
        category: Category,
        /// What put it there.
        evidence: Evidence,
    },
    /// It is not: a known problem, not listed, or unknown.
    Unsupported {
        /// The application id, when known.
        application_id: Option<String>,
        /// The application ref, when known.
        application: Option<String>,
        /// Manufacturer and product, from the project, when known.
        name: Option<String>,
        /// Why.
        reason: UnsupportedReason,
        /// The known problem, for [`UnsupportedReason::KnownProblem`]
        /// (boxed: most verdicts have none).
        known: Option<Box<KnownProblem>>,
    },
}

/// A known problem the list names for an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownProblem {
    /// The problem in words with its issue (`differs from ETS in the sweep,
    /// #971`).
    pub problem: String,
    /// Its cause, when the issue names one (`capture unusable: ...`).
    pub cause: Option<String>,
}

impl Support {
    /// Whether a write passes the gate: the application is `proven` or
    /// `likely`.
    pub fn is_supported(&self) -> bool {
        matches!(self, Support::Supported { .. })
    }

    /// The category: `proven`, `likely` or `unsupported`.
    pub fn category(&self) -> Category {
        match self {
            Support::Supported { category, .. } => *category,
            Support::Unsupported { .. } => Category::Unsupported,
        }
    }

    /// The application, as a message names it: the ref, or the id.
    pub fn application(&self) -> Option<&str> {
        match self {
            Support::Supported { application, .. } => Some(application),
            Support::Unsupported {
                application,
                application_id,
                ..
            } => application.as_deref().or(application_id.as_deref()),
        }
    }

    /// The product's name, when known.
    pub fn name(&self) -> Option<&str> {
        match self {
            Support::Supported { name, .. } => Some(name),
            Support::Unsupported { name, .. } => name.as_deref(),
        }
    }

    /// One line for a plan or a device view, without the override hint
    /// ([`SupportView::line`]).
    pub fn line(&self) -> String {
        self.view().line()
    }

    /// [`Support::view`] for a write on `config`: `override_needed` says
    /// whether a write is refused without the override.
    pub fn view_on(&self, config: &ConnectionConfig) -> SupportView {
        SupportView {
            override_needed: refuses(config, self),
            ..self.view()
        }
    }

    /// The JSON shape every surface reports (`support` in `plan --json`,
    /// `describe --json`, `knx_show_device`, `knx_plan_device`).
    pub fn view(&self) -> SupportView {
        match self {
            Support::Supported {
                application_id,
                application,
                name,
                category,
                evidence,
            } => SupportView {
                status: SupportStatus::Supported,
                category: *category,
                evidence: Some(*evidence),
                note: (*category == Category::Likely).then_some(NOT_CONFIRMED),
                reason: None,
                problem: None,
                cause: None,
                application: Some(application.clone()),
                application_id: Some(application_id.clone()),
                name: Some(name.clone()),
                override_needed: false,
            },
            Support::Unsupported {
                application_id,
                application,
                name,
                reason,
                known,
            } => SupportView {
                status: SupportStatus::Unsupported,
                category: Category::Unsupported,
                evidence: None,
                note: None,
                reason: Some(reason.text()),
                problem: known.as_ref().map(|k| k.problem.clone()),
                cause: known.as_ref().and_then(|k| k.cause.clone()),
                application: application.clone(),
                application_id: application_id.clone(),
                name: name.clone(),
                override_needed: false,
            },
        }
    }
}

/// The verdict as JSON: `{ status, category, evidence | reason, note,
/// problem, application, application_id, name }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportView {
    /// `supported` (a write passes) or `unsupported` (a verdict is never
    /// `forced`).
    pub status: SupportStatus,
    /// `proven`, `likely` or `unsupported`.
    pub category: Category,
    /// What put a supported device in its category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// `not confirmed on a real device`, for a `likely` device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    /// Why it is not supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The known problem, with its issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The known problem's cause, when its issue names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// The application ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// The application id, ten hex digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Manufacturer and product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether a write on this gateway is refused without the override (an
    /// unsupported device on a non-loopback gateway).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub override_needed: bool,
}

impl SupportView {
    /// Whether a write passes the gate (`proven` or `likely`).
    pub fn is_supported(&self) -> bool {
        self.status == SupportStatus::Supported
    }

    /// The application and product in words: `M-0083_A-0120-10 (MDT
    /// AKS-0816.03)`, the one rendering every message uses.
    pub fn what(&self) -> String {
        match (&self.application, &self.name) {
            (Some(app), Some(name)) => format!("{app} ({name})"),
            (Some(app), None) => app.clone(),
            (None, Some(name)) => format!("a {name} with no application pinned"),
            (None, None) => "no application pinned".to_string(),
        }
    }

    /// The known problem with its cause: `differs from ETS in the sweep,
    /// #1060: capture unusable: ...`, or `None`.
    pub fn problem_text(&self) -> Option<String> {
        let problem = self.problem.as_deref()?;
        Some(match &self.cause {
            Some(cause) => format!("{problem}: {cause}"),
            None => problem.to_string(),
        })
    }

    /// One line for a plan or a device view: `proven (live):
    /// M-0004_A-D142-21 (Jung 52921ST F50 push-button module)`, `likely
    /// (sweep), not confirmed on a real device: ...`, `known problem (differs
    /// from ETS in the sweep, #971): ...` or `not on the supported list
    /// (application not on the list): M-0083_A-0120-10 (MDT AKS-0816.03)`,
    /// the last two ending `; writes need --allow-unsupported` when a write
    /// on this gateway is refused without it.
    pub fn line(&self) -> String {
        let what = self.what();
        let refused = if self.override_needed {
            "; writes need --allow-unsupported"
        } else {
            ""
        };
        match (self.evidence, &self.problem) {
            (Some(evidence), _) => match self.note {
                Some(note) => format!("{} ({evidence}), {note}: {what}", self.category),
                None => format!("{} ({evidence}): {what}", self.category),
            },
            (None, Some(problem)) => format!("known problem ({problem}): {what}{refused}"),
            (None, None) => format!(
                "not on the supported list ({}): {what}{refused}",
                self.reason.unwrap_or("application not on the list"),
            ),
        }
    }

    /// What the assistant puts to the human before a write of an
    /// unsupported device (issue #1089) or a `likely` one (issue #1097), or
    /// `None` for a proven one.
    pub fn assistant_note(&self, target: &str) -> Option<String> {
        if self.is_supported() {
            return self.note.map(|note| {
                format!(
                    "{target} runs {}, which bussard rates likely supported: its download matched \
                     ETS in the {} evidence, but it is {note}. Tell the human this, and that a \
                     backup first is the safe way. The write is not refused.",
                    self.what(),
                    self.evidence.map_or("recorded", Evidence::as_str),
                )
            });
        }
        if let Some(problem) = self.problem_text() {
            let how = if self.override_needed {
                "The write is refused (code unsupported_device) unless the human explicitly says \
                 to write anyway; only then call the write again with allow_unsupported: true and \
                 this plan_digest."
            } else {
                "The gateway is loopback (a simulator), so the write is not refused."
            };
            return Some(format!(
                "{target} runs {}, which bussard's device-support list names with a known \
                 problem ({problem}). Tell the human this, with the cause, that a backup comes \
                 first, and that ETS is the safe way to program it. {how}",
                self.what()
            ));
        }
        let how = if self.override_needed {
            "The write is refused (code unsupported_device) unless the human explicitly says to \
             write anyway; only then call the write again with allow_unsupported: true and this \
             plan_digest."
        } else {
            "The gateway is loopback (a simulator), so the write is not refused."
        };
        Some(format!(
            "{target} runs {}, which is not on bussard's list of supported devices: bussard has \
             never checked what it writes to this product against ETS, and a wrong image can \
             leave the device not working. Tell the human this, that a backup comes first, and \
             that ETS is the safe way to program it. {how}",
            self.what()
        ))
    }
}

/// The verdict for a write of `device` that builds its image from
/// `application`: the program the write selected from the product data (the
/// download's, or the one the parameters are decoded with), or `None` when no
/// product data is at hand. Without one, the device's own application
/// decides: the device file's `application` override when set, else the one
/// `bussard.lock` pins. Every display and every gate decides through this
/// one function, so what is shown is what is judged and what is written.
pub fn verdict(device: Option<&Device>, application: Option<&str>) -> Support {
    verdict_in(SupportedList::embedded(), device, application)
}

/// [`verdict`] for the device `model` holds at `target`.
pub fn verdict_at(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
    application: Option<&str>,
) -> Support {
    verdict(
        model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device),
        application,
    )
}

/// [`verdict`] against `list`.
pub fn verdict_in(
    list: &SupportedList,
    device: Option<&Device>,
    application: Option<&str>,
) -> Support {
    let name = device.and_then(project_name);
    if let Some(app) = application {
        let id = application_id_from_ref(app).map(|(id, _)| id);
        return decide(list, id.as_deref(), Some(app), name);
    }
    // The device's own application: the override wins over the lock, as
    // the product resolution picks it.
    let effective = device.and_then(|d| {
        d.application_override
            .as_deref()
            .or_else(|| {
                d.product
                    .as_ref()
                    .and_then(|p| p.application_ref.as_deref())
            })
            .or(d.lock.application.as_deref())
    });
    let id = match effective {
        Some(app) => application_id_from_ref(app).map(|(id, _)| id),
        None => device.and_then(|d| LockIdentity::of(d).application_id),
    };
    decide(list, id.as_deref(), effective, name)
}

/// The one decision.
fn decide(
    list: &SupportedList,
    application_id: Option<&str>,
    application: Option<&str>,
    name: Option<String>,
) -> Support {
    let Some(id) = application_id else {
        return Support::Unsupported {
            application_id: None,
            application: application.map(str::to_string),
            name,
            reason: if application.is_some() {
                UnsupportedReason::NotListed
            } else {
                UnsupportedReason::NoProductData
            },
            known: None,
        };
    };
    match list.lookup(id) {
        Some(entry) if entry.category.passes() => Support::Supported {
            application_id: entry.application_id.clone(),
            application: entry.application(),
            name: entry.name.clone(),
            category: entry.category,
            evidence: entry.evidence,
        },
        Some(entry) => Support::Unsupported {
            application_id: Some(entry.application_id.clone()),
            application: Some(entry.application()),
            name: Some(entry.name.clone()),
            reason: UnsupportedReason::KnownProblem,
            known: entry.problem().map(|problem| {
                Box::new(KnownProblem {
                    problem,
                    cause: entry.cause.clone(),
                })
            }),
        },
        None => Support::Unsupported {
            application_id: Some(id.to_ascii_uppercase()),
            application: Some(
                application
                    .map(short_ref)
                    .unwrap_or_else(|| application_ref_of(id)),
            ),
            name,
            reason: UnsupportedReason::NotListed,
            known: None,
        },
    }
}

/// `M-0083_A-0120-10-ABCD-O000A` as `M-0083_A-0120-10`: the part the id
/// stands for.
fn short_ref(application: &str) -> String {
    match application_id_from_ref(application) {
        Some((id, _)) => application_ref_of(&id),
        None => application.to_string(),
    }
}

/// Manufacturer and order number from the device file, when it has them.
fn project_name(device: &Device) -> Option<String> {
    let product = device.product.as_ref()?;
    let parts: Vec<&str> = [
        product.manufacturer.as_deref(),
        product.order_number.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.trim().is_empty())
    .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// How a write passed the support gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// The device is on the list.
    Supported,
    /// It is not, and the gateway is loopback: reported, not refused.
    Unsupported,
    /// It is not, and the operator forced the write.
    Forced,
}

impl SupportStatus {
    /// The word a result and the history record carry.
    pub fn as_str(self) -> &'static str {
        match self {
            SupportStatus::Supported => "supported",
            SupportStatus::Unsupported => "unsupported",
            SupportStatus::Forced => "forced",
        }
    }
}

impl fmt::Display for SupportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The proof a device write passed the support gate. Only [`authorize`]
/// makes one; every write request carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrant {
    /// The device the grant is for.
    target: IndividualAddress,
    /// How it passed.
    status: SupportStatus,
    /// The verdict it passed on.
    verdict: Support,
}

impl SupportGrant {
    /// The device the grant is for.
    pub fn target(&self) -> IndividualAddress {
        self.target
    }

    /// How the gate passed.
    pub fn status(&self) -> SupportStatus {
        self.status
    }

    /// The verdict the gate passed on.
    pub fn verdict(&self) -> &Support {
        &self.verdict
    }

    /// Whether the write was forced past an unsupported verdict.
    pub fn forced(&self) -> bool {
        self.status == SupportStatus::Forced
    }

    /// The line a write tells the operator before it starts, or `None`: a
    /// forced write, and a `likely` device that is not confirmed on a real
    /// device. A loopback gateway passing an unsupported device stays
    /// silent (`plan`, `describe` and `device` show the verdict).
    pub fn notice(&self) -> Option<String> {
        if self.forced() || self.verdict.category() == Category::Likely {
            self.plan_line()
        } else {
            None
        }
    }

    /// The line a plan and a prompt carry when the device is not proven:
    /// `1.1.4: likely (house-capture), not confirmed on a real device:
    /// M-0004_A-20D7-26 (...)`, `1.1.7: not on the supported list, forced:
    /// M-0083_A-0120-10 (...)`, `1.1.9: known problem (differs from ETS in
    /// the sweep, #971), forced: ...`, or the same ending `; written because
    /// the gateway is loopback`. `None` for a proven device.
    pub fn plan_line(&self) -> Option<String> {
        let view = self.verdict.view();
        let target = self.target;
        let what = view.what();
        let unsupported = match &view.problem {
            Some(problem) => format!("known problem ({problem})"),
            None => "not on the supported list".to_string(),
        };
        match self.status {
            SupportStatus::Supported if view.note.is_some() => {
                Some(format!("{target}: {}", view.line()))
            }
            SupportStatus::Supported => None,
            SupportStatus::Forced => Some(format!("{target}: {unsupported}, forced: {what}")),
            SupportStatus::Unsupported => Some(format!(
                "{target}: {unsupported}; written because the gateway is loopback: {what}"
            )),
        }
    }

    /// This grant for a later step of the same command (the `flash` and
    /// `apply` of a `replace` or `commission`): the same device, judged on
    /// the application that step writes. Re-deciding gives the same verdict,
    /// so the operator's one answer covers it; another verdict (the step
    /// writes another application than the check judged) is refused.
    ///
    /// # Errors
    ///
    /// The grant is for another device, or the step's application has
    /// another verdict.
    pub fn reuse_for(
        &self,
        target: IndividualAddress,
        device: Option<&Device>,
        application: Option<&str>,
    ) -> Result<SupportGrant, String> {
        self.covers(target)?;
        let now = verdict(device, application);
        if now == self.verdict {
            return Ok(self.clone());
        }
        // The step names the program where the check could not (no product
        // data at hand then): a listed one passes as supported, an unlisted
        // one passes only when the check already let an unsupported device
        // through (forced, or a loopback gateway).
        let unknown_before = matches!(
            self.verdict,
            Support::Unsupported {
                reason: UnsupportedReason::NoProductData,
                ..
            }
        );
        if unknown_before && (now.is_supported() || self.status != SupportStatus::Supported) {
            return Ok(SupportGrant {
                target,
                status: if now.is_supported() {
                    SupportStatus::Supported
                } else {
                    self.status
                },
                verdict: now,
            });
        }
        Err(format!(
            "refusing to write {target}: its support check judged {}, but this step writes {}; \
             nothing was written by this step",
            self.verdict.view().what(),
            now.view().what()
        ))
    }

    /// Refuses a write of another device than the grant is for: a surface
    /// bug, never an operator's choice.
    pub(crate) fn covers(&self, target: IndividualAddress) -> Result<(), String> {
        if self.target == target {
            Ok(())
        } else {
            Err(format!(
                "refusing to write {target}: its support check was made for {}",
                self.target
            ))
        }
    }
}

/// An unsupported device on a non-loopback gateway, without the override.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "refusing to write: {}. Nothing was written.\nReads work (plan, describe, backup). To write \
     anyway, back the device up first and pass --allow-unsupported.",
    self.sentence()
)]
pub struct SupportRefusal {
    /// The device.
    pub target: IndividualAddress,
    /// The verdict.
    pub verdict: Support,
}

impl SupportRefusal {
    /// What is refused, without the override: `1.1.7 runs M-0083_A-0120-10
    /// (MDT AKS-0816.03), which is not on bussard's list of supported
    /// devices`, or `..., which has a known problem (differs from ETS in the
    /// sweep, #971)`.
    pub fn sentence(&self) -> String {
        let view = self.verdict.view();
        match view.problem_text() {
            Some(problem) => format!(
                "{} runs {}, which has a known problem ({problem})",
                self.target,
                view.what()
            ),
            None => format!(
                "{} runs {}, which is not on bussard's list of supported devices",
                self.target,
                view.what()
            ),
        }
    }
}

/// The support gate of a write of `device` at `target` that builds its image
/// from `application` (see [`verdict`]): the grant, or the refusal of an
/// unsupported device on a non-loopback gateway without `allow_unsupported`.
/// The verdict is derived here, never handed in, so a write is judged on the
/// application it writes.
///
/// A supported device always passes. An unsupported one passes as
/// [`SupportStatus::Forced`] with `allow_unsupported`, and as
/// [`SupportStatus::Unsupported`] on a loopback gateway (reported, not
/// refused).
///
/// # Errors
///
/// [`SupportRefusal`] for an unsupported device on a non-loopback gateway
/// without the override.
pub fn authorize(
    config: &ConnectionConfig,
    target: IndividualAddress,
    device: Option<&Device>,
    application: Option<&str>,
    allow_unsupported: bool,
) -> Result<SupportGrant, SupportRefusal> {
    authorize_verdict(
        config,
        target,
        verdict(device, application),
        allow_unsupported,
    )
}

/// [`authorize`] on a verdict already derived.
fn authorize_verdict(
    config: &ConnectionConfig,
    target: IndividualAddress,
    verdict: Support,
    allow_unsupported: bool,
) -> Result<SupportGrant, SupportRefusal> {
    let status = if verdict.is_supported() {
        SupportStatus::Supported
    } else if allow_unsupported {
        SupportStatus::Forced
    } else if is_loopback_gateway(config) {
        SupportStatus::Unsupported
    } else {
        return Err(SupportRefusal { target, verdict });
    };
    Ok(SupportGrant {
        target,
        status,
        verdict,
    })
}

/// Whether [`authorize`] would refuse `verdict` on `config` without the
/// override: what a plan tells the human before they are asked.
pub fn refuses(config: &ConnectionConfig, verdict: &Support) -> bool {
    !verdict.is_supported() && !is_loopback_gateway(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const LIST: &str = "[[device]]\napplication_id = \"000420DE22\"\nname = \"Jung 230021SU\"\n\
                        category = \"proven\"\nevidence = \"live\"\nmask = \"07B0\"\n\
                        source = \"#89\"\n\
                        [[device]]\napplication_id = \"000420D726\"\nname = \"Jung 230241SR\"\n\
                        category = \"likely\"\nevidence = \"house-capture\"\nmask = \"07B0\"\n\
                        source = \"#126\"\n\
                        [[device]]\napplication_id = \"000920AA10\"\nname = \"Hager\"\n\
                        category = \"unsupported\"\nevidence = \"issue\"\nmask = \"0701\"\n\
                        source = \"#1057\"\nissue = 971\nreason = \"differs from ETS in the sweep\"\n";

    fn tunnel(ip: Ipv4Addr) -> ConnectionConfig {
        ConnectionConfig::tunnel(SocketAddrV4::new(ip, 3671))
    }

    fn device(application: Option<&str>) -> Result<Device, Box<dyn std::error::Error>> {
        let mut device = Device {
            address: "1.1.7".parse()?,
            name: "test".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
            application_override: None,
            knxnet: None,
            lock: Default::default(),
        };
        device.lock.application = application.map(str::to_string);
        Ok(device)
    }

    fn unsupported() -> Support {
        Support::Unsupported {
            application_id: Some("0083012010".to_string()),
            application: Some("M-0083_A-0120-10".to_string()),
            name: Some("MDT AKS-0816.03".to_string()),
            reason: UnsupportedReason::NotListed,
            known: None,
        }
    }

    /// A generated half with one sweep `differs` entry whose cause says the
    /// capture, not bussard, is at fault.
    const GENERATED: &str = "[source]\nsweep_manifest = \"m\"\nsweep_generated = \"2026-11-10\"\n\
        synthetic_manifest = \"s\"\ncoverage_floor = 95.0\n\
        [differs]\nreason = \"differs from ETS in the sweep\"\nentries = [\n\
        { id = \"0004B00C01\", name = \"Jung B00C\", masks = [\"0701\"], issue = 1060, \
        cause = \"capture unusable: ETS loaded another application version\" },\n]\n";

    #[test]
    fn test_verdict_in_listed_application_is_supported() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let device = device(Some("M-0004_A-20DE-22-C7D8-O000A"))?;
        let support = verdict_in(&list, Some(&device), None);
        assert_eq!(
            support,
            Support::Supported {
                application_id: "000420DE22".to_string(),
                application: "M-0004_A-20DE-22".to_string(),
                name: "Jung 230021SU".to_string(),
                category: Category::Proven,
                evidence: Evidence::Live,
            }
        );
        assert_eq!(support.view().status, SupportStatus::Supported);
        Ok(())
    }

    #[test]
    fn test_verdict_in_unlisted_application_is_not_listed() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let device = device(Some("M-0083_A-0120-10-1234-O0000"))?;
        let support = verdict_in(&list, Some(&device), None);
        assert!(matches!(
            &support,
            Support::Unsupported { reason: UnsupportedReason::NotListed, application: Some(a), .. }
                if a == "M-0083_A-0120-10"
        ));
        assert_eq!(support.view().reason, Some("application not on the list"));
        Ok(())
    }

    #[test]
    fn test_verdict_in_no_application_is_no_product_data() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let device = device(None)?;
        assert!(matches!(
            verdict_in(&list, Some(&device), None),
            Support::Unsupported {
                reason: UnsupportedReason::NoProductData,
                ..
            }
        ));
        assert!(matches!(
            verdict_in(&list, None, None),
            Support::Unsupported {
                reason: UnsupportedReason::NoProductData,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_verdict_in_likely_passes_and_says_not_confirmed() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let device = device(Some("M-0004_A-20D7-26-1234-O000A"))?;
        let support = verdict_in(&list, Some(&device), None);
        assert!(support.is_supported());
        assert_eq!(support.category(), Category::Likely);
        let view = support.view();
        assert_eq!(view.note, Some(NOT_CONFIRMED));
        assert_eq!(
            view.line(),
            "likely (house-capture), not confirmed on a real device: M-0004_A-20D7-26 \
             (Jung 230241SR)"
        );
        let note = view.assistant_note("1.1.4").ok_or("no note")?;
        assert!(note.contains("not confirmed on a real device"), "{note}");
        let json = serde_json::to_value(&view)?;
        assert_eq!(json["category"], "likely");
        assert_eq!(json["status"], "supported");
        // The gate passes on a real gateway, and the write says why.
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let grant = authorize_verdict(&real, "1.1.4".parse()?, support, false)?;
        assert_eq!(grant.status(), SupportStatus::Supported);
        assert_eq!(
            grant.notice().as_deref(),
            Some(
                "1.1.4: likely (house-capture), not confirmed on a real device: \
                 M-0004_A-20D7-26 (Jung 230241SR)"
            )
        );
        Ok(())
    }

    #[test]
    fn test_verdict_in_known_problem_is_refused_with_its_issue() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let support = verdict_in(&list, None, Some("M-0009_A-20AA-10-E0C0"));
        assert!(!support.is_supported());
        assert_eq!(support.category(), Category::Unsupported);
        let view = support.view();
        assert_eq!(view.reason, Some("known problem"));
        assert_eq!(
            view.line(),
            "known problem (differs from ETS in the sweep, #971): M-0009_A-20AA-10 (Hager)"
        );
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let target: IndividualAddress = "1.1.9".parse()?;
        let refusal = authorize_verdict(&real, target, support.clone(), false)
            .err()
            .ok_or("not refused")?;
        assert_eq!(
            refusal.sentence(),
            "1.1.9 runs M-0009_A-20AA-10 (Hager), which has a known problem (differs from ETS \
             in the sweep, #971)"
        );
        let forced = authorize_verdict(&real, target, support.clone(), true)?;
        assert_eq!(
            forced.plan_line().as_deref(),
            Some(
                "1.1.9: known problem (differs from ETS in the sweep, #971), forced: \
                 M-0009_A-20AA-10 (Hager)"
            )
        );
        let local = authorize_verdict(&tunnel(Ipv4Addr::LOCALHOST), target, support, false)?;
        assert_eq!(
            local.plan_line().as_deref(),
            Some(
                "1.1.9: known problem (differs from ETS in the sweep, #971); written because \
                 the gateway is loopback: M-0009_A-20AA-10 (Hager)"
            )
        );
        Ok(())
    }

    #[test]
    fn test_verdict_in_known_problem_carries_its_cause() -> TestResult {
        // The cause is rendered as the issue gives it, never as "bussard's
        // download does not match ETS": here the capture was unusable.
        let list = SupportedList::parse_with(LIST, Some(GENERATED))?;
        let support = verdict_in(&list, None, Some("M-0004_A-B00C-01-439D"));
        let mut view = support.view_on(&tunnel(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(
            view.cause.as_deref(),
            Some("capture unusable: ETS loaded another application version")
        );
        let refusal = authorize_verdict(
            &tunnel(Ipv4Addr::new(192, 0, 2, 10)),
            "1.1.9".parse()?,
            support,
            false,
        )
        .err()
        .ok_or("not refused")?;
        assert_eq!(
            refusal.sentence(),
            "1.1.9 runs M-0004_A-B00C-01 (Jung B00C), which has a known problem (differs from \
             ETS in the sweep, #1060: capture unusable: ETS loaded another application version)"
        );
        let note = view.assistant_note("1.1.9").ok_or("no note")?;
        assert_eq!(
            note,
            "1.1.9 runs M-0004_A-B00C-01 (Jung B00C), which bussard's device-support list names \
             with a known problem (differs from ETS in the sweep, #1060: capture unusable: ETS \
             loaded another application version). Tell the human this, with the cause, that a \
             backup comes first, and that ETS is the safe way to program it. The write is \
             refused (code unsupported_device) unless the human explicitly says to write \
             anyway; only then call the write again with allow_unsupported: true and this \
             plan_digest."
        );
        assert!(!note.contains("does not match"), "{note}");
        view.override_needed = false;
        assert!(view.assistant_note("1.1.9").is_some_and(|n| {
            n.ends_with("The gateway is loopback (a simulator), so the write is not refused.")
        }));
        Ok(())
    }

    #[test]
    fn test_proven_grant_has_no_notice() -> TestResult {
        let list = SupportedList::parse(LIST)?;
        let support = verdict_in(&list, None, Some("M-0004_A-20DE-22-C7D8-O000A"));
        assert_eq!(support.category(), Category::Proven);
        assert_eq!(support.view().assistant_note("1.1.47"), None);
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let grant = authorize_verdict(&real, "1.1.47".parse()?, support, false)?;
        assert_eq!(grant.notice(), None);
        assert_eq!(grant.plan_line(), None);
        Ok(())
    }

    #[test]
    fn test_verdict_of_a_selected_program_uses_the_embedded_list() {
        assert!(verdict(None, Some("M-0004_A-D142-21-8848-O000A")).is_supported());
        assert!(!verdict(None, Some("M-0083_A-0120-10-0000")).is_supported());
    }

    #[test]
    fn test_authorize_refuses_unsupported_on_a_real_gateway() -> TestResult {
        let target: IndividualAddress = "1.1.7".parse()?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let refusal = authorize_verdict(&real, target, unsupported(), false)
            .err()
            .ok_or("not refused")?;
        assert!(refusal.to_string().starts_with(
            "refusing to write: 1.1.7 runs M-0083_A-0120-10 (MDT AKS-0816.03), which is not on \
             bussard's list of supported devices. Nothing was written."
        ));
        assert!(refusal.to_string().contains("--allow-unsupported"));
        assert!(refuses(&real, &unsupported()));
        Ok(())
    }

    #[test]
    fn test_authorize_forces_with_the_override() -> TestResult {
        let target: IndividualAddress = "1.1.7".parse()?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let grant = authorize_verdict(&real, target, unsupported(), true)?;
        assert_eq!(grant.status(), SupportStatus::Forced);
        assert!(grant.forced());
        assert_eq!(
            grant.plan_line().as_deref(),
            Some("1.1.7: not on the supported list, forced: M-0083_A-0120-10 (MDT AKS-0816.03)")
        );
        Ok(())
    }

    #[test]
    fn test_authorize_reports_but_passes_on_loopback() -> TestResult {
        let target: IndividualAddress = "1.1.7".parse()?;
        let local = tunnel(Ipv4Addr::LOCALHOST);
        let grant = authorize_verdict(&local, target, unsupported(), false)?;
        assert_eq!(grant.status(), SupportStatus::Unsupported);
        assert!(!refuses(&local, &unsupported()));
        Ok(())
    }

    #[test]
    fn test_authorize_supported_passes_everywhere() -> TestResult {
        let target: IndividualAddress = "1.1.4".parse()?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let grant = authorize(
            &real,
            target,
            None,
            Some("M-0004_A-D142-21-8848-O000A"),
            false,
        )?;
        assert_eq!(grant.status(), SupportStatus::Supported);
        assert_eq!(grant.plan_line(), None);
        assert!(grant.covers(target).is_ok());
        assert!(grant.covers("1.1.5".parse()?).is_err());
        Ok(())
    }

    #[test]
    fn test_verdict_judges_the_override_not_the_lock() -> TestResult {
        // The lock pins a listed program, the device file overrides it with
        // an unlisted one: the write builds the override, so it is judged.
        let mut device = device(Some("M-0004_A-D142-21-8848-O000A"))?;
        device.application_override = Some("M-0083_A-0120-10-0000".to_string());
        assert!(!verdict(Some(&device), None).is_supported());
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let target: IndividualAddress = "1.1.7".parse()?;
        assert!(authorize(&real, target, Some(&device), None, false).is_err());
        Ok(())
    }

    #[test]
    fn test_verdict_judges_the_selected_program_over_the_device() -> TestResult {
        // The lock pins an unlisted program and the write selected a listed
        // one (`--application`), and the other way round.
        let unlisted = device(Some("M-0083_A-0120-10-0000"))?;
        let listed = device(Some("M-0004_A-D142-21-8848-O000A"))?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let target: IndividualAddress = "1.1.7".parse()?;
        assert!(
            authorize(
                &real,
                target,
                Some(&unlisted),
                Some("M-0004_A-D142-21-8848-O000A"),
                false
            )
            .is_ok()
        );
        assert!(
            authorize(
                &real,
                target,
                Some(&listed),
                Some("M-0083_A-0120-10-0000"),
                false
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_assistant_note_and_line_read_as_one_sentence() {
        let mut view = unsupported().view();
        view.override_needed = true;
        let note = view.assistant_note("1.1.7").unwrap_or_default();
        assert!(note.starts_with("1.1.7 runs M-0083_A-0120-10 (MDT AKS-0816.03), which is not"));
        assert!(!note.contains("  "), "{note}");
        assert!(view.line().ends_with("; writes need --allow-unsupported"));
        view.override_needed = false;
        assert!(
            !view.line().contains("--allow-unsupported"),
            "{}",
            view.line()
        );
        let note = view.assistant_note("1.1.7").unwrap_or_default();
        assert!(!note.contains("  "), "{note}");
    }

    #[test]
    fn test_reuse_for_refuses_a_step_writing_another_application() -> TestResult {
        let target: IndividualAddress = "1.1.7".parse()?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let listed = device(Some("M-0004_A-D142-21-8848-O000A"))?;
        let grant = authorize(&real, target, Some(&listed), None, false)?;
        // The same program passes; an unlisted one in a later step does not.
        assert!(
            grant
                .reuse_for(target, Some(&listed), Some("M-0004_A-D142-21-8848-O000A"))
                .is_ok()
        );
        assert!(
            grant
                .reuse_for(target, Some(&listed), Some("M-0083_A-0120-10-0000"))
                .is_err()
        );
        assert!(
            grant
                .reuse_for("1.1.8".parse()?, Some(&listed), None)
                .is_err()
        );
        // A check that knew no application, forced, covers the program the
        // step finds.
        let bare = device(None)?;
        let forced = authorize(&real, target, Some(&bare), None, true)?;
        let reused = forced.reuse_for(target, Some(&bare), Some("M-0083_A-0120-10-0000"))?;
        assert_eq!(reused.status(), SupportStatus::Forced);
        Ok(())
    }
}
