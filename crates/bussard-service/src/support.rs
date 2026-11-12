//! Whether bussard supports writing a device (issue #1089): the verdict of
//! the supported-device list ([`bussard_model::supported`]) for a device's
//! application program, and the gate every device write passes.
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

pub use bussard_model::supported::{Evidence, SupportedEntry, SupportedList, application_ref_of};

/// Why a device is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// Its application program is not on the list.
    NotListed,
    /// The project pins no application for it, so it is unknown.
    NoProductData,
}

impl UnsupportedReason {
    /// The reason in words.
    pub fn text(self) -> &'static str {
        match self {
            UnsupportedReason::NotListed => "application not on the list",
            UnsupportedReason::NoProductData => "no product data pinned, application unknown",
        }
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// The verdict of the supported-device list for one application program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// The application is on the list.
    Supported {
        /// The application id, ten hex digits.
        application_id: String,
        /// The application ref prefix (`M-0004_A-20DE-22`).
        application: String,
        /// The list's name for it.
        name: String,
        /// Why it is on the list.
        evidence: Evidence,
    },
    /// It is not.
    Unsupported {
        /// The application id, when known.
        application_id: Option<String>,
        /// The application ref, when known.
        application: Option<String>,
        /// Manufacturer and product, from the project, when known.
        name: Option<String>,
        /// Why.
        reason: UnsupportedReason,
    },
}

impl Support {
    /// Whether the application is on the list.
    pub fn is_supported(&self) -> bool {
        matches!(self, Support::Supported { .. })
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
                evidence,
            } => SupportView {
                status: SupportStatus::Supported,
                evidence: Some(*evidence),
                reason: None,
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
            } => SupportView {
                status: SupportStatus::Unsupported,
                evidence: None,
                reason: Some(reason.text()),
                application: application.clone(),
                application_id: application_id.clone(),
                name: name.clone(),
                override_needed: false,
            },
        }
    }
}

/// The verdict as JSON: `{ status, evidence | reason, application,
/// application_id, name }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportView {
    /// `supported` or `unsupported` (a verdict is never `forced`).
    pub status: SupportStatus,
    /// Why it is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// Why it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
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
    /// Whether the device is on the list.
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

    /// One line for a plan or a device view: `supported (capture):
    /// M-0004_A-20DE-22 (Jung 230021SU switch actuator)`, or `not on the
    /// supported list (application not on the list): M-0083_A-0120-10 (MDT
    /// AKS-0816.03)`, ending `; writes need --allow-unsupported` when a write
    /// on this gateway is refused without it.
    pub fn line(&self) -> String {
        let what = self.what();
        match (self.evidence, self.reason) {
            (Some(evidence), _) => format!("supported ({evidence}): {what}"),
            (None, reason) => format!(
                "not on the supported list ({}): {what}{}",
                reason.unwrap_or("application not on the list"),
                if self.override_needed {
                    "; writes need --allow-unsupported"
                } else {
                    ""
                }
            ),
        }
    }

    /// What the assistant puts to the human before a write of an
    /// unsupported device (issue #1089), or `None` for a supported one.
    pub fn assistant_note(&self, target: &str) -> Option<String> {
        if self.is_supported() {
            return None;
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
        };
    };
    match list.lookup(id) {
        Some(entry) => Support::Supported {
            application_id: entry.application_id.clone(),
            application: entry.application(),
            name: entry.name.clone(),
            evidence: entry.evidence,
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

    /// The line a plan and a prompt carry when the device is not on the
    /// list: `not on the supported list, forced`, or that a loopback gateway
    /// does not refuse it. `None` for a supported device.
    pub fn plan_line(&self) -> Option<String> {
        match self.status {
            SupportStatus::Supported => None,
            SupportStatus::Forced => Some(format!(
                "{}: not on the supported list, forced ({})",
                self.target,
                self.verdict.line()
            )),
            SupportStatus::Unsupported => Some(format!(
                "{}: not on the supported list; written because the gateway is loopback ({})",
                self.target,
                self.verdict.line()
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
    /// devices`.
    pub fn sentence(&self) -> String {
        format!(
            "{} runs {}, which is not on bussard's list of supported devices",
            self.target,
            self.verdict.view().what()
        )
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
                        evidence = \"capture\"\nnote = \"#126\"\n";

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
        }
    }

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
                evidence: Evidence::Capture,
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
    fn test_verdict_of_a_selected_program_uses_the_embedded_list() {
        assert!(verdict(None, Some("M-0004_A-20DE-22-C7D8-O000A")).is_supported());
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
        assert!(
            grant
                .plan_line()
                .is_some_and(|l| l.contains("not on the supported list, forced"))
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
            Some("M-0004_A-20DE-22-C7D8-O000A"),
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
        let mut device = device(Some("M-0004_A-20DE-22-C7D8-O000A"))?;
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
        let listed = device(Some("M-0004_A-20DE-22-C7D8-O000A"))?;
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let target: IndividualAddress = "1.1.7".parse()?;
        assert!(
            authorize(
                &real,
                target,
                Some(&unlisted),
                Some("M-0004_A-20DE-22-C7D8-O000A"),
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
        let listed = device(Some("M-0004_A-20DE-22-C7D8-O000A"))?;
        let grant = authorize(&real, target, Some(&listed), None, false)?;
        // The same program passes; an unlisted one in a later step does not.
        assert!(
            grant
                .reuse_for(target, Some(&listed), Some("M-0004_A-20DE-22-C7D8-O000A"))
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
