//! The live state of one device, read over the bus (issues #391, #747).
//!
//! `bussard status <ADDRESS>` and `knx_show_device {live: true}` both read it
//! with [`read_live_status`] and build the report with [`status_report`]: the
//! device's mask and its identity against `bussard.lock`, and for a KNX IP
//! interface or router the KNXnet/IP parameter object (object type 11): the
//! IP address in use and how it was assigned, the configured method and
//! static settings, the MAC address, the friendly name, the tunnelling
//! addresses, the capabilities and the device state. What it read is kept
//! with the device facts (`.bussard/facts/<ia>.toml`) and compared with the
//! device file's `[knxnet]` table.
//!
//! Read-only on the bus: a descriptor read, the facts reads `describe` makes
//! (without the property descriptions) and property value reads. No
//! KNXnet/IP Secure property (PID 91 and up) is read. On a Data Secure device
//! read with its tool key, the security failures log, report and report
//! control (PID 55, 57, 58) are read too (issue #533).

use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::knxnet::{KnxnetConfig, KnxnetFacts};
use bussard_model::schema::Device;

use crate::ServiceError;
use crate::bus::Authorize;
use crate::facts::{FactsCache, FactsWant};

/// What one live status session read.
#[derive(Debug, Clone)]
pub struct LiveStatus {
    /// The mask version.
    pub mask: u16,
    /// The application id the device facts carry, when known.
    pub application_id: Option<String>,
    /// The KNXnet/IP parameter object; `None` on a device without one.
    pub knxnet: Option<KnxnetFacts>,
    /// Why the KNXnet/IP object could not be read, when it could not.
    pub knxnet_error: Option<String>,
    /// The Data Secure diagnostics, on a secured session.
    pub security: Option<bussard_download::SecurityDiagnostics>,
}

/// The authorize of a read-only session: skipped (with the key deferred)
/// when the facts say the device never answers `A_Authorize` (the deferred
/// key corrects a stale verdict on the same connection), the best-effort
/// free-access authorize otherwise.
pub fn read_only_authorize(facts: &mut FactsCache, target: IndividualAddress) -> Authorize {
    let key = bussard_mgmt::apci::FREE_ACCESS_KEY;
    if facts.may_skip_authorize(target) {
        facts.defer_authorize(key);
        Authorize::Skip
    } else {
        Authorize::BestEffort(key)
    }
}

/// Reads the descriptor, the device facts (object table, application id) and
/// the KNXnet/IP parameter object, which is stored with the facts; on a
/// secured session also the Data Secure diagnostics.
///
/// # Errors
///
/// A [`ServiceError`] when the descriptor or the interface objects cannot be
/// read, or the device hides its mask. A KNXnet/IP object that cannot be
/// read is reported in [`LiveStatus::knxnet_error`] instead.
pub async fn read_live_status<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
) -> Result<LiveStatus, ServiceError> {
    let target = l4.target();
    let mask = bussard_mgmt::read_device_descriptor(l4)
        .await
        .map_err(|e| {
            ServiceError::context(format!("reading the device descriptor of {target}"), e)
        })?;
    if mask == crate::identity::HIDDEN_MASK {
        return Err(ServiceError::Refused(format!(
            "{target} hides its mask (FFFF): it is secured and refuses plain management"
        )));
    }
    let mut established = facts
        .establish(l4, mask, FactsWant::Table)
        .await
        .map_err(|e| {
            ServiceError::context(format!("reading the interface objects of {target}"), e)
        })?;
    let application_id = established
        .record
        .as_ref()
        .and_then(|r| r.application_id.clone());
    let (knxnet, knxnet_error) =
        match crate::knxnet::read_knxnet_with_facts(l4, facts, &mut established).await {
            Ok(knxnet) => (knxnet, None),
            Err(err) => (None, Some(err.to_string())),
        };
    // Issue #533: a secured session also reads the failures log and report.
    let security = if l4.is_secure() {
        match bussard_download::read_security_diagnostics(l4).await {
            Ok(diag) => Some(diag),
            Err(err) => Some(bussard_download::SecurityDiagnostics {
                notes: vec![format!("Data Secure diagnostics not read: {err}")],
                ..Default::default()
            }),
        }
    } else {
        None
    };
    Ok(LiveStatus {
        mask,
        application_id,
        knxnet,
        knxnet_error,
        security,
    })
}

/// One device's live state in one shape (issue #904): `bussard status
/// <ADDRESS> --json` and the `live` part of `knx_show_device {live: true}`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusReport {
    /// Always `true`: the device was read.
    pub ok: bool,
    /// The device address.
    pub address: String,
    /// Whether it was read under KNX Data Secure.
    pub secured: bool,
    /// The device's name in the model, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The mask version, `0021`.
    pub mask: String,
    /// The system type of the mask.
    pub system_type: String,
    /// The identity verdict against `bussard.lock`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
    /// What the KNXnet/IP parameter object reported; absent on a device
    /// without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knxnet: Option<KnxnetFacts>,
    /// The device file's `[knxnet]` table, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_knxnet: Option<KnxnetConfig>,
    /// Where the device differs from `[knxnet]`, one sentence each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub knxnet_drift: Vec<String>,
    /// The Data Secure diagnostics (PID 55, 57, 58), read on a device
    /// managed with its tool key (issue #533).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<bussard_download::SecurityDiagnostics>,
    /// The state in words, names first.
    pub sentences: Vec<String>,
    /// The KNXnet/IP settings, one `label: value` line each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub knxnet_lines: Vec<String>,
    /// Why the KNXnet/IP parameter object was not read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knxnet_error: Option<String>,
}

impl crate::report::Report for StatusReport {
    const SCHEMA: u32 = 2;
}

/// The state of `report` in words, names first.
fn sentences(target: IndividualAddress, report: &StatusReport) -> Vec<String> {
    let who = match &report.name {
        Some(name) => format!("{name} ({target})"),
        None => target.to_string(),
    };
    let mut sentences = vec![format!(
        "{who} answers with mask {} ({}).",
        report.mask, report.system_type
    )];
    if let Some(check) = &report.identity {
        sentences.push(format!("{}.", crate::identity_line(target, check)));
    }
    match (&report.knxnet, &report.knxnet_error) {
        (Some(_), _) if report.model_knxnet.is_some() && report.knxnet_drift.is_empty() => {
            sentences.push(
                "It is a KNX IP interface; its KNXnet/IP settings match [knxnet] in its device \
                 file."
                    .to_string(),
            )
        }
        (Some(_), _) if report.model_knxnet.is_some() => sentences.push(format!(
            "It is a KNX IP interface; its KNXnet/IP settings differ from [knxnet] in its \
             device file: {}.",
            report.knxnet_drift.join("; ")
        )),
        (Some(_), _) => sentences.push(
            "It is a KNX IP interface; `knxnet_lines` lists its IP settings, tunnelling \
             addresses and state."
                .to_string(),
        ),
        (None, Some(err)) => sentences.push(format!(
            "Its KNXnet/IP parameter object was not read ({err})."
        )),
        (None, None) => {}
    }
    sentences
}

/// Builds the report from what the session read and the device's file
/// (`device`, when the model has one): the identity verdict against the
/// lock and the `[knxnet]` drift.
pub fn status_report(
    target: IndividualAddress,
    device: Option<&Device>,
    read: &LiveStatus,
    secured: bool,
) -> StatusReport {
    let identity = IdentityCheck::compare(
        device,
        ReportedIdentity {
            mask: bussard_model::facts::format_mask(read.mask),
            application_id: read.application_id.clone(),
        },
    );
    let model_knxnet = device.and_then(|d| d.knxnet.clone());
    let knxnet_drift = match (&read.knxnet, &model_knxnet) {
        (Some(facts), Some(config)) => facts.drift(config),
        _ => Vec::new(),
    };
    let mut report = StatusReport {
        ok: true,
        address: target.to_string(),
        secured,
        name: device.map(|d| d.name.clone()).filter(|n| !n.is_empty()),
        mask: bussard_model::facts::format_mask(read.mask),
        system_type: bussard_mgmt::system_type(read.mask).to_string(),
        identity: Some(identity),
        knxnet: read.knxnet.clone(),
        model_knxnet,
        knxnet_drift,
        security: read.security.clone(),
        sentences: Vec::new(),
        knxnet_lines: read
            .knxnet
            .as_ref()
            .map(|k| {
                k.lines()
                    .into_iter()
                    .map(|(label, value)| format!("{label}: {value}"))
                    .collect()
            })
            .unwrap_or_default(),
        knxnet_error: read.knxnet_error.clone(),
    };
    report.sentences = sentences(target, &report);
    report
}
