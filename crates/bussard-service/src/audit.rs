//! The installation audit: the typed report behind `bussard audit` and the
//! `knx_audit` MCP tool (issues #93, #896).
//!
//! [`AuditReport`] is one object with the same sections on both surfaces:
//!
//! | Key | Contents |
//! |-----|----------|
//! | `model` | [`bussard_model::analyze`]'s output: counts, per-line devices, model gaps, one-sided-link findings, neutral info, provenance. |
//! | `masks` | Devices grouped by mask version with the capability row from [`bussard_mgmt::MaskProfile::capabilities`]. |
//! | `secure` | KNX Secure devices and, when a keyring was given, whether each has a tool-key entry. |
//! | `live` | `null` for a static audit; otherwise the gateway description, the scan delta, the traffic sample and `secure`: each Data Secure device probed with its keyring tool key ([`SecureProbe`]). |
//! | `products` | CLI only (absent from the MCP report): the product data the lock pins ([`ProductsReport`]). |
//!
//! The JSON is the serialised struct as a [`serde_json::Value`] (keys sorted),
//! which is what both surfaces print, so text, `--json` and MCP cannot drift.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::path::Path;
use std::time::{Duration, SystemTime};

use bussard_mgmt::MaskProfile;
use bussard_model::identity::IdentityCheck;
use bussard_model::{GroupAddress, IndividualAddress, Model, ModelAnalysis};
use bussard_transport::bus::BusHandle;
use bussard_transport::cemi::{Apdu, Destination, MessageCode};
use bussard_transport::knxnet::GatewayDescription;
use bussard_transport::{BusConnection, ConnectionConfig, Transport, TransportError};
use serde::Serialize;

use crate::identity::{self, HIDDEN_MASK};
use crate::secure::ToolKeys;
use crate::{Authorize, BusService, L4Options};

/// Version of the audit JSON contract. Bumped on a breaking change.
pub const AUDIT_FORMAT_VERSION: u32 = 1;

/// Two identical telegrams (same source, GA and payload) closer than this are
/// counted as a repetition even when the cEMI repeat flag is not available.
pub const DUPLICATE_WINDOW: Duration = Duration::from_millis(500);

/// Default traffic-sample window for a live audit.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// How long a live audit waits for the interface's DESCRIPTION_RESPONSE.
pub const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The whole audit report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditReport {
    /// [`AUDIT_FORMAT_VERSION`].
    pub format_version: u32,
    /// The static model analysis.
    pub model: ModelAnalysis,
    /// Devices per mask version with what bussard can do with them.
    pub masks: Vec<MaskRow>,
    /// KNX Secure devices and their keyring coverage.
    pub secure: SecureCoverage,
    /// The live part; `null` for a static audit.
    pub live: Option<LiveReport>,
    /// The product data the lock pins (CLI only; absent when `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub products: Option<ProductsReport>,
}

/// One row of the `masks` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaskRow {
    /// The mask as four hex digits; `null` when the device file records none.
    pub mask: Option<String>,
    /// The mask family label.
    pub family: &'static str,
    /// The medium label; `null` without a mask.
    pub medium: Option<&'static str>,
    /// Whether `plan`/`apply` support the mask; `null` without a mask.
    pub plan_apply: Option<bool>,
    /// Whether `flash` supports the mask; `null` without a mask.
    pub flash: Option<bool>,
    /// Whether `describe` supports the mask.
    pub describe: bool,
    /// Whether `reconstruct` supports the mask; `null` without a mask.
    pub reconstruct: Option<bool>,
    /// One line: what bussard can do with such a device.
    pub bussard_can: String,
    /// A caveat for the mask family.
    pub note: &'static str,
    /// The devices with this mask.
    pub devices: Vec<String>,
}

impl MaskRow {
    /// The capability row for `mask` (or for devices without a recorded mask).
    fn new(mask: Option<u16>, devices: Vec<String>) -> MaskRow {
        let Some(mask) = mask else {
            return MaskRow {
                mask: None,
                family: "unknown (no mask recorded)",
                medium: None,
                plan_apply: None,
                flash: None,
                describe: true,
                reconstruct: None,
                bussard_can: "unknown until the device is scanned".to_string(),
                note: "the device file records no product mask; `bussard scan` reads it",
                devices,
            };
        };
        let profile = MaskProfile::from_mask(mask);
        let caps = profile.capabilities();
        MaskRow {
            mask: Some(format!("{mask:04X}")),
            family: profile.family().label(),
            medium: Some(profile.medium().label()),
            plan_apply: Some(caps.plan_apply),
            flash: Some(caps.flash),
            describe: caps.describe,
            reconstruct: Some(caps.reconstruct),
            bussard_can: caps.summary(),
            note: caps.note,
            devices,
        }
    }
}

/// The static `secure` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecureCoverage {
    /// Whether a keyring was given.
    pub keyring_checked: bool,
    /// The model's KNX Secure devices.
    pub devices: Vec<SecureCoverageRow>,
    /// Devices with a keyring entry; `null` without a keyring.
    pub with_keyring_entry: Option<usize>,
    /// Devices without a keyring entry; `null` without a keyring.
    pub without_keyring_entry: Option<usize>,
}

/// One KNX Secure device of the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecureCoverageRow {
    /// The device address.
    pub address: String,
    /// The model name.
    pub name: String,
    /// The application declares Data Secure support.
    pub secure_capable: bool,
    /// The model records security as activated.
    pub activated: bool,
    /// Whether the keyring has a tool key for it; `null` without a keyring.
    pub keyring_entry: Option<bool>,
}

impl AuditReport {
    /// Builds the static (model-only) audit; `live` is `None`.
    ///
    /// `keyring_devices` is the list of individual addresses the `.knxkeys`
    /// keyring carries a tool key for, or `None` when no keyring was given (the
    /// coverage column is then `null`, never `false`).
    pub fn from_model(model: &Model, keyring_devices: Option<&[IndividualAddress]>) -> AuditReport {
        let analysis = bussard_model::analyze(model);

        let mut by_mask: BTreeMap<Option<u16>, Vec<String>> = BTreeMap::new();
        for (addr, loaded) in &model.devices {
            let mask = loaded
                .device
                .product
                .as_ref()
                .and_then(|p| p.mask.as_deref())
                .and_then(parse_mask);
            by_mask.entry(mask).or_default().push(addr.to_string());
        }
        let masks = by_mask
            .into_iter()
            .map(|(mask, devices)| MaskRow::new(mask, devices))
            .collect();

        let keyring: Option<BTreeSet<IndividualAddress>> =
            keyring_devices.map(|ias| ias.iter().copied().collect());
        let devices: Vec<SecureCoverageRow> = analysis
            .secure_devices
            .iter()
            .map(|d| SecureCoverageRow {
                address: d.address.clone(),
                name: d.name.clone(),
                secure_capable: d.secure_capable,
                activated: d.activated,
                keyring_entry: keyring.as_ref().map(|k| {
                    d.address
                        .parse::<IndividualAddress>()
                        .is_ok_and(|ia| k.contains(&ia))
                }),
            })
            .collect();
        let entries = |want: bool| {
            keyring.as_ref().map(|_| {
                devices
                    .iter()
                    .filter(|d| d.keyring_entry == Some(want))
                    .count()
            })
        };
        let secure = SecureCoverage {
            keyring_checked: keyring.is_some(),
            with_keyring_entry: entries(true),
            without_keyring_entry: entries(false),
            devices,
        };

        AuditReport {
            format_version: AUDIT_FORMAT_VERSION,
            model: analysis,
            masks,
            secure,
            live: None,
            products: None,
        }
    }
}

/// Parses a device file's `product.mask` (`"07B0"` or `"0x07B0"`).
fn parse_mask(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(hex, 16).ok()
}

/// The `products` section (lock v2, issue #228).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductsReport {
    /// Devices with a product but no pinned product data.
    pub unpinned: Vec<String>,
    /// Pinned archives missing from the project, with a recovery hint.
    pub missing_archives: Vec<String>,
    /// Pinned archives whose content changed.
    pub hash_mismatch: Vec<String>,
    /// Devices whose stored facts report another application than the lock pins.
    pub application_drift: Vec<String>,
}

impl ProductsReport {
    /// Devices whose product data the lock does not pin, pinned archives that
    /// are missing or changed, and devices whose stored facts
    /// (`.bussard/facts`) report another application id than the lock pins.
    /// Offline: reads the model directory only.
    pub fn from_dir(model: &Model, dir: &Path) -> ProductsReport {
        let unpinned = model
            .devices
            .iter()
            .filter(|(_, l)| {
                l.device
                    .product
                    .as_ref()
                    .is_some_and(|p| p.order_number.is_some())
                    && l.device.lock.product_sha256.is_none()
            })
            .map(|(a, _)| a.to_string())
            .collect();
        let mut missing_archives = Vec::new();
        let mut hash_mismatch = Vec::new();
        for entry in bussard_model::lock_products::lock_entries(dir) {
            let Some(file) = entry.file.as_deref() else {
                continue;
            };
            match bussard_model::sha256_file(&dir.join(file)) {
                Err(_) => missing_archives.push(format!(
                    "{file} ({})",
                    bussard_model::lock_products::recovery_hint(&entry)
                )),
                Ok((sha, _)) if !sha.eq_ignore_ascii_case(&entry.sha256) => {
                    hash_mismatch.push(format!("{file} (pinned {}, found {sha})", entry.sha256))
                }
                Ok(_) => {}
            }
        }
        let application_drift = model
            .devices
            .iter()
            .filter_map(|(address, loaded)| {
                let facts = bussard_model::facts::load_facts(dir, *address).ok()??;
                let check = IdentityCheck::compare(
                    Some(&loaded.device),
                    bussard_model::identity::ReportedIdentity {
                        mask: facts.mask,
                        application_id: facts.application_id,
                    },
                );
                check
                    .is_drift()
                    .then(|| format!("{address} ({})", check.differences.join("; ")))
            })
            .collect();
        ProductsReport {
            unpinned,
            missing_archives,
            hash_mismatch,
            application_drift,
        }
    }
}

/// The `live` section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LiveReport {
    /// The bus connection as the surface reports it (the MCP server's
    /// connection status; `{"state": "connected"}` for the CLI).
    pub bus: serde_json::Value,
    /// The interface's own description.
    pub gateway: GatewayReport,
    /// The scan delta; `null` from the MCP tool (`knx_find_devices` scans).
    pub scan: Option<ScanReport>,
    /// The Data Secure probe; `null` when the bus is not connected.
    pub secure: Option<SecureLiveReport>,
    /// The traffic sample.
    pub traffic: TrafficReport,
}

/// The `live.gateway` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayReport {
    /// The interface's endpoint.
    pub endpoint: Option<String>,
    /// The device name the interface reports.
    pub name: Option<String>,
    /// The interface's own individual address.
    pub individual_address: Option<String>,
    /// Total tunnelling slots.
    pub tunnels: Option<usize>,
    /// Slots in use; `null` when the interface reports no per-slot state.
    pub tunnels_in_use: Option<usize>,
    /// The per-slot state, when reported.
    pub tunnel_slots: Option<Vec<TunnelSlotRow>>,
    /// Why the description is unavailable; `null` when it was read.
    pub error: Option<String>,
}

/// One tunnelling slot of the interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelSlotRow {
    /// The slot's individual address.
    pub individual_address: String,
    /// Whether the slot is free.
    pub free: bool,
    /// Read outside a secure session, the bit says whether the slot needs
    /// credentials (Core 3/8/2 §7.5.4.8, issue #518).
    pub authorisation_required: bool,
    /// `"needs tunnelling credentials"` or `"open"`.
    pub access: &'static str,
    /// Whether the slot is usable.
    pub usable: bool,
}

impl GatewayReport {
    /// The section from a DESCRIPTION_RESPONSE.
    pub fn described(endpoint: Option<SocketAddrV4>, d: &GatewayDescription) -> GatewayReport {
        let capacity = d.tunnel_capacity();
        let slots_reported = d.tunnel_slots.is_some();
        GatewayReport {
            endpoint: endpoint.map(|e| e.to_string()),
            name: d.name.clone(),
            individual_address: d
                .individual_address
                .map(|raw| IndividualAddress::from_raw(raw).to_string()),
            tunnels: capacity.map(|c| c.total),
            tunnels_in_use: if slots_reported {
                capacity.map(|c| c.in_use)
            } else {
                None
            },
            tunnel_slots: d.tunnel_slots.as_ref().map(|slots| {
                slots
                    .iter()
                    .map(|s| TunnelSlotRow {
                        individual_address: IndividualAddress::from_raw(s.individual_address)
                            .to_string(),
                        free: s.free,
                        authorisation_required: s.authorisation_required,
                        access: if s.authorisation_required {
                            "needs tunnelling credentials"
                        } else {
                            "open"
                        },
                        usable: s.usable,
                    })
                    .collect()
            }),
            error: None,
        }
    }

    /// The section when the description could not be obtained (routing
    /// transport, timeout, …).
    pub fn unavailable(endpoint: Option<SocketAddrV4>, reason: String) -> GatewayReport {
        GatewayReport {
            endpoint: endpoint.map(|e| e.to_string()),
            name: None,
            individual_address: None,
            tunnels: None,
            tunnels_in_use: None,
            tunnel_slots: None,
            error: Some(reason),
        }
    }

    /// Asks the interface at `endpoint` to describe itself: one UDP exchange,
    /// no tunnel slot.
    pub async fn describe(endpoint: SocketAddrV4) -> GatewayReport {
        match bussard_transport::describe_gateway(endpoint, DESCRIBE_TIMEOUT).await {
            Ok(d) => GatewayReport::described(Some(endpoint), &d),
            Err(err) => GatewayReport::unavailable(Some(endpoint), err.to_string()),
        }
    }
}

/// One group telegram observed during the traffic sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledTelegram {
    /// When it was received.
    pub at: SystemTime,
    /// The sending device.
    pub source: IndividualAddress,
    /// The destination group address.
    pub ga: GroupAddress,
    /// The raw APDU payload (for duplicate detection).
    pub payload: Vec<u8>,
    /// The cEMI control field marked the frame as a repetition. `false` when
    /// the source does not carry the flag (the MCP ring).
    pub repeat_flag: bool,
}

/// Opens one tunnel connection to the gateway of `config` and closes it
/// again, so a full interface fails loudly with
/// [`TransportError::NoMoreConnections`] instead of a silent reconnect loop
/// (issue #105).
///
/// # Errors
///
/// The connect error.
pub async fn probe_tunnel(config: &ConnectionConfig) -> Result<(), TransportError> {
    let conn = Transport::connect(config).await?;
    let _ = conn.close().await;
    Ok(())
}

/// Collects the group telegrams indicated on the bus for `window`.
///
/// Only `L_Data.ind` frames count: the gateway's `L_Data.con` echo of our own
/// requests is not bus traffic.
pub async fn sample_traffic(handle: &BusHandle, window: Duration) -> Vec<SampledTelegram> {
    let mut sub = handle.subscribe();
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let frame = match tokio::time::timeout_at(deadline, sub.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        if frame.message_code != MessageCode::LDataInd {
            continue;
        }
        let cemi = &frame.frame.frame;
        let Destination::Group(ga) = cemi.destination else {
            continue;
        };
        let payload = match &cemi.apdu {
            Apdu::GroupValueWrite(data) | Apdu::GroupValueResponse(data) => data.bytes(),
            Apdu::GroupValueRead => Vec::new(),
            _ => continue,
        };
        out.push(SampledTelegram {
            at: frame.frame.received_at,
            source: cemi.source,
            ga,
            payload,
            repeat_flag: cemi.control1.repeated,
        });
    }
    out
}

/// The `live.traffic` section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrafficReport {
    /// The sample window.
    pub window_seconds: u64,
    /// Group telegrams in the sample.
    pub telegrams: usize,
    /// Per GA: count and repetition rate.
    pub per_ga: Vec<GaTraffic>,
    /// GAs seen on the bus with no listener in the model.
    pub sender_no_listener: Vec<UnheardGa>,
    /// Source addresses the model does not know.
    pub unknown_sources: Vec<String>,
}

/// One GA of the traffic sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GaTraffic {
    /// The group address.
    pub ga: String,
    /// Its model name.
    pub name: Option<String>,
    /// Telegrams to it.
    pub telegrams: usize,
    /// Of those, repetitions.
    pub repeated: usize,
    /// `repeated / telegrams`, rounded to three decimals.
    pub repeat_rate: f64,
    /// The sending devices.
    pub sources: Vec<String>,
}

/// A GA seen on the bus that no modelled device listens to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnheardGa {
    /// The group address.
    pub ga: String,
    /// Its model name.
    pub name: Option<String>,
    /// Whether the model declares the GA.
    pub in_model: bool,
}

impl TrafficReport {
    /// Builds the section from the sampled telegrams.
    ///
    /// Per GA it reports the telegram count and the repetition rate (a frame
    /// the cEMI repeat flag marks, or an identical telegram from the same
    /// source within [`DUPLICATE_WINDOW`]). It also lists GAs seen on the bus
    /// with no listener in the model and source addresses the model does not
    /// know.
    pub fn new(model: &Model, window: Duration, telegrams: &[SampledTelegram]) -> TrafficReport {
        let mut listened: BTreeSet<GroupAddress> = BTreeSet::new();
        for links in model.links.links.values() {
            for link in links {
                listened.extend(link.listen.iter().copied());
            }
        }

        let mut sorted: Vec<&SampledTelegram> = telegrams.iter().collect();
        sorted.sort_by_key(|t| t.at);

        #[derive(Default)]
        struct Stats {
            telegrams: usize,
            repeated: usize,
            sources: BTreeSet<IndividualAddress>,
        }
        let mut per_ga: BTreeMap<GroupAddress, Stats> = BTreeMap::new();
        let mut last_seen: BTreeMap<(IndividualAddress, GroupAddress), (SystemTime, Vec<u8>)> =
            BTreeMap::new();
        let mut unknown_sources: BTreeSet<IndividualAddress> = BTreeSet::new();

        for t in sorted {
            let stats = per_ga.entry(t.ga).or_default();
            stats.telegrams += 1;
            stats.sources.insert(t.source);
            let duplicate = last_seen
                .get(&(t.source, t.ga))
                .is_some_and(|(at, payload)| {
                    *payload == t.payload
                        && t.at.duration_since(*at).unwrap_or(Duration::ZERO) <= DUPLICATE_WINDOW
                });
            if t.repeat_flag || duplicate {
                stats.repeated += 1;
            }
            last_seen.insert((t.source, t.ga), (t.at, t.payload.clone()));
            if !model.devices.contains_key(&t.source) {
                unknown_sources.insert(t.source);
            }
        }

        let name = |ga: &GroupAddress| model.groups.groups.get(ga).map(|g| g.name.clone());
        TrafficReport {
            window_seconds: window.as_secs(),
            telegrams: telegrams.len(),
            per_ga: per_ga
                .iter()
                .map(|(ga, s)| GaTraffic {
                    ga: ga.to_string(),
                    name: name(ga),
                    telegrams: s.telegrams,
                    repeated: s.repeated,
                    repeat_rate: if s.telegrams == 0 {
                        0.0
                    } else {
                        (s.repeated as f64 / s.telegrams as f64 * 1000.0).round() / 1000.0
                    },
                    sources: s.sources.iter().map(|a| a.to_string()).collect(),
                })
                .collect(),
            sender_no_listener: per_ga
                .keys()
                .filter(|ga| !listened.contains(ga))
                .map(|ga| UnheardGa {
                    ga: ga.to_string(),
                    name: name(ga),
                    in_model: model.groups.groups.contains_key(ga),
                })
                .collect(),
            unknown_sources: unknown_sources.iter().map(|a| a.to_string()).collect(),
        }
    }
}

/// The outcome of a [`SecureProbe`], serialised as its snake_case word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureProbeStatus {
    /// Read with the keyring tool key.
    ReachableSecured,
    /// Plain reads refused and the tool key was not accepted.
    KeyRefused,
    /// Plain reads refused and the keyring has no tool key for it.
    NotInKeyring,
    /// Plain reads refused; no keyring was given.
    PlainReadsRefused,
    /// Answers in the clear (not activated).
    Plain,
    /// Did not answer.
    NotAnswering,
}

impl SecureProbeStatus {
    /// The JSON word.
    pub fn as_str(self) -> &'static str {
        match self {
            SecureProbeStatus::ReachableSecured => "reachable_secured",
            SecureProbeStatus::KeyRefused => "key_refused",
            SecureProbeStatus::NotInKeyring => "not_in_keyring",
            SecureProbeStatus::PlainReadsRefused => "plain_reads_refused",
            SecureProbeStatus::Plain => "plain",
            SecureProbeStatus::NotAnswering => "not_answering",
        }
    }
}

/// What a live audit saw of one KNX Data Secure device (issue #203).
///
/// A Data Secure-activated device answers a plain descriptor read with mask
/// `FFFF` and drops every other plain read, so the live audit probes it with
/// the tool key from the keyring, as `describe --keyring` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureProbe {
    /// The device address.
    pub address: IndividualAddress,
    /// The model name.
    pub name: String,
    /// Whether the keyring lists the device; `None` without a keyring.
    pub in_keyring: Option<bool>,
    /// The mask the plain descriptor read returned (`FFFF` for an activated
    /// device); `None` when the plain probe was not answered.
    pub plain_mask: Option<u16>,
    /// The mask the secured descriptor read returned: `None` when no secured
    /// probe ran, `Some(None)` when it ran but was not answered.
    pub secured_mask: Option<Option<u16>>,
}

impl SecureProbe {
    /// Completes the probe of `address` after its plain descriptor read
    /// returned `plain_mask`: a secured read follows when the keyring lists the
    /// device with a tool key and the plain read was hidden or unanswered (a
    /// device that answered in the clear with a real mask is not activated; a
    /// secured probe would only time out).
    pub async fn run(
        service: &BusService,
        address: IndividualAddress,
        name: String,
        keys: &ToolKeys,
        plain_mask: Option<u16>,
        options: &L4Options,
    ) -> SecureProbe {
        let listed = keys.lists(address);
        let secured_mask = match keys.tool_key(address) {
            Some(key) if listed && plain_mask.is_none_or(|m| m == HIDDEN_MASK) => Some(
                identity::identify_secured(service, address, options, key)
                    .await
                    .map(|id| id.mask),
            ),
            _ => None,
        };
        SecureProbe {
            address,
            name,
            in_keyring: keys.keyring_given().then_some(listed),
            plain_mask,
            secured_mask,
        }
    }

    /// Whether the device answered the secured probe.
    pub fn reachable_secured(&self) -> Option<bool> {
        self.secured_mask.map(|m| m.is_some())
    }

    /// Whether the plain descriptor read came back with the hidden mask (the
    /// device refuses plain management); `None` when the plain probe was not
    /// answered.
    pub fn plain_reads_refused(&self) -> Option<bool> {
        self.plain_mask.map(|m| m == HIDDEN_MASK)
    }

    /// Whether the device showed itself Data Secure-activated in this run.
    pub fn activated(&self) -> bool {
        self.plain_reads_refused() == Some(true) || self.reachable_secured() == Some(true)
    }

    /// The real mask, when one was read (secured, or plain and not hidden).
    pub fn mask(&self) -> Option<u16> {
        match (self.secured_mask, self.plain_mask) {
            (Some(Some(mask)), _) => Some(mask),
            (_, Some(mask)) if mask != HIDDEN_MASK => Some(mask),
            _ => None,
        }
    }

    /// The outcome.
    pub fn status(&self) -> SecureProbeStatus {
        match (self.reachable_secured(), self.plain_reads_refused()) {
            (Some(true), _) => SecureProbeStatus::ReachableSecured,
            (Some(false), Some(true)) => SecureProbeStatus::KeyRefused,
            (_, Some(true)) if self.in_keyring == Some(false) => SecureProbeStatus::NotInKeyring,
            (_, Some(true)) => SecureProbeStatus::PlainReadsRefused,
            (_, Some(false)) => SecureProbeStatus::Plain,
            (_, None) => SecureProbeStatus::NotAnswering,
        }
    }

    /// The device's row in the `live.secure` section.
    pub fn row(&self) -> SecureProbeRow {
        SecureProbeRow {
            address: self.address.to_string(),
            name: self.name.clone(),
            status: self.status(),
            activated: self.activated(),
            reachable_secured: self.reachable_secured(),
            plain_reads_refused: self.plain_reads_refused(),
            in_keyring: self.in_keyring,
            mask: self.mask().map(|m| format!("{m:04X}")),
        }
    }
}

/// One row of the `live.secure` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecureProbeRow {
    /// The device address.
    pub address: String,
    /// The model name.
    pub name: String,
    /// The outcome.
    pub status: SecureProbeStatus,
    /// See [`SecureProbe::activated`].
    pub activated: bool,
    /// See [`SecureProbe::reachable_secured`].
    pub reachable_secured: Option<bool>,
    /// See [`SecureProbe::plain_reads_refused`].
    pub plain_reads_refused: Option<bool>,
    /// Whether the keyring lists the device; `null` without a keyring.
    pub in_keyring: Option<bool>,
    /// The real mask, when one was read.
    pub mask: Option<String>,
}

/// The `live.secure` section: one row per probed Data Secure device
/// (issue #203).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecureLiveReport {
    /// One row per probed device.
    pub devices: Vec<SecureProbeRow>,
    /// Devices read with the tool key.
    pub reachable_secured: usize,
    /// Devices that showed themselves activated.
    pub activated: usize,
    /// Activated devices the keyring has no tool key for.
    pub not_in_keyring: usize,
    /// Devices that refused the tool key.
    pub key_refused: usize,
}

impl SecureLiveReport {
    /// Builds the section from the probes.
    pub fn new(probes: &[SecureProbe]) -> SecureLiveReport {
        let count =
            |status: SecureProbeStatus| probes.iter().filter(|p| p.status() == status).count();
        SecureLiveReport {
            devices: probes.iter().map(SecureProbe::row).collect(),
            reachable_secured: count(SecureProbeStatus::ReachableSecured),
            activated: probes.iter().filter(|p| p.activated()).count(),
            not_in_keyring: count(SecureProbeStatus::NotInKeyring),
            key_refused: count(SecureProbeStatus::KeyRefused),
        }
    }
}

/// The options of the MCP server's Secure probe: the bus's group source,
/// discovery timeouts, no authorize.
pub fn secure_probe_options(service: &BusService) -> L4Options {
    L4Options::read_only(service.handle().group_source())
        .with_timeouts(bussard_mgmt::Timeouts::discovery())
        .with_authorize(Authorize::Skip)
}

/// Whether the live audit probes `address` as a Data Secure device without
/// a plain scan first: the model carries a security block or the keyring
/// lists it.
pub fn is_secure_candidate(model: &Model, keys: &ToolKeys, address: IndividualAddress) -> bool {
    keys.lists(address)
        || model
            .devices
            .get(&address)
            .is_some_and(|l| l.device.security.is_some())
}

/// The `live.scan` section (CLI only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Modelled devices probed.
    pub probed: usize,
    /// Of those, the ones that answered.
    pub answered: usize,
    /// Per line.
    pub lines: Vec<ScanLine>,
    /// What the scan does not cover.
    pub note: &'static str,
}

/// One line of the scan delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanLine {
    /// The line, as `"1.1"`.
    pub line: String,
    /// Devices that answered.
    pub answered: Vec<AnsweredDevice>,
    /// Devices that did not answer.
    pub not_answering: Vec<SilentDevice>,
}

/// A modelled device that answered the scan probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnsweredDevice {
    /// The device address.
    pub address: String,
    /// The model name.
    pub name: String,
    /// The mask read from the bus (`FFFF` when Data Secure hides it).
    pub mask: String,
    /// The mask the model records.
    pub model_mask: Option<String>,
    /// Whether the two masks differ.
    pub mask_mismatch: bool,
    /// What bussard can do with the device.
    pub bussard_can: String,
    /// The Secure probe's outcome, for a Data Secure candidate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureProbeStatus>,
    /// The identity verdict against the lock (issue #228, item 5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityCheck>,
}

/// A modelled device that did not answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SilentDevice {
    /// The device address.
    pub address: String,
    /// The model name.
    pub name: String,
}

/// The note on [`ScanReport::note`].
const SCAN_NOTE: &str = "only modelled addresses are probed; devices on the bus but not in the model \
                 show up as unknown sources in the traffic sample, or with `bussard scan`";

/// Probes every modelled device and reports the delta per line, plus the
/// KNX Data Secure probe of every Secure device (issue #203).
///
/// Probes are sequential (one connection-oriented session at a time, TP1
/// etiquette) and spaced by at least `min_interval`. Each device gets the
/// plain `scan` probe; a Data Secure device (one that answers mask `FFFF`,
/// carries a `security:` block in the model, or is in the keyring) whose tool
/// key the keyring holds is then probed secured, as `describe --keyring` reads
/// it. `progress` is called with each address before its probe. `dir` is the
/// model directory the identity facts are stored under.
pub async fn scan_model_devices(
    service: &BusService,
    model: &Model,
    dir: &Path,
    source: IndividualAddress,
    keys: &ToolKeys,
    min_interval: Duration,
    mut progress: impl FnMut(IndividualAddress),
) -> (ScanReport, Vec<SecureProbe>) {
    let mut lines: BTreeMap<(u8, u8), ScanLine> = BTreeMap::new();
    let mut answered_count = 0usize;
    let mut secure_probes = Vec::new();
    let options = L4Options::discovery(source);

    for (addr, loaded) in &model.devices {
        progress(*addr);
        let started = tokio::time::Instant::now();
        let plain_mask = identity::probe(service, *addr, &options, None)
            .await
            .map(|(id, _)| id.mask);
        let model_mask = loaded.device.product.as_ref().and_then(|p| p.mask.clone());

        let probe = if plain_mask == Some(HIDDEN_MASK) || is_secure_candidate(model, keys, *addr) {
            Some(
                SecureProbe::run(
                    service,
                    *addr,
                    loaded.device.name.clone(),
                    keys,
                    plain_mask,
                    &options,
                )
                .await,
            )
        } else {
            None
        };

        // The mask to report: the secured read's when there is one.
        let bus_mask = probe
            .as_ref()
            .and_then(SecureProbe::mask)
            .or(plain_mask.filter(|_| probe.is_none()));
        let line = lines
            .entry((addr.area(), addr.line()))
            .or_insert_with(|| ScanLine {
                line: format!("{}.{}", addr.area(), addr.line()),
                answered: Vec::new(),
                not_answering: Vec::new(),
            });
        if plain_mask.is_some() || bus_mask.is_some() {
            answered_count += 1;
            let bus_mask_text = bus_mask.map(|m| format!("{m:04X}"));
            let mask_mismatch = match (model_mask.as_deref(), bus_mask_text.as_deref()) {
                (Some(m), Some(bus)) => {
                    !m.trim().trim_start_matches("0x").eq_ignore_ascii_case(bus)
                }
                _ => false,
            };
            line.answered.push(AnsweredDevice {
                address: addr.to_string(),
                name: loaded.device.name.clone(),
                mask: bus_mask_text.unwrap_or_else(|| format!("{HIDDEN_MASK:04X}")),
                model_mask,
                mask_mismatch,
                bussard_can: match bus_mask {
                    Some(m) => MaskProfile::from_mask(m).capabilities().summary(),
                    None => {
                        "unknown: Data Secure hides the mask (pass --keyring with its tool key)"
                            .to_string()
                    }
                },
                secure: probe.as_ref().map(SecureProbe::status),
                identity: bus_mask.map(|mask| {
                    crate::scan::observe_identity(dir, true, *addr, mask, Some(&loaded.device))
                }),
            });
        } else {
            line.not_answering.push(SilentDevice {
                address: addr.to_string(),
                name: loaded.device.name.clone(),
            });
        }
        secure_probes.extend(probe);
        let elapsed = started.elapsed();
        if elapsed < min_interval {
            tokio::time::sleep(min_interval - elapsed).await;
        }
    }

    let scan = ScanReport {
        probed: model.devices.len(),
        answered: answered_count,
        lines: lines.into_values().collect(),
        note: SCAN_NOTE,
    };
    (scan, secure_probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_probe(
        in_keyring: Option<bool>,
        plain_mask: Option<u16>,
        secured_mask: Option<Option<u16>>,
    ) -> Result<SecureProbe, Box<dyn std::error::Error>> {
        Ok(SecureProbe {
            address: "1.1.10".parse()?,
            name: "Dimmer".to_string(),
            in_keyring,
            plain_mask,
            secured_mask,
        })
    }

    #[test]
    fn test_secure_probe_status_covers_every_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let secured = secure_probe(Some(true), Some(0xFFFF), Some(Some(0x07B0)))?;
        assert_eq!(secured.status(), SecureProbeStatus::ReachableSecured);
        assert_eq!(secured.mask(), Some(0x07B0));
        assert!(secured.activated());
        let refused = secure_probe(Some(true), Some(0xFFFF), Some(None))?;
        assert_eq!(refused.status(), SecureProbeStatus::KeyRefused);
        assert_eq!(refused.mask(), None);
        let unlisted = secure_probe(Some(false), Some(0xFFFF), None)?;
        assert_eq!(unlisted.status(), SecureProbeStatus::NotInKeyring);
        let unchecked = secure_probe(None, Some(0xFFFF), None)?;
        assert_eq!(unchecked.status(), SecureProbeStatus::PlainReadsRefused);
        let plain = secure_probe(Some(false), Some(0x07B0), None)?;
        assert_eq!(plain.status(), SecureProbeStatus::Plain);
        assert!(!plain.activated());
        let silent = secure_probe(None, None, None)?;
        assert_eq!(silent.status(), SecureProbeStatus::NotAnswering);
        let report = SecureLiveReport::new(&[secured, refused, unlisted]);
        assert_eq!(report.reachable_secured, 1);
        assert_eq!(report.activated, 3);
        assert_eq!(report.not_in_keyring, 1);
        assert_eq!(report.key_refused, 1);
        Ok(())
    }

    #[test]
    fn test_secure_status_as_str_matches_serde() -> Result<(), Box<dyn std::error::Error>> {
        for status in [
            SecureProbeStatus::ReachableSecured,
            SecureProbeStatus::KeyRefused,
            SecureProbeStatus::NotInKeyring,
            SecureProbeStatus::PlainReadsRefused,
            SecureProbeStatus::Plain,
            SecureProbeStatus::NotAnswering,
        ] {
            assert_eq!(serde_json::to_value(status)?, status.as_str());
        }
        Ok(())
    }

    #[test]
    fn test_parse_mask_accepts_both_spellings() {
        assert_eq!(parse_mask("07B0"), Some(0x07B0));
        assert_eq!(parse_mask("0x0705"), Some(0x0705));
        assert_eq!(parse_mask("nope"), None);
    }

    #[test]
    fn test_traffic_report_counts_repeats_and_orphans() -> Result<(), Box<dyn std::error::Error>> {
        let model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ga: GroupAddress = "1/0/1".parse()?;
        let src: IndividualAddress = "1.1.9".parse()?;
        let at = |ms: u64, payload: u8, repeat_flag: bool| SampledTelegram {
            at: t0 + Duration::from_millis(ms),
            source: src,
            ga,
            payload: vec![payload],
            repeat_flag,
        };
        let telegrams = vec![
            at(0, 1, false),
            // Identical within the duplicate window: a repetition.
            at(100, 1, false),
            // Different payload later: not a repetition.
            at(5_000, 0, false),
            // Flagged by the cEMI control field.
            at(6_000, 7, true),
        ];
        let report = TrafficReport::new(&model, Duration::from_secs(30), &telegrams);
        assert_eq!(report.telegrams, 4);
        assert_eq!(report.per_ga[0].repeated, 2);
        assert_eq!(report.per_ga[0].repeat_rate, 0.5);
        assert_eq!(report.sender_no_listener[0].ga, "1/0/1");
        assert_eq!(report.unknown_sources, ["1.1.9"]);
        Ok(())
    }

    #[test]
    fn test_gateway_report_distinguishes_unreported_slots() {
        let d = GatewayDescription {
            additional_individual_addresses: vec![0x10F1, 0x10F2],
            ..Default::default()
        };
        let report = GatewayReport::described(None, &d);
        assert_eq!(report.tunnels, Some(2));
        assert_eq!(report.tunnels_in_use, None);
    }
}
