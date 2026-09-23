//! The installation audit: the shared report builder behind `bussard audit`
//! and the `knx_audit` MCP tool (issue #93).
//!
//! The report is one JSON object with the same sections on both surfaces:
//!
//! | Key | Contents |
//! |-----|----------|
//! | `model` | [`bussard_model::analysis::analyze`]'s output: counts, per-line devices, model gaps, one-sided-link findings, neutral info, provenance. |
//! | `masks` | Devices grouped by mask version with the capability row from [`bussard_mgmt::MaskProfile::capabilities`]. |
//! | `secure` | KNX Secure devices and, when a keyring was given, whether each has a tool-key entry. |
//! | `live` | `null` for a static audit; otherwise the gateway description, the scan delta and the traffic sample. |
//!
//! The builders here are pure (no bus, no files): the CLI and the MCP server
//! gather the live inputs their own way and hand them in, so the two outputs
//! cannot drift. The CLI renders its text report from this same JSON.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::time::{Duration, SystemTime};

use bussard_mgmt::MaskProfile;
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_monitor::{DestinationRef, Filter};
use bussard_transport::knxnet::GatewayDescription;
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::BussardMcp;

/// Version of the audit JSON contract. Bumped on a breaking change.
pub const AUDIT_FORMAT_VERSION: u32 = 1;

/// Two identical telegrams (same source, GA and payload) closer than this are
/// counted as a repetition even when the cEMI repeat flag is not available.
pub const DUPLICATE_WINDOW: Duration = Duration::from_millis(500);

/// Default traffic-sample window for a live audit.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// Longest traffic-sample window the MCP tool accepts.
pub const MAX_MCP_WINDOW_SECS: u32 = 3600;

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

/// Parses a device file's `product.mask` (`"07B0"` or `"0x07B0"`).
fn parse_mask(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(hex, 16).ok()
}

/// The capability row for one mask as JSON.
fn capability_json(mask: u16) -> Value {
    let profile = MaskProfile::from_mask(mask);
    let caps = profile.capabilities();
    json!({
        "mask": format!("{mask:04X}"),
        "family": profile.family().label(),
        "medium": profile.medium().label(),
        "plan_apply": caps.plan_apply,
        "flash": caps.flash,
        "describe": caps.describe,
        "reconstruct": caps.reconstruct,
        "bussard_can": caps.summary(),
        "note": caps.note,
    })
}

/// Builds the static (model-only) part of the audit.
///
/// `keyring_devices` is the list of individual addresses the `.knxkeys` keyring
/// carries a tool key for, or `None` when no keyring was given (the coverage
/// column is then `null`, never `false`).
pub fn static_report(model: &Model, keyring_devices: Option<&[IndividualAddress]>) -> Value {
    let analysis = bussard_model::analyze(model);

    // Devices per mask.
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
    let masks: Vec<Value> = by_mask
        .into_iter()
        .map(|(mask, devices)| {
            let mut row = match mask {
                Some(mask) => capability_json(mask),
                None => json!({
                    "mask": Value::Null,
                    "family": "unknown (no mask recorded)",
                    "medium": Value::Null,
                    "plan_apply": Value::Null,
                    "flash": Value::Null,
                    "describe": true,
                    "reconstruct": Value::Null,
                    "bussard_can": "unknown until the device is scanned",
                    "note": "the device file records no product mask; `bussard scan` reads it",
                }),
            };
            row["devices"] = json!(devices);
            row
        })
        .collect();

    // KNX Secure coverage.
    let keyring: Option<BTreeSet<IndividualAddress>> =
        keyring_devices.map(|ias| ias.iter().copied().collect());
    let mut with_entry = 0usize;
    let mut without_entry = 0usize;
    let secure_devices: Vec<Value> = analysis
        .secure_devices
        .iter()
        .map(|d| {
            let entry = keyring.as_ref().map(|k| {
                d.address
                    .parse::<IndividualAddress>()
                    .is_ok_and(|ia| k.contains(&ia))
            });
            match entry {
                Some(true) => with_entry += 1,
                Some(false) => without_entry += 1,
                None => {}
            }
            json!({
                "address": d.address,
                "name": d.name,
                "secure_capable": d.secure_capable,
                "activated": d.activated,
                "keyring_entry": entry,
            })
        })
        .collect();
    let secure = json!({
        "keyring_checked": keyring.is_some(),
        "devices": secure_devices,
        "with_keyring_entry": keyring.as_ref().map(|_| with_entry),
        "without_keyring_entry": keyring.as_ref().map(|_| without_entry),
    });

    json!({
        "format_version": AUDIT_FORMAT_VERSION,
        "model": analysis,
        "masks": masks,
        "secure": secure,
        "live": Value::Null,
    })
}

/// Builds the `gateway` section of a live audit.
///
/// `description` is the DESCRIPTION_RESPONSE, or the reason it could not be
/// obtained (routing transport, timeout, …).
pub fn gateway_report(
    endpoint: Option<SocketAddrV4>,
    description: Result<&GatewayDescription, String>,
) -> Value {
    match description {
        Ok(d) => {
            let capacity = d.tunnel_capacity();
            let slots_reported = d.tunnel_slots.is_some();
            json!({
                "endpoint": endpoint.map(|e| e.to_string()),
                "name": d.name,
                "individual_address": d
                    .individual_address
                    .map(|raw| IndividualAddress::from_raw(raw).to_string()),
                "tunnels": capacity.map(|c| c.total),
                "tunnels_in_use": if slots_reported { capacity.map(|c| c.in_use) } else { None },
                "tunnel_slots": d.tunnel_slots.as_ref().map(|slots| {
                    slots
                        .iter()
                        .map(|s| {
                            json!({
                                "individual_address":
                                    IndividualAddress::from_raw(s.individual_address).to_string(),
                                "free": s.free,
                                "authorized": s.authorized,
                                "usable": s.usable,
                            })
                        })
                        .collect::<Vec<_>>()
                }),
                "error": Value::Null,
            })
        }
        Err(reason) => json!({
            "endpoint": endpoint.map(|e| e.to_string()),
            "name": Value::Null,
            "individual_address": Value::Null,
            "tunnels": Value::Null,
            "tunnels_in_use": Value::Null,
            "tunnel_slots": Value::Null,
            "error": reason,
        }),
    }
}

/// Builds the `traffic` section of a live audit from the sampled telegrams.
///
/// Per GA it reports the telegram count and the repetition rate (a frame the
/// cEMI repeat flag marks, or an identical telegram from the same source within
/// [`DUPLICATE_WINDOW`]). It also lists GAs seen on the bus with no listener in
/// the model and source addresses the model does not know.
pub fn traffic_report(model: &Model, window: Duration, telegrams: &[SampledTelegram]) -> Value {
    // Listener index from the model links.
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

    let per_ga_json: Vec<Value> = per_ga
        .iter()
        .map(|(ga, s)| {
            let rate = if s.telegrams == 0 {
                0.0
            } else {
                (s.repeated as f64 / s.telegrams as f64 * 1000.0).round() / 1000.0
            };
            json!({
                "ga": ga.to_string(),
                "name": model.groups.groups.get(ga).map(|g| g.name.clone()),
                "telegrams": s.telegrams,
                "repeated": s.repeated,
                "repeat_rate": rate,
                "sources": s.sources.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let sender_no_listener: Vec<Value> = per_ga
        .keys()
        .filter(|ga| !listened.contains(ga))
        .map(|ga| {
            json!({
                "ga": ga.to_string(),
                "name": model.groups.groups.get(ga).map(|g| g.name.clone()),
                "in_model": model.groups.groups.contains_key(ga),
            })
        })
        .collect();

    json!({
        "window_seconds": window.as_secs(),
        "telegrams": telegrams.len(),
        "per_ga": per_ga_json,
        "sender_no_listener": sender_no_listener,
        "unknown_sources": unknown_sources.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
    })
}

/// Arguments for `knx_audit`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct AuditArgs {
    /// Add the live part: the gateway description with its tunnel slots and a
    /// traffic sample from the telegrams the server observed over the last
    /// `window_seconds`. Read-only; refused when the server runs `--passive`.
    #[serde(default)]
    pub live: bool,
    /// The traffic-sample window in seconds for a live audit (default 30, max
    /// 3600). The sample is taken from the server's telegram buffer, so the call
    /// returns immediately.
    #[serde(default)]
    pub window_seconds: Option<u32>,
}

/// The `knx_audit` tool, on its own router so it can live in this module.
///
/// `BussardMcp::new` merges `audit_router()` into the main router.
// The `tool_router` macro generates the public `audit_router()` constructor and
// offers no way to attach a doc comment to it, so `missing_docs` is allowed on
// this impl only.
#[allow(missing_docs)]
#[tool_router(router = audit_router, vis = "pub")]
impl BussardMcp {
    /// `knx_audit`.
    #[tool(
        description = "Audit the installation: what the model holds and what bussard can do with it. Returns one JSON object with sections `model` (device count per line, devices without name or location, GAs without DPT or name, links to unknown com-objects, protected GAs, KNX Secure devices, one-sided links as `findings`, neutral `info` counts, and provenance), `masks` (devices per mask version with what bussard can do: plan/apply, flash, reconstruct, describe), `secure`, and `live`. With `live: true` (not available in passive mode) `live` adds the gateway description with its tunnel slots and a traffic sample from recently observed telegrams: per-GA repetition rate, GAs seen with no listener in the model, and unknown source addresses. Never writes to the bus. Line scans are CLI-only (`bussard audit --live`), so `live.scan` is null here."
    )]
    pub async fn knx_audit(
        &self,
        Parameters(args): Parameters<AuditArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let model = state.model.current();
        // The MCP server has no keyring password channel; coverage is unchecked.
        let mut report = static_report(&model, None);
        if !args.live {
            return Ok(CallToolResult::structured(report));
        }
        if state.passive {
            return Err(ErrorData::invalid_params(
                "a live audit is refused in --passive mode (it queries the gateway); \
                 call knx_audit with live: false"
                    .to_string(),
                None,
            ));
        }

        let window = Duration::from_secs(u64::from(
            args.window_seconds
                .unwrap_or(DEFAULT_WINDOW.as_secs() as u32)
                .clamp(1, MAX_MCP_WINDOW_SECS),
        ));

        // Gateway description: one UDP exchange with the interface, paced by the
        // shared read limiter like every other bus-touching tool.
        let endpoint = state.bus.gateway();
        let gateway = match endpoint {
            Some(endpoint) => {
                let _permit = state.read_limiter.acquire().await;
                match bussard_transport::describe_gateway(endpoint, Duration::from_secs(2)).await {
                    Ok(d) => gateway_report(Some(endpoint), Ok(&d)),
                    Err(err) => gateway_report(Some(endpoint), Err(err.to_string())),
                }
            }
            None => gateway_report(
                None,
                Err("no tunnelling gateway configured (routing transport)".to_string()),
            ),
        };

        // Traffic sample from the ring: group telegrams within the window.
        let since = SystemTime::now()
            .checked_sub(window)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let telegrams: Vec<SampledTelegram> = state
            .ring
            .recent(&Filter::default(), None)
            .into_iter()
            .filter(|t| t.timestamp >= since)
            .filter_map(|t| match t.destination {
                DestinationRef::Group(ga) => Some(SampledTelegram {
                    at: t.timestamp,
                    source: t.source,
                    ga,
                    payload: t.payload,
                    repeat_flag: false,
                }),
                DestinationRef::Individual(_) => None,
            })
            .collect();

        report["live"] = json!({
            "bus": state.bus.to_json(),
            "gateway": gateway,
            "scan": Value::Null,
            "traffic": traffic_report(&model, window, &telegrams),
        });
        Ok(CallToolResult::structured(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let telegrams = vec![
            SampledTelegram {
                at: t0,
                source: src,
                ga,
                payload: vec![1],
                repeat_flag: false,
            },
            // Identical within the duplicate window: a repetition.
            SampledTelegram {
                at: t0 + Duration::from_millis(100),
                source: src,
                ga,
                payload: vec![1],
                repeat_flag: false,
            },
            // Different payload later: not a repetition.
            SampledTelegram {
                at: t0 + Duration::from_secs(5),
                source: src,
                ga,
                payload: vec![0],
                repeat_flag: false,
            },
            // Flagged by the cEMI control field.
            SampledTelegram {
                at: t0 + Duration::from_secs(6),
                source: src,
                ga,
                payload: vec![7],
                repeat_flag: true,
            },
        ];
        let report = traffic_report(&model, Duration::from_secs(30), &telegrams);
        assert_eq!(report["telegrams"], 4);
        assert_eq!(report["per_ga"][0]["repeated"], 2);
        assert_eq!(report["per_ga"][0]["repeat_rate"], 0.5);
        assert_eq!(report["sender_no_listener"][0]["ga"], "1/0/1");
        assert_eq!(report["unknown_sources"][0], "1.1.9");
        Ok(())
    }

    #[test]
    fn test_gateway_report_distinguishes_unreported_slots() {
        let d = GatewayDescription {
            additional_individual_addresses: vec![0x10F1, 0x10F2],
            ..Default::default()
        };
        let report = gateway_report(None, Ok(&d));
        assert_eq!(report["tunnels"], 2);
        assert!(report["tunnels_in_use"].is_null());
    }
}
