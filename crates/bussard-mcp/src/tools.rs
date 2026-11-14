//! Pure tool logic: the JSON each read-only tool returns, built from the loaded
//! [`Model`] and a snapshot of the [`TelegramRing`].
//!
//! These functions take no rmcp types and do no I/O, so every tool's core can be
//! unit-tested against an in-code model and a hand-fed ring. The rmcp glue in
//! [`crate::server`] is a thin wrapper that calls these and boxes the result in
//! a `CallToolResult`.

use std::time::SystemTime;

use bussard_model::{Dpt, GroupAddress, Model};
use bussard_service::device_show::DeviceShow;
use bussard_service::monitor::{DecodedTelegram, DestinationRef, Filter, TelegramRing, json_line};
use bussard_service::project_view::{GroupView, LookupReport};
use bussard_service::validate_report::ValidateReport;
use serde_json::{Value, json};

/// Serializes one decoded telegram to the same JSON object the monitor's JSON
/// Lines format uses, so telegrams look identical across the CLI and MCP.
pub fn telegram_json(t: &DecodedTelegram) -> Value {
    // `json_line` is the single source of truth for the telegram schema; parse
    // its output back into a `Value` so we never drift from the monitor format.
    serde_json::from_str(&json_line(t)).unwrap_or_else(|_| json!({}))
}

/// `knx_model_lookup`: case-insensitive substring search over GA names +
/// addresses, device names + IAs, room names, com objects (the link name the
/// device file gives, the vendor text and function, the key) and channels
/// (the vendor text, the user's name, the handle). An object or channel hit
/// names its device, channel handle and object number (issue #276).
///
/// With `capabilities` (the model directory and the server's tiers, issue
/// #298) it adds `capabilities`: the parameter texts and enum choice texts
/// of the installed devices' product models that match, each with its
/// device, page or channel, whether that is active, and what enables it
/// when it is not ([`bussard_model::capabilities::capability_lookup`]), each
/// `needs` with how the tiers run that push.
pub fn model_lookup(
    model: &Model,
    query: &str,
    limit: usize,
    capabilities: Option<(&std::path::Path, crate::guidance::Tiers)>,
) -> Value {
    serde_json::to_value(lookup_report(model, query, limit, capabilities)).unwrap_or_default()
}

/// [`model_lookup`] typed.
pub fn lookup_report(
    model: &Model,
    query: &str,
    limit: usize,
    capabilities: Option<(&std::path::Path, crate::guidance::Tiers)>,
) -> LookupReport {
    let mut out = LookupReport::search(model, query, limit);
    if let Some((dir, tiers)) = capabilities {
        let mut found = bussard_model::capabilities::capability_lookup(model, dir, query, limit);
        for c in &mut found {
            if let Some(needs) = c.needs.take() {
                c.needs = Some(tiers.needs_how(&needs, c.device_ia.parse().ok()));
            }
        }
        out.capabilities = Some(found);
    }
    out
}

/// `knx_get_group`: the group entry, every link touching it, and the last seen
/// telegram from the ring (if any).
pub fn get_group(model: &Model, ring: &TelegramRing, ga: GroupAddress) -> Value {
    serde_json::to_value(group_view(model, ring, ga)).unwrap_or_default()
}

/// [`get_group`] typed.
pub fn group_view(model: &Model, ring: &TelegramRing, ga: GroupAddress) -> GroupView {
    let filter = Filter::parse(&ga.to_string()).unwrap_or_default();
    let last = ring
        .recent(&filter, Some(1))
        .into_iter()
        .find(|t| matches!(t.destination, DestinationRef::Group(g) if g == ga))
        .map(|t| telegram_json(&t));
    GroupView::of(model, ga, last)
}

/// `knx_recent_telegrams`: recent telegrams from the ring, filtered, oldest→newest.
///
/// The ring's `recent` returns newest-first; we reverse so the caller reads a
/// chronological transcript ending in the most recent event.
pub fn recent_telegrams(
    ring: &TelegramRing,
    filter: &Filter,
    since: Option<SystemTime>,
    limit: usize,
) -> Vec<DecodedTelegram> {
    let mut out = ring.recent(filter, None);
    // Apply the `since` cutoff (the ring has no time filter of its own).
    if let Some(cutoff) = since {
        out.retain(|t| t.timestamp >= cutoff);
    }
    out.truncate(limit);
    out.reverse(); // newest last
    out
}

/// `knx_show_device`'s view of a device: scoped to a channel or page, the
/// pages and inactive channels in one line each; unscoped, `how_to_change`.
/// Every inactive row's `needs` says how the server's tiers run that push.
pub fn show_device_result(
    mut view: bussard_model::device_view::DeviceView,
    inactive: bool,
    toml: bool,
    tiers: crate::guidance::Tiers,
) -> DeviceShow {
    let snippet = toml.then(|| view.render_toml());
    view.collapse_enable_chains();
    let ia = view.address.parse().ok();
    let how = |row: Option<&mut bussard_model::device_view::Inactive>| {
        if let Some(i) = row {
            i.needs = tiers.needs_how(&i.needs, ia);
        }
    };
    for row in view
        .blocks
        .iter_mut()
        .chain(view.inactive_channels.iter_mut())
    {
        how(row.inactive.as_mut());
    }
    how(view.scope.as_mut().and_then(|s| s.inactive.as_mut()));
    let mut show = if view.scope.is_some() {
        DeviceShow::scoped(view, inactive)
    } else {
        let how_to_change = crate::guidance::how_to_change(view.product_model, &view.notes);
        DeviceShow {
            how_to_change: Some(how_to_change),
            ..DeviceShow::of(view)
        }
    };
    show.toml = snippet;
    show
}

pub use bussard_service::validate_report::{ValidateFilter, parse_severity};

/// `knx_validate` (issue #304): of the shared `run` (issue #1112), the
/// diagnostics `filter` selects (by default errors and warnings), with
/// `counts` per severity over the whole project, `shown`, a `note` naming
/// what the filter left out and the rule families `checked`.
pub fn validate_filtered(
    model: &Model,
    run: bussard_service::validate_report::ValidateRun,
    filter: &ValidateFilter,
) -> Value {
    crate::reply::report(&ValidateReport::new(run, filter), model)
}

/// Decodes a raw payload against a GA's DPT into a display string + typed JSON,
/// used by `knx_read_group` to render the response value.
pub fn decode_for_dpt(dpt: Option<Dpt>, payload: &[u8]) -> (Option<String>, Value) {
    match dpt {
        Some(d) => {
            let value = bussard_model::decode(&d, payload);
            (
                Some(value.to_string()),
                bussard_service::group_report::typed_value(&value),
            )
        }
        None => (None, Value::Null),
    }
}

/// The object-type and PID name tables, shared with `bussard describe` so the
/// MCP and CLI surfaces agree (they live in [`bussard_service::describe`]).
pub use bussard_service::describe::{object_type_name, pid_name};

#[cfg(test)]
pub(crate) mod test_fixtures {
    //! A small in-code model + ring builders shared by the tool unit tests.

    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    use bussard_model::schema::{
        BussardConfig, Channel, Device, Group, Groups, Link, Links, Location, Range,
    };
    use bussard_model::{LoadedDevice, Model};
    use bussard_service::monitor::{ApciKind, DecodedTelegram, DestinationRef, TelegramRing};

    pub use bussard_testkit::{TestResult, ga, ia};

    /// Two GAs (one with DPT), one device in a room, one send + one listen link.
    pub fn model() -> TestResult<Model> {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/2/0")?,
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse()?),
                description: Some("wind alarm".to_string()),
                protected: true,
                secure: false,
            },
        );
        groups.insert(
            ga("3/0/4")?,
            Group {
                name: "Living Room Blind Move".to_string(),
                dpt: Some("1.008".parse()?),
                description: None,
                protected: false,
                secure: false,
            },
        );

        let mut ranges = BTreeMap::new();
        ranges.insert(
            "3".to_string(),
            Range {
                name: "Verschattung".to_string(),
            },
        );

        let mut links = BTreeMap::new();
        links.insert(
            ia("1.1.30")?,
            vec![Link {
                object: 3,
                name: Some("Windalarm 1".to_string()),
                send: Some(ga("3/2/0")?),
                listen: vec![],
            }],
        );
        links.insert(
            ia("1.1.4")?,
            vec![Link {
                object: 12,
                name: Some("A: Behang Auf/Ab".to_string()),
                send: None,
                listen: vec![ga("3/0/4")?],
            }],
        );

        let mut channels = BTreeMap::new();
        channels.insert(
            "A".to_string(),
            Channel {
                name: "Raffstore Süd".to_string(),
                key: None,
                number: None,
                text: None,
            },
        );

        let mut devices = BTreeMap::new();
        devices.insert(
            ia("1.1.4")?,
            LoadedDevice {
                device: Device {
                    address: ia("1.1.4")?,
                    name: "Blind Actuator 4-fold".to_string(),
                    description: None,
                    location: Some(Location {
                        floor: Some("EG".to_string()),
                        room: Some("Wohnzimmer".to_string()),
                    }),
                    replaced: None,
                    product: None,
                    channels,
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects: BTreeMap::new(),
                    security: None,
                    application_override: None,
                    knxnet: None,
                    lock: Default::default(),
                },
                file_stem: "1.1.4-jalousieaktor".to_string(),
            },
        );
        devices.insert(
            ia("1.1.30")?,
            LoadedDevice {
                device: Device {
                    address: ia("1.1.30")?,
                    name: "Weather Station".to_string(),
                    description: None,
                    location: Some(Location {
                        floor: Some("Attic".to_string()),
                        room: Some("Utility Room".to_string()),
                    }),
                    replaced: None,
                    product: None,
                    channels: BTreeMap::new(),
                    parameters: BTreeMap::new(),
                    module_bases: Default::default(),
                    com_objects: BTreeMap::new(),
                    security: None,
                    application_override: None,
                    knxnet: None,
                    lock: Default::default(),
                },
                file_stem: "1.1.30-wetterstation".to_string(),
            },
        );

        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: Some("Home".to_string()),
                imported_from: None,
                ranges,
                groups,
            },
            links: Links { links },
            devices,
        })
    }

    /// A telegram to `dest` at `secs` past the epoch.
    pub fn tel(dest: &str, secs: u64) -> TestResult<DecodedTelegram> {
        Ok(DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            source: ia("1.1.30")?,
            source_name: Some("Weather Station".to_string()),
            destination: DestinationRef::Group(ga(dest)?),
            destination_name: Some("Windalarm".to_string()),
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(bussard_model::codec::TypedValue::Bool {
                value: true,
                label: "Alarm",
            }),
            dpt: Some("1.005".parse()?),
            object_name: Some("Windalarm 1".to_string()),
            decode_note: None,
            secure: None,
        })
    }

    pub fn ring_with(dests: &[(&str, u64)]) -> TestResult<TelegramRing> {
        let ring = TelegramRing::new();
        for (d, s) in dests {
            ring.push(tel(d, *s)?);
        }
        Ok(ring)
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;
    use crate::state::BusStatus;
    use bussard_model::IndividualAddress;
    use bussard_model::param_model::ProductModels;
    use bussard_service::project_view::{DeviceInfo, ProjectSummary};
    use bussard_service::transport::TransportKind;
    use bussard_service::validate_report::{RuleSet, ValidateRun};

    /// `value` as JSON.
    fn json_of(value: impl serde::Serialize) -> Value {
        serde_json::to_value(value).unwrap_or_default()
    }

    fn project_summary(m: &Model, bus: &BusStatus) -> Value {
        json_of(ProjectSummary::of(m, bus.to_json()))
    }

    fn lookup(m: &Model, q: &str, limit: usize) -> Value {
        model_lookup(m, q, limit, None)
    }

    fn group(m: &Model, ring: &TelegramRing, ga: GroupAddress) -> Value {
        get_group(m, ring, ga)
    }

    fn get_device(m: &Model, p: &ProductModels, ia: IndividualAddress, t: bool) -> Value {
        json_of(DeviceInfo::of(m, p, ia, t))
    }

    #[test]
    fn summary_counts_and_ranges() -> TestResult {
        let m = model()?;
        let bus = BusStatus::new(TransportKind::Tunnel);
        let v = project_summary(&m, &bus);
        assert_eq!(v["project"], "Home");
        assert_eq!(v["counts"]["devices"], 2);
        assert_eq!(v["counts"]["group_addresses"], 2);
        assert_eq!(v["counts"]["links"], 2);
        // Two rooms with one device each.
        assert_eq!(v["rooms"].as_array().ok_or("not an array")?.len(), 2);
        // One main range "3".
        assert_eq!(v["ga_main_ranges"][0]["main"], "3");
        assert_eq!(v["ga_main_ranges"][0]["name"], "Verschattung");
        // Bus starts connecting.
        assert_eq!(v["bus"]["state"], "connecting");
        assert_eq!(v["bus"]["transport"], "tunnel");
        Ok(())
    }

    #[test]
    fn lookup_matches_across_kinds() -> TestResult {
        let m = model()?;
        // "wind" hits the GA name and the object name.
        let v = lookup(&m, "wind", 50);
        assert_eq!(v["groups"].as_array().ok_or("not an array")?.len(), 1);
        assert_eq!(v["groups"][0]["address"], "3/2/0");
        assert_eq!(v["objects"].as_array().ok_or("not an array")?.len(), 1);
        assert_eq!(v["objects"][0]["linked_gas"][0], "3/2/0");

        // A room-name match returns the device.
        let v = lookup(&m, "wohnzimmer", 50);
        assert_eq!(v["devices"].as_array().ok_or("not an array")?.len(), 1);
        assert_eq!(v["devices"][0]["ia"], "1.1.4");

        // An address substring match.
        let v = lookup(&m, "3/0/4", 50);
        assert_eq!(v["groups"][0]["address"], "3/0/4");
        Ok(())
    }

    #[test]
    fn lookup_respects_limit() -> TestResult {
        let m = model()?;
        // Both GAs contain "3/" — limit to 1.
        let v = lookup(&m, "3/", 1);
        assert_eq!(v["groups"].as_array().ok_or("not an array")?.len(), 1);
        Ok(())
    }

    #[test]
    fn get_group_assembles_links_and_last_telegram() -> TestResult {
        let m = model()?;
        let ring = ring_with(&[("3/2/0", 100)])?;
        let v = group(&m, &ring, ga("3/2/0")?);
        assert_eq!(v["found"], true);
        assert_eq!(v["group"]["name"], "Windalarm");
        // The sending link is present with role "send".
        let links = v["links"].as_array().ok_or("not an array")?;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["device_ia"], "1.1.30");
        assert_eq!(links[0]["role"], "send");
        // Last telegram resolved.
        assert_eq!(v["last_telegram"]["destination"], "3/2/0");
        Ok(())
    }

    #[test]
    fn get_group_listen_role() -> TestResult {
        let m = model()?;
        let ring = TelegramRing::new();
        let v = group(&m, &ring, ga("3/0/4")?);
        let links = v["links"].as_array().ok_or("not an array")?;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["role"], "listen");
        assert_eq!(links[0]["object"], 12);
        assert!(v["last_telegram"].is_null());
        Ok(())
    }

    #[test]
    fn get_device_full_and_links() -> TestResult {
        let m = model()?;
        let v = get_device(&m, &ProductModels::default(), ia("1.1.4")?, false);
        assert_eq!(v["found"], true);
        assert_eq!(v["device"]["name"], "Blind Actuator 4-fold");
        assert_eq!(v["device"]["location"]["room"], "Wohnzimmer");
        assert_eq!(v["links"].as_array().ok_or("not an array")?.len(), 1);
        assert_eq!(v["links"][0]["listen"][0], "3/0/4");
        Ok(())
    }

    #[test]
    fn test_get_device_hides_technical_parameters() -> TestResult {
        let mut m = model()?;
        let dev = &mut m.devices.get_mut(&ia("1.1.4")?).ok_or("no 1.1.4")?.device;
        dev.parameters
            .insert("fahrzeit@P-1_R-1".to_string(), "60".to_string());
        dev.parameters
            .insert(bussard_model::hidden_mem_key("P-2_R-2"), "0".to_string());
        dev.parameters.insert(
            bussard_model::label_mem_key("P-3_R-3"),
            "Kanal A".to_string(),
        );
        let v = get_device(&m, &ProductModels::default(), ia("1.1.4")?, false);
        let keys: Vec<&String> = v["device"]["parameters"]
            .as_object()
            .ok_or("no parameters")?
            .keys()
            .collect();
        assert_eq!(keys, ["fahrzeit@P-1_R-1"]);
        assert_eq!(v["hidden_parameters"], 2);
        let v = get_device(&m, &ProductModels::default(), ia("1.1.4")?, true);
        assert_eq!(
            v["device"]["parameters"]
                .as_object()
                .ok_or("no parameters")?
                .len(),
            3
        );
        assert_eq!(v["hidden_parameters"], 2);
        Ok(())
    }

    #[test]
    fn test_compact_row_pluralises_the_counts() {
        let row = |parameters, objects| bussard_model::device_view::BlockRow {
            handle: "logik".to_string(),
            id: "CH-7".to_string(),
            text: Some("Logik".to_string()),
            depth: 0,
            active: false,
            parameters,
            objects,
            inactive: None,
            includes: Vec::new(),
        };
        assert_eq!(
            bussard_service::device_show::compact_row(&row(1, 1)),
            "logik \"Logik\": inactive, 1 parameter, 1 object"
        );
        assert_eq!(
            bussard_service::device_show::compact_row(&row(2, 0)),
            "logik \"Logik\": inactive, 2 parameters, 0 objects"
        );
    }

    #[test]
    fn get_device_not_found() -> TestResult {
        let m = model()?;
        let v = get_device(&m, &ProductModels::default(), ia("9.9.9")?, false);
        assert_eq!(v["found"], false);
        Ok(())
    }

    #[test]
    fn recent_filters_since_and_orders_chronologically() -> TestResult {
        let ring = ring_with(&[("3/2/0", 10), ("3/2/0", 20), ("3/2/0", 30)])?;
        let filter = Filter::default();
        // No since: all three, newest last.
        let all = recent_telegrams(&ring, &filter, None, 50);
        assert_eq!(all.len(), 3);
        assert!(all[0].timestamp <= all[2].timestamp, "chronological");

        // Since t=20s: two remain.
        let since = Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(20));
        let filtered = recent_telegrams(&ring, &filter, since, 50);
        assert_eq!(filtered.len(), 2);

        // Limit to 1: newest only.
        let one = recent_telegrams(&ring, &filter, None, 1);
        assert_eq!(one.len(), 1);
        Ok(())
    }

    #[test]
    fn validate_shape_and_counts() -> TestResult {
        let m = model()?;
        let all = ValidateFilter {
            severity: Some(bussard_model::Severity::Info),
            ..ValidateFilter::default()
        };
        let v = validate_filtered(&m, run(bussard_model::validate(&m)), &all);
        assert!(v["counts"]["total"].as_u64().is_some());
        assert!(v["diagnostics"].is_array());
        // A well-formed fixture: `ok` reflects zero errors.
        let errors = v["counts"]["errors"].as_u64().ok_or("not a u64")?;
        assert_eq!(v["ok"], errors == 0);
        Ok(())
    }

    fn diag(
        code: &'static str,
        severity: bussard_model::Severity,
        location: &str,
    ) -> bussard_model::Diagnostic {
        bussard_model::Diagnostic::new(code, severity, location, format!("{code} test"))
    }

    /// A run of `diagnostics` with every rule family checked.
    fn run(diagnostics: Vec<bussard_model::Diagnostic>) -> ValidateRun {
        ValidateRun {
            diagnostics,
            checked: RuleSet::ALL.to_vec(),
        }
    }

    fn codes(v: &Value) -> Vec<String> {
        v["diagnostics"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|d| d["code"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn test_validate_filtered_default_excludes_infos_but_counts_them() -> TestResult {
        use bussard_model::Severity;
        let m = model()?;
        let extra = || {
            vec![
                diag("I909", Severity::Info, "devices/1.1.4.toml object 3"),
                diag("W909", Severity::Warning, "groups.\"7/6/5\""),
                diag("E909", Severity::Error, "links.\"1.1.9\"[0]"),
            ]
        };
        let all = validate_filtered(
            &m,
            run(extra()),
            &ValidateFilter {
                severity: Some(Severity::Info),
                ..ValidateFilter::default()
            },
        );
        let v = validate_filtered(&m, run(extra()), &ValidateFilter::default());
        assert!(
            v["diagnostics"]
                .as_array()
                .is_some_and(|a| a.iter().all(|d| d["severity"] != "info")),
            "{v}"
        );
        assert_eq!(v["counts"], all["counts"], "{v}");
        assert!(v["counts"]["infos"].as_u64().is_some_and(|n| n >= 1), "{v}");
        assert!(codes(&all).contains(&"I909".to_string()), "{all}");
        assert!(codes(&v).contains(&"W909".to_string()), "{v}");
        assert!(
            v["note"].as_str().is_some_and(|n| n.contains("severity")),
            "{v}"
        );
        assert_eq!(v["ok"], false);

        let errors = validate_filtered(
            &m,
            run(extra()),
            &ValidateFilter {
                severity: parse_severity("error"),
                ..ValidateFilter::default()
            },
        );
        assert!(codes(&errors).contains(&"E909".to_string()), "{errors}");
        assert!(!codes(&errors).contains(&"W909".to_string()), "{errors}");

        let device = validate_filtered(
            &m,
            run(extra()),
            &ValidateFilter {
                severity: Some(Severity::Info),
                address: Some("1.1.4".to_string()),
                ..ValidateFilter::default()
            },
        );
        assert!(codes(&device).contains(&"I909".to_string()), "{device}");
        assert!(!codes(&device).contains(&"E909".to_string()), "{device}");
        let line = validate_filtered(
            &m,
            run(extra()),
            &ValidateFilter {
                severity: Some(Severity::Info),
                address: Some("1.1.".to_string()),
                ..ValidateFilter::default()
            },
        );
        assert!(codes(&line).contains(&"E909".to_string()), "{line}");

        let group = validate_filtered(
            &m,
            run(extra()),
            &ValidateFilter {
                group: Some("7/".to_string()),
                ..ValidateFilter::default()
            },
        );
        assert_eq!(codes(&group), ["W909"], "{group}");
        Ok(())
    }

    #[test]
    fn decode_for_dpt_bool() -> TestResult {
        let (display, typed) = decode_for_dpt(Some("1.005".parse()?), &[1]);
        assert_eq!(display.as_deref(), Some("Alarm"));
        assert_eq!(typed["bool"], true);
        assert_eq!(typed["label"], "Alarm");

        let (display, typed) = decode_for_dpt(None, &[1]);
        assert!(display.is_none());
        assert!(typed.is_null());
        Ok(())
    }
}
