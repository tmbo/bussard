//! The `bussard scan` subcommand: sequential device discovery on one line.
//!
//! Sweeps `LINE.0` … `LINE.255` one connection at a time (TP1 etiquette — most
//! gateways will not multiplex connection-oriented sessions), reading each
//! responding device's mask version, manufacturer, serial and order info. When a
//! model directory is present it cross-references the discovered devices against
//! `devices/*.toml`: which are known, which are unexpected, and which model
//! devices did not answer. That delta is the command's real value.
//!
//! The address range can be narrowed with `--from`/`--to` (defaults `0`/`255`),
//! which cuts the sweep time when you already know the device numbers of
//! interest — a full line is 256 serial probes. An absent address costs tens of
//! milliseconds on an interface that reports a negative `L_Data.con`, and up to
//! a couple of seconds (the ACK timeout and its repetition) on one that does not
//! (issue #45). The summary and `--json`'s `timing` say which applied.
//!
//! It always exits 0 — it is a report, not a check.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_mgmt::{Timeouts, manufacturers, system_type};
use bussard_model::IndividualAddress;
use bussard_secure::Key16;
use bussard_service::BusService;
use bussard_service::WritePolicy;
use bussard_service::identity::SecureStatus;
use bussard_service::line::WalkEvent;
use bussard_service::scan::{self, LineRange, ScanReport, Sweep};
use bussard_service::secure::ToolKeys;

pub(crate) use bussard_service::scan::Found;

use crate::assign_cmd::hex;
use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{ConnOverrides, load_model_required, open_checked, resolve_config};
use crate::style::{Cell, Style, Symbol, Table, Tone, count};

/// The discovery timeout budget ([`scan::discovery_timeouts`]), honouring
/// `BUSSARD_SCAN_DISCOVERY_MS` when set.
pub(crate) fn discovery_timeouts() -> Timeouts {
    scan::discovery_timeouts()
}

/// `bussard scan`.
#[derive(Debug, clap::Args)]
pub(crate) struct ScanArgs {
    /// The line to scan, e.g. `1.1`.
    #[arg(value_name = "LINE", default_value = "1.1")]
    line: String,
    /// The first device number to probe (0–255).
    #[arg(long, value_name = "N", default_value_t = 0)]
    from: u8,
    /// The last device number to probe (0–255).
    #[arg(long, value_name = "N", default_value_t = 255)]
    to: u8,
}

impl Run for ScanArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(
            &self.line,
            self.from,
            self.to,
            g.dir(),
            g.json,
            g.keyring(),
            g.mgmt(),
        )
    }
}

/// Runs `bussard scan` (also the first-run scan of `init`).
pub(crate) fn run(
    line: &str,
    from: u8,
    to: u8,
    dir: &Path,
    json: bool,
    keyring: Option<&Path>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let (area, line_no) = parse_line(line)?;
    if from > to {
        return Err(anyhow!(
            "invalid range: --from {from} is greater than --to {to}"
        ));
    }
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // The keyring's tool keys (issue #203): a listed device is identified over
    // A_SecureData. Decrypted once for the whole sweep.
    let keys = ToolKeys::load(bussard_service::secure::ToolKeySource {
        keyring,
        tool_key: None,
    })
    .context("loading the keyring for scan")?;
    // Only a listed address gets a key; any other device is read in the clear
    // (an activated one then shows the hidden mask and its label).
    let key_for = |addr: IndividualAddress| -> Option<Key16> {
        keys.lists(addr).then(|| keys.tool_key(addr)).flatten()
    };

    // Up-front estimate (address count × per-address budget).
    let range = LineRange {
        area,
        line: line_no,
        from,
        to,
    };
    let estimate = range.estimate();
    eprintln!(
        "Scanning {area}.{line_no}.{from} to {area}.{line_no}.{to}, one address at a time (up to {} min {} s).",
        estimate.as_secs() / 60,
        estimate.as_secs() % 60
    );

    let runtime = tokio::runtime::Runtime::new()?;
    let swept = runtime.block_on(async move {
        // Read-only on the bus. Present the tunnel-assigned individual address
        // as the source; devices ignore connection-oriented frames from any
        // other source, and the gateway only routes replies back to the
        // assigned address (issue #30). Fall back to 0.0.255 on a routing
        // transport that assigns none.
        let (service, source) = open_checked(config, WritePolicy::ReadOnly, &overrides).await?;
        // Guard the sweep with Ctrl-C: on interrupt, stop sweeping and fall
        // through to a clean close so the gateway tunnel slot is released
        // rather than leaked (~2 min hold) — see issue #31.
        let swept = tokio::select! {
            swept = sweep(&service, range, source, json, &key_for) => swept,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Sweep::default()
            }
        };
        service.close().await;
        anyhow::Ok(swept)
    })?;

    let timing = swept.timing_json();
    let stats = SweepStats::of(&swept);
    let mut report = scan::cross_reference(swept.found, model.as_ref());
    // The identity verdict per device, against the lock and the stored facts
    // (issue #228, item 5); stale facts are dropped for the next connection.
    for f in &mut report.found {
        let device = model
            .as_ref()
            .and_then(|m| m.devices.get(&f.address))
            .map(|d| &d.device);
        f.identity = Some(scan::observe_identity(
            dir,
            model.is_some(),
            f.address,
            f.mask,
            device,
        ));
    }

    // The serial numbers the probes read go into the lock (issue #752); no
    // extra request, the probe reads PID 11 anyway.
    let serials: Vec<_> = report
        .found
        .iter()
        .filter_map(|f| Some((f.address, f.serial.clone()?, f.identity.as_ref()?.verdict)))
        .collect();
    let news = crate::keys_cmd::learn_serials(dir, model.as_ref(), &serials);

    if json {
        news.print(true);
        let style = crate::style::Style::stderr();
        eprintln!("{}", stats.summary(report.found.len(), &report, style));
        print_json(&report, timing)?;
    } else {
        news.print_warnings();
        print!(
            "{}",
            render_report(&report, &news, &stats, range, crate::style::Style::stdout())
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Sweeps every device address of `range` with [`scan::sweep`], showing the
/// progress on stderr (issue #147): a line rewritten in place, or the live
/// view on an interactive terminal. `key_for` gives the tool key of a
/// keyring-listed address.
async fn sweep(
    service: &BusService,
    range: LineRange,
    source: IndividualAddress,
    json: bool,
    key_for: &(dyn Fn(IndividualAddress) -> Option<Key16> + Sync),
) -> Sweep {
    let mut display = crate::progress::Display::sweep("scanning", range.count(), json);
    let swept = scan::sweep(service, range, source, key_for, &mut |event| match event {
        WalkEvent::Probing { address, found, .. } => display.probing(address, found),
        WalkEvent::Probed { .. } => display.advance(),
    })
    .await;
    display.finish(true);
    if !display.is_live() {
        // End the progress line the plain display rewrites in place.
        eprintln!();
    }
    swept
}

/// Parses a `area.line` (e.g. `1.1`) or a full `area.line.device` (ignoring the
/// device part) into `(area, line)` ([`bussard_service::line::parse_line`]).
pub(crate) fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    Ok(bussard_service::line::parse_line(line)?)
}

/// The sweep's counts for the summary line (issue #792).
#[derive(Debug, Clone, Copy, Default)]
struct SweepStats {
    /// Addresses probed.
    addresses: usize,
    /// The sweep's wall-clock time.
    elapsed: std::time::Duration,
    /// Addresses the interface reported absent at once.
    absent_at_once: usize,
    /// Addresses that did not answer within the budget.
    absent_timeout: usize,
    /// Addresses that refused the connection.
    refused: usize,
    /// How long one address is waited for.
    budget: std::time::Duration,
}

impl SweepStats {
    /// The counts of `swept` under the discovery timeouts.
    fn of(swept: &Sweep) -> SweepStats {
        use bussard_service::identity::ProbeMiss;
        let timeouts = discovery_timeouts();
        SweepStats {
            addresses: swept.timings.len(),
            elapsed: swept.elapsed,
            absent_at_once: swept.count(ProbeMiss::NegativeConfirmation),
            absent_timeout: swept.count(ProbeMiss::Timeout),
            refused: swept.count(ProbeMiss::Refused),
            budget: timeouts.ack_timeout * (timeouts.max_repetitions + 1),
        }
    }

    /// "46 devices found · 256 addresses in 52 s · 202 did not answer within
    /// 3 s", plus how many are not in the project.
    fn summary(&self, found: usize, report: &ScanReport, style: Style) -> String {
        let absent = self.absent_at_once + self.absent_timeout;
        let mut parts = vec![
            (
                format!("{} found", count(found, "device", "devices")),
                if found == 0 { Tone::Warn } else { Tone::Ok },
            ),
            (
                format!(
                    "{} in {}",
                    count(self.addresses, "address", "addresses"),
                    seconds(self.elapsed)
                ),
                Tone::Plain,
            ),
        ];
        if absent > 0 {
            let within = if self.absent_timeout > 0 {
                format!(" within {}", seconds(self.budget))
            } else {
                String::new()
            };
            parts.push((format!("{absent} did not answer{within}"), Tone::Dim));
        }
        if self.refused > 0 {
            parts.push((
                format!("{} refused the connection", self.refused),
                Tone::Warn,
            ));
        }
        if report.have_model && !report.not_in_model.is_empty() {
            parts.push((
                format!("{} not in your project", report.not_in_model.len()),
                Tone::Warn,
            ));
        }
        style.summary(&parts)
    }
}

/// `52 s`, `3 s`, `0.4 s`, `40 ms`: whole seconds from ten seconds up,
/// tenths below, milliseconds under one second.
fn seconds(duration: std::time::Duration) -> String {
    let secs = duration.as_secs_f64();
    if duration.as_secs() == 0 && duration.subsec_millis() < 100 {
        format!("{} ms", duration.as_millis())
    } else if secs >= 10.0 || duration.subsec_millis() == 0 {
        format!("{} s", secs.round())
    } else {
        format!("{secs:.1} s")
    }
}

/// The product of a found device: manufacturer and order number.
fn product(f: &Found) -> String {
    let manufacturer = f.manufacturer_id.map(manufacturers::display);
    match (manufacturer, f.order.as_deref()) {
        (Some(m), Some(o)) => format!("{m} {o}"),
        (Some(m), None) => m,
        (None, Some(o)) => o.to_string(),
        (None, None) => String::new(),
    }
}

/// The Secure cell of a found device, and the sentence that explains a
/// secured device bussard could not read.
fn secure_cell(f: &Found, style: Style) -> (Cell, Option<String>) {
    let lock = style.symbol(Symbol::Secured);
    match f.secure {
        SecureStatus::Plain => (Cell::default(), None),
        SecureStatus::Activated => (Cell::plain(lock), None),
        SecureStatus::ActivatedNoKey => (
            Cell::new(format!("{lock} (no tool key)"), Tone::Warn),
            Some(format!(
                "{} is secured and bussard has no tool key for it, so its product was not read",
                f.address
            )),
        ),
        SecureStatus::KeyRefused => (
            Cell::new(format!("{lock} (key refused)"), Tone::Error),
            Some(format!(
                "{} is secured and did not accept the tool key bussard has for it",
                f.address
            )),
        ),
    }
}

/// The scan's text report: the table, the notes, the summary line, the
/// devices of the project that did not answer and the next steps.
fn render_report(
    report: &ScanReport,
    news: &crate::keys_cmd::SerialNews,
    stats: &SweepStats,
    range: LineRange,
    style: Style,
) -> String {
    let mut headers = vec!["Address", "Product", "Serial number", "Secure"];
    if report.have_model {
        headers.push("In project");
    }
    let mut table = Table::new(&headers);
    let mut notes = Vec::new();
    let mut secured_without_key = false;
    for f in &report.found {
        let serial = match f.serial.as_deref() {
            Some(bytes) if news.saved(f.address) => {
                Cell::new(format!("{} (saved)", hex(bytes).to_uppercase()), Tone::Ok)
            }
            Some(bytes) => Cell::plain(hex(bytes).to_uppercase()),
            None => Cell::new(style.symbol(Symbol::Missing), Tone::Dim),
        };
        let product = match product(f) {
            p if p.is_empty() => Cell::new(style.symbol(Symbol::Missing), Tone::Dim),
            p => Cell::plain(p),
        };
        let (secure, note) = secure_cell(f, style);
        secured_without_key |= f.secure == SecureStatus::ActivatedNoKey;
        notes.extend(note.map(|n| style.warn(&n)));
        let mut row = vec![Cell::plain(f.address.to_string()), product, serial, secure];
        match report.known(f.address) {
            Some(true) => row.push(Cell::new("yes", Tone::Ok)),
            Some(false) => row.push(Cell::new("no", Tone::Warn)),
            None => {}
        }
        table.row(row);
    }
    for f in &report.found {
        if let Some(check) = f.identity.as_ref().filter(|c| c.is_drift()) {
            notes.push(style.warn(&bussard_service::identity_line(f.address, check)));
        }
    }
    notes.extend(news.lines(style));

    let mut out = String::new();
    if !table.is_empty() {
        out.push_str(&table.render(style));
        out.push('\n');
    }
    for note in &notes {
        out.push_str(note);
        out.push('\n');
    }
    if !notes.is_empty() {
        out.push('\n');
    }
    out.push_str(&stats.summary(report.found.len(), report, style));
    out.push('\n');

    let mut steps: Vec<(String, String)> = Vec::new();
    if report.have_model && report.model_device_count == 0 {
        // A project without devices: the cross-reference is vacuous (#30).
        steps.push((
            "bussard import <FILE>".to_string(),
            "your project has no devices yet; this brings in the devices of an ETS project"
                .to_string(),
        ));
    } else if report.have_model {
        let missing: Vec<&(IndividualAddress, String)> = report
            .missing
            .iter()
            .filter(|(a, _)| range.contains(*a))
            .collect();
        if !missing.is_empty() {
            let mut silent = Table::new(&["Address", "Name"]);
            for (address, name) in &missing {
                silent.row(vec![
                    Cell::plain(address.to_string()),
                    Cell::plain(name.as_str()),
                ]);
            }
            out.push_str(&format!(
                "\n{}\n",
                style.bold(&format!(
                    "{} in your project did not answer",
                    count(missing.len(), "device", "devices")
                ))
            ));
            for line in silent.render(style).lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        if let Some(first) = report.not_in_model.first() {
            steps.push((
                format!("bussard describe {first}"),
                "shows what a device that is not in your project is".to_string(),
            ));
        }
    }
    if secured_without_key {
        steps.push((
            "bussard keys import <FILE>".to_string(),
            "adds the tool keys of secured devices from an ETS keyring export".to_string(),
        ));
    }
    let steps: Vec<(&str, &str)> = steps
        .iter()
        .map(|(c, w)| (c.as_str(), w.as_str()))
        .collect();
    let block = style.next_steps(&steps);
    if !block.is_empty() {
        out.push('\n');
        out.push_str(&block);
    }
    out
}

/// Prints a stable JSON array of the discovered devices plus the model delta
/// and the sweep's `timing` (issue #45).
fn print_json(report: &ScanReport, timing: serde_json::Value) -> anyhow::Result<()> {
    use serde_json::json;
    let devices: Vec<_> = report
        .found
        .iter()
        .map(|f| {
            let status = if !report.have_model {
                serde_json::Value::Null
            } else if report.not_in_model.contains(&f.address) {
                json!("not_in_model")
            } else {
                json!("known")
            };
            let mut row = json!({
                "address": f.address.to_string(),
                "mask": format!("{:04X}", f.mask),
                "system_type": system_type(f.mask),
                "manufacturer_id": f.manufacturer_id.map(|id| format!("{id:#06X}")),
                "manufacturer": f.manufacturer_id.map(manufacturers::display),
                "serial": f.serial.as_deref().map(hex),
                "order": f.order,
                "model_status": status,
            });
            // A plain device's row is unchanged; an activated one says how it
            // was read (issue #203).
            if f.secure.activated() {
                row["secure"] = json!(f.secure.as_str());
            }
            if let Some(identity) = &f.identity {
                row["identity"] = json!(identity);
            }
            row
        })
        .collect();

    let out = json!({
        "found": devices,
        "model_device_count": report.model_device_count,
        "not_in_model": report.not_in_model.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "missing_from_bus": report
            .missing
            .iter()
            .map(|(a, name)| json!({ "address": a.to_string(), "name": name }))
            .collect::<Vec<_>>(),
        "timing": timing,
    });
    crate::output::print(crate::output::schema::SCAN, &out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_service::identity::SecureStatus;

    #[test]
    fn parse_line_keeps_the_service_messages() {
        let err = parse_line("16.1").err().map(|e| e.to_string());
        assert_eq!(
            err.as_deref(),
            Some("area and line must each be 0–15 (got \"16.1\")")
        );
    }

    #[test]
    fn hex_formats_lowercase() {
        assert_eq!(hex(&[0xDE, 0xAD]), "dead");
    }

    // --- cross_reference regression coverage (issue #30) ---

    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Device, Groups, Links};
    use bussard_model::{LoadedDevice, Model};

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("test fixture")
    }

    /// Builds a model whose `devices` map contains exactly `addrs`.
    fn model_with_devices(addrs: &[&str]) -> Model {
        let mut devices = BTreeMap::new();
        for a in addrs {
            let addr = ia(a);
            devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: format!("dev {a}"),
                        description: None,
                        location: None,
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
                    file_stem: a.to_string(),
                },
            );
        }
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups: BTreeMap::new(),
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices,
        }
    }

    fn found_at(addr: &str) -> Found {
        Found {
            address: ia(addr),
            mask: 0x07B0,
            manufacturer_id: None,
            serial: None,
            order: None,
            secure: SecureStatus::Plain,
            identity: None,
        }
    }

    fn report_with_secure_devices() -> ScanReport {
        let model = model_with_devices(&["1.1.4", "1.1.12"]);
        let mut plain = found_at("1.1.4");
        plain.manufacturer_id = Some(0x0083);
        plain.order = Some("JAL-0410.01".to_string());
        plain.serial = Some(vec![0x00, 0xFA, 0x01, 0x02, 0x03, 0x04]);
        let mut secured = found_at("1.1.10");
        secured.secure = SecureStatus::Activated;
        let mut hidden = found_at("1.1.12");
        hidden.mask = 0xFFFF;
        hidden.secure = SecureStatus::ActivatedNoKey;
        scan::cross_reference(vec![plain, secured, hidden], Some(&model))
    }

    fn stats() -> SweepStats {
        SweepStats {
            addresses: 256,
            elapsed: std::time::Duration::from_millis(52_200),
            absent_at_once: 0,
            absent_timeout: 202,
            refused: 0,
            budget: std::time::Duration::from_secs(3),
        }
    }

    fn range() -> LineRange {
        LineRange {
            area: 1,
            line: 1,
            from: 0,
            to: 255,
        }
    }

    #[test]
    fn test_render_report_plain_marks_secure_and_saved() {
        let report = report_with_secure_devices();
        let news = crate::keys_cmd::SerialNews {
            saved: vec![(ia("1.1.4"), "00FA01020304".to_string())],
            attached: vec![ia("1.1.4")],
            ..Default::default()
        };
        let text = render_report(&report, &news, &stats(), range(), Style::plain());
        assert_eq!(
            text,
            "Address  Product          Serial number         Secure                In project\n\
             1.1.4    MDT JAL-0410.01  00FA01020304 (saved)                        yes\n\
             1.1.10   -                -                     secure                no\n\
             1.1.12   -                -                     secure (no tool key)  yes\n\
             \n\
             1.1.12 is secured and bussard has no tool key for it, so its product was not read\n\
             certificate for 1.1.4 attached\n\
             \n\
             3 devices found, 256 addresses in 52 s, 202 did not answer within 3 s, 1 not in your project\n\
             \n\
             Next steps\n  \
             > bussard describe 1.1.10\n    \
             shows what a device that is not in your project is\n  \
             > bussard keys import <FILE>\n    \
             adds the tool keys of secured devices from an ETS keyring export\n"
        );
    }

    #[test]
    fn test_render_report_colour_uses_lock_and_tones() {
        let report = report_with_secure_devices();
        let text = render_report(
            &report,
            &crate::keys_cmd::SerialNews::default(),
            &stats(),
            range(),
            Style::rich(),
        );
        assert!(text.contains('\u{1F512}'), "{text}");
        assert!(!text.contains("secure (no tool key)"), "{text}");
        assert!(text.contains(" \u{00B7} "), "{text}");
        assert!(text.contains("\u{1b}[32m"), "green: {text:?}");
        assert!(text.contains("\u{1b}[33m"), "yellow: {text:?}");
    }

    #[test]
    fn test_render_report_prints_an_identity_drift_once() {
        let model = model_with_devices(&["1.1.4"]);
        let mut found = found_at("1.1.4");
        found.identity = Some(bussard_model::identity::IdentityCheck {
            lock: None,
            device: bussard_model::identity::ReportedIdentity {
                mask: "07B0".to_string(),
                application_id: None,
            },
            verdict: bussard_model::identity::IdentityVerdict::Drift,
            differences: vec!["mask 07B0, your project pins 0705".to_string()],
        });
        let report = scan::cross_reference(vec![found], Some(&model));
        let text = render_report(
            &report,
            &crate::keys_cmd::SerialNews::default(),
            &stats(),
            range(),
            Style::plain(),
        );
        assert_eq!(
            text.matches("identity of 1.1.4: differs from your project")
                .count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn test_seconds_rounds_by_size() {
        use std::time::Duration;
        assert_eq!(seconds(Duration::from_millis(52_200)), "52 s");
        assert_eq!(seconds(Duration::from_secs(3)), "3 s");
        assert_eq!(seconds(Duration::from_millis(400)), "0.4 s");
        assert_eq!(seconds(Duration::from_millis(40)), "40 ms");
    }

    /// The live shape from issue #30: a 46-device model is loaded and exactly
    /// one of those devices responds (the rest were silent because of the
    /// source-IA bug). The missing list MUST name the other 45 — it was empty
    /// in the field, which this test guards against.
    #[test]
    fn cross_reference_lists_all_non_responders() {
        let addrs: Vec<String> = (1..=46u16).map(|n| format!("1.1.{n}")).collect();
        let addr_refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        let model = model_with_devices(&addr_refs);

        // Only 1.1.1 answered; it IS a model device, so it is "known".
        let report = scan::cross_reference(vec![found_at("1.1.1")], Some(&model));

        assert!(report.have_model);
        assert!(
            report.not_in_model.is_empty(),
            "the sole responder is in the model, so nothing is unexpected"
        );
        assert_eq!(
            report.missing.len(),
            45,
            "the 45 silent model devices must all be listed as missing"
        );
        // The responder itself is not listed as missing.
        assert!(
            !report.missing.iter().any(|(a, _)| *a == ia("1.1.1")),
            "the device that responded must not be in the missing list"
        );
    }

    /// A responder that is *not* in the model is reported as not_in_model, and
    /// every model device is missing.
    #[test]
    fn cross_reference_flags_unexpected_and_all_missing() {
        let model = model_with_devices(&["1.1.4", "1.1.20"]);
        // The IP interface (1.1.200) answered but is not modelled.
        let report = scan::cross_reference(vec![found_at("1.1.200")], Some(&model));
        assert_eq!(report.not_in_model, vec![ia("1.1.200")]);
        assert_eq!(report.missing.len(), 2, "both model devices are missing");
    }

    /// Without a model, there is no cross-reference at all.
    #[test]
    fn cross_reference_without_model_has_no_delta() {
        let report = scan::cross_reference(vec![found_at("1.1.1")], None);
        assert!(!report.have_model);
        assert!(report.not_in_model.is_empty());
        assert!(report.missing.is_empty());
    }
}
