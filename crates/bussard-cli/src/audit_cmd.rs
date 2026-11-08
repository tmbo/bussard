//! The `bussard audit` subcommand: what the installation holds and what
//! bussard can do with it (issue #93).
//!
//! The static part reads only the model. The live part (`--live`) is read tier:
//! it asks the interface to describe itself (tunnel slots, issue #105), listens
//! to the bus for `--window` seconds, then probes each modelled device with the
//! `scan` machinery, one address at a time and paced like the MCP read limiter.
//! It never sends a group telegram.
//!
//! The report itself is [`bussard_service::audit::AuditReport`], the same type
//! the `knx_audit` MCP tool returns; this module opens the bus for the live
//! part and renders the text form from the typed report, so text, `--json` and
//! MCP cannot disagree.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use bussard_model::Model;
use bussard_service::audit::{
    AuditReport, GatewayReport, LiveReport, ProductsReport, SecureLiveReport, SecureProbeStatus,
    TrafficReport,
};
use bussard_service::secure::ToolKeys;
use bussard_service::transport::{ConnectionConfig, TransportKind};
use bussard_service::{BusService, WritePolicy};

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_required, resolve_config,
};
use crate::style::{Cell, Style, Table, Tone, count};

/// `bussard audit`.
#[derive(Debug, clap::Args)]
pub(crate) struct AuditArgs {
    /// Add the live part: gateway description, traffic sample and a probe of
    /// every device in the project. Read tier only; never sends a group telegram.
    #[arg(long)]
    live: bool,
    /// Traffic-sample window in seconds for `--live`.
    #[arg(long, value_name = "SECS", default_value_t = 30, requires = "live")]
    window: u64,
}

impl Run for AuditArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self, g)
    }
}

/// Runs `bussard audit`. Exits 0 on a completed audit, whatever it found.
fn run(options: AuditArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, overrides) = (g.dir(), g.mgmt());
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "`bussard audit` needs a project; none was found at {} (run `bussard init` or \
             `bussard import` first)",
            dir.display()
        );
    };

    let keys = ToolKeys::load(bussard_service::secure::ToolKeySource {
        keyring: g.keyring(),
        tool_key: None,
    })
    .context("loading the keyring for audit")?;
    let keyring_devices = keys.keyring_given().then(|| keys.listed());
    let mut report = AuditReport::from_model(&model, keyring_devices.as_deref());
    report.products = Some(ProductsReport::from_dir(&model, dir));

    if options.live {
        let config = resolve_config(Some(&model), &overrides)?;
        let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
        report.live = Some(runtime.block_on(live_report(
            &model,
            dir,
            config,
            Duration::from_secs(options.window),
            &overrides,
            &keys,
        ))?);
    }

    if g.json {
        crate::output::report(&report)?;
    } else {
        print!("{}", render_text(&report, Style::stdout()));
    }
    Ok(ExitCode::SUCCESS)
}

/// Gathers the live section: gateway description, traffic sample, scan delta.
async fn live_report(
    model: &Model,
    dir: &Path,
    config: ConnectionConfig,
    window: Duration,
    overrides: &ConnOverrides,
    keys: &ToolKeys,
) -> anyhow::Result<LiveReport> {
    // 1. The interface's own description: one UDP exchange, no tunnel slot.
    let is_tunnel = config.transport == TransportKind::Tunnel;
    let gateway = match (is_tunnel, config.gateway) {
        (true, Some(endpoint)) => GatewayReport::describe(endpoint).await,
        _ => GatewayReport::unavailable(
            None,
            "routing transport: there is no tunnelling interface to describe".to_string(),
        ),
    };

    // 2. A full interface must fail loudly with its own exit code, not as a
    //    silent reconnect loop: probe one tunnel connect first (issue #105).
    if is_tunnel {
        match bussard_service::audit::probe_tunnel(&config).await {
            Ok(()) => {}
            Err(err @ bussard_service::transport::TransportError::NoMoreConnections) => {
                return Err(anyhow::Error::new(err));
            }
            Err(err) => {
                return Err(anyhow::Error::new(err).context("connecting to the gateway"));
            }
        }
    }

    let service = BusService::open(config, WritePolicy::ReadOnly)?;

    let handle = service.handle().clone();
    if !handle.wait_connected(crate::conn_cmd::connect_wait()).await {
        let _ = handle.close().await;
        bail!("the bus did not connect within 10 s; the live audit needs a working gateway");
    }

    // 3. Listen first, so the sample is not polluted by our own probes (which
    //    are individually addressed anyway).
    eprintln!("sampling bus traffic for {} s…", window.as_secs());
    let telegrams = bussard_service::audit::sample_traffic(&handle, window).await;
    let traffic = TrafficReport::new(model, window, &telegrams);

    // 4. Probe each modelled device, line by line, paced like the MCP read
    //    limiter. The probes are connection-oriented, so check our own source
    //    address first. The check runs after the sample, not before it, so
    //    listening starts as soon as the tunnel is up instead of after the
    //    probe's ~600 ms wait.
    let source = checked_source_or_close(&service, overrides).await?;
    let (scan, secure) = bussard_service::audit::scan_model_devices(
        &service,
        model,
        dir,
        source,
        keys,
        bussard_mcp::READ_MIN_INTERVAL,
        |addr| eprint!("\rprobing {addr}…   "),
    )
    .await;
    eprintln!(
        "\rprobed {} device(s) of your project    ",
        model.devices.len()
    );
    let _ = handle.close().await;

    Ok(LiveReport {
        bus: serde_json::json!({ "state": "connected" }),
        gateway,
        scan: Some(scan),
        secure: Some(SecureLiveReport::new(&secure)),
        traffic,
    })
}

/// Renders the text report.
pub fn render_text(report: &AuditReport, style: Style) -> String {
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    let heading = |title: &str| style.bold(title);
    let model = &report.model;

    line(heading("Your project"));
    line(format!(
        "  {} {}   {} {}",
        style.dim("project:"),
        model.project.as_deref().unwrap_or("(not recorded)"),
        style.dim("imported from:"),
        model.imported_from.as_deref().unwrap_or("(not recorded)")
    ));
    line(format!(
        "  {}, {}, {}",
        count(model.devices, "device", "devices"),
        count(model.group_addresses, "group address", "group addresses"),
        count(model.links, "link", "links")
    ));
    for l in &model.devices_per_line {
        line(format!(
            "    line {}: {}",
            l.line,
            count(l.devices, "device", "devices")
        ));
    }
    line(String::new());

    line(heading("Gaps in your project"));
    let mut gap = |label: &str, items: &[String]| list_section(&mut line, style, label, items);
    gap("devices without a name", &model.devices_without_name);
    gap(
        "devices without a location",
        &model.devices_without_location,
    );
    gap(
        "group addresses without a DPT",
        &model.group_addresses_without_dpt,
    );
    gap(
        "group addresses without a name",
        &model.group_addresses_without_name,
    );
    let unknown_objects: Vec<String> = model
        .links_to_unknown_objects
        .iter()
        .map(|l| format!("{} object {}", l.device, l.object))
        .collect();
    gap("links to unknown com-objects", &unknown_objects);
    gap(
        "links for devices without a device file",
        &model.links_to_unknown_devices,
    );
    line(String::new());

    line(heading("One-sided links"));
    if model.findings.is_empty() {
        line(format!("  {}", style.ok("none")));
    }
    for f in &model.findings {
        line(format!("  {}", style.warn(&f.message)));
    }
    line(format!(
        "  {}",
        style.dim(&format!(
            "{} and {} (normal, not problems)",
            count(
                model.info.unlinked_com_objects,
                "unlinked com-object",
                "unlinked com-objects"
            ),
            count(
                model.info.unused_group_addresses,
                "unused group address",
                "unused group addresses"
            )
        ))
    ));
    line(String::new());

    line(heading("Devices per mask"));
    for m in &report.masks {
        line(format!(
            "  {} {} ({}): {} {}",
            m.mask.as_deref().unwrap_or("----"),
            m.family,
            count(m.devices.len(), "device", "devices"),
            style.dim("bussard can:"),
            m.bussard_can
        ));
        line(format!("      {}", style.dim(&m.devices.join(", "))));
    }
    line(String::new());

    line(heading("KNX Secure"));
    if report.secure.devices.is_empty() {
        line(format!(
            "  {}",
            style.dim("no device in your project supports Secure")
        ));
    }
    let mut table = Table::new(&["Address", "Name", "Secure", "Tool key"]);
    for d in &report.secure.devices {
        let key = match d.keyring_entry {
            Some(true) => Cell::new("present", Tone::Ok),
            Some(false) => Cell::new("missing", Tone::Warn),
            None => Cell::new("not checked (pass --keyring)", Tone::Dim),
        };
        table.row(vec![
            Cell::plain(d.address.clone()),
            Cell::plain(d.name.clone()),
            if d.activated {
                Cell::plain("secured")
            } else {
                Cell::new("supports Secure", Tone::Dim)
            },
            key,
        ]);
    }
    if !table.is_empty() {
        for l in table.render(style).lines() {
            line(format!("  {l}"));
        }
    }
    list_section(
        &mut line,
        style,
        "protected group addresses",
        &model.protected_group_addresses,
    );

    if let Some(products) = &report.products {
        line(String::new());
        line(heading("Product data (bussard.lock)"));
        let mut gap = |label: &str, items: &[String]| list_section(&mut line, style, label, items);
        gap(
            "devices with a product but no pinned product data",
            &products.unpinned,
        );
        gap(
            "pinned archives missing from your project",
            &products.missing_archives,
        );
        gap(
            "pinned archives whose content changed (sha256 mismatch)",
            &products.hash_mismatch,
        );
        gap(
            "devices whose stored facts report another application than the lock pins",
            &products.application_drift,
        );
    }

    let Some(live) = &report.live else {
        return out;
    };
    line(String::new());
    line(heading("Gateway"));
    let gw = &live.gateway;
    if let Some(err) = &gw.error {
        line(format!(
            "  {}",
            style.warn(&format!("description unavailable: {err}"))
        ));
    } else {
        line(format!(
            "  {} {}",
            gw.name.as_deref().unwrap_or("KNXnet/IP interface"),
            style.dim(&format!(
                "({}, address {})",
                gw.endpoint.as_deref().unwrap_or("?"),
                gw.individual_address.as_deref().unwrap_or("?")
            ))
        ));
        match (gw.tunnels, gw.tunnels_in_use) {
            (Some(t), Some(m)) => line(format!("  {t} tunnels, {m} in use")),
            (Some(t), None) => line(format!("  {t} tunnels (usage not reported)")),
            _ => line(format!(
                "  {}",
                style.dim("tunnel slots not reported by this interface")
            )),
        }
    }

    line(String::new());
    line(heading("Devices on the bus"));
    let (answered, probed) = live
        .scan
        .as_ref()
        .map_or((0, 0), |scan| (scan.answered, scan.probed));
    line(format!(
        "  {}",
        style.summary(&[(
            format!(
                "{answered} of {} answered",
                count(probed, "device in your project", "devices in your project")
            ),
            if answered == probed {
                Tone::Ok
            } else {
                Tone::Warn
            },
        )])
    ));
    for l in live.scan.iter().flat_map(|scan| &scan.lines) {
        line(format!("  line {}:", l.line));
        for d in &l.answered {
            let mismatch = if d.mask_mismatch {
                style.warn(&format!(
                    " (your project says {})",
                    d.model_mask.as_deref().unwrap_or("?")
                ))
            } else {
                String::new()
            };
            let secure = d
                .secure
                .map(|status| format!(", {}", secure_phrase(status)))
                .unwrap_or_default();
            line(format!(
                "    {} {}, mask {}{}{}",
                d.address,
                style.ok("answered"),
                d.mask,
                mismatch,
                secure
            ));
            if let (Some(check), Ok(address)) = (&d.identity, d.address.parse()) {
                let identity = bussard_service::identity_line(address, check);
                let identity = if check.is_drift() {
                    style.warn(&identity)
                } else {
                    style.dim(&identity)
                };
                line(format!("      {identity}"));
            }
        }
        for d in &l.not_answering {
            line(format!(
                "    {} {} {}",
                d.address,
                d.name,
                style.warn("did not answer")
            ));
        }
    }

    let secure_live = live.secure.as_ref().map_or(&[][..], |s| &s.devices);
    if !secure_live.is_empty() {
        line(String::new());
        line(heading("KNX Secure on the bus"));
        for d in secure_live {
            line(format!(
                "  {} {}: {}",
                d.address,
                d.name,
                secure_phrase(d.status)
            ));
        }
    }

    line(String::new());
    line(heading("Traffic sample"));
    let traffic = &live.traffic;
    line(format!(
        "  {} in {} s",
        count(traffic.telegrams, "group telegram", "group telegrams"),
        traffic.window_seconds
    ));
    for g in &traffic.per_ga {
        line(format!(
            "    {} {}: {}, {} repeated ({:.0}%)",
            g.ga,
            g.name.as_deref().unwrap_or(""),
            count(g.telegrams, "telegram", "telegrams"),
            g.repeated,
            g.repeat_rate * 100.0
        ));
    }
    let orphans: Vec<String> = traffic
        .sender_no_listener
        .iter()
        .map(|g| g.ga.clone())
        .collect();
    list_section(
        &mut line,
        style,
        "group addresses sent on the bus that no device in your project listens to",
        &orphans,
    );
    list_section(
        &mut line,
        style,
        "senders not in your project",
        &traffic.unknown_sources,
    );
    out
}

/// The words for a [`SecureProbeStatus`] (issue #203).
fn secure_phrase(status: SecureProbeStatus) -> &'static str {
    match status {
        SecureProbeStatus::ReachableSecured => "secured, read with the tool key",
        SecureProbeStatus::KeyRefused => {
            "secured, plain reads refused, the tool key was not accepted"
        }
        SecureProbeStatus::NotInKeyring => "secured, plain reads refused, no tool key for it",
        SecureProbeStatus::PlainReadsRefused => {
            "secured, plain reads refused (pass --keyring to read it secured)"
        }
        SecureProbeStatus::Plain => "not secured (answers in the clear)",
        SecureProbeStatus::NotAnswering => "did not answer",
    }
}

/// Prints `label: none` (dim) or `label (N): a, b, c` (the label yellow).
fn list_section(line: &mut impl FnMut(String), style: Style, label: &str, items: &[String]) {
    if items.is_empty() {
        line(format!("  {}", style.dim(&format!("{label}: none"))));
    } else {
        line(format!(
            "  {} {}",
            style.warn(&format!("{label} ({}):", items.len())),
            items.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_text_static_report_has_every_section() {
        let model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        let report = AuditReport::from_model(&model, None);
        let text = render_text(&report, Style::plain());
        for section in [
            "Your project\n",
            "Gaps in your project\n",
            "One-sided links\n",
            "Devices per mask\n",
            "KNX Secure\n",
            "  protected group addresses: none\n",
            "  0 devices, 0 group addresses, 0 links\n",
        ] {
            assert!(text.contains(section), "missing {section}:\n{text}");
        }
        assert!(!text.contains("Gateway"), "static report has no live part");
        assert!(!text.contains("model"), "{text}");
        let rich = render_text(&report, Style::rich());
        assert!(rich.contains("\u{1b}[1mYour project"), "{rich:?}");
    }
}
