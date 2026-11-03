//! Find what is on the bus (issue #747): the line scan of `knx_find_devices`
//! and the live device status of `knx_show_device {live: true}`.
//!
//! Both read only and call the `bussard-service` functions the CLI calls:
//! [`bussard_service::scan::sweep`] (with the same probe per address,
//! [`bussard_service::identity::probe_classified`]) for `bussard scan`, and
//! [`bussard_service::status::read_live_status`] with
//! [`bussard_service::status::status_report`] for `bussard status <ia>`. The
//! scan takes seconds per address, so it runs as a job of the server's job
//! table ([`crate::jobs::JobKind::Scan`]) and reports the addresses probed
//! and the devices found so far while it runs; `knx_job_status` reads it.

use std::sync::Arc;

use bussard_model::{IndividualAddress, Model};
use bussard_secure::Key16;
use bussard_service::scan::{self, LineRange, ScanReport, Sweep, SweepEvent};
use bussard_service::secure::{ToolKeySource, ToolKeys};
use bussard_service::status::{read_live_status, read_only_authorize, status_report};
use bussard_service::{BusService, FactsCache, L4Options, SourcePolicy, identity_line};
use serde_json::{Value, json};

use crate::jobs::JobTable;
use crate::server::BussardMcp;
use crate::state::SharedState;
use crate::warm::WarmConnection;

/// What `knx_find_devices` scans: the parsed line and range.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanRequest {
    /// The addresses to probe.
    pub(crate) range: LineRange,
}

impl ScanRequest {
    /// Parses `line` (`"1.1"`) and the optional device range (default the
    /// whole line, 0 to 255).
    pub(crate) fn parse(line: &str, from: Option<u8>, to: Option<u8>) -> Result<Self, String> {
        let (area, line_no) = scan::parse_line(line.trim()).map_err(|e| e.to_string())?;
        let (from, to) = (from.unwrap_or(0), to.unwrap_or(255));
        if from > to {
            return Err(format!(
                "invalid range: from {from} is greater than to {to}"
            ));
        }
        Ok(ScanRequest {
            range: LineRange {
                area,
                line: line_no,
                from,
                to,
            },
        })
    }

    /// The line as `"1.1"`.
    fn line(&self) -> String {
        format!("{}.{}", self.range.area, self.range.line)
    }
}

impl BussardMcp {
    /// `knx_find_devices`'s body; `Err` is a refusal reason.
    pub(crate) async fn find_devices(&self, request: ScanRequest) -> Result<Value, String> {
        let service = self.device_read_bus()?;
        let state = Arc::clone(self.state());
        // The keyring's tool keys (issue #203): a listed device is identified
        // over A_SecureData, as `bussard scan --keyring`.
        let keys = ToolKeys::load(ToolKeySource {
            keyring: state.keyring.as_deref(),
            tool_key: None,
        })
        .map_err(|e| format!("loading the keyring for the scan: {e}"))?;
        let line = request.line();
        let jobs = Arc::clone(&state.jobs);
        let id = jobs.claim_scan(&line)?;
        let total = request.range.count();
        jobs.progress(&id, "total", json!(total));
        jobs.progress(&id, "probed", json!(0));
        jobs.progress(&id, "found", json!(0));

        // The sweep continues in a server task, so a client that stops
        // waiting does not cut it; the job holds the result.
        let warm = self.warm().clone();
        let task_jobs = Arc::clone(&jobs);
        let task_id = id.clone();
        tokio::spawn(async move {
            let result = run_scan(
                &service, &state, request, &keys, &task_jobs, &task_id, &warm,
            )
            .await;
            task_jobs.finish(&task_id, result);
        });

        if jobs.wait(&id, jobs.read_wait()).await
            && let Some(result) = jobs.result(&id)
        {
            // Answered inline: the job is not needed any more.
            jobs.abandon(&id);
            return Ok(result);
        }
        let estimate = request.range.estimate().as_secs();
        Ok(json!({
            "ok": true,
            "started": true,
            "done": false,
            "job": id,
            "line": line,
            "from": request.range.from,
            "to": request.range.to,
            "addresses": total,
            "estimate_s_worst_case": estimate,
            "summary": format!(
                "Scanning line {line} ({total} addresses, one at a time; up to {}m{:02}s on \
                 TP1). Nothing is written.",
                estimate / 60,
                estimate % 60
            ),
            "next_step": format!(
                "Tell the human the scan of line {line} is running. Call knx_job_status with job \
                 {id} every few seconds: `progress` counts the addresses probed and the devices \
                 found so far, and once `done` is true `result` is the device list."
            ),
        }))
    }

    /// The `live` object of `knx_show_device`: the live status, or `ok:
    /// false` with the reason it was not read.
    pub(crate) async fn live_part(&self, target: IndividualAddress) -> Value {
        match self.live_status(target).await {
            Ok(value) => value,
            Err(reason) => json!({ "ok": false, "reason": reason }),
        }
    }

    /// `knx_show_device {live: true}`'s live part: what `bussard status
    /// <ia>` reads, as JSON; `Err` is a refusal reason.
    pub(crate) async fn live_status(&self, target: IndividualAddress) -> Result<Value, String> {
        let service = self.device_read_bus()?;
        let state = Arc::clone(self.state());
        let model = state.model.current();
        // KNX Data Secure (issue #533): the target's tool key wraps every
        // APDU, as `bussard status --keyring`; the FDSK names a device reset
        // to default (issue #532).
        let activated = bussard_service::secure::model_activated(Some(&model), target);
        let (tool_key, factory_key) = bussard_service::secure::resolve_session_keys(
            target,
            ToolKeySource {
                keyring: state.keyring.as_deref(),
                tool_key: None,
            },
            activated,
        )
        .map_err(|e| e.to_string())?;
        let secured = tool_key.is_some();
        let mut facts = FactsCache::new(&state.dir, false);
        let authorize = read_only_authorize(&mut facts, target);
        let options = L4Options {
            source: SourcePolicy::Check { skip: false },
            tool_key,
            factory_key,
            high_water: bussard_secure::SequenceHighWater::new(),
            authorize,
            ..L4Options::default()
        };
        let _permit = state.read_limiter.acquire().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let read = service
            .with_l4(target, &options, async |l4| {
                read_live_status(l4, &facts)
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await;
        drop(warm);
        let read = read.map_err(|err| format!("{err:#}"))?;
        let device = model.devices.get(&target).map(|d| &d.device);
        let report = status_report(target, device, &read);
        let who = match &report.name {
            Some(name) => format!("{name} ({target})"),
            None => target.to_string(),
        };
        let mut sentences = vec![format!(
            "{who} answers with mask {} ({}).",
            report.mask, report.system_type
        )];
        if let Some(check) = &report.identity {
            sentences.push(format!("{}.", identity_line(target, check)));
        }
        let knxnet_lines: Vec<String> = report
            .knxnet
            .as_ref()
            .map(|k| {
                k.lines()
                    .into_iter()
                    .map(|(label, value)| format!("{label}: {value}"))
                    .collect()
            })
            .unwrap_or_default();
        match (&report.knxnet, &read.knxnet_error) {
            (Some(_), _) if report.model_knxnet.is_some() && report.knxnet_drift.is_empty() => {
                sentences.push(
                    "It is a KNX IP interface; its KNXnet/IP settings match [knxnet] in its \
                     device file."
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
        let mut out = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        out["ok"] = json!(true);
        out["secured"] = json!(secured);
        out["sentences"] = json!(sentences);
        if !knxnet_lines.is_empty() {
            out["knxnet_lines"] = json!(knxnet_lines);
        }
        if let Some(err) = &read.knxnet_error {
            out["knxnet_error"] = json!(err);
        }
        Ok(out)
    }
}

/// The scan job: holds the management slot (issue #215) for the sweep, then
/// sets the responders against the model. Returns the job's result.
async fn run_scan(
    service: &BusService,
    state: &SharedState,
    request: ScanRequest,
    keys: &ToolKeys,
    jobs: &JobTable,
    id: &str,
    warm: &WarmConnection,
) -> Value {
    let line = request.line();
    let mut guard = warm.lock().await;
    guard.release().await;
    // Read-only on the bus. The tunnel-assigned individual address is the
    // source; devices ignore connection-oriented frames from any other
    // source (issue #30).
    let source = match service.checked_source(false).await {
        Ok(source) => source,
        Err(err) => {
            return json!({
                "ok": false,
                "refused": true,
                "line": line,
                "reason": format!("the source address check failed: {err}"),
            });
        }
    };
    // Only a listed address gets a key; any other device is read in the
    // clear (an activated one then shows the hidden mask and its label).
    let key_for = |addr: IndividualAddress| -> Option<Key16> {
        keys.lists(addr).then(|| keys.tool_key(addr)).flatten()
    };
    let mut probed = 0usize;
    let swept = scan::sweep(
        service,
        request.range,
        source,
        &key_for,
        &mut |event| match event {
            SweepEvent::Probing { address, found } => {
                jobs.step(id, format!("probing {address} ({found} found so far)"));
            }
            SweepEvent::Probed { found, .. } => {
                probed += 1;
                jobs.progress(id, "probed", json!(probed));
                jobs.progress(id, "found", json!(found));
            }
        },
    )
    .await;
    drop(guard);
    let model = state.model.reload();
    scan_result(&state.dir, request.range, swept, &model)
}

/// The result of a finished sweep: the responders names first, the model
/// delta of the swept range, and one summary sentence.
fn scan_result(dir: &std::path::Path, range: LineRange, swept: Sweep, model: &Model) -> Value {
    let summary_timing = swept.summary();
    let timing = json!({
        "addresses": swept.timings.len(),
        "total_ms": swept.elapsed.as_millis(),
        "summary": summary_timing,
    });
    let mut report = scan::cross_reference(swept.found, Some(model));
    for f in &mut report.found {
        let device = model.devices.get(&f.address).map(|d| &d.device);
        f.identity = Some(scan::observe_identity(dir, true, f.address, f.mask, device));
    }
    let name_of = |addr: IndividualAddress| -> Option<String> {
        model
            .devices
            .get(&addr)
            .map(|d| d.device.name.clone())
            .filter(|n| !n.is_empty())
    };
    let devices: Vec<Value> = report
        .found
        .iter()
        .map(|f| device_row(f, name_of(f.address), &report))
        .collect();
    let missing: Vec<(IndividualAddress, String)> = report
        .missing
        .iter()
        .filter(|(addr, _)| range.contains(*addr))
        .cloned()
        .collect();
    let line = format!("{}.{}", range.area, range.line);
    let summary = summary(&line, &report, &missing, &name_of, swept.timings.len());
    json!({
        "ok": true,
        "line": line,
        "from": range.from,
        "to": range.to,
        "summary": summary,
        "devices": devices,
        "not_in_model": report
            .not_in_model
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "missing_from_bus": missing
            .iter()
            .map(|(addr, name)| json!({ "name": name, "address": addr.to_string() }))
            .collect::<Vec<_>>(),
        "timing": timing,
        "next_step": "Tell the human the summary and the devices by name. knx_show_device with \
            `live: true` reads one device's live status (identity, and for an IP interface its \
            IP settings and tunnels).",
    })
}

/// One responder as `knx_find_devices` lists it: name first.
fn device_row(f: &scan::Found, name: Option<String>, report: &ScanReport) -> Value {
    let mut row = json!({
        "name": name,
        "address": f.address.to_string(),
        "known": report.known(f.address),
        "mask": format!("{:04X}", f.mask),
        "system_type": f.system_type(),
        "manufacturer": f.manufacturer_id.map(bussard_mgmt::manufacturers::display),
        "manufacturer_id": f.manufacturer_id.map(|id| format!("{id:#06X}")),
        "order_number": f.order,
        "serial": f.serial.as_deref().map(hex),
    });
    if f.secure.activated() {
        row["secure"] = json!(f.secure.as_str());
        row["secure_note"] = json!(scan::secure_label(f.secure));
    }
    if let Some(check) = &f.identity {
        row["identity"] = json!(check);
        row["identity_line"] = json!(identity_line(f.address, check));
    }
    row
}

/// The one-sentence summary of a scan, names first.
fn summary(
    line: &str,
    report: &ScanReport,
    missing: &[(IndividualAddress, String)],
    name_of: &dyn Fn(IndividualAddress) -> Option<String>,
    probed: usize,
) -> String {
    let who = |addr: IndividualAddress| match name_of(addr) {
        Some(name) => format!("{name} ({addr})"),
        None => format!("{addr} (not in the model)"),
    };
    let answered: Vec<String> = report.found.iter().map(|f| who(f.address)).collect();
    let mut out = if answered.is_empty() {
        format!("No device answered on line {line} ({probed} addresses probed).")
    } else {
        format!(
            "{} device(s) answered on line {line} ({probed} addresses probed): {}.",
            answered.len(),
            answered.join(", ")
        )
    };
    if !missing.is_empty() {
        let names: Vec<String> = missing
            .iter()
            .map(|(addr, name)| {
                if name.is_empty() {
                    addr.to_string()
                } else {
                    format!("{name} ({addr})")
                }
            })
            .collect();
        out.push_str(&format!(
            " {} model device(s) in the scanned range did not answer: {}.",
            names.len(),
            names.join(", ")
        ));
    }
    out
}

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_request_parse_defaults_to_the_whole_line() -> Result<(), String> {
        let request = ScanRequest::parse(" 1.1 ", None, None)?;
        assert_eq!(request.range.count(), 256);
        assert_eq!(request.line(), "1.1");
        assert!(ScanRequest::parse("1.1", Some(9), Some(3)).is_err());
        assert!(ScanRequest::parse("16.1", None, None).is_err());
        Ok(())
    }

    #[test]
    fn test_hex_formats_lowercase() {
        assert_eq!(hex(&[0xDE, 0xAD]), "dead");
    }
}
