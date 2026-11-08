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

use crate::jobs::{JobKind, Subject};
use std::sync::Arc;

use bussard_model::{IndividualAddress, Model};
use bussard_service::line::WalkEvent;
use bussard_service::scan::{self, LineRange, ScanOutcome, Sweep};
use bussard_service::secure::Key16;
use bussard_service::secure::{ToolKeySource, ToolKeys};
use bussard_service::status::{read_live_status, read_only_authorize, status_report};
use bussard_service::{BusService, FactsCache, L4Options, SourcePolicy};
use serde_json::Value;

use crate::jobs::JobTable;
use crate::server::BussardMcp;
use crate::state::{Need, SharedState};
use crate::warm::WarmConnection;

/// What a started scan establishes.
#[derive(serde::Serialize)]
struct ScanStarted {
    /// The line.
    line: String,
    /// The first device number.
    from: u8,
    /// The last device number.
    to: u8,
    /// How many addresses.
    addresses: usize,
    /// The worst-case duration in seconds.
    estimate_s_worst_case: u64,
}

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
        let (area, line_no) = bussard_service::line::parse_line(line).map_err(|e| e.to_string())?;
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
        let service = self.state().live_service(Need::Manage)?.clone();
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
        let id = jobs.claim(JobKind::Scan, Subject::Line(&line))?.id;
        let total = request.range.count();
        jobs.progress(&id, |p| {
            p.total = Some(total);
            p.probed = Some(0);
            p.found = Some(0);
        });

        // The sweep continues in a server task, so a client that stops
        // waiting does not cut it; the job holds the result.
        let warm = self.warm().clone();
        let task_jobs = Arc::clone(&jobs);
        let task_id = id.clone();
        jobs.spawn(&id, "scan", async move {
            Ok(run_scan(
                &service, &state, request, &keys, &task_jobs, &task_id, &warm,
            )
            .await)
        });
        if let Some(result) = jobs.outcome(&id, jobs.read_wait()).await {
            // Answered inline: the job is not needed any more.
            jobs.abandon(&id);
            return Ok(result);
        }
        let estimate = request.range.estimate().as_secs();
        let mut out = crate::reply::started_with(
            &id,
            "scanning the line",
            ScanStarted {
                line: line.clone(),
                from: request.range.from,
                to: request.range.to,
                addresses: total,
                estimate_s_worst_case: estimate,
            },
            None,
            format!(
                "Tell the human the scan of line {line} is running. Call knx_job_status with job \
                 {id} every few seconds: `progress` counts the addresses probed and the devices \
                 found so far, and once `done` is true `result` is the device list."
            ),
        );
        crate::reply::envelope(
            &mut out,
            Some(format!(
                "Scanning line {line} ({total} addresses, one at a time; up to {}m{:02}s on \
                 TP1). Nothing is written.",
                estimate / 60,
                estimate % 60
            )),
            None,
        );
        Ok(out)
    }

    /// The `live` object of `knx_show_device`: the live status, or `ok:
    /// false` with the reason it was not read.
    pub(crate) async fn live_part(&self, target: IndividualAddress) -> Value {
        match self.live_status(target).await {
            Ok(value) => value,
            Err(reason) => {
                serde_json::to_value(bussard_service::report::Refusal::new(reason))
                    .unwrap_or_default()
            }
        }
    }

    /// `knx_show_device {live: true}`'s live part: what `bussard status
    /// <ia>` reads, as JSON; `Err` is a refusal reason.
    pub(crate) async fn live_status(&self, target: IndividualAddress) -> Result<Value, String> {
        let service = self.state().live_service(Need::Manage)?.clone();
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
        let options = L4Options::secured(
            SourcePolicy::Check { skip: false },
            tool_key,
            bussard_service::secure::SequenceHighWater::new(),
        )
        .with_factory_key(factory_key)
        .with_authorize(authorize);
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
        let report = status_report(target, device, &read, secured);
        serde_json::to_value(&report).map_err(|e| e.to_string())
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
            return serde_json::to_value(bussard_service::report::Refusal {
                line: Some(line),
                ..bussard_service::report::Refusal::new(format!(
                    "the source address check failed: {err}"
                ))
            })
            .unwrap_or_default();
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
            WalkEvent::Probing { address, found, .. } => {
                jobs.step(id, format!("probing {address} ({found} found so far)"));
            }
            WalkEvent::Probed { found, .. } => {
                probed += 1;
                jobs.progress(id, |p| {
                    p.probed = Some(probed);
                    p.found = Some(found);
                });
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
    let timing = scan::ScanTiming::of(&swept);
    let mut report = scan::cross_reference(swept.found, Some(model));
    for f in &mut report.found {
        let device = model.devices.get(&f.address).map(|d| &d.device);
        f.identity = Some(scan::observe_identity(dir, true, f.address, f.mask, device));
    }
    crate::reply::report(&ScanOutcome::new(range, &report, timing, Some(model)), model)
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
}
