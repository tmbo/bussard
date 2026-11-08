//! The device reads of the default tier: the safety-net reads
//! `knx_backup_device` and `knx_reconstruct_device` (issue #717), and the line
//! scan `knx_find_devices` (issue #747, body in [`crate::tools_find`]).
//!
//! Both are read-only on the bus and call the `bussard-service` functions the
//! CLI's `bussard backup` and `bussard reconstruct <address>` call:
//! [`bussard_service::backup::capture_devices`] and
//! [`bussard_service::backup::write_backup_run`] for the backup,
//! [`bussard_service::reconstruct::build_report`] for the read-back and its
//! diff against the model. The reconstruct read is the session
//! `knx_plan_device` reads on. Neither is registered in `--passive` mode,
//! since both transmit management traffic. A backup writes its files under
//! `<dir>/captures/backups/<timestamp>/`, where `knx_restore_tables` and
//! `bussard restore` read them.

use crate::jobs::{JobKind, Subject};
use crate::reply::{answer_chat, answer_on};
use std::sync::Arc;
use std::time::SystemTime;

use crate::args::Parameters;
use bussard_model::IndividualAddress;
use bussard_service::FactsCache;
use bussard_service::backup::BackupOutcome;
use bussard_service::backup::{
    BackupInputs, capture_devices, default_out_dir, select_targets, write_backup_run,
};
use bussard_service::line::WalkEvent;
use bussard_service::reconstruct::build_report;
use bussard_service::reconstruct_line::{
    OutDir, build_summary, check_out_dir, inject_reconstruct_banners, sweep_line, synthesize_model,
};
use bussard_service::scan::LineRange;
use bussard_service::secure::ToolKeySource;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::Value;

use crate::guidance::Tiers;
use crate::server::BussardMcp;
use crate::state::Need;

/// Arguments for `knx_backup_device`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct BackupDeviceArgs {
    /// The address of the device to back up, e.g. `"1.1.4"`.
    /// Omit it and pass `all: true` to back up every device in the project.
    #[serde(default)]
    pub address: Option<String>,
    /// Back up every device the project lists (instead of one `address`).
    #[serde(default)]
    pub all: Option<bool>,
}

/// Arguments for `knx_reconstruct_device`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ReconstructDeviceArgs {
    /// The address of the device to read back, e.g. `"1.1.4"`.
    /// Pass either `address` or `line`.
    #[serde(default)]
    pub address: Option<String>,
    /// A line, e.g. `"1.1"`: sweep it and synthesize a fresh project from the
    /// tables, as `bussard reconstruct --line` does.
    #[serde(default)]
    pub line: Option<String>,
    /// With `line`: the fresh (absent or empty) directory to write the project
    /// to, relative to the project folder. Default:
    /// `captures/reconstructed/line-<line>-<unix time>`.
    #[serde(default)]
    pub out: Option<String>,
    /// With `line`: the first device number to probe (default 0).
    #[serde(default)]
    pub from: Option<u8>,
    /// With `line`: the last device number to probe (default 255).
    #[serde(default)]
    pub to: Option<u8>,
}

/// Arguments for `knx_find_devices`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindDevicesArgs {
    /// The line to scan, `"1.1"` (area.line; a full address's device part
    /// is ignored).
    pub line: String,
    /// The first device number to probe (default 0). Narrow the range when
    /// the device numbers of interest are known: a full line is 256 probes.
    #[serde(default)]
    pub from: Option<u8>,
    /// The last device number to probe (default 255).
    #[serde(default)]
    pub to: Option<u8>,
}

#[tool_router(router = device_router, vis = "pub(crate)")]
impl BussardMcp {
    // `knx_backup_device` (omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_backup_device.md")]
    #[tool]
    async fn knx_backup_device(
        &self,
        Parameters(args): Parameters<BackupDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let label = args.address.clone().unwrap_or_else(|| "all".to_string());
        answer_chat(
            "address",
            &label,
            self.backup_devices(args).await,
            &self.model(),
        )
    }

    // `knx_reconstruct_device` (omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_reconstruct_device.md")]
    #[tool]
    async fn knx_reconstruct_device(
        &self,
        Parameters(args): Parameters<ReconstructDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let given = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        match (given(&args.address), given(&args.line)) {
            (Some(address), None) => answer_chat(
                "address",
                &address,
                self.reconstruct_device(&address).await,
                &self.model(),
            ),
            (None, Some(line)) => answer_chat(
                "line",
                &line,
                self.reconstruct_line(&line, &args).await,
                &self.model(),
            ),
            (Some(_), Some(_)) => answer_on(
                "address",
                "",
                Err("pass either `address` or `line`, not both".into()),
            ),
            (None, None) => answer_on(
                "address",
                "",
                Err("pass a device `address`, or a `line` (e.g. \"1.1\") to sweep".into()),
            ),
        }
    }

    // `knx_find_devices` (omitted in passive mode).
    #[doc = include_str!("../guidance/tools/knx_find_devices.md")]
    #[tool]
    async fn knx_find_devices(
        &self,
        Parameters(args): Parameters<FindDevicesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = match crate::tools_find::ScanRequest::parse(&args.line, args.from, args.to) {
            Ok(request) => self.find_devices(request).await,
            Err(reason) => Err(reason),
        };
        answer_on("line", &args.line, result)
    }
}

impl BussardMcp {
    /// `knx_backup_device`'s body; `Err` is a refusal reason.
    async fn backup_devices(&self, args: BackupDeviceArgs) -> Result<Value, String> {
        let all = args.all.unwrap_or(false);
        let addresses: Vec<String> = match (args.address.as_deref().map(str::trim), all) {
            (Some(address), false) if !address.is_empty() => vec![address.to_string()],
            (None, true) | (Some(""), true) => Vec::new(),
            (Some(_), true) => {
                return Err("pass either `address` or `all: true`, not both".into());
            }
            _ => return Err("pass a device `address`, or `all: true` for every device".into()),
        };
        let service = self.state().live_service(Need::Manage)?.clone();
        let state = Arc::clone(self.state());
        let model = state.model.reload();
        let targets = select_targets(&model, &addresses, None).map_err(|e| e.to_string())?;
        if targets.is_empty() {
            return Err("no devices to back up: your project has no device files".into());
        }
        let gateway = state
            .bus
            .diagnostics()
            .map(|d| d.interface)
            .unwrap_or_else(|| "the bus".to_string());
        let dir = state.dir.clone();
        let started = SystemTime::now();
        let out_dir = default_out_dir(&dir, started);

        // A burst of management round-trips: hold the rate limiter's permit
        // and the management slot (issue #215) for the whole run.
        let _permit = self.state().read_limiter.acquire().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let source = service.checked_source(false).await?;
        // The run continues in its own task, so a client that stops waiting
        // does not leave a half-written backup: the files land either way.
        let run_dir = out_dir.clone();
        let run_gateway = gateway.clone();
        let task = tokio::spawn(async move {
            let facts = FactsCache::new(&dir, false);
            let keyring = state.keyring.clone();
            let tool_key = |target: IndividualAddress, activated: bool| {
                bussard_service::secure::resolve(
                    target,
                    ToolKeySource {
                        keyring: keyring.as_deref(),
                        tool_key: None,
                    },
                    activated,
                )
            };
            let user_memory = |target: IndividualAddress| {
                let product = crate::tools_program::product_for(&dir, &model, target);
                bussard_service::download::uses_user_memory(
                    product.source.as_ref().and_then(|p| p.app()),
                )
            };
            let inputs = BackupInputs {
                model: &model,
                source,
                facts: &facts,
                tool_key: &tool_key,
                user_memory_above_64k: &user_memory,
            };
            let captures = capture_devices(&service, inputs, &targets, &mut |_| {}).await;
            write_backup_run(&run_dir, run_gateway, started, captures)
        });
        let written = task
            .await
            .map_err(|e| format!("the backup task stopped unexpectedly: {e}"))?;
        drop(warm);
        let (manifest, manifest_path) =
            written.map_err(|e| format!("writing the backup failed: {e}"))?;
        let mut outcome = BackupOutcome::new(&out_dir, manifest, &manifest_path);
        outcome.programming = Tiers::of(self.state()).programming;
        Ok(crate::reply::report(&outcome, &self.model()))
    }

    /// `knx_reconstruct_device`'s body; `Err` is a refusal reason.
    async fn reconstruct_device(&self, address: &str) -> Result<Value, String> {
        let target: IndividualAddress = address
            .trim()
            .parse()
            .map_err(|_| format!("invalid individual address {address:?}"))?;
        let service = self.state().live_service(Need::Manage)?.clone();
        let state = Arc::clone(self.state());
        let model = state.model.reload();
        let dir = state.dir.clone();
        // The product data the parameter read-back decodes with, when the
        // lock pins it; without it the tables are still read and diffed.
        let product = crate::tools_program::product_for(&dir, &model, target);
        // KNX Data Secure (issue #170): the target's tool key wraps every
        // APDU, as `bussard reconstruct --keyring`; the FDSK names a device
        // reset to default (issue #532).
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
        let _permit = state.read_limiter.acquire().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let read = crate::tools_program::read_for_reconstruct(
            &service,
            target,
            (&tool_key, &factory_key),
            &dir,
            &model,
            product.source.as_ref(),
        )
        .await;
        drop(warm);
        let (live, check, params) = read?;
        let mut report = build_report(target, live.tables(), Some(&model));
        report.parameters = params.map(|p| p.readback);
        report.identity = check;
        report.secured = tool_key.is_some();
        report.parameters_note = product.refusal.clone();
        report.programming = Tiers::of(self.state()).programming;
        let report = report.with_differences(target, &model);
        Ok(crate::reply::report(&report, &model))
    }
}

/// A line sweep still running, as its call answers.
#[derive(serde::Serialize)]
struct SweepStarted {
    /// Always a read job.
    kind: JobKind,
    /// The line.
    line: String,
}

/// Resolves `out` (relative to the model directory, without `..`) or the
/// default `captures/reconstructed/line-<line>-<unix time>`.
fn reconstruct_out(
    dir: &std::path::Path,
    out: Option<&str>,
    line: &str,
) -> Result<std::path::PathBuf, String> {
    match out.map(str::trim).filter(|o| !o.is_empty()) {
        Some(out) => {
            let path = std::path::Path::new(out);
            let escapes = path.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            });
            if escapes {
                return Err(format!(
                    "out {out:?} must be a relative path inside the project folder, without \
                     `..`"
                ));
            }
            Ok(dir.join(path))
        }
        None => {
            let unix = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Ok(dir
                .join("captures")
                .join("reconstructed")
                .join(format!("line-{line}-{unix}")))
        }
    }
}

impl BussardMcp {
    /// `knx_reconstruct_device` with `line`; `Err` is a refusal reason.
    ///
    /// The sweep runs as a read job of the server's job table (it takes up
    /// to about 3 s per address): the call answers with the result when the
    /// sweep ends within the read wait, else with `started: true` and the
    /// job id for knx_job_status.
    async fn reconstruct_line(
        &self,
        line: &str,
        args: &ReconstructDeviceArgs,
    ) -> Result<Value, String> {
        let began = std::time::Instant::now();
        let (area, line_no) = bussard_service::line::parse_line(line).map_err(|e| e.to_string())?;
        let line_text = format!("{area}.{line_no}");
        let (from, to) = (args.from.unwrap_or(0), args.to.unwrap_or(255));
        if from > to {
            return Err(format!(
                "invalid range: from {from} is greater than to {to}"
            ));
        }
        let state = Arc::clone(self.state());
        let dir = state.dir.clone();
        let out = reconstruct_out(&dir, args.out.as_deref(), &line_text)?;
        match check_out_dir(&out)? {
            OutDir::Fresh => {}
            OutDir::File => {
                return Err(format!(
                    "out {} is a file; expected a fresh (absent or empty) directory",
                    out.display()
                ));
            }
            OutDir::NotEmpty => {
                return Err(format!(
                    "out {} is not empty; reconstruction never merges into an existing project \
                     (choose a fresh directory)",
                    out.display()
                ));
            }
        }
        let service = self.state().live_service(Need::Manage)?.clone();
        let at = IndividualAddress::new(area, line_no, 0).map_err(|e| e.to_string())?;
        let job = state.jobs.claim(JobKind::Read, Subject::Device(at))?.id;
        let me = self.clone();
        let id = job.clone();
        let worker_line = line_text.clone();
        state.jobs.spawn(&job, "line sweep", async move {
            let range = (from, to);
            let body =
                me.reconstruct_line_body(&id, &service, (area, line_no), range, &out, &worker_line);
            Ok(body.await.unwrap_or_else(|reason| {
                serde_json::to_value(bussard_service::report::Refusal {
                    line: Some(worker_line),
                    ..bussard_service::report::Refusal::new(reason)
                })
                .unwrap_or_default()
            }))
        });
        let wait = state.jobs.read_wait().saturating_sub(began.elapsed());
        if let Some(mut result) = state.jobs.outcome(&job, wait).await {
            if let Some(map) = result.as_object_mut() {
                map.insert("job".to_string(), Value::String(job));
            }
            return Ok(result);
        }
        let estimate = bussard_service::reconstruct_line::PER_ADDRESS_ESTIMATE
            * (u32::from(to) - u32::from(from) + 1);
        Ok(crate::reply::started_with(
            &job,
            "sweeping the line",
            SweepStarted {
                kind: JobKind::Read,
                line: line_text.clone(),
            },
            None,
            format!(
                "The sweep of line {line_text} ({from} to {to}) runs in the server as job {job}, \
                 read-only on the bus; it can take up to about {} minute(s). Tell the human it \
                 is running, then call knx_job_status with job {job} every few seconds until \
                 `done` is true and report its `result`.",
                estimate.as_secs().div_ceil(60)
            ),
        ))
    }

    /// The sweep, the synthesized model and its summary, run inside the
    /// read job; `Err` is the reason it stopped.
    async fn reconstruct_line_body(
        &self,
        job: &str,
        service: &bussard_service::BusService,
        (area, line_no): (u8, u8),
        (from, to): (u8, u8),
        out: &std::path::Path,
        line: &str,
    ) -> Result<Value, String> {
        let state = Arc::clone(self.state());
        // The model dir only supplies the connection block; the synthesized
        // model is written to `out`, never merged into it.
        let model = state.model.reload();
        let history = bussard_model::history::History::open(&state.dir);
        if let Err(err) = history.snapshot_if_changed_externally() {
            tracing::warn!("could not record a history snapshot: {err}");
        }
        let found = {
            let _permit = state.read_limiter.acquire().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            let source = service.checked_source(false).await?;
            let jobs = Arc::clone(&state.jobs);
            let range = LineRange {
                area,
                line: line_no,
                from,
                to,
            };
            let found = sweep_line(service, range, source, &mut |event| {
                if let WalkEvent::Probing {
                    address,
                    index,
                    total,
                    found,
                } = event
                {
                    jobs.step(
                        job,
                        format!("probing {address} ({index} of {total}), {found} device(s) found"),
                    );
                }
            })
            .await;
            drop(warm);
            found
        };
        state.jobs.step(job, "writing the reconstructed project");
        let config = bussard_model::schema::BussardConfig {
            connection: model.config.connection.clone(),
            lint: None,
            import: None,
            home_assistant: None,
            enroll: None,
        };
        let synthesized = synthesize_model(&found, config);
        synthesized.save(out).map_err(|e| {
            format!(
                "writing the reconstructed project to {}: {e}",
                out.display()
            )
        })?;
        inject_reconstruct_banners(out).map_err(|e| {
            let cause = std::error::Error::source(&e)
                .map(|c| format!(": {c}"))
                .unwrap_or_default();
            format!("{e}{cause}")
        })?;
        // `out` was empty, so there is no prior state to preserve; the
        // snapshot records the reconstructed model itself as the baseline
        // the next edit is measured against (issue #110).
        let out_history = bussard_model::history::History::open(out);
        if out_history.has_model_files()
            && let Err(err) = out_history.snapshot(
                bussard_model::history::SnapshotReason::new("mcp knx_reconstruct_device")
                    .with_args(["--line".to_string(), line.to_string()])
                    .with_result("the project reconstructed from the line sweep"),
            )
        {
            tracing::warn!("could not record a history snapshot: {err}");
        }
        let summary = build_summary(line, out, &found, &synthesized);
        let mut value = crate::reply::report(&summary, &model);
        crate::reply::with_job(&mut value, job, false, true);
        Ok(value)
    }
}
