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
use std::sync::Arc;
use std::time::SystemTime;

use crate::args::Parameters;
use bussard_model::IndividualAddress;
use bussard_service::backup::{
    BackupInputs, capture_devices, default_out_dir, select_targets, write_backup_run,
};
use bussard_service::line::WalkEvent;
use bussard_service::reconstruct::{Diff, DifferenceKind, build_report};
use bussard_service::reconstruct_line::{
    OutDir, build_summary, check_out_dir, inject_reconstruct_banners, sweep_line, synthesize_model,
};
use bussard_service::scan::LineRange;
use bussard_service::secure::ToolKeySource;
use bussard_service::{FactsCache, identity_line};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::guidance::Tiers;
use crate::server::BussardMcp;
use crate::state::ConnState;

/// The tools this module registers: the default tier, omitted in `--passive`.
pub const DEVICE_TOOLS: [&str; 3] = [
    "knx_backup_device",
    "knx_reconstruct_device",
    "knx_find_devices",
];

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
    /// `knx_backup_device` (omitted in passive mode).
    #[tool(
        description = "Back up ONE device (`address`) or every device in the project (`all: \
        true`) over the bus, as `bussard backup` does (issue #717): reads each device's \
        group-address and association tables and, on System B, the parameter memory the device \
        bounds itself (PID_TABLE_REFERENCE + PID_MCB_TABLE), and writes one JSON file per \
        device plus manifest.json under captures/backups/<timestamp>/. READ-ONLY on the bus \
        (descriptor, authorize, property and memory reads; never a write). Returns `out_dir`, \
        `backup` (the directory name knx_restore_tables takes), `manifest`, `devices` (per \
        device: `status` backed_up, skipped, unreachable or failed, `file`, `mask`, \
        `application`, `parameters` with what was captured or why not, `detail`, \
        `identity`) and `totals`. A device that is switched off is `unreachable`, not a \
        failure; `ok` is false only when a device answered and its read failed. Suggest it \
        before a change the human may want to undo. Backing up every device takes a few \
        seconds per device. Only available when the server is NOT in passive mode."
    )]
    async fn knx_backup_device(
        &self,
        Parameters(args): Parameters<BackupDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let label = args.address.clone().unwrap_or_else(|| "all".to_string());
        match self.backup_devices(args).await {
            Ok(value) => ok(value),
            Err(reason) => refusal(&label, reason),
        }
    }

    /// `knx_reconstruct_device` (omitted in passive mode).
    #[tool(
        description = "Read ONE device's group-address and association tables back over the bus \
        and compare them with its device file, as `bussard reconstruct <address>` does (issue \
        #717). READ-ONLY on the bus. Returns `mask`, `system_type`, `addresses` (the address \
        table), `associations`, `objects` (com-object -> group addresses as resolved from the \
        tables), `table_source`, `notes`, `identity` (the device against bussard.lock), \
        `parameters` (the parameter read-back when bussard.lock pins the product data) and \
        `diff` in the shape knx_diff_project returns: `from`, `to`, `count`, `summary`, \
        `touches_protected`, `sentences` (one per object/group-address pair the device and the \
        project disagree on), `changes`, plus `matches` and `note`. The tables do not say \
        whether an object sends or listens, so the diff compares group-address sets per \
        object. Quote the sentences to the human. Use it after an apply or a restore, or to \
        see what ETS or another tool left on a device. LINE FORM: pass `line` (e.g. \"1.1\") \
        instead of `address` to sweep the line (device numbers `from` to `to`, default 0 to \
        255) and synthesize a fresh project from the tables, as `bussard reconstruct --line` \
        does: written to `out` (a fresh directory relative to the project folder; default \
        captures/reconstructed/line-<line>-<time>), never into the project this server serves. \
        Group names and DPTs are placeholders and every group address is recorded as listen. \
        It runs as a job (about 3 s per address; `started: true` with a `job`: poll \
        knx_job_status) and returns `out`, `devices_found`, `devices_read`, \
        `devices_skipped`, `group_addresses`, `links` and `device_details`. Only available \
        when the server is NOT in passive mode."
    )]
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
            (Some(address), None) => match self.reconstruct_device(&address).await {
                Ok(value) => ok(value),
                Err(reason) => refusal(&address, reason),
            },
            (None, Some(line)) => match self.reconstruct_line(&line, &args).await {
                Ok(value) => ok(value),
                Err(reason) => ok(json!({
                    "line": line,
                    "ok": false,
                    "refused": true,
                    "reason": reason,
                })),
            },
            (Some(_), Some(_)) => refusal("", "pass either `address` or `line`, not both".into()),
            (None, None) => refusal(
                "",
                "pass a device `address`, or a `line` (e.g. \"1.1\") to sweep".into(),
            ),
        }
    }

    /// `knx_find_devices` (omitted in passive mode).
    #[tool(
        description = "Find the devices on ONE line (`line`, e.g. \"1.1\") over the bus, as \
        `bussard scan` does (issue #747): probes each address one at a time and reads each \
        responder's mask, manufacturer, order number and serial, over KNX Data Secure when \
        the server's --keyring holds the device's tool key. READ-ONLY on the bus. `from` and \
        `to` narrow the device numbers (default 0 to 255); an absent address costs tens of \
        milliseconds to about 3 s depending on the interface, so a full line can take \
        minutes. Runs as a job: when it ends within a few seconds the call returns the \
        result, otherwise `started: true` and a `job` id for knx_job_status, whose \
        `progress` counts the addresses `probed` and the devices `found` so far. The result \
        has `summary` (one sentence, names first), `devices` (per responder: `name` from the \
        project or null, `address`, `known` (in the project), `mask`, `system_type`, \
        `manufacturer`, `order_number`, `serial`, `secure` for a Data Secure device, \
        `identity_line` against bussard.lock), `not_in_model`, `missing_from_bus` (the project's \
        devices in the scanned range that did not answer) and `timing`. Tell the human the \
        summary. Only available when the server is NOT in passive mode."
    )]
    async fn knx_find_devices(
        &self,
        Parameters(args): Parameters<FindDevicesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = match crate::tools_find::ScanRequest::parse(&args.line, args.from, args.to) {
            Ok(request) => self.find_devices(request).await,
            Err(reason) => Err(reason),
        };
        match result {
            Ok(value) => ok(value),
            Err(reason) => ok(json!({
                "line": args.line,
                "ok": false,
                "refused": true,
                "reason": reason,
            })),
        }
    }
}

impl BussardMcp {
    /// The connected bus of a default-tier device read, or why there is none.
    pub(crate) fn device_read_bus(&self) -> Result<bussard_service::BusService, String> {
        let state = self.state();
        if state.passive {
            return Err("server is in passive mode; bus management traffic is disabled".into());
        }
        let Some(service) = state.bus.service() else {
            return Err("the bus is not wired".into());
        };
        if state.bus.state() != ConnState::Connected {
            return Err(state.bus.not_connected_reason());
        }
        Ok(service.clone())
    }

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
        let service = self.device_read_bus()?;
        let state = Arc::clone(self.state());
        let model = state.model.reload();
        let targets = select_targets(&model, &addresses, None).map_err(|e| e.to_string())?;
        if targets.is_empty() {
            return Err("no devices to back up: the model has no device files".into());
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
        let source = service
            .checked_source(false)
            .await
            .map_err(|e| e.to_string())?;
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
                bussard_download::uses_user_memory(product.source.as_ref().and_then(|p| p.app()))
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
        let totals = manifest.totals();
        let backed_up = totals.get("backed_up").copied().unwrap_or(0);
        let name = out_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let tiers = Tiers::of(self.state());
        let restore = if tiers.programming {
            format!(
                "To put a device's link tables back later, knx_restore_tables with backup \
                 {name:?} (plan, the human's yes, then the write)."
            )
        } else {
            format!(
                "Restoring a device's link tables needs --allow-programming \
                 (knx_restore_tables with backup {name:?}) or `bussard restore {} <ia>` at the \
                 CLI.",
                out_dir.display()
            )
        };
        Ok(json!({
            "ok": !manifest.any_failed(),
            "out_dir": out_dir.display().to_string(),
            "backup": name,
            "manifest": manifest_path.display().to_string(),
            "gateway": gateway,
            "devices": manifest.devices,
            "totals": totals,
            "next_step": format!(
                "Tell the human {backed_up} device(s) were backed up to {} (list any skipped, \
                 unreachable or failed device with its detail). {restore}",
                out_dir.display()
            ),
        }))
    }

    /// `knx_reconstruct_device`'s body; `Err` is a refusal reason.
    async fn reconstruct_device(&self, address: &str) -> Result<Value, String> {
        let target: IndividualAddress = address
            .trim()
            .parse()
            .map_err(|_| format!("invalid individual address {address:?}"))?;
        let service = self.device_read_bus()?;
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
        let identity = report
            .identity
            .as_ref()
            .map(|check| identity_line(target, check));
        let diff = report
            .diff
            .as_ref()
            .map(|diff| diff_json(target, diff, &model, &dir));
        let differs = report.diff.as_ref().is_some_and(|d| !d.is_empty());
        let mut out = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        out["ok"] = json!(true);
        out["secured"] = json!(tool_key.is_some());
        out["identity_line"] = json!(identity);
        out["diff"] = diff.unwrap_or(Value::Null);
        if let Some(why) = &product.refusal {
            out["parameters_note"] = json!(why);
        }
        out["next_step"] = json!(if differs {
            let tiers = Tiers::of(self.state());
            if tiers.programming {
                format!(
                    "Quote diff.sentences to the human. knx_plan_device and knx_apply_device \
                     write the model's links to {target}; knx_restore_tables puts the link \
                     tables of a backup back. Neither runs without the human's yes to its plan."
                )
            } else {
                format!(
                    "Quote diff.sentences to the human. Writing the model's links to {target} \
                     needs --allow-programming (knx_plan_device, knx_apply_device) or `bussard \
                     plan {target}` and `bussard apply {target}` at the CLI."
                )
            }
        } else {
            format!("{target}'s link tables match your project.")
        });
        Ok(out)
    }
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
                    "out {out:?} must be a relative path inside the model directory, without \
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
        match check_out_dir(&out).map_err(|e| e.to_string())? {
            OutDir::Fresh => {}
            OutDir::File => {
                return Err(format!(
                    "out {} is a file; expected a fresh (absent or empty) directory",
                    out.display()
                ));
            }
            OutDir::NotEmpty => {
                return Err(format!(
                    "out {} is not empty; reconstruction never merges into an existing model \
                     (choose a fresh directory)",
                    out.display()
                ));
            }
        }
        let service = self.device_read_bus()?;
        let at = IndividualAddress::new(area, line_no, 0).map_err(|e| e.to_string())?;
        let job = state.jobs.claim(JobKind::Read, Subject::Device(at))?.id;
        let me = self.clone();
        let id = job.clone();
        let worker_line = line_text.clone();
        state.jobs.spawn(&job, "line sweep", async move {
            let range = (from, to);
            let body =
                me.reconstruct_line_body(&id, &service, (area, line_no), range, &out, &worker_line);
            Ok(body.await.unwrap_or_else(
                |reason| json!({"line": worker_line, "ok": false, "reason": reason}),
            ))
        });
        let wait = state.jobs.read_wait().saturating_sub(began.elapsed());
        if let Some(mut result) = state.jobs.outcome(&job, wait).await {
            result["job"] = json!(job);
            return Ok(result);
        }
        let estimate = bussard_service::reconstruct_line::PER_ADDRESS_ESTIMATE
            * (u32::from(to) - u32::from(from) + 1);
        Ok(json!({
            "started": true,
            "done": false,
            "kind": "read",
            "job": job,
            "line": line_text,
            "step": "sweeping the line",
            "next_step": format!(
                "The sweep of line {line_text} ({from} to {to}) runs in the server as job {job}, \
                 read-only on the bus; it can take up to about {} minute(s). Tell the human it \
                 is running, then call knx_job_status with job {job} every few seconds until \
                 `done` is true and report its `result`.",
                estimate.as_secs().div_ceil(60)
            ),
        }))
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
            let source = service
                .checked_source(false)
                .await
                .map_err(|e| e.to_string())?;
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
        state.jobs.step(job, "writing the reconstructed model");
        let config = bussard_model::schema::BussardConfig {
            connection: model.config.connection.clone(),
            lint: None,
            import: None,
            home_assistant: None,
            enroll: None,
        };
        let synthesized = synthesize_model(&found, config);
        synthesized
            .save(out)
            .map_err(|e| format!("writing the reconstructed model to {}: {e}", out.display()))?;
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
                    .with_result("the model reconstructed from the line sweep"),
            )
        {
            tracing::warn!("could not record a history snapshot: {err}");
        }
        let summary = build_summary(line, out, &found, &synthesized);
        let mut value = serde_json::to_value(&summary).map_err(|e| e.to_string())?;
        value["ok"] = json!(true);
        value["started"] = json!(false);
        value["done"] = json!(true);
        value["next_step"] = json!(format!(
            "Tell the human {} device(s) answered on line {line}: {} read, {} recorded as stubs \
             (name each stub with its skip_reason), and that the model in {} is a scaffold \
             synthesized from the tables: group names and DPTs are placeholders and every group \
             address is recorded as listen, so it needs naming (watch the bus) before it is \
             treated as the truth. It was written to its own directory; the model this server \
             serves is unchanged.",
            summary.devices_found, summary.devices_read, summary.devices_skipped, summary.out
        ));
        Ok(value)
    }
}

/// The diff in the shape `knx_diff_project` returns: from, to, count,
/// summary, touches_protected, sentences and changes, plus the matches and
/// the direction note.
fn diff_json(
    target: IndividualAddress,
    diff: &Diff,
    model: &bussard_model::Model,
    dir: &std::path::Path,
) -> Value {
    let changes = diff.differences(target, Some(model));
    let extra = changes
        .iter()
        .filter(|c| c.kind == DifferenceKind::OnDeviceNotInModel)
        .count();
    let missing = changes.len() - extra;
    let file = model
        .devices
        .get(&target)
        .map(|d| format!("devices/{}.toml", d.file_stem));
    json!({
        "from": match file {
            Some(file) => format!("the model ({file} in {})", dir.display()),
            None => "the model (no device file for this address)".to_string(),
        },
        "to": format!("{target} as read from the bus"),
        "count": changes.len(),
        "summary": if changes.is_empty() {
            "no differences".to_string()
        } else {
            format!(
                "{extra} link(s) on the device the model does not have, {missing} link(s) in the \
                 model the device does not have"
            )
        },
        "touches_protected": changes.iter().any(|c| c.protected),
        "sentences": changes.iter().map(|c| c.sentence.as_str()).collect::<Vec<_>>(),
        "changes": changes,
        "matches": diff.matches.len(),
        "note": diff.note,
    })
}

/// A structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result the caller reads out.
fn refusal(address: &str, reason: String) -> Result<CallToolResult, ErrorData> {
    ok(json!({
        "address": address,
        "ok": false,
        "refused": true,
        "reason": reason,
    }))
}
