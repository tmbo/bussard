//! The device safety-net reads of the default tier (issue #717):
//! `knx_backup_device` and `knx_reconstruct_device`.
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

use std::sync::Arc;
use std::time::SystemTime;

use crate::args::Parameters;
use bussard_model::IndividualAddress;
use bussard_service::backup::{
    BackupInputs, capture_devices, default_out_dir, select_targets, write_backup_run,
};
use bussard_service::reconstruct::{Diff, DifferenceKind, build_report};
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
pub const DEVICE_TOOLS: [&str; 2] = ["knx_backup_device", "knx_reconstruct_device"];

/// Arguments for `knx_backup_device`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct BackupDeviceArgs {
    /// The individual address of the device to back up, e.g. `"1.1.4"`.
    /// Omit it and pass `all: true` to back up every device in the model.
    #[serde(default)]
    pub address: Option<String>,
    /// Back up every device the model lists (instead of one `address`).
    #[serde(default)]
    pub all: Option<bool>,
}

/// Arguments for `knx_reconstruct_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReconstructDeviceArgs {
    /// The individual address of the device to read back, e.g. `"1.1.4"`.
    pub address: String,
}

#[tool_router(router = device_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_backup_device` (omitted in passive mode).
    #[tool(
        description = "Back up ONE device (`address`) or every device in the model (`all: \
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
        model disagree on), `changes`, plus `matches` and `note`. The tables do not say \
        whether an object sends or listens, so the diff compares group-address sets per \
        object. Quote the sentences to the human. Use it after an apply or a restore, or to \
        see what ETS or another tool left on a device. Only available when the server is NOT \
        in passive mode."
    )]
    async fn knx_reconstruct_device(
        &self,
        Parameters(args): Parameters<ReconstructDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match self.reconstruct_device(&args.address).await {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
    }
}

impl BussardMcp {
    /// The connected bus of a default-tier device read, or why there is none.
    fn device_read_bus(&self) -> Result<bussard_service::BusService, String> {
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
                probe_timeouts: bussard_mgmt::Timeouts::discovery(),
                tool_key: &tool_key,
                user_memory_above_64k: &user_memory,
            };
            let captures = capture_devices(&service, inputs, &targets, &mut |_| {}).await;
            write_backup_run(&run_dir, run_gateway, started, &captures)
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
            format!("{target}'s link tables match the model.")
        });
        Ok(out)
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
