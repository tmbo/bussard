//! `knx_restore_tables` (issue #717): write a device's backed-up link tables
//! back onto it, as `bussard restore <BACKUP_DIR> <ADDRESS>` does.
//!
//! The CLI's restore is `apply` with the desired tables taken from a backup
//! file instead of the device file's links
//! ([`bussard_download::backup::DeviceBackup::desired_tables`]). This tool is
//! the same over the programming tier: the plan, the digest, the audit
//! snapshot, the pre-write backup, the table write and the independent
//! read-back are `knx_apply_device`'s ([`BussardMcp::apply_write`]), fed with
//! the backup's tables. Only the tables are written; a parameter image the
//! backup carries is left alone, as the CLI's restore leaves it. The plan
//! digest binds the device, the backup file's bytes, the live tables read and
//! what a secured write gives the security object, so a device or backup that
//! moves between the plan and the write retires it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use bussard_download::backup::{
    DeviceBackup, backups_root, find_device_backup, read_device_backup,
};
use bussard_download::{
    DesiredTables, DevicePlan, PlanReport, PlanWrites, SecurityInputs, Sys7TableImages, plan,
    render_plan_text, state_hash, sys7_table_images, write_pre_write_backup,
};
use bussard_mgmt::{MaskProfile, system_type};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::params::BuiltPlan;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    BussardMcp, DeviceRead, Origin, Prepared, ProgrammingTier, chain, live_digest, put,
    read_device, refuse_protected, security_inputs, security_json,
};

/// One table-restore plan this session produced, remembered until written,
/// refused or expired.
#[derive(Debug, Clone)]
pub(super) struct PendingTables {
    /// The device.
    target: IndividualAddress,
    /// The backup file.
    file: PathBuf,
    /// When the plan was produced.
    created: Instant,
}

/// What a table restore read and planned.
struct Planned {
    /// The model the security inputs came from.
    model: Arc<Model>,
    /// The checked source address.
    source: IndividualAddress,
    /// The read the plan came from.
    read: DeviceRead,
    /// The backup.
    backup: DeviceBackup,
    /// The backup's tables.
    desired: DesiredTables,
    /// The table plan.
    report: PlanReport,
    /// The security-object inputs, on the secured System B path.
    security: Option<SecurityInputs>,
    /// The System 7 table images, on System 7.
    images: Option<Sys7TableImages>,
    /// The Data Secure tool key, `None` on the plain path.
    tool_key: Option<Key16>,
    /// The send-sequence high-water mark of the read and the write.
    high_water: SequenceHighWater,
    /// Whether nothing differs.
    noop: bool,
    /// The plan digest.
    digest: String,
}

/// Resolves `backup` to one device backup file of `target` under the model's
/// backup root `<dir>/captures/backups`: omitted, the newest file for the
/// device in the root itself (the pre-write backups `apply` and
/// `knx_apply_device` keep); a directory name or path there (a `bussard
/// backup` or `knx_backup_device` run), the newest file for the device in it;
/// a file there, that file.
fn backup_file(
    dir: &Path,
    backup: Option<&str>,
    target: IndividualAddress,
) -> Result<PathBuf, String> {
    let root = backups_root(dir);
    let candidate = match backup.map(str::trim).filter(|b| !b.is_empty()) {
        None => root.clone(),
        Some(given) => {
            let given = Path::new(given);
            if given.is_absolute() {
                given.to_path_buf()
            } else if given.starts_with("captures") {
                dir.join(given)
            } else {
                root.join(given)
            }
        }
    };
    let (Ok(found), Ok(root_abs)) = (
        std::fs::canonicalize(&candidate),
        std::fs::canonicalize(&root),
    ) else {
        return Err(format!(
            "no backup {} under {}; pass the `backup` name knx_backup_device returned (a \
             directory there), or omit it for the pre-write backups apply keeps",
            backup.unwrap_or("(the backup root)"),
            root.display()
        ));
    };
    if !found.starts_with(&root_abs) {
        return Err(format!(
            "{} is not under {}; knx_restore_tables restores only the backups bussard keeps \
             there",
            candidate.display(),
            root.display()
        ));
    }
    if found.is_dir() {
        return find_device_backup(&found, target).map_err(|e| e.to_string());
    }
    if found.is_file() {
        return Ok(found);
    }
    Err(format!(
        "{} is not a backup file or directory",
        found.display()
    ))
}

/// The plan digest of a table restore.
fn tables_digest(
    target: IndividualAddress,
    backup_bytes: &[u8],
    read: &DeviceRead,
    desired: &DesiredTables,
    security: Option<&SecurityInputs>,
) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-restore-tables-v1");
    put(&mut h, &target.raw().to_be_bytes());
    put(&mut h, backup_bytes);
    put(&mut h, &live_digest(read));
    let addresses: Vec<u8> = desired
        .addresses
        .iter()
        .flat_map(|ga| ga.raw().to_be_bytes())
        .collect();
    put(&mut h, &addresses);
    let associations: Vec<u8> = desired
        .associations
        .iter()
        .flat_map(|(tsap, asap)| {
            let mut pair = tsap.to_be_bytes().to_vec();
            pair.extend_from_slice(&asap.to_be_bytes());
            pair
        })
        .collect();
    put(&mut h, &associations);
    match security {
        Some(inputs) => put(&mut h, inputs.describe(&desired.addresses).as_bytes()),
        None => put(&mut h, b"plain"),
    }
    let bytes: [u8; 32] = h.finalize().into();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The device plan of a restore: the tables only, no parameter, flag or
/// security change of its own beyond what the System 7 images carry.
fn tables_only_plan(
    target: IndividualAddress,
    model: &Model,
    gateway: &str,
    dir: &Path,
    planned: &Planned,
) -> BuiltPlan {
    BuiltPlan {
        plan: DevicePlan {
            address: target.to_string(),
            name: model
                .devices
                .get(&target)
                .map(|d| d.device.name.clone())
                .unwrap_or_default(),
            gateway: gateway.to_string(),
            changes: Vec::new(),
            channels: BTreeMap::new(),
            unchanged_objects: 0,
            unchanged_parameters: None,
            writes: PlanWrites {
                address_table: Some(planned.desired.addresses.len()),
                association_table: Some(planned.desired.associations.len()),
                communication_flags: planned
                    .images
                    .as_ref()
                    .map(|i| i.flag_writes.iter().map(|f| f.object).collect())
                    .unwrap_or_default(),
                ..PlanWrites::default()
            },
            backup_dir: backups_root(dir).display().to_string(),
            notes: Vec::new(),
            state_hash: state_hash(&planned.read.live, None),
        },
        partial: None,
        parameters: Vec::new(),
        refusal: None,
        needs_flash: None,
        parameters_skipped: Some(
            "a restore writes the link tables only, as `bussard restore` does".to_string(),
        ),
        octet_ranges: Vec::new(),
        object_table: None,
    }
}

impl BussardMcp {
    /// `knx_restore_tables`'s body; `Err` is a refusal reason.
    pub(super) async fn restore_tables(
        &self,
        address: &str,
        backup: Option<&str>,
        digest: Option<&str>,
    ) -> Result<Value, String> {
        let target = super::parse_address(address)?;
        let (tier, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let file = backup_file(&dir, backup, target)?;
        let Some(digest) = digest else {
            if let Some(refusal) = tier.jobs.busy(crate::apply_jobs::JobKind::Plan) {
                return Err(refusal);
            }
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            let planned = self.plan_tables(target, &file).await;
            drop(warm);
            let planned = planned?;
            return Ok(self.tables_plan_json(tier, target, &file, &gateway, &planned));
        };
        let digest = digest.to_string();
        self.run_job(target, "restore", move |me, job, started| async move {
            me.tables_job(&job, target, &file, &digest, started).await;
        })
        .await
    }

    /// Reads `target` and plans writing the tables of the backup at `file`.
    async fn plan_tables(&self, target: IndividualAddress, file: &Path) -> Result<Planned, String> {
        let (_, service, _) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let backup = read_device_backup(file).map_err(|e| chain(&e))?;
        let backed_up = backup.device_address(file).map_err(|e| chain(&e))?;
        if backed_up != target {
            return Err(format!(
                "{} is a backup of {backed_up}, not {target}",
                file.display()
            ));
        }
        let desired = backup.desired_tables(file).map_err(|e| chain(&e))?;
        let model = self.state().model.reload();
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let tunnel = self.admitted_tunnel(&model, tool_key.is_some())?;
        let high_water = SequenceHighWater::new();
        // The tables only, at the default System 7 bases, as the CLI's
        // restore reads them: no product data, no parameter memory.
        let (source, read) = read_device(
            &service,
            target,
            &tool_key,
            &material.fdsk,
            &high_water,
            &dir,
            &model,
            None,
            &[],
            None,
        )
        .await?;
        let tables = read.live.tables();
        if !MaskProfile::from_mask(tables.mask)
            .capabilities()
            .plan_apply
        {
            return Err(format!(
                "{target} reports mask {:04X} ({}); refusing to write a device outside the \
                 System B / System 7 families",
                tables.mask,
                system_type(tables.mask)
            ));
        }
        let backup_mask = backup.mask_version(file).map_err(|e| chain(&e))?;
        if backup_mask != tables.mask {
            return Err(format!(
                "{} was read from a device with mask {backup_mask:04X}; {target} reports {:04X} \
                 now, so its tables do not belong on it",
                file.display(),
                tables.mask
            ));
        }
        let report = plan(tables, &desired);
        refuse_protected(&model, &report)?;
        let security = security_inputs(
            &model, target, &desired, &material, &read.live, &tunnel, &dir,
        )?;
        let images = match read.live.sys7() {
            Some(s7) => Some(
                sys7_table_images(s7, &desired)
                    .map_err(|e| format!("computing the System 7 table images: {e}"))?,
            ),
            None => None,
        };
        let noop = report.is_noop()
            && images
                .as_ref()
                .is_none_or(|images| images.flag_writes.is_empty());
        let digest = tables_digest(target, &bytes, &read, &desired, security.as_ref());
        Ok(Planned {
            model,
            source,
            read,
            backup,
            desired,
            report,
            security,
            images,
            tool_key,
            high_water,
            noop,
            digest,
        })
    }

    /// The plan reply; remembers the plan when it writes anything.
    fn tables_plan_json(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        gateway: &str,
        planned: &Planned,
    ) -> Value {
        let noop = planned.noop;
        if !noop {
            let mut plans = tier.table_restores();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.insert(
                planned.digest.clone(),
                PendingTables {
                    target,
                    file: file.to_path_buf(),
                    created: Instant::now(),
                },
            );
        }
        let tables = planned.read.live.tables();
        let report = &planned.report;
        let pairs = |list: &[bussard_download::ObjectGa]| -> Vec<Value> {
            list.iter()
                .map(|p| json!({"object": p.object, "ga": p.ga.to_string()}))
                .collect()
        };
        let mut notes = Vec::new();
        if let Some(parameters) = &planned.backup.parameters {
            notes.push(format!(
                "the backup also carries {} octet(s) of parameter memory at {:#X}; a restore \
                 writes the link tables only",
                parameters.length, parameters.base
            ));
        }
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let now = std::time::SystemTime::now();
        json!({
            "ok": true,
            "method": "restore",
            "address": target.to_string(),
            "gateway": gateway,
            "backup": file.display().to_string(),
            "backup_read_time": planned.backup.read_time,
            "backup_mask": planned.backup.mask,
            "mask": format!("{:04X}", tables.mask),
            "system_type": system_type(tables.mask),
            "secured": planned.tool_key.is_some(),
            "identity": planned.read.check.as_ref().map(|c| bussard_service::identity_line(target, c)),
            "noop": noop,
            "plan": render_plan_text(target, tables, report),
            "additions": pairs(&report.additions),
            "removals": pairs(&report.removals),
            "unchanged": report.unchanged.len(),
            "current_address_count": report.current_address_count,
            "resulting_address_count": report.resulting_address_count,
            "current_association_count": report.current_association_count,
            "resulting_association_count": report.resulting_association_count,
            "security_object": security_json(planned.security.as_ref(), &planned.desired, noop),
            "notes": notes,
            "question": (!noop).then(|| format!(
                "restore the link tables of {target} from {name} through {gateway}?"
            )),
            "plan_digest": (!noop).then(|| planned.digest.clone()),
            "expires_at": (!noop).then(|| bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl)),
            "next_step": if noop {
                format!("nothing to write: {target} already holds the backup's link tables")
            } else {
                "Show the plan above to the human (what is added and removed) and ask the \
                 question. Call knx_restore_tables with this plan_digest only after an explicit \
                 yes."
                    .to_string()
            },
        })
    }

    /// One table-restore job: the pre-flight (digest, fresh read, snapshot,
    /// pre-write backup), then `knx_apply_device`'s table write and
    /// read-back, holding the bus lock and the management slot.
    async fn tables_job(
        &self,
        job: &str,
        target: IndividualAddress,
        file: &Path,
        digest: &str,
        started: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            let _ = started.send(Err("the programming tier is off".into()));
            return;
        };
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let prepared = match self.tables_preflight(tier, target, file, digest).await {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.refuse(job, &reason);
                let _ = started.send(Err(reason));
                return;
            }
        };
        let record = prepared.snapshot.as_ref().map(|id| {
            History::open(&prepared.dir)
                .history_dir()
                .join(id)
                .join(crate::apply_jobs::RECORD_FILE)
        });
        tier.jobs.started(job, prepared.result.clone(), record);
        let _ = started.send(Ok(()));
        let result = self.apply_write(tier, job, prepared).await;
        drop(warm);
        tier.jobs.finish(job, result);
    }

    /// The pre-flight of a table restore. `Err` is a refusal; nothing was
    /// written.
    async fn tables_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        digest: &str,
    ) -> Result<Prepared, String> {
        let (_, service, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let pending = {
            let mut plans = tier.table_restores();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.get(digest).cloned()
        };
        let Some(pending) = pending else {
            return Err(format!(
                "no fresh table-restore plan with digest {digest:?} in this session (plans \
                 expire after {} minute(s) and are single use); call knx_restore_tables without \
                 plan_digest, show the plan to the human and ask again",
                tier.plan_ttl.as_secs().div_ceil(60)
            ));
        };
        if pending.target != target || pending.file != file {
            return Err(format!(
                "table-restore plan {digest} is for {} from {}, not {target} from {}",
                pending.target,
                pending.file.display(),
                file.display()
            ));
        }
        let planned = self.plan_tables(target, file).await;
        // One digest, one write: consumed whatever the fresh read says.
        tier.table_restores().remove(digest);
        let planned = planned?;
        if planned.digest != digest {
            return Err(format!(
                "refusing to restore {target}: the device's tables, the backup or the keyring \
                 changed since the plan was made. Plan again with knx_restore_tables and show \
                 the new plan to the human."
            ));
        }
        if planned.noop {
            return Err(format!(
                "nothing to write: {target} already holds the backup's link tables"
            ));
        }
        // The audit line, before the bus write.
        let history = History::open(&dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_restore_tables")
                .with_args([target.to_string(), file.display().to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result("before restoring the device tables");
            match history.snapshot(reason) {
                Ok(id) => Some(id.to_string()),
                Err(err) => {
                    return Err(format!(
                        "refusing to write {target}: the audit snapshot could not be recorded \
                         ({err})"
                    ));
                }
            }
        } else {
            None
        };
        // The state this restore overwrites is still the only copy of what
        // the device holds now: it is backed up first, as `apply` does.
        let tables = planned.read.live.tables();
        let backup = write_pre_write_backup(&dir, target, tables, planned.read.live.sys7())
            .map_err(|e| format!("refusing to write {target} without a backup: {e}"))?;
        let backup_path = backup.display().to_string();
        let built = tables_only_plan(target, &planned.model, &gateway, &dir, &planned);
        let result = json!({
            "method": "restore",
            "address": target.to_string(),
            "gateway": gateway,
            "secured": planned.tool_key.is_some(),
            "restored_from": file.display().to_string(),
            "backup": backup_path,
            "parameter_backup": Value::Null,
            "snapshot": snapshot,
        });
        Ok(Prepared {
            model: planned.model,
            product: None,
            target,
            gateway,
            dir,
            handle: service.handle().clone(),
            source: planned.source,
            tool_key: planned.tool_key,
            high_water: planned.high_water,
            desired: planned.desired,
            report: planned.report,
            built,
            read: planned.read,
            security: planned.security,
            images: planned.images,
            snapshot,
            backup_path,
            param_backup_path: None,
            flash: None,
            result,
            origin: Origin::Backup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_file_refuses_a_path_outside_the_backup_root() -> Result<(), String> {
        let dir =
            std::env::temp_dir().join(format!("bussard-restore-tables-{}", std::process::id()));
        let root = backups_root(&dir);
        let run = root.join("2026-10-31T120000Z");
        std::fs::create_dir_all(&run).map_err(|e| e.to_string())?;
        std::fs::write(run.join("1.1.4-100.json"), "{}").map_err(|e| e.to_string())?;
        std::fs::write(root.join("1.1.4-50.json"), "{}").map_err(|e| e.to_string())?;
        std::fs::write(dir.join("other.json"), "{}").map_err(|e| e.to_string())?;
        let target: IndividualAddress = "1.1.4".parse().map_err(|_| "address")?;
        let in_run = backup_file(&dir, Some("2026-10-31T120000Z"), target);
        let in_root = backup_file(&dir, None, target);
        let outside = backup_file(&dir, Some("../../other.json"), target);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(in_run.is_ok_and(|p| p.ends_with("1.1.4-100.json")));
        assert!(in_root.is_ok_and(|p| p.ends_with("1.1.4-50.json")));
        assert!(outside.is_err());
        Ok(())
    }
}
