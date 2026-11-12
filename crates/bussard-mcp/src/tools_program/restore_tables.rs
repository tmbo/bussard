//! `knx_restore_tables` (issue #717): write a device's backed-up link tables
//! back onto it, as `bussard restore <BACKUP_DIR> <ADDRESS>` does.
//!
//! The CLI's restore is `apply` with the desired tables taken from a backup
//! file instead of the device file's links
//! (`bussard_download::backup::DeviceBackup::desired_tables`). This tool is
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

use bussard_model::history::SnapshotReason;
use bussard_model::{IndividualAddress, Model};
use bussard_service::download::backup::{
    DeviceBackup, backups_root, find_device_backup, read_device_backup,
};
use bussard_service::download::{
    DesiredTables, DevicePlan, PlanReport, PlanWrites, SecurityInputs, Sys7TableImages,
    render_plan_text, state_hash,
};
use bussard_service::mgmt::{MaskProfile, system_type};
use bussard_service::params::BuiltPlan;
use bussard_service::program::outcome::{SecurityObject, WriteOutcome};
use bussard_service::program::plan::Fingerprint;
use bussard_service::program::{self, read::FlagsCache};
use bussard_service::report::Approval;
use bussard_service::restore::TableRestorePlan;
use bussard_service::secure::{Key16, SequenceHighWater};
use serde_json::Value;

use super::{
    BussardMcp, DeviceRead, Origin, Prepared, ProgrammingTier, Read, Subject, chain, read_device,
    refuse_protected, security_for,
};

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
    let security = security.map(|inputs| inputs.describe(&desired.addresses));
    Fingerprint::new(b"bussard-restore-tables-v1")
        .address(target)
        .put(backup_bytes)
        .put(program::plan::live_fingerprint(read))
        .desired(desired)
        .put(security.as_deref().unwrap_or("plain"))
        .hex()
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
        allow_unsupported: bool,
    ) -> Result<Value, String> {
        let target = super::parse_address(address)?;
        let (tier, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let file = backup_file(&dir, backup, target)?;
        let Some(digest) = digest else {
            if let Some(refusal) = tier.jobs.busy(crate::jobs::JobKind::Plan) {
                return Err(refusal);
            }
            let planned = self.on_bus(tier, self.plan_tables(target, &file)).await?;
            let plan = self.tables_plan_json(tier, target, &file, &gateway, &planned);
            return Ok(crate::reply::report(&plan, &self.state().model.current()));
        };
        // The supported-device gate (issue #1089) answered before this call
        // (`knx_restore_tables`, through `unsupported_override`); the
        // pre-flight asks it again.
        let digest = digest.to_string();
        self.run_write(
            Subject::Device(target),
            "restore",
            move |me, job, gate| async move {
                let tier = me.tier()?;
                me.on_bus(tier, async {
                    let prepared = me
                        .tables_preflight(tier, target, &file, &digest, allow_unsupported)
                        .await?;
                    let record =
                        crate::jobs::record_file(&prepared.dir, prepared.snapshot.as_deref());
                    gate.pass(&prepared.result, record);
                    Ok(me.apply_write(tier, &job, prepared).await)
                })
                .await
            },
        )
        .await
    }

    /// The supported-device gate of a table restore before its job (issue
    /// #1089): the refusal, `None` to go on (an unknown digest is left to the
    /// pre-flight's refusal).
    pub(super) fn tables_unsupported(
        &self,
        target: IndividualAddress,
        digest: &str,
        allow_unsupported: bool,
    ) -> Option<super::support::Refused> {
        let tier = self.tier().ok()?;
        let unsupported = tier.table_restores.get(digest)?;
        super::support::gate(
            &tier.connection,
            &self.state().model.current(),
            target,
            None,
            (allow_unsupported, unsupported),
        )
        .err()
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
            &dir,
            Read {
                tool_key: &tool_key,
                factory_key: &material.fdsk,
                high_water: &high_water,
                model: &model,
                product: None,
                tunnel: &[],
                flags_cache: FlagsCache::Off,
            },
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
        let report = program::plan::table_plan(&read, &desired);
        refuse_protected(&model, &report)?;
        let security = security_for(
            &model, target, &desired, &material, &read.live, &tunnel, &dir,
        )?;
        let images = program::plan::sys7_images(&read, &desired)
            .map_err(|e| format!("computing the System 7 table images: {e}"))?;
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
    ) -> TableRestorePlan {
        let noop = planned.noop;
        let tables = planned.read.live.tables();
        let report = &planned.report;
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
        let mut approval = Approval::question((!noop).then(|| {
            format!("restore the link tables of {target} from {name} through {gateway}?")
        }));
        let model = self.state().model.current();
        // A table restore writes no application image: the device's own
        // application is judged (issue #1089).
        let support = bussard_service::support::verdict_at(Some(&model), target, None);
        if !noop {
            let subject = format!("{target} from {}", file.display());
            tier.table_restores
                .insert(planned.digest.clone(), subject, !support.is_supported());
            approval.plan_digest = Some(planned.digest.clone());
            approval.expires_at =
                Some(tier.table_restores.expires_at(std::time::SystemTime::now()));
        }
        TableRestorePlan {
            ok: true,
            method: "restore".to_string(),
            address: target.to_string(),
            gateway: gateway.to_string(),
            backup: file.display().to_string(),
            backup_read_time: planned.backup.read_time.clone(),
            backup_mask: planned.backup.mask.clone(),
            mask: format!("{:04X}", tables.mask),
            system_type: system_type(tables.mask).to_string(),
            secured: planned.tool_key.is_some(),
            identity: planned.read.check().cloned(),
            noop,
            table_plan: render_plan_text(target, tables, report),
            additions: report.additions.clone(),
            removals: report.removals.clone(),
            unchanged: report.unchanged.clone(),
            current_address_count: report.current_address_count,
            resulting_address_count: report.resulting_address_count,
            current_association_count: report.current_association_count,
            resulting_association_count: report.resulting_association_count,
            security_object: SecurityObject::of(planned.security.as_ref(), &planned.desired, noop),
            notes,
            support: Some(support.view_on(&tier.connection)),
            approval,
        }
    }

    /// The pre-flight of a table restore. `Err` is a refusal; nothing was
    /// written.
    async fn tables_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        digest: &str,
        allow_unsupported: bool,
    ) -> Result<Prepared, String> {
        let (_, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let subject = format!("{target} from {}", file.display());
        let again = "call knx_restore_tables without plan_digest, show the plan to the human and \
                     ask again";
        // One digest, one write: consumed whatever the fresh read says, except
        // by the supported-device refusal, which keeps it for the override
        // as `knx_apply_device` does (issue #1093).
        let unsupported =
            tier.table_restores
                .fresh(digest, subject, "table-restore plan", again)?;
        // The supported-device gate (issue #1089), before the bus.
        let grant = super::support::gate(
            &tier.connection,
            &self.state().model.current(),
            target,
            None,
            (allow_unsupported, unsupported),
        )
        .map_err(|refused| refused.reason())?;
        tier.table_restores.retire(digest);
        let planned = self.plan_tables(target, file).await;
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
        let reason = SnapshotReason::new("mcp knx_restore_tables")
            .with_args([target.to_string(), file.display().to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before restoring the device tables");
        let snapshot = super::audit_snapshot(&dir, reason, target)?;
        // The state this restore overwrites is still the only copy of what
        // the device holds now: it is backed up first, as `apply` does.
        let backup_path = program::apply::back_up(&dir, target, &planned.read.live, None)
            .map_err(|e| format!("refusing to write {target} without a backup: {e}"))?
            .tables
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let built = tables_only_plan(target, &planned.model, &gateway, &dir, &planned);
        let result = WriteOutcome {
            method: Some("restore".to_string()),
            gateway: Some(gateway.clone()),
            secured: Some(planned.tool_key.is_some()),
            restored_from: Some(file.display().to_string()),
            backup: Some(backup_path.clone()),
            snapshot: snapshot.clone(),
            support: Some(grant.status()),
            ..WriteOutcome::new(target)
        };
        Ok(Prepared {
            model: planned.model,
            product: None,
            target,
            gateway,
            dir,
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
            support: grant,
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
