//! `knx_restore_parameters` (issue #290): replay a parameter backup from
//! `<dir>/captures/backups/parameters/` onto one device, with the plan,
//! digest and explicit-yes flow of the programming tier and the job model of
//! `knx_apply_device` (issue #289).
//!
//! The plan and the write are `bussard restore --parameters`'s
//! ([`bussard_service::restore`], [`bussard_service::download::write_parameters`]):
//! a backup of another device, application or mask is refused, only the
//! octets a parameter is placed in under the model's configuration are
//! written, device-managed octets keep the device's value, and the write is
//! verified by read-back. The backup must be a file in the model's parameter
//! backup directory.

use std::path::{Path, PathBuf};

use crate::jobs::{JobSink, PARAMETER_DOWNLOAD};
use bussard_model::history::SnapshotReason;
use bussard_model::{IndividualAddress, Model};
use bussard_service::L4Options;
use bussard_service::download::backup::{
    ParameterBackup, parameter_backups_dir, read_parameter_backup,
};
use bussard_service::program::outcome::{ParametersWritten, WriteOutcome};
use bussard_service::program::plan::Fingerprint;
use bussard_service::program::{self, read::FlagsCache};
use bussard_service::restore::ParameterRestorePlan;
use bussard_service::restore::{RestorePlan, build_restore_plan};
use bussard_service::secure::SequenceHighWater;
use serde_json::Value;

use super::{
    BussardMcp, DeviceRead, ProgrammingTier, Read, Subject, chain, product_for, read_device,
    refuse_drift,
};

/// What a restore read and planned.
struct Planned {
    /// The checked source address.
    source: IndividualAddress,
    /// The read the plan came from.
    read: DeviceRead,
    /// The restore plan.
    plan: RestorePlan,
    /// The plan digest.
    digest: String,
    /// The Data Secure tool key, `None` on the plain path.
    tool_key: Option<bussard_service::secure::Key16>,
    /// The send-sequence high-water mark of the read and the write.
    high_water: SequenceHighWater,
}

/// Resolves `backup` (a file name, or a path) to a file in the parameter
/// backup directory of the model at `dir`.
fn backup_file(dir: &Path, backup: &str) -> Result<PathBuf, String> {
    let root = parameter_backups_dir(dir);
    let given = Path::new(backup.trim());
    let candidate = if given.is_absolute() {
        given.to_path_buf()
    } else if given.components().count() == 1 {
        root.join(given)
    } else {
        dir.join(given)
    };
    let (Ok(file), Ok(root_abs)) = (
        std::fs::canonicalize(&candidate),
        std::fs::canonicalize(&root),
    ) else {
        return Err(format!(
            "no parameter backup {backup:?} in {}; pass the file name of a backup there (apply \
             writes one before every parameter write)",
            root.display()
        ));
    };
    if !file.starts_with(&root_abs) || !file.is_file() {
        return Err(format!(
            "{backup:?} is not a file in {}; knx_restore_parameters replays only the parameter \
             backups bussard keeps there",
            root.display()
        ));
    }
    Ok(file)
}

/// The plan digest of a restore: the device, the backup's bytes, the model's
/// parameter values for the device, the live read and the octets the
/// download would write.
fn restore_digest(
    target: IndividualAddress,
    backup_bytes: &[u8],
    model: &Model,
    read: &DeviceRead,
    plan: &RestorePlan,
) -> String {
    let parameters = model.devices.get(&target).map(|d| &d.device.parameters);
    let h = Fingerprint::new(b"bussard-restore-v1")
        .address(target)
        .put(backup_bytes)
        .put(format!("{parameters:?}"))
        .put(program::plan::live_fingerprint(read));
    let Some(partial) = &plan.partial else {
        return h.put(b"nothing").hex();
    };
    let mut h = h;
    for (segment, octets) in partial.changed_bits() {
        h = h.put(segment.as_bytes());
        for (i, _) in octets {
            h = h.put((i as u64).to_be_bytes());
        }
        h = h.put(partial.image_bytes(&segment).unwrap_or_default());
    }
    h.hex()
}

impl BussardMcp {
    /// `knx_restore_parameters`'s body; `Err` is a refusal reason.
    pub(super) async fn restore_parameters(
        &self,
        address: &str,
        backup: &str,
        digest: Option<&str>,
    ) -> Result<Value, String> {
        let target = super::parse_address(address)?;
        let (tier, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let file = backup_file(&dir, backup)?;
        let Some(digest) = digest else {
            if let Some(refusal) = tier.jobs.busy(crate::jobs::JobKind::Plan) {
                return Err(refusal);
            }
            let planned = self.on_bus(tier, self.plan_restore(target, &file)).await?;
            let plan = self.restore_plan_json(tier, target, &file, &gateway, &planned);
            return Ok(crate::reply::report(&plan, &self.state().model.current()));
        };
        let digest = digest.to_string();
        self.run_write(
            Subject::Device(target),
            "restore",
            move |me, job, gate| async move {
                let tier = me.tier()?;
                me.on_bus(tier, async {
                    let (planned, result, record) =
                        me.restore_preflight(tier, target, &file, &digest).await?;
                    gate.pass(&result, record);
                    Ok(me.restore_write(tier, &job, target, &planned, result).await)
                })
                .await
            },
        )
        .await
    }

    /// Reads `target` and plans replaying the backup at `file` onto it.
    async fn plan_restore(
        &self,
        target: IndividualAddress,
        file: &Path,
    ) -> Result<Planned, String> {
        let (_, service, _) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let backup: ParameterBackup = read_parameter_backup(file).map_err(|e| chain(&e))?;
        let model = self.state().model.reload();
        let product = product_for(&dir, &model, target);
        let Some(source) = product.source.as_ref() else {
            return Err(product.refusal.unwrap_or_else(|| {
                format!("no product data for {target}; the restore decodes with it")
            }));
        };
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let high_water = SequenceHighWater::new();
        let (checked, read) = read_device(
            &service,
            target,
            &dir,
            Read {
                tool_key: &tool_key,
                factory_key: &material.fdsk,
                high_water: &high_water,
                model: &model,
                product: Some(source),
                tunnel: &[],
                flags_cache: FlagsCache::Off,
            },
        )
        .await?;
        refuse_drift(target, &read)?;
        let state = read
            .params
            .as_ref()
            .ok_or("the parameter memory was not read")?;
        let Some(detail) = state.detail.as_ref() else {
            return Err(format!(
                "the parameter memory of {target} cannot be restored: {}",
                state
                    .readback
                    .note
                    .as_deref()
                    .unwrap_or("it could not be read")
            ));
        };
        let app = source
            .app()
            .ok_or("the application is not in the product data")?;
        let plan = build_restore_plan(app, Some(&model), target, detail, &backup)
            .map_err(|e| e.to_string())?;
        let digest = restore_digest(target, &bytes, &model, &read, &plan);
        Ok(Planned {
            source: checked,
            read,
            plan,
            digest,
            tool_key,
            high_water,
        })
    }

    /// The plan reply; remembers the plan when it writes anything.
    fn restore_plan_json(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        gateway: &str,
        planned: &Planned,
    ) -> ParameterRestorePlan {
        let mut out = ParameterRestorePlan::new(
            target,
            gateway,
            file,
            planned.read.check().cloned(),
            &planned.plan,
        );
        if !out.noop {
            let subject = format!("{target} from {}", file.display());
            tier.restore_plans
                .insert(planned.digest.clone(), subject, ());
            out.approval.plan_digest = Some(planned.digest.clone());
            out.approval.expires_at =
                Some(tier.restore_plans.expires_at(std::time::SystemTime::now()));
        }
        out
    }

    /// The pre-flight of a restore. `Err` is a refusal; nothing was written.
    async fn restore_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        digest: &str,
    ) -> Result<(Planned, WriteOutcome, Option<PathBuf>), String> {
        let (_, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let subject = format!("{target} from {}", file.display());
        let again = "call knx_restore_parameters without plan_digest, show the plan to the human \
                     and ask again";
        // One digest, one write: consumed whatever the fresh read says.
        tier.restore_plans
            .take(digest, subject, "restore plan", again)?;
        let planned = self.plan_restore(target, file).await;
        let planned = planned?;
        if planned.digest != digest {
            return Err(format!(
                "refusing to restore {target}: the device's memory, the backup or your project \
                 changed since the plan was made. Plan again with knx_restore_parameters and \
                 show the new plan to the human."
            ));
        }
        let Some(detail) = planned.read.params.as_ref().and_then(|p| p.detail.as_ref()) else {
            return Err("the parameter memory was not read".into());
        };
        let reason = SnapshotReason::new("mcp knx_restore_parameters")
            .with_args([target.to_string(), file.display().to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before restoring the parameter memory");
        let snapshot = super::audit_snapshot(&dir, reason, target)?;
        let backup = bussard_service::download::write_parameter_memory_backup(
            &dir,
            target,
            &detail.plan,
            &detail.regions,
        )
        .map_err(|e| format!("refusing to write {target} without a parameter backup: {e}"))?;
        let record = crate::jobs::record_file(&dir, snapshot.as_deref());
        let result = WriteOutcome {
            gateway: Some(gateway),
            secured: Some(planned.tool_key.is_some()),
            restored_from: Some(file.display().to_string()),
            parameter_backup: Some(backup.display().to_string()),
            snapshot,
            ..WriteOutcome::new(target)
        };
        Ok((planned, result, record))
    }

    /// The write of a restore whose pre-flight passed, onto the
    /// pre-flight's `result`. Never refuses: a failure is the result.
    async fn restore_write(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        target: IndividualAddress,
        planned: &Planned,
        mut result: WriteOutcome,
    ) -> WriteOutcome {
        let (Some(partial), Some(detail)) = (
            planned.plan.partial.as_ref(),
            planned.read.params.as_ref().and_then(|p| p.detail.as_ref()),
        ) else {
            result.verify();
            result.parameters = Some(ParametersWritten::default());
            return result;
        };
        let Some(service) = self.state().bus.service() else {
            result.fail("the bus is not wired");
            return result;
        };
        tier.jobs.step(
            job,
            format!("restoring {} parameter octet(s)", planned.plan.octets),
        );
        let read_options = L4Options::secured(
            planned.source,
            planned.tool_key.clone(),
            planned.high_water.clone(),
        );
        let mut observer = JobSink::new(&tier.jobs, job).download(PARAMETER_DOWNLOAD, target);
        let outcome = bussard_service::download::write_parameters(
            bussard_service::download::ParamWrite {
                service,
                target,
                source: planned.source,
                partial,
                detail,
                tool_key: planned.tool_key.clone(),
                high_water: planned.high_water.clone(),
                read_options: &read_options,
            },
            &mut observer,
        )
        .await;
        let (ok, parameters) = match &outcome {
            Ok(bussard_service::download::ParamWriteOutcome::Verified { octets }) => (
                true,
                ParametersWritten {
                    written: true,
                    verified: Some(true),
                    octets: Some(*octets),
                    ..ParametersWritten::default()
                },
            ),
            Ok(failed) => (false, ParametersWritten::failed(failed.failure())),
            Err(err) => (
                false,
                ParametersWritten::failed(format!(
                    "the parameter read-back failed: {}",
                    chain(&err)
                )),
            ),
        };
        tracing::info!(
            "audit: knx_restore_parameters {target}: {}",
            if ok { "verified" } else { "FAILED" }
        );
        result.verdict.ok = ok;
        result.verdict.verified = ok;
        result.parameters = Some(parameters);
        if !ok {
            result.verdict.recovery = Some(
                "The parameter memory before the restore is backed up (see parameter_backup). If \
                 the application still reads Loaded, planning the restore again rewrites only the \
                 octets that still differ; otherwise recover with a full `bussard flash --force` \
                 at the CLI."
                    .to_string(),
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_file_refuses_a_file_outside_the_backup_dir() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("bussard-restore-file-{}", std::process::id()));
        let root = parameter_backups_dir(&dir);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        std::fs::write(root.join("1.1.4-1.json"), "{}").map_err(|e| e.to_string())?;
        std::fs::write(dir.join("other.json"), "{}").map_err(|e| e.to_string())?;
        let inside = backup_file(&dir, "1.1.4-1.json");
        let outside = backup_file(&dir, "other.json");
        let escape = backup_file(&dir, "captures/backups/parameters/../../../other.json");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(inside.is_ok(), "{inside:?}");
        assert!(outside.is_err(), "{outside:?}");
        assert!(escape.is_err(), "{escape:?}");
        Ok(())
    }
}
