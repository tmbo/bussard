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
use std::time::Instant;

use bussard_download::backup::{ParameterBackup, parameter_backups_dir, read_parameter_backup};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::SequenceHighWater;
use bussard_service::restore::{RestorePlan, build_restore_plan};
use bussard_service::{Authorize, L4Options, SourcePolicy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    BussardMcp, DeviceRead, JobObserver, ProgrammingTier, chain, live_digest, product_for, put,
    read_device, refuse_drift,
};

/// One restore plan this session produced, remembered until written, refused
/// or expired.
#[derive(Debug, Clone)]
pub(super) struct PendingRestore {
    /// The device.
    target: IndividualAddress,
    /// The backup file.
    backup: PathBuf,
    /// When the plan was produced.
    created: Instant,
}

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
    tool_key: Option<bussard_secure::Key16>,
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
    let mut h = Sha256::new();
    put(&mut h, b"bussard-restore-v1");
    put(&mut h, &target.raw().to_be_bytes());
    put(&mut h, backup_bytes);
    put(
        &mut h,
        format!(
            "{:?}",
            model.devices.get(&target).map(|d| &d.device.parameters)
        )
        .as_bytes(),
    );
    put(&mut h, &live_digest(read));
    match &plan.partial {
        Some(partial) => {
            for (segment, octets) in partial.changed_bits() {
                put(&mut h, segment.as_bytes());
                for (i, _) in octets {
                    put(&mut h, &(i as u64).to_be_bytes());
                }
                put(&mut h, partial.image_bytes(&segment).unwrap_or_default());
            }
        }
        None => put(&mut h, b"nothing"),
    }
    let bytes: [u8; 32] = h.finalize().into();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
            if let Some((job, device)) = tier.jobs.running() {
                return Err(format!(
                    "an apply is running on this server (job {job} for {device}); call \
                     knx_apply_status with job {job} until it is done, then plan again"
                ));
            }
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            let planned = self.plan_restore(target, &file).await;
            drop(warm);
            let planned = planned?;
            return Ok(self.restore_plan_json(tier, target, &file, &gateway, &planned));
        };
        let digest = digest.to_string();
        self.run_job(target, "restore", move |me, job, started| async move {
            me.restore_job(&job, target, &file, &digest, started).await;
        })
        .await
    }

    /// Reads `target` and plans replaying the backup at `file` onto it.
    async fn plan_restore(
        &self,
        target: IndividualAddress,
        file: &Path,
    ) -> Result<Planned, String> {
        let (_, handle, _) = self.programming_preflight()?;
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
            &handle,
            target,
            &tool_key,
            &high_water,
            &dir,
            &model,
            Some(source),
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
    ) -> Value {
        let plan = &planned.plan;
        let noop = plan.partial.is_none();
        if !noop {
            let mut plans = tier.restore_plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.insert(
                planned.digest.clone(),
                PendingRestore {
                    target,
                    backup: file.to_path_buf(),
                    created: Instant::now(),
                },
            );
        }
        let now = std::time::SystemTime::now();
        json!({
            "ok": true,
            "address": target.to_string(),
            "gateway": gateway,
            "backup": file.display().to_string(),
            "identity": planned.read.check.as_ref().map(|c| bussard_service::identity_line(target, c)),
            "noop": noop,
            "sentences": plan.render_text(target),
            "octets": plan.octets,
            "octet_ranges": plan.octet_ranges,
            "notes": plan.notes,
            "question": (!noop).then(|| plan.question(target, gateway)),
            "plan_digest": (!noop).then(|| planned.digest.clone()),
            "expires_at": (!noop).then(|| bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl)),
            "next_step": if noop {
                format!("nothing to write: {target} already holds the backup's parameter octets")
            } else {
                "Show the sentences above to the human in full (what is written, what is \
                 left as the device holds it) and ask the question. Call \
                 knx_restore_parameters with this plan_digest only after an explicit yes."
                    .to_string()
            },
        })
    }

    /// One restore job: the pre-flight (digest, fresh read, gates, snapshot,
    /// backup), then the write, holding the bus lock and the warm slot.
    async fn restore_job(
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
        let prepared = self.restore_preflight(tier, target, file, digest).await;
        let (planned, mut result, record) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.abandon(job);
                let _ = started.send(Err(reason));
                return;
            }
        };
        tier.jobs.started(job, result.clone(), record);
        let _ = started.send(Ok(()));
        let outcome = self.restore_write(tier, job, target, &planned).await;
        drop(warm);
        merge_into(&mut result, outcome);
        tier.jobs.finish(job, result);
    }

    /// The pre-flight of a restore. `Err` is a refusal; nothing was written.
    async fn restore_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        file: &Path,
        digest: &str,
    ) -> Result<(Planned, Value, Option<PathBuf>), String> {
        let (_, _, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let pending = {
            let mut plans = tier.restore_plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.get(digest).cloned()
        };
        let Some(pending) = pending else {
            return Err(format!(
                "no fresh restore plan with digest {digest:?} in this session (plans expire after \
                 {} minute(s) and are single use); call knx_restore_parameters without \
                 plan_digest, show the plan to the human and ask again",
                tier.plan_ttl.as_secs().div_ceil(60)
            ));
        };
        if pending.target != target || pending.backup != file {
            return Err(format!(
                "restore plan {digest} is for {} from {}, not {target} from {}",
                pending.target,
                pending.backup.display(),
                file.display()
            ));
        }
        let planned = self.plan_restore(target, file).await;
        // One digest, one write: consumed whatever the fresh read says.
        tier.restore_plans().remove(digest);
        let planned = planned?;
        if planned.digest != digest {
            return Err(format!(
                "refusing to restore {target}: the device's memory, the backup or the model \
                 changed since the plan was made. Plan again with knx_restore_parameters and \
                 show the new plan to the human."
            ));
        }
        let Some(detail) = planned.read.params.as_ref().and_then(|p| p.detail.as_ref()) else {
            return Err("the parameter memory was not read".into());
        };
        let history = History::open(&dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_restore_parameters")
                .with_args([target.to_string(), file.display().to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result("before restoring the parameter memory");
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
        let backup = bussard_download::write_parameter_memory_backup(
            &dir,
            target,
            &detail.plan,
            &detail.regions,
        )
        .map_err(|e| format!("refusing to write {target} without a parameter backup: {e}"))?;
        let record = snapshot.as_ref().map(|id| {
            History::open(&dir)
                .history_dir()
                .join(id)
                .join(crate::apply_jobs::RECORD_FILE)
        });
        let result = json!({
            "address": target.to_string(),
            "gateway": gateway,
            "secured": planned.tool_key.is_some(),
            "restored_from": file.display().to_string(),
            "parameter_backup": backup.display().to_string(),
            "snapshot": snapshot,
        });
        Ok((planned, result, record))
    }

    /// The write of a restore whose pre-flight passed. Never refuses: a
    /// failure is the result.
    async fn restore_write(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        target: IndividualAddress,
        planned: &Planned,
    ) -> Value {
        let (Some(partial), Some(detail)) = (
            planned.plan.partial.as_ref(),
            planned.read.params.as_ref().and_then(|p| p.detail.as_ref()),
        ) else {
            return json!({"ok": true, "verified": true, "parameters": {"written": false}});
        };
        let Some(service) = self.state().bus.service() else {
            return json!({"ok": false, "verified": false, "reason": "the bus is not wired"});
        };
        tier.jobs.step(
            job,
            format!("restoring {} parameter octet(s)", planned.plan.octets),
        );
        let read_options = L4Options {
            source: SourcePolicy::Known(planned.source),
            tool_key: planned.tool_key.clone(),
            high_water: planned.high_water.clone(),
            authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
            ..L4Options::default()
        };
        let mut observer = JobObserver {
            jobs: &tier.jobs,
            job,
        };
        let outcome = bussard_service::download::write_parameters(
            service,
            target,
            planned.source,
            partial,
            detail,
            planned.tool_key.clone(),
            planned.high_water.clone(),
            &read_options,
            &mut observer,
        )
        .await;
        let (ok, parameters) = match outcome {
            Ok(bussard_service::download::ParamWriteOutcome::Verified { octets }) => (
                true,
                json!({"written": true, "verified": true, "octets": octets}),
            ),
            Ok(failed) => (
                false,
                json!({"written": false, "verified": false, "reason": failed.failure()}),
            ),
            Err(err) => (
                false,
                json!({
                    "written": false,
                    "verified": false,
                    "reason": format!("the parameter read-back failed: {}", chain(&err)),
                }),
            ),
        };
        tracing::info!(
            "audit: knx_restore_parameters {target}: {}",
            if ok { "verified" } else { "FAILED" }
        );
        let mut result = json!({"ok": ok, "verified": ok, "parameters": parameters});
        if !ok {
            result["recovery"] = json!(
                "The parameter memory before the restore is backed up (see parameter_backup). If \
                 the application still reads Loaded, planning the restore again rewrites only the \
                 octets that still differ; otherwise recover with a full `bussard flash --force` \
                 at the CLI."
            );
        }
        result
    }
}

/// Copies every field of `extra` into `into` (both objects).
fn merge_into(into: &mut Value, extra: Value) {
    if let (Some(into), Value::Object(extra)) = (into.as_object_mut(), extra) {
        into.extend(extra);
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
