//! The line form of `knx_plan_device` and `knx_apply_device` (issue #748):
//! `line: "1.1"` plans or writes every device the model has on the line, as
//! `bussard plan --line` and `bussard apply --line` do.
//!
//! Each device is visited by [`bussard_service::line::visit_device`], the
//! function the CLI's line runner calls: the same read, the same refusals
//! (an unlinked device or an unsupported mask is skipped, a device that
//! fails is reported and the run goes on), the same per-device backup, the
//! same write and the same independent read-back. Like the CLI, the line
//! form writes the link tables (and the group-object table and System 7
//! communication flags they need), not the parameters: a parameter change is
//! planned and written per device.
//!
//! One plan, one digest, one job. The plan reads every device and returns a
//! `plan_digest` over the line: the model's devices and links on it, the
//! protected group addresses, and each device's fingerprint (its tables as
//! read and the write the model asks for). The write presents that digest,
//! is refused when the model moved since, and runs as one job. Each device
//! is read again right before its write, and a device whose fresh read no
//! longer produces its planned fingerprint is failed without a write. The
//! result lists per device what was written and whether its read-back
//! verified; `ok` is true only when no device failed.

use std::collections::BTreeMap;
use std::time::{Instant, SystemTime};

use bussard_mgmt::system_type;
use bussard_model::history::{History, SnapshotReason};
use bussard_model::text::hex;
use bussard_model::{IndividualAddress, Model};
use bussard_service::line::{
    DeviceStatus, LineMode, LineOutcome, LineTarget, LineVisit, parse_line, targets_digest,
    targets_on_line, visit_device,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{BussardMcp, ProgrammingTier, merge, put, refuse_insecure_links, refuse_protected};

/// One line plan this session produced, remembered until applied, refused
/// or expired.
#[derive(Debug, Clone)]
pub(super) struct PendingLinePlan {
    /// The line, `area.line`.
    line: (u8, u8),
    /// When the plan was produced.
    created: Instant,
    /// The model side of the line ([`model_digest`]).
    model: String,
    /// Each device's fingerprint as the plan read it.
    devices: BTreeMap<IndividualAddress, String>,
}

/// The line as a job's address: the line coupler's `area.line.0`.
fn line_address((area, line_no): (u8, u8)) -> Result<IndividualAddress, String> {
    IndividualAddress::new(area, line_no, 0).map_err(|e| e.to_string())
}

/// The model side of a line plan: the devices and their desired tables
/// ([`targets_digest`]) and the protected group addresses, which the plan's
/// refusal depends on.
fn model_digest(model: &Model, targets: &[LineTarget]) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-line-model-v1");
    put(&mut h, targets_digest(targets).as_bytes());
    for (ga, group) in &model.groups.groups {
        if group.protected {
            put(&mut h, &ga.raw().to_be_bytes());
        }
    }
    hex(&h.finalize())
}

/// The digest the human's yes binds: the line, its model side and every
/// device's outcome and fingerprint.
fn line_digest(line: (u8, u8), model: &str, outcomes: &[LineOutcome]) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-line-plan-v1");
    put(&mut h, &[line.0, line.1]);
    put(&mut h, model.as_bytes());
    for o in outcomes {
        put(&mut h, &o.address.raw().to_be_bytes());
        put(&mut h, o.status.key().as_bytes());
        put(&mut h, o.fingerprint.as_deref().unwrap_or("-").as_bytes());
    }
    hex(&h.finalize())
}

/// A group address in the model's words: `1/2/2 (Blind position)`.
fn ga_words(model: &Model, ga: bussard_model::GroupAddress) -> String {
    match model.groups.groups.get(&ga) {
        Some(group) => format!("{ga} ({})", group.name),
        None => ga.to_string(),
    }
}

/// The sentences of one device's link plan, names first.
fn sentences(model: &Model, o: &LineOutcome) -> Vec<String> {
    let Some(report) = &o.report else {
        return Vec::new();
    };
    let add = report.additions.iter().map(|p| {
        format!(
            "+ {} object {} now on {}",
            o.name,
            p.object,
            ga_words(model, p.ga)
        )
    });
    let remove = report.removals.iter().map(|p| {
        format!(
            "- {} object {} no longer on {}",
            o.name,
            p.object,
            ga_words(model, p.ga)
        )
    });
    add.chain(remove).collect()
}

/// One device's row of a line result.
fn device_json(model: &Model, o: &LineOutcome, notes: &[String]) -> Value {
    json!({
        "address": o.address.to_string(),
        "name": o.name,
        "mask": o.mask.map(|m| format!("{m:04X}")),
        "system_type": o.mask.map(|m| system_type(m).to_string()),
        "status": o.status.key(),
        "changes": o.status.changes(),
        "detail": o.status.detail(),
        "verified": matches!(o.status, DeviceStatus::Applied(_)),
        "sentences": sentences(model, o),
        "notes": notes,
        "backup": o.backup.as_ref().map(|p| p.display().to_string()),
    })
}

/// The counts of a line result.
fn totals(outcomes: &[LineOutcome]) -> Value {
    let count = |key: &str| outcomes.iter().filter(|o| o.status.key() == key).count();
    json!({
        "total": outcomes.len(),
        "changed": count("changes") + count("applied"),
        "unchanged": count("unchanged"),
        "skipped": count("skipped"),
        "failed": count("failed"),
    })
}

impl BussardMcp {
    /// `knx_plan_device` with `line`; `Err` is a refusal reason.
    ///
    /// Runs as a plan job, as the device form does (issue #332): answers
    /// with the plan when every device is read within the read wait, else
    /// with `started: true` and the job id.
    pub(super) async fn plan_line(&self, line: &str) -> Result<Value, String> {
        let began = Instant::now();
        let parsed = parse_line(line).map_err(|e| e.to_string())?;
        let at = line_address(parsed)?;
        self.line_targets(parsed)?;
        let (tier, _, _) = self.programming_preflight()?;
        let (job, fresh) = match tier.jobs.claim_plan(at)? {
            crate::jobs::PlanClaim::New(job) => (job, true),
            crate::jobs::PlanClaim::Running(job) => (job, false),
        };
        let line_text = format!("{}.{}", parsed.0, parsed.1);
        if fresh {
            let me = self.clone();
            let id = job.clone();
            let worker = tokio::spawn(async move {
                let plan = match me.plan_line_body(&id, parsed).await {
                    Ok(plan) => plan,
                    Err(reason) => line_refusal(&format!("{}.{}", parsed.0, parsed.1), reason),
                };
                if let Some(tier) = me.state().programming.as_ref() {
                    tier.jobs.finish(&id, plan);
                }
            });
            self.watch_job(job.clone(), "plan", worker);
        }
        let wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        if tier.jobs.wait(&job, wait).await {
            return Ok(tier.jobs.result(&job).unwrap_or_else(|| json!({})));
        }
        Ok(json!({
            "started": true,
            "done": false,
            "kind": "plan",
            "job": job,
            "line": line_text,
            "step": "reading the devices on the line",
            "next_step": format!(
                "Reading every device on line {line_text} takes longer than this call may wait; \
                 the plan is computed in the server as job {job}, and nothing is written. Tell \
                 the human the read is running, then call knx_job_status with job {job} every \
                 few seconds until `done` is true. Its `result` is the line plan: show it to \
                 the human and follow result.next_step. Do not call knx_apply_device before you \
                 have shown that plan."
            ),
        }))
    }

    /// The model's devices on `line`, refused when there are none or one of
    /// them is linked without KNX Data Secure to a secured group address
    /// (issue #330).
    fn line_targets(
        &self,
        line: (u8, u8),
    ) -> Result<(std::sync::Arc<Model>, Vec<LineTarget>), String> {
        let model = self.state().model.reload();
        let targets = targets_on_line(&model, line.0, line.1);
        if targets.is_empty() {
            return Err(format!(
                "the model has no devices on line {}.{} (looked in {}/devices)",
                line.0,
                line.1,
                self.state().dir.display()
            ));
        }
        for target in targets.iter().filter(|t| t.desired.is_ok()) {
            refuse_insecure_links(&model, target.address)
                .map_err(|why| format!("{} ({}): {why}", target.address, target.name))?;
        }
        Ok((model, targets))
    }

    /// Visits every target in `mode`, updating `job`'s step, and returns
    /// each device's outcome with the notes its visit made. Holds the bus
    /// lock and the warm slot throughout.
    async fn visit_line(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        model: &Model,
        targets: &[LineTarget],
        mode: LineMode,
        expected: Option<&BTreeMap<IndividualAddress, String>>,
    ) -> Result<Vec<(LineOutcome, Vec<String>)>, String> {
        let (_, service, _) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let source = service
            .checked_source(false)
            .await
            .map_err(|e| super::chain(&e))?;
        let material = |address: IndividualAddress| self.plan_material(address, model);
        let tunnel = |secured: bool| self.admitted_tunnel(model, secured);
        let visit = LineVisit {
            service: &service,
            source,
            model,
            dir: &dir,
            mode,
            material: &material,
            tunnel: &tunnel,
            on_parse: None,
            expected,
        };
        let total = targets.len();
        let mut outcomes = Vec::with_capacity(total);
        for (index, target) in targets.iter().enumerate() {
            tier.jobs.step(
                job,
                format!(
                    "{} {} ({}), device {} of {total}",
                    match mode {
                        LineMode::Plan => "reading",
                        LineMode::Apply => "writing",
                    },
                    target.address,
                    target.name,
                    index + 1
                ),
            );
            if mode == LineMode::Apply {
                // The write may change the PID 61 flags: the next plan reads
                // them again instead of a cache (issue #336).
                bussard_service::security_change::forget_flags(&dir, target.address);
            }
            let mut notes = bussard_service::observer::Collected::default();
            let outcome = visit_device(&visit, target, &mut notes).await;
            outcomes.push((outcome, notes.lines));
        }
        Ok(outcomes)
    }

    /// The line plan itself, run inside the plan job; `Err` is a refusal.
    async fn plan_line_body(&self, job: &str, line: (u8, u8)) -> Result<Value, String> {
        let (model, targets) = self.line_targets(line)?;
        let (tier, _, gateway) = self.programming_preflight()?;
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let visited = self
            .visit_line(tier, job, &model, &targets, LineMode::Plan, None)
            .await;
        drop(warm);
        let visited = visited?;
        let line_text = format!("{}.{}", line.0, line.1);
        // A protected group address in any device's change refuses the line,
        // as it refuses the device form, with no override.
        for (o, _) in &visited {
            if let Some(report) = &o.report {
                refuse_protected(&model, report)
                    .map_err(|why| format!("{} ({}): {why}", o.address, o.name))?;
            }
        }
        let outcomes: Vec<LineOutcome> = visited.iter().map(|(o, _)| o.clone()).collect();
        let changed = outcomes
            .iter()
            .filter(|o| matches!(o.status, DeviceStatus::Changes(_)))
            .count();
        let model_side = model_digest(&model, &targets);
        let digest = (changed > 0).then(|| {
            let digest = line_digest(line, &model_side, &outcomes);
            let devices = outcomes
                .iter()
                .filter_map(|o| o.fingerprint.clone().map(|f| (o.address, f)))
                .collect();
            let mut plans = tier.line_plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.insert(
                digest.clone(),
                PendingLinePlan {
                    line,
                    created: Instant::now(),
                    model: model_side.clone(),
                    devices,
                },
            );
            digest
        });
        let devices: Vec<Value> = visited
            .iter()
            .map(|(o, notes)| device_json(&model, o, notes))
            .collect();
        let all_sentences: Vec<String> =
            outcomes.iter().flat_map(|o| sentences(&model, o)).collect();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o.status, DeviceStatus::Failed(_)))
            .count();
        let now = SystemTime::now();
        let question = digest.as_ref().map(|_| {
            format!(
                "Write the model's links to {changed} device(s) on line {line_text} via {gateway}?"
            )
        });
        let failed_note = if failed > 0 {
            format!(
                " {failed} device(s) could not be read (status failed, with the reason in \
                 detail): name them; they are not written."
            )
        } else {
            String::new()
        };
        Ok(json!({
            "ok": true,
            "line": line_text,
            "mode": "plan",
            "gateway": gateway,
            "noop": digest.is_none(),
            "devices": devices,
            "totals": totals(&outcomes),
            "sentences": all_sentences,
            "question": question,
            "plan_digest": digest,
            "planned_at": bussard_monitor::timefmt::to_rfc3339(now),
            "expires_at": digest.as_ref().map(|_| bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl)),
            "next_step": match &digest {
                None => format!(
                    "nothing to write on line {line_text}: every device that answered already \
                     holds the model's links (see devices for any skipped or failed one).{failed_note}"
                ),
                Some(_) => format!(
                    "Show the plan to the human: every device with status changes and its \
                     sentences, and the skipped devices with their reason. Only the link tables \
                     are written in the line form; a parameter change is planned per device \
                     (knx_plan_device with address).{failed_note} Ask the question. Call \
                     knx_apply_device with line {line_text} and this plan_digest only after an \
                     explicit yes."
                ),
            },
        }))
    }

    /// `knx_apply_device` with `line`; `Err` is a refusal reason.
    ///
    /// One job for the line: the pre-flight (the digest, the model, the
    /// validation gate, the audit snapshot) answers in the call; the device
    /// writes continue in the server, as the device form's write does.
    pub(super) async fn apply_line(&self, line: &str, digest: &str) -> Result<Value, String> {
        let began = Instant::now();
        let parsed = parse_line(line).map_err(|e| e.to_string())?;
        let at = line_address(parsed)?;
        let line_text = format!("{}.{}", parsed.0, parsed.1);
        let (tier, _, _) = self.programming_preflight()?;
        let job = tier.jobs.claim(at)?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let me = self.clone();
        let (id, digest_owned) = (job.clone(), digest.to_string());
        let worker = tokio::spawn(async move {
            me.apply_line_job(&id, parsed, &digest_owned, started_tx)
                .await;
        });
        self.watch_job(job.clone(), "apply", worker);
        let read_wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        match tokio::time::timeout(read_wait, started_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                tier.jobs.abandon(&job);
                return Err(reason);
            }
            Ok(Err(_)) => {
                return Err(format!(
                    "the apply of line {line_text} stopped before its pre-flight ended; call \
                     knx_job_status with job {job}"
                ));
            }
            Err(_) => return Ok(self.line_job_started(tier, &job, &line_text)),
        }
        let wait = tier.jobs.reply_wait().saturating_sub(began.elapsed());
        if tier.jobs.wait(&job, wait).await {
            let mut result = tier.jobs.result(&job).unwrap_or_else(|| json!({}));
            let next_step = format!(
                "The write finished within this call (job {job}). Tell the human, per device, \
                 what was written and verified, and name every failed device with its detail \
                 and backup; knx_job_status with job {job} returns this result again.{}",
                super::declared_step(&result)
            );
            merge(
                &mut result,
                json!({"started": false, "done": true, "job": job, "next_step": next_step}),
            );
            return Ok(result);
        }
        Ok(self.line_job_started(tier, &job, &line_text))
    }

    /// The `started: true` answer of a line write still running.
    fn line_job_started(&self, tier: &ProgrammingTier, job: &str, line: &str) -> Value {
        let mut status = tier
            .jobs
            .status(&self.state().dir, job)
            .unwrap_or_else(|| json!({}));
        merge(
            &mut status,
            json!({
                "started": true,
                "done": false,
                "job": job,
                "line": line,
                "next_step": format!(
                    "The write to line {line} continues in the server as job {job}, one device \
                     after the other; it is not done yet. Tell the human it is running, then \
                     call knx_job_status with job {job} every few seconds until `done` is true \
                     and report its `result` per device (what was written, whether it \
                     verified, the backups; or, when result.refused is true, the pre-flight's \
                     reason: nothing was written)."
                ),
            }),
        );
        if let Some(map) = status.as_object_mut() {
            map.remove("result");
            map.remove("state");
        }
        status
    }

    /// One line apply job: the pre-flight, then every device's write and
    /// read-back, holding the bus lock and the warm slot throughout.
    async fn apply_line_job(
        &self,
        job: &str,
        line: (u8, u8),
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
        let prepared = match self.apply_line_preflight(tier, line, digest) {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.refuse(job, &reason);
                let _ = started.send(Err(reason));
                return;
            }
        };
        let (model, targets, planned, gateway, snapshot, declared) = prepared;
        let line_text = format!("{}.{}", line.0, line.1);
        let record = snapshot.as_ref().map(|id| {
            History::open(&self.state().dir)
                .history_dir()
                .join(id)
                .join(crate::jobs::RECORD_FILE)
        });
        tier.jobs.started(
            job,
            json!({
                "line": line_text,
                "gateway": gateway,
                "snapshot": snapshot,
                "declared": declared,
            }),
            record,
        );
        let _ = started.send(Ok(()));
        let visited = self
            .visit_line(
                tier,
                job,
                &model,
                &targets,
                LineMode::Apply,
                Some(&planned.devices),
            )
            .await;
        drop(warm);
        let result = match visited {
            Err(reason) => json!({
                "ok": false,
                "verified": false,
                "line": line_text,
                "gateway": gateway,
                "reason": reason,
                "snapshot": snapshot,
                "declared": declared,
            }),
            Ok(visited) => {
                for (o, _) in &visited {
                    if matches!(o.status, DeviceStatus::Applied(_) | DeviceStatus::Unchanged) {
                        // The device now holds the model's links; its
                        // parameter edits stay pending (not written here).
                        self.session_edits().applied(o.address, false);
                    }
                }
                let outcomes: Vec<LineOutcome> = visited.iter().map(|(o, _)| o.clone()).collect();
                let failed = outcomes
                    .iter()
                    .filter(|o| matches!(o.status, DeviceStatus::Failed(_)))
                    .count();
                json!({
                    "ok": failed == 0,
                    "verified": failed == 0,
                    "line": line_text,
                    "mode": "apply",
                    "gateway": gateway,
                    "snapshot": snapshot,
                    "declared": declared,
                    "devices": visited
                        .iter()
                        .map(|(o, notes)| device_json(&model, o, notes))
                        .collect::<Vec<_>>(),
                    "totals": totals(&outcomes),
                })
            }
        };
        tier.jobs.finish(job, result);
    }

    /// The pre-flight of a line write: the digest names a fresh line plan of
    /// this session for `line`, the model still produces it, the group
    /// addresses the device files use are declared, the model validates, and
    /// the audit snapshot is recorded. Consumes the plan.
    #[allow(clippy::type_complexity)] // one pre-flight's findings, used once
    fn apply_line_preflight(
        &self,
        tier: &ProgrammingTier,
        line: (u8, u8),
        digest: &str,
    ) -> Result<
        (
            std::sync::Arc<Model>,
            Vec<LineTarget>,
            PendingLinePlan,
            String,
            Option<String>,
            Vec<String>,
        ),
        String,
    > {
        let (_, _, gateway) = self.programming_preflight()?;
        let line_text = format!("{}.{}", line.0, line.1);
        let planned = {
            let mut plans = tier.line_plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.get(digest).cloned()
        };
        let Some(planned) = planned else {
            return Err(format!(
                "no fresh line plan with digest {digest:?} in this session (plans expire after \
                 {} minute(s) and are single use); call knx_plan_device with line {line_text}, \
                 show the plan to the human and ask again",
                tier.plan_ttl.as_secs().div_ceil(60)
            ));
        };
        if planned.line != line {
            return Err(format!(
                "plan {digest} is for line {}.{}, not {line_text}",
                planned.line.0, planned.line.1
            ));
        }
        let (model, targets) = self.line_targets(line)?;
        if model_digest(&model, &targets) != planned.model {
            tier.line_plans().remove(digest);
            return Err(format!(
                "refusing to write line {line_text}: the model's devices or links on the line \
                 (or its protected group addresses) changed since the plan was made. Plan again \
                 with knx_plan_device and line {line_text}, and show the new plan to the human."
            ));
        }
        // A group address a device file uses but groups.toml does not define
        // is declared there first, named after the object that uses it, as
        // `bussard apply --line` does (issue #779). It adds no link, so the
        // plan's tables stand.
        let dir = self.state().dir.clone();
        let (model, declared) = self.declare_used(model, "mcp knx_apply_device --line")?;
        // Validation is part of apply, as `bussard apply --line` gates it: a
        // model with errors is never written.
        let errors: Vec<String> = bussard_model::validate_in_dir(&model, &dir)
            .iter()
            .filter(|d| d.severity == bussard_model::Severity::Error)
            .map(|d| format!("error[{}]: {} ({})", d.code, d.message, d.location))
            .collect();
        if !errors.is_empty() {
            return Err(format!(
                "refusing to write line {line_text}: the model has {} validation error(s); \
                 nothing was written. Fix these first: {}",
                errors.len(),
                errors.join("; ")
            ));
        }
        // The plan is consumed from here on: one digest, one write.
        tier.line_plans().remove(digest);
        // The audit line: one history snapshot for the whole run, before the
        // first bus write, naming the line, the plan and the gateway.
        let history = History::open(&dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_apply_device")
                .with_args(["--line".to_string(), line_text.clone(), digest.to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result(super::with_declared(
                    "before writing the line's device tables",
                    &declared,
                ));
            match history.snapshot(reason) {
                Ok(id) => Some(id.to_string()),
                Err(err) => {
                    return Err(format!(
                        "refusing to write line {line_text}: the audit snapshot could not be \
                         recorded ({err})"
                    ));
                }
            }
        } else {
            None
        };
        Ok((model, targets, planned, gateway, snapshot, declared))
    }
}

/// A refusal of a line call, in the shape of the device form's.
pub(super) fn line_refusal(line: &str, reason: String) -> Value {
    json!({
        "line": line,
        "ok": false,
        "refused": true,
        "reason": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_address_is_the_coupler() -> Result<(), String> {
        assert_eq!(line_address((1, 1))?.to_string(), "1.1.0");
        Ok(())
    }

    #[test]
    fn test_line_digest_binds_every_fingerprint() -> Result<(), String> {
        let ia: IndividualAddress = "1.1.4".parse().map_err(|_| "address".to_string())?;
        let outcome = |fingerprint: &str| LineOutcome {
            address: ia,
            name: "a".into(),
            mask: Some(0x07B0),
            status: DeviceStatus::Changes(1),
            report: None,
            fingerprint: Some(fingerprint.into()),
            backup: None,
        };
        let a = line_digest((1, 1), "m", &[outcome("x")]);
        assert_ne!(a, line_digest((1, 1), "m", &[outcome("y")]));
        assert_ne!(a, line_digest((1, 2), "m", &[outcome("x")]));
        assert_ne!(a, line_digest((1, 1), "n", &[outcome("x")]));
        assert_eq!(a.len(), 64);
        Ok(())
    }
}
