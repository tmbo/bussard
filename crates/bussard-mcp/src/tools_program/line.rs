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

use crate::reply::refused_on;
use std::collections::BTreeMap;
use std::time::SystemTime;

use bussard_mgmt::system_type;
use bussard_model::history::SnapshotReason;
use bussard_model::{IndividualAddress, Model};
use bussard_service::line::{
    DeviceStatus, LineMode, LineOutcome, LineTarget, LineVisit, parse_line, targets_digest,
    targets_on_line, visit_device,
};
use bussard_service::program::plan::Fingerprint;
use serde_json::{Value, json};

use super::{BussardMcp, ProgrammingTier, Subject, merge, refuse_insecure_links, refuse_protected};

/// What a line plan this session produced binds, remembered until applied,
/// refused or expired.
#[derive(Debug, Clone)]
pub(super) struct LinePlan {
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
    let mut h = Fingerprint::new(b"bussard-line-model-v1").put(targets_digest(targets));
    for (ga, _) in model.groups.groups.iter().filter(|(_, g)| g.protected) {
        h = h.put(ga.raw().to_be_bytes());
    }
    h.hex()
}

/// The digest the human's yes binds: the line, its model side and every
/// device's outcome and fingerprint.
fn line_digest(line: (u8, u8), model: &str, outcomes: &[LineOutcome]) -> String {
    let mut h = Fingerprint::new(b"bussard-line-plan-v1")
        .put([line.0, line.1])
        .put(model);
    for o in outcomes {
        let fingerprint = o.fingerprint.as_deref().unwrap_or("-");
        h = h.address(o.address).put(o.status.key()).put(fingerprint);
    }
    h.hex()
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
    /// `knx_plan_device` with `line`; `Err` is a refusal reason. Runs as a
    /// plan job, as the device form does (issue #332).
    pub(super) async fn plan_line(&self, line: &str) -> Result<Value, String> {
        let parsed = parse_line(line).map_err(|e| e.to_string())?;
        let at = line_address(parsed)?;
        self.line_targets(parsed)?;
        let text = format!("{}.{}", parsed.0, parsed.1);
        let subject = Subject::Line(text.clone(), at);
        self.run_plan(subject, move |me, job| async move {
            Ok(me
                .plan_line_body(&job, parsed)
                .await
                .unwrap_or_else(|reason| refused_on("line", &text, reason)))
        })
        .await
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
        let source = service.checked_source(false).await?;
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
            let plan = LinePlan {
                model: model_side.clone(),
                devices,
            };
            tier.line_plans
                .insert(digest.clone(), format!("line {line_text}"), plan);
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
            "expires_at": digest.as_ref().map(|_| tier.line_plans.expires_at(now)),
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
    /// One job for the line ([`BussardMcp::run_write`]): the pre-flight (the
    /// digest, the model, the validation gate, the audit snapshot) answers in
    /// the call; the device writes continue in the server, holding the bus
    /// lock and the warm slot throughout, as the device form's write does.
    pub(super) async fn apply_line(&self, line: &str, digest: &str) -> Result<Value, String> {
        let parsed = parse_line(line).map_err(|e| e.to_string())?;
        let at = line_address(parsed)?;
        let text = format!("{}.{}", parsed.0, parsed.1);
        let digest = digest.to_string();
        let subject = Subject::Line(text.clone(), at);
        self.run_write(subject, "apply", move |me, job, gate| async move {
            let tier = me.tier()?;
            me.on_bus(tier, async {
                let (model, targets, planned, gateway, snapshot, declared) =
                    me.apply_line_preflight(tier, parsed, &digest)?;
                let context = json!({
                    "line": text,
                    "gateway": gateway,
                    "snapshot": snapshot,
                    "declared": declared,
                });
                let record = crate::jobs::record_file(&me.state().dir, snapshot.as_deref());
                gate.pass(context.clone(), record);
                let mode = LineMode::Apply;
                let expected = Some(&planned.devices);
                let visited = me.visit_line(tier, &job, &model, &targets, mode, expected);
                let mut result = context;
                match visited.await {
                    Err(reason) => merge(
                        &mut result,
                        json!({"ok": false, "verified": false, "reason": reason}),
                    ),
                    Ok(visited) => {
                        for (o, _) in &visited {
                            if matches!(
                                o.status,
                                DeviceStatus::Applied(_) | DeviceStatus::Unchanged
                            ) {
                                // The device now holds the model's links; its
                                // parameter edits stay pending (not written here).
                                me.session_edits().applied(o.address, false);
                            }
                        }
                        let outcomes: Vec<LineOutcome> =
                            visited.iter().map(|(o, _)| o.clone()).collect();
                        let failed = outcomes
                            .iter()
                            .filter(|o| matches!(o.status, DeviceStatus::Failed(_)))
                            .count();
                        let devices: Vec<Value> = visited
                            .iter()
                            .map(|(o, notes)| device_json(&model, o, notes))
                            .collect();
                        merge(
                            &mut result,
                            json!({
                                "ok": failed == 0,
                                "verified": failed == 0,
                                "mode": "apply",
                                "devices": devices,
                                "totals": totals(&outcomes),
                            }),
                        );
                    }
                }
                Ok(result)
            })
            .await
        })
        .await
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
            LinePlan,
            String,
            Option<String>,
            Vec<String>,
        ),
        String,
    > {
        let (_, _, gateway) = self.programming_preflight()?;
        let line_text = format!("{}.{}", line.0, line.1);
        let again = format!(
            "call knx_plan_device with line {line_text}, show the plan to the human and ask again"
        );
        let subject = format!("line {line_text}");
        let planned = tier.line_plans.fresh(digest, subject, "line plan", again)?;
        let (model, targets) = self.line_targets(line)?;
        if model_digest(&model, &targets) != planned.model {
            tier.line_plans.retire(digest);
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
        tier.line_plans.retire(digest);
        // The audit line: one history snapshot for the whole run, before the
        // first bus write, naming the line, the plan and the gateway.
        let reason = SnapshotReason::new("mcp knx_apply_device")
            .with_args(["--line".to_string(), line_text.clone(), digest.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result(super::with_declared(
                "before writing the line's device tables",
                &declared,
            ));
        let snapshot = super::audit_snapshot(&dir, reason, format!("line {line_text}"))?;
        Ok((model, targets, planned, gateway, snapshot, declared))
    }
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
