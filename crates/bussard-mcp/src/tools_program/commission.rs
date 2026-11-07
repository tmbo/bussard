//! `knx_commission_line` (issue #753): commission a line from chat, the
//! flow `bussard commission` runs at the terminal, on the same functions
//! ([`bussard_service::commission`], composed from
//! [`bussard_service::assign`]).
//!
//! Three kinds of call, one job of the server's job table
//! ([`crate::jobs::JobKind::Commission`]):
//!
//! 1. **The plan.** `{line}` reads the model only: the devices of the line by
//!    name, room and order number, the sentences, the question and a
//!    `plan_digest`. Nothing touches the bus.
//! 2. **The yes.** `{line, plan_digest, yes: true}` starts the job. One yes
//!    covers the run, as the CLI's one confirmation does: the job checks
//!    which model addresses already answer (those are skipped), then repeats
//!    per device `press_button` (the question names the device), `identified`
//!    (serial, mask and order number, the order number checked against the
//!    model) and `assigned` (the address written and read back, and the
//!    label text the CLI prints), without asking again while the identified
//!    device is the product the model expects.
//! 3. **The human's word.** Anything else pauses the job (no device, several,
//!    another product, an unreadable order number, a device the model has no
//!    order number for): nothing is written and the slot is free while it
//!    waits. `{job, answer}` goes on with `retry`, `skip` or `stop`, or
//!    `assign` where the question offers it; `stop` also ends a running job
//!    (at once while it waits for a button, else after the device it is on).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bussard_model::Model;
use bussard_model::history::SnapshotReason;
use bussard_service::assign::hex;
use bussard_service::commission::{
    Identified, LineRun, Next, OrderCheck, Outcome, Status, Target, assign_pressed,
    identify_pressed, probe_line,
};
use bussard_service::line::WalkEvent;
use bussard_service::observer::Collected;
use bussard_service::program::assign::{AssignFlow, Stop as FlowStop};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::addressing::assigned_notes;
use super::{BussardMcp, ProgrammingTier, chain, put};
use crate::jobs::JobSink;

/// The answers a paused job takes.
const ANSWERS: [&str; 4] = ["retry", "skip", "stop", "assign"];

/// The session state of `knx_commission_line`: the plans handed out and
/// the jobs running or waiting.
#[derive(Default)]
pub(super) struct Commissions {
    /// Plans produced in this session, by digest.
    plans: HashMap<String, PlanEntry>,
    /// Jobs of this session, by id.
    jobs: HashMap<String, JobEntry>,
}

/// A plan handed out.
struct PlanEntry {
    /// The line it covers.
    line: String,
    /// When it was produced.
    created: Instant,
}

/// A job of this session.
struct JobEntry {
    /// The human's stop.
    stop: Arc<Stop>,
    /// The run, while the job waits for the human's word.
    paused: Option<Paused>,
}

/// A run waiting for the human's word.
struct Paused {
    /// Where the run is.
    run: RunState,
    /// The question offers `assign` (the model has no order number).
    offers_assign: bool,
}

/// The human's stop: a flag the run checks between steps and a wake-up for
/// the wait for the programming button.
#[derive(Default)]
struct Stop {
    /// Set once the human said stop.
    flag: AtomicBool,
    /// Wakes the wait.
    notify: tokio::sync::Notify,
}

impl Stop {
    /// Says stop.
    fn set(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Whether stop was said.
    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Returns once stop was said.
    async fn wait(&self) {
        while !self.is_set() {
            self.notify.notified().await;
        }
    }
}

/// The device the run is on.
#[derive(Debug, Clone)]
struct Current {
    /// Its 1-based position on the line.
    position: usize,
    /// How many devices the line has.
    total: usize,
    /// The device.
    target: Target,
    /// Why the job paused on it, for a `skip`.
    reason: Option<String>,
    /// The human said `assign` to a device the model has no order number
    /// for.
    accept_unchecked: bool,
}

/// One run over a line.
#[derive(Debug, Clone)]
struct RunState {
    /// The walk and its outcomes.
    walk: LineRun,
    /// The gateway, for the result.
    gateway: String,
    /// The pre-pass ran.
    probed: bool,
    /// The history snapshot before the first write was taken.
    snapshot: bool,
    /// The device the run is on.
    current: Option<Current>,
    /// One report per device that ended, in order.
    reports: Vec<Value>,
}

/// How a stretch of the run ended.
enum Segment {
    /// The run is over; the job's result.
    Done(Value),
    /// The run waits for the human's word.
    Pause(Box<PauseParts>),
}

/// What a pause reports.
struct PauseParts {
    /// The run to resume.
    run: RunState,
    /// The step it paused at.
    step: &'static str,
    /// Why, in a sentence that ends with what was written (nothing).
    reason: String,
    /// The question for the human.
    question: String,
    /// The identification, when the device was read.
    identified: Value,
    /// The question offers `assign`.
    offers_assign: bool,
}

/// The device in words: name, room and order number.
fn who(target: &Target) -> String {
    let room = target
        .room
        .as_deref()
        .map(|r| format!(" in {r}"))
        .unwrap_or_default();
    let order = match &target.order_number {
        Some(order) => format!(" ({order})"),
        None => " (no order number in the model)".to_string(),
    };
    format!("{}{room}{order}", target.name)
}

/// A model device as the results list it.
fn device_json(target: &Target) -> Value {
    json!({
        "address": target.address.to_string(),
        "name": target.name,
        "floor": target.floor,
        "room": target.room,
        "order_number": target.order_number,
    })
}

/// What the identification read, for the `identified` step.
fn identified_json(i: &Identified) -> Value {
    let v = &i.verified;
    json!({
        "current_address": i.current.to_string(),
        "serial": v.serial.as_deref().map(hex),
        "mask": v.mask.map(|m| format!("{m:04X}")),
        "manufacturer": v.manufacturer_id.map(bussard_mgmt::manufacturers::display),
        "order_number": v.order,
        "order_check": match i.check {
            OrderCheck::Matches => "matches",
            OrderCheck::NoModelNumber => "no_model_number",
            OrderCheck::Refused(_) => "refused",
        },
    })
}

/// The plan digest: the line, the gateway and every model device on it
/// (address, name, product, place).
fn plan_digest(line: &str, gateway: &str, targets: &[Target]) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-commission-line-v1");
    put(&mut h, line.as_bytes());
    put(&mut h, gateway.as_bytes());
    for t in targets {
        put(&mut h, &t.address.raw().to_be_bytes());
        put(&mut h, t.name.as_bytes());
        for field in [&t.order_number, &t.manufacturer, &t.floor, &t.room] {
            put(&mut h, field.as_deref().unwrap_or("").as_bytes());
        }
    }
    let bytes: [u8; 32] = h.finalize().into();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// The line's run over `model`, or the refusal for an empty line.
fn line_run(model: &Model, line: &str) -> Result<LineRun, String> {
    let (area, line_no) = bussard_service::line::parse_line(line).map_err(|e| e.to_string())?;
    let run = LineRun::new(model, area, line_no);
    if run.targets().is_empty() {
        return Err(format!(
            "the model has no devices on line {}; nothing to commission",
            run.line()
        ));
    }
    Ok(run)
}

/// The question to retry, skip or stop on `target`.
fn retry_question(target: &Target, what_to_do: &str) -> String {
    format!(
        "{what_to_do} Say retry to go on with {}, skip to leave it for later, or stop to end \
         the run.",
        target.name
    )
}

impl BussardMcp {
    /// `knx_commission_line`'s body; `Err` is a refusal reason.
    pub(super) async fn commission_line_tool(
        &self,
        args: super::CommissionLineArgs,
    ) -> Result<Value, String> {
        let (tier, _, gateway) = self.programming_preflight()?;
        if let Some(job) = args.job.as_deref().map(str::trim) {
            let answer = args.answer.as_deref().map(str::trim).unwrap_or_default();
            return self.commission_answer(tier, job, answer);
        }
        let Some(line) = args.line.as_deref().map(str::trim) else {
            return Err(
                "pass `line` (e.g. \"1.1\") for the plan, or `job` with `answer` for a running \
                 commissioning job"
                    .into(),
            );
        };
        let model = self.state().model.reload();
        let walk = line_run(&model, line)?;
        let digest = plan_digest(walk.line(), &gateway, walk.targets());
        match args.plan_digest.as_deref().map(str::trim) {
            None => {
                if args.yes == Some(true) {
                    return Err(
                        "yes answers a plan: call knx_commission_line with `line` alone first, \
                         show the human its sentences, then pass its plan_digest with yes: true"
                            .into(),
                    );
                }
                Ok(self.commission_plan(tier, &walk, &gateway, digest))
            }
            Some(given) => self.commission_start(tier, walk, gateway, &digest, given, args.yes),
        }
    }

    /// The plan: the model's devices on the line, the sentences and the
    /// question. Reads the model only.
    fn commission_plan(
        &self,
        tier: &ProgrammingTier,
        walk: &LineRun,
        gateway: &str,
        digest: String,
    ) -> Value {
        let line = walk.line();
        let targets = walk.targets();
        {
            let mut c = tier.commissions();
            c.plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            c.plans.insert(
                digest.clone(),
                PlanEntry {
                    line: line.to_string(),
                    created: Instant::now(),
                },
            );
        }
        let names: Vec<String> = targets.iter().map(who).collect();
        let n = targets.len();
        let sentences = vec![
            format!(
                "Line {line} has {n} device(s) in the model: {}.",
                names.join("; ")
            ),
            "First bussard checks which of them already answer at their address; those are \
             skipped."
                .to_string(),
            "Then, one device at a time, the human presses its programming button. bussard reads \
             the device's order number and, when it is the product the model expects, writes the \
             address, reads the device back at it and gives the label text, without asking \
             again."
                .to_string(),
            "A different product, no device, two devices in programming mode, or a device the \
             model has no order number for pauses the run until the human says retry, skip or \
             stop. Only addresses are written: no links, parameters or application programs."
                .to_string(),
        ];
        let now = std::time::SystemTime::now();
        json!({
            "ok": true,
            "step": "plan",
            "line": line,
            "gateway": gateway,
            "devices": targets.iter().map(device_json).collect::<Vec<_>>(),
            "total": n,
            "sentences": sentences,
            "summary": format!(
                "Commissioning line {line} gives its {n} device(s) their addresses, one press \
                 of a programming button at a time."
            ),
            "question": format!(
                "Commission the {n} device(s) of line {line} via {gateway}? One yes covers every \
                 device that turns out to be the product the model expects. Say yes."
            ),
            "plan_digest": digest,
            "expires_at": bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl),
            "next_step": "Say the summary, show the human the sentences in full and ask the \
                question. Only after an explicit yes call knx_commission_line with line, \
                plan_digest and yes: true. Nothing is written before that.",
        })
    }

    /// The yes: checks the digest, claims the job and starts the run.
    fn commission_start(
        &self,
        tier: &ProgrammingTier,
        walk: LineRun,
        gateway: String,
        fresh: &str,
        given: &str,
        yes: Option<bool>,
    ) -> Result<Value, String> {
        let line = walk.line().to_string();
        let known = {
            let mut c = tier.commissions();
            c.plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            c.plans.get(given).map(|p| p.line.clone())
        };
        match known {
            None => {
                return Err(format!(
                    "no plan with this plan_digest in this session (unknown, used, or older than \
                     the plan lifetime). Call knx_commission_line with line {line} for a new one. \
                     Nothing was written."
                ));
            }
            Some(planned) if planned != line => {
                return Err(format!(
                    "the plan_digest is the plan of line {planned}, not {line}. Nothing was \
                     written."
                ));
            }
            Some(_) => {}
        }
        if given != fresh {
            return Err(format!(
                "the model's devices on line {line} or the gateway changed since the plan. Call \
                 knx_commission_line with line {line} for a new plan. Nothing was written."
            ));
        }
        if yes != Some(true) {
            return Err(
                "commissioning writes addresses on the bus: pass yes: true only after the \
                 human's explicit yes to the plan's question. Nothing was written."
                    .into(),
            );
        }
        let job = tier.jobs.claim_commission(&line)?;
        let stop = Arc::new(Stop::default());
        {
            let mut c = tier.commissions();
            c.plans.remove(given);
            c.jobs.insert(
                job.clone(),
                JobEntry {
                    stop: Arc::clone(&stop),
                    paused: None,
                },
            );
        }
        let run = RunState {
            walk,
            gateway: gateway.clone(),
            probed: false,
            snapshot: false,
            current: None,
            reports: Vec::new(),
        };
        self.spawn_commission(job.clone(), run, stop);
        Ok(json!({
            "ok": true,
            "started": true,
            "done": false,
            "step": "checking which devices already answer",
            "job": job,
            "line": line,
            "gateway": gateway,
            "next_step": format!(
                "The run is job {job}. Call knx_job_status with job {job} every few seconds. \
                 While it waits for a button its `question` names the device: relay it to the \
                 human word for word. When `waiting` is set, tell the human waiting.reason and \
                 ask `question`, then pass the answer as knx_commission_line {{job, answer}}. \
                 The human can stop the run at any time: answer \"stop\"."
            ),
        }))
    }

    /// The human's word for a job: `retry`, `skip`, `assign` or `stop`.
    fn commission_answer(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        answer: &str,
    ) -> Result<Value, String> {
        let answer = answer.to_ascii_lowercase();
        if !ANSWERS.contains(&answer.as_str()) {
            return Err(format!(
                "pass `answer` with the job: \"retry\", \"skip\", \"stop\" or \"assign\" (got \
                 {answer:?})"
            ));
        }
        let (stop, paused) = {
            let mut c = tier.commissions();
            let Some(entry) = c.jobs.get_mut(job) else {
                return Err(format!(
                    "no running commissioning job {job} in this session (it ended, or the \
                     server restarted). Call knx_commission_line with the line for a new plan."
                ));
            };
            (Arc::clone(&entry.stop), entry.paused.take())
        };
        let Some(paused) = paused else {
            if answer == "stop" {
                stop.set();
                return Ok(json!({
                    "ok": true,
                    "job": job,
                    "stopping": true,
                    "next_step": format!(
                        "The run stops at once while it waits for a button, else after the \
                         device it is on (a write in progress is never cut). Call \
                         knx_job_status with job {job} until `done` is true and tell the human \
                         result.summary."
                    ),
                }));
            }
            return Err(format!(
                "job {job} is not waiting for an answer; call knx_job_status with job {job} and \
                 answer its question when `waiting` is set"
            ));
        };
        if answer == "stop" {
            tier.commissions().jobs.remove(job);
            let result = final_result(&paused.run, true, None);
            tier.jobs.finish(job, result.clone());
            let mut out = result;
            super::merge(&mut out, json!({ "job": job, "done": true }));
            return Ok(out);
        }
        if answer == "assign" && !paused.offers_assign {
            self.put_back(tier, job, paused);
            return Err(
                "`assign` answers only a device the model has no order number for; this question \
                 offers retry, skip or stop"
                    .into(),
            );
        }
        let step = match answer.as_str() {
            "skip" => "skipping the device",
            "assign" => "assigning the pressed device",
            _ => "retrying the device",
        };
        if let Err(reason) = tier.jobs.resume(job, step) {
            self.put_back(tier, job, paused);
            return Err(reason);
        }
        tier.jobs.forget(job, "waiting");
        let mut run = paused.run;
        let skipped = match answer.as_str() {
            "skip" => run.current.take(),
            "assign" => {
                if let Some(cur) = run.current.as_mut() {
                    cur.accept_unchecked = true;
                }
                None
            }
            _ => None,
        };
        if let Some(cur) = skipped {
            let detail = format!(
                "skipped on the human's word: {}",
                cur.reason
                    .as_deref()
                    .unwrap_or("the run paused on this device")
            );
            let outcome = Outcome::failed(&cur.target, detail);
            run.reports
                .push(outcome_report(&cur.target, &outcome, None));
            run.walk.record(outcome);
            tier.jobs
                .progress(job, "devices", Value::Array(run.reports.clone()));
        }
        self.spawn_commission(job.to_string(), run, stop);
        Ok(json!({
            "ok": true,
            "job": job,
            "resumed": true,
            "answer": answer,
            "step": step,
            "next_step": format!(
                "The run goes on as job {job}. Call knx_job_status with job {job} every few \
                 seconds and relay its `question` to the human word for word."
            ),
        }))
    }

    /// Puts a paused run back after a refused answer.
    fn put_back(&self, tier: &ProgrammingTier, job: &str, paused: Paused) {
        if let Some(entry) = tier.commissions().jobs.get_mut(job) {
            entry.paused = Some(paused);
        }
    }

    /// Runs the job in a server task until it ends or pauses.
    fn spawn_commission(&self, job: String, run: RunState, stop: Arc<Stop>) {
        let me = self.clone();
        let id = job.clone();
        let worker = tokio::spawn(async move {
            let state = Arc::clone(me.state());
            let Some(tier) = state.programming.as_ref() else {
                return;
            };
            let segment = me
                .on_bus(tier, me.commission_segment(&id, run, &stop))
                .await;
            match segment {
                Segment::Done(result) => {
                    tier.commissions().jobs.remove(&id);
                    tier.jobs.finish(&id, result);
                }
                Segment::Pause(parts) => {
                    let PauseParts {
                        run,
                        step,
                        reason,
                        question,
                        identified,
                        offers_assign,
                    } = *parts;
                    let device = run.current.as_ref().map(|c| device_json(&c.target));
                    let answers: &[&str] = if offers_assign {
                        &["assign", "retry", "skip", "stop"]
                    } else {
                        &["retry", "skip", "stop"]
                    };
                    let detail = json!({
                        "waiting": {
                            "device": device,
                            "reason": reason,
                            "identified": identified,
                            "answers": answers,
                        },
                    });
                    tier.jobs
                        .progress(&id, "devices", Value::Array(run.reports.clone()));
                    if let Some(entry) = tier.commissions().jobs.get_mut(&id) {
                        entry.paused = Some(Paused { run, offers_assign });
                    }
                    tier.jobs.pause(&id, step, question, None, detail);
                }
            }
        });
        self.watch_job(job, "commission", worker);
    }

    /// One stretch of the run, on the bus: the pre-pass, then device after
    /// device until the line is walked, the human stops it, or a device needs
    /// the human's word.
    async fn commission_segment(&self, job: &str, mut run: RunState, stop: &Stop) -> Segment {
        let state = self.state();
        let Some(tier) = state.programming.as_ref() else {
            return Segment::Done(final_result(
                &run,
                false,
                Some("the programming tier is off".into()),
            ));
        };
        let (service, source) = match self.address_bus().await {
            Ok(bus) => bus,
            Err(reason) => return Segment::Done(final_result(&run, false, Some(reason))),
        };
        let flow = AssignFlow {
            service: &service,
            source,
        };
        let jobs = Arc::clone(&tier.jobs);

        if !run.probed {
            tier.jobs.step(job, "checking which devices already answer");
            let targets = run.walk.targets().to_vec();
            let mut on_probe = |event: WalkEvent<'_, _>| {
                if let WalkEvent::Probing { address, .. } = event {
                    jobs.progress(job, "checking", json!(address.to_string()));
                }
            };
            let verdicts = probe_line(&service, source, &targets, &mut on_probe).await;
            run.walk.set_verdicts(verdicts);
            run.probed = true;
            tier.jobs
                .progress(job, "pending", json!(run.walk.pending()));
        }

        loop {
            if stop.is_set() {
                return Segment::Done(final_result(&run, true, None));
            }
            if run.current.is_none() {
                match run.walk.advance() {
                    None => break,
                    Some(Next::Settled(outcome)) => {
                        if let Some(target) = run
                            .walk
                            .targets()
                            .iter()
                            .find(|t| t.address == outcome.address)
                        {
                            run.reports.push(outcome_report(target, &outcome, None));
                        }
                        tier.jobs
                            .progress(job, "devices", Value::Array(run.reports.clone()));
                        continue;
                    }
                    Some(Next::Device {
                        position,
                        total,
                        target,
                    }) => {
                        run.current = Some(Current {
                            position,
                            total,
                            target,
                            reason: None,
                            accept_unchecked: false,
                        });
                    }
                }
            }
            let Some(cur) = run.current.clone() else {
                continue;
            };
            let target = &cur.target;
            if !run.snapshot {
                let mut said = Collected::default();
                bussard_service::setup::import::snapshot(
                    &state.dir,
                    SnapshotReason::new("knx_commission_line")
                        .with_args([run.walk.line().to_string()])
                        .with_gateway(Some(run.gateway.clone()))
                        .with_result("before assigning addresses on the line"),
                    &mut said,
                );
                run.snapshot = true;
            }

            // press_button
            tier.jobs.progress(
                job,
                "device",
                json!({
                    "position": cur.position,
                    "total": cur.total,
                    "device": device_json(target),
                }),
            );
            let mut observer = JobSink::new(&tier.jobs, job).press(format!(
                "Device {} of {}: press the programming button on {} (its LED usually lights \
                 up), then say done.",
                cur.position,
                cur.total,
                who(target)
            ));
            let waited = tokio::select! {
                waited = flow.wait_for_one(&mut observer) => waited,
                () = stop.wait() => return Segment::Done(final_result(&run, true, None)),
            };
            let current = match waited {
                Ok(current) => current,
                Err(FlowStop::Several(found)) => {
                    let list: Vec<String> = found.iter().map(ToString::to_string).collect();
                    let reason = format!(
                        "{} devices are in programming mode ({}); commissioning works on one \
                         device at a time. Nothing was written.",
                        found.len(),
                        list.join(", ")
                    );
                    let question = retry_question(
                        target,
                        &format!("Leave programming mode on all devices but {}.", target.name),
                    );
                    return pause(run, "press_button", reason, question, Value::Null, false);
                }
                Err(FlowStop::Nothing { waited }) => {
                    let reason = format!(
                        "No device entered programming mode within {} s. Nothing was written.",
                        waited.as_secs()
                    );
                    let question = retry_question(
                        target,
                        &format!("Press the programming button on {}.", who(target)),
                    );
                    return pause(run, "press_button", reason, question, Value::Null, false);
                }
                Err(e) => {
                    let reason = format!(
                        "The programming-mode broadcast failed ({}). Nothing was written.",
                        chain(&e)
                    );
                    let question = retry_question(target, "Check the bus connection.");
                    return pause(run, "press_button", reason, question, Value::Null, false);
                }
            };

            // identified
            let identified = match identify_pressed(&flow, target, current, &mut observer).await {
                Ok(identified) => identified,
                Err(e) => {
                    let reason = format!(
                        "The device in programming mode at {current} did not answer the \
                         identification ({}). Nothing was written.",
                        chain(&e)
                    );
                    let question = retry_question(
                        target,
                        &format!("Press the programming button on {} again.", target.name),
                    );
                    return pause(run, "identified", reason, question, Value::Null, false);
                }
            };
            let ident = identified_json(&identified);
            tier.jobs.progress(job, "identified", ident.clone());
            match &identified.check {
                OrderCheck::Matches => {}
                OrderCheck::NoModelNumber if cur.accept_unchecked => {}
                OrderCheck::NoModelNumber => {
                    let reason = format!(
                        "The model has no order number for {}, so the pressed device (order \
                         number {}) cannot be checked against it. Nothing was written.",
                        target.name,
                        identified.verified.order.as_deref().unwrap_or("unknown")
                    );
                    let question = format!(
                        "Say assign to give {}'s address to the pressed device anyway, retry \
                         after pressing another device, skip to leave {} for later, or stop.",
                        target.name, target.name
                    );
                    return pause(run, "identified", reason, question, ident, true);
                }
                OrderCheck::Refused(_) => {
                    let expected = target.order_number.as_deref().unwrap_or_default();
                    let reason = match identified.verified.order.as_deref() {
                        Some(read) => format!(
                            "The pressed device is a {read}, but the model expects a {expected} \
                             for {}. Nothing was written.",
                            target.name
                        ),
                        None => format!(
                            "The pressed device did not report an order number, so it cannot be \
                             checked against the {expected} the model expects for {}. Nothing \
                             was written.",
                            target.name
                        ),
                    };
                    let question = retry_question(
                        target,
                        &format!(
                            "Leave programming mode on the pressed device (press its button \
                             again) and press the button on {}.",
                            who(target)
                        ),
                    );
                    return pause(run, "identified", reason, question, ident, false);
                }
            }

            // assigned
            let (outcome, readback) =
                match assign_pressed(&flow, &state.dir, target, &identified, &mut observer).await {
                    Ok(labelled) => {
                        let mut notes = assigned_notes(&labelled.assigned);
                        if matches!(identified.check, OrderCheck::NoModelNumber) {
                            notes.push(format!(
                                "Assigned on the human's word: the model has no order number \
                                 for {}.",
                                target.name
                            ));
                        }
                        let v = &labelled.identity;
                        let readback = json!({
                            "verified": true,
                            "mask": v.mask.map(|m| format!("{m:04X}")),
                            "serial": v.serial.as_deref().map(hex),
                            "order_number": v.order,
                            "programming_mode_cleared": v.programming_mode_cleared,
                            "notes": notes,
                        });
                        (Outcome::commissioned(target, labelled.label), readback)
                    }
                    Err(e) => (
                        Outcome::failed(target, chain(&e)),
                        json!({ "verified": false }),
                    ),
                };
            let mut report = outcome_report(target, &outcome, Some(ident));
            super::merge(
                &mut report,
                json!({ "step": "assigned", "from": current.to_string(), "readback": readback }),
            );
            run.reports.push(report);
            run.walk.record(outcome);
            run.current = None;
            tier.jobs
                .progress(job, "devices", Value::Array(run.reports.clone()));
            tier.jobs.progress(job, "identified", Value::Null);
        }
        Segment::Done(final_result(&run, false, None))
    }
}

/// A pause on the run's current device.
fn pause(
    mut run: RunState,
    step: &'static str,
    reason: String,
    question: String,
    identified: Value,
    offers_assign: bool,
) -> Segment {
    if let Some(cur) = run.current.as_mut() {
        cur.reason = Some(reason.clone());
    }
    Segment::Pause(Box::new(PauseParts {
        run,
        step,
        reason,
        question,
        identified,
        offers_assign,
    }))
}

/// One device's report in `progress.devices` and the result.
fn outcome_report(target: &Target, outcome: &Outcome, identified: Option<Value>) -> Value {
    let mut report = device_json(target);
    super::merge(
        &mut report,
        json!({
            "status": outcome.status.key(),
            "detail": outcome.status.detail(),
            "label": outcome.label,
        }),
    );
    if let Some(identified) = identified {
        super::merge(&mut report, json!({ "identified": identified }));
    }
    report
}

/// The job's result: per device what happened and its label, the totals,
/// what the run did not reach, and the summary.
fn final_result(run: &RunState, stopped: bool, reason: Option<String>) -> Value {
    let totals = run.walk.totals();
    let line = run.walk.line();
    let mut not_reached: Vec<&Target> = run.current.iter().map(|c| &c.target).collect();
    not_reached.extend(run.walk.remaining());
    let labels: Vec<&str> = run
        .walk
        .outcomes()
        .iter()
        .filter_map(|o| o.label.as_deref())
        .collect();
    let names = |status: fn(&Status) -> bool| -> Vec<String> {
        run.walk
            .outcomes()
            .iter()
            .filter(|o| status(&o.status))
            .map(|o| o.name.clone())
            .collect()
    };
    let mut summary = format!("Line {line}: ");
    let commissioned = names(|s| matches!(s, Status::Commissioned));
    summary.push_str(&if commissioned.is_empty() {
        "no device was commissioned".to_string()
    } else {
        format!("commissioned {}", commissioned.join(", "))
    });
    let present = names(|s| matches!(s, Status::AlreadyPresent));
    if !present.is_empty() {
        summary.push_str(&format!(
            "; already at their address: {}",
            present.join(", ")
        ));
    }
    let failed = names(|s| matches!(s, Status::Failed(_)));
    if !failed.is_empty() {
        summary.push_str(&format!("; not commissioned: {}", failed.join(", ")));
    }
    if !not_reached.is_empty() {
        let left: Vec<&str> = not_reached.iter().map(|t| t.name.as_str()).collect();
        summary.push_str(&format!(
            "; {} before: {}",
            if stopped { "stopped" } else { "the run ended" },
            left.join(", ")
        ));
    } else if stopped {
        summary.push_str("; stopped");
    }
    summary.push('.');
    if let Some(reason) = &reason {
        summary.push_str(&format!(" The run did not go on: {reason}."));
    }
    let ok = reason.is_none() && !stopped && totals.failed == 0 && not_reached.is_empty();
    let next_step = if totals.commissioned > 0 {
        "Tell the human the summary and read out `labels`, one per device to stick on it. Only \
         addresses were written: push each commissioned device's links and parameters with \
         knx_plan_device and knx_apply_device (a factory-fresh device needs its application \
         loaded first; the plan says so). Call knx_commission_line again for the devices that \
         were not commissioned."
    } else {
        "Tell the human the summary. Call knx_commission_line again for the devices that were \
         not commissioned."
    };
    json!({
        "ok": ok,
        "step": "done",
        "line": line,
        "gateway": run.gateway,
        "stopped": stopped,
        "reason": reason,
        "devices": run.reports,
        "labels": labels,
        "total": run.walk.targets().len(),
        "commissioned": totals.commissioned,
        "present": totals.present,
        "failed": totals.failed,
        "not_reached": not_reached.iter().map(|t| device_json(t)).collect::<Vec<_>>(),
        "summary": summary,
        "next_step": next_step,
    })
}

impl ProgrammingTier {
    /// The commissioning plans and jobs, recovering from a poisoned lock.
    pub(super) fn commissions(&self) -> std::sync::MutexGuard<'_, Commissions> {
        self.commissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
