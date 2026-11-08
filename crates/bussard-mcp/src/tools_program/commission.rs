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

use bussard_model::Model;
use bussard_model::history::SnapshotReason;
use bussard_service::commission::{
    CommissionDevice, CommissionReadback, CommissionReport, CommissionTarget, IdentifiedDevice,
    LineRun, Next, OrderCheck, Outcome, Target, assign_pressed, identify_pressed, probe_line,
};
use bussard_service::line::WalkEvent;
use bussard_service::observer::Collected;
use bussard_service::program::assign::{AssignFlow, Stop as FlowStop};
use bussard_service::program::plan::Fingerprint;
use bussard_service::report::{Approval, Report};
use serde_json::Value;

use super::{BussardMcp, ProgrammingTier, chain};
use crate::jobs::{JobKind, JobSink, Subject};

/// The answers a paused job takes.
const ANSWERS: [&str; 4] = ["retry", "skip", "stop", "assign"];

/// The session state of `knx_commission_line`: the jobs running or waiting.
#[derive(Default)]
pub(super) struct Commissions {
    /// Jobs of this session, by id.
    jobs: HashMap<String, JobEntry>,
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
    reports: Vec<CommissionDevice>,
}

/// How a stretch of the run ended.
enum Segment {
    /// The run is over; the job's result.
    Done(Box<CommissionReport>),
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
    identified: Option<IdentifiedDevice>,
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
        None => " (no order number in your project)".to_string(),
    };
    format!("{}{room}{order}", target.name)
}

/// The plan digest: the line, the gateway and every model device on it
/// (address, name, product, place).
fn plan_digest(line: &str, gateway: &str, targets: &[Target]) -> String {
    let mut h = Fingerprint::new(b"bussard-commission-line-v1")
        .put(line)
        .put(gateway);
    for t in targets {
        h = h.address(t.address).put(&t.name);
        for field in [&t.order_number, &t.manufacturer, &t.floor, &t.room] {
            h = h.put(field.as_deref().unwrap_or(""));
        }
    }
    format!("sha256:{}", h.hex())
}

/// The line's run over `model`, or the refusal for an empty line.
fn line_run(model: &Model, line: &str) -> Result<LineRun, String> {
    let (area, line_no) = bussard_service::line::parse_line(line).map_err(|e| e.to_string())?;
    let run = LineRun::new(model, area, line_no);
    if run.targets().is_empty() {
        return Err(format!(
            "your project has no devices on line {}; nothing to commission",
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
        tier.commission_plans
            .insert(digest.clone(), format!("line {line}"), ());
        let names: Vec<String> = targets.iter().map(who).collect();
        let n = targets.len();
        let sentences = vec![
            format!(
                "Line {line} has {n} device(s) in your project: {}.",
                names.join("; ")
            ),
            "First bussard checks which of them already answer at their address; those are \
             skipped."
                .to_string(),
            "Then, one device at a time, the human presses its programming button. bussard reads \
             the device's order number and, when it is the product your project expects, writes the \
             address, reads the device back at it and gives the label text, without asking \
             again."
                .to_string(),
            "A different product, no device, two devices in programming mode, or a device your \
             project has no order number for pauses the run until the human says retry, skip or \
             stop. Only addresses are written: no links, parameters or application programs."
                .to_string(),
        ];
        let plan = CommissionPlan {
            ok: true,
            step: "plan",
            line: line.to_string(),
            gateway: gateway.to_string(),
            devices: targets.iter().map(CommissionTarget::of).collect(),
            total: n,
            sentences,
            approval: Approval {
                question: Some(format!(
                    "Commission the {n} device(s) of line {line} via {gateway}? One yes covers \
                     every device that turns out to be the product your project expects. Say yes."
                )),
                plan_digest: Some(digest),
                expires_at: Some(
                    tier.commission_plans
                        .expires_at(std::time::SystemTime::now()),
                ),
            },
        };
        crate::reply::report(&plan, &self.model())
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
        let again = format!(
            "call knx_commission_line with line {line} for a new one. Nothing was written."
        );
        tier.commission_plans
            .fresh(given, format!("line {line}"), "plan", again)?;
        if given != fresh {
            return Err(format!(
                "the devices in your project on line {line} or the gateway changed since the plan. Call \
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
        let job = tier
            .jobs
            .claim(JobKind::Commission, Subject::Line(&line))?
            .id;
        let stop = Arc::new(Stop::default());
        tier.commission_plans.retire(given);
        {
            let mut c = tier.commissions();
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
        Ok(crate::reply::started_with(
            &job,
            "checking which devices already answer",
            CommissionStarted { line, gateway },
            None,
            format!(
                "The run is job {job}. Call knx_job_status with job {job} every few seconds. \
                 While it waits for a button its `question` names the device: relay it to the \
                 human word for word. When `waiting` is set, tell the human waiting.reason and \
                 ask `question`, then pass the answer as knx_commission_line {{job, answer}}. \
                 The human can stop the run at any time: answer \"stop\"."
            ),
        ))
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
                let mut out = serde_json::to_value(Answered {
                    ok: true,
                    job,
                    stopping: Some(true),
                    resumed: None,
                    answer: None,
                    step: None,
                })
                .unwrap_or_default();
                crate::reply::envelope(
                    &mut out,
                    None,
                    Some(format!(
                        "The run stops at once while it waits for a button, else after the \
                         device it is on (a write in progress is never cut). Call \
                         knx_job_status with job {job} until `done` is true and tell the human \
                         result.summary."
                    )),
                );
                return Ok(out);
            }
            return Err(format!(
                "job {job} is not waiting for an answer; call knx_job_status with job {job} and \
                 answer its question when `waiting` is set"
            ));
        };
        if answer == "stop" {
            tier.commissions().jobs.remove(job);
            let result = crate::reply::report(
                final_result(&paused.run, true, None).as_ref(),
                &self.model(),
            );
            tier.jobs.finish(job, &result);
            let mut out = result;
            if let Some(map) = out.as_object_mut() {
                map.insert("job".to_string(), Value::String(job.to_string()));
                map.insert("done".to_string(), Value::Bool(true));
            }
            return Ok(out);
        }
        if answer == "assign" && !paused.offers_assign {
            self.put_back(tier, job, paused);
            return Err(
                "`assign` answers only a device your project has no order number for; this question \
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
                .push(CommissionDevice::of(&cur.target, &outcome));
            run.walk.record(outcome);
            tier.jobs
                .progress(job, |p| p.devices = devices_json(&run.reports));
        }
        self.spawn_commission(job.to_string(), run, stop);
        let mut out = serde_json::to_value(Answered {
            ok: true,
            job,
            stopping: None,
            resumed: Some(true),
            answer: Some(&answer),
            step: Some(step),
        })
        .unwrap_or_default();
        crate::reply::envelope(
            &mut out,
            None,
            Some(format!(
                "The run goes on as job {job}. Call knx_job_status with job {job} every few \
                 seconds and relay its `question` to the human word for word."
            )),
        );
        Ok(out)
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
                    tier.jobs
                        .finish(&id, crate::reply::report(result.as_ref(), &me.model()));
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
                    let device = run
                        .current
                        .as_ref()
                        .map(|c| CommissionTarget::of(&c.target));
                    let answers: &[&str] = if offers_assign {
                        &["assign", "retry", "skip", "stop"]
                    } else {
                        &["retry", "skip", "stop"]
                    };
                    let detail = Waiting {
                        waiting: WaitingFor {
                            device,
                            reason,
                            identified,
                            answers,
                        },
                    };
                    tier.jobs
                        .progress(&id, |p| p.devices = devices_json(&run.reports));
                    if let Some(entry) = tier.commissions().jobs.get_mut(&id) {
                        entry.paused = Some(Paused { run, offers_assign });
                    }
                    tier.jobs.pause(&id, step, question, None, detail);
                }
            }
        });
        if let Some(tier) = self.state().programming.as_ref() {
            tier.jobs.watch(&job, "commission", worker);
        }
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
                    jobs.progress(job, |p| p.checking = Some(address.to_string()));
                }
            };
            let verdicts = probe_line(&service, source, &targets, &mut on_probe).await;
            run.walk.set_verdicts(verdicts);
            run.probed = true;
            tier.jobs.progress(job, |p| {
                p.pending = serde_json::to_value(run.walk.pending()).ok()
            });
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
                            run.reports.push(CommissionDevice::of(target, &outcome));
                        }
                        tier.jobs
                            .progress(job, |p| p.devices = devices_json(&run.reports));
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
            tier.jobs.progress(job, |p| {
                p.device = serde_json::to_value(OnDevice {
                    position: cur.position,
                    total: cur.total,
                    device: CommissionTarget::of(target),
                })
                .ok();
            });
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
                    return pause(run, "press_button", reason, question, None, false);
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
                    return pause(run, "press_button", reason, question, None, false);
                }
                Err(e) => {
                    let reason = format!(
                        "The programming-mode broadcast failed ({}). Nothing was written.",
                        chain(&e)
                    );
                    let question = retry_question(target, "Check the bus connection.");
                    return pause(run, "press_button", reason, question, None, false);
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
                    return pause(run, "identified", reason, question, None, false);
                }
            };
            let ident = IdentifiedDevice::of(&identified);
            tier.jobs
                .progress(job, |p| p.identified = serde_json::to_value(&ident).ok());
            match &identified.check {
                OrderCheck::Matches => {}
                OrderCheck::NoModelNumber if cur.accept_unchecked => {}
                OrderCheck::NoModelNumber => {
                    let reason = format!(
                        "Your project has no order number for {}, so the pressed device (order \
                         number {}) cannot be checked against it. Nothing was written.",
                        target.name,
                        identified.verified.order.as_deref().unwrap_or("unknown")
                    );
                    let question = format!(
                        "Say assign to give {}'s address to the pressed device anyway, retry \
                         after pressing another device, skip to leave {} for later, or stop.",
                        target.name, target.name
                    );
                    return pause(run, "identified", reason, question, Some(ident), true);
                }
                OrderCheck::Refused(_) => {
                    let expected = target.order_number.as_deref().unwrap_or_default();
                    let reason = match identified.verified.order.as_deref() {
                        Some(read) => format!(
                            "The pressed device is a {read}, but your project expects a {expected} \
                             for {}. Nothing was written.",
                            target.name
                        ),
                        None => format!(
                            "The pressed device did not report an order number, so it cannot be \
                             checked against the {expected} your project expects for {}. Nothing \
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
                    return pause(run, "identified", reason, question, Some(ident), false);
                }
            }

            // assigned
            let (outcome, readback) =
                match assign_pressed(&flow, &state.dir, target, &identified, &mut observer).await {
                    Ok(labelled) => {
                        let readback = CommissionReadback::of(&labelled, &identified, target);
                        (Outcome::commissioned(target, labelled.label), readback)
                    }
                    Err(e) => (
                        Outcome::failed(target, chain(&e)),
                        CommissionReadback::default(),
                    ),
                };
            let report = CommissionDevice::assigned(target, &outcome, &identified, readback);
            run.reports.push(report);
            run.walk.record(outcome);
            run.current = None;
            tier.jobs
                .progress(job, |p| p.devices = devices_json(&run.reports));
            tier.jobs.progress(job, |p| p.identified = None);
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
    identified: Option<IdentifiedDevice>,
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

/// The job's result: per device what happened and its label, the totals,
/// what the run did not reach, and the summary.
fn final_result(run: &RunState, stopped: bool, reason: Option<String>) -> Box<CommissionReport> {
    Box::new(CommissionReport::new(
        &run.walk,
        &run.gateway,
        run.reports.clone(),
        run.current.as_ref().map(|c| &c.target),
        stopped,
        reason,
    ))
}

/// The device rows as the job's progress holds them.
fn devices_json(reports: &[CommissionDevice]) -> Option<Vec<Value>> {
    reports
        .iter()
        .map(|r| serde_json::to_value(r).ok())
        .collect()
}

/// The plan of commissioning a line: the model's devices, the sentences and
/// the question.
#[derive(serde::Serialize)]
struct CommissionPlan {
    /// Always `true`.
    ok: bool,
    /// Always `plan`.
    step: &'static str,
    /// The line.
    line: String,
    /// The resolved gateway.
    gateway: String,
    /// The model's devices on it.
    devices: Vec<CommissionTarget>,
    /// How many.
    total: usize,
    /// The plan in words.
    sentences: Vec<String>,
    /// The question and the digest.
    #[serde(flatten)]
    approval: Approval,
}

impl Report for CommissionPlan {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &Model) -> Option<String> {
        Some(format!(
            "Commissioning line {} gives its {} device(s) their addresses, one press of a \
             programming button at a time.",
            self.line, self.total
        ))
    }

    fn next_step(&self) -> Option<String> {
        Some(
            "Say the summary, show the human the sentences in full and ask the question. Only \
             after an explicit yes call knx_commission_line with line, plan_digest and yes: \
             true. Nothing is written before that."
                .to_string(),
        )
    }
}

/// What the start of a commissioning run established.
#[derive(serde::Serialize)]
struct CommissionStarted {
    /// The line.
    line: String,
    /// The resolved gateway.
    gateway: String,
}

/// The answer to the human's word for a paused run.
#[derive(serde::Serialize)]
struct Answered<'a> {
    /// Always `true`.
    ok: bool,
    /// The job.
    job: &'a str,
    /// `stop` while the run works: it stops after the device it is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopping: Option<bool>,
    /// The run goes on.
    #[serde(skip_serializing_if = "Option::is_none")]
    resumed: Option<bool>,
    /// The answer taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<&'a str>,
    /// What the run does now.
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<&'a str>,
}

/// What a paused run reports at the top of its status.
#[derive(serde::Serialize)]
struct Waiting<'a> {
    /// The pause.
    waiting: WaitingFor<'a>,
}

/// Why a run waits for the human's word, and the answers it takes.
#[derive(serde::Serialize)]
struct WaitingFor<'a> {
    /// The device it is on.
    device: Option<CommissionTarget>,
    /// Why, ending with what was written (nothing).
    reason: String,
    /// The identification, when the device was read.
    identified: Option<IdentifiedDevice>,
    /// The answers the question takes.
    answers: &'a [&'a str],
}

/// The device a run waits for and where it is in the walk.
#[derive(serde::Serialize)]
struct OnDevice {
    /// Its 1-based position.
    position: usize,
    /// How many devices the line has.
    total: usize,
    /// The device.
    device: CommissionTarget,
}

impl ProgrammingTier {
    /// The commissioning plans and jobs, recovering from a poisoned lock.
    pub(super) fn commissions(&self) -> std::sync::MutexGuard<'_, Commissions> {
        self.commissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
