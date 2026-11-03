//! The server's one job table (issues #289, #746).
//!
//! Every long operation of the server runs as a job of this table, whatever
//! its tier: a client bridge cuts a tool call at 60 s, so a call that may
//! outlast that answers with a job id and the assistant polls
//! `knx_job_status {job}` (registered in every tier). A job carries `step`
//! (what it is doing now), `question` (what the human must do or answer
//! before it can go on, such as "press the programming button", set with
//! [`JobTable::ask`]), `done` and, once done, `result`. The table lives in
//! [`crate::SharedState::jobs`]; the programming tier shares it, and
//! `knx_apply_status` reads it under its old name and payload.
//!
//! The apply job model of the programming tier (issue #289):
//!
//! A client bridge caps one tool call at 60 s, and a secured apply with a
//! restart and a read-back takes longer, so the reply was lost while the
//! write completed on the bus. `knx_apply_device` therefore runs as a job:
//!
//! - **Pre-flight in the call.** The gates, the digest check against a fresh
//!   read, the identity verdict, the audit snapshot and both backups run
//!   before the call answers. A refusal there is the call's reply, and no job
//!   is left behind.
//! - **The write in the server.** The table and parameter writes continue in
//!   a server task. The call waits for them up to the reply wait (default
//!   [`DEFAULT_REPLY_WAIT`] from the start of the call) and then answers with
//!   the full result (`started: false, done: true`) or with `started: true`
//!   and the job id.
//! - **Status and recovery.** `knx_apply_status {job}` reports the step, the
//!   download progress and, once done, the final result. `knx_last_apply
//!   {address}` returns the latest job for a device. Each job is also
//!   recorded as [`RECORD_FILE`] in the audit snapshot's directory under
//!   `<dir>/.bussard/history/`, written when the write starts and again when
//!   it ends, so a server restart does not lose the result; a record still
//!   marked running after a restart reads as `interrupted`.
//! - **One apply at a time.** A second `knx_apply_device` while a job runs
//!   is refused with the running job's id (management calls are sequential,
//!   issue #215).
//! - **A slow pre-flight answers too (issue #332).** When the pre-flight's
//!   device read outlasts the read wait (default [`DEFAULT_REPLY_WAIT`]), the
//!   call answers `started: true` with the job id; a pre-flight that refuses
//!   later ends the job with `result.refused: true`, nothing written.
//!
//! **Plan jobs (issue #332).** Reading a KNX Data Secure System B device's
//! whole parameter memory can outlast the bridge's 60 s too, so
//! `knx_plan_device` runs its read as a job of the same table
//! ([`JobKind::Plan`]): it answers with the plan when the read ends within
//! the read wait, and otherwise with the job id, which `knx_apply_status`
//! polls; the finished job's `result` is the plan exactly as the call would
//! have returned it. Plan and apply jobs share the one slot, so a plan never
//! reads a device while a write runs and the other way round. A second plan
//! of the same device while its plan job runs gets that job back. Plan jobs
//! are not recorded on disk and are not an apply for `knx_last_apply`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bussard_model::IndividualAddress;
use bussard_model::history::HISTORY_DIR;
use serde_json::{Map, Value, json};

/// How long `knx_apply_device` waits for the write to finish, counted from
/// the start of the call, before it answers `started: true`. The client
/// bridge of the owner's setup cuts a call at 60 s (issue #289); a plain
/// apply on the reference installation finishes in well under this, so it
/// still answers with the full result, and a secured one with a restart
/// answers with the job id with a wide margin to the cut.
pub const DEFAULT_REPLY_WAIT: Duration = Duration::from_secs(20);

/// The file a job's record is written to, in the audit snapshot's directory.
pub const RECORD_FILE: &str = "apply-result.json";

/// What a job does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// A write: `knx_apply_device` or `knx_restore_parameters` with a digest.
    Apply,
    /// The device read and diff of `knx_plan_device` (issue #332).
    Plan,
}

impl JobKind {
    /// The kind as `knx_apply_status` reports it.
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Apply => "apply",
            JobKind::Plan => "plan",
        }
    }
}

/// The outcome of claiming the slot for a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanClaim {
    /// A new plan job with this id; the caller starts its work.
    New(String),
    /// A plan job of the same device is already running under this id; the
    /// caller waits for it instead of reading the device again.
    Running(String),
}

/// A job's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobState {
    /// The pre-flight passed and the write is running.
    Running,
    /// The write ended (verified or not); the result is final.
    Done,
}

/// One job of this session.
struct Job {
    /// Apply or plan.
    kind: JobKind,
    /// The device written or read.
    address: IndividualAddress,
    /// When the call that started the job came in.
    started_at: SystemTime,
    /// When the write ended.
    finished_at: Option<SystemTime>,
    /// Monotonic start, for the elapsed time.
    began: Instant,
    /// The lifecycle state.
    state: JobState,
    /// What the job is doing now, in words.
    step: String,
    /// What the human must do or answer before the job goes on, if anything
    /// (issue #746): "press the programming button on the new device".
    question: Option<String>,
    /// Progress counters (download step, octets written, tables outcome).
    progress: Map<String, Value>,
    /// What the pre-flight established (gateway, backups, snapshot).
    context: Value,
    /// The final result once done.
    result: Option<Value>,
    /// Where the record is persisted, when there is an audit snapshot.
    record: Option<PathBuf>,
    /// Flips to `true` when the job is done.
    done: tokio::sync::watch::Sender<bool>,
}

/// The table behind the lock.
#[derive(Default)]
struct Inner {
    /// The job writing now, if any.
    running: Option<String>,
    /// Every job this session started, by id.
    jobs: HashMap<String, Job>,
    /// The latest job per device.
    last: HashMap<IndividualAddress, String>,
}

/// The apply jobs of one server.
pub struct JobTable {
    /// The jobs.
    inner: std::sync::Mutex<Inner>,
    /// The reply wait in milliseconds (see [`DEFAULT_REPLY_WAIT`]).
    reply_wait_ms: AtomicU64,
    /// The read wait in milliseconds: how long a call waits for a device
    /// read (a plan, an apply's pre-flight) before it answers with the job
    /// (issue #332; default [`DEFAULT_REPLY_WAIT`]).
    read_wait_ms: AtomicU64,
}

impl Default for JobTable {
    fn default() -> Self {
        JobTable {
            inner: std::sync::Mutex::new(Inner::default()),
            reply_wait_ms: AtomicU64::new(millis(DEFAULT_REPLY_WAIT)),
            read_wait_ms: AtomicU64::new(millis(DEFAULT_REPLY_WAIT)),
        }
    }
}

/// A duration in whole milliseconds, saturating.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl JobTable {
    /// An empty table with the default reply wait.
    pub fn new() -> Self {
        Self::default()
    }

    /// The table, recovering from a poisoned lock (it holds plain data).
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How long `knx_apply_device` waits for the write before it answers.
    pub fn reply_wait(&self) -> Duration {
        Duration::from_millis(self.reply_wait_ms.load(Ordering::Relaxed))
    }

    /// Sets the reply wait (tests use zero to always get `started`).
    pub fn set_reply_wait(&self, wait: Duration) {
        self.reply_wait_ms.store(millis(wait), Ordering::Relaxed);
    }

    /// How long a call waits for a device read (a plan, an apply's
    /// pre-flight) before it answers with the job id.
    pub fn read_wait(&self) -> Duration {
        Duration::from_millis(self.read_wait_ms.load(Ordering::Relaxed))
    }

    /// Sets the read wait (tests shrink it to turn a slow plan into a job).
    pub fn set_read_wait(&self, wait: Duration) {
        self.read_wait_ms.store(millis(wait), Ordering::Relaxed);
    }

    /// Why a `wanting` job cannot start now: the running job, named with its
    /// id and what to poll. `None` when the slot is free.
    pub fn busy(&self, wanting: JobKind) -> Option<String> {
        busy_message(&self.inner(), wanting)
    }

    /// The job writing now and its device, if any.
    pub fn running(&self) -> Option<(String, IndividualAddress)> {
        let inner = self.inner();
        let id = inner.running.clone()?;
        let address = inner.jobs.get(&id)?.address;
        Some((id, address))
    }

    /// Claims the one apply slot for `address` and returns the new job's id,
    /// or the refusal naming the job that runs.
    pub fn claim(&self, address: IndividualAddress) -> Result<String, String> {
        let mut inner = self.inner();
        if let Some(refusal) = busy_message(&inner, JobKind::Apply) {
            return Err(refusal);
        }
        Ok(insert(&mut inner, JobKind::Apply, address))
    }

    /// Claims the slot for a plan of `address` (issue #332): a new job, the
    /// running plan job of the same device, or the refusal naming the job
    /// that runs. A new plan drops the finished plan jobs of the device (it
    /// supersedes them).
    pub fn claim_plan(&self, address: IndividualAddress) -> Result<PlanClaim, String> {
        let mut inner = self.inner();
        if let Some(id) = &inner.running
            && let Some(job) = inner.jobs.get(id)
            && job.kind == JobKind::Plan
            && job.address == address
        {
            return Ok(PlanClaim::Running(id.clone()));
        }
        if let Some(refusal) = busy_message(&inner, JobKind::Plan) {
            return Err(refusal);
        }
        // Inserted before the prune, so the new id never reuses a dropped one.
        let id = insert(&mut inner, JobKind::Plan, address);
        inner.jobs.retain(|_, job| {
            !(job.kind == JobKind::Plan && job.address == address && job.state == JobState::Done)
        });
        Ok(PlanClaim::New(id))
    }

    /// Ends a job whose pre-flight refused: nothing was written. The job
    /// stays done with the refusal as its result, for a caller that already
    /// answered `started` (issue #332); one that gets the refusal in time
    /// drops the job with [`JobTable::abandon`].
    pub fn refuse(&self, id: &str, reason: &str) {
        let mut inner = self.inner();
        if inner.running.as_deref() == Some(id) {
            inner.running = None;
        }
        let Some(job) = inner.jobs.get_mut(id) else {
            return;
        };
        job.state = JobState::Done;
        job.finished_at = Some(SystemTime::now());
        job.step = "refused".to_string();
        job.question = None;
        job.result = Some(json!({
            "ok": false,
            "refused": true,
            "address": job.address.to_string(),
            "reason": reason,
        }));
        job.done.send_replace(true);
    }
}

/// The refusal for a `wanting` job while another runs, or `None`.
fn busy_message(inner: &Inner, wanting: JobKind) -> Option<String> {
    let id = inner.running.as_ref()?;
    let job = inner.jobs.get(id)?;
    let device = job.address;
    Some(match (job.kind, wanting) {
        (JobKind::Apply, JobKind::Apply) => format!(
            "an apply is already running on this server: job {id} for {device}; one apply at a \
             time. Call knx_apply_status with job {id} until it is done, then plan again"
        ),
        (JobKind::Apply, JobKind::Plan) => format!(
            "an apply is running on this server (job {id} for {device}); call \
             knx_apply_status with job {id} until it is done, then plan again"
        ),
        (JobKind::Plan, _) => format!(
            "a plan is already running on this server: job {id} reads {device}; one bus job at \
             a time. Call knx_apply_status with job {id} until it is done, then call again"
        ),
    })
}

/// Inserts a new running job and marks it as the one in the slot.
fn insert(inner: &mut Inner, kind: JobKind, address: IndividualAddress) -> String {
    let now = SystemTime::now();
    let stamp = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let prefix = kind.as_str();
    let mut id = format!("{prefix}-{stamp}-{address}");
    let mut seq = 1;
    while inner.jobs.contains_key(&id) {
        seq += 1;
        id = format!("{prefix}-{stamp}-{address}-{seq}");
    }
    let (done, _) = tokio::sync::watch::channel(false);
    let step = match kind {
        JobKind::Apply => "pre-flight: reading the device and checking the plan",
        JobKind::Plan => "reading the device",
    };
    inner.jobs.insert(
        id.clone(),
        Job {
            kind,
            address,
            started_at: now,
            finished_at: None,
            began: Instant::now(),
            state: JobState::Running,
            step: step.to_string(),
            question: None,
            progress: Map::new(),
            context: Value::Null,
            result: None,
            record: None,
            done,
        },
    );
    inner.running = Some(id.clone());
    id
}

impl JobTable {
    /// Drops a job: one whose pre-flight refusal is the call's reply
    /// (nothing was written), or a plan the call answered with inline.
    pub fn abandon(&self, id: &str) {
        let mut inner = self.inner();
        inner.jobs.remove(id);
        if inner.running.as_deref() == Some(id) {
            inner.running = None;
        }
    }

    /// The pre-flight passed: records what it established (`context`: the
    /// gateway, the backups, the snapshot) and persists the running record to
    /// `record` when there is one.
    pub fn started(&self, id: &str, context: Value, record: Option<PathBuf>) {
        let status = {
            let mut inner = self.inner();
            let Some(job) = inner.jobs.get_mut(id) else {
                return;
            };
            job.context = context;
            job.record = record;
            job.step = "writing".to_string();
            let address = job.address;
            let status = job.status(id);
            inner.last.insert(address, id.to_string());
            status
        };
        persist(&status);
    }

    /// Sets the job's current step.
    pub fn step(&self, id: &str, step: impl Into<String>) {
        if let Some(job) = self.inner().jobs.get_mut(id) {
            job.step = step.into();
        }
    }

    /// Sets or clears the question the job waits on: what the human must do
    /// or answer before it goes on (issue #746). `knx_job_status` reports it
    /// as `question`; the assistant relays it to the human and keeps polling.
    pub fn ask(&self, id: &str, question: Option<String>) {
        if let Some(job) = self.inner().jobs.get_mut(id) {
            job.question = question;
        }
    }

    /// Sets one progress counter.
    pub fn progress(&self, id: &str, key: &str, value: Value) {
        if let Some(job) = self.inner().jobs.get_mut(id) {
            job.progress.insert(key.to_string(), value);
        }
    }

    /// The write ended with `result`: the job is done, the slot is free, and
    /// the final record is persisted.
    pub fn finish(&self, id: &str, result: Value) {
        let status = {
            let mut inner = self.inner();
            if inner.running.as_deref() == Some(id) {
                inner.running = None;
            }
            let Some(job) = inner.jobs.get_mut(id) else {
                return;
            };
            job.state = JobState::Done;
            job.finished_at = Some(SystemTime::now());
            job.step = "done".to_string();
            job.question = None;
            job.result = Some(result);
            job.done.send_replace(true);
            let (address, kind) = (job.address, job.kind);
            let status = job.status(id);
            if kind == JobKind::Apply {
                inner.last.insert(address, id.to_string());
            }
            status
        };
        persist(&status);
    }

    /// Waits up to `wait` for the job to finish; `true` when it is done.
    pub async fn wait(&self, id: &str, wait: Duration) -> bool {
        let receiver = {
            let inner = self.inner();
            let Some(job) = inner.jobs.get(id) else {
                return false;
            };
            if job.state == JobState::Done {
                return true;
            }
            job.done.subscribe()
        };
        let mut receiver = receiver;
        matches!(
            tokio::time::timeout(wait, receiver.wait_for(|done| *done)).await,
            Ok(Ok(_))
        )
    }

    /// The job's status, from this session or from its record under `dir`'s
    /// history (`None` when neither knows it).
    pub fn status(&self, dir: &Path, id: &str) -> Option<Value> {
        if let Some(job) = self.inner().jobs.get(id) {
            return Some(job.status(id));
        }
        records(dir)
            .into_iter()
            .find(|record| record["job"] == id)
            .map(restored)
    }

    /// The latest job for `address`: this session's, else the newest record
    /// under `dir`'s history.
    pub fn last(&self, dir: &Path, address: IndividualAddress) -> Option<Value> {
        {
            let inner = self.inner();
            if let Some(job) = inner
                .last
                .get(&address)
                .and_then(|id| inner.jobs.get(id).map(|job| job.status(id)))
            {
                return Some(job);
            }
        }
        let wanted = address.to_string();
        records(dir)
            .into_iter()
            .find(|record| record["address"] == wanted.as_str())
            .map(restored)
    }

    /// The final result of a job of this session, once done.
    pub fn result(&self, id: &str) -> Option<Value> {
        self.inner().jobs.get(id).and_then(|job| job.result.clone())
    }
}

impl Job {
    /// The job as `knx_apply_status` reports it. `question` is there only
    /// while the job waits on one, so an apply's payload is unchanged.
    fn status(&self, id: &str) -> Value {
        let state = match self.state {
            JobState::Running => "running",
            JobState::Done => "done",
        };
        let elapsed = match self.finished_at {
            Some(end) => end
                .duration_since(self.started_at)
                .unwrap_or_default()
                .as_secs_f64(),
            None => self.began.elapsed().as_secs_f64(),
        };
        let mut status = json!({
            "job": id,
            "kind": self.kind.as_str(),
            "address": self.address.to_string(),
            "state": state,
            "done": self.state == JobState::Done,
            "started_at": bussard_monitor::timefmt::to_rfc3339(self.started_at),
            "finished_at": self.finished_at.map(bussard_monitor::timefmt::to_rfc3339),
            "elapsed_s": (elapsed * 10.0).round() / 10.0,
            "step": self.step,
            "progress": Value::Object(self.progress.clone()),
            "result": self.result,
            "record": self.record.as_ref().map(|p| p.display().to_string()),
        });
        if let (Some(question), Some(map)) = (&self.question, status.as_object_mut()) {
            map.insert("question".to_string(), json!(question));
        }
        if let (Some(status), Value::Object(context)) = (status.as_object_mut(), &self.context) {
            for (key, value) in context {
                status.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        status["next_step"] = json!(next_step(&status));
        status
    }
}

/// Writes a job's status to its record file (temp file, then rename, so a
/// reader never sees half a record). A failure is logged: the job itself
/// goes on, and its session status stays available.
fn persist(status: &Value) {
    let Some(path) = status["record"].as_str().map(PathBuf::from) else {
        return;
    };
    let mut record = status.clone();
    if let Some(map) = record.as_object_mut() {
        map.remove("next_step");
    }
    let tmp = path.with_extension("json.tmp");
    let written = serde_json::to_vec_pretty(&record)
        .map_err(std::io::Error::other)
        .and_then(|bytes| std::fs::write(&tmp, bytes))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(err) = written {
        tracing::warn!(
            "could not record the apply job at {}: {err}",
            path.display()
        );
    }
}

/// Every job record under `dir`'s history, newest snapshot first.
fn records(dir: &Path) -> Vec<Value> {
    let history = dir.join(HISTORY_DIR);
    let Ok(entries) = std::fs::read_dir(&history) else {
        return Vec::new();
    };
    let mut snapshots: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join(RECORD_FILE).is_file())
        .collect();
    snapshots.sort();
    snapshots.reverse();
    snapshots
        .into_iter()
        .filter_map(|p| std::fs::read(p.join(RECORD_FILE)).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .collect()
}

/// A record read back from disk: a job no running server holds that is
/// still marked running was cut off by a server stop (`interrupted`).
fn restored(mut record: Value) -> Value {
    if record["state"] == "running" {
        record["state"] = json!("interrupted");
        record["step"] = json!("interrupted: the server stopped before the write ended");
    }
    record["from_record"] = json!(true);
    record["next_step"] = json!(next_step(&record));
    record
}

/// What the assistant does next with a job in `status`.
fn next_step(status: &Value) -> String {
    let job = status["job"].as_str().unwrap_or_default();
    let address = status["address"].as_str().unwrap_or_default();
    if status["kind"] == "plan" {
        return match status["state"].as_str() {
            Some("running") => format!(
                "Still reading {address} for the plan. Call knx_apply_status with job {job} \
                 again in a few seconds; the read continues in the server whether or not you \
                 poll. Nothing is written."
            ),
            _ if status["result"]["refused"] == true => {
                format!("The plan for {address} was refused: tell the human result.reason.")
            }
            _ => format!(
                "The plan for {address} is ready: `result` is exactly what knx_plan_device \
                 returns. Follow result.next_step: show the human result.sentences in full and \
                 ask result.question; knx_apply_device takes result.plan_digest only after an \
                 explicit yes."
            ),
        };
    }
    match status["state"].as_str() {
        Some("running") => format!(
            "Still working on {address} ({}). Call knx_apply_status with job {job} again in a \
             few seconds; the job continues in the server whether or not you poll.",
            status["step"].as_str().unwrap_or("writing")
        ),
        _ if status["result"]["refused"] == true => format!(
            "Job {job} was refused in its pre-flight; nothing was written to {address}. Tell \
             the human result.reason, then call knx_plan_device for {address} and ask again."
        ),
        Some("interrupted") => format!(
            "The server stopped while job {job} was writing {address}; the device may be partly \
             written. The pre-apply backups are named in this record. Call knx_plan_device for \
             {address}, show the new plan to the human and ask again."
        ),
        _ if status["result"]["ok"] == true => format!(
            "Done: tell the human the outcome of job {job} on {address} (result.verified, \
             result.readback.compared, result.parameters) and the backup paths. A new \
             knx_plan_device for {address} reports nothing to do."
        ),
        _ => format!(
            "Job {job} on {address} did not verify: tell the human result.reason or \
             result.detail, what result.readback.leftovers still differs, and \
             result.recovery, and the backup paths."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ia() -> Result<IndividualAddress, String> {
        "1.1.4".parse().map_err(|_| "address".to_string())
    }

    #[test]
    fn test_claim_refuses_a_second_apply_with_the_running_job() -> Result<(), String> {
        let jobs = JobTable::new();
        let first = jobs.claim(ia()?)?;
        let refused = jobs.claim(ia()?).err().ok_or("second claim must refuse")?;
        assert!(refused.contains(&first), "{refused}");
        jobs.abandon(&first);
        assert!(jobs.running().is_none());
        let second = jobs.claim(ia()?)?;
        jobs.finish(&second, json!({"ok": true}));
        assert!(jobs.running().is_none());
        Ok(())
    }

    #[test]
    fn test_record_survives_a_restart_and_reads_interrupted_while_running() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let snapshot = dir.path().join(HISTORY_DIR).join("20261001T183000Z-001");
        std::fs::create_dir_all(&snapshot).map_err(|e| e.to_string())?;
        let record = snapshot.join(RECORD_FILE);

        let jobs = JobTable::new();
        let id = jobs.claim(ia()?)?;
        jobs.started(&id, json!({"backup": "b.json"}), Some(record.clone()));
        // A new server (empty session) reads the running record back.
        let fresh = JobTable::new();
        let cut = fresh
            .last(dir.path(), ia()?)
            .ok_or("no record after restart")?;
        assert_eq!(cut["state"], "interrupted", "{cut}");
        assert_eq!(cut["backup"], "b.json", "{cut}");

        jobs.finish(&id, json!({"ok": true, "verified": true}));
        let done = fresh.status(dir.path(), &id).ok_or("no record by job")?;
        assert_eq!(done["state"], "done", "{done}");
        assert_eq!(done["result"]["verified"], true, "{done}");
        assert_eq!(done["from_record"], true, "{done}");
        Ok(())
    }

    #[test]
    fn test_claim_plan_joins_the_same_device_and_shares_the_slot_with_apply() -> Result<(), String>
    {
        let jobs = JobTable::new();
        let other: IndividualAddress = "1.1.5".parse().map_err(|_| "address".to_string())?;
        let PlanClaim::New(plan) = jobs.claim_plan(ia()?)? else {
            return Err("the first plan must be new".into());
        };
        assert!(plan.starts_with("plan-"), "{plan}");
        assert_eq!(jobs.claim_plan(ia()?)?, PlanClaim::Running(plan.clone()));
        let refused = jobs
            .claim_plan(other)
            .err()
            .ok_or("another device must wait")?;
        assert!(refused.contains(&plan), "{refused}");
        let refused = jobs.claim(ia()?).err().ok_or("an apply must wait")?;
        assert!(refused.contains(&plan), "{refused}");
        jobs.finish(&plan, json!({"ok": true}));
        assert!(jobs.last(Path::new("/nonexistent"), ia()?).is_none());

        let apply = jobs.claim(ia()?)?;
        let refused = jobs.claim_plan(ia()?).err().ok_or("a plan must wait")?;
        assert!(refused.contains(&apply), "{refused}");
        jobs.refuse(&apply, "the device moved");
        let status = jobs
            .status(Path::new("/nonexistent"), &apply)
            .ok_or("the refused job stays")?;
        assert_eq!(status["result"]["refused"], true, "{status}");
        assert!(jobs.running().is_none());
        // A new plan of the device supersedes its finished plan job.
        assert!(matches!(jobs.claim_plan(ia()?)?, PlanClaim::New(_)));
        assert!(jobs.status(Path::new("/nonexistent"), &plan).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_returns_when_the_job_finishes() -> Result<(), String> {
        let jobs = std::sync::Arc::new(JobTable::new());
        let id = jobs.claim(ia()?)?;
        assert!(!jobs.wait(&id, Duration::from_millis(10)).await);
        let finisher = std::sync::Arc::clone(&jobs);
        let job = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            finisher.finish(&job, json!({"ok": true}));
        });
        assert!(jobs.wait(&id, Duration::from_secs(5)).await);
        assert_eq!(jobs.result(&id), Some(json!({"ok": true})));
        Ok(())
    }
}
