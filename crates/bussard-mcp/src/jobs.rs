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
//!
//! **Scan jobs (issue #747).** `knx_find_devices` sweeps a line, which takes
//! seconds per address, so it runs as a job of the same table
//! ([`JobKind::Scan`], claimed with [`JobTable::claim`]). A scan has no
//! device address: its job carries `address: null` and `line`, and reports
//! the addresses probed and the devices found so far in `progress`. It takes
//! the one slot, so a scan never runs while a plan or an apply reads or
//! writes a device.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bussard_model::IndividualAddress;
use bussard_model::Model;
use bussard_model::history::HISTORY_DIR;
use bussard_model::text::capitalize;
use bussard_service::download::Progress;
use bussard_service::observer::{Answer, Event, ProgressSink, Prompt, Question, Step};
use bussard_service::program::outcome::{OutcomeHead, Verdict};
use bussard_service::report::{Refusal, is_false, subject_phrase};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    /// A write: `knx_apply_device` or `knx_restore_parameters` with a digest.
    /// A record that names no kind is one.
    #[default]
    Apply,
    /// The device read and diff of `knx_plan_device` (issue #332).
    Plan,
    /// A read-only bus job of the default tier: the line sweep of
    /// `knx_reconstruct_device` (issue #748).
    Read,
    /// The line scan of `knx_find_devices` (issue #747).
    Scan,
    /// Adding a device: the wait for the programming button, then, after
    /// the human's yes, the address write and the read-back of
    /// `knx_add_device` (issue #749).
    Add,
    /// Replacing a dead device: the check that it is gone and the wait for
    /// the replacement's programming button, then, after the human's yes,
    /// the address, the flash and the apply with their read-backs and the
    /// record of `knx_replace_device` (issue #751).
    Replace,
    /// Commissioning a line: per device of the model, the wait for the
    /// programming button, the identification against the model and the
    /// address write with its read-back, of `knx_commission_line` (issue
    /// #753).
    Commission,
}

impl JobKind {
    /// The kind as `knx_apply_status` reports it.
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Apply => "apply",
            JobKind::Plan => "plan",
            JobKind::Read => "read",
            JobKind::Scan => "scan",
            JobKind::Add => "add",
            JobKind::Replace => "replace",
            JobKind::Commission => "commission",
        }
    }
}

/// What a job is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject<'a> {
    /// One device (a line job of the programming tier names the line
    /// coupler's address).
    Device(IndividualAddress),
    /// A line (`"1.1"`): the job has no device address.
    Line(&'a str),
    /// The bus: a device not addressed yet.
    Bus,
}

/// A claimed slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The job's id.
    pub id: String,
    /// A plan job of the same device was already running: the caller waits
    /// for it instead of reading the device again (issue #332).
    pub joined: bool,
}

/// A job's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    /// The pre-flight passed and the write is running.
    Running,
    /// The write ended (verified or not); the result is final.
    Done,
    /// A record still marked running after a server restart: the write was
    /// cut off.
    Interrupted,
}

/// A job's progress counters, each there once the job reported it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobProgress {
    /// The download step, `3/7`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_step: Option<String>,
    /// How far the segment walk got.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment: Option<SegmentPosition>,
    /// The octets the last System 7 segment stream wrote (issue #320).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub octets: Option<OctetsWritten>,
    /// The table write: `verified` or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<String>,
    /// The download: `verified` or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<String>,
    /// A scan's addresses to probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// A scan's addresses probed so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probed: Option<usize>,
    /// A scan's devices found so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
    /// A commissioning run's device reports so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<Value>>,
    /// The address a commissioning run checks now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checking: Option<String>,
    /// The devices a commissioning run has still to do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Value>,
    /// The device a commissioning run waits for, and where it is in the
    /// walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Value>,
    /// The device a commissioning run identified last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identified: Option<Value>,
}

/// How far a segment walk got.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPosition {
    /// Octets walked.
    pub position: usize,
    /// Octets in the segment.
    pub total: usize,
}

/// The octets a System 7 segment stream wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OctetsWritten {
    /// Octets written.
    pub written: usize,
    /// Octets the stream could write.
    pub writable: usize,
}

/// A job as `knx_job_status` and `knx_apply_status` report it, and as its
/// record under `.bussard/history` holds it (without the envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    /// The job id.
    pub job: String,
    /// What it does.
    #[serde(default)]
    pub kind: JobKind,
    /// The device, `None` for a job about no one device.
    #[serde(default)]
    pub address: Option<String>,
    /// The line of a scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    /// Where it stands.
    pub state: JobState,
    /// Whether it ended.
    pub done: bool,
    /// When it started, RFC 3339.
    pub started_at: String,
    /// When it ended.
    #[serde(default)]
    pub finished_at: Option<String>,
    /// Seconds since the start (to the end once done).
    #[serde(default)]
    pub elapsed_s: f64,
    /// What it does now, in words.
    #[serde(default)]
    pub step: String,
    /// What the human must do or answer, while it waits on one (`null`
    /// otherwise).
    #[serde(default)]
    pub question: Option<String>,
    /// The progress counters.
    #[serde(default)]
    pub progress: JobProgress,
    /// The final result once done: the flow's outcome as it serialises.
    #[serde(default)]
    pub result: Option<Value>,
    /// Where the record is persisted.
    #[serde(default)]
    pub record: Option<String>,
    /// Read back from its record (a job of an earlier server).
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_record: bool,
    /// What the pre-flight established (gateway, backups, snapshot), or
    /// what a paused job reports (its plan and question).
    #[serde(flatten)]
    pub context: Map<String, Value>,
}

/// The keys of [`JobStatus`] a context may not shadow.
const STATUS_KEYS: &[&str] = &[
    "job",
    "kind",
    "address",
    "line",
    "state",
    "done",
    "started_at",
    "finished_at",
    "elapsed_s",
    "step",
    "question",
    "progress",
    "result",
    "record",
    "from_record",
    "summary",
    "next_step",
    // The verdict belongs to the result, not to what the pre-flight found.
    "ok",
    "verified",
    "refused",
    "reason",
    "recovery",
];

/// `value`'s fields, without the ones a [`JobStatus`] has itself.
fn context_of(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(mut map) => {
            map.retain(|k, _| !STATUS_KEYS.contains(&k.as_str()));
            map
        }
        _ => Map::new(),
    }
}

/// One job of this session.
struct Job {
    /// Apply or plan.
    kind: JobKind,
    /// The device written or read; `None` for a job about no one device
    /// (a line scan).
    address: Option<IndividualAddress>,
    /// What the job is about, in words: the device address, or `line 1.1`.
    subject: String,
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
    progress: JobProgress,
    /// The line of a scan.
    line: Option<String>,
    /// What the pre-flight established (gateway, backups, snapshot).
    context: Map<String, Value>,
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

    /// The job running now and its device (`None` for a line scan), if any.
    pub fn running(&self) -> Option<(String, Option<IndividualAddress>)> {
        let inner = self.inner();
        let id = inner.running.clone()?;
        let address = inner.jobs.get(&id)?.address;
        Some((id, address))
    }

    /// Claims the one bus slot for a `kind` job about `subject`, or the
    /// refusal naming the job that runs: one bus job at a time, so a plan
    /// never reads a device while a write runs and the other way round. A
    /// plan of the device a running plan job reads joins that job; a new
    /// plan or scan drops the finished ones of its device or line (it
    /// supersedes them).
    pub fn claim(&self, kind: JobKind, subject: Subject<'_>) -> Result<Claim, String> {
        let mut inner = self.inner();
        let (address, line) = match subject {
            Subject::Device(address) => (Some(address), None),
            Subject::Line(line) => (None, Some(line)),
            Subject::Bus => (None, None),
        };
        if let Some(id) = &inner.running
            && let Some(job) = inner.jobs.get(id)
            && kind == JobKind::Plan
            && job.kind == JobKind::Plan
            && job.address == address
        {
            let id = id.clone();
            return Ok(Claim { id, joined: true });
        }
        if let Some(refusal) = busy_message(&inner, kind) {
            return Err(refusal);
        }
        // Inserted before the prune, so the new id never reuses a dropped one.
        let id = insert(&mut inner, kind, address, line);
        inner.jobs.retain(|job_id, job| {
            let superseded = match kind {
                JobKind::Plan => job.address == address,
                JobKind::Scan => job.line.as_deref() == line,
                _ => false,
            };
            *job_id == id || !(job.kind == kind && job.state == JobState::Done && superseded)
        });
        Ok(Claim { id, joined: false })
    }

    /// Drops `key` from the fields a paused job reported at the top of its
    /// status ([`JobTable::pause`]), once the answer it waited for came.
    pub fn forget(&self, id: &str, key: &str) {
        if let Some(job) = self.inner().jobs.get_mut(id) {
            job.context.remove(key);
        }
    }

    /// The job waits on the human (issue #749): it frees the slot, so other
    /// bus jobs run meanwhile, and reports `step`, `question`, the device it
    /// is about (`address`) and the fields of `detail` at the top of its
    /// status until [`JobTable::resume`] takes it up again.
    pub fn pause(
        &self,
        id: &str,
        step: &str,
        question: String,
        address: Option<IndividualAddress>,
        detail: Value,
    ) {
        let mut inner = self.inner();
        if inner.running.as_deref() == Some(id) {
            inner.running = None;
        }
        let Some(job) = inner.jobs.get_mut(id) else {
            return;
        };
        job.step = step.to_string();
        job.question = Some(question);
        if address.is_some() {
            job.address = address;
        }
        job.context.extend(context_of(detail));
    }

    /// Takes a paused job up again (issue #749): it holds the slot once more,
    /// or the refusal names the job that runs now. A job that is not paused
    /// (unknown, done, or running) is refused too.
    pub fn resume(&self, id: &str, step: &str) -> Result<(), String> {
        let mut inner = self.inner();
        let kind = match inner.jobs.get(id) {
            Some(job) if job.state == JobState::Running && inner.running.as_deref() != Some(id) => {
                job.kind
            }
            Some(_) => return Err(format!("job {id} is not waiting for an answer")),
            None => return Err(format!("no job {id} in this session")),
        };
        if let Some(refusal) = busy_message(&inner, kind) {
            return Err(refusal);
        }
        inner.running = Some(id.to_string());
        if let Some(job) = inner.jobs.get_mut(id) {
            job.step = step.to_string();
            job.question = None;
        }
        Ok(())
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
        job.result = serde_json::to_value(Refusal {
            address: job.address.map(|a| a.to_string()),
            ..Refusal::new(reason)
        })
        .ok();
        job.done.send_replace(true);
    }
}

/// The refusal for a `wanting` job while another runs, or `None`.
fn busy_message(inner: &Inner, wanting: JobKind) -> Option<String> {
    let id = inner.running.as_ref()?;
    let job = inner.jobs.get(id)?;
    let device = &job.subject;
    let again = match wanting {
        JobKind::Scan => "scan again",
        JobKind::Add => "add the device again",
        JobKind::Replace => "replace the device again",
        JobKind::Commission => "commission the line again",
        _ => "plan again",
    };
    Some(match (job.kind, wanting) {
        (JobKind::Apply, JobKind::Apply) => format!(
            "an apply is already running on this server: job {id} for {device}; one apply at a \
             time. Call knx_apply_status with job {id} until it is done, then plan again"
        ),
        (JobKind::Apply, JobKind::Read) => format!(
            "an apply is running on this server (job {id} for {device}); call \
             knx_job_status with job {id} until it is done, then call again"
        ),
        (JobKind::Apply, _) => format!(
            "an apply is running on this server (job {id} for {device}); call \
             knx_apply_status with job {id} until it is done, then {again}"
        ),
        (JobKind::Read, _) => format!(
            "a read is already running on this server: job {id} reads {device}; one bus job at \
             a time. Call knx_job_status with job {id} until it is done, then call again"
        ),
        (JobKind::Plan, _) => format!(
            "a plan is already running on this server: job {id} reads {device}; one bus job at \
             a time. Call knx_apply_status with job {id} until it is done, then call again"
        ),
        (JobKind::Scan, _) => format!(
            "a scan is already running on this server: job {id} sweeps {device}; one bus job at \
             a time. Call knx_job_status with job {id} until it is done, then call again"
        ),
        (JobKind::Add, _) => format!(
            "a device is being added on this server: job {id}; one bus job at a time. Call \
             knx_job_status with job {id} until it is done or waits for an answer, then call again"
        ),
        (JobKind::Replace, _) => format!(
            "a device is being replaced on this server: job {id} for {device}; one bus job at a \
             time. Call knx_job_status with job {id} until it is done or waits for an answer, \
             then call again"
        ),
        (JobKind::Commission, _) => format!(
            "{device} is being commissioned on this server: job {id}; one bus job at a time. \
             Call knx_job_status with job {id} until it is done or waits for an answer (or stop \
             it with knx_commission_line {{job, answer: \"stop\"}}), then call again"
        ),
    })
}

/// Inserts a new running job and marks it as the one in the slot.
/// `line` is the line of a scan, which has no `address`.
fn insert(
    inner: &mut Inner,
    kind: JobKind,
    address: Option<IndividualAddress>,
    line: Option<&str>,
) -> String {
    let now = SystemTime::now();
    let stamp = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let prefix = kind.as_str();
    let tag = match (address, line) {
        (Some(address), _) => address.to_string(),
        (None, Some(line)) => line.to_string(),
        (None, None) => "bus".to_string(),
    };
    let subject = match (address, line) {
        (Some(address), _) => address.to_string(),
        (None, Some(line)) => format!("line {line}"),
        (None, None) if kind == JobKind::Add => "the new device".to_string(),
        (None, None) => "the bus".to_string(),
    };
    let mut id = format!("{prefix}-{stamp}-{tag}");
    let mut seq = 1;
    while inner.jobs.contains_key(&id) {
        seq += 1;
        id = format!("{prefix}-{stamp}-{tag}-{seq}");
    }
    let (done, _) = tokio::sync::watch::channel(false);
    let step = match kind {
        JobKind::Apply => "pre-flight: reading the device and checking the plan",
        JobKind::Plan => "reading the device",
        JobKind::Read => "reading the bus",
        JobKind::Scan => "scanning the line",
        JobKind::Add => "press_button",
        JobKind::Replace => "check_gone",
        JobKind::Commission => "checking which devices already answer",
    };

    inner.jobs.insert(
        id.clone(),
        Job {
            kind,
            address,
            subject,
            started_at: now,
            finished_at: None,
            began: Instant::now(),
            state: JobState::Running,
            step: step.to_string(),
            question: None,
            progress: JobProgress::default(),
            line: line.map(str::to_string),
            context: Map::new(),
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
    pub fn started(&self, id: &str, context: &impl Serialize, record: Option<PathBuf>) {
        let context = context_of(serde_json::to_value(context).unwrap_or_default());
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
            if let Some(address) = address {
                inner.last.insert(address, id.to_string());
            }
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

    /// Updates the progress counters.
    pub fn progress(&self, id: &str, update: impl FnOnce(&mut JobProgress)) {
        if let Some(job) = self.inner().jobs.get_mut(id) {
            update(&mut job.progress);
        }
    }

    /// The write ended with `result`: the job is done, the slot is free, and
    /// the final record is persisted.
    pub fn finish(&self, id: &str, result: impl Serialize) {
        let result = serde_json::to_value(result).unwrap_or_else(|err| {
            serde_json::to_value(Verdict::failed(format!(
                "the result could not be serialised: {err}"
            )))
            .unwrap_or_default()
        });
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
            if let (JobKind::Apply, Some(address)) = (kind, address) {
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
    pub fn status(&self, dir: &Path, id: &str) -> Option<JobStatus> {
        if let Some(job) = self.inner().jobs.get(id) {
            return Some(job.status(id));
        }
        records(dir)
            .into_iter()
            .find(|record| record.job == id)
            .map(restored)
    }

    /// The latest job for `address`: this session's, else the newest record
    /// under `dir`'s history.
    pub fn last(&self, dir: &Path, address: IndividualAddress) -> Option<JobStatus> {
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
            .find(|record| record.address.as_deref() == Some(wanted.as_str()))
            .map(restored)
    }

    /// How many seconds the last verified write of `address` took (this
    /// session's, else the newest record), for a plan's
    /// `what_you_will_notice` (issue #306).
    pub fn last_write_seconds(&self, dir: &Path, address: IndividualAddress) -> Option<f64> {
        let last = self.last(dir, address)?;
        (last.kind == JobKind::Apply && last.state == JobState::Done && last.head().verdict.ok)
            .then_some(last.elapsed_s)
    }

    /// The final result of a job of this session, once done.
    pub fn result(&self, id: &str) -> Option<Value> {
        self.inner().jobs.get(id).and_then(|job| job.result.clone())
    }

    /// Waits up to `wait` for job `id` and returns its result once done.
    pub async fn outcome(&self, id: &str, wait: Duration) -> Option<Value> {
        if self.wait(id, wait).await {
            self.result(id)
        } else {
            None
        }
    }

    /// Runs `work` as job `id` in a server task, so a client that stops
    /// waiting does not cut it: its value finishes the job, its `Err` is the
    /// refusal ([`JobTable::refuse`]). `verb` names the job when the task
    /// panics.
    pub fn spawn<F, R>(self: &Arc<Self>, id: &str, verb: &'static str, work: F)
    where
        F: Future<Output = Result<R, String>> + Send + 'static,
        R: Serialize,
    {
        let (jobs, job) = (Arc::clone(self), id.to_string());
        self.watch(
            id,
            verb,
            tokio::spawn(async move {
                match work.await {
                    Ok(result) => jobs.finish(&job, result),
                    Err(reason) => jobs.refuse(&job, &reason),
                }
            }),
        );
    }

    /// Finishes job `id` with a failure when its task `worker` panics, so a
    /// panic never leaves the slot claimed for good.
    pub fn watch(self: &Arc<Self>, id: &str, verb: &'static str, worker: JoinHandle<()>) {
        let (jobs, job) = (Arc::clone(self), id.to_string());
        tokio::spawn(async move {
            if let Err(err) = worker.await {
                jobs.finish(
                    &job,
                    Verdict::failed(format!("the {verb} task stopped unexpectedly: {err}")),
                );
            }
        });
    }
}

/// The pre-flight gate of a write job (issue #289): the call that started
/// the job waits on it, and answers with the refusal, or once the
/// pre-flight passed with the result or the job id.
#[derive(Clone)]
pub struct Gate {
    /// The job table.
    jobs: Arc<JobTable>,
    /// The job.
    job: String,
    /// The waiting call, until the pre-flight ended.
    tx: Arc<std::sync::Mutex<Option<GateVerdict>>>,
}

/// Where the pre-flight's verdict goes: `Ok` once it passed, else the
/// refusal.
type GateVerdict = oneshot::Sender<Result<(), String>>;

impl Gate {
    /// A gate for `job`, and what the call waits on.
    pub fn new(jobs: &Arc<JobTable>, job: &str) -> (Gate, oneshot::Receiver<Result<(), String>>) {
        let (tx, rx) = oneshot::channel();
        let gate = Gate {
            jobs: Arc::clone(jobs),
            job: job.to_string(),
            tx: Arc::new(std::sync::Mutex::new(Some(tx))),
        };
        (gate, rx)
    }

    /// The pre-flight passed: records what it established (`context`, the
    /// record file) and lets the call answer.
    pub fn pass(&self, context: &impl Serialize, record: Option<PathBuf>) {
        self.jobs.started(&self.job, context, record);
        self.send(Ok(()));
    }

    /// The pre-flight refused: the call answers with `reason`.
    pub fn refuse(&self, reason: &str) {
        self.send(Err(reason.to_string()));
    }

    /// Answers the waiting call once.
    fn send(&self, verdict: Result<(), String>) {
        let tx = self
            .tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(tx) = tx {
            let _ = tx.send(verdict);
        }
    }
}

/// The record file of a job whose audit snapshot is `snapshot` in the
/// history of `dir`.
pub fn record_file(dir: &Path, snapshot: Option<&str>) -> Option<PathBuf> {
    snapshot.map(|id| {
        bussard_model::history::History::open(dir)
            .history_dir()
            .join(id)
            .join(RECORD_FILE)
    })
}

impl Job {
    /// The job as `knx_apply_status` reports it. `question` is there only
    /// while the job waits on one, so an apply's payload is unchanged.
    fn status(&self, id: &str) -> JobStatus {
        let state = self.state;
        let elapsed = match self.finished_at {
            Some(end) => end
                .duration_since(self.started_at)
                .unwrap_or_default()
                .as_secs_f64(),
            None => self.began.elapsed().as_secs_f64(),
        };
        JobStatus {
            job: id.to_string(),
            kind: self.kind,
            address: self.address.map(|a| a.to_string()),
            line: self.line.clone(),
            state,
            done: state == JobState::Done,
            started_at: bussard_service::monitor::timefmt::to_rfc3339(self.started_at),
            finished_at: self
                .finished_at
                .map(bussard_service::monitor::timefmt::to_rfc3339),
            elapsed_s: (elapsed * 10.0).round() / 10.0,
            step: self.step.clone(),
            question: self.question.clone(),
            progress: self.progress.clone(),
            result: self.result.clone(),
            record: self.record.as_ref().map(|p| p.display().to_string()),
            from_record: false,
            context: self.context.clone(),
        }
    }
}

/// Writes a job's status to its record file (temp file, then rename, so a
/// reader never sees half a record). A failure is logged: the job itself
/// goes on, and its session status stays available.
fn persist(status: &JobStatus) {
    let Some(path) = status.record.as_deref().map(PathBuf::from) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    let written = serde_json::to_vec_pretty(status)
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
fn records(dir: &Path) -> Vec<JobStatus> {
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
        .filter_map(|bytes| serde_json::from_slice::<JobStatus>(&bytes).ok())
        .collect()
}

/// A record read back from disk: a job no running server holds that is
/// still marked running was cut off by a server stop (`interrupted`).
fn restored(mut record: JobStatus) -> JobStatus {
    if record.state == JobState::Running {
        record.state = JobState::Interrupted;
        record.step = "interrupted: the server stopped before the write ended".to_string();
    }
    record.from_record = true;
    record
}

/// What a plan job's result says to the human, read back from the result
/// it stored (the plan exactly as `knx_plan_device` returns it).
#[derive(Debug, Default, Deserialize)]
struct Said {
    /// The plan's `summary`.
    #[serde(default)]
    summary: Option<String>,
}

impl JobStatus {
    /// The head of the result: its verdict and what the write was.
    pub fn head(&self) -> OutcomeHead {
        self.result
            .clone()
            .and_then(|r| serde_json::from_value(r).ok())
            .unwrap_or_default()
    }

    /// The job's status as an MCP result: the status plus the chat
    /// envelope (`summary`, `next_step`).
    pub fn chat(&self, model: &Model) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        crate::reply::envelope(&mut value, self.summary(model), Some(self.next_step()));
        value
    }

    /// The homeowner's sentence about the job (issue #306); `None` for a
    /// kind whose result carries its own.
    pub fn summary(&self, model: &Model) -> Option<String> {
        let device = subject_phrase(model, self.address.as_deref(), self.line.as_deref());
        let plan = self.kind == JobKind::Plan;
        Some(match self.state {
            JobState::Running if plan => {
                format!("Still reading {device} for the plan; nothing is written.")
            }
            JobState::Running => format!(
                "{} is still being written; the result follows.",
                capitalize(&device)
            ),
            JobState::Interrupted => format!(
                "The write to {device} was cut off when the server stopped; the device may be \
                 partly written. A new plan shows where it stands; the backup taken before the \
                 write is kept."
            ),
            JobState::Done if plan => self
                .result
                .clone()
                .and_then(|r| serde_json::from_value::<Said>(r).ok())
                .and_then(|said| said.summary)
                .unwrap_or_else(|| format!("The plan for {device} is ready.")),
            JobState::Done => match self.kind {
                JobKind::Apply | JobKind::Read => {
                    let mut head = self.head();
                    if head.address.is_none() {
                        head.address = self.address.clone();
                        head.line = self.line.clone();
                    }
                    head.summary(model)
                }
                _ => return None,
            },
        })
    }

    /// What the assistant does next with this job.
    pub fn next_step(&self) -> String {
        let job = self.job.as_str();
        let address = self.address.as_deref().unwrap_or_default();
        match self.kind {
            JobKind::Scan => self.scan_next_step(),
            JobKind::Add => self.add_next_step(),
            JobKind::Replace => self.replace_next_step(address),
            JobKind::Commission => self.commission_next_step(),
            JobKind::Plan => match self.state {
                JobState::Running => format!(
                    "Still reading {address} for the plan. Call knx_apply_status with job {job} \
                     again in a few seconds; the read continues in the server whether or not \
                     you poll. Nothing is written."
                ),
                _ if self.head().verdict.refused => {
                    format!("The plan for {address} was refused: tell the human result.reason.")
                }
                _ => format!(
                    "The plan for {address} is ready: `result` is exactly what knx_plan_device \
                     returns. Follow result.next_step: show the human result.sentences in full \
                     and ask result.question; knx_apply_device takes result.plan_digest only \
                     after an explicit yes."
                ),
            },
            JobKind::Apply | JobKind::Read => self.apply_next_step(address),
        }
    }

    /// What the assistant does next with a `knx_find_devices` job (issue
    /// #747).
    fn scan_next_step(&self) -> String {
        let (job, line) = (&self.job, self.line.as_deref().unwrap_or_default());
        match self.state {
            JobState::Running => format!(
                "Still scanning line {line} ({}; {} device(s) found so far). Call knx_job_status \
                 with job {job} again in a few seconds; the scan continues in the server whether \
                 or not you poll. Nothing is written.",
                if self.step.is_empty() {
                    "probing"
                } else {
                    &self.step
                },
                self.progress.found.unwrap_or(0)
            ),
            _ if self.head().verdict.ok => format!(
                "The scan of line {line} is done: `result` is exactly what knx_find_devices \
                 returns. Tell the human result.summary and the devices by name."
            ),
            _ => format!("The scan of line {line} did not run: tell the human result.reason."),
        }
    }

    /// What the assistant does next with an apply job (and a read job).
    fn apply_next_step(&self, address: &str) -> String {
        let job = &self.job;
        let head = self.head();
        match self.state {
            JobState::Running => format!(
                "Still working on {address} ({}). Call knx_apply_status with job {job} again in \
                 a few seconds; the job continues in the server whether or not you poll.",
                self.step
            ),
            _ if head.verdict.refused => format!(
                "Job {job} was refused in its pre-flight; nothing was written to {address}. \
                 Tell the human result.reason, then call knx_plan_device for {address} and ask \
                 again."
            ),
            JobState::Interrupted => format!(
                "The server stopped while job {job} was writing {address}; the device may be \
                 partly written. The pre-apply backups are named in this record. Call \
                 knx_plan_device for {address}, show the new plan to the human and ask again."
            ),
            _ if head.verdict.ok => format!(
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

    /// What the assistant does next with a `knx_add_device` job (issue
    /// #749).
    fn add_next_step(&self) -> String {
        let job = &self.job;
        match (self.state, self.step.as_str()) {
            (JobState::Running, "press_button") => format!(
                "Relay `question` to the human word for word: the job waits up to 30 s for a \
                 device to enter programming mode. Call knx_job_status with job {job} again in a \
                 few seconds."
            ),
            (JobState::Running, "identified") => format!(
                "The device is identified and nothing was written. Show the human `sentences` \
                 in full and ask `question`. Only after an explicit yes call knx_add_device with \
                 job {job}, plan_digest and yes: true, and download: true when \
                 `download_needed` is true and the human agreed to the download."
            ),
            (JobState::Running, step) => format!(
                "Still working ({step}). Call knx_job_status with job {job} again in a few \
                 seconds; the job continues in the server whether or not you poll."
            ),
            (JobState::Interrupted, _) => format!(
                "The server stopped while job {job} was adding a device. Call knx_add_device \
                 again to start over; check the device with knx_show_device {{live: true}} first."
            ),
            _ if self.head().verdict.ok => {
                "Done: tell the human result.summary, then follow result.next_step.".to_string()
            }
            _ => format!(
                "Job {job} did not add the device: tell the human result.reason. Nothing more is \
                 written until knx_add_device is called again."
            ),
        }
    }

    /// What the assistant does next with a `knx_replace_device` job (issue
    /// #751).
    fn replace_next_step(&self, address: &str) -> String {
        let job = &self.job;
        match (self.state, self.step.as_str()) {
            (JobState::Running, "check_gone" | "press_button") => format!(
                "Relay `question` to the human word for word when there is one: the job checks \
                 that {address} no longer answers, then waits up to 30 s for the replacement to \
                 enter programming mode. Call knx_job_status with job {job} again in a few \
                 seconds."
            ),
            (JobState::Running, "identified") => format!(
                "The replacement is identified and nothing was written. Show the human \
                 `sentences` in full and ask `question`. Only after an explicit yes call \
                 knx_replace_device with job {job}, plan_digest and yes: true, and download: \
                 true when `download_needed` is true and the human agreed to the download."
            ),
            (JobState::Running, step) => format!(
                "Still working on {address} ({step}). Call knx_job_status with job {job} again \
                 in a few seconds; the job continues in the server whether or not you poll."
            ),
            (JobState::Interrupted, _) => format!(
                "The server stopped while job {job} was replacing {address}; the device may be \
                 addressed and partly written. Call knx_plan_device for {address}, show the plan \
                 to the human and ask again."
            ),
            _ if self.head().verdict.ok => {
                "Done: tell the human result.summary, then follow result.next_step.".to_string()
            }
            _ => format!(
                "Job {job} did not complete the replacement of {address}: tell the human \
                 result.reason and result.recovery when there is one."
            ),
        }
    }

    /// What the assistant does next with a `knx_commission_line` job (issue
    /// #753).
    fn commission_next_step(&self) -> String {
        let job = &self.job;
        let waiting = self.context.get("waiting").is_some_and(Value::is_object);
        match self.state {
            JobState::Running if waiting => format!(
                "The job waits for the human's word and nothing more is written until it comes. \
                 Tell the human `waiting.reason`, then ask `question`; pass the answer as \
                 knx_commission_line {{job: {job}, answer}} with answer \"retry\", \"skip\" or \
                 \"stop\" (\"assign\" only where `question` offers it)."
            ),
            JobState::Running if self.question.is_some() => format!(
                "Relay `question` to the human word for word: the job waits up to 30 s for the \
                 named device to enter programming mode, then identifies it and assigns its \
                 address without asking again when it is the product the model expects. Call \
                 knx_job_status with job {job} again in a few seconds; progress.devices lists \
                 each device's outcome and label as it ends."
            ),
            JobState::Running => format!(
                "Still working ({}). Call knx_job_status with job {job} again in a few seconds; \
                 the job continues in the server whether or not you poll.",
                self.step
            ),
            JobState::Interrupted => format!(
                "The server stopped while job {job} was commissioning a line. Call \
                 knx_commission_line again for a new plan; devices already commissioned are \
                 found at their address and skipped."
            ),
            JobState::Done => "Done: tell the human result.summary and read out result.labels \
                               so they can label each device; follow result.next_step."
                .to_string(),
        }
    }
}

/// What [`JobSink::what`] names for a parameter-only write.
pub const PARAMETER_DOWNLOAD: &str = "parameter download";

/// A flow's [`ProgressSink`] and [`Prompt`] in the job table: its steps as
/// the job's `step`, its download as `progress`, the programming button as
/// `question`. Every flow of the server reports through it (the apply, the
/// flash, the restore, and the addressing flows of add, replace and
/// commission).
///
/// Its questions are answered yes: the human's yes is the plan digest with
/// `yes: true` the tool was called with (the three-step chat contract,
/// `dev/chat-parity.md`), checked before any flow runs.
pub struct JobSink<'a> {
    /// The job table.
    pub jobs: &'a JobTable,
    /// The job.
    pub job: &'a str,
    /// What downloads: [`PARAMETER_DOWNLOAD`] for a parameter-only write,
    /// `"download"` for a flash (issue #303).
    pub what: &'static str,
    /// The device a programming flow writes.
    pub target: Option<IndividualAddress>,
    /// What the read-back compares with.
    pub truth: &'static str,
    /// The parameter octets a parameter write streams.
    pub parameter_octets: usize,
    /// The question while the job waits for the programming button.
    pub press: String,
    /// Name the occupant check as the check that the dead device is gone
    /// (`knx_replace_device`).
    pub check_gone: bool,
}

impl<'a> JobSink<'a> {
    /// The sink of `job`, with the defaults of a download that names no
    /// plan, compared with the model.
    pub fn new(jobs: &'a JobTable, job: &'a str) -> Self {
        JobSink {
            jobs,
            job,
            what: "download",
            target: None,
            truth: "the model",
            parameter_octets: 0,
            press: String::new(),
            check_gone: false,
        }
    }

    /// A download (`what`) of `target`.
    pub fn download(mut self, what: &'static str, target: IndividualAddress) -> Self {
        self.what = what;
        self.target = Some(target);
        self
    }

    /// The question while the job waits for the programming button.
    pub fn press(mut self, question: String) -> Self {
        self.press = question;
        self
    }

    /// The device, in a step text.
    fn device(&self) -> String {
        self.target
            .map_or_else(|| "the device".to_string(), |t| t.to_string())
    }

    /// The `step` text of a flow step, or `None` for a step the job does not
    /// name.
    fn step_text(&self, step: &Step<'_>) -> Option<String> {
        Some(match step {
            Step::WriteTables => {
                "writing the group-address and association tables, then reading them back"
                    .to_string()
            }
            Step::WaitRestart => "waiting for the device to restart".to_string(),
            Step::WriteParameters { .. } => {
                format!("writing {} parameter octet(s)", self.parameter_octets)
            }
            Step::Download { .. } => format!(
                "flashing {}: the full application download, then the restart (the device is \
                 offline for {} to {} s) and the read-back",
                self.device(),
                bussard_service::flash::DEVICE_OFFLINE_SECONDS.0,
                bussard_service::flash::DEVICE_OFFLINE_SECONDS.1
            ),
            Step::ReadBack => format!(
                "reading {} back (tables, parameters, security object) to compare it with {}",
                self.device(),
                self.truth
            ),
            Step::PressButton => "press_button".to_string(),
            Step::CheckFree { target } if self.check_gone => {
                format!("check_gone: checking that {target} no longer answers")
            }
            Step::Identify { at } => format!("identifying the device at {at}"),
            Step::WriteAddress { target } => format!("writing the address {target}"),
            Step::ReadAddress { target } => format!("reading the device back at {target}"),
            Step::DeviceFile => "writing the device file".to_string(),
            _ => return None,
        })
    }

    /// One download progress event.
    fn progress(&self, event: Progress) {
        let (jobs, job) = (self.jobs, self.job);
        match event {
            Progress::Step {
                index,
                total,
                label,
            } => {
                jobs.step(
                    job,
                    format!("{} step {index} of {total}: {label}", self.what),
                );
                jobs.progress(job, |p| p.download_step = Some(format!("{index}/{total}")));
            }
            // How far the segment walk got (a read-compare compares most
            // chunks and writes few): not the octets written.
            Progress::Bytes { written, total } => {
                jobs.progress(job, |p| {
                    p.segment = Some(SegmentPosition {
                        position: written,
                        total,
                    });
                });
            }
            // The octets the last System 7 segment stream wrote (issue #320).
            Progress::Written { written, writable } => {
                jobs.progress(job, |p| {
                    p.octets = Some(OctetsWritten { written, writable });
                });
            }
        }
    }
}

/// `verified` or `failed`.
fn verdict_word(verified: bool) -> String {
    if verified { "verified" } else { "failed" }.to_string()
}

impl ProgressSink for JobSink<'_> {
    fn event(&mut self, event: Event<'_>) {
        let (jobs, job) = (self.jobs, self.job);
        match event {
            Event::Step(step) => {
                if let Some(text) = self.step_text(&step) {
                    jobs.step(job, text);
                }
                match step {
                    Step::PressButton => jobs.ask(job, Some(self.press.clone())),
                    Step::Found { .. } => jobs.ask(job, None),
                    _ => {}
                }
            }
            Event::Phase(text) => jobs.step(job, text),
            Event::Done {
                step: Step::WriteTables,
                verified,
            } => jobs.progress(job, |p| p.tables = Some(verdict_word(verified))),
            Event::Progress(progress) => self.progress(progress),
            Event::Finished { verified } => {
                jobs.progress(job, |p| p.download = Some(verdict_word(verified)));
                if verified && self.what == PARAMETER_DOWNLOAD {
                    jobs.step(job, "reading the parameter memory back to verify");
                }
            }
            _ => {}
        }
    }
}

impl Prompt for JobSink<'_> {
    fn ask(&mut self, _question: &Question) -> Answer {
        Answer::Yes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `status` as JSON, for the assertions.
    fn as_json(status: JobStatus) -> Result<Value, String> {
        serde_json::to_value(status).map_err(|e| e.to_string())
    }

    fn ia() -> Result<IndividualAddress, String> {
        "1.1.4".parse().map_err(|_| "address".to_string())
    }

    /// Claims an apply of 1.1.4.
    fn apply(jobs: &JobTable) -> Result<String, String> {
        Ok(jobs.claim(JobKind::Apply, Subject::Device(ia()?))?.id)
    }

    /// Claims a plan of `at`.
    fn plan(jobs: &JobTable, at: IndividualAddress) -> Result<Claim, String> {
        jobs.claim(JobKind::Plan, Subject::Device(at))
    }

    #[test]
    fn test_claim_refuses_a_second_apply_with_the_running_job() -> Result<(), String> {
        let jobs = JobTable::new();
        let first = apply(&jobs)?;
        let refused = apply(&jobs).err().ok_or("second claim must refuse")?;
        assert!(refused.contains(&first), "{refused}");
        jobs.abandon(&first);
        assert!(jobs.running().is_none());
        let second = apply(&jobs)?;
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
        let id = apply(&jobs)?;
        jobs.started(&id, &json!({"backup": "b.json"}), Some(record.clone()));
        // A new server (empty session) reads the running record back.
        let fresh = JobTable::new();
        let cut = fresh
            .last(dir.path(), ia()?)
            .ok_or("no record after restart")?;
        let cut = as_json(cut)?;
        assert_eq!(cut["state"], "interrupted", "{cut}");
        assert_eq!(cut["backup"], "b.json", "{cut}");

        jobs.finish(&id, json!({"ok": true, "verified": true}));
        let done = as_json(fresh.status(dir.path(), &id).ok_or("no record by job")?)?;
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
        let first = plan(&jobs, ia()?)?;
        assert!(!first.joined, "the first plan must be new");
        let plan_id = first.id;
        assert!(plan_id.starts_with("plan-"), "{plan_id}");
        assert_eq!(
            plan(&jobs, ia()?)?,
            Claim {
                id: plan_id.clone(),
                joined: true
            }
        );
        let refused = plan(&jobs, other).err().ok_or("another device must wait")?;
        assert!(refused.contains(&plan_id), "{refused}");
        let refused = apply(&jobs).err().ok_or("an apply must wait")?;
        assert!(refused.contains(&plan_id), "{refused}");
        jobs.finish(&plan_id, json!({"ok": true}));
        assert!(jobs.last(Path::new("/nonexistent"), ia()?).is_none());

        let apply = apply(&jobs)?;
        let refused = plan(&jobs, ia()?).err().ok_or("a plan must wait")?;
        assert!(refused.contains(&apply), "{refused}");
        jobs.refuse(&apply, "the device moved");
        let status = jobs
            .status(Path::new("/nonexistent"), &apply)
            .ok_or("the refused job stays")?;
        let status = as_json(status)?;
        assert_eq!(status["result"]["refused"], true, "{status}");
        assert!(jobs.running().is_none());
        // A new plan of the device supersedes its finished plan job.
        assert!(!plan(&jobs, ia()?)?.joined);
        assert!(jobs.status(Path::new("/nonexistent"), &plan_id).is_none());
        Ok(())
    }

    #[test]
    fn test_pause_frees_the_slot_and_resume_takes_it_again() -> Result<(), String> {
        let jobs = JobTable::new();
        let add = jobs.claim(JobKind::Add, Subject::Bus)?.id;
        assert!(apply(&jobs).is_err(), "the slot is the add's");
        jobs.pause(
            &add,
            "identified",
            "Assign 1.1.4? Say yes.".into(),
            Some(ia()?),
            json!({"plan_digest": "abc"}),
        );
        let status = jobs
            .status(Path::new("/nonexistent"), &add)
            .ok_or("the paused job stays")?;
        let status = as_json(status)?;
        assert_eq!(status["step"], "identified", "{status}");
        assert_eq!(status["plan_digest"], "abc", "{status}");
        assert_eq!(status["address"], "1.1.4", "{status}");
        assert_eq!(status["done"], false, "{status}");
        let other = apply(&jobs)?;
        let refused = jobs
            .resume(&add, "writing")
            .err()
            .ok_or("busy slot refuses")?;
        assert!(refused.contains(&other), "{refused}");
        jobs.finish(&other, json!({"ok": true}));
        jobs.resume(&add, "writing")?;
        assert!(
            jobs.resume(&add, "writing").is_err(),
            "a running job is not paused"
        );
        jobs.finish(&add, json!({"ok": true}));
        assert!(
            jobs.resume(&add, "writing").is_err(),
            "a done job is not paused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_returns_when_the_job_finishes() -> Result<(), String> {
        let jobs = std::sync::Arc::new(JobTable::new());
        let id = apply(&jobs)?;
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
