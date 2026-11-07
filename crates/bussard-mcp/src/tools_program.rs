//! The programming tier (issue #118): `knx_plan_device` and `knx_apply_device`.
//!
//! The tier also carries the safety net around them (issue #717):
//! `knx_restore_tables` writes a backup's link tables back through the same
//! write and read-back as `knx_apply_device` (the `restore_tables`
//! submodule), and `knx_restart_device` restarts a device with
//! [`bussard_service::restart`] (the `restart` submodule).
//!
//! Registered only when the server runs with `--allow-programming`. The tier
//! writes a device's group-address and association tables and the parameter
//! octets that differ from the model (issue #274), the same write `bussard
//! apply` performs with the same engine ([`bussard_service::params`] and
//! [`bussard_service::download`]), so it carries three gates on top of the
//! CLI's:
//!
//! 1. **The write gate.** A non-loopback gateway needs the operator's opt-in
//!    (`BUSSARD_ALLOW_REAL_GATEWAY=1` or `--allow-remote-gateway`), checked at
//!    server start by the CLI and again on every tool call here, through the
//!    one shared policy in [`bussard_transport::write_gate`].
//! 2. **The source-address probe.** Both tools refuse when a device already
//!    answers at the tunnel's own individual address
//!    ([`bussard_mgmt::checked_source`]), exactly like the CLI device commands.
//!    The probe runs once per tunnel instance (issue #341): a passed probe is
//!    reused until the bus reconnects, a refusal is never remembered.
//! 3. **The plan digest.** `knx_plan_device` reads the live tables, computes the
//!    plan and returns a `plan_digest`: SHA-256 over the device address, the
//!    model's links and parameter values for it, the desired tables, the
//!    parameter image the write would stream, and the live tables and
//!    parameter memory it read.
//!    `knx_apply_device` refuses unless that digest was produced by this server
//!    session within the plan lifetime (default ten minutes) and a fresh read of
//!    the live tables, with the current model, reproduces it. A plan is single
//!    use: a write, or a refusal because the device or model moved, retires it.
//!
//! The plan is the one `bussard plan --json` prints for the tables: changes in
//! the model's words (`+ langzeitbetrieb now listens on 0/1/3 (…)`), what stays,
//! what is written, the one question, and a `state_hash` of the device state
//! read ([`bussard_download::state_hash`], the same fingerprint the CLI's
//! `apply --plan <hash>` checks). `knx_apply_device` also accepts that hash as
//! `plan_hash` and refuses when a fresh read no longer produces it; the digest
//! stays required.
//!
//! The parameter half (issue #274): with the product data bussard.lock pins
//! for the device, the plan reads the parameter memory on the same session,
//! decodes it and lists every parameter that differs (key, vendor text,
//! device value, model value) with one sentence each, and the octet count.
//! The write streams only the differing octets (the `flash
//! --parameters-only` download), after the tables, and reads them back.
//! Without the product data (a pinned archive missing or changed) the plan
//! says why, with the recovery step, and a links-only plan the human
//! approved still applies. A device whose application drifted from the lock
//! gets the pinned application loaded by the plan's flash (issue #750);
//! without product data to load, it is refused with the `bussard flash` it
//! needs.
//!
//! A parameter change that shows or hides a com-object changes the
//! group-object table, which the parameter-only write cannot touch (issue
//! #303). The plan then says `method: "flash"` (otherwise `"apply"`) and
//! lists the com-objects that appear or disappear and why, the table sizes,
//! the time the device is offline, the parameter backup and the pinned
//! archive; `knx_apply_device` runs the full download `bussard flash --yes`
//! writes, as the same job (the `flash` submodule). The plan digest binds
//! the image.
//!
//! The read, the plan and the write are the CLI's, the same functions
//! ([`bussard_service::program`], issue #901): back up the pre-state (tables
//! and parameter memory) to `captures/backups/`, write with
//! [`bussard_service::program::apply::apply_device`], verify by an
//! independent read-back. A history snapshot naming the gateway is recorded
//! before the write, so `bussard history` shows every MCP apply (the audit
//! line). Protected group addresses in the change are refused with no
//! override.
//!
//! KNX Data Secure (issues #170, #205): with the server's keyring (`bussard mcp
//! --keyring`, `BUSSARD_KEYRING` or `connection.keyring`, the same resolver
//! every bus command uses), `knx_plan_device` reads a device the keyring holds
//! a tool key for over `A_SecureData`, the way `knx_describe_device` and
//! `bussard plan --keyring` do; a device the keyring does not list is read in
//! the clear. For such a device `knx_apply_device` does what `bussard apply
//! --keyring` does: every APDU rides `A_SecureData`, and a System B write also
//! reprograms the security object through [`bussard_download`] (the security
//! individual address table, PID 54; the group key table, PID 53; the
//! group-object security flags, PID 61), in the ETS order. The plan says what
//! the security object receives (addresses and object numbers, never a key),
//! a group address the model marks secure without a key in the keyring refuses
//! at plan time, and the digest binds that part too, so a keyring or `secure`
//! flag that moves between plan and apply retires the plan. The gates above
//! are unchanged.

use crate::reply::{answer_on, merge, ok, refused_on};
use bussard_service::program::chain;
use std::time::{Duration, Instant, SystemTime};

use crate::args::Parameters;
use bussard_download::{DesiredTables, LiveTables, PlanReport, SecurityInputs};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::params::{
    BuiltPlan, MissingProduct, ProductSource, Selection, resolve_product,
};
use bussard_service::program::apply::{ApplyRequest, TablesWritten};
use bussard_service::program::flash::{FlashFor, FlashImage, FlashNeed};
use bussard_service::program::plan::{PlanInputs, Planned};
use bussard_service::program::read::{FlagsCache, ReadError, ReadRequest};
use bussard_service::program::{self as program};
use bussard_service::secure::{SecureMaterial, ToolKeySource};
use bussard_service::{BusService, FactsCache, L4Options, ServiceError};
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::{check_write_gate, gateway_display};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::confirm::Store;
use crate::jobs::{Gate, JobKind, JobSink, PARAMETER_DOWNLOAD, Subject as On};
use crate::server::BussardMcp;
use crate::state::Need;

mod add_device;
mod addressing;
mod commission;
mod flash;
mod interface;
mod ip_secure;
mod line;
mod replace_device;
mod restart;
mod restore;
mod restore_tables;
mod secure_diag;

/// How long a plan stays valid for `knx_apply_device` unless configured.
pub const DEFAULT_PLAN_TTL: Duration = Duration::from_secs(10 * 60);

/// The programming tier's configuration and session state.
///
/// Present in [`crate::SharedState::programming`] only when the server runs
/// with `--allow-programming`.
pub struct ProgrammingTier {
    /// The resolved bus connection, for the write gate and the audit line.
    connection: ConnectionConfig,
    /// Whether the operator passed `--allow-remote-gateway`.
    allow_remote_gateway: bool,
    /// Device plans produced in this session, by digest.
    plans: Store<PlanSides>,
    /// Serialises programming: one plan or apply on the bus at a time.
    bus_lock: tokio::sync::Mutex<()>,
    /// The server's job table (issues #289, #746), shared with
    /// [`crate::SharedState::jobs`]: one apply or plan at a time, with status
    /// and record.
    jobs: std::sync::Arc<crate::jobs::JobTable>,
    /// Restore plans produced in this session, by digest (issue #290).
    restore_plans: Store<()>,
    /// Restart questions asked in this session, by digest (issue #717).
    restarts: Store<bussard_download::RestartForm>,
    /// Table-restore plans produced in this session, by digest (issue #717).
    table_restores: Store<()>,
    /// Line plans produced in this session, by digest (issue #748).
    line_plans: Store<line::LinePlan>,
    /// Devices `knx_add_device` identified, waiting for the human's yes, by
    /// job id (issue #749).
    adds: Store<add_device::AddPlan>,
    /// `knx_commission_line`'s plans, by digest (issue #753).
    commission_plans: Store<()>,
    /// `knx_commission_line`'s jobs (issue #753).
    commissions: std::sync::Mutex<commission::Commissions>,
    /// Replacements `knx_replace_device` identified, waiting for the human's
    /// yes, by job id (issue #751).
    replaces: Store<replace_device::ReplacePlan>,
}

impl ProgrammingTier {
    /// A tier for `connection`, with plans valid for `plan_ttl`, running its
    /// jobs in the server's job table `jobs`.
    pub fn new(
        connection: ConnectionConfig,
        allow_remote_gateway: bool,
        plan_ttl: Duration,
        jobs: std::sync::Arc<crate::jobs::JobTable>,
    ) -> Self {
        ProgrammingTier {
            connection,
            allow_remote_gateway,
            plans: Store::new(plan_ttl),
            bus_lock: tokio::sync::Mutex::new(()),
            jobs,
            restore_plans: Store::new(plan_ttl),
            restarts: Store::new(plan_ttl),
            table_restores: Store::new(plan_ttl),
            line_plans: Store::new(plan_ttl),
            adds: Store::new(plan_ttl),
            commission_plans: Store::new(plan_ttl),
            commissions: std::sync::Mutex::new(commission::Commissions::default()),
            replaces: Store::new(plan_ttl),
        }
    }

    /// Sets how long `knx_apply_device` waits for its write before it
    /// answers `started` (default [`crate::jobs::DEFAULT_REPLY_WAIT`],
    /// counted from the start of the call). Tests pass zero.
    pub fn set_reply_wait(&self, wait: Duration) {
        self.jobs.set_reply_wait(wait);
    }

    /// Sets how long a call waits for its device read before it answers
    /// with a job id: `knx_plan_device`'s read and `knx_apply_device`'s
    /// pre-flight (issue #332; default
    /// [`crate::jobs::DEFAULT_REPLY_WAIT`], counted from the start of
    /// the call). Tests shrink it to turn a slow read into a job.
    pub fn set_read_wait(&self, wait: Duration) {
        self.jobs.set_read_wait(wait);
    }

    /// How long a plan stays valid.
    pub fn plan_ttl(&self) -> Duration {
        self.plans.ttl()
    }
}

/// The two sides of a device plan this session produced, remembered until
/// applied, refused or expired: what the write re-derives from a fresh read.
#[derive(Debug, Clone)]
struct PlanSides {
    /// SHA-256 over the live tables the plan read.
    live: [u8; 32],
    /// SHA-256 over the model's links for the device and the desired tables.
    model: [u8; 32],
}

/// Arguments for `knx_plan_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanDeviceArgs {
    /// The address of the device to plan, e.g. `"1.1.4"`. Pass
    /// either `address` or `line`.
    #[serde(default)]
    pub address: Option<String>,
    /// A line, e.g. `"1.1"`: plan every device the project has on it, as
    /// `bussard plan --line` does (the link tables only).
    #[serde(default)]
    pub line: Option<String>,
}

/// Arguments for `knx_apply_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyDeviceArgs {
    /// The address of the device to write, e.g. `"1.1.4"`. Pass
    /// either `address` or `line`, as in the plan.
    #[serde(default)]
    pub address: Option<String>,
    /// A line, e.g. `"1.1"`: write the line plan `knx_plan_device` returned
    /// for it, as `bussard apply --line` does.
    #[serde(default)]
    pub line: Option<String>,
    /// The `plan_digest` returned by `knx_plan_device` for this device or line.
    pub plan_digest: String,
    /// Optional: the `state_hash` from the same plan (or from `bussard plan
    /// --json`). When given, the write is refused unless a fresh read of the
    /// device produces the same hash.
    #[serde(default)]
    pub plan_hash: Option<String>,
}

/// Arguments for `knx_restore_parameters`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RestoreParametersArgs {
    /// The address of the device, e.g. `"1.1.4"`.
    pub address: String,
    /// The parameter backup to replay: a file name in
    /// `<dir>/captures/backups/parameters/` (e.g. `"1.1.18-1790880058.json"`),
    /// or a path to one there.
    pub backup: String,
    /// Omit it to get the restore plan and its digest; pass that digest
    /// (after the human's explicit yes) to write.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// Arguments for `knx_restart_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RestartDeviceArgs {
    /// The address of the device, e.g. `"1.1.4"`.
    pub address: String,
    /// Omit it to get the restart form, the question and its digest; pass
    /// that digest (after the human's explicit yes) to restart.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// Arguments for `knx_restore_tables`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RestoreTablesArgs {
    /// The address of the device, e.g. `"1.1.4"`.
    pub address: String,
    /// The backup to restore from, under `<dir>/captures/backups/`: the
    /// `backup` name knx_backup_device returned (a directory; its newest
    /// file for the device is used), or a file name there. Omit it for the
    /// newest pre-write backup an apply kept of the device.
    #[serde(default)]
    pub backup: Option<String>,
    /// Omit it to get the restore plan and its digest; pass that digest
    /// (after the human's explicit yes) to write.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// Arguments for `knx_interface_secure`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct InterfaceSecureArgs {
    /// The address of the KNX IP interface, e.g. `"1.1.200"`.
    pub address: String,
    /// `"on"` or `"off"`.
    pub state: String,
    /// Omit it to get the plan and its digest; pass that digest (after the
    /// human's explicit yes) to switch.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// Arguments for `knx_clear_security_log`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClearSecurityLogArgs {
    /// The address of the KNX Data Secure device, e.g. `"1.1.12"`.
    pub address: String,
    /// Omit it to read the log and get the question and its digest; pass
    /// that digest (after the human's explicit yes) to clear.
    #[serde(default)]
    pub plan_digest: Option<String>,
}

/// Arguments for `knx_add_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddDeviceArgs {
    /// The address the new device gets, e.g. `"1.1.42"`. Omit it
    /// for the next free address on the project's busiest line (a device the
    /// keyring lists keeps its address). First call only.
    #[serde(default)]
    pub address: Option<String>,
    /// The order number the human says the device is, e.g. `"2138.10 REG"`.
    /// Optional: the device's own order number is read; this one names the
    /// product data when the device reports none. First call only.
    #[serde(default)]
    pub order_number: Option<String>,
    /// A path to the device's vendor `.knxprod` on the server's machine, as
    /// `bussard adopt --product`: imported into the product store first and
    /// used as the device's product data, whatever order number it reports.
    /// First call only.
    #[serde(default)]
    pub product: Option<String>,
    /// The `job` the first call returned. Pass it with `plan_digest` and
    /// `yes: true` to write, after the human's yes.
    #[serde(default)]
    pub job: Option<String>,
    /// The `plan_digest` the job reported at the `identified` step.
    #[serde(default)]
    pub plan_digest: Option<String>,
    /// `true` only after the human's explicit yes to the job's question.
    #[serde(default)]
    pub yes: Option<bool>,
    /// `true` only after the human agreed to download the vendor product
    /// data (`download_needed`); `yes` never answers that.
    #[serde(default)]
    pub download: Option<bool>,
}

/// Arguments for `knx_commission_line`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommissionLineArgs {
    /// The line to commission, e.g. `"1.1"`. Alone it returns the plan; with
    /// `plan_digest` and `yes: true` it starts the run.
    #[serde(default)]
    pub line: Option<String>,
    /// The `plan_digest` the plan returned.
    #[serde(default)]
    pub plan_digest: Option<String>,
    /// `true` only after the human's explicit yes to the plan's question.
    #[serde(default)]
    pub yes: Option<bool>,
    /// The `job` the run returned, with `answer`.
    #[serde(default)]
    pub job: Option<String>,
    /// The human's word for a waiting job: `"retry"`, `"skip"`, `"stop"`, or
    /// `"assign"` where the question offers it. `"stop"` also ends a
    /// running job.
    #[serde(default)]
    pub answer: Option<String>,
}

/// Arguments for `knx_replace_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplaceDeviceArgs {
    /// The address of the dead device, e.g. `"1.1.4"`: the
    /// address its replacement gets. First call only.
    #[serde(default)]
    pub address: Option<String>,
    /// The `job` the first call returned. Pass it with `plan_digest` and
    /// `yes: true` to write, after the human's yes.
    #[serde(default)]
    pub job: Option<String>,
    /// The `plan_digest` the job reported at the `identified` step.
    #[serde(default)]
    pub plan_digest: Option<String>,
    /// `true` only after the human's explicit yes to the job's question.
    #[serde(default)]
    pub yes: Option<bool>,
    /// `true` only after the human agreed to download the vendor product
    /// data (`download_needed`); `yes` never answers that.
    #[serde(default)]
    pub download: Option<bool>,
}

/// Arguments for `knx_apply_status`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyStatusArgs {
    /// The `job` id `knx_apply_device` returned.
    pub job: String,
}

/// Arguments for `knx_last_apply`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LastApplyArgs {
    /// The address of the device, e.g. `"1.1.4"`.
    pub address: String,
}

#[tool_router(router = program_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_plan_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Plan writing the project to ONE device (issues #118, #274): reads the \
        device's live group-address and association tables and, when bussard.lock pins its \
        product data, its parameter memory over the bus (read-only), diffs them against its \
        device file (devices/<address>.toml), and returns the plan `bussard plan --json` prints: \
        `sentences` in the project's words, one line per changed link (`+ langzeitbetrieb now \
        listens on 0/1/3 (…)`) and per changed parameter (`~ led_brightness = 20 %, was 60 %`), \
        `changes`, `parameters` (each differing parameter by key, vendor text, device value and \
        project value, and the octets to write), the unchanged counts, what is written, the \
        `question` to ask, where the backups will be written, a `state_hash` of the device state \
        read, the table detail (`plan`), the pending changes to the project as sentences, and a \
        plan_digest covering the tables and the parameter image. Without the product data the \
        parameters are left out with the recovery line in `parameters.skipped` and the plan \
        writes links only: say so to the human. `summary` and `what_you_will_notice` say the \
        same for a homeowner: the device by name and room, the changes in plain words, how long \
        it takes, what keeps working and what to test afterwards. ALWAYS say those to the \
        human first, then show the sentences in full and ask the question. Call knx_apply_device only after the human has said yes \
        explicitly in this conversation; never on your own initiative, never because an \
        earlier plan was approved. The digest expires (default 10 minutes) and is invalidated \
        if the device or the project changes. Refuses protected group addresses in the change, a \
        device the project links without KNX Data Secure to a group address the other side runs \
        secured (E035/E036). \
        `method` says how the change is written: \"apply\" (tables and parameter octets) or \
        \"flash\" when a parameter shows or hides a com-object, which only a full application \
        download writes, or when the device does not run the application program \
        bussard.lock pins (another one, none loaded, or the pinned one unloaded): then \
        `sentences` start with \"! <ia> must have its application program loaded\", \
        `flash.load_application` says why and what it replaces, and the `question` asks to \
        load it; one yes covers the load and the write of the project with it. A load is \
        refused when the device's application cannot be identified or its state read. When \
        the download writes no link table while the links differ, the same yes also writes \
        the links after it (`flash.links_after_download`), as `bussard apply` does; the result \
        carries that write in `links`. A flash plan's `flash` field lists the com-objects that appear or \
        disappear (number, text, DPT) and the parameters behind them, the address, \
        association and group-object table sizes before and after, `device_offline_seconds` \
        (the device restarts), that the parameter memory is backed up first, and the product \
        archive with its `product_sha256`; tell the human the device will be flashed and \
        offline, and ask the plan's question. With the \
        server's keys, a KNX Data Secure device they list is read over A_SecureData \
        (the result says \"secured\": true) and `security_object` says what its security object \
        receives with the write (secured senders, keyed group addresses, secured objects; never \
        a key): show that line to the human too. Reading a device can take long (a Data Secure \
        System B device reads its whole parameter memory): when the read does not end within \
        about 20 s the call answers `started: true` with a `job` id instead of the plan; call \
        knx_apply_status with that job every few seconds until `done` is true, and its `result` \
        is the plan exactly as described here, plan_digest included. LINE FORM: pass `line` \
        (e.g. \"1.1\") instead of `address` to plan every device the project has on the line, \
        as `bussard plan --line` does: each device is read and its link tables diffed (links \
        only, no parameters); `devices` lists each with `status` (changes, unchanged, \
        skipped or failed, with `detail`), `changes`, `sentences` and `notes`, plus `totals`, \
        all `sentences`, the `question` and ONE plan_digest over the whole line. It runs as a \
        job like the device form (`started: true` with a `job`: poll knx_job_status). Show \
        every device with changes and every skipped or failed one to the human. Only \
        available with --allow-programming."
    )]
    async fn knx_plan_device(
        &self,
        Parameters(args): Parameters<PlanDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match target_of(args.address.as_deref(), args.line.as_deref()) {
            Err(reason) => ok(refused_on("address", "", reason)),
            Ok(Target::Line(line)) => answer_on("line", line, self.plan_line(line).await),
            Ok(Target::Device(address)) => {
                answer_on("address", address, self.plan_device(address).await)
            }
        }
    }

    /// `knx_apply_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Write the planned change to ONE device on the PHYSICAL bus (issues #118, \
        #274, #289): the group-address and association tables when a link changes, then the \
        parameter octets that differ, with the engine `bussard apply` uses. Call this ONLY \
        after you showed the human the plan from knx_plan_device and the human answered yes \
        explicitly in this conversation. Pass the plan_digest from that plan, and its \
        state_hash as plan_hash to refuse if the device changed since. Refuses unless the \
        digest came from this server session within the plan lifetime and a fresh read of the \
        device, with the current project, still matches it; if refused, plan again and ask \
        again. The pre-flight (gates, digest, identity, backups of the tables and parameter \
        memory) runs in this call; the write and its read-back run as a job in the server. \
        When the write ends within about 20 s the reply is the full result with `started: \
        false, done: true` (the verify outcome, `parameters` written, the backup paths); \
        otherwise it is `started: true` with the `job` id: call knx_apply_status with that job \
        until `done` is true, and knx_last_apply with the address recovers the result if a \
        reply is lost. A pre-flight read that outlasts about 20 s (a Data Secure device) also \
        answers `started: true`; if it then refuses, the job ends with `result.refused: true` \
        and nothing written. One job at a time: a second call while a job (an apply or a \
        plan) runs is refused with its id. Tell the human the outcome and the backup paths. A KNX Data Secure device the \
        server's key store (or keyring) lists is written over A_SecureData, its security object reprogrammed \
        with the tables, exactly as `bussard apply --keyring` does. A plan with `method: \
        \"flash\"` runs the full application download `bussard flash --yes` writes, through \
        the same service function (the parameter memory backed up first when it is readable, \
        then the download, the restart, the independent read-back and the lock update) as \
        the same job; call it only after the human said yes to flashing the device. When the \
        plan loads the application (`flash.load_application`), the result carries \
        `load_application` with `loaded`, and `ok` is true only when the read-back matches \
        the project. LINE \
        FORM: pass `line` and the plan_digest of knx_plan_device's line plan (instead of \
        `address`) after the human's explicit yes to it, to write the line as `bussard apply \
        --line` does: one job (poll knx_job_status) that writes each device with changes in \
        address order, each backed up first and verified by an independent read-back; a \
        device that fails is reported and the next one is tried, and a device whose fresh read \
        no longer matches the plan is not written. Refused when the project's devices or links \
        on the line changed since the plan, or the project has validation errors. The result \
        lists per device `status` (applied, unchanged, skipped, failed), `verified`, \
        `changes`, `sentences`, `backup` and `detail`; `ok` is true only when no device \
        failed: report every failed device. Only available with --allow-programming."
    )]
    async fn knx_apply_device(
        &self,
        Parameters(args): Parameters<ApplyDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match target_of(args.address.as_deref(), args.line.as_deref()) {
            Err(reason) => ok(refused_on("address", "", reason)),
            Ok(Target::Line(line)) => answer_on(
                "line",
                line,
                self.apply_line(line, args.plan_digest.trim()).await,
            ),
            Ok(Target::Device(address)) => answer_on(
                "address",
                address,
                self.apply_device(
                    address,
                    args.plan_digest.trim(),
                    args.plan_hash.as_deref().map(str::trim),
                )
                .await,
            ),
        }
    }

    /// `knx_add_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Add a NEW device on the PHYSICAL bus, the flow of `bussard adopt` (issue \
        #749): press the button, identify, assign the address, fetch the product data, write \
        the device file. Three steps. (1) Call with optional `address` (else the next free one), \
        `order_number` and `product` (a path to the device's .knxprod, imported into the product \
        store first, as `bussard adopt --product`; then no download is asked): answers at once with `job` and `question` (press the programming \
        button): relay it word for word, then poll knx_job_status. The job waits up to 30 s for \
        the device. (2) knx_job_status reports step `identified`: serial, mask, order number, \
        `product_data` (in the store, or what would be downloaded), `sentences`, `plan_digest` \
        and `question`. Nothing is written yet: show the sentences and ask the question. (3) \
        ONLY after the human's explicit yes in this conversation, call again with `job`, \
        `plan_digest` and `yes: true`, plus `download: true` when `download_needed` is true and \
        the human agreed to the download too. It re-reads the device and refuses when it \
        changed, writes the address, reads the device back at the new address and writes the \
        device file and its lock entry: the result has `step: done`, `assigned`, `verified` \
        (the read-back matches the identified serial and mask), `summary`, `objects` to wire \
        and `next_step`. Refuses an address another device answers at. A device the keyring \
        lists is adopted where ETS put it over A_SecureData; securing a \
        factory-fresh device stays with ETS. Only available with --allow-programming."
    )]
    async fn knx_add_device(
        &self,
        Parameters(args): Parameters<AddDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = args
            .address
            .clone()
            .or_else(|| args.job.clone())
            .unwrap_or_default();
        answer_on("address", &address, self.add_device_tool(args).await)
    }

    /// `knx_commission_line` (registered only with `--allow-programming`).
    #[tool(
        description = "Commission a LINE on the PHYSICAL bus, the flow of `bussard commission` \
        (issue #753): give each device the project has on the line its address, one press of a \
        programming button at a time, and return the label text per device. Three kinds of \
        call. (1) `line` alone (e.g. \"1.1\") reads the project only and returns the devices by \
        name, room and order number, `sentences`, `question` and `plan_digest`: show the \
        sentences and ask the question. (2) ONLY after the human's explicit yes in this \
        conversation, call again with `line`, `plan_digest` and `yes: true`: it starts a job \
        (poll knx_job_status). The job skips the devices that already answer at their address, \
        then repeats per device: `press_button` (`question` names the device by name, room and \
        order number: relay it word for word; the job waits up to 30 s), `identified` (serial, \
        mask and order number read at the device's current address, the order number checked \
        against the project) and `assigned` (the address written and read back at the new \
        address; `progress.devices` gets the device's report and `label`). That one yes covers \
        every device whose identification matches the project's order number, exactly as the \
        CLI's one confirmation covers its run: no further yes per device. Anything else pauses \
        the job with `waiting` (reason) and `question`, writing nothing: another product, an \
        unreadable order number, no device or several in programming mode, or a device the \
        project has no order number for. (3) Pass the human's word as `job` with `answer`: \
        \"retry\", \"skip\" or \"stop\", or \"assign\" where the question offers it (a device \
        the project has no order number for). The human can stop the run at any time: `answer: \
        \"stop\"` ends it at once while it waits for a button, else after the device it is \
        on. The result has `devices` (status, identified, readback, label), `labels`, the \
        totals, `not_reached` and `summary`. Only addresses are written, as `bussard \
        commission` without --flash/--apply: push each device afterwards with knx_plan_device \
        and knx_apply_device. Securing a fresh device stays with ETS. Only \
        available with --allow-programming."
    )]
    async fn knx_commission_line(
        &self,
        Parameters(args): Parameters<CommissionLineArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = args
            .line
            .clone()
            .or_else(|| args.job.clone())
            .unwrap_or_default();
        answer_on("address", &subject, self.commission_line_tool(args).await)
    }

    /// `knx_replace_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Replace a DEAD device with the same product on the PHYSICAL bus, the \
        flow of `bussard replace` (issue #751): backup, press the button, identify, then the \
        address, the application, the project's parameters and links and the record, with one \
        yes. Three calls. (1) Call with `address` (the dead device's): it snapshots the project \
        (`backup`: the device file and its bussard.lock record, kept in the history) and \
        answers at once with `job` and `question` (press the programming button on the \
        replacement): tell the human what `backup` kept, relay the question word for word, \
        then poll knx_job_status. The job first checks that the address no longer answers \
        (a device that still answers is refused), then waits up to 30 s for the replacement. \
        (2) knx_job_status reports step `identified`: serial, mask, order number, the \
        resident application, `identity` against bussard.lock, `application` and \
        `product_data` (the pinned archive, or what would be downloaded), `sentences`, \
        `plan_digest` and `question`. Another product (order number or mask) is refused. \
        Nothing is written yet: show the sentences and ask the question. (3) ONLY after the \
        human's explicit yes in this conversation, call again with `job`, `plan_digest` and \
        `yes: true`, plus `download: true` when `download_needed` is true and the human \
        agreed to the download too. It re-reads the device and refuses when it changed, \
        writes the address and reads it back, then plans and writes the device as \
        knx_plan_device and knx_apply_device do (the pinned application loaded when the \
        replacement does not run it, the backups, the independent read-back) as the same \
        job, and records `replaced` in the device file and the new serial in bussard.lock. \
        The result has `step: done`, `ok`, `verified`, `assigned`, `flashed`, `write` (the \
        apply result), `recorded`, `summary` and `next_step`; when the address took but the \
        write did not verify, `ok: false` with `reason` and `recovery`. A device the project \
        records as secured is refused: securing a factory-fresh \
        device stays with ETS. Only available with --allow-programming."
    )]
    async fn knx_replace_device(
        &self,
        Parameters(args): Parameters<ReplaceDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = args
            .address
            .clone()
            .or_else(|| args.job.clone())
            .unwrap_or_default();
        answer_on("address", &address, self.replace_device_tool(args).await)
    }

    /// `knx_restore_parameters` (registered only with `--allow-programming`).
    #[tool(
        description = "Replay a parameter backup onto ONE device on the PHYSICAL bus (issue \
        #290), in two calls. Every apply keeps the device's parameter memory under \
        captures/backups/parameters/<ia>-<unix>.json before it writes; pass that file name as \
        `backup`. Without plan_digest: reads the device (read-only) and returns the restore \
        plan: `sentences`, `octets` to write, `octet_ranges` (each run with the parameters \
        behind it, their role, the device's and the backup's value, and `written`: false for \
        octets the restore leaves as the device holds them, because no parameter is placed \
        there under the project's configuration, which ETS does not write either, or because the \
        application owns the value at runtime), the `question` and a plan_digest. Say the \
        `summary`, show the sentences to the human in full and ask the question. With the plan_digest (ONLY after \
        the human's explicit yes in this conversation): re-reads the device, refuses if \
        anything moved, backs up the current parameter memory, writes and verifies by \
        read-back, as a job like knx_apply_device (`started: true` with a `job`: poll \
        knx_apply_status). Refuses a backup of another device, application or mask, a device \
        whose application drifted from bussard.lock, and a device that does not run the \
        application. Only available with --allow-programming."
    )]
    async fn knx_restore_parameters(
        &self,
        Parameters(args): Parameters<RestoreParametersArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on(
            "address",
            &args.address,
            self.restore_parameters(
                &args.address,
                &args.backup,
                args.plan_digest.as_deref().map(str::trim),
            )
            .await,
        )
    }

    /// `knx_restart_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Restart ONE device on the PHYSICAL bus in the form ETS uses for it and \
        wait until it answers again, as `bussard restart <address>` does (issue #717), in two \
        calls. Without plan_digest: sends nothing and returns `form` (\"confirmed\", the \
        master reset a System B application that supports Secure answers, or \"basic\", a bare \
        A_Restart), `form_reason`, the `question` and a plan_digest. Tell the human the device \
        restarts and ask the question. With the plan_digest (ONLY after the human's explicit \
        yes in this conversation): restarts as a job like knx_apply_device (`started: true` \
        with a `job`: poll knx_apply_status). The result says `confirmed` (the device answered \
        the restart with error code 0; a basic restart is never confirmed, only seen to answer \
        again), `mask` and `answered_after_ms`; `ok: false` with the reason when a confirmed \
        restart is refused or the device does not come back. Only available with \
        --allow-programming."
    )]
    async fn knx_restart_device(
        &self,
        Parameters(args): Parameters<RestartDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on(
            "address",
            &args.address,
            self.restart_device_tool(&args.address, args.plan_digest.as_deref().map(str::trim))
                .await,
        )
    }

    /// `knx_restore_tables` (registered only with `--allow-programming`).
    #[tool(
        description = "Write a backup's group-address and association tables back onto ONE \
        device on the PHYSICAL bus, as `bussard restore <backup> <address>` does (issue #717), \
        in two calls. `backup` names a knx_backup_device run (its `backup` field) or a file \
        under captures/backups/; omitted, the newest pre-write backup an apply kept of the \
        device. Without plan_digest: reads the device (read-only) and returns the plan: \
        `plan` (what is added and removed), `additions`, `removals`, the table sizes, \
        `security_object` on a secured device, the `question` and a plan_digest; `noop: true` \
        when the device already holds the backup's tables. Say the `summary`, show the plan \
        to the human and ask the question. With the plan_digest (ONLY after the human's explicit yes in this \
        conversation): re-reads the device, refuses if the device or the backup moved, records \
        a history snapshot, backs up the current tables, writes them with knx_apply_device's \
        engine and reads them back independently, as a job (`started: true` with a `job`: poll \
        knx_apply_status; knx_last_apply recovers it). `verified` is true only when the \
        read-back matches the backup. Only the link tables are written, never parameters. \
        Refuses a backup of another device or mask, a backup outside captures/backups, and a \
        change touching a protected group address. Only available with --allow-programming."
    )]
    async fn knx_restore_tables(
        &self,
        Parameters(args): Parameters<RestoreTablesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on(
            "address",
            &args.address,
            self.restore_tables(
                &args.address,
                args.backup.as_deref(),
                args.plan_digest.as_deref().map(str::trim),
            )
            .await,
        )
    }

    /// `knx_interface_secure` (registered only with `--allow-programming`).
    #[tool(
        description = "Switch KNXnet/IP Secure of ONE KNX IP interface on or off on the \
        PHYSICAL bus (issue #398), in two calls, as `bussard interface secure on|off` does. \
        Without plan_digest: returns the steps (the security mode and tool key under the \
        device's factory key, then the device authentication code, the password hashes, the \
        tunnelling users and the secured service families under the tool key, and a master \
        reset; `off` undoes it), the credentials the key store would gain (names only), the \
        `question` and a plan_digest. Show the steps to the human and ask the question. With \
        the plan_digest (ONLY after the human's explicit yes in this conversation): saves \
        generated credentials to the key store first, switches, waits out the restart and \
        reads back on a fresh connection; the result says `verified`. Credentials never leave \
        the key store and are never returned. Refused when the server's own session is a \
        KNXnet/IP Secure session with that interface (the restart would end it): the owner \
        runs it in a terminal. Only available with --allow-programming."
    )]
    async fn knx_interface_secure(
        &self,
        Parameters(args): Parameters<InterfaceSecureArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on(
            "address",
            &args.address,
            self.interface_secure(
                &args.address,
                &args.state,
                args.plan_digest.as_deref().map(str::trim),
            )
            .await,
        )
    }

    /// `knx_clear_security_log` (registered only with `--allow-programming`).
    #[tool(
        description = "Clear the KNX Data Secure security failures log (PID 55) and reset the \
        security report of ONE device on the PHYSICAL bus (issues #533, #571), in two calls, as \
        `bussard secure diag <ia> --clear` does after its confirmation. Without plan_digest: \
        reads the log over A_SecureData with the device's tool key from the server's keys \
        (read-only) and returns `diagnostics` (the sequence, cryptographic and access error \
        counts, the latest failure, the report), `lines`, the `question` and a plan_digest. \
        Show the lines to the human and ask the question. With the plan_digest (ONLY after the \
        human's explicit yes in this conversation): reads the log again, refuses if it moved, \
        clears it, and reads it back; `cleared: true` means every counter read zero and the \
        report clear afterwards. Clearing erases the evidence of a failed secured write: read \
        it with knx_describe_device first if the human is still diagnosing. Refused without a \
        tool key for the device in the server's keys. Only available with \
        --allow-programming."
    )]
    async fn knx_clear_security_log(
        &self,
        Parameters(args): Parameters<ClearSecurityLogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on(
            "address",
            &args.address,
            self.clear_security_log(&args.address, args.plan_digest.as_deref().map(str::trim))
                .await,
        )
    }

    /// `knx_apply_status` (registered only with `--allow-programming`).
    #[tool(
        description = "Report one job of the programming tier (issues #289, #332): an apply \
        started by knx_apply_device or knx_restore_parameters, or a plan started by \
        knx_plan_device (`kind`: apply or plan). `state` \
        (running, done, or interrupted when the server stopped mid-write), `done`, the current \
        `step`, `progress` (the table outcome, the download step, the segment position, the \
        octets the last segment wrote of those it may write), \
        the backup paths and, once done, `result`: the same result knx_apply_device returns \
        inline (ok, verified, parameters, recovery), or for a plan job the plan exactly as \
        knx_plan_device returns it (sentences, question, plan_digest). Reads only the server's job table and the \
        job record under .bussard/history; never touches the bus. Poll every few seconds while \
        `done` is false, then tell the human the outcome. Only available with \
        --allow-programming."
    )]
    async fn knx_apply_status(
        &self,
        Parameters(args): Parameters<ApplyStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on("address", &args.job, self.apply_status(&args.job))
    }

    /// `knx_last_apply` (registered only with `--allow-programming`).
    #[tool(
        description = "The latest apply job for ONE device (issue #289), in the shape of \
        knx_apply_status: this session's, else the newest record under .bussard/history, so a \
        result whose reply was lost (a client timeout, a server restart) is recoverable. \
        `found: false` when no apply of the device is recorded. Never touches the bus. Only \
        available with --allow-programming."
    )]
    async fn knx_last_apply(
        &self,
        Parameters(args): Parameters<LastApplyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        answer_on("address", &args.address, self.last_apply(&args.address))
    }
}

impl BussardMcp {
    /// Declares in `groups.toml` the group addresses the device files use but
    /// do not define, as `bussard apply` does before its validation gate
    /// (issue #779), through the same [`bussard_service::declare::declare_used`].
    /// Returns the model to go on with and one sentence per addition. A
    /// server started with `--no-model-edits` writes nothing to the project,
    /// so it declares nothing (an undeclared address is a validation warning,
    /// E001, and the apply goes on as before).
    fn declare_used(
        &self,
        model: std::sync::Arc<Model>,
        verb: &str,
    ) -> Result<(std::sync::Arc<Model>, Vec<String>), String> {
        if self.state().no_model_edits {
            return Ok((model, Vec::new()));
        }
        let dir = self.state().dir.clone();
        let mut edited = (*model).clone();
        let mut out = bussard_service::observer::Collected::default();
        let added = bussard_service::declare::declare_used(&dir, &mut edited, verb, &mut out)
            .map_err(|err| {
                format!(
                    "refusing to write: the group addresses the device files use could not be \
                     declared ({err}); nothing was written"
                )
            })?;
        for line in &out.lines {
            tracing::warn!("{line}");
        }
        if added.is_empty() {
            return Ok((model, Vec::new()));
        }
        // The handle debounces its directory check; force it so the next
        // tool call sees the declared addresses.
        self.state().model.reload();
        let sentences = added.iter().map(|d| d.sentence()).collect();
        Ok((std::sync::Arc::new(edited), sentences))
    }

    /// The tier, the write gate and the connected bus every programming call
    /// needs, or the refusal saying which is missing.
    fn programming_preflight(&self) -> Result<(&ProgrammingTier, BusService, String), String> {
        let tier = self.tier()?;
        let gateway = gateway_display(&tier.connection);
        check_write_gate(&tier.connection, tier.allow_remote_gateway)
            .map_err(|refused| refused.to_string())?;
        let service = self.state().live_service(Need::Manage)?.clone();
        Ok((tier, service, gateway))
    }

    /// The Data Secure material for `target` from the server's keyring: its
    /// tool key, the group keys and the senders' sequence numbers, or the
    /// plain path (no tool key) without a keyring or for a device the keyring
    /// does not list (ETS only lists a device once its security is
    /// commissioned). A device the model records as security-activated but
    /// the keyring lacks is a refusal (issue #189): plain access cannot reach
    /// it. The same rule `bussard apply --keyring` resolves with.
    fn plan_material(
        &self,
        target: IndividualAddress,
        model: &bussard_model::Model,
    ) -> Result<SecureMaterial, String> {
        let source = ToolKeySource {
            keyring: self.state().keyring.as_deref(),
            tool_key: None,
        };
        let activated = bussard_service::secure::model_activated(Some(model), target);
        bussard_service::secure::resolve_material(target, source, activated)
            .map_err(|err| chain(&err))
    }

    /// The tunnelling addresses `[connection] admit_tunnel_senders` adds to
    /// a Secure device's PID 54 (issue #297): every tunnelling interface of
    /// the server's keyring or key store. Empty when the option is off or the
    /// device is written in the clear.
    fn admitted_tunnel(
        &self,
        model: &Model,
        secured: bool,
    ) -> Result<Vec<IndividualAddress>, String> {
        if !secured || !bussard_service::admission::admit_tunnel_senders(Some(model)) {
            return Ok(Vec::new());
        }
        let evidence = crate::secure_group::admission_evidence(self.state().keyring.as_deref())?;
        Ok(evidence.tunnel_addresses())
    }

    /// `knx_plan_device`'s body; `Err` is a refusal reason. Runs the plan
    /// as a job ([`BussardMcp::run_plan`], issue #332).
    async fn plan_device(&self, address: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        // A link the model itself shows cannot work refuses before the bus is
        // touched or a job is claimed (issue #330); `plan_body` checks again
        // on the model it plans with.
        refuse_insecure_links(&self.state().model.reload(), target)?;
        let address = address.to_string();
        self.run_plan(Subject::Device(target), |me, _| async move {
            Ok(me
                .plan_body(&address)
                .await
                .unwrap_or_else(|reason| refused_on("address", &address, reason)))
        })
        .await
    }

    /// Runs a plan as a job (issue #332): claims the one slot (or joins the
    /// running plan job of the same subject), computes the plan in a server
    /// task, and answers with the plan when it is done within the read wait,
    /// else with `started: true` and the job id. The bus is the running
    /// apply's until it ends (issue #289), so a plan is refused while one
    /// runs: waiting for it here could outlast the client's call budget.
    async fn run_plan<F, Fut>(&self, subject: Subject, work: F) -> Result<Value, String>
    where
        F: FnOnce(BussardMcp, String) -> Fut,
        Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
    {
        let began = Instant::now();
        let (tier, _, _) = self.programming_preflight()?;
        let claim = tier.jobs.claim(JobKind::Plan, On::Device(subject.at()))?;
        let job = claim.id;
        if !claim.joined {
            tier.jobs
                .spawn(&job, "plan", work(self.clone(), job.clone()));
        }
        // Answered inline, as before issue #332. The finished job stays in
        // the table until the next plan of the subject supersedes it, so a
        // second caller that joined it reads the same plan.
        let wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        match tier.jobs.outcome(&job, wait).await {
            Some(plan) => Ok(plan),
            None => Ok(subject.plan_started(&job)),
        }
    }

    /// The plan itself, run inside the plan job; `Err` is a refusal reason.
    async fn plan_body(&self, address: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        // A link the model itself shows cannot work refuses before the bus is
        // touched (issue #330).
        let model = self.state().model.reload();
        // A KNX IP interface (a `[knxnet]` table, no links) is planned as its
        // KNXnet/IP parameter object (issue #391).
        if bussard_service::knxnet::interface_config(&model, target).is_some() {
            return self.plan_interface_body(target).await;
        }
        refuse_insecure_links(&model, target)?;
        let (tier, service, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        // The product data the parameter half decodes with (issue #274): the
        // archive the lock pins for the device, as `bussard apply` resolves it.
        let product = product_for(&dir, &model, target);
        let app = product.source.as_ref().and_then(|p| p.app());
        let desired = program::plan::desired_tables(&model, target, product.source.as_ref())?;

        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let tunnel = self.admitted_tunnel(&model, tool_key.is_some())?;
        let _guard = tier.bus_lock.lock().await;
        // A property-only load procedure (issue #390): no tables, the plan is
        // the properties the procedure writes.
        if let (Some(app), Some(props)) = (
            app,
            app.and_then(|a| {
                bussard_service::property_plan::property_plan(a, Some(&model), target)
            }),
        ) {
            let mut warm = self.warm().lock().await;
            warm.release().await;
            let rows = read_property_rows(&service, target, &tool_key, &props).await?;
            drop(warm);
            let noop = !rows.iter().any(|r| r.differs());
            return Ok(json!({
                "ok": true,
                "method": "flash",
                "address": target.to_string(),
                "gateway": gateway,
                "mask": format!("{:04X}", props.device_mask),
                "system_type": bussard_mgmt::system_type(props.device_mask),
                "secured": tool_key.is_some(),
                "noop": noop,
                "plan": bussard_service::property_plan::render_text(target, &app.id, &rows),
                "property_procedure": rows,
            }));
        }
        // Management calls are sequential (issue #215): this read opens its own
        // lease, so the warm connection is released first. The read budget of
        // PID 61 (issue #336): a cached read is used when the model asks for
        // exactly those flags (no security change pending).
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let (_, read) = read_device(
            &service,
            target,
            &dir,
            Read {
                tool_key: &tool_key,
                factory_key: &material.fdsk,
                high_water: &SequenceHighWater::new(),
                model: &model,
                product: product.source.as_ref(),
                tunnel: &tunnel,
                flags_cache: FlagsCache::Plan {
                    dir: &dir,
                    refresh: false,
                    desired: &desired,
                    group_keys: material.group_keys.as_ref(),
                },
            },
        )
        .await?;
        drop(warm);
        // Issue #750: a device that does not run the application the lock
        // pins (another one, none, or the pinned one unloaded) gets it
        // loaded by this plan's flash; without product data to load it is
        // the drift refusal, as before.
        let load = program::flash::load_need(&model, target, &read, product.source.as_ref())
            .transpose()?;
        if load.is_none() {
            refuse_drift(target, &read)?;
        }
        let ctx = PlanCtx {
            model: &model,
            target,
            gateway: &gateway,
            dir: &dir,
            desired: &desired,
            tunnel: &tunnel,
            material: &material,
            product: &product,
        };
        let planned = ctx.planned(&read);
        let tables = read.live.tables();
        let report = &planned.report;
        refuse_protected(&model, report)?;
        let security = ctx.security(&read)?;
        // A System 7 image that would not fit its memory region must refuse at
        // plan time, before the human is asked anything.
        program::plan::sys7_images(&read, &desired)
            .map_err(|e| format!("computing the System 7 table images: {e}"))?;
        let built = &planned.built;
        // A parameter change that shows or hides a com-object is written by a
        // full download (issue #303), and so is an application that must be
        // loaded (issue #750): the plan says `method: flash`.
        let flash = ctx.flash(&read, report, load.as_ref(), built)?;
        if flash.is_none()
            && let Some(refusal) = &built.refusal
        {
            return Err(refusal.clone());
        }

        // Issue #279: the edits this session made to this device and has not
        // applied yet (issue #112 listed the whole model against the last
        // snapshot), then record an edit made outside bussard so it cannot
        // be lost.
        let history = History::open(&dir);
        if let Err(err) = history.snapshot_if_changed_externally() {
            tracing::warn!("could not record a history snapshot: {err}");
        }

        // A security-object change of its own rewrites the tables too (issue
        // #297): the security object is written inside the table download.
        // A System 7 communication flag that does not follow its links is written
        // with the tables too.
        let tables_noop = report.is_noop()
            && !built.plan.writes.security_object
            && built.plan.writes.communication_flags.is_empty()
            && built.object_table.is_none();
        let noop = tables_noop && built.partial.is_none() && flash.is_none();
        if noop {
            // The device already holds the model: nothing this session
            // edited is pending on it any more.
            self.session_edits()
                .applied(target, built.parameters_skipped.is_none());
        }
        let pending = self.session_edits().for_device(target);
        let mut device_plan = built.plan.clone();
        // Issue #297: with `admit_tunnel_senders` off, say when only tunnel
        // clients can write a secured GA of this device and it does not
        // admit the tunnelling addresses.
        if !bussard_service::admission::admit_tunnel_senders(Some(&model))
            && let Some(keys) = material.group_keys.as_ref()
            && let Ok(evidence) =
                crate::secure_group::admission_evidence(self.state().keyring.as_deref())
        {
            for gap in bussard_service::admission::tunnel_gaps(
                &model,
                |ga| keys.contains_key(&ga),
                &evidence,
                Some(target),
            ) {
                device_plan.notes.push(gap.message());
            }
        }
        if let Some(line) = security
            .as_ref()
            .filter(|_| !tables_noop)
            .map(|s| s.describe(&desired.addresses))
        {
            device_plan.notes.push(line);
        }
        if let Some(f) = &flash {
            match &f.load {
                // Issue #750: the load leads the plan's sentences.
                Some(why) => {
                    device_plan
                        .notes
                        .insert(0, load_note(target, why, &f.plan, f.links_after));
                    if device_plan.writes.full_image.is_none() {
                        device_plan.writes.full_image = Some(bussard_download::FullImage {
                            segments: Vec::new(),
                            address_table: report.resulting_address_count,
                            association_table: report.resulting_association_count,
                            tables_change: !report.is_noop(),
                        });
                    }
                }
                None => {
                    device_plan.notes.push(flash_note(target));
                    if f.links_after {
                        device_plan.notes.push(links_after_note(target, &f.plan));
                    }
                }
            }
            // Issue #326: name what the full download writes.
            if let Some(full) = device_plan.writes.full_image.as_mut() {
                full.segments = f.plan.written_segments();
            }
        }
        let plan_text = match device_plan.writes.full_image.as_ref() {
            Some(full) if flash.is_some() => {
                bussard_download::render_full_image_plan_text(target, tables, report, full)
            }
            _ => bussard_download::render_plan_text(target, tables, report),
        };
        let digest = (!noop).then(|| {
            tier.remember_plan(
                target,
                PlanSides {
                    live: program::plan::live_fingerprint(&read),
                    model: model_fingerprint(&ctx, security.as_ref(), built, flash.as_ref()),
                },
            )
        });
        let now = SystemTime::now();
        let pairs = |list: &[bussard_download::ObjectGa]| -> Vec<Value> {
            list.iter()
                .map(|p| json!({"object": p.object, "ga": p.ga.to_string()}))
                .collect()
        };
        let parameters_json = parameters_json(built);
        let facts = crate::everyday::PlanFacts {
            model: &model,
            target,
            additions: report.additions.iter().map(|p| (p.object, p.ga)).collect(),
            removals: report.removals.iter().map(|p| (p.object, p.ga)).collect(),
            parameters: built
                .parameters
                .iter()
                .map(|p| (p.name.clone(), p.device.clone(), p.model.clone()))
                .collect(),
            flash: flash.is_some(),
            noop,
            last_write_s: tier.jobs.last_write_seconds(&self.state().dir, target),
        };
        let question = match &flash {
            _ if noop => None,
            Some(f) if f.load.is_some() => {
                Some(load_question(target, &gateway, &f.plan, f.links_after))
            }
            Some(_) => Some(flash_question(target, &gateway, device_plan.change_count())),
            None => Some(device_plan.question()),
        };
        // Issue #750: the sentences say first that the application must be
        // loaded, so a human who reads only them knows what the yes is for.
        let sentences = match flash
            .as_ref()
            .and_then(|f| f.load.as_ref().map(|why| (f, why)))
        {
            Some((f, why)) if f.links_after => format!(
                "! {target} must have its application program loaded: {why}. The yes loads {} \
                 with the model's parameters and reads it back, then writes the model's links \
                 (the download of this application does not write the link tables) and reads \
                 them back, as one job.\n{}",
                f.plan.identity.id,
                device_plan.render_text()
            ),
            Some((f, why)) => format!(
                "! {target} must have its application program loaded: {why}. The yes loads {} \
                 and writes the model's parameters and links with it.\n{}",
                f.plan.identity.id,
                device_plan.render_text()
            ),
            None => device_plan.render_text(),
        };
        Ok(json!({
            "ok": true,
            "method": if flash.is_some() { "flash" } else { "apply" },
            "flash": flash.as_ref().map(|f| json!(f.summary)),
            "address": target.to_string(),
            "gateway": gateway,
            "mask": format!("{:04X}", tables.mask),
            "system_type": bussard_mgmt::system_type(tables.mask),
            "secured": tool_key.is_some(),
            "identity": read.check().map(|c| bussard_service::identity_line(target, c)),
            "security_object": security_json(security.as_ref(), &desired, tables_noop),
            "noop": noop,
            "plan": plan_text,
            "summary": facts.summary(),
            "what_you_will_notice": facts.what_you_will_notice(),
            "sentences": sentences,
            "changes": device_plan.changes,
            "unchanged_objects": device_plan.unchanged_objects,
            "unchanged_parameters": device_plan.unchanged_parameters,
            "parameters": parameters_json,
            "writes": device_plan.writes,
            "notes": device_plan.notes,
            "question": question,
            "state_hash": device_plan.state_hash,
            "pending_model_changes": pending,
            "additions": pairs(&report.additions),
            "removals": pairs(&report.removals),
            "unchanged": report.unchanged.len(),
            "current_address_count": report.current_address_count,
            "resulting_address_count": report.resulting_address_count,
            "current_association_count": report.current_association_count,
            "resulting_association_count": report.resulting_association_count,
            "load_steps": report.load_steps.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "backup_dir": device_plan.backup_dir,
            "plan_digest": digest,
            "planned_at": bussard_monitor::timefmt::to_rfc3339(now),
            "expires_at": digest.as_ref().map(|_| tier.plans.expires_at(now)),
            "next_step": if noop {
                match &built.parameters_skipped {
                    Some(why) => format!(
                        "nothing to write over MCP: the links already match your project, and {why}"
                    ),
                    None if built.octet_ranges.iter().any(|r| !r.written) => "nothing to \
                        write: the device matches your project wherever the configuration places a \
                        parameter; the parameter octets that differ (parameters.octet_ranges \
                        with written: false) are ones ETS does not write in a download either, \
                        so they stay as the device holds them (see notes)"
                        .to_string(),
                    None if !built.octet_ranges.is_empty() => "nothing to write: the device \
                        already matches your project; only device-managed parameter octets differ \
                        (see notes and parameters.octet_ranges), and those are not written on \
                        their own"
                        .to_string(),
                    None => "nothing to write: the device already matches your project".to_string(),
                }
            } else if let Some(why) = flash.as_ref().and_then(|f| f.load.as_ref()) {
                format!(
                    "Show the plan above to the human (every sentence, and \
                     flash.load_application) and say that the application program must be \
                     loaded first: {why}. Loading it replaces what {target} runs now, \
                     {target} restarts and is offline for {} to {} s, and {} Ask whether to \
                     load the application into {target}. Call knx_apply_device with this \
                     plan_digest only after an explicit yes to loading it; that one call runs \
                     the load and the write as one job.",
                    bussard_service::flash::DEVICE_OFFLINE_SECONDS.0,
                    bussard_service::flash::DEVICE_OFFLINE_SECONDS.1,
                    if flash.as_ref().is_some_and(|f| f.links_after) {
                        "the model's parameters are written with it and read back; then the \
                         links are written by a table write (this application's download does \
                         not write them) and read back."
                    } else {
                        "the model's parameters and links are written with it and read back."
                    }
                )
            } else if flash.is_some() {
                format!(
                    "Show the plan above to the human (every sentence, the com-objects in \
                     flash.objects and the table sizes in flash.tables) and say that this change \
                     needs a full download: {target} restarts and is offline for {} to {} s, and \
                     its parameter memory is backed up first. Ask whether to flash {target}. \
                     Call knx_apply_device with this plan_digest only after an explicit yes to \
                     flashing it.",
                    bussard_service::flash::DEVICE_OFFLINE_SECONDS.0,
                    bussard_service::flash::DEVICE_OFFLINE_SECONDS.1
                )
            } else {
                let skipped = built
                    .parameters_skipped
                    .as_ref()
                    .map(|why| {
                        format!(
                            " The parameters are not part of this plan ({why}); tell the human \
                             that only the links are written."
                        )
                    })
                    .unwrap_or_default();
                format!(
                    "Show the plan above to the human (every sentence, links and parameters) \
                     and ask whether to write it to {target}. Call knx_apply_device with this \
                     plan_digest only after an explicit yes.{skipped}"
                )
            },
        }))
    }

    /// `knx_apply_device`'s body; `Err` is a refusal reason. One job
    /// ([`BussardMcp::run_write`]): the pre-flight, then the write, holding
    /// the bus lock and the warm slot throughout (management calls are
    /// sequential and the write leases the bus itself, issue #215); the
    /// table write after a download that writes no link table takes them
    /// again itself.
    async fn apply_device(
        &self,
        address: &str,
        digest: &str,
        plan_hash: Option<&str>,
    ) -> Result<Value, String> {
        let target = parse_address(address)?;
        let (digest, plan_hash) = (digest.to_string(), plan_hash.map(str::to_string));
        self.run_write(
            Subject::Device(target),
            "apply",
            move |me, job, gate| async move {
                let tier = me.tier()?;
                let (result, links_after) = me
                    .on_bus(tier, async {
                        // A KNX IP interface: the plan was its KNXnet/IP
                        // parameter object (issue #391), and so is the write.
                        let model = me.state().model.reload();
                        if bussard_service::knxnet::interface_config(&model, target).is_some() {
                            let result = me
                                .apply_interface(
                                    tier,
                                    &job,
                                    target,
                                    &digest,
                                    plan_hash.as_deref(),
                                    &gate,
                                )
                                .await?;
                            return Ok((result, None));
                        }
                        let prepared = me
                            .apply_preflight(tier, target, &digest, plan_hash.as_deref())
                            .await?;
                        let record =
                            crate::jobs::record_file(&prepared.dir, prepared.snapshot.as_deref());
                        gate.pass(prepared.result.clone(), record);
                        let links_after = LinksAfter::of(&prepared);
                        Ok::<_, String>((me.apply_write(tier, &job, prepared).await, links_after))
                    })
                    .await?;
                Ok(match links_after {
                    Some(consent) => me.links_after_download(tier, &job, consent, result).await,
                    None => result,
                })
            },
        )
        .await
    }

    /// The programming tier, or the refusal that it is off.
    pub(super) fn tier(&self) -> Result<&ProgrammingTier, String> {
        self.state().programming.as_ref().ok_or_else(|| {
            "the programming tier is off; start the server with --allow-programming".into()
        })
    }

    /// Runs one write as a job of the programming tier (issue #289): claims
    /// the one slot for `subject`, runs `work` (the pre-flight, which passes
    /// the [`Gate`] or refuses with `Err`, then the write) in a server task,
    /// and answers once the pre-flight is through: with the full result when
    /// the write also ends within the reply wait, else with `started: true`
    /// and the job id. The pre-flight reads the device, which can outlast the
    /// bridge on a Data Secure device (issue #332): past the read wait the
    /// call answers `started` and a later refusal ends the job instead.
    /// `verb` names the write in a refusal.
    async fn run_write<F, Fut>(
        &self,
        subject: Subject,
        verb: &'static str,
        work: F,
    ) -> Result<Value, String>
    where
        F: FnOnce(BussardMcp, String, Gate) -> Fut,
        Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
    {
        let began = Instant::now();
        let (tier, _, _) = self.programming_preflight()?;
        let job = tier
            .jobs
            .claim(JobKind::Apply, On::Device(subject.at()))?
            .id;
        let (gate, started) = Gate::new(&tier.jobs, &job);
        let fut = work(self.clone(), job.clone(), gate.clone());
        tier.jobs.spawn(&job, verb, async move {
            let result = fut.await;
            if let Err(reason) = &result {
                gate.refuse(reason);
            }
            result
        });
        let read_wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        match tokio::time::timeout(read_wait, started).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                tier.jobs.abandon(&job);
                return Err(reason);
            }
            Ok(Err(_)) => {
                return Err(format!(
                    "the {verb} of {subject} stopped before its pre-flight ended; call {} with \
                     job {job}",
                    subject.poll()
                ));
            }
            Err(_) => return Ok(self.write_started(tier, &job, &subject)),
        }
        let wait = tier.jobs.reply_wait().saturating_sub(began.elapsed());
        let Some(mut result) = tier.jobs.outcome(&job, wait).await else {
            return Ok(self.write_started(tier, &job, &subject));
        };
        let extra = match &subject {
            Subject::Device(target) => json!({
                "record": tier.jobs.status(&self.state().dir, &job).map(|s| s["record"].clone()),
                "next_step": inline_next_step(&job, *target, &result),
            }),
            Subject::Line(..) => json!({
                "next_step": format!(
                    "The write finished within this call (job {job}). Tell the human, per \
                     device, what was written and verified, and name every failed device with \
                     its detail and backup; knx_job_status with job {job} returns this result \
                     again.{}",
                    declared_step(&result)
                ),
            }),
        };
        merge(
            &mut result,
            json!({"started": false, "done": true, "job": job}),
        );
        merge(&mut result, extra);
        Ok(result)
    }

    /// The `started: true` answer of a write job still running.
    fn write_started(&self, tier: &ProgrammingTier, job: &str, subject: &Subject) -> Value {
        let mut status = tier
            .jobs
            .status(&self.state().dir, job)
            .unwrap_or_else(|| json!({}));
        merge(
            &mut status,
            json!({"started": true, "done": false, "job": job}),
        );
        merge(
            &mut status,
            match subject {
                Subject::Device(target) => json!({
                    "address": target.to_string(),
                    "next_step": format!(
                        "The write to {target} continues in the server as job {job}; it is not done \
                         yet. Tell the human it is running, then call knx_apply_status with job \
                         {job} every few seconds until `done` is true and report its `result` (the \
                         verify outcome, the parameters written, the backup paths; or, when \
                         result.refused is true, the pre-flight's reason: nothing was written). If \
                         the reply is lost, knx_last_apply with address {target} returns the same \
                         job."
                    ),
                }),
                Subject::Line(line, _) => json!({
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
            },
        );
        if let Some(map) = status.as_object_mut() {
            map.remove("result");
            map.remove("state");
        }
        status
    }

    /// The table write after a download that writes no link table (issue
    /// #779), as `bussard replace` runs `bussard apply` after `bussard
    /// flash`: once the download verified, the device is planned again (it
    /// now runs the application, so the plan is the table write of `bussard
    /// apply`), and that plan is written through the apply pre-flight and
    /// write, read-back included. The human's yes to the load covered it:
    /// the model's tables and parameter values for the device must still be
    /// the ones the yes was given for. `flashed` is the download's result;
    /// the answer is verified only when the table write's read-back
    /// matches. Called without the bus lock (the plan takes it).
    pub(super) async fn links_after_download(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        consent: LinksAfter,
        mut flashed: Value,
    ) -> Value {
        let target = consent.target;
        let application = flashed["application"]
            .as_str()
            .unwrap_or("the application")
            .to_string();
        if !(flashed["ok"] == json!(true) && flashed["verified"] == json!(true)) {
            flashed["links"] = json!({
                "written": false,
                "reason": "not written: the download did not verify",
            });
            return flashed;
        }
        let fail = |mut flashed: Value, reason: String| -> Value {
            flashed["ok"] = json!(false);
            flashed["verified"] = json!(false);
            flashed["reason"] = json!(format!(
                "{application} is loaded on {target} and verified, but its links were not \
                 written: {reason}"
            ));
            flashed["recovery"] = json!(format!(
                "Plan {target} again with knx_plan_device: the device runs the application now, \
                 so the plan is the table write of its links. Do not report the change as done \
                 until a plan reports nothing to do."
            ));
            flashed["links"] = json!({"written": false, "reason": reason});
            flashed
        };
        tier.jobs.step(
            job,
            format!(
                "{application} is loaded on {target}; planning its links (the download does not \
                 write the link tables)"
            ),
        );
        let plan = match self.plan_body(&target.to_string()).await {
            Ok(plan) => plan,
            Err(reason) => return fail(flashed, format!("the plan of its links failed: {reason}")),
        };
        if !consent.holds(self) {
            return fail(
                flashed,
                "the project's links or parameter values for the device changed since the yes"
                    .to_string(),
            );
        }
        if plan["noop"] == json!(true) {
            // A fresh read after the load shows the device holds the model:
            // that read is the read-back.
            flashed["links"] = json!({
                "written": false,
                "verified": true,
                "note": "a fresh read after the download shows the device already holds the \
                         project's links",
            });
            self.session_edits().applied(target, true);
            return flashed;
        }
        if plan["method"] != json!("apply") {
            return fail(
                flashed,
                format!(
                    "the plan after the download is method {} rather than the table write",
                    plan["method"]
                ),
            );
        }
        let Some(digest) = plan["plan_digest"].as_str().map(str::to_string) else {
            return fail(
                flashed,
                "the plan after the download has no digest".to_string(),
            );
        };
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        tier.jobs.step(
            job,
            format!("writing {target}'s links: pre-flight, backups"),
        );
        let prepared = match self.apply_preflight(tier, target, &digest, None).await {
            Ok(prepared) => prepared,
            Err(reason) => {
                return fail(
                    flashed,
                    format!("the table write was refused in its pre-flight: {reason}"),
                );
            }
        };
        let links = self.apply_write(tier, job, prepared).await;
        drop(warm);
        let verified = links["ok"] == json!(true) && links["verified"] == json!(true);
        if !verified {
            let reason = links["reason"]
                .as_str()
                .or_else(|| links["detail"].as_str())
                .unwrap_or("the table write did not verify")
                .to_string();
            let mut result = fail(flashed, reason);
            if let Some(recovery) = links["recovery"].as_str() {
                result["recovery"] = json!(recovery);
            }
            result["links"] = links;
            return result;
        }
        flashed["links"] = links;
        flashed
    }

    /// The pre-flight of an apply: the digest names a fresh plan of this
    /// session for `target`, a fresh read with the current model reproduces
    /// it, the gates pass, and the audit snapshot and both backups are
    /// written. `Err` is a refusal reason; nothing was written to the device.
    async fn apply_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        digest: &str,
        plan_hash: Option<&str>,
    ) -> Result<Prepared, String> {
        let (_, service, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();

        // The digest must name a plan this session produced, for this device,
        // within the plan lifetime.
        let planned = tier.plans.fresh(digest, target, "plan", again(target))?;
        let model = self.state().model.reload();
        // The model may have changed since the plan (issue #330).
        refuse_insecure_links(&model, target)?;
        let product = product_for(&dir, &model, target);
        let desired = program::plan::desired_tables(&model, target, product.source.as_ref())?;
        // KNX Data Secure: the same material the plan resolved, one
        // high-water mark for the read and the write so the send sequence
        // stays monotonic across both connections (spec §5.9).
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let tunnel = self.admitted_tunnel(&model, tool_key.is_some())?;
        let high_water = SequenceHighWater::new();
        // The apply may change the flags: the next plan reads PID 61 again
        // instead of a cache (issue #336).
        let (source, read) = read_device(
            &service,
            target,
            &dir,
            Read {
                tool_key: &tool_key,
                factory_key: &material.fdsk,
                high_water: &high_water,
                model: &model,
                product: product.source.as_ref(),
                tunnel: &tunnel,
                flags_cache: FlagsCache::Forget { dir: &dir },
            },
        )
        .await?;
        let ctx = PlanCtx {
            model: &model,
            target,
            gateway: &gateway,
            dir: &dir,
            desired: &desired,
            tunnel: &tunnel,
            material: &material,
            product: &product,
        };
        let security = ctx.security(&read)?;
        let Planned { report, built, .. } = ctx.planned(&read);
        let tables = read.live.tables();
        // The flash a com-object change needs (issue #303), or the load of
        // the pinned application (issue #750), rebuilt from the fresh read:
        // its image is part of the digest.
        let flash = match program::flash::load_need(&model, target, &read, product.source.as_ref())
            .transpose()
            .and_then(|load| {
                let flash = ctx.flash(&read, &report, load.as_ref(), &built)?;
                Ok((load, flash))
            }) {
            Ok(found) => found,
            Err(reason) => {
                tier.plans.retire(digest);
                return Err(reason);
            }
        };
        let (load, flash) = flash;

        // Re-derive the digest from what is true now; anything that moved since
        // the plan retires it.
        let now = PlanSides {
            live: program::plan::live_fingerprint(&read),
            model: model_fingerprint(&ctx, security.as_ref(), &built, flash.as_ref()),
        };
        let moved = match (now.live != planned.live, now.model != planned.model) {
            (true, true) => Some("the device's live state and the model both changed"),
            (true, false) => Some("the device's live tables changed (or its parameter memory)"),
            (false, true) => Some(
                "the model's links or parameter values for the device (or its Data Secure \
                 inputs, or its product data) changed",
            ),
            (false, false) => None,
        };
        let hash_moved = plan_hash.is_some_and(|h| !h.eq_ignore_ascii_case(&built.plan.state_hash));
        let moved = moved.or(hash_moved.then_some("the device state no longer matches plan_hash"));
        if let Some(what) = moved {
            tier.plans.retire(digest);
            return Err(format!(
                "refusing to write {target}: {what} since the plan was made. Plan again with \
                 knx_plan_device and show the new plan to the human."
            ));
        }
        // The identity verdict (issue #228, item 5): a device that runs another
        // application than the lock pins cannot take the model's tables and
        // parameters; it needs a flash first.
        if load.is_none()
            && let Err(refusal) = refuse_drift(target, &read)
        {
            tier.plans.retire(digest);
            return Err(refusal);
        }
        refuse_protected(&model, &report)?;
        if flash.is_none()
            && let Some(refusal) = &built.refusal
        {
            tier.plans.retire(digest);
            return Err(refusal.clone());
        }
        if let Some(refusal) = program::plan::family_refusal(target, tables.mask) {
            return Err(refusal);
        }
        // The plan is consumed from here on: one digest, one write.
        tier.plans.retire(digest);
        let tables_change = !report.is_noop()
            || built.plan.writes.security_object
            || !built.plan.writes.communication_flags.is_empty();
        let images = match program::plan::sys7_images(&read, &desired) {
            Ok(images) => images.filter(|_| tables_change),
            Err(e) => return Err(format!("computing the System 7 table images: {e}")),
        };
        let param_write = built.partial.is_some()
            && read
                .params
                .as_ref()
                .and_then(|p| p.detail.as_ref())
                .is_some();

        // A group address a device file uses but groups.toml does not define
        // is declared there first, named after the object that uses it, as
        // `bussard apply` does (issue #779). It adds no link, so the plan's
        // tables stand; the audit snapshot below holds the declared file.
        let (model, declared) = self.declare_used(model, "mcp knx_apply_device")?;

        // The audit line: a history snapshot naming the device, the plan and the
        // gateway, recorded before the bus write (as `bussard apply` does).
        let reason = SnapshotReason::new("mcp knx_apply_device")
            .with_args([target.to_string(), digest.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result(with_declared(
                match (tables_change, param_write) {
                    _ if load.is_some() => "before loading the application program",
                    _ if flash.is_some() => "before flashing the application program",
                    (true, true) => "before writing the device tables and parameters",
                    (false, true) => "before writing the device parameters",
                    _ => "before writing the device tables",
                },
                &declared,
            ));
        let snapshot = audit_snapshot(&dir, reason, target)?;

        // Both backups before the first write, as `bussard apply` takes them.
        // A flash rewrites the whole parameter memory: it is backed up first,
        // where knx_restore_parameters reads it (issue #303).
        let detail = read.params.as_ref().and_then(|p| p.detail.as_ref());
        let backups = program::apply::back_up(
            &dir,
            target,
            &read.live,
            detail.filter(|_| flash.is_some() || param_write),
        )
        .map_err(|e| match e {
            program::apply::BackupError::Tables(e) => {
                format!("refusing to write {target} without a backup: {e}")
            }
            program::apply::BackupError::Parameters(e) => {
                format!("refusing to write {target} without a parameter backup: {e}")
            }
        })?;
        let backup_path = backups
            .tables
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let param_backup_path = backups.parameters.as_ref().map(|p| p.display().to_string());

        let mut result = json!({
            "method": if flash.is_some() { "flash" } else { "apply" },
            "address": target.to_string(),
            "gateway": gateway,
            "secured": tool_key.is_some(),
            "backup": backup_path,
            "parameter_backup": param_backup_path,
            "snapshot": snapshot,
            "declared": declared,
        });
        if load.is_some() && param_backup_path.is_none() {
            // Issue #750: the device holds no application the pinned
            // product data can read, so there is no parameter memory to
            // keep; the tables are backed up as for any apply.
            result["parameter_backup_note"] = json!(
                "not backed up: the device holds no application whose parameter memory the \
                 pinned product data can read (as `bussard flash`, which takes no backup)"
            );
        }
        Ok(Prepared {
            origin: Origin::Model,
            model: std::sync::Arc::clone(&model),
            product: product.source,
            target,
            gateway,
            dir,
            source,
            tool_key,
            high_water,
            desired,
            report,
            built,
            read,
            security,
            images,
            snapshot,
            backup_path,
            param_backup_path,
            flash,
            result,
        })
    }

    /// The write of an apply whose pre-flight passed: the tables when a link
    /// changes, then the parameter octets, each verified, then the
    /// independent read-back, through [`program::apply::apply_device`] (the
    /// function `bussard apply` writes with). Never refuses: a failure is the
    /// result (`ok: false` with the reason and the recovery).
    async fn apply_write(&self, tier: &ProgrammingTier, job: &str, p: Prepared) -> Value {
        let Prepared {
            origin,
            model,
            product,
            target,
            gateway,
            dir,
            source,
            tool_key,
            high_water,
            desired,
            report,
            built,
            read,
            security,
            images,
            backup_path,
            param_backup_path,
            flash,
            mut result,
            ..
        } = p;
        let Some(service) = self.state().bus.service().cloned() else {
            merge(
                &mut result,
                json!({"ok": false, "verified": false, "reason": "the bus is not wired"}),
            );
            return result;
        };
        if let Some(image) = flash {
            let links_after = image.links_after;
            let ctx = flash::FlashJob {
                service: &service,
                target,
                gateway: &gateway,
                dir: &dir,
                source,
                tool_key,
                high_water,
                changed: json!(built.parameters),
                param_backup: param_backup_path.as_deref(),
                readback: product.as_ref().and_then(|source| {
                    program::flash::readback_inputs(source, Some(&model), read.live.tables().mask)
                }),
            };
            let result = self.flash_write(tier, job, &image, ctx, result).await;
            if result["ok"] == json!(true) {
                // The lock may have changed (the PID 54 record): serve it.
                self.state().model.reload();
                // With the links still to write (issue #779), the edits are
                // applied once the table write after the download verified.
                if !links_after {
                    self.session_edits().applied(target, true);
                }
            }
            return result;
        }
        let tables = read.live.tables();
        let tables_change = !report.is_noop()
            || built.plan.writes.security_object
            || !built.plan.writes.communication_flags.is_empty();
        let detail = read.params.as_ref().and_then(|p| p.detail.as_ref());
        let param_write = built.partial.as_ref().zip(detail);
        let (tool, planner) = (origin.tool(), origin.planner());
        let recovery = format!(
            "The device may be left with partially written or unloaded tables. The pre-write \
             state is backed up at {backup_path}. Planning {target} again with {planner} and \
             writing it is safe (the tables are rewritten wholesale); do not assume the device \
             works until a new plan reports nothing to do."
        );
        let mut observer = JobSink {
            truth: origin.truth(),
            parameter_octets: built.plan.writes.parameter_octets,
            ..JobSink::new(&tier.jobs, job).download(PARAMETER_DOWNLOAD, target)
        };
        // Authorize (free access) best-effort, as the read did.
        let options = L4Options::secured(source, tool_key.clone(), high_water.clone());
        let written = program::apply::apply_device(
            ApplyRequest {
                service: &service,
                target,
                source,
                dir: &dir,
                model: Some(&model),
                product: product.as_ref(),
                mask: tables.mask,
                desired: &desired,
                tables_change,
                object_table: built.object_table.as_deref(),
                images: images.as_ref(),
                security: security.as_ref(),
                parameters: param_write,
                tool_key,
                high_water,
                // The facts the pre-flight read checked seed every later
                // connection of the job (issue #761); a device they record
                // as not answering authorize is not asked again (#215).
                options,
                seed: read.seed(),
            },
            &mut observer,
        )
        .await;
        let audit = |what: &str, verified: bool| {
            tracing::info!(
                "audit: {tool} {target} {what} via {gateway}: {}",
                match (verified, what) {
                    (true, _) => "verified",
                    (false, "read-back") => "NOT VERIFIED",
                    (false, _) => "FAILED",
                }
            );
        };
        if let Some(tables_written) = &written.tables {
            tracing::info!(
                "audit: {tool} {target} tables via {gateway}: {}; backup {backup_path}",
                if tables_written.verified() {
                    "verified"
                } else {
                    "FAILED"
                }
            );
            merge(
                &mut result,
                match tables_written {
                    TablesWritten::Ran(summary) => json!({
                        "ok": summary.ok,
                        "verified": summary.ok,
                        "security_object": security_json(security.as_ref(), &desired, false),
                        "address_state": summary.address_state.to_string(),
                        "association_state": summary.association_state.to_string(),
                        "resulting_address_count": report.resulting_address_count,
                        "resulting_association_count": report.resulting_association_count,
                        "group_object_table": summary.object_table.as_ref().map(|t| json!({
                            "state": t.state.to_string(),
                            "entries": t.entries,
                            "read_back_matches": t.matches,
                        })),
                        "detail": if summary.ok { Value::Null } else { Value::String(summary.detail.clone()) },
                        "recovery": if summary.ok { Value::Null } else { Value::String(recovery.clone()) },
                    }),
                    TablesWritten::Lease(err) => json!({
                        "ok": false,
                        "verified": false,
                        "reason": format!("could not lease the bus: {}", match err {
                            ServiceError::Lease(cause) => cause.to_string(),
                            other => other.to_string(),
                        }),
                        "recovery": recovery,
                    }),
                    TablesWritten::Failed(why) => json!({
                        "ok": false,
                        "verified": false,
                        "reason": format!("the write failed: {why}"),
                        "recovery": recovery.clone(),
                    }),
                },
            );
            if !tables_written.verified() && param_write.is_some() {
                result["parameters"] = json!({
                    "written": false,
                    "reason": "not written: the table write did not verify",
                });
            }
        }
        match &written.restarted {
            Some(Ok(after)) => {
                result["restarted"] = json!({"answered_after_ms": after.as_millis() as u64});
            }
            Some(Err(reason)) => merge(
                &mut result,
                json!({
                    "ok": false,
                    "verified": false,
                    "reason": format!("the device did not come back after its restart: {reason}"),
                    "recovery": recovery.clone(),
                }),
            ),
            None => {}
        }
        record_json(&mut result, &written.lock);
        let reached = written.tables.as_ref().is_none_or(TablesWritten::verified)
            && !matches!(written.restarted, Some(Err(_)));
        match &written.parameters {
            Some(outcome) => {
                let ok = matches!(
                    outcome,
                    Ok(bussard_service::download::ParamWriteOutcome::Verified { .. })
                );
                audit("parameters", ok);
                result["parameters"] = match outcome {
                    Ok(bussard_service::download::ParamWriteOutcome::Verified { octets }) => {
                        json!({
                            "written": true,
                            "verified": true,
                            "octets": octets,
                            "changed": built.parameters,
                        })
                    }
                    Ok(failed) => json!({
                        "written": false,
                        "verified": false,
                        "reason": failed.failure(),
                    }),
                    Err(why) => json!({
                        "written": false,
                        "verified": false,
                        "reason": format!("the parameter read-back failed: {why}"),
                    }),
                };
                result["ok"] = json!(ok);
                result["verified"] = json!(ok);
                if !ok {
                    result["recovery"] = json!(format!(
                        "The parameter memory before the write is backed up at {}. If the \
                         application still reads Loaded, re-planning and re-applying {target} \
                         rewrites only the octets that still differ; otherwise recover with a full \
                         `bussard flash --force {target}` at the CLI. Do not assume the device works \
                         until a new knx_plan_device reports nothing to do.",
                        param_backup_path.as_deref().unwrap_or("(no backup)")
                    ));
                }
            }
            None if reached => {
                if let Some(why) = &built.parameters_skipped {
                    result["parameters"] = json!({"written": false, "reason": why});
                }
            }
            None => {}
        }
        // Verified means read back and compared (issues #319, #349).
        if let Some(readback) = &written.readback {
            audit("read-back", readback.verified);
            result["readback"] = json!(readback);
            if let Some(failure) = readback.failure() {
                // Say what is left first; a write failure already reported
                // stays in `write_reason`.
                if let Some(previous) = result.get("reason").filter(|r| !r.is_null()).cloned() {
                    result["write_reason"] = previous;
                }
                result["ok"] = json!(false);
                result["verified"] = json!(false);
                result["reason"] = json!(failure);
                if result.get("recovery").is_none_or(Value::is_null) {
                    result["recovery"] = json!(format!(
                        "The items listed still differ from {} on {target}. The pre-write \
                         state is backed up at {backup_path}. Plan {target} again with \
                         {planner} and write it again; do not report the change as done until \
                         a plan reports nothing to do.",
                        origin.truth()
                    ));
                }
            }
        }
        if result.get("ok").is_none() {
            result["ok"] = json!(true);
            result["verified"] = json!(true);
        }
        // A restore writes a backup, not the model: the session's model
        // edits are still pending on the device after it.
        if result["ok"] == json!(true) && origin == Origin::Model {
            self.session_edits()
                .applied(target, built.parameters_skipped.is_none());
        }
        result
    }

    /// `knx_apply_status`'s body; `Err` is a refusal reason.
    fn apply_status(&self, job: &str) -> Result<Value, String> {
        let tier = self.tier()?;
        let job = job.trim();
        tier.jobs.status(&self.state().dir, job).ok_or_else(|| {
            format!(
                "no job {job:?} in this session or under .bussard/history; \
                 knx_last_apply with the device's address returns its latest job"
            )
        })
    }

    /// `knx_last_apply`'s body; `Err` is a refusal reason.
    fn last_apply(&self, address: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        let tier = self.tier()?;
        Ok(match tier.jobs.last(&self.state().dir, target) {
            Some(status) => {
                let mut status = status;
                status["found"] = json!(true);
                status
            }
            None => json!({
                "found": false,
                "address": target.to_string(),
                "next_step": format!(
                    "no apply of {target} is recorded in this session or under \
                     .bussard/history; call knx_plan_device for {target} to see what the device \
                     holds"
                ),
            }),
        })
    }
}

/// What a yes to a download with the links written after it (issue #779)
/// was given for: the device, and the model's tables and parameter values
/// for it. The table write after the download runs only while the model
/// still holds them.
pub(super) struct LinksAfter {
    /// The device.
    target: IndividualAddress,
    /// The model's tables for the device when the yes was given.
    desired: DesiredTables,
    /// The device's parameter values in the model when the yes was given.
    parameters: Option<std::collections::BTreeMap<String, String>>,
}

impl LinksAfter {
    /// The consent `p` carries, `None` unless its download leaves the links
    /// to a table write after it.
    fn of(p: &Prepared) -> Option<LinksAfter> {
        p.flash.as_ref().filter(|f| f.links_after)?;
        Some(LinksAfter {
            target: p.target,
            desired: p.desired.clone(),
            parameters: Self::parameters(&p.model, p.target),
        })
    }

    /// The device's parameter values in `model`.
    fn parameters(
        model: &Model,
        target: IndividualAddress,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        model
            .devices
            .get(&target)
            .map(|d| d.device.parameters.clone())
    }

    /// Whether the model the server serves now still holds what the yes was
    /// given for.
    fn holds(&self, server: &BussardMcp) -> bool {
        let model = server.state().model.reload();
        let product = product_for(&server.state().dir, &model, self.target);
        let desired = program::plan::desired_tables(&model, self.target, product.source.as_ref());
        desired.is_ok_and(|d| d == self.desired)
            && Self::parameters(&model, self.target) == self.parameters
    }
}

/// What an apply whose pre-flight passed carries into its write.
struct Prepared {
    /// Where the desired tables came from (issue #717).
    origin: Origin,
    /// The model the plan was made from (the read-back compares with it).
    model: std::sync::Arc<Model>,
    /// The product data the parameters are decoded with, when the lock pins
    /// it (a flash takes it for its own read-back).
    product: Option<ProductSource>,
    /// The device.
    target: IndividualAddress,
    /// The resolved gateway, for the audit line.
    gateway: String,
    /// The model directory.
    dir: std::path::PathBuf,
    /// The checked source address.
    source: IndividualAddress,
    /// The Data Secure tool key, `None` on the plain path.
    tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared by the read and the write.
    high_water: SequenceHighWater,
    /// The model's tables for the device.
    desired: DesiredTables,
    /// The table plan.
    report: PlanReport,
    /// The device plan with its parameter half.
    built: BuiltPlan,
    /// The pre-flight read.
    read: DeviceRead,
    /// The security-object inputs, on the secured System B path.
    security: Option<SecurityInputs>,
    /// The System 7 table images, when a System 7 device's links change.
    images: Option<bussard_download::Sys7TableImages>,
    /// The audit snapshot's id.
    snapshot: Option<String>,
    /// The table backup.
    backup_path: String,
    /// The parameter backup, when parameters are written.
    param_backup_path: Option<String>,
    /// The full download, when the plan says `method: flash` (issue #303).
    flash: Option<FlashImage>,
    /// The result so far (address, gateway, backups, snapshot).
    result: Value,
}

/// Where a write's desired tables came from: the model's device file
/// (`knx_apply_device`) or a backup (`knx_restore_tables`, issue #717), as
/// the CLI's `apply` and `restore` share one write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The model's links.
    Model,
    /// A backup file's tables.
    Backup,
}

impl Origin {
    /// The tool that writes it, for the audit line.
    fn tool(self) -> &'static str {
        match self {
            Origin::Model => "knx_apply_device",
            Origin::Backup => "knx_restore_tables",
        }
    }

    /// What the read-back compares with.
    fn truth(self) -> &'static str {
        match self {
            Origin::Model => "the model",
            Origin::Backup => "the backup",
        }
    }

    /// The tool that plans it again.
    fn planner(self) -> &'static str {
        match self {
            Origin::Model => "knx_plan_device",
            Origin::Backup => "knx_restore_tables (without plan_digest)",
        }
    }
}

/// The `next_step` of an apply that finished within its call.
fn inline_next_step(job: &str, target: IndividualAddress, result: &Value) -> String {
    format!(
        "{}{}",
        inline_outcome_step(job, target, result),
        declared_step(result)
    )
}

/// The sentence naming the group addresses an apply declared in
/// `groups.toml` (issue #779), empty when it declared none.
fn declared_step(result: &Value) -> &'static str {
    match result["declared"].as_array() {
        Some(declared) if !declared.is_empty() => {
            " Before writing, it added to groups.toml the group addresses the device files use \
             but did not define (result.declared); name each one to the human."
        }
        _ => "",
    }
}

/// The outcome half of [`inline_next_step`].
fn inline_outcome_step(job: &str, target: IndividualAddress, result: &Value) -> String {
    if result["ok"] == true {
        // The table backup taken before the write (issue #717): the way back.
        let undo = if result["backup"].is_string() {
            format!(
                " To undo it, knx_restore_tables with address {target} (no backup argument) \
                 plans writing those pre-write tables back."
            )
        } else {
            String::new()
        };
        format!(
            "The write finished within this call (job {job}). Tell the human the outcome and \
             the backup paths; knx_apply_status with job {job} or knx_last_apply with address \
             {target} returns this result again.{undo}"
        )
    } else {
        format!(
            "The write ended without verifying (job {job}). Tell the human the reason, the \
             recovery and the backup paths; knx_last_apply with address {target} returns this \
             result again."
        )
    }
}

/// The `security_object` field of a plan or apply result: what the security
/// object receives, or `null` on the plain path and for a plan with nothing
/// to write. Addresses and object numbers only, never a key.
fn security_json(security: Option<&SecurityInputs>, desired: &DesiredTables, noop: bool) -> Value {
    match security {
        Some(inputs) if !noop => json!({
            "summary": inputs.describe(&desired.addresses),
            "secure_senders": inputs
                .senders
                .iter()
                .map(|e| json!({"address": e.address.to_string(), "sequence": e.sequence}))
                .collect::<Vec<_>>(),
            "keyed_groups": inputs
                .keyed(&desired.addresses)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "secured_objects": inputs.secure_objects.iter().collect::<Vec<_>>(),
        }),
        _ => Value::Null,
    }
}

/// What a plan or apply call names: one device or a whole line.
enum Target<'a> {
    /// `address`.
    Device(&'a str),
    /// `line`.
    Line(&'a str),
}

/// What a job of the tier plans or writes: one device, or every device on
/// a line.
#[derive(Debug, Clone)]
enum Subject {
    /// One device.
    Device(IndividualAddress),
    /// A line (`"1.1"`) and its coupler's address, the job's address.
    Line(String, IndividualAddress),
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subject::Device(target) => write!(f, "{target}"),
            Subject::Line(line, _) => write!(f, "line {line}"),
        }
    }
}

impl Subject {
    /// The address the job is claimed for.
    fn at(&self) -> IndividualAddress {
        match self {
            Subject::Device(at) | Subject::Line(_, at) => *at,
        }
    }

    /// The tool that reports the job.
    fn poll(&self) -> &'static str {
        match self {
            Subject::Device(_) => "knx_apply_status",
            Subject::Line(..) => "knx_job_status",
        }
    }

    /// The `started: true` answer of a plan job still reading.
    fn plan_started(&self, job: &str) -> Value {
        let (key, value, step, read, poll) = match self {
            Subject::Device(target) => (
                "address",
                target.to_string(),
                "reading the device",
                format!(
                    "Reading {target} takes longer than this call may wait (a Data Secure \
                     device reads its whole parameter memory)"
                ),
                "knx_apply_status",
            ),
            Subject::Line(line, _) => (
                "line",
                line.clone(),
                "reading the devices on the line",
                format!("Reading every device on line {line} takes longer than this call may wait"),
                "knx_job_status",
            ),
        };
        let what = match self {
            Subject::Device(_) => "plan",
            Subject::Line(..) => "line plan",
        };
        json!({
            "started": true,
            "done": false,
            "kind": "plan",
            "job": job,
            key: value,
            "step": step,
            "next_step": format!(
                "{read}; the plan is computed in the server as job {job}, and nothing is \
                 written. Tell the human the read is running, then call {poll} with job {job} \
                 every few seconds until `done` is true. Its `result` is the {what}: show it to \
                 the human and follow result.next_step. Do not call knx_apply_device before you \
                 have shown that plan."
            ),
        })
    }
}

/// The one target of a call that takes `address` or `line`; `Err` when it
/// names both or neither.
fn target_of<'a>(address: Option<&'a str>, line: Option<&'a str>) -> Result<Target<'a>, String> {
    let given = |v: Option<&'a str>| v.map(str::trim).filter(|v| !v.is_empty());
    match (given(address), given(line)) {
        (Some(address), None) => Ok(Target::Device(address)),
        (None, Some(line)) => Ok(Target::Line(line)),
        (Some(_), Some(_)) => Err("pass either `address` or `line`, not both".into()),
        (None, None) => {
            Err("pass a device `address`, or a `line` (e.g. \"1.1\") for every device on it".into())
        }
    }
}

/// Parses an individual address argument.
fn parse_address(address: &str) -> Result<IndividualAddress, String> {
    address
        .trim()
        .parse()
        .map_err(|_| format!("invalid individual address {address:?}"))
}

/// Refuses a plan for a device the model puts, without KNX Data Secure, on a
/// group address the other side runs secured (validation errors E035 and
/// E036, issue #330): the download would succeed and the link would not work.
fn refuse_insecure_links(model: &Model, target: IndividualAddress) -> Result<(), String> {
    let found: Vec<String> = bussard_model::secure_link_conflicts(model)
        .iter()
        .filter(|c| c.device == target)
        .map(|c| format!("{}: {}", c.code(), c.message()))
        .collect();
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "refusing to plan {target}: its links would not work. {}. Fix the model \
             (knx_remove_link, or the ways out above) and plan again",
            found.join("; ")
        ))
    }
}

/// Refuses a plan whose additions or removals touch a protected GA
/// ([`program::plan::protected_refusal`]).
fn refuse_protected(model: &Model, report: &PlanReport) -> Result<(), String> {
    program::plan::protected_refusal(model, report).map_or(Ok(()), Err)
}

/// The product data for the parameter half of `target`'s plan, or why there
/// is none. A pinned archive that is missing or changed does not refuse the
/// plan: it refuses the parameter part, with its recovery line, and the links
/// are still planned (issue #274).
pub(crate) struct ProductFor {
    /// The product data, when the lock pins an intact archive.
    pub(crate) source: Option<ProductSource>,
    /// Why the parameters are not compared, when the lookup failed.
    pub(crate) refusal: Option<String>,
}

/// Resolves the product data for `target` the way `bussard apply` does,
/// warning instead of refusing (see [`ProductFor`]).
pub(crate) fn product_for(
    dir: &std::path::Path,
    model: &Model,
    target: IndividualAddress,
) -> ProductFor {
    match resolve_product(
        dir,
        Selection::default(),
        Some(model),
        target,
        MissingProduct::Warn,
        None,
    ) {
        Ok(lookup) => ProductFor {
            source: lookup.source,
            refusal: lookup
                .warning
                .map(|w| format!("parameters not compared: {w}")),
        },
        Err(err) => ProductFor {
            source: None,
            refusal: Some(format!("parameters not compared: {err}")),
        },
    }
}

/// What one read of a device returned ([`program::read`]).
type DeviceRead = program::read::DeviceRead<LiveTables>;

/// What a read of the programming tier covers besides the device.
struct Read<'a> {
    /// The tool key, `None` on the plain path.
    tool_key: &'a Option<Key16>,
    /// The device's factory key: a device reset to default is named, not
    /// read under it (issue #532).
    factory_key: &'a Option<Key16>,
    /// The send-sequence high-water mark of the read and the write.
    high_water: &'a SequenceHighWater,
    /// The model.
    model: &'a Model,
    /// The product data the parameters are decoded with.
    product: Option<&'a ProductSource>,
    /// The admitted tunnelling addresses (PID 54 is read when any).
    tunnel: &'a [IndividualAddress],
    /// The PID 61 cache.
    flags_cache: FlagsCache<'a>,
}

/// Checks the source address (once per tunnel instance, issue #341), then
/// reads the device on one layer-4 session ([`program::read::read_device`],
/// the read `bussard plan` and `bussard apply` make): the facts and the
/// identity verdict, the live tables, with `product` the parameter memory,
/// PID 54 and PID 61. Returns the checked source for the write phase.
async fn read_device(
    service: &BusService,
    target: IndividualAddress,
    dir: &std::path::Path,
    read: Read<'_>,
) -> Result<(IndividualAddress, DeviceRead), String> {
    let source = service.checked_source(false).await?;
    // Authorize (free access) before reading, best-effort, skipped for a
    // device whose facts record that it never answers (issues #215, #761).
    let mut facts = FactsCache::new(dir, false);
    let options = L4Options::secured(source, read.tool_key.clone(), read.high_water.clone())
        .with_factory_key(read.factory_key.clone())
        .with_authorize(bussard_service::status::read_only_authorize(
            &mut facts, target,
        ));
    let request = ReadRequest {
        target,
        model: Some(read.model),
        product: read.product,
        facts: &facts,
        tunnel: read.tunnel,
        secured: read.tool_key.is_some(),
        flags_cache: read.flags_cache,
        properties: None,
    };
    let device = program::read::read_device(service, &options, &request)
        .await
        .map_err(|err| match err {
            ReadError::Open(ServiceError::Lease(e)) => format!("could not lease the bus: {e}"),
            ReadError::Open(ServiceError::SourceCheck(e)) => chain(&e),
            ReadError::Open(e) => format!("connecting to {target}: {e}"),
            e => chain(&e),
        })?;
    match device.into_tables() {
        Ok(device) => Ok((source, device)),
        Err((address, mask)) => Err(format!(
            "{address} reports mask {mask:04X} ({}); programming supports the System B (x7B0) \
             and System 7 (0705 / 0701) families; on this mask bussard can: {}",
            bussard_mgmt::system_type(mask),
            bussard_mgmt::MaskProfile::from_mask(mask)
                .capabilities()
                .summary()
        )),
    }
}

/// What `knx_reconstruct_device` reads (issue #717): the live tables, the
/// identity verdict and, with `product`, the parameter read-back, on the one
/// session [`read_device`] opens for `knx_plan_device`. Read-only.
pub(crate) async fn read_for_reconstruct(
    service: &BusService,
    target: IndividualAddress,
    keys: (&Option<Key16>, &Option<Key16>),
    dir: &std::path::Path,
    model: &Model,
    product: Option<&ProductSource>,
) -> Result<
    (
        LiveTables,
        Option<bussard_model::identity::IdentityCheck>,
        Option<bussard_service::params::ParamState>,
    ),
    String,
> {
    let (tool_key, factory_key) = keys;
    let (_, read) = read_device(
        service,
        target,
        dir,
        Read {
            tool_key,
            factory_key,
            high_water: &SequenceHighWater::new(),
            model,
            product,
            tunnel: &[],
            flags_cache: FlagsCache::Off,
        },
    )
    .await?;
    let check = read.check().cloned();
    Ok((read.live, check, read.params))
}

/// Reads the properties a property-only load procedure writes (issue #390)
/// in one read-only session to `target`.
async fn read_property_rows(
    service: &BusService,
    target: IndividualAddress,
    tool_key: &Option<Key16>,
    plan: &bussard_download::FlashPlan,
) -> Result<Vec<bussard_service::property_plan::PropertyRow>, String> {
    let source = service.checked_source(false).await?;
    let options = L4Options::secured(source, tool_key.clone(), SequenceHighWater::new());
    service
        .with_l4(target, &options, async |l4| {
            Ok::<_, ServiceError>(
                bussard_service::property_plan::read_property_rows(l4, plan).await,
            )
        })
        .await
        .map_err(|err| match err {
            ServiceError::Lease(e) => format!("could not lease the bus: {e}"),
            e => format!("connecting to {target}: {e}"),
        })
}

/// What a plan of one device is computed from, besides the read: the plan
/// `knx_plan_device` shows and `knx_apply_device` re-derives.
struct PlanCtx<'a> {
    /// The model.
    model: &'a Model,
    /// The device.
    target: IndividualAddress,
    /// The gateway.
    gateway: &'a str,
    /// The model directory.
    dir: &'a std::path::Path,
    /// The model's tables for the device.
    desired: &'a DesiredTables,
    /// The admitted tunnelling addresses.
    tunnel: &'a [IndividualAddress],
    /// The Data Secure material.
    material: &'a SecureMaterial,
    /// The product data the lock pins.
    product: &'a ProductFor,
}

impl PlanCtx<'_> {
    /// The plan ([`program::plan::plan_device`]): the table plan, the
    /// device plan with its parameter half (a failed product lookup is a
    /// note and leaves the parameters out), the tunnel admission and the
    /// security-object change.
    fn planned(&self, read: &DeviceRead) -> Planned {
        program::plan::plan_device(
            &PlanInputs {
                model: self.model,
                target: self.target,
                gateway: self.gateway,
                dir: self.dir,
                desired: self.desired,
                tunnel: self.tunnel,
                group_keys: self.material.group_keys.as_ref(),
                parameters_skipped: self.product.refusal.as_deref(),
            },
            read,
        )
    }

    /// The security object a secured System B write reprograms, as `bussard
    /// apply --keyring` derives it; `None` on the plain path and on System 7.
    /// A group address the model marks `secure` without a key refuses here,
    /// before anything is asked or written.
    fn security(&self, read: &DeviceRead) -> Result<Option<SecurityInputs>, String> {
        security_for(
            self.model,
            self.target,
            self.desired,
            self.material,
            &read.live,
            self.tunnel,
            self.dir,
        )
    }

    /// The full download the plan writes, when the application must be
    /// loaded (`load`, issue #750) or a parameter change reshapes the
    /// group-object table (issue #303).
    fn flash(
        &self,
        read: &DeviceRead,
        report: &PlanReport,
        load: Option<&program::flash::LoadNeed>,
        built: &BuiltPlan,
    ) -> Result<Option<FlashImage>, String> {
        let need = match (load, &built.needs_flash) {
            (Some(need), _) => FlashNeed::Load(need),
            (None, Some(_)) => FlashNeed::Parameters(built),
            (None, None) => return Ok(None),
        };
        program::flash::flash_image(
            &FlashFor {
                dir: self.dir,
                model: self.model,
                target: self.target,
                read,
                report,
                product: self.product.source.as_ref(),
                material: self.material,
                tunnel: self.tunnel,
            },
            need,
        )
        .map(Some)
    }
}

/// The security object of a secured System B write of `desired`
/// ([`program::plan::security_inputs`]); `None` without a tool key and on
/// System 7, whose security object a table write does not reprogram.
fn security_for(
    model: &Model,
    target: IndividualAddress,
    desired: &DesiredTables,
    material: &SecureMaterial,
    live: &LiveTables,
    tunnel: &[IndividualAddress],
    dir: &std::path::Path,
) -> Result<Option<SecurityInputs>, String> {
    if live.sys7().is_some() {
        return Ok(None);
    }
    program::plan::security_inputs(Some(model), target, desired, material, &[], tunnel, dir)
        .map_err(|e| match e {
            bussard_download::SecurityPlanError::OverCapacity { .. } => {
                format!("{target}'s security object cannot be programmed: {e}")
            }
            e => format!(
                "{target}'s security object cannot be programmed: {e}; export a current keyring \
                 from ETS or fix the group's `secure` flag in groups.toml"
            ),
        })
}

/// The model's side of a plan digest
/// ([`program::plan::model_fingerprint`]), extended with the flash image so
/// the digest binds the exact octets a flash writes.
fn model_fingerprint(
    ctx: &PlanCtx<'_>,
    security: Option<&SecurityInputs>,
    built: &BuiltPlan,
    flash: Option<&FlashImage>,
) -> [u8; 32] {
    let model =
        program::plan::model_fingerprint(ctx.model, ctx.target, ctx.desired, security, built);
    flash.map_or(model, |image| image.fingerprint(model))
}

/// The lock records of a verified secured write, as result fields.
fn record_json(result: &mut Value, record: &bussard_service::flash_flow::LockRecord) {
    for (recorded, key, note) in [
        (
            &record.senders,
            "secure_senders_recorded",
            "secure_senders_note",
        ),
        (
            &record.flags,
            "security_flags_recorded",
            "security_flags_note",
        ),
    ] {
        match recorded {
            Some((Ok(recorded), _)) => result[key] = json!(recorded),
            Some((Err(err), _)) => {
                tracing::warn!("{err}");
                result[key] = json!(false);
                result[note] = json!(err);
            }
            None => {}
        }
    }
}

/// Refuses a device whose identity drifted from the lock, naming the
/// `bussard flash` it needs (the CLI's `apply` rule). A System 7 device has
/// no readable application id: code that differs from the pinned product's
/// is its drift (issue #314).
fn refuse_drift(target: IndividualAddress, read: &DeviceRead) -> Result<(), String> {
    if let Some(refusal) = read
        .check()
        .and_then(|check| bussard_service::drift_refusal(target, check, "write"))
    {
        return Err(refusal);
    }
    if let Some(bussard_download::Sys7Identity::Resident { reason }) =
        read.params.as_ref().and_then(|p| p.sys7_identity.as_ref())
    {
        return Err(format!(
            "{target} does not run the application bussard.lock pins: {reason}; replacing it \
             is `bussard flash --force {target}` at the CLI"
        ));
    }
    Ok(())
}

/// The plan note of a flash (issue #303).
fn flash_note(target: IndividualAddress) -> String {
    let (min, max) = bussard_service::flash::DEVICE_OFFLINE_SECONDS;
    format!(
        "method: flash. The parameter values change the group-object table, which only a full \
         download writes: {target} gets the application, its parameters and its tables as \
         `bussard flash {target} --yes` writes them, restarts, and is offline for {min} to \
         {max} s. Its parameter memory is backed up first."
    )
}

/// The question of a flash plan: the human's yes must be a yes to flashing.
fn flash_question(target: IndividualAddress, gateway: &str, changes: usize) -> String {
    let (min, max) = bussard_service::flash::DEVICE_OFFLINE_SECONDS;
    format!(
        "flash {target} through {gateway} to write {}? The device restarts and is offline for \
         {min} to {max} s.",
        if changes == 1 {
            "this change".to_string()
        } else {
            format!("these {changes} changes")
        }
    )
}

/// The plan note of a load (issue #750): why, and what the download does.
/// With `links_after` (issue #779) the links follow the download as `bussard
/// apply` writes them.
fn load_note(
    target: IndividualAddress,
    why: &str,
    plan: &bussard_download::FlashPlan,
    links_after: bool,
) -> String {
    let (min, max) = bussard_service::flash::DEVICE_OFFLINE_SECONDS;
    let reset = if plan.has_factory_reset() {
        ", after a factory reset that erases what it runs now"
    } else {
        ""
    };
    if links_after {
        return format!(
            "method: flash. The application program must be loaded: {why}. {target} gets {} \
             with the model's parameters as `bussard flash {target} --yes` writes them{reset}, \
             restarts, and is offline for {min} to {max} s; the download is read back and \
             compared with the model. {}",
            plan.identity.id,
            links_after_note(target, plan)
        );
    }
    format!(
        "method: flash. The application program must be loaded: {why}. {target} gets {} with \
         the model's parameters and tables as `bussard flash {target} --yes` writes them{reset}, \
         restarts, and is offline for {min} to {max} s; the result is read back and compared \
         with the model.",
        plan.identity.id,
    )
}

/// The plan note of a download that writes no link table while the links
/// differ (issue #779): the table write that follows it.
fn links_after_note(target: IndividualAddress, plan: &bussard_download::FlashPlan) -> String {
    format!(
        "The download of {} does not write the link tables, so once it verified the same job \
         writes {target}'s links as `bussard apply {target}` does and reads them back; the \
         result is verified only when that read-back matches the model.",
        plan.identity.id
    )
}

/// The question of a load plan: the human's yes must be a yes to loading.
fn load_question(
    target: IndividualAddress,
    gateway: &str,
    plan: &bussard_download::FlashPlan,
    links_after: bool,
) -> String {
    let (min, max) = bussard_service::flash::DEVICE_OFFLINE_SECONDS;
    let what = if links_after {
        "with the model's parameters, then write its links"
    } else {
        "and write the model's parameters and links with it"
    };
    format!(
        "load application {} into {target} through {gateway} {what}? The device restarts and is \
         offline for {min} to {max} s.",
        plan.identity.id
    )
}

/// The `parameters` field of a plan: what differs, by key, vendor text,
/// device value and model value, and whether it is written.
fn parameters_json(built: &BuiltPlan) -> Value {
    json!({
        "compared": built.parameters_skipped.is_none() || !built.parameters.is_empty(),
        "changed": built.parameters,
        "octets": built.plan.writes.parameter_octets,
        "octet_ranges": built.octet_ranges,
        "written": built.partial.is_some(),
        "skipped": built.parameters_skipped,
    })
}

/// The audit line, as `bussard apply` records it: a history snapshot before
/// the bus write (`None` without model files); `Err` refuses the write of
/// `what`.
fn audit_snapshot(
    dir: &std::path::Path,
    reason: SnapshotReason,
    what: impl std::fmt::Display,
) -> Result<Option<String>, String> {
    let history = History::open(dir);
    if !history.has_model_files() {
        return Ok(None);
    }
    history
        .snapshot(reason)
        .map(|id| Some(id.to_string()))
        .map_err(|err| {
            format!("refusing to write {what}: the audit snapshot could not be recorded ({err})")
        })
}

/// How a refusal of a device plan says to get a new one.
fn again(target: IndividualAddress) -> String {
    format!("call knx_plan_device for {target}, show the plan to the human and ask again")
}

impl ProgrammingTier {
    /// Remembers the plan of `target` with `sides` and returns its digest
    /// ([`program::plan::plan_digest`]).
    fn remember_plan(&self, target: IndividualAddress, sides: PlanSides) -> String {
        let digest = program::plan::plan_digest(target, &sides.model, &sides.live);
        self.plans.insert(digest.clone(), target, sides);
        digest
    }
}

/// `text`, followed by the group addresses the apply declared in
/// `groups.toml` first, for the audit snapshot's result line.
fn with_declared(text: &str, declared: &[String]) -> String {
    if declared.is_empty() {
        return text.to_string();
    }
    format!("{text}; {}", declared.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_digest_binds_the_device() -> Result<(), String> {
        let digest = |a: &str| -> Result<String, String> {
            Ok(program::plan::plan_digest(
                parse_address(a)?,
                &[2; 32],
                &[1; 32],
            ))
        };
        assert_ne!(digest("1.1.4")?, digest("1.1.5")?);
        assert_eq!(digest("1.1.4")?.len(), 64);
        Ok(())
    }
}
