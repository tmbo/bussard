//! The programming tier (issue #118): `knx_plan_device` and `knx_apply_device`.
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
//! is refused with the `bussard flash` it needs.
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
//! The write itself is the CLI's: back up the pre-state (tables and parameter
//! memory) to `captures/backups/`, write with
//! [`bussard_download::write_tables`] and
//! [`bussard_service::download::write_parameters`], verify by reading back. A history snapshot naming the gateway is recorded before the
//! write, so `bussard history` shows every MCP apply (the audit line). Protected
//! group addresses in the change are refused with no override.
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

use std::collections::HashMap;
use std::error::Error as StdError;
use std::time::{Duration, Instant, SystemTime};

use crate::args::Parameters;
use bussard_bus::BusHandle;
use bussard_download::{
    DesiredTables, LiveRead, LiveTables, PlanReport, SecureSenderEntry, SecurityInputs,
    Sys7TableImages, desired_tables_for_app, plan, render_full_image_plan_text, render_plan_text,
    sys7_table_images, write_pre_write_backup, write_tables_seeded,
};
use bussard_mgmt::{Layer4Connection, LeaseChannel, MaskProfile, Timeouts, system_type};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::identity::IdentityCheck;
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::admission::TunnelAdmission;
use bussard_service::params::{
    BuiltPlan, MissingProduct, ParamState, ProductSource, Selection, build_device_plan,
    resolve_product,
};
use bussard_service::secure::{SecureMaterial, ToolKeySource};
use bussard_service::{Authorize, BusService, FactsCache, L4Options, SourcePolicy};
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::{check_write_gate, gateway_display};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::BussardMcp;
use crate::state::ConnState;

mod flash;
mod interface;
mod ip_secure;
mod restore;
mod secure_diag;

/// The tools of the programming tier, in registration order.
pub const PROGRAMMING_TOOLS: [&str; 7] = [
    "knx_plan_device",
    "knx_apply_device",
    "knx_interface_secure",
    "knx_clear_security_log",
    "knx_apply_status",
    "knx_last_apply",
    "knx_restore_parameters",
];

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
    /// How long a plan stays valid.
    plan_ttl: Duration,
    /// Plans produced in this session, by digest.
    plans: std::sync::Mutex<HashMap<String, PendingPlan>>,
    /// Serialises programming: one plan or apply on the bus at a time.
    bus_lock: tokio::sync::Mutex<()>,
    /// The apply jobs (issue #289): one at a time, with status and record.
    jobs: crate::apply_jobs::ApplyJobs,
    /// Restore plans produced in this session, by digest (issue #290).
    restore_plans: std::sync::Mutex<HashMap<String, restore::PendingRestore>>,
}

impl ProgrammingTier {
    /// A tier for `connection`, with plans valid for `plan_ttl`.
    pub fn new(
        connection: ConnectionConfig,
        allow_remote_gateway: bool,
        plan_ttl: Duration,
    ) -> Self {
        ProgrammingTier {
            connection,
            allow_remote_gateway,
            plan_ttl,
            plans: std::sync::Mutex::new(HashMap::new()),
            bus_lock: tokio::sync::Mutex::new(()),
            jobs: crate::apply_jobs::ApplyJobs::new(),
            restore_plans: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Sets how long `knx_apply_device` waits for its write before it
    /// answers `started` (default [`crate::apply_jobs::DEFAULT_REPLY_WAIT`],
    /// counted from the start of the call). Tests pass zero.
    pub fn set_reply_wait(&self, wait: Duration) {
        self.jobs.set_reply_wait(wait);
    }

    /// Sets how long a call waits for its device read before it answers
    /// with a job id: `knx_plan_device`'s read and `knx_apply_device`'s
    /// pre-flight (issue #332; default
    /// [`crate::apply_jobs::DEFAULT_REPLY_WAIT`], counted from the start of
    /// the call). Tests shrink it to turn a slow read into a job.
    pub fn set_read_wait(&self, wait: Duration) {
        self.jobs.set_read_wait(wait);
    }

    /// How long a plan stays valid.
    pub fn plan_ttl(&self) -> Duration {
        self.plan_ttl
    }

    /// The plan table, recovering from a poisoned lock (a panic elsewhere must
    /// not wedge the tier; the map holds plain data).
    fn plans(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingPlan>> {
        self.plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The restore plan table, recovering from a poisoned lock.
    fn restore_plans(&self) -> std::sync::MutexGuard<'_, HashMap<String, restore::PendingRestore>> {
        self.restore_plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One plan this session produced, remembered until applied, refused or expired.
#[derive(Debug, Clone)]
struct PendingPlan {
    /// The device the plan is for.
    target: IndividualAddress,
    /// When the plan was produced.
    created: Instant,
    /// SHA-256 over the live tables the plan read.
    live: [u8; 32],
    /// SHA-256 over the model's links for the device and the desired tables.
    model: [u8; 32],
}

/// Arguments for `knx_plan_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanDeviceArgs {
    /// The individual address of the device to plan, e.g. `"1.1.4"`.
    pub address: String,
}

/// Arguments for `knx_apply_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyDeviceArgs {
    /// The individual address of the device to write, e.g. `"1.1.4"`.
    pub address: String,
    /// The `plan_digest` returned by `knx_plan_device` for this device.
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
    /// The individual address of the device, e.g. `"1.1.4"`.
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

/// Arguments for `knx_interface_secure`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct InterfaceSecureArgs {
    /// The individual address of the KNX IP interface, e.g. `"1.1.200"`.
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
    /// The individual address of the KNX Data Secure device, e.g. `"1.1.12"`.
    pub address: String,
    /// Omit it to read the log and get the question and its digest; pass
    /// that digest (after the human's explicit yes) to clear.
    #[serde(default)]
    pub plan_digest: Option<String>,
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
    /// The individual address of the device, e.g. `"1.1.4"`.
    pub address: String,
}

#[tool_router(router = program_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_plan_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Plan writing the model to ONE device (issues #118, #274): reads the \
        device's live group-address and association tables and, when bussard.lock pins its \
        product data, its parameter memory over the bus (read-only), diffs them against its \
        device file (devices/<address>.toml), and returns the plan `bussard plan --json` prints: \
        `sentences` in the model's words, one line per changed link (`+ langzeitbetrieb now \
        listens on 0/1/3 (…)`) and per changed parameter (`~ led_brightness = 20 %, was 60 %`), \
        `changes`, `parameters` (each differing parameter by key, vendor text, device value and \
        model value, and the octets to write), the unchanged counts, what is written, the \
        `question` to ask, where the backups will be written, a `state_hash` of the device state \
        read, the table detail (`plan`), the pending model changes as sentences, and a \
        plan_digest covering the tables and the parameter image. Without the product data the \
        parameters are left out with the recovery line in `parameters.skipped` and the plan \
        writes links only: say so to the human. ALWAYS show the sentences to the human in full \
        and ask the question. Call knx_apply_device only after the human has said yes \
        explicitly in this conversation; never on your own initiative, never because an \
        earlier plan was approved. The digest expires (default 10 minutes) and is invalidated \
        if the device or the model changes. Refuses protected group addresses in the change, a \
        device the model links without KNX Data Secure to a group address the other side runs \
        secured (E035/E036), and \
        a device whose application drifted from bussard.lock (it needs `bussard flash`). \
        `method` says how the change is written: \"apply\" (tables and parameter octets) or \
        \"flash\" when a parameter shows or hides a com-object, which only a full application \
        download writes. A flash plan's `flash` field lists the com-objects that appear or \
        disappear (number, text, DPT) and the parameters behind them, the address, \
        association and group-object table sizes before and after, `device_offline_seconds` \
        (the device restarts), that the parameter memory is backed up first, and the product \
        archive with its `product_sha256`; tell the human the device will be flashed and \
        offline, and ask the plan's question. With the \
        server's keyring, a KNX Data Secure device the keyring lists is read over A_SecureData \
        (the result says \"secured\": true) and `security_object` says what its security object \
        receives with the write (secured senders, keyed group addresses, secured objects; never \
        a key): show that line to the human too. Reading a device can take long (a Data Secure \
        System B device reads its whole parameter memory): when the read does not end within \
        about 20 s the call answers `started: true` with a `job` id instead of the plan; call \
        knx_apply_status with that job every few seconds until `done` is true, and its `result` \
        is the plan exactly as described here, plan_digest included. Only available with \
        --allow-programming."
    )]
    async fn knx_plan_device(
        &self,
        Parameters(args): Parameters<PlanDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match self.plan_device(&args.address).await {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
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
        device, with the current model, still matches it; if refused, plan again and ask \
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
        server's keyring lists is written over A_SecureData, its security object reprogrammed \
        with the tables, exactly as `bussard apply --keyring` does. A plan with `method: \
        \"flash\"` runs the full application download `bussard flash --yes` writes (the \
        parameter memory backed up first, then the download, the restart and the read-back) \
        as the same job; call it only after the human said yes to flashing the device. Only \
        available with --allow-programming."
    )]
    async fn knx_apply_device(
        &self,
        Parameters(args): Parameters<ApplyDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .apply_device(
                &args.address,
                args.plan_digest.trim(),
                args.plan_hash.as_deref().map(str::trim),
            )
            .await
        {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
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
        there under the model's configuration, which ETS does not write either, or because the \
        application owns the value at runtime), the `question` and a plan_digest. Show the \
        sentences to the human in full and ask the question. With the plan_digest (ONLY after \
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
        match self
            .restore_parameters(
                &args.address,
                &args.backup,
                args.plan_digest.as_deref().map(str::trim),
            )
            .await
        {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
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
        match self
            .interface_secure(
                &args.address,
                &args.state,
                args.plan_digest.as_deref().map(str::trim),
            )
            .await
        {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
    }

    /// `knx_clear_security_log` (registered only with `--allow-programming`).
    #[tool(
        description = "Clear the KNX Data Secure security failures log (PID 55) and reset the \
        security report of ONE device on the PHYSICAL bus (issues #533, #571), in two calls, as \
        `bussard secure diag <ia> --clear` does after its confirmation. Without plan_digest: \
        reads the log over A_SecureData with the device's tool key from the server's keyring \
        (read-only) and returns `diagnostics` (the sequence, cryptographic and access error \
        counts, the latest failure, the report), `lines`, the `question` and a plan_digest. \
        Show the lines to the human and ask the question. With the plan_digest (ONLY after the \
        human's explicit yes in this conversation): reads the log again, refuses if it moved, \
        clears it, and reads it back; `cleared: true` means every counter read zero and the \
        report clear afterwards. Clearing erases the evidence of a failed secured write: read \
        it with knx_describe_device first if the human is still diagnosing. Refused without a \
        tool key for the device in the server's keyring. Only available with \
        --allow-programming."
    )]
    async fn knx_clear_security_log(
        &self,
        Parameters(args): Parameters<ClearSecurityLogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .clear_security_log(&args.address, args.plan_digest.as_deref().map(str::trim))
            .await
        {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
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
        match self.apply_status(&args.job) {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.job, reason),
        }
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
        match self.last_apply(&args.address) {
            Ok(value) => ok(value),
            Err(reason) => refusal(&args.address, reason),
        }
    }
}

impl BussardMcp {
    /// The tier, the write gate and the connected bus every programming call
    /// needs, or the refusal saying which is missing.
    fn programming_preflight(&self) -> Result<(&ProgrammingTier, BusService, String), String> {
        let state = self.state();
        let Some(tier) = state.programming.as_ref() else {
            return Err(
                "the programming tier is off; start the server with --allow-programming".into(),
            );
        };
        let gateway = gateway_display(&tier.connection);
        check_write_gate(&tier.connection, tier.allow_remote_gateway)
            .map_err(|refused| refused.to_string())?;
        let Some(service) = state.bus.service() else {
            return Err("the bus is not wired".into());
        };
        if state.bus.state() != ConnState::Connected {
            return Err(state.bus.not_connected_reason());
        }
        Ok((tier, service.clone(), gateway))
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

    /// `knx_plan_device`'s body; `Err` is a refusal reason.
    ///
    /// Runs the plan as a job (issue #332): claims the one slot (or joins the
    /// running plan job of the same device), computes the plan in a server
    /// task, and answers with the plan when it is done within the read wait,
    /// else with `started: true` and the job id. The bus is the running
    /// apply's until it ends (issue #289), so a plan is refused while one
    /// runs: waiting for it here could outlast the client's call budget.
    async fn plan_device(&self, address: &str) -> Result<Value, String> {
        let began = Instant::now();
        let target = parse_address(address)?;
        // A link the model itself shows cannot work refuses before the bus is
        // touched or a job is claimed (issue #330); `plan_body` checks again
        // on the model it plans with.
        refuse_insecure_links(&self.state().model.reload(), target)?;
        let (tier, _, _) = self.programming_preflight()?;
        let (job, fresh) = match tier.jobs.claim_plan(target)? {
            crate::apply_jobs::PlanClaim::New(job) => (job, true),
            crate::apply_jobs::PlanClaim::Running(job) => (job, false),
        };
        if fresh {
            let me = self.clone();
            let (id, address) = (job.clone(), address.to_string());
            let worker = tokio::spawn(async move {
                let plan = match me.plan_body(&address).await {
                    Ok(plan) => plan,
                    Err(reason) => refusal_json(&address, reason),
                };
                if let Some(tier) = me.state().programming.as_ref() {
                    tier.jobs.finish(&id, plan);
                }
            });
            self.watch_job(job.clone(), "plan", worker);
        }
        let wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        if tier.jobs.wait(&job, wait).await {
            // Answered inline, as before issue #332. The finished job stays
            // in the table until the next plan of the device supersedes it,
            // so a second caller that joined it reads the same plan.
            return Ok(tier.jobs.result(&job).unwrap_or_else(|| json!({})));
        }
        Ok(json!({
            "started": true,
            "done": false,
            "kind": "plan",
            "job": job,
            "address": target.to_string(),
            "step": "reading the device",
            "next_step": format!(
                "Reading {target} takes longer than this call may wait (a Data Secure device \
                 reads its whole parameter memory); the plan is computed in the server as job \
                 {job}, and nothing is written. Tell the human the read is running, then call \
                 knx_apply_status with job {job} every few seconds until `done` is true. Its \
                 `result` is the plan: show it to the human and follow result.next_step. Do not \
                 call knx_apply_device before you have shown that plan."
            ),
        }))
    }

    /// Finishes `job` with a failure when its task panics, so a panic never
    /// leaves the slot claimed for good. `verb` names the job in the reason.
    fn watch_job(&self, job: String, verb: &'static str, worker: tokio::task::JoinHandle<()>) {
        let state = std::sync::Arc::clone(self.state());
        tokio::spawn(async move {
            if let Err(err) = worker.await
                && let Some(tier) = state.programming.as_ref()
            {
                tier.jobs.finish(
                    &job,
                    json!({
                        "ok": false,
                        "verified": false,
                        "reason": format!("the {verb} task stopped unexpectedly: {err}"),
                    }),
                );
            }
        });
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
        let desired = desired_tables_for_app(&model, target, app).map_err(|e| e.to_string())?;

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
                "system_type": system_type(props.device_mask),
                "secured": tool_key.is_some(),
                "noop": noop,
                "plan": bussard_service::property_plan::render_text(target, &app.id, &rows),
                "property_procedure": rows,
            }));
        }
        // Management calls are sequential (issue #215): this read opens its own
        // lease, so the warm connection is released first.
        // The read budget of PID 61 (issue #336): a cached read is used when
        // the model asks for exactly those flags (no security change pending).
        let known_flags = tool_key
            .is_some()
            .then(|| {
                let empty = HashMap::new();
                let keys = material.group_keys.as_ref().unwrap_or(&empty);
                let inputs =
                    bussard_download::security_inputs_for(Some(&model), target, &desired, keys);
                bussard_service::security_change::unchanged_cached_flags(
                    &dir, target, &desired, &inputs, false,
                )
            })
            .flatten();
        let flags_cached = known_flags.is_some();
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let (_, read) = read_device(
            &service,
            target,
            &tool_key,
            &material.fdsk,
            &SequenceHighWater::new(),
            &dir,
            &model,
            product.source.as_ref(),
            &tunnel,
            known_flags,
        )
        .await?;
        drop(warm);
        if let (false, Some(flags)) = (flags_cached, read.go_flags.as_deref()) {
            bussard_service::security_change::remember_flags(&dir, target, flags);
        }
        refuse_drift(target, &read)?;
        let live = &read.live;
        let tables = live.tables();
        let report = plan(tables, &desired);
        refuse_protected(&model, &report)?;
        let security = security_inputs(&model, target, &desired, &material, live, &tunnel, &dir)?;
        // A System 7 image that would not fit its memory region must refuse at
        // plan time, before the human is asked anything.
        if let Some(s7) = live.sys7() {
            sys7_table_images(s7, &desired, target.raw())
                .map_err(|e| format!("computing the System 7 table images: {e}"))?;
        }
        let mut built = built_plan(&model, target, &gateway, &dir, &read, &report, &product);
        admit_in_plan(&mut built, target, &tunnel, &read, &report);
        security_change_in_plan(
            &mut built,
            &model,
            target,
            &desired,
            security.as_ref(),
            &read,
            &report,
        );
        // A parameter change that shows or hides a com-object is written by a
        // full download (issue #303): the plan says `method: flash`.
        let flash = match built.needs_flash {
            Some(_) => Some(flash::flash_image(
                &dir, &model, target, &read, &report, &built, &product, &material, &tunnel,
            )?),
            None => None,
        };
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
            device_plan.notes.push(flash_note(target));
            // Issue #326: name what the full download writes.
            if let Some(full) = device_plan.writes.full_image.as_mut() {
                full.segments = f.plan.written_segments();
            }
        }
        let plan_text = match device_plan.writes.full_image.as_ref() {
            Some(full) if flash.is_some() => {
                render_full_image_plan_text(target, tables, &report, full)
            }
            _ => render_plan_text(target, tables, &report),
        };
        let digest = if noop {
            None
        } else {
            let pending_plan = PendingPlan {
                target,
                created: Instant::now(),
                live: live_digest(&read),
                model: flash::with_flash(
                    model_digest(&model, target, &desired, security.as_ref(), &built),
                    flash.as_ref(),
                ),
            };
            let digest = plan_digest(&pending_plan);
            let mut plans = tier.plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.insert(digest.clone(), pending_plan);
            Some(digest)
        };
        let now = SystemTime::now();
        let pairs = |list: &[bussard_download::ObjectGa]| -> Vec<Value> {
            list.iter()
                .map(|p| json!({"object": p.object, "ga": p.ga.to_string()}))
                .collect()
        };
        let parameters_json = parameters_json(&built);
        let question = match &flash {
            _ if noop => None,
            Some(_) => Some(flash_question(target, &gateway, device_plan.change_count())),
            None => Some(device_plan.question()),
        };
        Ok(json!({
            "ok": true,
            "method": if flash.is_some() { "flash" } else { "apply" },
            "flash": flash.as_ref().map(|f| f.summary.clone()),
            "address": target.to_string(),
            "gateway": gateway,
            "mask": format!("{:04X}", tables.mask),
            "system_type": system_type(tables.mask),
            "secured": tool_key.is_some(),
            "identity": read.check.as_ref().map(|c| bussard_service::identity_line(target, c)),
            "security_object": security_json(security.as_ref(), &desired, tables_noop),
            "noop": noop,
            "plan": plan_text,
            "sentences": device_plan.render_text(),
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
            "expires_at": digest.as_ref().map(|_| bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl)),
            "next_step": if noop {
                match &built.parameters_skipped {
                    Some(why) => format!(
                        "nothing to write over MCP: the links already match the model, and {why}"
                    ),
                    None if built.octet_ranges.iter().any(|r| !r.written) => "nothing to \
                        write: the device matches the model wherever the configuration places a \
                        parameter; the parameter octets that differ (parameters.octet_ranges \
                        with written: false) are ones ETS does not write in a download either, \
                        so they stay as the device holds them (see notes)"
                        .to_string(),
                    None if !built.octet_ranges.is_empty() => "nothing to write: the device \
                        already matches the model; only device-managed parameter octets differ \
                        (see notes and parameters.octet_ranges), and those are not written on \
                        their own"
                        .to_string(),
                    None => "nothing to write: the device already matches the model".to_string(),
                }
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

    /// `knx_apply_device`'s body; `Err` is a refusal reason.
    ///
    /// Claims the one apply slot, runs the pre-flight and the write in a
    /// server task ([`BussardMcp::apply_job`]), and answers once the
    /// pre-flight is through: with the full result when the write also ends
    /// within the reply wait, else with `started: true` and the job id
    /// (issue #289).
    async fn apply_device(
        &self,
        address: &str,
        digest: &str,
        plan_hash: Option<&str>,
    ) -> Result<Value, String> {
        let target = parse_address(address)?;
        let (digest, plan_hash) = (digest.to_string(), plan_hash.map(str::to_string));
        self.run_job(target, "apply", move |me, job, started| async move {
            me.apply_job(&job, target, &digest, plan_hash.as_deref(), started)
                .await;
        })
        .await
    }

    /// Runs one write as a job of the programming tier (issue #289):
    /// claims the one slot, runs `work` (the pre-flight, which answers on its
    /// `started` sender, then the write) in a server task, and answers once
    /// the pre-flight is through: with the full result when the write also
    /// ends within the reply wait, else with `started: true` and the job id.
    /// `verb` names the write in a refusal.
    async fn run_job<F, Fut>(
        &self,
        target: IndividualAddress,
        verb: &'static str,
        work: F,
    ) -> Result<Value, String>
    where
        F: FnOnce(BussardMcp, String, tokio::sync::oneshot::Sender<Result<(), String>>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let began = Instant::now();
        let (tier, _, _) = self.programming_preflight()?;
        let job = tier.jobs.claim(target)?;
        let reply_wait = tier.jobs.reply_wait();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(work(self.clone(), job.clone(), started_tx));
        // A panic in the job must not leave the slot claimed for good.
        self.watch_job(job.clone(), verb, worker);
        // The pre-flight reads the device, which can outlast the bridge on a
        // Data Secure device (issue #332): past the read wait the call
        // answers `started` and a later refusal ends the job instead.
        let read_wait = tier.jobs.read_wait().saturating_sub(began.elapsed());
        match tokio::time::timeout(read_wait, started_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                tier.jobs.abandon(&job);
                return Err(reason);
            }
            Ok(Err(_)) => {
                return Err(format!(
                    "the {verb} of {target} stopped before its pre-flight ended; call \
                     knx_apply_status with job {job}"
                ));
            }
            Err(_) => return Ok(self.job_started(tier, &job, target)),
        }
        let wait = reply_wait.saturating_sub(began.elapsed());
        if tier.jobs.wait(&job, wait).await {
            let mut result = tier.jobs.result(&job).unwrap_or_else(|| json!({}));
            let status = tier.jobs.status(&self.state().dir, &job);
            let record = status.as_ref().map(|s| s["record"].clone());
            let next_step = inline_next_step(&job, target, &result);
            merge(
                &mut result,
                json!({
                    "started": false,
                    "done": true,
                    "job": job,
                    "record": record,
                    "next_step": next_step,
                }),
            );
            return Ok(result);
        }
        Ok(self.job_started(tier, &job, target))
    }

    /// The `started: true` answer of a write job still running.
    fn job_started(&self, tier: &ProgrammingTier, job: &str, target: IndividualAddress) -> Value {
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
        );
        if let Some(map) = status.as_object_mut() {
            map.remove("result");
            map.remove("state");
        }
        status
    }

    /// One apply job: the pre-flight, then the write, holding the bus lock
    /// and the warm slot throughout. `started` gets the pre-flight's verdict;
    /// a refusal abandons the job, a pass is followed by the write and the
    /// final result in the job table.
    async fn apply_job(
        &self,
        job: &str,
        target: IndividualAddress,
        digest: &str,
        plan_hash: Option<&str>,
        started: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            let _ = started.send(Err("the programming tier is off".into()));
            return;
        };
        let _guard = tier.bus_lock.lock().await;
        // Held until the write is done: management calls are sequential and
        // this one leases the bus itself (issue #215).
        let mut warm = self.warm().lock().await;
        warm.release().await;
        // A KNX IP interface: the plan was its KNXnet/IP parameter object
        // (issue #391), and so is the write.
        if bussard_service::knxnet::interface_config(&self.state().model.reload(), target).is_some()
        {
            self.apply_interface_job(tier, job, target, digest, plan_hash, started)
                .await;
            drop(warm);
            return;
        }
        let prepared = match self.apply_preflight(tier, target, digest, plan_hash).await {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.refuse(job, &reason);
                let _ = started.send(Err(reason));
                return;
            }
        };
        let record = prepared.snapshot.as_ref().map(|id| {
            History::open(&prepared.dir)
                .history_dir()
                .join(id)
                .join(crate::apply_jobs::RECORD_FILE)
        });
        tier.jobs.started(job, prepared.result.clone(), record);
        let _ = started.send(Ok(()));
        let result = self.apply_write(tier, job, prepared).await;
        drop(warm);
        tier.jobs.finish(job, result);
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
        let handle = service.handle().clone();
        let dir = self.state().dir.clone();

        // The digest must name a plan this session produced, for this device,
        // within the plan lifetime.
        let planned = {
            let mut plans = tier.plans();
            plans.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            plans.get(digest).cloned()
        };
        let Some(planned) = planned else {
            return Err(format!(
                "no fresh plan with digest {digest:?} in this session (plans expire after {} \
                 minute(s) and are single use); call knx_plan_device for {target}, show the plan \
                 to the human and ask again",
                tier.plan_ttl.as_secs().div_ceil(60)
            ));
        };
        if planned.target != target {
            return Err(format!(
                "plan {digest} is for {}, not {target}",
                planned.target
            ));
        }

        let model = self.state().model.reload();
        // The model may have changed since the plan (issue #330).
        refuse_insecure_links(&model, target)?;
        let mut product = product_for(&dir, &model, target);
        let desired = desired_tables_for_app(
            &model,
            target,
            product.source.as_ref().and_then(|p| p.app()),
        )
        .map_err(|e| e.to_string())?;
        // KNX Data Secure: the same material the plan resolved, one
        // high-water mark for the read and the write so the send sequence
        // stays monotonic across both connections (spec §5.9).
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let tunnel = self.admitted_tunnel(&model, tool_key.is_some())?;
        let high_water = SequenceHighWater::new();
        let (source, read) = read_device(
            &service,
            target,
            &tool_key,
            &material.fdsk,
            &high_water,
            &dir,
            &model,
            product.source.as_ref(),
            &tunnel,
            None,
        )
        .await?;
        // The apply may change the flags: the next plan reads PID 61 again
        // instead of a cache (issue #336).
        bussard_service::security_change::forget_flags(&dir, target);
        let live = &read.live;
        let security = security_inputs(&model, target, &desired, &material, live, &tunnel, &dir)?;
        let tables = live.tables();
        let report = plan(tables, &desired);
        let mut built = built_plan(&model, target, &gateway, &dir, &read, &report, &product);
        admit_in_plan(&mut built, target, &tunnel, &read, &report);
        security_change_in_plan(
            &mut built,
            &model,
            target,
            &desired,
            security.as_ref(),
            &read,
            &report,
        );
        // The flash a com-object change needs (issue #303), rebuilt from the
        // fresh read: its image is part of the digest.
        let flash = match built.needs_flash {
            Some(_) => match flash::flash_image(
                &dir, &model, target, &read, &report, &built, &product, &material, &tunnel,
            ) {
                Ok(image) => Some(image),
                Err(reason) => {
                    tier.plans().remove(digest);
                    return Err(reason);
                }
            },
            None => None,
        };

        // Re-derive the digest from what is true now; anything that moved since
        // the plan retires it.
        let now = PendingPlan {
            target,
            created: planned.created,
            live: live_digest(&read),
            model: flash::with_flash(
                model_digest(&model, target, &desired, security.as_ref(), &built),
                flash.as_ref(),
            ),
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
            tier.plans().remove(digest);
            return Err(format!(
                "refusing to write {target}: {what} since the plan was made. Plan again with \
                 knx_plan_device and show the new plan to the human."
            ));
        }
        // The identity verdict (issue #228, item 5): a device that runs another
        // application than the lock pins cannot take the model's tables and
        // parameters; it needs a flash first.
        if let Err(refusal) = refuse_drift(target, &read) {
            tier.plans().remove(digest);
            return Err(refusal);
        }
        refuse_protected(&model, &report)?;
        if flash.is_none()
            && let Some(refusal) = &built.refusal
        {
            tier.plans().remove(digest);
            return Err(refusal.clone());
        }
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
        // The plan is consumed from here on: one digest, one write.
        tier.plans().remove(digest);
        let tables_change = !report.is_noop()
            || built.plan.writes.security_object
            || !built.plan.writes.communication_flags.is_empty();
        let images = match live.sys7() {
            Some(s7) if tables_change => Some(
                sys7_table_images(s7, &desired, target.raw())
                    .map_err(|e| format!("computing the System 7 table images: {e}"))?,
            ),
            _ => None,
        };
        let param_write = match (
            &built.partial,
            read.params.as_ref().and_then(|p| p.detail.as_ref()),
        ) {
            (Some(partial), Some(detail)) => Some((partial, detail)),
            _ => None,
        };

        // The audit line: a history snapshot naming the device, the plan and the
        // gateway, recorded before the bus write (as `bussard apply` does).
        let history = History::open(&dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_apply_device")
                .with_args([target.to_string(), digest.to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result(match (tables_change, param_write.is_some()) {
                    _ if flash.is_some() => "before flashing the application program",
                    (true, true) => "before writing the device tables and parameters",
                    (false, true) => "before writing the device parameters",
                    _ => "before writing the device tables",
                });
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

        // Both backups before the first write, as `bussard apply` takes them.
        let backup = write_pre_write_backup(&dir, target, tables, live.sys7())
            .map_err(|e| format!("refusing to write {target} without a backup: {e}"))?;
        // A flash rewrites the whole parameter memory: it is backed up first,
        // where knx_restore_parameters reads it (issue #303).
        let backed_up = match (&flash, param_write) {
            (Some(_), _) => read.params.as_ref().and_then(|p| p.detail.as_ref()),
            (None, write) => write.map(|(_, detail)| detail),
        };
        let param_backup = match backed_up {
            Some(detail) => Some(
                bussard_download::write_parameter_memory_backup(
                    &dir,
                    target,
                    &detail.plan,
                    &detail.regions,
                )
                .map_err(|e| {
                    format!("refusing to write {target} without a parameter backup: {e}")
                })?,
            ),
            None => None,
        };
        let backup_path = backup.display().to_string();
        let param_backup_path = param_backup.as_ref().map(|p| p.display().to_string());
        // What the flash's read-back compares against (issue #319).
        let flash = flash.map(|mut image| {
            image.readback = product.source.take().map(|source| flash::FlashReadback {
                model: std::sync::Arc::clone(&model),
                source,
                device_mask: tables.mask,
            });
            image
        });

        let result = json!({
            "method": if flash.is_some() { "flash" } else { "apply" },
            "address": target.to_string(),
            "gateway": gateway,
            "secured": tool_key.is_some(),
            "backup": backup_path,
            "parameter_backup": param_backup_path,
            "snapshot": snapshot,
        });
        Ok(Prepared {
            model: std::sync::Arc::clone(&model),
            product: product.source,
            target,
            gateway,
            dir,
            handle,
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
    /// changes, then the parameter octets, each verified. Never refuses: a
    /// failure is the result (`ok: false` with the reason and the recovery).
    async fn apply_write(&self, tier: &ProgrammingTier, job: &str, p: Prepared) -> Value {
        let Prepared {
            model,
            product,
            target,
            gateway,
            dir,
            handle,
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
        if let Some(image) = flash {
            let ctx = flash::FlashJob {
                target,
                gateway: &gateway,
                dir: &dir,
                source,
                tool_key,
                high_water,
                changed: json!(built.parameters),
                param_backup: param_backup_path.as_deref(),
            };
            let result = self.flash_write(tier, job, image, ctx, result).await;
            if result["ok"] == json!(true) {
                // The lock may have changed (the PID 54 record): serve it.
                self.state().model.reload();
                self.session_edits().applied(target, true);
            }
            return result;
        }
        let live = &read.live;
        let tables = live.tables();
        let tables_change = !report.is_noop()
            || built.plan.writes.security_object
            || !built.plan.writes.communication_flags.is_empty();
        // The System B group-object table reload (issue #540), written first.
        let object_table = built.object_table.clone();
        let param_write = match (
            &built.partial,
            read.params.as_ref().and_then(|p| p.detail.as_ref()),
        ) {
            (Some(partial), Some(detail)) => Some((partial, detail)),
            _ => None,
        };
        let recovery = format!(
            "The device may be left with partially written or unloaded tables. The pre-apply \
             state is backed up at {backup_path}. Re-planning and re-applying {target} is safe \
             (the tables are rewritten wholesale); do not assume the device works until a new \
             knx_plan_device reports nothing to do."
        );

        // What the write means to leave on the device, for the read-back
        // that ends every apply (issue #349).
        let expected = bussard_service::verify::Expected {
            tables: Some(desired.clone()),
            group_objects: None,
            object_table: object_table.clone(),
            parameters: match (&param_write, &product) {
                (Some(_), Some(source)) => {
                    source
                        .app()
                        .map(|app| bussard_service::verify::ExpectedParameters {
                            product: &source.product,
                            app,
                            model: Some(&model),
                            device_mask: tables.mask,
                        })
                }
                _ => None,
            },
            security: if tables_change {
                security.as_ref().map(|inputs| {
                    bussard_service::verify::ExpectedSecurity::from_inputs(
                        inputs,
                        &desired.addresses,
                    )
                })
            } else {
                None
            },
            // The properties the parameters live in (issue #669), when the
            // parameters are written.
            properties: param_write
                .map(|(_, detail)| {
                    bussard_service::verify::ExpectedProperty::from_parameter_writes(&detail.plan)
                })
                .unwrap_or_default(),
            table_bases: product
                .as_ref()
                .and_then(|p| p.app())
                .map(bussard_download::sys7_table_bases)
                .unwrap_or_default(),
        };

        // Whether a write stopped before it reached the device (no lease, a
        // sequence error): its error is the result, and there is nothing new
        // to read back.
        let mut stopped = false;
        'write: {
            // The tables first, when a link changes (with the group-object
            // table reload before them, issue #540).
            if tables_change || object_table.is_some() {
                tier.jobs.step(
                    job,
                    "writing the group-address and association tables, then reading them back",
                );
                let lease = match handle.lease().await {
                    Ok(lease) => lease,
                    Err(e) => {
                        stopped = true;
                        merge(
                            &mut result,
                            json!({
                                "ok": false,
                                "verified": false,
                                "reason": format!("could not lease the bus: {e}"),
                                "recovery": recovery,
                            }),
                        );
                        break 'write;
                    }
                };
                let outcome = write_tables_seeded(
                    LeaseChannel::new(lease),
                    target,
                    source,
                    tables.mask,
                    &desired,
                    images.as_ref(),
                    bussard_service::secure::layer(&tool_key, &high_water),
                    bussard_download::SystemBLoad {
                        security: security.as_ref(),
                        object_table: object_table.as_deref(),
                        keep_tables: !tables_change,
                        user_memory_above_64k: bussard_download::uses_user_memory(
                            product.as_ref().and_then(|p| p.app()),
                        ),
                    },
                    None,
                )
                .await;
                let verified = matches!(&outcome, Ok(summary) if summary.ok);
                let restarted = matches!(&outcome, Ok(summary) if summary.restarted);
                stopped = outcome.is_err();
                tracing::info!(
                    "audit: knx_apply_device {target} tables via {gateway}: {}; backup {backup_path}",
                    if verified { "verified" } else { "FAILED" }
                );
                tier.jobs.progress(
                    job,
                    "tables",
                    json!(if verified { "verified" } else { "failed" }),
                );
                merge(
                    &mut result,
                    match outcome {
                        Ok(summary) => json!({
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
                            "detail": if summary.ok { Value::Null } else { Value::String(summary.detail) },
                            "recovery": if summary.ok { Value::Null } else { Value::String(recovery.clone()) },
                        }),
                        Err(err) => json!({
                            "ok": false,
                            "verified": false,
                            "reason": format!("the write failed: {err}"),
                            "recovery": recovery.clone(),
                        }),
                    },
                );
                if !verified {
                    if param_write.is_some() {
                        result["parameters"] = json!({
                            "written": false,
                            "reason": "not written: the table write did not verify",
                        });
                    }
                    break 'write;
                }
                // A System 7 table write ends with a basic restart, as ETS's
                // does: the parameters and the read-back need the device back.
                if restarted {
                    tier.jobs.step(job, "waiting for the device to restart");
                    let back = match self.state().bus.service() {
                        Some(service) => {
                            let options = L4Options {
                                source: SourcePolicy::Known(source),
                                tool_key: tool_key.clone(),
                                high_water: high_water.clone(),
                                authorize: Authorize::BestEffort(
                                    bussard_mgmt::apci::FREE_ACCESS_KEY,
                                ),
                                ..L4Options::default()
                            };
                            bussard_service::restart::wait_until_back(
                                service,
                                target,
                                &options,
                                tables.mask,
                                bussard_service::restart::RestartWait::default(),
                            )
                            .await
                            .map_err(|err| err.to_string())
                        }
                        None => Err("the bus is not wired".to_string()),
                    };
                    match back {
                        Ok(after) => {
                            result["restarted"] = json!({
                                "answered_after_ms": after.as_millis() as u64,
                            });
                        }
                        Err(reason) => {
                            stopped = true;
                            merge(
                                &mut result,
                                json!({
                                    "ok": false,
                                    "verified": false,
                                    "reason": format!("the device did not come back after its restart: {reason}"),
                                    "recovery": recovery.clone(),
                                }),
                            );
                            break 'write;
                        }
                    }
                }
                // The security object was written with this PID 54 table and the
                // write verified: record it in the lock, as `adopt` does (issue
                // #297), so the sender admission check sees it. A reload of the
                // group-object table alone does not write it (issue #540).
                if let Some(inputs) = security.as_ref().filter(|_| tables_change) {
                    match bussard_service::admission::record_secure_senders(
                        &dir,
                        target,
                        &inputs.senders,
                    ) {
                        Ok(recorded) => result["secure_senders_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["secure_senders_recorded"] = json!(false);
                            result["secure_senders_note"] = json!(err.to_string());
                        }
                    }
                    // And the group-object flags it wrote (PID 61, issue #331).
                    match bussard_service::security_change::record_security_flags(
                        &dir,
                        target,
                        &inputs.secure_objects,
                    ) {
                        Ok(recorded) => result["security_flags_recorded"] = json!(recorded),
                        Err(err) => {
                            tracing::warn!("{err}");
                            result["security_flags_recorded"] = json!(false);
                            result["security_flags_note"] = json!(err.to_string());
                        }
                    }
                }
            }

            // Then the parameter octets that differ, with the CLI's engine
            // (issue #274): the parameter-only download, verified by reading the
            // memory back.
            if let Some((partial, detail)) = param_write {
                let Some(service) = self.state().bus.service() else {
                    merge(
                        &mut result,
                        json!({
                            "ok": false,
                            "verified": false,
                            "reason": "the bus is not wired",
                        }),
                    );
                    break 'write;
                };
                tier.jobs.step(
                    job,
                    format!(
                        "writing {} parameter octet(s)",
                        built.plan.writes.parameter_octets
                    ),
                );
                let read_options = L4Options {
                    source: SourcePolicy::Known(source),
                    tool_key: tool_key.clone(),
                    high_water: high_water.clone(),
                    authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
                    ..L4Options::default()
                };
                let mut observer = JobObserver {
                    jobs: &tier.jobs,
                    job,
                    what: PARAMETER_DOWNLOAD,
                };
                let outcome = bussard_service::download::write_parameters(
                    service,
                    target,
                    source,
                    partial,
                    detail,
                    tool_key.clone(),
                    high_water.clone(),
                    &read_options,
                    &mut observer,
                )
                .await;
                stopped = matches!(
                    outcome,
                    Ok(bussard_service::download::ParamWriteOutcome::Failed(_)) | Err(_)
                );
                let (ok, parameters) = match outcome {
                    Ok(bussard_service::download::ParamWriteOutcome::Verified { octets }) => (
                        true,
                        json!({
                            "written": true,
                            "verified": true,
                            "octets": octets,
                            "changed": built.parameters,
                        }),
                    ),
                    Ok(failed) => (
                        false,
                        json!({
                            "written": false,
                            "verified": false,
                            "reason": failed.failure(),
                        }),
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
                    "audit: knx_apply_device {target} parameters via {gateway}: {}",
                    if ok { "verified" } else { "FAILED" }
                );
                result["parameters"] = parameters;
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
            } else if let Some(why) = &built.parameters_skipped {
                result["parameters"] = json!({"written": false, "reason": why});
            }
        }

        // Verified means read back and compared (issues #319, #349): a fresh
        // session reads the tables, the written parameters and the security
        // object back and compares them with the model.
        if let Some(service) = self.state().bus.service().filter(|_| !stopped) {
            tier.jobs.step(
                job,
                format!(
                    "reading {target} back (tables, parameters, security object) to compare it \
                     with the model"
                ),
            );
            let read_options = L4Options {
                source: SourcePolicy::Known(source),
                tool_key: tool_key.clone(),
                high_water: high_water.clone(),
                authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
                ..L4Options::default()
            };
            let readback = bussard_service::verify::read_back_on(
                service,
                target,
                &read_options,
                None,
                &expected,
            )
            .await;
            tracing::info!(
                "audit: knx_apply_device {target} read-back via {gateway}: {}",
                if readback.verified {
                    "verified"
                } else {
                    "NOT VERIFIED"
                }
            );
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
                        "The items listed still differ from the model on {target}. The \
                         pre-apply state is backed up at {backup_path}. Plan {target} again \
                         with knx_plan_device and re-apply; do not report the change as done \
                         until a plan reports nothing to do."
                    ));
                }
            }
        }
        if result.get("ok").is_none() {
            result["ok"] = json!(true);
            result["verified"] = json!(true);
        }
        if result["ok"] == json!(true) {
            self.session_edits()
                .applied(target, built.parameters_skipped.is_none());
        }
        result
    }

    /// `knx_apply_status`'s body; `Err` is a refusal reason.
    fn apply_status(&self, job: &str) -> Result<Value, String> {
        let Some(tier) = self.state().programming.as_ref() else {
            return Err(
                "the programming tier is off; start the server with --allow-programming".into(),
            );
        };
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
        let Some(tier) = self.state().programming.as_ref() else {
            return Err(
                "the programming tier is off; start the server with --allow-programming".into(),
            );
        };
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

/// What an apply whose pre-flight passed carries into its write.
struct Prepared {
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
    /// The bus.
    handle: BusHandle,
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
    images: Option<Sys7TableImages>,
    /// The audit snapshot's id.
    snapshot: Option<String>,
    /// The table backup.
    backup_path: String,
    /// The parameter backup, when parameters are written.
    param_backup_path: Option<String>,
    /// The full download, when the plan says `method: flash` (issue #303).
    flash: Option<flash::FlashImage>,
    /// The result so far (address, gateway, backups, snapshot).
    result: Value,
}

/// [`JobObserver::what`] of a parameter-only write.
const PARAMETER_DOWNLOAD: &str = "parameter download";

/// Reports a download's progress into its job.
struct JobObserver<'a> {
    /// The job table.
    jobs: &'a crate::apply_jobs::ApplyJobs,
    /// The job.
    job: &'a str,
    /// What downloads: `"parameter download"` for a parameter-only write,
    /// `"download"` for a flash (issue #303).
    what: &'static str,
}

impl bussard_service::download::FlashObserver for JobObserver<'_> {
    fn progress(&mut self, event: bussard_download::Progress) {
        match event {
            bussard_download::Progress::Step {
                index,
                total,
                label,
            } => {
                self.jobs.step(
                    self.job,
                    format!("{} step {index} of {total}: {label}", self.what),
                );
                self.jobs
                    .progress(self.job, "download_step", json!(format!("{index}/{total}")));
            }
            bussard_download::Progress::Bytes { written, total } => {
                // How far the segment walk got (a read-compare compares
                // most chunks and writes few): not the octets written.
                self.jobs.progress(
                    self.job,
                    "segment",
                    json!({"position": written, "total": total}),
                );
            }
            bussard_download::Progress::Written { written, writable } => {
                // The octets the last System 7 segment stream wrote (issue
                // #320).
                self.jobs.progress(
                    self.job,
                    "octets",
                    json!({"written": written, "writable": writable}),
                );
            }
        }
    }

    fn finished(&mut self, verified: bool) {
        self.jobs.progress(
            self.job,
            "download",
            json!(if verified { "verified" } else { "failed" }),
        );
        if verified && self.what == PARAMETER_DOWNLOAD {
            self.jobs
                .step(self.job, "reading the parameter memory back to verify");
        }
    }
}

/// The `next_step` of an apply that finished within its call.
fn inline_next_step(job: &str, target: IndividualAddress, result: &Value) -> String {
    if result["ok"] == true {
        format!(
            "The write finished within this call (job {job}). Tell the human the outcome and \
             the backup paths; knx_apply_status with job {job} or knx_last_apply with address \
             {target} returns this result again."
        )
    } else {
        format!(
            "The write ended without verifying (job {job}). Tell the human the reason, the \
             recovery and the backup paths; knx_last_apply with address {target} returns this \
             result again."
        )
    }
}

/// The security-object inputs for writing `desired` to `target`, as `bussard
/// apply --keyring` derives them: `None` on the plain path (no tool key) and
/// for a System 7 device (its tables are written secured, its security object
/// is not reprogrammed, as in the CLI). The security individual address
/// table holds the secured senders the model's links imply, with the
/// keyring's sequence numbers. A group address the model marks `secure`
/// without a key in the keyring refuses here, before anything is asked or
/// written.
fn security_inputs(
    model: &Model,
    target: IndividualAddress,
    desired: &DesiredTables,
    material: &SecureMaterial,
    live: &LiveTables,
    tunnel: &[IndividualAddress],
    dir: &std::path::Path,
) -> Result<Option<SecurityInputs>, String> {
    if material.tool_key.is_none() || live.sys7().is_some() {
        return Ok(None);
    }
    let empty = HashMap::new();
    let keys = material.group_keys.as_ref().unwrap_or(&empty);
    let mut inputs = bussard_download::security_inputs_for(Some(model), target, desired, keys);
    // The tunnelling addresses `admit_tunnel_senders` admits (issue #297),
    // sequence 0; empty when the option is off.
    inputs.senders = bussard_download::secured_senders(
        Some(model),
        target,
        keys,
        &material.device_sequences,
        tunnel,
    );
    inputs.admitted_tunnel = tunnel.iter().copied().filter(|ia| *ia != target).collect();
    // The table capacities the product declares (issue #537): a program the
    // device cannot hold refuses here, at plan time.
    inputs.capacity = bussard_download::TableCapacity::for_device(dir, Some(model), target);
    bussard_download::check_planned_capacity(target, &desired.addresses, &inputs).map_err(|e| {
        match e {
            bussard_download::SecurityPlanError::OverCapacity { .. } => {
                format!("{target}'s security object cannot be programmed: {e}")
            }
            e => format!(
                "{target}'s security object cannot be programmed: {e}; export a current keyring \
                 from ETS or fix the group's `secure` flag in groups.toml"
            ),
        }
    })?;
    Ok(Some(inputs))
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

/// Refuses a plan whose additions or removals touch a protected GA.
fn refuse_protected(model: &Model, report: &PlanReport) -> Result<(), String> {
    let protected: Vec<String> = report
        .additions
        .iter()
        .chain(&report.removals)
        .filter(|p| {
            model
                .groups
                .groups
                .get(&p.ga)
                .is_some_and(|group| group.protected)
        })
        .map(|p| format!("{} (object {})", p.ga, p.object))
        .collect();
    if protected.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the change touches protected group address(es) {}; programming them is refused via \
             MCP with no override (use the CLI with the human at the keyboard)",
            protected.join(", ")
        ))
    }
}

/// The product data for the parameter half of `target`'s plan, or why there
/// is none. A pinned archive that is missing or changed does not refuse the
/// plan: it refuses the parameter part, with its recovery line, and the links
/// are still planned (issue #274).
struct ProductFor {
    /// The product data, when the lock pins an intact archive.
    source: Option<ProductSource>,
    /// Why the parameters are not compared, when the lookup failed.
    refusal: Option<String>,
}

/// Resolves the product data for `target` the way `bussard apply` does,
/// warning instead of refusing (see [`ProductFor`]).
fn product_for(dir: &std::path::Path, model: &Model, target: IndividualAddress) -> ProductFor {
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

/// What one read of the device returned.
struct DeviceRead {
    /// The live link tables.
    live: LiveTables,
    /// The identity verdict against the lock, when the descriptor answered.
    check: Option<IdentityCheck>,
    /// The parameter read-back, when product data was at hand.
    params: Option<ParamState>,
    /// The security individual address table (PID 54), read only when
    /// `admit_tunnel_senders` has tunnelling addresses to admit (issue #297);
    /// `None` otherwise or when the device refused the read.
    senders: Option<Vec<SecureSenderEntry>>,
    /// The group-object security flags (PID 61), read on a secured session
    /// of a System B device (issue #331); `None` on a plain session, on
    /// System 7, or when the device refused the read.
    go_flags: Option<Vec<u8>>,
}

/// Checks the source address (once per tunnel instance, issue #341: the
/// service remembers a passed probe until the bus reconnects), then reads the
/// device on one layer-4 session:
/// the device facts and the identity verdict, the live tables, and with
/// `product` the parameter memory (the same session `bussard apply` reads
/// on). Returns the checked source for the write phase.
///
/// With a tool key every APDU, the descriptor read included, rides
/// `A_SecureData`; `None` is the unchanged plain path.
#[allow(clippy::too_many_arguments)] // one read's context; a struct would only move it
async fn read_device(
    service: &BusService,
    target: IndividualAddress,
    tool_key: &Option<Key16>,
    factory_key: &Option<Key16>,
    high_water: &SequenceHighWater,
    dir: &std::path::Path,
    model: &Model,
    product: Option<&ProductSource>,
    tunnel: &[IndividualAddress],
    known_flags: Option<Vec<u8>>,
) -> Result<(IndividualAddress, DeviceRead), String> {
    let source = service.checked_source(false).await.map_err(|e| chain(&e))?;
    let lease = service
        .handle()
        .lease()
        .await
        .map_err(|e| format!("could not lease the bus: {e}"))?;
    // A device reset to default is named, not read under its FDSK (#532).
    let secure = bussard_service::secure::layer_with_factory_key(tool_key, factory_key, high_water);
    let mut l4 = Layer4Connection::connect_with_secure(
        LeaseChannel::new(lease),
        target,
        source,
        Timeouts::default(),
        secure,
    )
    .await
    .map_err(|e| format!("connecting to {target}: {e}"))?;
    // Authorize (free access) before reading, as ETS does and as System 7
    // requires before any memory access. Best-effort on this read.
    if let Err(err) = l4
        .authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
    {
        tracing::debug!("{target} authorize (free access) did not grant: {err}");
    }
    let read = read_on(
        &mut l4,
        target,
        dir,
        model,
        product,
        tunnel,
        tool_key.is_some(),
        known_flags,
    )
    .await;
    let _ = l4.disconnect().await;
    let (read, check, params, senders, go_flags) = read?;
    match read {
        LiveRead::Tables(live) => Ok((
            source,
            DeviceRead {
                live,
                check,
                params,
                senders,
                go_flags,
            },
        )),
        LiveRead::UnsupportedMask { address, mask } => Err(format!(
            "{address} reports mask {mask:04X} ({}); programming supports the System B (x7B0) \
             and System 7 (0705 / 0701) families; on this mask bussard can: {}",
            system_type(mask),
            MaskProfile::from_mask(mask).capabilities().summary()
        )),
    }
}

/// Reads the properties a property-only load procedure writes (issue #390)
/// in one read-only session to `target`.
async fn read_property_rows(
    service: &BusService,
    target: IndividualAddress,
    tool_key: &Option<Key16>,
    plan: &bussard_download::FlashPlan,
) -> Result<Vec<bussard_service::property_plan::PropertyRow>, String> {
    let source = service.checked_source(false).await.map_err(|e| chain(&e))?;
    let lease = service
        .handle()
        .lease()
        .await
        .map_err(|e| format!("could not lease the bus: {e}"))?;
    let secure = bussard_service::secure::layer(tool_key, &SequenceHighWater::new());
    let mut l4 = Layer4Connection::connect_with_secure(
        LeaseChannel::new(lease),
        target,
        source,
        Timeouts::default(),
        secure,
    )
    .await
    .map_err(|e| format!("connecting to {target}: {e}"))?;
    if let Err(err) = l4
        .authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
    {
        tracing::debug!("{target} authorize (free access) did not grant: {err}");
    }
    let rows = bussard_service::property_plan::read_property_rows(&mut l4, plan).await;
    let _ = l4.disconnect().await;
    Ok(rows)
}

/// The reads of [`read_device`] on its open session; `secured` says the
/// session rides `A_SecureData`, so the security object can be read.
#[allow(clippy::type_complexity)] // the five reads of one session, named at the caller
#[allow(clippy::too_many_arguments)] // one session's context, as `read_device`
async fn read_on<Ch: bussard_mgmt::L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    target: IndividualAddress,
    dir: &std::path::Path,
    model: &Model,
    product: Option<&ProductSource>,
    tunnel: &[IndividualAddress],
    secured: bool,
    known_flags: Option<Vec<u8>>,
) -> Result<
    (
        LiveRead,
        Option<IdentityCheck>,
        Option<ParamState>,
        Option<Vec<SecureSenderEntry>>,
        Option<Vec<u8>>,
    ),
    String,
> {
    let facts = FactsCache::new(dir, false);
    let device = model.devices.get(&target).map(|d| &d.device);
    let identified = bussard_service::identify(l4, &facts, device)
        .await
        .map_err(|e| chain(&e))?;
    let bases = product
        .and_then(|p| p.app())
        .map(bussard_download::sys7_table_bases)
        .unwrap_or_default();
    let read = bussard_download::read_live_tables_at(l4, bases)
        .await
        .map_err(|e| chain(&e))?;
    let params = match (&read, product) {
        (LiveRead::Tables(live), Some(product)) => Some(
            bussard_service::params::read_state(
                l4,
                product,
                Some(model),
                target,
                live.tables().mask,
            )
            .await,
        ),
        _ => None,
    };
    // PID 54, for `admit_tunnel_senders` only (issue #297).
    let senders = match &read {
        LiveRead::Tables(live) if !tunnel.is_empty() && live.sys7().is_none() => {
            bussard_download::read_security_sender_table(l4)
                .await
                .map_err(|e| chain(&e))?
        }
        _ => None,
    };
    // PID 61 on a Secure System B device (issue #331): a group object that
    // leaves or joins Data Secure is a plan change of its own.
    let go_flags = match &read {
        // A plan's cached read with no security change pending (#336).
        LiveRead::Tables(live) if secured && live.sys7().is_none() && known_flags.is_some() => {
            known_flags
        }
        LiveRead::Tables(live) if secured && live.sys7().is_none() => {
            // The session's last read: a device that refuses or does not
            // answer leaves the flags unknown, and the plan shows no
            // security-object change.
            match bussard_download::read_security_flags(l4).await {
                Ok(flags) => flags,
                Err(err) => {
                    tracing::debug!("{target}: PID 61 not read: {}", chain(&err));
                    None
                }
            }
        }
        _ => None,
    };
    Ok((read, identified.check, params, senders, go_flags))
}

/// Adds the security-object change (issue #331) to `built`: the group
/// objects whose security flag on the device (PID 61 as read) differs from
/// the model and the key store, and the group keys that leave or join the
/// group key table with them. Nothing without a secured read of PID 61.
fn security_change_in_plan(
    built: &mut BuiltPlan,
    model: &Model,
    target: IndividualAddress,
    desired: &DesiredTables,
    security: Option<&SecurityInputs>,
    read: &DeviceRead,
    report: &PlanReport,
) {
    if let (Some(inputs), Some(flags)) = (security, read.go_flags.as_deref()) {
        bussard_service::security_change::SecurityObjectChange::compare(
            target, desired, inputs, flags,
        )
        .add_to(&mut built.plan, report, Some(model));
    }
}

/// Adds the `admit_tunnel_senders` change (issue #297) to `built`: the
/// tunnelling addresses `read`'s PID 54 is missing. Nothing on System 7 or
/// without tunnelling addresses to admit.
fn admit_in_plan(
    built: &mut BuiltPlan,
    target: IndividualAddress,
    tunnel: &[IndividualAddress],
    read: &DeviceRead,
    report: &PlanReport,
) {
    if tunnel.is_empty() || read.live.sys7().is_some() {
        return;
    }
    TunnelAdmission::new(target, tunnel, read.senders.as_deref()).add_to(&mut built.plan, report);
}

/// Refuses a device whose identity drifted from the lock, naming the
/// `bussard flash` it needs (the CLI's `apply` rule). A System 7 device has
/// no readable application id: code that differs from the pinned product's
/// is its drift (issue #314).
fn refuse_drift(target: IndividualAddress, read: &DeviceRead) -> Result<(), String> {
    if let Some(refusal) = read
        .check
        .as_ref()
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

/// The device plan with its parameter half, built by the CLI's builder
/// ([`build_device_plan`]); a failed product lookup is a note and leaves the
/// parameters out.
fn built_plan(
    model: &Model,
    target: IndividualAddress,
    gateway: &str,
    dir: &std::path::Path,
    read: &DeviceRead,
    report: &PlanReport,
    product: &ProductFor,
) -> BuiltPlan {
    let mut built = build_device_plan(
        model,
        target,
        gateway,
        dir,
        &read.live,
        report,
        read.params.as_ref(),
    );
    if let Some(why) = &product.refusal {
        built.plan.notes.insert(0, why.clone());
        built.parameters_skipped = Some(why.clone());
    }
    built
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

/// Copies every field of `extra` into `into` (both objects).
fn merge(into: &mut Value, extra: Value) {
    if let (Some(into), Value::Object(extra)) = (into.as_object_mut(), extra) {
        into.extend(extra);
    }
}

/// An error and its sources, joined with `": "`.
fn chain(err: &dyn StdError) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}

/// Feeds a length-prefixed byte string into a hash, so field boundaries are
/// unambiguous.
fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// SHA-256 over the live tables a read returned, including the System 7
/// region layout the write depends on, and the parameter memory it read.
fn live_digest(read: &DeviceRead) -> [u8; 32] {
    let live = &read.live;
    let tables = live.tables();
    let mut h = Sha256::new();
    put(&mut h, b"live-v2");
    put(&mut h, &tables.mask.to_be_bytes());
    let addresses: Vec<u8> = tables
        .addresses
        .iter()
        .flat_map(|ga| ga.raw().to_be_bytes())
        .collect();
    put(&mut h, &addresses);
    let associations: Vec<u8> = tables
        .associations
        .iter()
        .flat_map(|(tsap, asap)| {
            let mut pair = tsap.to_be_bytes().to_vec();
            pair.extend_from_slice(&asap.to_be_bytes());
            pair
        })
        .collect();
    put(&mut h, &associations);
    match live.sys7() {
        Some(s7) => {
            put(&mut h, b"sys7");
            put(&mut h, &s7.address_base.to_be_bytes());
            put(&mut h, &s7.association_base.to_be_bytes());
            put(&mut h, &s7.own_ia.to_be_bytes());
            match s7.group_object_base {
                Some(base) => put(&mut h, &base.to_be_bytes()),
                None => put(&mut h, b"no-object-table"),
            }
            put(&mut h, &s7.group_object_image);
        }
        None => put(&mut h, b"system-b"),
    }
    match read.params.as_ref().and_then(|p| p.detail.as_ref()) {
        Some(detail) => {
            put(&mut h, b"parameters");
            for (segment, region) in &detail.regions {
                put(&mut h, segment.as_bytes());
                put(&mut h, &region.address.to_be_bytes());
                put(&mut h, &region.bytes);
            }
        }
        None => put(&mut h, b"no-parameters"),
    }
    // PID 54 when it was read (issue #297); nothing otherwise, so the digest
    // of a plain or option-off plan is unchanged.
    if let Some(senders) = &read.senders {
        put(&mut h, b"pid54");
        put(&mut h, &bussard_download::sender_table_bytes(senders));
    }
    // PID 61 when it was read (issue #331), likewise.
    if let Some(flags) = &read.go_flags {
        put(&mut h, b"pid61");
        put(&mut h, flags);
    }
    // The System B group-object table when it was read (issue #540),
    // likewise.
    if let Some(table) = read
        .params
        .as_ref()
        .and_then(|p| p.detail.as_ref())
        .and_then(|d| d.object_table.as_ref())
        .and_then(|c| c.live.as_ref().ok())
    {
        put(&mut h, b"object-table");
        put(&mut h, &table.image());
    }
    h.finalize().into()
}

/// SHA-256 over the model's links for the device (its fingerprint), the
/// desired tables computed from them, for a secured write what the security
/// object receives (its [`SecurityInputs::describe`] line and the secure group
/// addresses: addresses, object numbers and sequence numbers, no key
/// material) and the parameter half: the model's parameter values, the
/// parameter image the write would stream, or why it is left out.
fn model_digest(
    model: &Model,
    target: IndividualAddress,
    desired: &DesiredTables,
    security: Option<&SecurityInputs>,
    built: &BuiltPlan,
) -> [u8; 32] {
    let mut h = Sha256::new();
    put(&mut h, b"model-v2");
    // The Debug rendering is stable within one build, which is all a digest
    // that lives for one server session needs.
    put(
        &mut h,
        format!("{:?}", model.links.links.get(&target)).as_bytes(),
    );
    let addresses: Vec<u8> = desired
        .addresses
        .iter()
        .flat_map(|ga| ga.raw().to_be_bytes())
        .collect();
    put(&mut h, &addresses);
    let associations: Vec<u8> = desired
        .associations
        .iter()
        .flat_map(|(tsap, asap)| {
            let mut pair = tsap.to_be_bytes().to_vec();
            pair.extend_from_slice(&asap.to_be_bytes());
            pair
        })
        .collect();
    put(&mut h, &associations);
    match security {
        Some(inputs) => {
            put(&mut h, b"secure-v1");
            put(&mut h, inputs.describe(&desired.addresses).as_bytes());
            let secure_gas: Vec<u8> = inputs
                .secure_gas
                .iter()
                .flat_map(|ga| ga.raw().to_be_bytes())
                .collect();
            put(&mut h, &secure_gas);
        }
        None => put(&mut h, b"plain"),
    }
    put(
        &mut h,
        format!(
            "{:?}",
            model.devices.get(&target).map(|d| &d.device.parameters)
        )
        .as_bytes(),
    );
    match &built.partial {
        Some(partial) => {
            put(&mut h, b"parameter-image");
            for segment in parameter_segments(partial) {
                put(&mut h, segment.as_bytes());
                put(&mut h, partial.image_bytes(&segment).unwrap_or_default());
            }
        }
        None => put(&mut h, b"no-parameter-write"),
    }
    put(
        &mut h,
        built.parameters_skipped.as_deref().unwrap_or("").as_bytes(),
    );
    h.finalize().into()
}

/// The parameter segments a parameter-only plan writes, in plan order.
fn parameter_segments(partial: &bussard_download::FlashPlan) -> Vec<String> {
    let mut out: Vec<String> = partial.param_images.keys().cloned().collect();
    out.sort();
    out
}

/// The plan digest: SHA-256 over the device address, the model part and the
/// live part, as lowercase hex.
fn plan_digest(plan: &PendingPlan) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-plan-v1");
    put(&mut h, &plan.target.raw().to_be_bytes());
    put(&mut h, &plan.model);
    put(&mut h, &plan.live);
    let bytes: [u8; 32] = h.finalize().into();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result the caller reads out.
fn refusal(address: &str, reason: String) -> Result<CallToolResult, ErrorData> {
    ok(refusal_json(address, reason))
}

/// The JSON of a refusal: what [`refusal`] returns, and a refused plan
/// job's result (issue #332).
fn refusal_json(address: &str, reason: String) -> Value {
    json!({
        "ok": false,
        "refused": true,
        "address": address,
        "reason": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_mgmt::tables::DeviceTables;

    fn live(addresses: &[u16]) -> DeviceRead {
        DeviceRead {
            live: live_tables(addresses),
            check: None,
            params: None,
            senders: None,
            go_flags: None,
        }
    }

    fn live_tables(addresses: &[u16]) -> LiveTables {
        LiveTables::SystemB(DeviceTables {
            mask: 0x07B0,
            addresses: addresses
                .iter()
                .map(|&raw| bussard_model::GroupAddress::from_raw(raw))
                .collect(),
            associations: vec![(1, 20)],
            resolved: Vec::new(),
            sources: Vec::new(),
            notes: Vec::new(),
            group_objects: None,
        })
    }

    #[test]
    fn test_live_digest_changes_with_the_tables() {
        assert_eq!(live_digest(&live(&[0x0A00])), live_digest(&live(&[0x0A00])));
        assert_ne!(live_digest(&live(&[0x0A00])), live_digest(&live(&[0x0A01])));
    }

    #[test]
    fn test_plan_digest_binds_the_device() -> Result<(), String> {
        let a = PendingPlan {
            target: parse_address("1.1.4")?,
            created: Instant::now(),
            live: [1; 32],
            model: [2; 32],
        };
        let b = PendingPlan {
            target: parse_address("1.1.5")?,
            ..a.clone()
        };
        assert_ne!(plan_digest(&a), plan_digest(&b));
        assert_eq!(plan_digest(&a).len(), 64);
        Ok(())
    }
}
