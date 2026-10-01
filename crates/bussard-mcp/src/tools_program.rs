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
//! is refused with the `bussard flash` it needs, as is a parameter change
//! that shows or hides a com-object.
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
    DesiredTables, LiveRead, LiveTables, PlanReport, SecurityInputs, Sys7TableImages,
    desired_tables_for, plan, render_plan_text, sys7_table_images, write_pre_write_backup,
    write_tables_secured,
};
use bussard_mgmt::{Layer4Connection, LeaseChannel, MaskProfile, Timeouts, system_type};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::identity::IdentityCheck;
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::params::{
    BuiltPlan, MissingProduct, ParamState, ProductSource, Selection, build_device_plan,
    resolve_product,
};
use bussard_service::secure::{SecureMaterial, ToolKeySource};
use bussard_service::{Authorize, FactsCache, L4Options, SourcePolicy};
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

mod restore;

/// The tools of the programming tier, in registration order.
pub const PROGRAMMING_TOOLS: [&str; 5] = [
    "knx_plan_device",
    "knx_apply_device",
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
        device whose application drifted from bussard.lock (it needs `bussard flash`), and a \
        parameter change that shows or hides a com-object (also `bussard flash`). With the \
        server's keyring, a KNX Data Secure device the keyring lists is read over A_SecureData \
        (the result says \"secured\": true) and `security_object` says what its security object \
        receives with the write (secured senders, keyed group addresses, secured objects; never \
        a key): show that line to the human too. Only available with --allow-programming."
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
        reply is lost. One apply at a time: a second call while a job runs is refused with \
        its id. Tell the human the outcome and the backup paths. A KNX Data Secure device the \
        server's keyring lists is written over A_SecureData, its security object reprogrammed \
        with the tables, exactly as `bussard apply --keyring` does. Only available with \
        --allow-programming."
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

    /// `knx_apply_status` (registered only with `--allow-programming`).
    #[tool(
        description = "Report one apply job started by knx_apply_device (issue #289): `state` \
        (running, done, or interrupted when the server stopped mid-write), `done`, the current \
        `step`, `progress` (the table outcome, the parameter download step, octets written), \
        the backup paths and, once done, `result`: the same result knx_apply_device returns \
        inline (ok, verified, parameters, recovery). Reads only the server's job table and the \
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
    fn programming_preflight(&self) -> Result<(&ProgrammingTier, BusHandle, String), String> {
        let state = self.state();
        let Some(tier) = state.programming.as_ref() else {
            return Err(
                "the programming tier is off; start the server with --allow-programming".into(),
            );
        };
        let gateway = gateway_display(&tier.connection);
        check_write_gate(&tier.connection, tier.allow_remote_gateway)
            .map_err(|refused| refused.to_string())?;
        let Some(handle) = state.bus.handle() else {
            return Err("the bus is not wired".into());
        };
        if state.bus.state() != ConnState::Connected {
            return Err(state.bus.not_connected_reason());
        }
        Ok((tier, handle.clone(), gateway))
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

    /// `knx_plan_device`'s body; `Err` is a refusal reason.
    async fn plan_device(&self, address: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        let (tier, handle, gateway) = self.programming_preflight()?;
        // The bus is the running apply's until it ends (issue #289): waiting
        // for it here could outlast the client's call budget.
        if let Some((job, device)) = tier.jobs.running() {
            return Err(format!(
                "an apply is running on this server (job {job} for {device}); call                  knx_apply_status with job {job} until it is done, then plan again"
            ));
        }
        let dir = self.state().dir.clone();
        let model = self.state().model.reload();
        let desired = desired_tables_for(&model, target).map_err(|e| e.to_string())?;

        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        // The product data the parameter half decodes with (issue #274): the
        // archive the lock pins for the device, as `bussard apply` resolves it.
        let product = product_for(&dir, &model, target);
        let _guard = tier.bus_lock.lock().await;
        // Management calls are sequential (issue #215): this read opens its own
        // lease, so the warm connection is released first.
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let (_, read) = read_device(
            &handle,
            target,
            &tool_key,
            &SequenceHighWater::new(),
            &dir,
            &model,
            product.source.as_ref(),
        )
        .await?;
        drop(warm);
        refuse_drift(target, &read)?;
        let live = &read.live;
        let tables = live.tables();
        let report = plan(tables, &desired);
        refuse_protected(&model, &report)?;
        let security = security_inputs(&model, target, &desired, &material, live)?;
        // A System 7 image that would not fit its memory region must refuse at
        // plan time, before the human is asked anything.
        if let Some(s7) = live.sys7() {
            sys7_table_images(s7, &desired, target.raw())
                .map_err(|e| format!("computing the System 7 table images: {e}"))?;
        }
        let built = built_plan(&model, target, &gateway, &dir, &read, &report, &product);
        if let Some(refusal) = &built.refusal {
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

        let plan_text = render_plan_text(target, tables, &report);
        let tables_noop = report.is_noop();
        let noop = tables_noop && built.partial.is_none();
        if noop {
            // The device already holds the model: nothing this session
            // edited is pending on it any more.
            self.session_edits()
                .applied(target, built.parameters_skipped.is_none());
        }
        let pending = self.session_edits().for_device(target);
        let mut device_plan = built.plan.clone();
        if let Some(line) = security
            .as_ref()
            .filter(|_| !tables_noop)
            .map(|s| s.describe(&desired.addresses))
        {
            device_plan.notes.push(line);
        }
        let digest = if noop {
            None
        } else {
            let pending_plan = PendingPlan {
                target,
                created: Instant::now(),
                live: live_digest(&read),
                model: model_digest(&model, target, &desired, security.as_ref(), &built),
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
        Ok(json!({
            "ok": true,
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
            "question": (!noop).then(|| device_plan.question()),
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
        let state = std::sync::Arc::clone(self.state());
        let watched = job.clone();
        tokio::spawn(async move {
            if let Err(err) = worker.await
                && let Some(tier) = state.programming.as_ref()
            {
                tier.jobs.finish(
                    &watched,
                    json!({
                        "ok": false,
                        "verified": false,
                        "reason": format!("the {verb} task stopped unexpectedly: {err}"),
                    }),
                );
            }
        });
        match started_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => return Err(reason),
            Err(_) => {
                return Err(format!(
                    "the {verb} of {target} stopped before its pre-flight ended; call \
                     knx_apply_status with job {job}"
                ));
            }
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
        let mut status = tier
            .jobs
            .status(&self.state().dir, &job)
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
                     verify outcome, the parameters written, the backup paths). If the reply is \
                     lost, knx_last_apply with address {target} returns the same job."
                ),
            }),
        );
        if let Some(map) = status.as_object_mut() {
            map.remove("result");
            map.remove("state");
        }
        Ok(status)
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
        let prepared = match self.apply_preflight(tier, target, digest, plan_hash).await {
            Ok(prepared) => prepared,
            Err(reason) => {
                tier.jobs.abandon(job);
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
        let (_, handle, gateway) = self.programming_preflight()?;
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
        let desired = desired_tables_for(&model, target).map_err(|e| e.to_string())?;
        let product = product_for(&dir, &model, target);
        // KNX Data Secure: the same material the plan resolved, one
        // high-water mark for the read and the write so the send sequence
        // stays monotonic across both connections (spec §5.9).
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let high_water = SequenceHighWater::new();
        let (source, read) = read_device(
            &handle,
            target,
            &tool_key,
            &high_water,
            &dir,
            &model,
            product.source.as_ref(),
        )
        .await?;
        let live = &read.live;
        let security = security_inputs(&model, target, &desired, &material, live)?;
        let tables = live.tables();
        let report = plan(tables, &desired);
        let built = built_plan(&model, target, &gateway, &dir, &read, &report, &product);

        // Re-derive the digest from what is true now; anything that moved since
        // the plan retires it.
        let now = PendingPlan {
            target,
            created: planned.created,
            live: live_digest(&read),
            model: model_digest(&model, target, &desired, security.as_ref(), &built),
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
        if let Some(refusal) = &built.refusal {
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
        let tables_change = !report.is_noop();
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
        let param_backup = match param_write {
            Some((_, detail)) => Some(
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

        let result = json!({
            "address": target.to_string(),
            "gateway": gateway,
            "secured": tool_key.is_some(),
            "backup": backup_path,
            "parameter_backup": param_backup_path,
            "snapshot": snapshot,
        });
        Ok(Prepared {
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
            result,
        })
    }

    /// The write of an apply whose pre-flight passed: the tables when a link
    /// changes, then the parameter octets, each verified. Never refuses: a
    /// failure is the result (`ok: false` with the reason and the recovery).
    async fn apply_write(&self, tier: &ProgrammingTier, job: &str, p: Prepared) -> Value {
        let Prepared {
            target,
            gateway,
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
            mut result,
            ..
        } = p;
        let live = &read.live;
        let tables = live.tables();
        let tables_change = !report.is_noop();
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

        // The tables first, when a link changes.
        if tables_change {
            tier.jobs.step(
                job,
                "writing the group-address and association tables, then reading them back",
            );
            let lease = match handle.lease().await {
                Ok(lease) => lease,
                Err(e) => {
                    merge(
                        &mut result,
                        json!({
                            "ok": false,
                            "verified": false,
                            "reason": format!("could not lease the bus: {e}"),
                            "recovery": recovery,
                        }),
                    );
                    return result;
                }
            };
            let outcome = write_tables_secured(
                LeaseChannel::new(lease),
                target,
                source,
                tables.mask,
                &desired,
                images.as_ref(),
                bussard_service::secure::layer(&tool_key, &high_water),
                security.as_ref(),
            )
            .await;
            let verified = matches!(&outcome, Ok(summary) if summary.ok);
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
                return result;
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
                return result;
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
                "no apply job {job:?} in this session or under .bussard/history; \
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
    /// The result so far (address, gateway, backups, snapshot).
    result: Value,
}

/// Reports a parameter download's progress into its job.
struct JobObserver<'a> {
    /// The job table.
    jobs: &'a crate::apply_jobs::ApplyJobs,
    /// The job.
    job: &'a str,
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
                    format!("parameter download step {index} of {total}: {label}"),
                );
                self.jobs
                    .progress(self.job, "download_step", json!(format!("{index}/{total}")));
            }
            bussard_download::Progress::Bytes { written, total } => {
                self.jobs.progress(
                    self.job,
                    "octets",
                    json!({"written": written, "total": total}),
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
        if verified {
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
) -> Result<Option<SecurityInputs>, String> {
    if material.tool_key.is_none() || live.sys7().is_some() {
        return Ok(None);
    }
    let empty = HashMap::new();
    let keys = material.group_keys.as_ref().unwrap_or(&empty);
    let mut inputs = bussard_download::security_inputs_for(Some(model), target, desired, keys);
    inputs.senders = bussard_download::secured_senders(
        Some(model),
        target,
        keys,
        &material.device_sequences,
        &[],
    );
    bussard_download::build_security_program(
        target,
        &desired.addresses,
        inputs.fallback_go_count,
        &inputs.secure_objects,
        &inputs.secure_gas,
        &inputs.group_keys,
    )
    .map_err(|e| {
        format!(
            "{target}'s security object cannot be programmed: {e}; export a current keyring \
             from ETS or fix the group's `secure` flag in groups.toml"
        )
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
}

/// Checks the source address, then reads the device on one layer-4 session:
/// the device facts and the identity verdict, the live tables, and with
/// `product` the parameter memory (the same session `bussard apply` reads
/// on). Returns the checked source for the write phase.
///
/// With a tool key every APDU, the descriptor read included, rides
/// `A_SecureData`; `None` is the unchanged plain path.
async fn read_device(
    handle: &BusHandle,
    target: IndividualAddress,
    tool_key: &Option<Key16>,
    high_water: &SequenceHighWater,
    dir: &std::path::Path,
    model: &Model,
    product: Option<&ProductSource>,
) -> Result<(IndividualAddress, DeviceRead), String> {
    let source = bussard_mgmt::checked_source(handle, false)
        .await
        .map_err(|e| chain(&e))?;
    let lease = handle
        .lease()
        .await
        .map_err(|e| format!("could not lease the bus: {e}"))?;
    let secure = bussard_service::secure::layer(tool_key, high_water);
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
    let read = read_on(&mut l4, target, dir, model, product).await;
    let _ = l4.disconnect().await;
    let (read, check, params) = read?;
    match read {
        LiveRead::Tables(live) => Ok((
            source,
            DeviceRead {
                live,
                check,
                params,
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

/// The reads of [`read_device`] on its open session.
async fn read_on<Ch: bussard_mgmt::L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    target: IndividualAddress,
    dir: &std::path::Path,
    model: &Model,
    product: Option<&ProductSource>,
) -> Result<(LiveRead, Option<IdentityCheck>, Option<ParamState>), String> {
    let facts = FactsCache::new(dir, false);
    let device = model.devices.get(&target).map(|d| &d.device);
    let identified = bussard_service::identify(l4, &facts, device)
        .await
        .map_err(|e| chain(&e))?;
    let read = bussard_download::read_live_tables(l4)
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
    Ok((read, identified.check, params))
}

/// Refuses a device whose identity drifted from the lock, naming the
/// `bussard flash` it needs (the CLI's `apply` rule).
fn refuse_drift(target: IndividualAddress, read: &DeviceRead) -> Result<(), String> {
    match read
        .check
        .as_ref()
        .and_then(|check| bussard_service::drift_refusal(target, check, "write"))
    {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
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
            put(&mut h, &s7.group_object_base.to_be_bytes());
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
    ok(json!({
        "ok": false,
        "refused": true,
        "address": address,
        "reason": reason,
    }))
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
