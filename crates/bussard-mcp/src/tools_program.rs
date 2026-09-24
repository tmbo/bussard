//! The programming tier (issue #118): `knx_plan_device` and `knx_apply_device`.
//!
//! Registered only when the server runs with `--allow-programming`. The tier
//! writes a device's group-address and association tables, the same write
//! `bussard apply` performs, so it carries three gates on top of the CLI's:
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
//!    model's links for it, the desired tables and the live tables it read.
//!    `knx_apply_device` refuses unless that digest was produced by this server
//!    session within the plan lifetime (default ten minutes) and a fresh read of
//!    the live tables, with the current model, reproduces it. A plan is single
//!    use: a write, or a refusal because the device or model moved, retires it.
//!
//! The write itself is the CLI's: back up the pre-state to
//! `captures/backups/`, write with [`bussard_download::write_tables`], verify by
//! reading back. A history snapshot naming the gateway is recorded before the
//! write, so `bussard history` shows every MCP apply (the audit line). Protected
//! group addresses in the change are refused with no override.
//!
//! KNX Data Secure (issue #170): with `bussard mcp --keyring`, `knx_plan_device`
//! reads a device the keyring holds a tool key for over `A_SecureData`, the way
//! `knx_describe_device` and `bussard plan --keyring` do; a device the keyring
//! does not list is read in the clear. `knx_apply_device` refuses such a device:
//! rewriting its tables also means reprogramming its security object, which only
//! `bussard apply --keyring` does.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::time::{Duration, Instant, SystemTime};

use bussard_bus::BusHandle;
use bussard_download::{
    DesiredTables, LiveRead, LiveTables, PlanReport, backups_root, desired_tables_for, plan,
    render_plan_text, sys7_table_images, write_pre_write_backup, write_tables,
};
use bussard_mgmt::{
    Layer4Connection, LeaseChannel, MaskProfile, SecureLayer, Timeouts, system_type,
};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::secure::ToolKeySource;
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::{check_write_gate, gateway_display};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::BussardMcp;
use crate::state::ConnState;

/// The two tools of the programming tier, in registration order.
pub const PROGRAMMING_TOOLS: [&str; 2] = ["knx_plan_device", "knx_apply_device"];

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
        }
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
}

#[tool_router(router = program_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_plan_device` (registered only with `--allow-programming`).
    #[tool(
        description = "Plan writing the model's links to ONE device (issue #118): reads the \
        device's live group-address and association tables over the bus (read-only), diffs them \
        against links.yaml, and returns the plan the CLI `bussard plan` prints (additions, \
        removals, unchanged count, table sizes, load operations), the pending model changes as \
        sentences, where the backup will be written, and a plan_digest. ALWAYS show the plan \
        text to the human in full and ask whether to write it. Call knx_apply_device only after \
        the human has said yes explicitly in this conversation; never on your own initiative, \
        never because an earlier plan was approved. The digest expires (default 10 minutes) and \
        is invalidated if the device or the model changes. Refuses protected group addresses in \
        the change. With the server's --keyring, a KNX Data Secure device the keyring lists is \
        read over A_SecureData (the result says \"secured\": true). Only available with \
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
        description = "Write the planned tables to ONE device on the PHYSICAL bus (issue #118). \
        Call this ONLY after you showed the human the plan from knx_plan_device and the human \
        answered yes explicitly in this conversation. Pass the plan_digest from that plan. \
        Refuses unless the digest came from this server session within the plan lifetime and a \
        fresh read of the device, with the current model, still matches it; if refused, plan \
        again and ask again. On success it backs up the device's current tables first, writes, \
        reads back to verify, and returns the verify outcome and the backup path. Tell the human \
        the outcome and the backup path. Refuses a device the server's --keyring holds a KNX \
        Data Secure tool key for (that write needs `bussard apply --keyring`). Only available \
        with --allow-programming."
    )]
    async fn knx_apply_device(
        &self,
        Parameters(args): Parameters<ApplyDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .apply_device(&args.address, args.plan_digest.trim())
            .await
        {
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
            return Err(format!("the bus to {gateway} is not connected"));
        }
        Ok((tier, handle.clone(), gateway))
    }

    /// The tool key for `target` from the server's `--keyring`, or `None` for
    /// the plain path: no keyring, or a keyring that does not list the device
    /// (ETS only lists a device once its security is commissioned). A device
    /// the model records as security-activated but the keyring lacks is a
    /// refusal (issue #189): plain access cannot reach it.
    fn plan_tool_key(
        &self,
        target: IndividualAddress,
        model: &bussard_model::Model,
    ) -> Result<Option<Key16>, String> {
        let source = ToolKeySource {
            keyring: self.state().keyring.as_deref(),
            tool_key: None,
        };
        let activated = bussard_service::secure::model_activated(Some(model), target);
        bussard_service::secure::resolve(target, source, activated).map_err(|err| chain(&err))
    }

    /// `knx_plan_device`'s body; `Err` is a refusal reason.
    async fn plan_device(&self, address: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        let (tier, handle, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let model = self.state().model.reload();
        let desired = desired_tables_for(&model, target).map_err(|e| e.to_string())?;

        let tool_key = self.plan_tool_key(target, &model)?;
        let _guard = tier.bus_lock.lock().await;
        let (_, live) = read_live(&handle, target, &tool_key).await?;
        let tables = live.tables();
        let report = plan(tables, &desired);
        refuse_protected(&model, &report)?;
        // A System 7 image that would not fit its memory region must refuse at
        // plan time, before the human is asked anything.
        if let Some(s7) = live.sys7() {
            sys7_table_images(s7, &desired, target.raw())
                .map_err(|e| format!("computing the System 7 table images: {e}"))?;
        }

        // Issue #112: the model changes since the last snapshot, as sentences,
        // then record an edit made outside bussard so it cannot be lost (the
        // same order `bussard plan` uses).
        let history = History::open(&dir);
        let pending = match history.pending() {
            Ok(p) if p.base.is_some() && !p.changes.is_empty() => {
                Some(bussard_model::change::render_text(&p.changes))
            }
            _ => None,
        };
        if let Err(err) = history.snapshot_if_changed_externally() {
            tracing::warn!("could not record a history snapshot: {err}");
        }

        let plan_text = render_plan_text(target, tables, &report);
        let noop = report.is_noop();
        let digest = if noop {
            None
        } else {
            let pending_plan = PendingPlan {
                target,
                created: Instant::now(),
                live: live_digest(&live),
                model: model_digest(&model, target, &desired),
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
        Ok(json!({
            "ok": true,
            "address": target.to_string(),
            "gateway": gateway,
            "mask": format!("{:04X}", tables.mask),
            "system_type": system_type(tables.mask),
            "secured": tool_key.is_some(),
            "noop": noop,
            "plan": plan_text,
            "pending_model_changes": pending,
            "additions": pairs(&report.additions),
            "removals": pairs(&report.removals),
            "unchanged": report.unchanged.len(),
            "current_address_count": report.current_address_count,
            "resulting_address_count": report.resulting_address_count,
            "current_association_count": report.current_association_count,
            "resulting_association_count": report.resulting_association_count,
            "load_steps": report.load_steps.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "backup_dir": backups_root(&dir).display().to_string(),
            "plan_digest": digest,
            "planned_at": bussard_monitor::timefmt::to_rfc3339(now),
            "expires_at": digest.as_ref().map(|_| bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl)),
            "next_step": if noop {
                "nothing to write: the device already matches the model".to_string()
            } else {
                format!(
                    "Show the plan above to the human and ask whether to write it to {target}. \
                     Call knx_apply_device with this plan_digest only after an explicit yes."
                )
            },
        }))
    }

    /// `knx_apply_device`'s body; `Err` is a refusal reason.
    async fn apply_device(&self, address: &str, digest: &str) -> Result<Value, String> {
        let target = parse_address(address)?;
        let (tier, handle, gateway) = self.programming_preflight()?;
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

        if self
            .plan_tool_key(target, &self.state().model.current())?
            .is_some()
        {
            return Err(format!(
                "{target} has a Data Secure tool key in the keyring: writing its tables also \
                 reprograms its security object (group key table, group-object flags), which \
                 the MCP programming tier does not do. Use `bussard apply {target} --keyring \
                 <file>` with the human at the keyboard."
            ));
        }
        let _guard = tier.bus_lock.lock().await;
        let model = self.state().model.reload();
        let desired = desired_tables_for(&model, target).map_err(|e| e.to_string())?;
        let (source, live) = read_live(&handle, target, &None).await?;

        // Re-derive the digest from what is true now; anything that moved since
        // the plan retires it.
        let now = PendingPlan {
            target,
            created: planned.created,
            live: live_digest(&live),
            model: model_digest(&model, target, &desired),
        };
        let moved = match (now.live != planned.live, now.model != planned.model) {
            (true, true) => Some("the device's live tables and the model both changed"),
            (true, false) => Some("the device's live tables changed"),
            (false, true) => Some("the model's links for the device changed"),
            (false, false) => None,
        };
        if let Some(what) = moved {
            tier.plans().remove(digest);
            return Err(format!(
                "refusing to write {target}: {what} since the plan was made. Plan again with \
                 knx_plan_device and show the new plan to the human."
            ));
        }
        let tables = live.tables();
        let report = plan(tables, &desired);
        refuse_protected(&model, &report)?;
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
        let images = match live.sys7() {
            Some(s7) => Some(
                sys7_table_images(s7, &desired, target.raw())
                    .map_err(|e| format!("computing the System 7 table images: {e}"))?,
            ),
            None => None,
        };

        // The audit line: a history snapshot naming the device, the plan and the
        // gateway, recorded before the bus write (as `bussard apply` does).
        let history = History::open(&dir);
        let snapshot = if history.has_model_files() {
            let reason = SnapshotReason::new("mcp knx_apply_device")
                .with_args([target.to_string(), digest.to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result("before writing the device tables");
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

        let backup = write_pre_write_backup(&dir, target, tables, live.sys7())
            .map_err(|e| format!("refusing to write {target} without a backup: {e}"))?;

        let lease = handle
            .lease()
            .await
            .map_err(|e| format!("could not lease the bus: {e}"))?;
        let outcome = write_tables(
            LeaseChannel::new(lease),
            target,
            source,
            tables.mask,
            &desired,
            images.as_ref(),
            SecureLayer::plain(),
        )
        .await;

        let backup_path = backup.display().to_string();
        let verified = matches!(&outcome, Ok(summary) if summary.ok);
        tracing::info!(
            "audit: knx_apply_device {target} via {gateway}: {}; backup {backup_path}",
            if verified { "verified" } else { "FAILED" }
        );
        let recovery = format!(
            "The device may be left with partially written or unloaded tables. The pre-apply \
             state is backed up at {backup_path}. Re-planning and re-applying {target} is safe \
             (the tables are rewritten wholesale); do not assume the device works until a new \
             knx_plan_device reports nothing to do."
        );
        Ok(match outcome {
            Ok(summary) => json!({
                "ok": summary.ok,
                "verified": summary.ok,
                "address": target.to_string(),
                "gateway": gateway,
                "backup": backup_path,
                "snapshot": snapshot,
                "address_state": summary.address_state.to_string(),
                "association_state": summary.association_state.to_string(),
                "resulting_address_count": report.resulting_address_count,
                "resulting_association_count": report.resulting_association_count,
                "detail": if summary.ok { Value::Null } else { Value::String(summary.detail) },
                "recovery": if summary.ok { Value::Null } else { Value::String(recovery) },
            }),
            Err(err) => json!({
                "ok": false,
                "verified": false,
                "address": target.to_string(),
                "gateway": gateway,
                "backup": backup_path,
                "snapshot": snapshot,
                "reason": format!("the write failed: {err}"),
                "recovery": recovery,
            }),
        })
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

/// Checks the source address, then reads the device's live tables on one
/// layer-4 session. Returns the checked source for the write phase.
///
/// With a tool key every APDU, the descriptor read included, rides
/// `A_SecureData`; `None` is the unchanged plain path.
async fn read_live(
    handle: &BusHandle,
    target: IndividualAddress,
    tool_key: &Option<Key16>,
) -> Result<(IndividualAddress, LiveTables), String> {
    let source = bussard_mgmt::checked_source(handle, false)
        .await
        .map_err(|e| chain(&e))?;
    let lease = handle
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
    // Authorize (free access) before reading, as ETS does and as System 7
    // requires before any memory access. Best-effort on this read.
    if let Err(err) = l4
        .authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
    {
        tracing::debug!("{target} authorize (free access) did not grant: {err}");
    }
    let read = bussard_download::read_live_tables(&mut l4).await;
    let _ = l4.disconnect().await;
    match read.map_err(|e| chain(&e))? {
        LiveRead::Tables(live) => Ok((source, live)),
        LiveRead::UnsupportedMask { address, mask } => Err(format!(
            "{address} reports mask {mask:04X} ({}); programming supports the System B (x7B0) \
             and System 7 (0705 / 0701) families; on this mask bussard can: {}",
            system_type(mask),
            MaskProfile::from_mask(mask).capabilities().summary()
        )),
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
/// region layout the write depends on.
fn live_digest(live: &LiveTables) -> [u8; 32] {
    let tables = live.tables();
    let mut h = Sha256::new();
    put(&mut h, b"live-v1");
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
    h.finalize().into()
}

/// SHA-256 over the model's links for the device (its fingerprint) and the
/// desired tables computed from them.
fn model_digest(model: &Model, target: IndividualAddress, desired: &DesiredTables) -> [u8; 32] {
    let mut h = Sha256::new();
    put(&mut h, b"model-v1");
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
    h.finalize().into()
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

    fn live(addresses: &[u16]) -> LiveTables {
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
