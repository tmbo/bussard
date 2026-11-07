//! `knx_plan_device` and `knx_apply_device` for a KNX IP interface (issue
//! #391): a device whose file has a `[knxnet]` table and no links is planned
//! and written as properties of its KNXnet/IP parameter object, through the
//! same service functions `bussard plan` / `bussard apply` call
//! ([`bussard_service::knxnet::read_and_plan`],
//! [`bussard_service::knxnet::apply_interface`]).
//!
//! The MCP server has no `--allow-self-reconfigure`: a plan that changes the
//! IP assignment or the static address set of the interface the server
//! tunnels through, or rewrites its tunnel addresses (PID 53), is refused with the
//! reason and the terminal command the owner runs instead.

use std::time::SystemTime;

use bussard_model::IndividualAddress;
use bussard_model::history::SnapshotReason;
use bussard_model::knxnet::KnxnetConfig;
use bussard_secure::{Key16, SequenceHighWater};
use bussard_service::knxnet::{
    self, InterfacePlan, InterfaceRead, InterfaceReadPlan, InterfaceRequest, ReadAndPlanError,
    SessionLink, apply_interface, interface_config, write_interface_backup,
};
use bussard_service::program::plan::Fingerprint;
use bussard_service::{BusService, FactsCache, L4Options, ServiceError};
use serde_json::{Value, json};

use super::{BussardMcp, PlanSides, ProgrammingTier, chain};
use crate::jobs::Gate;

/// What one interface read and plan produced.
struct Planned {
    /// The checked source address of the session.
    source: IndividualAddress,
    /// The read.
    read: InterfaceRead,
    /// The plan.
    plan: InterfacePlan,
    /// The properties of the application's property-only load procedure
    /// (issue #390), when one was given: `flash` writes them.
    rows: Option<Vec<bussard_service::property_plan::PropertyRow>>,
}

/// The digest halves of an interface plan: the state it read, and the
/// writes it derived.
fn sides(plan: &InterfacePlan) -> PlanSides {
    let live = Fingerprint::new(b"interface").put(&plan.state_hash);
    let mut model = Fingerprint::new(b"interface-writes");
    for step in &plan.steps {
        model = model.put(step.wire());
    }
    for change in &plan.changes {
        model = model.put(&change.sentence);
    }
    PlanSides {
        live: live.finish(),
        model: model.finish(),
    }
}

/// The session options of one interface read or write: the checked
/// `source`, the Data Secure layer with `tool_key`, a free-access authorize.
fn session_options(
    source: IndividualAddress,
    tool_key: &Option<Key16>,
    high_water: &SequenceHighWater,
) -> L4Options {
    L4Options::secured(source, tool_key.clone(), high_water.clone())
}

/// The refusal sentence of a failed interface session.
fn session_error(target: IndividualAddress, err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(e) => format!("could not lease the bus: {e}"),
        e => format!("{target}: {}", chain(e)),
    }
}

impl BussardMcp {
    /// Reads `target` and plans `config` against it.
    #[allow(clippy::too_many_arguments)] // one read's context; a struct would only move it
    async fn read_and_plan_interface(
        &self,
        service: &BusService,
        gateway: &str,
        target: IndividualAddress,
        config: &KnxnetConfig,
        tool_key: &Option<Key16>,
        high_water: &SequenceHighWater,
        procedure: Option<&bussard_download::FlashPlan>,
    ) -> Result<Planned, String> {
        let model = self.state().model.reload();
        let facts = FactsCache::new(&self.state().dir, false);
        let source = service.checked_source(false).await.map_err(|e| chain(&e))?;
        let link = SessionLink {
            source: Some(source),
            gateway: SessionLink::gateway_of(gateway),
        };
        let req = InterfaceRequest {
            target,
            config,
            device: model.devices.get(&target).map(|d| &d.device),
            facts: &facts,
            link: &link,
            procedure,
        };
        let options = session_options(source, tool_key, high_water);
        let InterfaceReadPlan { read, plan, rows } = knxnet::read_and_plan(service, &options, req)
            .await
            .map_err(|err| match err {
                ReadAndPlanError::Service(err) => session_error(target, &err),
                err => err.to_string(),
            })?;
        Ok(Planned {
            source,
            read,
            plan,
            rows,
        })
    }

    /// `knx_plan_device` for an IP interface; `Err` is a refusal reason.
    pub(super) async fn plan_interface_body(
        &self,
        target: IndividualAddress,
    ) -> Result<Value, String> {
        let model = self.state().model.reload();
        let Some(config) = interface_config(&model, target).cloned() else {
            return Err(format!("{target} is not planned as an IP interface"));
        };
        let (tier, service, gateway) = self.programming_preflight()?;
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        // The application's property-only load procedure (issue #390), when
        // the lock pins its product: read on the same session and shown next
        // to the [knxnet] changes; `flash` writes it.
        let product = super::product_for(&self.state().dir, &model, target);
        let app = product.source.as_ref().and_then(|p| p.app());
        let procedure = app
            .and_then(|a| bussard_service::property_plan::property_plan(a, Some(&model), target));
        let planned = {
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            self.read_and_plan_interface(
                &service,
                &gateway,
                target,
                &config,
                &tool_key,
                &SequenceHighWater::new(),
                procedure.as_ref(),
            )
            .await?
        };
        if let Some(refusal) =
            bussard_service::drift_refusal(target, &planned.read.check, "apply to")
        {
            return Err(refusal);
        }
        let plan = &planned.plan;
        let name = model
            .devices
            .get(&target)
            .map(|d| d.device.name.clone())
            .unwrap_or_default();
        let backup_dir = bussard_download::backup::backups_root(&self.state().dir)
            .display()
            .to_string();
        let mut device_plan = plan.device_plan(target, &name, &gateway, backup_dir);
        device_plan
            .notes
            .extend(bussard_service::knxnet::parameters_note(&model, target));
        if let Some(why) = plan.refusal(false) {
            let how = if plan.refusals.is_empty() {
                format!(
                    " knx_apply_device cannot write this. The owner runs `bussard apply {target} \
                     --allow-self-reconfigure` in a terminal, or plans it through another \
                     interface."
                )
            } else {
                String::new()
            };
            return Err(format!(
                "{}refusing to write {target}: {why}.{how}",
                device_plan.render_text()
            ));
        }
        let rows = planned.rows.clone();
        let procedure_differs = rows
            .as_ref()
            .is_some_and(|r| r.iter().any(|row| row.differs()));
        let procedure_text = match (&rows, app) {
            (Some(rows), Some(app)) => format!(
                "\n{}",
                bussard_service::property_plan::render_text(target, &app.id, rows)
            ),
            _ => String::new(),
        };
        let noop = plan.is_empty();
        if noop && !procedure_differs {
            self.session_edits().applied(target, true);
        }
        let digest = (!noop).then(|| tier.remember_plan(target, sides(plan)));
        let now = SystemTime::now();
        Ok(json!({
            "ok": true,
            "method": "apply",
            "address": target.to_string(),
            "gateway": gateway,
            "mask": format!("{:04X}", planned.read.mask),
            "secured": tool_key.is_some(),
            "identity": bussard_service::identity_line(target, &planned.read.check),
            "noop": noop && !procedure_differs,
            "sentences": format!("{}{procedure_text}", device_plan.render_text()),
            "property_procedure": rows,
            "changes": device_plan.changes,
            "writes": device_plan.writes,
            "interface_writes": plan.steps.iter().map(|s| s.wire()).collect::<Vec<_>>(),
            "notes": device_plan.notes,
            "question": (!noop).then(|| device_plan.question()),
            "state_hash": device_plan.state_hash,
            "pending_model_changes": self.session_edits().for_device(target),
            "backup_dir": device_plan.backup_dir,
            "plan_digest": digest,
            "planned_at": bussard_monitor::timefmt::to_rfc3339(now),
            "expires_at": digest.as_ref().map(|_| tier.plans.expires_at(now)),
            "next_step": if noop {
                if procedure_differs {
                    format!(
                        "nothing for knx_apply_device to write: the interface matches its \
                         [knxnet] table. The properties of its load procedure differ (see \
                         property_procedure); `bussard flash {target}` writes them."
                    )
                } else {
                    "nothing to write: the interface already matches its [knxnet] table"
                        .to_string()
                }
            } else {
                format!(
                    "Show the plan above to the human (every sentence) and ask whether to write \
                     it to the KNXnet/IP parameter object of {target}. Call knx_apply_device \
                     with this plan_digest only after an explicit yes."
                )
            },
        }))
    }

    /// The apply job of an IP interface: the pre-flight (the digest names a
    /// fresh plan of this session, a fresh read reproduces it, the gates
    /// pass, the snapshot and the backup are written), then the write and its
    /// read-back. The caller holds the bus lock and the warm slot. `Err` is
    /// the pre-flight's refusal.
    pub(super) async fn apply_interface(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        target: IndividualAddress,
        digest: &str,
        plan_hash: Option<&str>,
        gate: &Gate,
    ) -> Result<Value, String> {
        let (service, config, planned, mut result, tool_key, high_water) = self
            .interface_preflight(tier, target, digest, plan_hash)
            .await?;
        gate.pass(result.clone(), None);
        tier.jobs
            .step(job, "writing the KNXnet/IP parameter object");
        let dir = self.state().dir.clone();
        let mut established = planned.read.established.clone();
        let plan = planned.plan;
        let options = session_options(planned.source, &tool_key, &high_water);
        let applied = service
            .with_l4(target, &options, async |l4| {
                let facts = FactsCache::new(&dir, false);
                let established = Some((&facts, &mut established));
                Ok(apply_interface(l4, target, &config, &plan, established).await)
            })
            .await
            .map_err(|err| session_error(target, &err));
        let failure = match applied {
            Ok(applied) => {
                result["written"] = json!(applied.written);
                result["readback"] = json!(applied.readback);
                applied.failure().map(|failure| {
                    json!({
                        "reason": failure,
                        "recovery": format!(
                            "The values before the apply are in {}. Plan {target} again with \
                             knx_plan_device to see what the interface holds; do not report the \
                             change as done until a plan reports nothing to do.",
                            result["backup"].as_str().unwrap_or("the backup")
                        ),
                    })
                })
            }
            Err(reason) => Some(json!({ "reason": reason })),
        };
        let ok = failure.is_none();
        result["ok"] = json!(ok);
        result["verified"] = json!(ok);
        match failure {
            Some(failure) => super::merge(&mut result, failure),
            None => self.session_edits().applied(target, true),
        }
        tracing::info!(
            "audit: knx_apply_device {target} KNXnet/IP parameter object: {}",
            if ok { "verified" } else { "NOT VERIFIED" }
        );
        Ok(result)
    }

    /// The pre-flight of an interface apply; `Err` is a refusal reason and
    /// nothing was written.
    #[allow(clippy::type_complexity)] // the pre-flight's outputs, named at the caller
    async fn interface_preflight(
        &self,
        tier: &ProgrammingTier,
        target: IndividualAddress,
        digest: &str,
        plan_hash: Option<&str>,
    ) -> Result<
        (
            BusService,
            KnxnetConfig,
            Planned,
            Value,
            Option<Key16>,
            SequenceHighWater,
        ),
        String,
    > {
        let (_, service, gateway) = self.programming_preflight()?;
        let dir = self.state().dir.clone();
        let before = tier
            .plans
            .fresh(digest, target, "plan", super::again(target))?;
        let model = self.state().model.reload();
        let Some(config) = interface_config(&model, target).cloned() else {
            tier.plans.retire(digest);
            return Err(format!(
                "{target} is no longer planned as an IP interface (its [knxnet] table or links \
                 changed); plan it again with knx_plan_device"
            ));
        };
        let material = self.plan_material(target, &model)?;
        let tool_key = material.tool_key.clone();
        let high_water = SequenceHighWater::new();
        let planned = self
            .read_and_plan_interface(
                &service,
                &gateway,
                target,
                &config,
                &tool_key,
                &high_water,
                None,
            )
            .await?;
        let now = sides(&planned.plan);
        let moved = match (now.live != before.live, now.model != before.model) {
            (true, true) => Some("the interface's values and the model both changed"),
            (true, false) => Some("the interface's KNXnet/IP values changed"),
            (false, true) => Some("the device file's [knxnet] table changed"),
            (false, false) => None,
        };
        let hash_moved =
            plan_hash.is_some_and(|h| !h.eq_ignore_ascii_case(&planned.plan.state_hash));
        let moved = moved.or(hash_moved.then_some("the device state no longer matches plan_hash"));
        if let Some(what) = moved {
            tier.plans.retire(digest);
            return Err(format!(
                "refusing to write {target}: {what} since the plan was made. Plan again with \
                 knx_plan_device and show the new plan to the human."
            ));
        }
        if let Some(refusal) =
            bussard_service::drift_refusal(target, &planned.read.check, "apply to")
        {
            tier.plans.retire(digest);
            return Err(refusal);
        }
        if let Some(why) = planned.plan.refusal(false) {
            tier.plans.retire(digest);
            return Err(format!("refusing to write {target}: {why}"));
        }
        // The plan is consumed from here on: one digest, one write.
        tier.plans.retire(digest);
        let reason = SnapshotReason::new("mcp knx_apply_device")
            .with_args([target.to_string(), digest.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before writing the KNXnet/IP parameter object");
        let snapshot = super::audit_snapshot(&dir, reason, target)?;
        let Some(facts) = &planned.read.knxnet else {
            return Err(format!("{target}: no KNXnet/IP parameter object"));
        };
        let backup = write_interface_backup(&dir, target, facts)
            .map_err(|e| format!("refusing to write {target} without a backup: {e}"))?;
        let result = json!({
            "method": "apply",
            "address": target.to_string(),
            "gateway": gateway,
            "source": planned.source.to_string(),
            "secured": tool_key.is_some(),
            "backup": backup.display().to_string(),
            "snapshot": snapshot,
            "interface_writes": planned.plan.steps.iter().map(|s| s.wire()).collect::<Vec<_>>(),
        });
        Ok((service, config, planned, result, tool_key, high_water))
    }
}
