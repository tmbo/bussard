//! The plan of writing the model (or a backup's tables) to one device, from
//! one read ([`super::read`]): the table plan, the device plan in the model's
//! words with its parameter half, the tunnel admission (PID 54, issue #297)
//! and the security-object change (PID 61, issue #331), computed once for
//! `bussard plan`, `bussard apply`, `knx_plan_device` and
//! `knx_apply_device` (issue #901). The fingerprints a plan is approved by
//! come out of the same read, so the CLI's `state_hash` and the MCP tier's
//! plan digest cannot drift apart.

use std::collections::HashMap;
use std::path::Path;

use bussard_download::{
    DesiredTables, LiveTables, PlanReport, SecureSenderEntry, SecurityInputs, SecurityPlanError,
};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_secure::Key16;
use sha2::{Digest, Sha256};

use super::read::DeviceRead;
use crate::admission::TunnelAdmission;
use crate::params::BuiltPlan;
use crate::secure::SecureMaterial;
use crate::security_change::SecurityObjectChange;

/// What a plan of the model for one device is built from, besides the read.
pub struct PlanInputs<'a> {
    /// The model.
    pub model: &'a Model,
    /// The device.
    pub target: IndividualAddress,
    /// The gateway, as the plan names it.
    pub gateway: &'a str,
    /// The model directory (backups, the lock).
    pub dir: &'a Path,
    /// The tables the model asks for.
    pub desired: &'a DesiredTables,
    /// The tunnelling addresses `admit_tunnel_senders` admits (issue #297).
    pub tunnel: &'a [IndividualAddress],
    /// The key store's group keys, for the security-object change.
    pub group_keys: Option<&'a HashMap<GroupAddress, Key16>>,
    /// Why the parameters are not compared (a pinned archive that is missing
    /// or changed), noted first in the plan.
    pub parameters_skipped: Option<&'a str>,
}

/// The plan of writing the model to one device.
pub struct Planned {
    /// The link-table plan.
    pub report: PlanReport,
    /// The device plan in the model's words, with its parameter half.
    pub built: BuiltPlan,
    /// The tunnelling addresses PID 54 is missing (issue #297), when any are
    /// admitted and the device is System B.
    pub admission: Option<TunnelAdmission>,
    /// The security-object change against the PID 61 read (issue #331).
    pub security_change: Option<SecurityObjectChange>,
}

impl Planned {
    /// Whether the link tables are rewritten: a link changes, a tunnelling
    /// address is admitted, a group object leaves or joins Data Secure, or a
    /// System 7 communication flag follows its links.
    pub fn tables_change(&self) -> bool {
        self.built.tables_change(&self.report)
    }
}

/// Plans writing the model to `inputs.target`, as read in `read`.
pub fn plan_device(inputs: &PlanInputs<'_>, read: &DeviceRead<LiveTables>) -> Planned {
    let target = inputs.target;
    let live = &read.live;
    let report = bussard_download::plan(live.tables(), inputs.desired);
    let mut built = crate::params::build_device_plan(
        inputs.model,
        target,
        inputs.gateway,
        inputs.dir,
        live,
        &report,
        read.params.as_ref(),
    );
    if let Some(why) = inputs.parameters_skipped {
        built.plan.notes.insert(0, why.to_string());
        built.parameters_skipped = Some(why.to_string());
    }
    let admission = tunnel_admission(
        target,
        inputs.tunnel,
        live.sys7().is_some(),
        read.senders.as_deref(),
    );
    if let Some(admission) = &admission {
        admission.add_to(&mut built.plan, &report);
    }
    // PID 61 is read only on a secured System B session.
    let security_change = read.flags.as_deref().map(|flags| {
        let empty = HashMap::new();
        let keys = inputs.group_keys.unwrap_or(&empty);
        let security =
            bussard_download::security_inputs_for(Some(inputs.model), target, inputs.desired, keys);
        SecurityObjectChange::compare(target, inputs.desired, &security, flags)
    });
    if let Some(change) = &security_change {
        change.add_to(&mut built.plan, &report, Some(inputs.model));
    }
    // After every reason to rewrite the link tables is known (issue #1095):
    // the partial download's restart, and a restart a write left pending.
    built.restart_pending = crate::pending_restart::pending(inputs.dir, target);
    built.mark_restart(&report);
    Planned {
        report,
        built,
        admission,
        security_change,
    }
}

/// The `admit_tunnel_senders` comparison of `target` (issue #297), or `None`
/// when there is nothing to admit or the device is System 7, whose security
/// object a table write does not reprogram.
pub fn tunnel_admission(
    target: IndividualAddress,
    tunnel: &[IndividualAddress],
    sys7: bool,
    live: Option<&[SecureSenderEntry]>,
) -> Option<TunnelAdmission> {
    (!tunnel.is_empty() && !sys7).then(|| TunnelAdmission::new(target, tunnel, live))
}

/// The security object a secured table write reprograms (issue #156): the
/// group key table, the group-object flags, and the security individual
/// address table of the secured senders the model's links imply plus
/// `extra` (`--secure-sender`, the admitted tunnelling addresses `tunnel`),
/// with the table capacities the product declares (issue #537). `None` on
/// the plain path.
///
/// # Errors
///
/// The program does not fit the device, or a secure group has no key.
pub fn security_inputs(
    model: Option<&Model>,
    target: IndividualAddress,
    desired: &DesiredTables,
    material: &SecureMaterial,
    extra: &[IndividualAddress],
    tunnel: &[IndividualAddress],
    dir: &Path,
) -> Result<Option<SecurityInputs>, SecurityPlanError> {
    if material.tool_key.is_none() {
        return Ok(None);
    }
    let empty = HashMap::new();
    let keys = material.group_keys.as_ref().unwrap_or(&empty);
    let mut inputs = bussard_download::security_inputs_for(model, target, desired, keys);
    let mut senders: Vec<IndividualAddress> = extra.to_vec();
    senders.extend(tunnel.iter().copied());
    inputs.senders = bussard_download::secured_senders(
        model,
        target,
        keys,
        &material.device_sequences,
        &senders,
    );
    inputs.admitted_tunnel = tunnel.iter().copied().filter(|ia| *ia != target).collect();
    inputs.capacity = bussard_download::TableCapacity::for_device(dir, model, target);
    bussard_download::check_planned_capacity(target, &desired.addresses, &inputs)?;
    Ok(Some(inputs))
}

/// The refusal of a change that touches a protected group address, `None`
/// when it touches none. The MCP tier refuses it with no override.
pub fn protected_refusal(model: &Model, report: &PlanReport) -> Option<String> {
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
    (!protected.is_empty()).then(|| {
        format!(
            "the change touches protected group address(es) {}; programming them is refused via \
             MCP with no override (use the CLI with the human at the keyboard)",
            protected.join(", ")
        )
    })
}

/// Feeds a length-prefixed byte string into a hash, so field boundaries are
/// unambiguous.
pub fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// The device-state fingerprint of a read: [`bussard_download::state_hash_with`]
/// (the `state_hash` a plan reports) over the tables, the parameter memory
/// and the group-object table as read, extended with the security tables the
/// read covered (PID 54, issue #297; PID 61, issue #331), which a write of
/// the security object depends on.
pub fn live_fingerprint(read: &DeviceRead<LiveTables>) -> [u8; 32] {
    let live = &read.live;
    let detail = read.params.as_ref().and_then(|p| p.detail.as_ref());
    let object_table = detail
        .and_then(|d| d.object_table.as_ref())
        .and_then(|c| c.live.as_ref().ok())
        .map(|table| table.image());
    let state = bussard_download::state_hash_with(
        live,
        detail.map(|d| &d.regions),
        object_table.as_deref(),
    );
    let mut h = Sha256::new();
    put(&mut h, state.as_bytes());
    if let Some(senders) = &read.senders {
        put(&mut h, b"pid54");
        put(&mut h, &bussard_download::sender_table_bytes(senders));
    }
    if let Some(flags) = &read.flags {
        put(&mut h, b"pid61");
        put(&mut h, flags);
    }
    h.finalize().into()
}

/// The model's side of a plan: SHA-256 over the device's links, the desired
/// tables, for a secured write what the security object receives (addresses,
/// object numbers and sequence numbers, never a key) and the parameter half:
/// the model's values, the image the write would stream, or why it is left
/// out.
pub fn model_fingerprint(
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
    put_desired(&mut h, desired);
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
            let mut segments: Vec<&String> = partial.param_images.keys().collect();
            segments.sort();
            for segment in segments {
                put(&mut h, segment.as_bytes());
                put(&mut h, partial.image_bytes(segment).unwrap_or_default());
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

/// Hashes desired tables: the addresses, then the `(TSAP, ASAP)` pairs.
pub fn put_desired(h: &mut Sha256, desired: &DesiredTables) {
    let addresses: Vec<u8> = desired
        .addresses
        .iter()
        .flat_map(|ga| ga.raw().to_be_bytes())
        .collect();
    put(h, &addresses);
    let associations: Vec<u8> = desired
        .associations
        .iter()
        .flat_map(|(tsap, asap)| {
            let mut pair = tsap.to_be_bytes().to_vec();
            pair.extend_from_slice(&asap.to_be_bytes());
            pair
        })
        .collect();
    put(h, &associations);
}

/// The one digest builder of a confirmed write (issue #905): SHA-256 over a
/// salt, then length-prefixed fields ([`put`]), so field boundaries are
/// unambiguous and every digest a human's yes answers is built the same way.
#[derive(Clone)]
pub struct Fingerprint(Sha256);

impl Fingerprint {
    /// A digest salted with `salt` (`b"bussard-plan-v1"`).
    pub fn new(salt: &[u8]) -> Self {
        let mut h = Sha256::new();
        put(&mut h, salt);
        Fingerprint(h)
    }

    /// Adds one field.
    #[must_use]
    pub fn put(mut self, bytes: impl AsRef<[u8]>) -> Self {
        put(&mut self.0, bytes.as_ref());
        self
    }

    /// Adds a device address.
    #[must_use]
    pub fn address(self, address: IndividualAddress) -> Self {
        self.put(address.raw().to_be_bytes())
    }

    /// Adds desired tables ([`put_desired`]).
    #[must_use]
    pub fn desired(mut self, desired: &DesiredTables) -> Self {
        put_desired(&mut self.0, desired);
        self
    }

    /// The digest.
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    /// The digest as lowercase hex.
    pub fn hex(self) -> String {
        bussard_model::text::hex(&self.finish())
    }
}

/// The plan digest a human approves: SHA-256 over the device, the model's
/// side and the device's side of the plan, as lowercase hex.
pub fn plan_digest(target: IndividualAddress, model: &[u8; 32], live: &[u8; 32]) -> String {
    Fingerprint::new(b"bussard-plan-v1")
        .address(target)
        .put(model)
        .put(live)
        .hex()
}

/// The link-table plan of writing `desired` (a backup's tables, for a
/// restore) to the device as read.
pub fn table_plan(read: &DeviceRead<LiveTables>, desired: &DesiredTables) -> PlanReport {
    bussard_download::plan(read.live.tables(), desired)
}

/// The System 7 region images of `desired` on the device as read, computed
/// before anything is confirmed, backed up or written, so an image that does
/// not fit its region refuses first. `None` on System B.
///
/// # Errors
///
/// An image does not fit its memory region.
pub fn sys7_images(
    read: &DeviceRead<LiveTables>,
    desired: &DesiredTables,
) -> Result<Option<bussard_download::Sys7TableImages>, bussard_download::apply_sys7::Sys7ApplyError>
{
    read.live
        .sys7()
        .map(|s7| bussard_download::sys7_table_images(s7, desired))
        .transpose()
}

/// The tables the model asks for on `target`
/// ([`bussard_download::desired_tables_for_app`]): a device with no links is
/// refused unless its application has no group objects.
///
/// # Errors
///
/// The refusal, in one sentence.
pub fn desired_tables(
    model: &Model,
    target: IndividualAddress,
    product: Option<&crate::params::ProductSource>,
) -> Result<DesiredTables, String> {
    bussard_download::desired_tables_for_app(model, target, product.and_then(|p| p.app()))
        .map_err(|e| e.to_string())
}

/// The refusal to write a device outside the System B and System 7 families
/// (the readers gate on the family already; every write asserts it again),
/// `None` for a device bussard writes.
pub fn family_refusal(target: IndividualAddress, mask: u16) -> Option<String> {
    (!bussard_mgmt::MaskProfile::from_mask(mask)
        .capabilities()
        .plan_apply)
        .then(|| {
            format!(
                "{target} reports mask {mask:04X} ({}); refusing to write a device outside the \
                 System B / System 7 families",
                bussard_mgmt::system_type(mask)
            )
        })
}
