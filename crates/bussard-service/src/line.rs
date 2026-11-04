//! The whole-line runner (issues #100, #748): every device the model has on
//! one line, planned and, in [`LineMode::Apply`], written and verified.
//!
//! `bussard plan --line` / `bussard apply --line` and the `line` argument of
//! `knx_plan_device` / `knx_apply_device` all visit a device through
//! [`visit_device`], so the CLI and the MCP server read, refuse, back up,
//! write and read back each device the same way (the #314 rule). The
//! surfaces keep their own loop around it: the CLI its resume state file and
//! summary table, the MCP server its job and plan digest.
//!
//! What a visit reuses, so the line path never drifts from the single-device
//! one:
//!
//! * the desired tables come from [`bussard_download::compute_tables`];
//! * the live read is [`bussard_download::read_live_tables_at`], so both
//!   device families (System B `x7B0`, System 7 `0705` / `0701`) are read the
//!   same way, and on System B the group-object table is compared with the
//!   image the full flash writes (issue #540);
//! * the write is [`bussard_download::write_system_b_seeded`] /
//!   [`bussard_download::write_sys7`] after
//!   [`bussard_download::write_pre_write_backup`]: the same per-device backup,
//!   the same load sequence, the same read-back verify. A System 7 write ends
//!   with a restart, after which the tables are read back on a fresh session.
//!
//! The visit never prints; what the CLI printed while visiting a device is
//! handed to the caller as [`LineNote`]s.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::path::{Path, PathBuf};

use bussard_download::{
    DesiredTables, LiveRead, LiveTables, ObjectTableCheck, PlanReport, compute_tables, plan,
    sys7_flag_writes, sys7_table_images,
};
use bussard_mgmt::{MaskProfile, system_type};
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};
use sha2::{Digest, Sha256};

use crate::params::{MissingProduct, ParseHook, ProductSource, Selection, resolve_product};
use crate::secure::SecureMaterial;
use crate::{Authorize, BusService, L4Options, ServiceError, SourcePolicy};

/// A line argument that is not `area.line`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct LineError(String);

/// Parses an `area.line` string (e.g. `1.1`) into its two parts.
///
/// A full `area.line.device` is accepted and its device part ignored, so
/// `1.1.4` is read as line `1.1` rather than rejected.
///
/// # Errors
///
/// Fewer than two parts, a part that is not a number, or one above 15.
pub fn parse_line(line: &str) -> Result<(u8, u8), LineError> {
    let parts: Vec<&str> = line.trim().split('.').collect();
    if parts.len() < 2 {
        return Err(LineError(format!(
            "invalid line {line:?}; expected area.line like \"1.1\""
        )));
    }
    let area: u8 = parts[0]
        .parse()
        .map_err(|_| LineError(format!("invalid area in {line:?}")))?;
    let line_no: u8 = parts[1]
        .parse()
        .map_err(|_| LineError(format!("invalid line in {line:?}")))?;
    if area > 15 || line_no > 15 {
        return Err(LineError(format!(
            "area and line must each be 0–15 (got {line:?})"
        )));
    }
    Ok((area, line_no))
}

/// Which half of a run this is: a read-only preview or the real write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineMode {
    /// Read the tables and diff them, never write.
    Plan,
    /// Back up, write and verify each device with changes.
    Apply,
}

impl LineMode {
    /// The verb used in messages and in the JSON `mode` field.
    pub fn verb(self) -> &'static str {
        match self {
            LineMode::Plan => "plan",
            LineMode::Apply => "apply",
        }
    }
}

/// What happened to one device in a whole-line run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Plan only: the device differs from the model by this many changes.
    Changes(usize),
    /// Apply only: this many changes were written and verified.
    Applied(usize),
    /// The device already matches the model; nothing to do.
    Unchanged,
    /// The device was deliberately not touched, for the stated reason.
    Skipped(String),
    /// The device could not be planned or written, for the stated reason.
    Failed(String),
}

impl DeviceStatus {
    /// The machine-readable status key (`changes`, `applied`, `unchanged`,
    /// `skipped`, `failed`).
    pub fn key(&self) -> &'static str {
        match self {
            DeviceStatus::Changes(_) => "changes",
            DeviceStatus::Applied(_) => "applied",
            DeviceStatus::Unchanged => "unchanged",
            DeviceStatus::Skipped(_) => "skipped",
            DeviceStatus::Failed(_) => "failed",
        }
    }

    /// The number of changes this status counted, zero when it counted none.
    pub fn changes(&self) -> usize {
        match self {
            DeviceStatus::Changes(n) | DeviceStatus::Applied(n) => *n,
            _ => 0,
        }
    }

    /// The reason text for a skip or a failure.
    pub fn detail(&self) -> Option<&str> {
        match self {
            DeviceStatus::Skipped(d) | DeviceStatus::Failed(d) => Some(d),
            _ => None,
        }
    }

    /// The human cell for a summary table.
    pub fn label(&self) -> String {
        match self {
            DeviceStatus::Changes(n) => format!("changes: {n}"),
            DeviceStatus::Applied(n) => format!("applied: {n}"),
            DeviceStatus::Unchanged => "unchanged".to_string(),
            DeviceStatus::Skipped(d) => format!("skipped: {d}"),
            DeviceStatus::Failed(d) => format!("failed: {d}"),
        }
    }
}

/// One device to visit: its model identity plus the tables the model wants on it.
#[derive(Debug, Clone)]
pub struct LineTarget {
    /// The device's individual address.
    pub address: IndividualAddress,
    /// Its name from the model.
    pub name: String,
    /// The desired tables, or the reason this device is skipped without a read.
    pub desired: Result<DesiredTables, String>,
}

/// The model's devices on `area.line`, in address order, each with the tables
/// the model wants on it.
///
/// A device with no links in its device file is carried as a skip rather than
/// an error: an empty table set would wipe the device, and one unlinked device
/// must not abort a whole-line run (the single-device `plan` still refuses it).
pub fn targets_on_line(model: &Model, area: u8, line_no: u8) -> Vec<LineTarget> {
    model
        .devices
        .iter()
        .filter(|(ia, _)| ia.area() == area && ia.line() == line_no)
        .map(|(ia, loaded)| {
            let links = model
                .links
                .links
                .get(ia)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let desired = if links.is_empty() {
                Err("no links in your project".to_string())
            } else {
                Ok(compute_tables(links))
            };
            LineTarget {
                address: *ia,
                name: loaded.device.name.clone(),
                desired,
            }
        })
        .collect()
}

/// SHA-256 (hex) over the model side of a line: every target's address,
/// name and desired tables, in address order. A plan of the line records it,
/// and a write refuses when the model no longer produces it.
pub fn targets_digest(targets: &[LineTarget]) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-line-targets-v1");
    for target in targets {
        put(&mut h, &target.address.raw().to_be_bytes());
        put(&mut h, target.name.as_bytes());
        match &target.desired {
            Ok(desired) => put_desired(&mut h, desired),
            Err(why) => put(&mut h, why.as_bytes()),
        }
    }
    hex(&h.finalize())
}

/// What a visit says while it runs, the lines `bussard apply --line` prints
/// under the device's progress line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineNote {
    /// A line about this device (a backup path, an unchecked flag, a product
    /// warning); the CLI indents it under the device.
    Detail(String),
    /// A warning that does not change the outcome; the CLI prints it as is.
    Warning(String),
}

impl LineNote {
    /// The note's text.
    pub fn text(&self) -> &str {
        match self {
            LineNote::Detail(s) | LineNote::Warning(s) => s,
        }
    }
}

/// One device's line in the summary.
#[derive(Debug, Clone)]
pub struct LineOutcome {
    /// The device's individual address.
    pub address: IndividualAddress,
    /// Its name from the model.
    pub name: String,
    /// The mask version it reported, when it answered.
    pub mask: Option<u16>,
    /// What happened.
    pub status: DeviceStatus,
    /// The link plan against the device as read, when it was read.
    pub report: Option<PlanReport>,
    /// SHA-256 (hex) over the device state read and the write it implies
    /// (see [`LineVisit::expected`]), when the device was read.
    pub fingerprint: Option<String>,
    /// The pre-write backup, when one was written.
    pub backup: Option<PathBuf>,
}

/// Resolves a device's KNX Data Secure material; `Err` is the reason.
pub type MaterialFn<'a> = &'a (dyn Fn(IndividualAddress) -> Result<SecureMaterial, String> + Sync);

/// The tunnelling addresses `admit_tunnel_senders` admits for a device
/// written secured (`true`) or in the clear; `Err` is the reason.
pub type TunnelFn<'a> = &'a (dyn Fn(bool) -> Result<Vec<IndividualAddress>, String> + Sync);

/// What every device visit of one run shares.
pub struct LineVisit<'a> {
    /// The open bus.
    pub service: &'a BusService,
    /// The checked source address the run speaks from.
    pub source: IndividualAddress,
    /// The model the run plans against.
    pub model: &'a Model,
    /// The model directory (product data, backups, the lock).
    pub dir: &'a Path,
    /// Plan or apply.
    pub mode: LineMode,
    /// The Data Secure material of a device.
    pub material: MaterialFn<'a>,
    /// The admitted tunnelling addresses (issue #297).
    pub tunnel: TunnelFn<'a>,
    /// The product-parse timing hook, if the surface records one.
    pub on_parse: Option<ParseHook>,
    /// In [`LineMode::Apply`]: the fingerprint each device had when the line
    /// was planned (`knx_apply_device` with `line`). A device whose fresh read
    /// no longer produces its fingerprint, or that the plan did not read, is
    /// failed without a write. `None` (the CLI) writes what the read shows.
    pub expected: Option<&'a BTreeMap<IndividualAddress, String>>,
}

/// Plans (and, in [`LineMode::Apply`], writes) one device.
///
/// Never returns early with an error: a device that cannot be planned or
/// written is an outcome with [`DeviceStatus::Failed`], so a run goes on.
pub async fn visit_device(
    ctx: &LineVisit<'_>,
    target: &LineTarget,
    note: &mut (dyn FnMut(LineNote) + Send),
) -> LineOutcome {
    let mut outcome = LineOutcome {
        address: target.address,
        name: target.name.clone(),
        mask: None,
        status: DeviceStatus::Unchanged,
        report: None,
        fingerprint: None,
        backup: None,
    };
    let status = visit(ctx, target, note, &mut outcome).await;
    outcome.status = status;
    outcome
}

/// The body of [`visit_device`]: fills `out` as it learns and returns the
/// status.
async fn visit(
    ctx: &LineVisit<'_>,
    target: &LineTarget,
    note: &mut (dyn FnMut(LineNote) + Send),
    out: &mut LineOutcome,
) -> DeviceStatus {
    let (service, source, model, dir) = (ctx.service, ctx.source, ctx.model, ctx.dir);
    let desired = match &target.desired {
        Ok(desired) => desired,
        Err(reason) => return DeviceStatus::Skipped(reason.clone()),
    };

    // KNX Data Secure (issue #71): one key per device, since a keyring holds one
    // per address. A device the keyring does not cover fails alone.
    let material = match (ctx.material)(target.address) {
        Ok(material) => material,
        Err(err) => return DeviceStatus::Failed(err),
    };
    let tool_key = material.tool_key.clone();
    // `admit_tunnel_senders` (issue #297): a line run keeps the tunnelling
    // addresses in every table it reprograms, so it never drops them.
    let tunnel = match (ctx.tunnel)(tool_key.is_some()) {
        Ok(tunnel) => tunnel,
        Err(err) => return DeviceStatus::Failed(err),
    };
    // A secured System B write reprograms the security object too (issue
    // #156); on a line walk the keyring is the source of the secured GAs. The
    // model's links name the secured senders of the IA table (issue #181).
    let security = tool_key.as_ref().map(|_| {
        let empty = std::collections::HashMap::new();
        let keys = material.group_keys.as_ref().unwrap_or(&empty);
        let mut inputs = bussard_download::security_inputs_for(None, target.address, desired, keys);
        inputs.senders = bussard_download::secured_senders(
            Some(model),
            target.address,
            keys,
            &material.device_sequences,
            &tunnel,
        );
        inputs.admitted_tunnel = tunnel
            .iter()
            .copied()
            .filter(|ia| *ia != target.address)
            .collect();
        inputs
    });
    let secure_seq = SequenceHighWater::new();

    // The product data places a System 7 device's tables and its group-object
    // table, as `apply` reads them; without it the communication flags go
    // unchecked and the plan says so.
    let product = match resolve_product(
        dir,
        Selection::default(),
        Some(model),
        target.address,
        MissingProduct::Warn,
        ctx.on_parse,
    ) {
        Ok(lookup) => {
            if let Some(warning) = lookup.warning {
                note(LineNote::Detail(format!("warning: {warning}")));
            }
            lookup.source
        }
        Err(err) => return DeviceStatus::Failed(one_line(&err.to_string())),
    };

    // An application without extended memory services gets its tables above
    // 0xFFFF written with A_UserMemory_Write (issue #472).
    let user_memory_above_64k =
        bussard_download::uses_user_memory(product.as_ref().and_then(|p| p.app()));
    let (live, object_table) = match read_device_and_object_table(
        service,
        source,
        model,
        target.address,
        product.as_ref(),
        &tool_key,
        &secure_seq,
    )
    .await
    {
        Ok((LiveRead::Tables(live), object_table)) => (live, object_table),
        Ok((LiveRead::UnsupportedMask { mask, .. }, _)) => {
            out.mask = Some(mask);
            return DeviceStatus::Skipped(format!(
                "unsupported mask {mask:04X} ({})",
                system_type(mask)
            ));
        }
        Err(err) => return DeviceStatus::Failed(one_line(&err)),
    };
    out.fingerprint = Some(fingerprint(
        target.address,
        &live,
        object_table.as_ref(),
        desired,
    ));
    let sys7_live = live.sys7().cloned();
    let live = live.tables();
    let mask = live.mask;
    out.mask = Some(mask);

    // Belt and braces before any write: the readers already gate on the family,
    // but the write path asserts it too (same check as the single-device apply).
    let profile = MaskProfile::from_mask(mask);
    if !(profile.is_system_b() || profile.is_system_7()) {
        return DeviceStatus::Skipped(format!(
            "unsupported mask {mask:04X} ({})",
            system_type(mask)
        ));
    }

    let report = plan(live, desired);
    out.report = Some(report.clone());
    // A System 7 communication flag that does not follow its links is a change
    // too: `apply` writes it with the tables.
    let (flag_writes, unchecked) = sys7_live.as_ref().map_or((0, Vec::new()), |s7| {
        let linked = desired.associations.iter().map(|&(_, a)| a).collect();
        let (writes, unchecked) = sys7_flag_writes(s7, &linked);
        (writes.len(), unchecked)
    });
    if !unchecked.is_empty() {
        note(LineNote::Detail(unchecked_flags_note(&unchecked)));
    }
    // A System B group-object table that differs from the image the full
    // flash writes is reloaded first (issue #540), as the single-device apply
    // does; without a comparison a newly linked object is named.
    let reload = match &object_table {
        Some(check) => match &check.live {
            Ok(_) => check.change().map(|change| {
                for sentence in change.sentences() {
                    note(LineNote::Detail(format!("group-object table: {sentence}")));
                }
                (check.model.clone(), change.objects.len().max(1))
            }),
            Err(why) => {
                if let Some(line) = unchecked_object_table_note(&report, why) {
                    note(LineNote::Detail(line));
                }
                None
            }
        },
        None if sys7_live.is_none() => {
            if let Some(line) = unchecked_object_table_note(&report, "no product data writes it") {
                note(LineNote::Detail(line));
            }
            None
        }
        None => None,
    };
    let tables_change = !report.is_noop() || flag_writes > 0;
    let changes = report.additions.len()
        + report.removals.len()
        + flag_writes
        + reload.as_ref().map_or(0, |(_, n)| *n);
    if !tables_change && reload.is_none() {
        return DeviceStatus::Unchanged;
    }
    if ctx.mode == LineMode::Plan {
        return DeviceStatus::Changes(changes);
    }

    // The plan the human approved binds this device (`knx_apply_device` with
    // `line`): a device that moved since is not written.
    if let Some(expected) = ctx.expected {
        match expected.get(&target.address) {
            Some(planned) if Some(planned) == out.fingerprint.as_ref() => {}
            Some(_) => {
                return DeviceStatus::Failed(
                    "the device changed since the line was planned; nothing was written to it \
                     (plan the line again)"
                        .to_string(),
                );
            }
            None => {
                return DeviceStatus::Failed(
                    "the line plan did not read this device; nothing was written to it (plan \
                     the line again)"
                        .to_string(),
                );
            }
        }
    }

    // System 7 region images are computed before anything is backed up or
    // written, so an image that would not fit refuses without touching the device.
    let images = match &sys7_live {
        Some(s7) => match sys7_table_images(s7, desired) {
            Ok(images) => Some(images),
            Err(err) => {
                return DeviceStatus::Failed(format!("computing the System 7 table images: {err}"));
            }
        },
        None => None,
    };

    let backup_path = match bussard_download::write_pre_write_backup(
        dir,
        target.address,
        live,
        sys7_live.as_ref(),
    ) {
        Ok(path) => path,
        Err(err) => {
            return DeviceStatus::Failed(format!(
                "no backup written, so nothing was written to the device: {}",
                chain(&err)
            ));
        }
    };
    note(LineNote::Detail(format!(
        "backup written to {}",
        backup_path.display()
    )));
    out.backup = Some(backup_path.clone());

    let channel = match service.lease_channel().await {
        Ok(channel) => channel,
        Err(err) => return DeviceStatus::Failed(session_error_detail(&err)),
    };
    let secure = crate::secure::layer(&tool_key, &secure_seq);
    let verified = match &images {
        Some(images) => {
            bussard_download::write_sys7(channel, target.address, source, mask, images, secure)
                .await
                .map(|v| (v.ok(), v.restarted, format!("{v:?}")))
                .map_err(|e| e.to_string())
        }
        None => bussard_download::write_system_b_seeded(
            channel,
            target.address,
            source,
            desired,
            secure,
            bussard_download::SystemBLoad {
                security: security.as_ref(),
                object_table: reload.as_ref().map(|(image, _)| image.as_slice()),
                keep_tables: !tables_change,
                user_memory_above_64k,
            },
            None,
        )
        .await
        .map(|v| (v.ok(), false, format!("{v:?}")))
        .map_err(|e| e.to_string()),
    };

    match verified {
        Ok((true, true, _)) => {
            // A System 7 write ends with a basic restart: wait for the device,
            // then read its tables back on a fresh connection, which also shows
            // the write survived the restart.
            match verify_after_restart(
                service,
                source,
                target.address,
                mask,
                desired,
                product.as_ref(),
                &tool_key,
                &secure_seq,
            )
            .await
            {
                Ok(()) => DeviceStatus::Applied(changes),
                Err(why) => DeviceStatus::Failed(format!(
                    "{}; pre-state backed up to {}",
                    one_line(&why),
                    backup_path.display()
                )),
            }
        }
        Ok((true, _, _)) => {
            // A verified secured System B write put this PID 54 table on the
            // device: record it in the lock, as `adopt` does (issue #297). A
            // reload of the group-object table alone does not write it.
            if let (Some(inputs), None, true) = (&security, &sys7_live, tables_change)
                && let Err(err) =
                    crate::admission::record_secure_senders(dir, target.address, &inputs.senders)
            {
                note(LineNote::Warning(format!(
                    "warning: {}: {err}",
                    target.address
                )));
            }
            DeviceStatus::Applied(changes)
        }
        Ok((false, _, detail)) => DeviceStatus::Failed(format!(
            "did not verify: {}; pre-state backed up to {}",
            one_line(&detail),
            backup_path.display()
        )),
        Err(err) => DeviceStatus::Failed(format!(
            "{}; pre-state backed up to {}",
            one_line(&err),
            backup_path.display()
        )),
    }
}

/// SHA-256 (hex) over one device's state as read and the write the model asks
/// for: the address, [`bussard_download::state_hash_with`] of the tables and
/// the group-object table read, the desired tables and the group-object
/// image the write would load.
fn fingerprint(
    address: IndividualAddress,
    live: &LiveTables,
    object_table: Option<&ObjectTableCheck>,
    desired: &DesiredTables,
) -> String {
    let live_image = object_table.and_then(|c| c.live.as_ref().ok().map(|t| t.image()));
    let mut h = Sha256::new();
    put(&mut h, b"bussard-line-device-v1");
    put(&mut h, &address.raw().to_be_bytes());
    put(
        &mut h,
        bussard_download::state_hash_with(live, None, live_image.as_deref()).as_bytes(),
    );
    put_desired(&mut h, desired);
    match object_table {
        Some(check) => {
            put(&mut h, b"object-table");
            put(&mut h, &check.model);
            if let Err(why) = &check.live {
                put(&mut h, why.as_bytes());
            }
        }
        None => put(&mut h, b"no-object-table"),
    }
    hex(&h.finalize())
}

/// Hashes the desired tables.
fn put_desired(h: &mut Sha256, desired: &DesiredTables) {
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

/// Feeds a length-prefixed field to the hasher, so field boundaries count.
fn put(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The note for newly linked System 7 objects whose communication flag could
/// not be checked.
fn unchecked_flags_note(objects: &[u16]) -> String {
    let list = objects
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "object(s) {list}: newly linked, but the communication flag was not checked (the \
         group-object table was not read: no product data places it, or the device refused \
         the read); the device may ignore these links"
    )
}

/// The note for newly linked System B objects whose communication flag was
/// not checked, because the group-object table was not compared. `None` when
/// the plan links no new object.
fn unchecked_object_table_note(report: &PlanReport, why: &str) -> Option<String> {
    let objects: BTreeSet<u16> = report.additions.iter().map(|a| a.object).collect();
    if objects.is_empty() {
        return None;
    }
    let list = objects
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "object(s) {list}: newly linked, but the communication flag was not checked (the \
         group-object table was not compared: {why}); the device may ignore these links"
    ))
}

/// The read options of a line run: free-access authorize, best-effort, as the
/// single-device `apply` read phase.
fn read_options(
    source: IndividualAddress,
    tool_key: &Option<Key16>,
    secure_seq: &SequenceHighWater,
) -> L4Options {
    L4Options {
        source: SourcePolicy::Known(source),
        tool_key: tool_key.clone(),
        high_water: secure_seq.clone(),
        // Authorize (free access) before reading, as ETS does (issue #52
        // finding #1) and as System 7 requires before any memory access.
        // Best-effort.
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    }
}

/// Where the device's product puts a System 7 device's tables; the corpus
/// defaults without a product.
fn table_bases(product: Option<&ProductSource>) -> bussard_download::Sys7TableBases {
    product
        .and_then(|p| p.app())
        .map(bussard_download::sys7_table_bases)
        .unwrap_or_default()
}

/// After a System 7 write's closing restart: waits for the device to answer
/// again as `mask`, reads its tables back and checks they and the
/// communication flags match `desired`.
#[allow(clippy::too_many_arguments)] // the read phase's inputs plus what to compare
async fn verify_after_restart(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    mask: u16,
    desired: &DesiredTables,
    product: Option<&ProductSource>,
    tool_key: &Option<Key16>,
    secure_seq: &SequenceHighWater,
) -> Result<(), String> {
    crate::restart::wait_until_back(
        service,
        target,
        &read_options(source, tool_key, secure_seq),
        mask,
        crate::restart::RestartWait::default(),
    )
    .await
    .map_err(|err| err.to_string())?;
    let options = read_options(source, tool_key, secure_seq);
    let read = service
        .with_l4(target, &options, async |l4| {
            Ok::<_, ServiceError>(
                bussard_download::read_live_tables_at(l4, table_bases(product))
                    .await
                    .map_err(|e| chain(&e)),
            )
        })
        .await
        .map_err(|err| session_open_error(&err))
        .and_then(|read| read);
    let live = match read {
        Ok(LiveRead::Tables(live)) => live,
        Ok(LiveRead::UnsupportedMask { mask, .. }) => {
            return Err(format!(
                "read back after the restart: mask {mask:04X} is not supported"
            ));
        }
        Err(err) => return Err(format!("read back after the restart: {err}")),
    };
    if !plan(live.tables(), desired).is_noop() {
        return Err(
            "read back after the restart: the tables do not match your project".to_string(),
        );
    }
    if let Some(s7) = live.sys7() {
        let linked = desired.associations.iter().map(|&(_, a)| a).collect();
        let (writes, _) = sys7_flag_writes(s7, &linked);
        if let Some(flag) = writes.first() {
            return Err(format!(
                "read back after the restart: object {}'s communication flag reads {:02X}, \
                 the model needs {:02X}",
                flag.object, flag.from, flag.to
            ));
        }
    }
    Ok(())
}

/// Reads one device's live tables on a fresh lease (connect, best-effort
/// free-access authorize, read, disconnect) and, on a System B device with
/// product data, its group-object table against the image the full flash
/// writes (issue #540), over the same session. `Err` is the reason, as the
/// CLI prints it.
async fn read_device_and_object_table(
    service: &BusService,
    source: IndividualAddress,
    model: &Model,
    target: IndividualAddress,
    product: Option<&ProductSource>,
    tool_key: &Option<Key16>,
    secure_seq: &SequenceHighWater,
) -> Result<(LiveRead, Option<ObjectTableCheck>), String> {
    let options = read_options(source, tool_key, secure_seq);
    service
        .with_l4(target, &options, async |l4| {
            let read = bussard_download::read_live_tables_at(l4, table_bases(product)).await;
            let check = match (&read, product) {
                (Ok(LiveRead::Tables(live)), Some(product)) if live.sys7().is_none() => {
                    match product.app().map(|app| {
                        bussard_download::plan_for_readback(
                            &product.product,
                            app,
                            Some(model),
                            target,
                            live.tables().mask,
                        )
                    }) {
                        Some(Ok(plan)) => bussard_download::check_object_table(l4, &plan).await,
                        _ => None,
                    }
                }
                _ => None,
            };
            Ok::<_, ServiceError>(read.map(|read| (read, check)).map_err(|e| chain(&e)))
        })
        .await
        .map_err(|err| session_open_error(&err))
        .and_then(|read| read)
}

/// A management session that could not be opened, in the words the CLI used:
/// a lease failure as it is, a connect failure under "connecting to the
/// device".
fn session_open_error(err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(_) => chain(err),
        other => format!("connecting to the device: {}", chain(other)),
    }
}

/// A management session that could not be opened, as a per-device row reads
/// it: `leasing the bus: <cause>` or `connecting: <cause>`.
fn session_error_detail(err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(cause) => format!("leasing the bus: {cause}"),
        other => format!("connecting: {other}"),
    }
}

/// An error and its sources joined with `": "` (anyhow's `{:#}`).
fn chain(err: &dyn StdError) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Flattens a multi-line error into one summary-table cell.
pub fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_accepts_area_line() -> Result<(), LineError> {
        assert_eq!(parse_line("1.1")?, (1, 1));
        assert_eq!(parse_line("0.15")?, (0, 15));
        // A full address is accepted, its device part ignored.
        assert_eq!(parse_line("2.3.47")?, (2, 3));
        Ok(())
    }

    #[test]
    fn test_parse_line_rejects_nonsense() {
        assert!(parse_line("1").is_err());
        assert!(parse_line("16.1").is_err());
        assert!(parse_line("a.b").is_err());
    }

    #[test]
    fn test_device_status_labels_and_keys() {
        assert_eq!(DeviceStatus::Changes(3).label(), "changes: 3");
        assert_eq!(DeviceStatus::Applied(2).key(), "applied");
        assert_eq!(DeviceStatus::Unchanged.changes(), 0);
        assert_eq!(
            DeviceStatus::Skipped("unsupported mask 0012 (System 1)".to_string()).label(),
            "skipped: unsupported mask 0012 (System 1)"
        );
    }

    #[test]
    fn test_one_line_flattens_multiline_errors() {
        assert_eq!(one_line("a\n\n  b  \nc"), "a; b; c");
    }

    #[test]
    fn test_targets_digest_changes_with_the_desired_tables() -> Result<(), String> {
        let ia: IndividualAddress = "1.1.4".parse().map_err(|_| "address".to_string())?;
        let target = |associations: Vec<(u16, u16)>| LineTarget {
            address: ia,
            name: "a".into(),
            desired: Ok(DesiredTables {
                addresses: Vec::new(),
                associations,
            }),
        };
        let a = targets_digest(&[target(vec![(1, 20)])]);
        let b = targets_digest(&[target(vec![(1, 21)])]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(a, targets_digest(&[target(vec![(1, 20)])]));
        Ok(())
    }
}
