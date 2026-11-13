//! The write half of `bussard apply`, `bussard restore`, `knx_apply_device`
//! and `knx_restore_tables` (issue #901): the link tables (with the System B
//! group-object table reload and the security object they carry), the wait
//! for a System 7 device's closing restart, the lock records of what a
//! verified secured write programmed, the parameter octets that differ, and
//! the independent read-back every write ends with (issues #319, #349). One
//! function, so the surfaces cannot drift (the #314 rule).

use std::path::{Path, PathBuf};
use std::time::Duration;

use bussard_download::{DesiredTables, FlashPlan, SecurityInputs, Sys7TableImages, backup};
use bussard_mgmt::ConnectionSeed;
use bussard_model::{IndividualAddress, Model};
use bussard_secure::{Key16, SequenceHighWater};

use crate::download::ParamWriteOutcome;
use crate::flash_flow::LockRecord;
use crate::observer::{Event, Observer, Step};
use crate::params::{ParamDetail, ProductSource};
use crate::verify::WriteReadback;
use crate::verify::{Expected, ExpectedParameters, ExpectedProperty, ExpectedSecurity};
use crate::{Authorize, BusService, L4Options};

/// The backups a write takes before its first write: the link tables, and the
/// parameter memory it overwrites.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Backups {
    /// The pre-write table backup (`<dir>/captures/backups/<ia>-<ts>.json`).
    pub tables: Option<PathBuf>,
    /// The parameter memory backup
    /// (`<dir>/captures/backups/parameters/<ia>-<ts>.json`).
    pub parameters: Option<PathBuf>,
}

/// Writes the pre-write backup of the tables `live` (and of the parameter
/// memory in `parameters`), refusing the write when one cannot be written.
///
/// # Errors
///
/// A backup could not be written; nothing may be written to the device then.
pub fn back_up(
    dir: &Path,
    target: IndividualAddress,
    live: &bussard_download::LiveTables,
    parameters: Option<&ParamDetail>,
) -> Result<Backups, BackupError> {
    let tables = bussard_download::write_pre_write_backup(dir, target, live.tables(), live.sys7())
        .map_err(BackupError::Tables)?;
    let parameters = parameters
        .map(|detail| back_up_parameters(dir, target, detail))
        .transpose()?;
    Ok(Backups {
        tables: Some(tables),
        parameters,
    })
}

/// Writes the parameter memory backup of `detail`.
///
/// # Errors
///
/// The backup could not be written.
pub fn back_up_parameters(
    dir: &Path,
    target: IndividualAddress,
    detail: &ParamDetail,
) -> Result<PathBuf, BackupError> {
    bussard_download::write_parameter_memory_backup(
        dir,
        target,
        &detail.plan,
        &detail.regions,
        &detail.properties,
    )
    .map_err(BackupError::Parameters)
}

/// Whether a parameter backup of `regions` and `properties` holds what a
/// restore needs: a memory region or a parameter property that was read (a
/// program whose parameters all live in properties has no region, issue
/// #944), and every parameter property the write would change read first.
/// A property whose read failed counts as differing and is written, but the
/// backup cannot record it, so a later restore could not put it back: the
/// write must not start then.
///
/// # Errors
///
/// [`BackupError::NoParameterMemory`] when the backup would be empty,
/// [`BackupError::UnreadParameterProperty`] when a property it would leave
/// out could not be read.
pub fn check_backup_covers(
    regions: &bussard_download::ParamRegions,
    properties: &[bussard_download::ParamProperty],
) -> Result<(), BackupError> {
    if regions.is_empty() && !properties.iter().any(|p| p.device.is_some()) {
        return Err(BackupError::NoParameterMemory);
    }
    let unread: Vec<String> = properties
        .iter()
        .filter(|p| p.device.is_none())
        .map(bussard_download::ParamProperty::label)
        .collect();
    if !unread.is_empty() {
        return Err(BackupError::UnreadParameterProperty {
            properties: unread.join(", "),
        });
    }
    Ok(())
}

/// [`check_backup_covers`] for the parameter backup a parameter-only write
/// of `detail` takes first; the write must not start when it fails. A full
/// flash rewrites everything and needs no such check.
///
/// # Errors
///
/// As [`check_backup_covers`].
pub fn check_parameter_backup(detail: &ParamDetail) -> Result<(), BackupError> {
    check_backup_covers(&detail.regions, &detail.properties)
}

/// A backup that could not be written.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The table backup.
    #[error(transparent)]
    Tables(backup::BackupError),
    /// The parameter memory backup.
    #[error(transparent)]
    Parameters(backup::BackupError),
    /// The parameter backup would hold nothing: no parameter memory region
    /// and no parameter property could be read.
    #[error(
        "the parameter backup would be empty: neither the device's parameter memory nor the \
         properties its parameters live in could be read, so nothing could be restored from \
         it; nothing is written"
    )]
    NoParameterMemory,
    /// A parameter property the write would change could not be read, so
    /// the backup cannot record it (issue #944).
    #[error(
        "the parameter backup would miss {properties}: the device did not answer the read of \
         that property, so the backup could not put it back; nothing is written. Read the \
         device again, or run a full flash"
    )]
    UnreadParameterProperty {
        /// The properties, in words (`object 10 PID 53`).
        properties: String,
    },
}

/// What one write of a device needs.
pub struct ApplyRequest<'a> {
    /// The bus.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The model directory (the lock).
    pub dir: &'a Path,
    /// The model the read-back compares the parameters with; `None` records
    /// nothing in the lock.
    pub model: Option<&'a Model>,
    /// The product data the parameters are decoded with.
    pub product: Option<&'a ProductSource>,
    /// The device's mask, as read.
    pub mask: u16,
    /// The tables to write.
    pub desired: &'a DesiredTables,
    /// Whether the link tables are rewritten
    /// ([`crate::params::BuiltPlan::tables_change`]).
    pub tables_change: bool,
    /// The System B group-object table image, for a device whose table was
    /// read: written with the link tables by the partial download of the
    /// three tables, which ends with a restart (issue #1095), or alone when
    /// it differs and the links stay (issue #540). `None` without product
    /// data, or when the device's table did not read: the link tables alone.
    pub object_table: Option<&'a crate::params::GroupObjectImage>,
    /// A restart the last write left unsent ([`crate::pending_restart`]):
    /// this write sends it when its own does not.
    pub restart_pending: bool,
    /// The System 7 table images.
    pub images: Option<&'a Sys7TableImages>,
    /// The security object a secured System B write reprograms.
    pub security: Option<&'a SecurityInputs>,
    /// The parameter-only download and the read it was planned from.
    pub parameters: Option<(&'a FlashPlan, &'a ParamDetail)>,
    /// The KNX Data Secure tool key, `None` on the plain path.
    pub tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared with the read.
    pub high_water: SequenceHighWater,
    /// The session options of the restart wait, the parameter write and the
    /// read-back.
    pub options: L4Options,
    /// The device facts the read checked, seeding every later connection.
    pub seed: Option<ConnectionSeed>,
    /// The support gate's grant for the device (issue #1089).
    pub support: &'a crate::support::SupportGrant,
}

/// How a write of the link tables ended.
#[derive(Debug)]
pub enum TablesWritten {
    /// The bus could not be leased.
    Lease(crate::ServiceError),
    /// The write ran.
    Ran(bussard_download::program::TableWriteSummary),
    /// The write failed.
    Failed(String),
}

impl TablesWritten {
    /// Whether the tables loaded and read back byte for byte.
    pub fn verified(&self) -> bool {
        matches!(self, TablesWritten::Ran(summary) if summary.ok)
    }
}

/// Why the restart that ends a table write did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestartFailure {
    /// It could not be sent, was refused or was not confirmed. The device
    /// holds what was written; the restart stays pending
    /// ([`crate::pending_restart`]) and the next plan offers it.
    #[error("the restart was not sent ({0}); the next plan offers it again")]
    NotSent(String),
    /// It was sent, and the device did not answer again.
    #[error("the device did not come back after its restart: {0}")]
    NoAnswer(String),
}

/// What one write of a device did.
#[derive(Debug, Default)]
pub struct Written {
    /// The table write, when the tables (or the group-object table) were
    /// written.
    pub tables: Option<TablesWritten>,
    /// The restart that ended the table write (a System 7 write's own, or
    /// the one the System B partial download leaves due, issue #1095): how
    /// long until the device answered again, or why it was not sent,
    /// confirmed or answered.
    pub restarted: Option<Result<Duration, RestartFailure>>,
    /// What a verified secured write recorded in the lock: the PID 54 table
    /// and the PID 61 flags it programmed.
    pub lock: LockRecord,
    /// The parameter write, when the parameters were written.
    pub parameters: Option<Result<ParamWriteOutcome, String>>,
    /// The independent read-back, unless a write stopped before it reached
    /// the device.
    pub readback: Option<WriteReadback>,
}

impl Written {
    /// Whether a write stopped before it reached the device (no lease, a
    /// sequence error, a device that did not come back, a failed parameter
    /// session): there is nothing new to read back.
    pub fn stopped(&self) -> bool {
        matches!(
            self.tables,
            Some(TablesWritten::Lease(_) | TablesWritten::Failed(_))
        ) || matches!(self.restarted, Some(Err(RestartFailure::NoAnswer(_))))
            || matches!(
                self.parameters,
                Some(Err(_) | Ok(ParamWriteOutcome::Failed(_)))
            )
    }

    /// Whether everything written verified and the read-back found nothing
    /// that differs.
    pub fn verified(&self) -> bool {
        self.tables.as_ref().is_none_or(TablesWritten::verified)
            && !matches!(self.restarted, Some(Err(_)))
            && self
                .parameters
                .as_ref()
                .is_none_or(|p| p.as_ref().is_ok_and(ParamWriteOutcome::ok))
            && self
                .readback
                .as_ref()
                .is_some_and(|r| r.failure().is_none())
    }
}

/// The expected state the read-back after a write compares with (issue
/// #349): the tables, a reloaded group-object table, the written parameters
/// and their properties (issue #669), and a rewritten security object.
pub fn expected<'a>(req: &ApplyRequest<'a>) -> Expected<'a> {
    let written_params = req.parameters.filter(|_| req.product.is_some());
    Expected {
        tables: Some(req.desired.clone()),
        group_objects: None,
        object_table: written_object_table(req).map(<[u8]>::to_vec),
        parameters: written_params.and_then(|_| {
            let product = req.product?;
            product.app().map(|app| ExpectedParameters {
                product: &product.product,
                app,
                model: req.model,
                device_mask: req.mask,
            })
        }),
        security: req
            .security
            .filter(|_| req.tables_change)
            .map(|inputs| ExpectedSecurity::from_inputs(inputs, &req.desired.addresses)),
        properties: req
            .parameters
            .map(|(_, detail)| ExpectedProperty::from_checked(&detail.plan))
            .unwrap_or_default(),
        table_bases: super::read::table_bases(req.product),
    }
}

/// The group-object table image a write of `req` sends: with a link change
/// the image the partial download reloads with the link tables (issue #1095),
/// else the reload of a table that differs (issue #540).
fn written_object_table<'a>(req: &ApplyRequest<'a>) -> Option<&'a [u8]> {
    req.object_table
        .filter(|_| req.images.is_none())
        .and_then(|group| group.written(req.tables_change))
}

/// Writes one device: the tables when a link changes (or the group-object
/// table needs its reload), the lock records once they verified, the wait
/// for the restart that ends the table write, the parameter octets that
/// differ, a restart left pending, then the independent read-back. A restart
/// that could not be sent stays pending ([`crate::pending_restart`]). Never
/// refuses: what failed is in the outcome.
pub async fn apply_device(req: ApplyRequest<'_>, observer: &mut impl Observer) -> Written {
    let mut out = Written::default();
    if let Err(refusal) = req.support.covers(req.target) {
        out.tables = Some(TablesWritten::Failed(refusal));
        return out;
    }
    let expected = expected(&req);
    let target = req.target;
    // The facts the read checked seed every later connection; a device they
    // record as not answering authorize is not asked again (issue #215).
    let checked = req.options.clone().with_authorize(
        if req.seed.as_ref().is_some_and(|s| s.authorize_unanswered) {
            Authorize::Skip
        } else {
            req.options.authorize
        },
    );
    // The restart that ends the procedure: sent by the table write, left to
    // the parameter download, or pending from an earlier write (#1095).
    let mut restart = if req.restart_pending {
        bussard_download::TableRestart::NotSent("pending from an earlier write".to_string())
    } else {
        bussard_download::TableRestart::NotDue
    };
    if req.tables_change || written_object_table(&req).is_some() {
        let tables = write_tables(&req, &mut *observer).await;
        let verified = tables.verified();
        if let TablesWritten::Ran(summary) = &tables
            && summary.restart != bussard_download::TableRestart::NotDue
        {
            restart = summary.restart.clone();
        }
        out.tables = Some(tables);
        if !verified {
            out.readback = read_back(&req, &checked, &expected, &out, &mut *observer).await;
            return out;
        }
        // The tables verified: the security object was written with this
        // PID 54 table, record it in the lock as `adopt` does (issue #297),
        // and the group-object flags it wrote (PID 61, issue #331), whatever
        // the restart does next. A reload of the group-object table alone
        // writes neither.
        if let (Some(inputs), Some(_), true) = (req.security, req.model, req.tables_change) {
            out.lock = LockRecord {
                senders: Some((
                    crate::admission::record_secure_senders(req.dir, target, &inputs.senders)
                        .map_err(|err| err.to_string()),
                    inputs.senders.len(),
                )),
                flags: Some((
                    crate::security_change::record_security_flags(
                        req.dir,
                        target,
                        &inputs.secure_objects,
                    )
                    .map_err(|err| err.to_string()),
                    inputs.secure_objects.len(),
                )),
            };
        }
        if let bussard_download::TableRestart::Sent { process_wait } = restart {
            out.restarted = Some(wait_for_restart(&req, &checked, process_wait, observer).await);
            if matches!(out.restarted, Some(Err(_))) {
                return out;
            }
        }
    }
    // Then the parameter octets that differ (issue #274): the parameter-only
    // download, verified by reading the memory back. It restarts the device
    // itself, which also ends a partial download that left it its restart.
    if let Some((partial, detail)) = req.parameters {
        observer.event(Event::Step(Step::WriteParameters { plan: partial }));
        let outcome = crate::download::write_parameters(
            crate::download::ParamWrite {
                service: req.service,
                target,
                source: req.source,
                partial,
                detail,
                tool_key: req.tool_key.clone(),
                high_water: req.high_water.clone(),
                read_options: &checked,
                read_back_properties: false,
                support: req.support,
            },
            &mut *observer,
        )
        .await
        .map_err(|err| super::chain(&err));
        if restart == bussard_download::TableRestart::Deferred
            && outcome.as_ref().is_ok_and(ParamWriteOutcome::ok)
            && defers_restart(&req)
        {
            restart = bussard_download::TableRestart::Sent {
                process_wait: Duration::ZERO,
            };
        }
        out.parameters = Some(outcome);
    }
    // A restart pending from an earlier write that nothing above sent.
    if req.restart_pending
        && matches!(restart, bussard_download::TableRestart::NotSent(_))
        && !out.stopped()
    {
        observer.event(Event::Step(Step::WaitRestart));
        out.restarted = Some(
            crate::restart::restart_device(
                req.service,
                target,
                &checked,
                restart_form(&req),
                crate::restart::RestartWait::default(),
            )
            .await
            .map(|outcome| outcome.answered_after)
            .map_err(|err| match err {
                crate::restart::RestartError::NoAnswer { .. }
                | crate::restart::RestartError::MaskChanged { .. } => {
                    RestartFailure::NoAnswer(err.to_string())
                }
                other => RestartFailure::NotSent(other.to_string()),
            }),
        );
        if matches!(
            out.restarted,
            Some(Ok(_)) | Some(Err(RestartFailure::NoAnswer(_)))
        ) {
            restart = bussard_download::TableRestart::Sent {
                process_wait: Duration::ZERO,
            };
        }
    }
    // The restart the tables need and nothing sent stays pending, so the
    // next plan offers it; a sent one clears it.
    match &restart {
        bussard_download::TableRestart::NotSent(why) => {
            if !matches!(out.restarted, Some(Err(_))) {
                out.restarted = Some(Err(RestartFailure::NotSent(why.clone())));
            }
            let _ = crate::pending_restart::mark(req.dir, target, why);
        }
        bussard_download::TableRestart::Deferred => {
            let why = "it was left to the parameter download, which did not complete";
            out.restarted = Some(Err(RestartFailure::NotSent(why.to_string())));
            let _ = crate::pending_restart::mark(req.dir, target, why);
        }
        bussard_download::TableRestart::Sent { .. } => {
            let _ = crate::pending_restart::clear(req.dir, target);
        }
        bussard_download::TableRestart::NotDue => {}
    }
    out.readback = read_back(&req, &checked, &expected, &out, observer).await;
    out
}

/// The restart form of `req`'s application ([`bussard_download::restart_form`]),
/// basic without product data.
fn restart_form(req: &ApplyRequest<'_>) -> bussard_download::RestartForm {
    req.product.and_then(ProductSource::app).map_or(
        bussard_download::RestartForm::Basic,
        bussard_download::restart_form,
    )
}

/// Waits for the device after the restart a table write sent in its own
/// session: the announced process time, then until it answers again as the
/// same mask, on the `checked` session options (a device that does not
/// answer `A_Authorize` is not asked again, #215).
async fn wait_for_restart(
    req: &ApplyRequest<'_>,
    checked: &L4Options,
    process_wait: Duration,
    observer: &mut impl Observer,
) -> Result<Duration, RestartFailure> {
    observer.event(Event::Step(Step::WaitRestart));
    let started = std::time::Instant::now();
    tokio::time::sleep(process_wait).await;
    crate::restart::wait_until_back(
        req.service,
        req.target,
        checked,
        req.mask,
        crate::restart::RestartWait::default(),
    )
    .await
    .map(|_| started.elapsed())
    .map_err(|err| RestartFailure::NoAnswer(err.to_string()))
}

/// Writes the link tables (with the System B group-object table and the
/// security object `req` carries): the table write of [`apply_device`]. The
/// restart that ends it (a System 7 write's, or the System B partial
/// download's, issue #1095) is sent in the write session; the summary says
/// how ([`bussard_download::TableRestart`]).
pub async fn write_tables(req: &ApplyRequest<'_>, observer: &mut impl Observer) -> TablesWritten {
    observer.event(Event::Step(Step::WriteTables));
    let written = match req.support.covers(req.target) {
        Err(refusal) => TablesWritten::Failed(refusal),
        Ok(()) => lease_and_write(req).await,
    };
    observer.event(Event::Done {
        step: Step::WriteTables,
        verified: written.verified(),
    });
    written
}

/// Whether the parameter download `req` carries ends with a restart of its
/// own, so the partial download of the tables leaves its restart to it
/// (issue #1095): one restart, at the end, as the plan says.
pub fn defers_restart(req: &ApplyRequest<'_>) -> bool {
    req.parameters.is_some_and(|(partial, _)| {
        partial.steps.iter().any(|step| {
            matches!(
                step,
                bussard_download::FlashStep::Restart
                    | bussard_download::FlashStep::MasterReset { .. }
            )
        })
    })
}

/// Leases the bus and writes the link tables `req` carries.
async fn lease_and_write(req: &ApplyRequest<'_>) -> TablesWritten {
    match req.service.lease_channel().await {
        Err(err) => TablesWritten::Lease(err),
        Ok(channel) => match bussard_download::write_tables(
            channel,
            req.target,
            req.source,
            req.mask,
            req.desired,
            req.images,
            crate::secure::layer(&req.tool_key, &req.high_water),
            bussard_download::SystemBLoad {
                security: req.security,
                object_table: written_object_table(req),
                keep_tables: !req.tables_change,
                user_memory_above_64k: bussard_download::uses_user_memory(
                    req.product.and_then(ProductSource::app),
                ),
                confirmed_restart: restart_form(req).is_confirmed(),
                defer_restart: defers_restart(req),
            },
            req.seed.clone(),
        )
        .await
        {
            Ok(summary) => TablesWritten::Ran(summary),
            Err(err) => TablesWritten::Failed(err),
        },
    }
}

/// The independent read-back after a write, `None` when a write stopped
/// before it reached the device.
async fn read_back(
    req: &ApplyRequest<'_>,
    options: &L4Options,
    expected: &Expected<'_>,
    out: &Written,
    observer: &mut impl Observer,
) -> Option<WriteReadback> {
    if out.stopped() {
        return None;
    }
    observer.event(Event::Step(Step::ReadBack));
    Some(
        crate::verify::read_back_on(req.service, req.target, options, req.seed.clone(), expected)
            .await,
    )
}
