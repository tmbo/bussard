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

use super::observer::{Observer, Step};
use crate::download::ParamWriteOutcome;
use crate::flash_flow::LockRecord;
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
    bussard_download::write_parameter_memory_backup(dir, target, &detail.plan, &detail.regions)
        .map_err(BackupError::Parameters)
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
    /// Whether the link tables are rewritten (otherwise only the group-object
    /// table is reloaded, when `object_table` is given).
    pub tables_change: bool,
    /// The System B group-object table image to reload (issue #540).
    pub object_table: Option<&'a [u8]>,
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

/// What one write of a device did.
#[derive(Debug, Default)]
pub struct Written {
    /// The table write, when the tables (or the group-object table) were
    /// written.
    pub tables: Option<TablesWritten>,
    /// The wait for a System 7 device's closing restart: how long it took,
    /// or why the device did not come back.
    pub restarted: Option<Result<Duration, String>>,
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
        ) || matches!(self.restarted, Some(Err(_)))
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
        object_table: req.object_table.map(<[u8]>::to_vec),
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
            .map(|(_, detail)| ExpectedProperty::from_parameter_writes(&detail.plan))
            .unwrap_or_default(),
        table_bases: super::read::table_bases(req.product),
    }
}

/// Writes one device: the tables when a link changes (or the group-object
/// table needs its reload), the restart wait of a System 7 write, the lock
/// records, the parameter octets that differ, then the independent
/// read-back. Never refuses: what failed is in the outcome.
pub async fn apply_device(req: ApplyRequest<'_>, observer: &mut impl Observer) -> Written {
    let mut out = Written::default();
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
    if req.tables_change || req.object_table.is_some() {
        let (tables, restarted) = write_tables(&req, true, &mut *observer).await;
        let verified = tables.verified();
        out.tables = Some(tables);
        if !verified {
            out.readback = read_back(&req, &checked, &expected, &out, &mut *observer).await;
            return out;
        }
        let failed = matches!(restarted, Some(Err(_)));
        out.restarted = restarted;
        if failed {
            return out;
        }
        // The security object was written with this PID 54 table and the
        // write verified: record it in the lock, as `adopt` does (issue
        // #297), and the group-object flags it wrote (PID 61, issue #331). A
        // reload of the group-object table alone writes neither.
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
    }
    // Then the parameter octets that differ (issue #274): the parameter-only
    // download, verified by reading the memory back.
    if let Some((partial, detail)) = req.parameters {
        observer.step(Step::WriteParameters { plan: partial });
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
            },
            &mut *observer,
        )
        .await
        .map_err(|err| super::chain(&err));
        out.parameters = Some(outcome);
    }
    out.readback = read_back(&req, &checked, &expected, &out, observer).await;
    out
}

/// Writes the link tables (with the System B group-object table reload and
/// the security object `req` carries) and, with `wait_restart`, waits for a
/// System 7 device's closing restart, as ETS's table-only downloads end: the
/// table write of [`apply_device`] and of a line run's device
/// ([`crate::line::visit_device`]). Returns how the write ended and how the
/// wait did, `None` when there was none.
pub async fn write_tables(
    req: &ApplyRequest<'_>,
    wait_restart: bool,
    observer: &mut impl Observer,
) -> (TablesWritten, Option<Result<Duration, String>>) {
    observer.step(Step::WriteTables);
    let written = match req.service.lease_channel().await {
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
                object_table: req.object_table,
                keep_tables: !req.tables_change,
                user_memory_above_64k: bussard_download::uses_user_memory(
                    req.product.and_then(ProductSource::app),
                ),
            },
            req.seed.clone(),
        )
        .await
        {
            Ok(summary) => TablesWritten::Ran(summary),
            Err(err) => TablesWritten::Failed(err),
        },
    };
    observer.done(Step::WriteTables, written.verified());
    let restart = matches!(&written, TablesWritten::Ran(s) if s.ok && s.restarted);
    if !(restart && wait_restart) {
        return (written, None);
    }
    observer.step(Step::WaitRestart);
    let back = crate::restart::wait_until_back(
        req.service,
        req.target,
        &req.options,
        req.mask,
        crate::restart::RestartWait::default(),
    )
    .await
    .map_err(|err| err.to_string());
    (written, Some(back))
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
    observer.step(Step::ReadBack);
    Some(
        crate::verify::read_back_on(req.service, req.target, options, req.seed.clone(), expected)
            .await,
    )
}
