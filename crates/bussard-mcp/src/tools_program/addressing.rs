//! The chat side of the addressing flows (issue #902): `knx_add_device`,
//! `knx_replace_device` and `knx_commission_line` run
//! [`bussard_service::program::assign`] through the job table's
//! [`crate::jobs::JobSink`], and share the yes call, the
//! download consent and the sentences about the pressed device.

use std::future::Future;
use std::time::Instant;

use bussard_model::IndividualAddress;
use bussard_service::BusService;
use bussard_service::assign::{Verified, hex};
use bussard_service::observer::{Collected, Consented};
use bussard_service::program::addressed::AddressOutcome;
use bussard_service::program::assign::{Assigned, Stop};
use serde_json::Value;

use super::{BussardMcp, ProgrammingTier, chain};

/// How a tool names the device and itself in its refusals.
pub(super) struct Wording {
    /// The flow, as the subject of "works on one device at a time".
    pub work: &'static str,
    /// The device being addressed, in "press the programming button on …".
    pub device: &'static str,
    /// The device, in "leave programming mode on all but …".
    pub all_but: &'static str,
    /// The device, in "… is no longer the one device in programming mode".
    pub subject: &'static str,
    /// The tool to call again.
    pub tool: &'static str,
}

impl Wording {
    /// The refusal for a wait that found no single device, or for a device
    /// that left programming mode before the write; `None` for any other
    /// stop.
    pub(super) fn wait_refusal(&self, stop: &Stop) -> Option<String> {
        let tool = self.tool;
        Some(match stop {
            Stop::Several(found) => format!(
                "{} devices are in programming mode ({}); {} works on one device at a time. \
                 Ask the human to leave programming mode on all but {}, then call {tool} again. \
                 Nothing was written.",
                found.len(),
                join(found),
                self.work,
                self.all_but
            ),
            Stop::Nothing { waited } => format!(
                "No device entered programming mode within {} s. Ask the human to press the \
                 programming button on {} (its LED usually lights up), then call {tool} \
                 again. Nothing was written.",
                waited.as_secs(),
                self.device
            ),
            Stop::Moved { current, now } => format!(
                "{} is no longer the one device in programming mode at {current} (now: {}). Ask \
                 the human to press its programming button again, then call {tool} again. \
                 Nothing was written.",
                self.subject,
                if now.is_empty() {
                    "none".to_string()
                } else {
                    join(now)
                }
            ),
            _ => return None,
        })
    }
}

/// Addresses joined with `", "`.
fn join(addresses: &[IndividualAddress]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Who the device is, in words: the product name or order number, then the
/// manufacturer.
pub(super) fn who(identified: &Verified) -> String {
    let manufacturer = identified
        .manufacturer_id
        .map(bussard_service::mgmt::manufacturers::display);
    match (&identified.order, manufacturer) {
        (Some(order), Some(m))
            if order
                .to_ascii_uppercase()
                .starts_with(&m.to_ascii_uppercase()) =>
        {
            order.clone()
        }
        (Some(order), Some(m)) => format!("{m} {order}"),
        (Some(order), None) => order.clone(),
        (None, Some(m)) => format!("A {m} device"),
        (None, None) => "A device".to_string(),
    }
}

/// The first sentence of an `identified` step: who answers where, its
/// serial and mask, then `rest` (`, running …`).
pub(super) fn found_sentence(v: &Verified, current: IndividualAddress, rest: &str) -> String {
    format!(
        "{} is in programming mode at {current}{}{}{rest}.",
        who(v),
        v.serial
            .as_deref()
            .map(|s| format!(", serial {}", hex(s)))
            .unwrap_or_default(),
        match v.mask {
            Some(mask) => format!(
                ", mask {mask:04X} ({})",
                bussard_service::mgmt::system_type(mask)
            ),
            None => String::new(),
        }
    )
}

/// The notes an address write leaves for the human: the read-back's
/// warnings and a device still in programming mode.
pub(super) fn assigned_notes(assigned: &Assigned) -> Vec<String> {
    let mut notes = assigned.verified.warnings.clone();
    let target = assigned.target;
    if assigned.still_in_programming_mode {
        notes.push(format!(
            "{target} is still in programming mode after the assignment; ask the human to press \
             its programming button once to leave it (on KNX Virtual: toggle it off in the GUI)."
        ));
    } else if !assigned.written {
        notes.push(format!(
            "{target} stays in programming mode (nothing was written to it); ask the human to \
             press its programming button to leave it."
        ));
    }
    notes
}

/// The result of a job that stopped before anything was written.
pub(super) fn refused(reason: String) -> AddressOutcome {
    AddressOutcome::refused("", reason)
}

/// Downloads the product data for `order` (the human agreed): the archive
/// it gave, or why not.
pub(super) fn download(dir: &std::path::Path, order: &str) -> Result<std::path::PathBuf, String> {
    let outcome = bussard_service::setup::products::fetch_missing(
        dir,
        &[order.to_string()],
        &mut Consented,
        &mut Collected::default(),
    )
    .map_err(|e| chain(&e))?;
    match outcome.fetched.into_iter().next() {
        Some((_, path)) => Ok(path),
        None => Err(outcome
            .not_fetched
            .into_iter()
            .next()
            .map(|(_, why)| why)
            .unwrap_or_else(|| "it is not in the index".to_string())),
    }
}

/// The human's answer to an identified device: the job, the plan digest,
/// `yes` and the download consent.
pub(super) struct Yes<'a> {
    /// The job.
    pub job: &'a str,
    /// The digest presented.
    pub digest: Option<&'a str>,
    /// `yes: true`.
    pub yes: Option<bool>,
    /// `download: true`.
    pub download: Option<bool>,
}

impl Yes<'_> {
    /// Checks the answer against the job's digest; `writes` names the
    /// write (`adding the device`), `needs_download` whether the product
    /// data must be fetched first.
    pub(super) fn check(
        &self,
        digest: &str,
        writes: &str,
        needs_download: bool,
    ) -> Result<(), String> {
        let job = self.job;
        let Some(given) = self.digest.map(str::trim) else {
            return Err(format!(
                "pass the plan_digest of job {job} (knx_job_status shows it) with yes: true"
            ));
        };
        if given != digest {
            return Err(format!(
                "the plan_digest does not match job {job}: pass the one knx_job_status shows for \
                 it. Nothing was written."
            ));
        }
        if self.yes != Some(true) {
            return Err(format!(
                "{writes} writes to the bus: pass yes: true only after the human's explicit yes \
                 to the question. Nothing was written."
            ));
        }
        if needs_download && self.download != Some(true) {
            return Err(
                "the product data needs a download from the vendor, a separate consent: ask the \
                 human whether bussard may download it, and pass download: true only after a \
                 yes to that too (without it, nothing is written)."
                    .into(),
            );
        }
        Ok(())
    }
}

impl BussardMcp {
    /// Runs `work` holding the programming tier's bus lock, with the warm
    /// connection released.
    pub(super) async fn on_bus<T>(
        &self,
        tier: &ProgrammingTier,
        work: impl Future<Output = T>,
    ) -> T {
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        work.await
    }

    /// The bus and the checked source address of an addressing job.
    pub(super) async fn address_bus(&self) -> Result<(BusService, IndividualAddress), String> {
        let service = self
            .state()
            .bus
            .service()
            .ok_or("the bus is not wired")?
            .clone();
        let source = service
            .checked_source(false)
            .await
            .map_err(|e| format!("the source address check failed: {e}"))?;
        Ok((service, source))
    }

    /// Runs the write job `work` after the human's yes: answers with its
    /// result when it ends within the reply wait, else with the job and
    /// `next_step`.
    pub(super) async fn spawn_write(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        began: Instant,
        verb: &'static str,
        work: impl Future<Output = Value> + Send + 'static,
        next_step: String,
    ) -> Result<Value, String> {
        tier.jobs.spawn(job, verb, async move { Ok(work.await) });
        let wait = tier.jobs.reply_wait().saturating_sub(began.elapsed());
        if let Some(mut result) = tier.jobs.outcome(job, wait).await {
            crate::reply::with_job(&mut result, job, false, true);
            return Ok(result);
        }
        Ok(crate::reply::started(job, "writing", next_step))
    }
}
