//! `knx_replace_device` (issue #751): replace a dead device from chat, the
//! flow `bussard replace` runs at the terminal, on the same step machine
//! ([`bussard_service::replace`]) and the same write paths: the assign steps
//! of [`bussard_service::assign`], then the plan and the apply job of
//! `knx_plan_device` and `knx_apply_device`, whose flash loads the
//! application ([`bussard_service::flash_flow`]) when the replacement does
//! not run it.
//!
//! One job of the server's job table ([`crate::jobs::JobKind::Replace`]),
//! four steps:
//!
//! 1. **`backup`.** The first call records a history snapshot of the model
//!    (the dead device's file and its `bussard.lock` record among it), so
//!    `bussard history` can put both back, and says what they hold.
//! 2. **`press_button`.** The job checks that nothing answers at the address
//!    any more, then waits for the programming-mode broadcast as long as the
//!    CLI does ([`bussard_service::assign::PROGRAMMING_WAIT_TOTAL`]).
//! 3. **`identified`.** The replacement answered: the job reads its serial,
//!    mask, order number and resident application, checks them against the
//!    device file and the lock (another product is refused, as without
//!    `--force`), and pauses with the plan sentences, a `plan_digest` over
//!    the assign, the flash and the apply, and the question. Nothing is
//!    written.
//! 4. **`done`.** The write call presents the job, the digest and `yes:
//!    true` (plus `download: true` when the pinned product archive must be
//!    fetched first). The job re-reads the device and refuses when the digest
//!    no longer matches, writes the address and reads it back, plans the
//!    device as `knx_plan_device` does (the load of the pinned application
//!    when the replacement does not run it), writes that plan through
//!    `knx_apply_device`'s pre-flight and write with their backups and
//!    independent read-back, and only then records `replaced` in the device
//!    file and the new serial number in the lock.
//!
//! A device the model records as KNX Data Secure-activated is refused: the
//! Secure activation of a fresh device stays with ETS.

use std::time::Instant;

use bussard_model::history::{History, SnapshotReason};
use bussard_model::identity::LockIdentity;
use bussard_model::{IndividualAddress, Model};
use bussard_service::adopt::flow::{ProductPlan, product_plan};
use bussard_service::assign::hex;
use bussard_service::program::addressed::{AddressFlow, AddressOutcome, DeviceReadback, Recorded};
use bussard_service::program::assign::{AssignFlow, Stop};
use bussard_service::program::outcome::Verdict;
use bussard_service::program::outcome::WriteOutcome;
use bussard_service::program::plan::Fingerprint;
use bussard_service::replace::{self, Pressed, Replacement};
use serde_json::Value;

use super::addressing::{Wording, Yes, assigned_notes, found_sentence, refused};
use super::{BussardMcp, ProgrammingTier, chain, parse_address, product_for};
use crate::jobs::{JobKind, JobSink, Subject};

/// The question of the `press_button` step.
const PRESS_BUTTON: &str = "Press the programming button on the replacement device (its LED \
    usually lights up), then say done.";

/// Where the product data for the flash comes from.
#[derive(Debug, Clone)]
enum Source {
    /// The archive bussard.lock pins for the device, in the store.
    Pinned {
        /// The archive's path in the model directory.
        archive: String,
        /// The application program it loads.
        application: String,
    },
    /// The pinned archive is not at hand; the vendor index has it.
    Download {
        /// The index entry's product name.
        name: String,
        /// Its manufacturer.
        manufacturer: String,
        /// The archive's size in bytes.
        size: u64,
        /// Where it is downloaded from.
        url: String,
        /// The archive's SHA-256, as the index lists it.
        sha256: String,
    },
}

/// One identified replacement waiting for the human's yes, by job id.
#[derive(Debug, Clone)]
pub(super) struct ReplacePlan {
    /// The replacement.
    replacement: Replacement,
    /// What the identification read.
    pressed: Pressed,
    /// Where the product data comes from.
    source: Source,
    /// The digest the human's yes answers.
    digest: String,
}

/// How `knx_replace_device` names the device in its refusals.
const WORDING: Wording = Wording {
    work: "a replacement",
    device: "the replacement",
    all_but: "the replacement",
    subject: "the replacement",
    tool: "knx_replace_device",
};

/// The refusal for a stop of the flow on `target`.
fn refusal(target: IndividualAddress, stop: Stop) -> String {
    if let Some(reason) = WORDING.wait_refusal(&stop) {
        return reason;
    }
    match stop {
        Stop::Occupied { occupant, .. } => gone_refusal(target, &occupant.describe()),
        other => chain(&other),
    }
}

/// The plan digest: the address, the device that answered (current
/// address, serial, mask, order number, resident application), the model's
/// device (its file and lock record) and links, and the product data the
/// flash loads. The flash and the apply are planned from exactly these after
/// the address is written, so a yes to this digest is a yes to all three.
fn replace_digest(model: &Model, r: &Replacement, p: &Pressed, source: &Source) -> String {
    let device = model.devices.get(&r.target).map(|d| &d.device);
    let product = match source {
        Source::Pinned {
            archive,
            application,
        } => format!("pinned:{archive}:{application}"),
        Source::Download { sha256, .. } => format!("download:{sha256}"),
    };
    let h = Fingerprint::new(b"bussard-replace-device-v1")
        .address(r.target)
        .address(p.address)
        .put(p.serial.as_deref().unwrap_or_default())
        .put(p.mask.unwrap_or(0).to_be_bytes())
        .put(p.order.as_deref().unwrap_or(""))
        .put(p.application_id.as_deref().unwrap_or(""))
        .put(format!("{device:?}"))
        .put(format!("{:?}", model.links.links.get(&r.target)))
        .put(product);
    format!("sha256:{}", h.hex())
}

impl BussardMcp {
    /// `knx_replace_device`'s body; `Err` is a refusal reason.
    pub(super) async fn replace_device_tool(
        &self,
        args: super::ReplaceDeviceArgs,
    ) -> Result<Value, String> {
        let (tier, _, gateway) = self.programming_preflight()?;
        if let Some(job) = args.job.as_deref().map(str::trim) {
            return self
                .replace_write_call(
                    tier,
                    job,
                    args.plan_digest.as_deref(),
                    args.yes,
                    args.download,
                )
                .await;
        }
        if args.plan_digest.is_some() || args.yes == Some(true) {
            return Err(
                "plan_digest and yes answer an identified replacement: pass the `job` \
                 knx_replace_device returned with them"
                    .into(),
            );
        }
        let address =
            args.address.as_deref().map(str::trim).ok_or(
                "pass `address`, the individual address of the dead device, e.g. \"1.1.4\"",
            )?;
        let target = parse_address(address)?;
        let model = self.state().model.reload();
        let dir = self.state().dir.clone();
        let replacement = Replacement::from_model(&model, &dir, target, false)?;
        if bussard_service::secure::model_activated(Some(&model), target) {
            return Err(format!(
                "{target} is KNX Data Secure-activated in the model. A replacement arrives \
                 factory-fresh, and its Secure activation (the FDSK step) stays with ETS: \
                 download the replacement with ETS, export the project and keyring again and \
                 import them. Nothing was written."
            ));
        }
        let source = replace_source(&dir, &model, &replacement)?;
        let job = tier
            .jobs
            .claim(JobKind::Replace, Subject::Device(target))?
            .id;
        let backup = match backup(&dir, &model, &replacement) {
            Ok(backup) => backup,
            Err(reason) => {
                tier.jobs.abandon(&job);
                return Err(reason);
            }
        };
        let me = self.clone();
        let id = job.clone();
        let worker = tokio::spawn(async move {
            me.replace_identify_job(&id, replacement, source).await;
        });
        tier.jobs.watch(&job, "replace-device", worker);
        Ok(crate::reply::started_with(
            &job,
            "press_button",
            ReplaceStarted {
                address: target.to_string(),
                gateway,
                backup,
            },
            Some(PRESS_BUTTON),
            format!(
                "Tell the human what `backup` kept, then relay `question` word for word. The \
                 server first checks that {target} no longer answers, then waits up to 30 s for \
                 the replacement's programming-mode answer; call knx_job_status with job {job} \
                 every few seconds. When its step is `identified`, show the human its \
                 `sentences` and ask its `question`. Nothing is written before that."
            ),
        ))
    }

    /// The first job: the check that the old device is gone, the wait for
    /// the button and the identification. Ends paused at `identified` (the
    /// slot free) or finished with the reason.
    async fn replace_identify_job(&self, job: &str, replacement: Replacement, source: Source) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return;
        };
        let outcome = self
            .on_bus(tier, self.replace_identify(job, &replacement))
            .await;
        match outcome {
            Ok(pressed) => {
                let model = state.model.reload();
                let digest = replace_digest(&model, &replacement, &pressed, &source);
                let detail =
                    identified_detail(&model, &replacement, &pressed, &source, &digest, tier);
                let question = format!(
                    "Replace {} ({}): give the device at {} the address {}, load the \
                     application and write the model's parameters and links? Say yes.",
                    replacement.name, replacement.target, pressed.address, replacement.target
                );
                let target = replacement.target;
                let plan = ReplacePlan {
                    replacement,
                    pressed,
                    source,
                    digest,
                };
                tier.replaces.insert(job, "", plan);
                tier.jobs
                    .pause(job, "identified", question, Some(target), detail);
            }
            Err(reason) => tier.jobs.finish(job, refused(reason)),
        }
    }

    /// The bus half of the first job; `Err` is the reason it stopped.
    async fn replace_identify(&self, job: &str, r: &Replacement) -> Result<Pressed, String> {
        let tier = self.tier()?;
        let (service, source) = self.address_bus().await?;
        let flow = AssignFlow {
            service: &service,
            source,
        };
        let observer = &mut replace_observer(tier, job);
        let target = r.target;
        flow.check_free(target, false, observer)
            .await
            .map_err(|stop| refusal(target, stop))?;
        let located = replace::locate(&flow, r, observer)
            .await
            .map_err(|stop| refusal(target, stop))?;
        match located.mismatch {
            Some(problem) => Err(mismatch_refusal(target, &problem)),
            None => Ok(located.pressed),
        }
    }

    /// The write call: checks the answer, takes the job up again and runs
    /// the write; answers with the result when it ends within the reply
    /// wait, else with the job.
    async fn replace_write_call(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        digest: Option<&str>,
        yes: Option<bool>,
        download: Option<bool>,
    ) -> Result<Value, String> {
        let began = Instant::now();
        let pending = tier.replaces.get(job).ok_or_else(|| {
            format!(
                "no identified replacement waits under job {job} (it was written, refused, or \
                 older than the plan lifetime). Call knx_replace_device with the address to \
                 start again."
            )
        })?;
        let needs_download = matches!(pending.source, Source::Download { .. });
        Yes {
            job,
            digest,
            yes,
            download,
        }
        .check(&pending.digest, "replacing the device", needs_download)?;
        tier.jobs.resume(job, "checking the device again")?;
        tier.replaces.retire(job);
        let me = self.clone();
        let id = job.to_string();
        let work = async move { me.replace_write_job(&id, pending).await };
        let next_step = format!(
            "The device is being replaced in the server as job {job}: the address, the \
             application and the model's parameters and links, each read back. Call \
             knx_job_status with job {job} every few seconds until `done` is true; its `result` \
             is the outcome."
        );
        self.spawn_write(tier, job, began, "replace-device", work, next_step)
            .await
    }

    /// The write job: the assign half, then the flash and the apply, then
    /// the record. Returns the job's result.
    async fn replace_write_job(&self, job: &str, p: ReplacePlan) -> Value {
        let outcome = self.replace_write(job, p).await;
        crate::reply::report(&outcome, &self.model())
    }

    /// [`BussardMcp::replace_write_job`]'s outcome.
    async fn replace_write(&self, job: &str, p: ReplacePlan) -> AddressOutcome {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return AddressOutcome {
                verdict: Verdict::failed("the programming tier is off"),
                ..AddressOutcome::default()
            };
        };
        let target = p.replacement.target;
        // The address, on the bus lock (released before the plan, which takes
        // it itself).
        let assigned = self.on_bus(tier, self.replace_assign(job, &p)).await;
        let (pressed, mut notes) = match assigned {
            Ok(Swap::Done { pressed, notes }) => (pressed, notes),
            Ok(Swap::Failed(result)) => return *result,
            Err(reason) => {
                return AddressOutcome {
                    verdict: Verdict::failed(reason),
                    address: target.to_string(),
                    written: Some(false),
                    flow: AddressFlow::Replace,
                    ..AddressOutcome::default()
                };
            }
        };

        // The flash and the apply: the plan of knx_plan_device on the
        // replacement at its new address, then knx_apply_device's pre-flight
        // and write. The human's yes covered both (the digest bound the
        // model and the product they are planned from).
        tier.jobs.step(
            job,
            format!("planning {target}: the application, the parameters and the links"),
        );
        let plan = match self.plan_body(&target.to_string()).await {
            Ok(plan) => plan,
            Err(reason) => {
                return after_assign_failure(
                    &p,
                    &pressed,
                    notes,
                    format!(
                        "{target} has its address, but its application and links could not be \
                         planned: {reason}"
                    ),
                );
            }
        };
        let write = if plan.noop() {
            None
        } else {
            let Some(digest) = plan.plan_digest() else {
                return after_assign_failure(
                    &p,
                    &pressed,
                    notes,
                    format!(
                        "{target} has its address, but its plan carries nothing to write over \
                         this tool ({}); plan it with knx_plan_device",
                        plan.method()
                    ),
                );
            };
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            tier.jobs.step(
                job,
                format!(
                    "{} {target}: pre-flight, backups",
                    if plan.method() == "flash" {
                        "flashing"
                    } else {
                        "writing"
                    }
                ),
            );
            let prepared = match self.apply_preflight(tier, target, &digest, None).await {
                Ok(prepared) => prepared,
                Err(reason) => {
                    drop(warm);
                    return after_assign_failure(
                        &p,
                        &pressed,
                        notes,
                        format!(
                            "{target} has its address, but the write of its application and \
                             links was refused in its pre-flight: {reason}"
                        ),
                    );
                }
            };
            let record = prepared.snapshot.as_ref().map(|id| {
                History::open(&prepared.dir)
                    .history_dir()
                    .join(id)
                    .join(crate::jobs::RECORD_FILE)
            });
            tier.jobs.started(job, &prepared.result, record);
            let links_after = super::LinksAfter::of(&prepared);
            let result = self.apply_write(tier, job, prepared).await;
            drop(warm);
            drop(_guard);
            // A self-contained application's download writes no link table
            // (issue #779): its links follow it, as `bussard replace` runs
            // `apply` after `flash`.
            Some(match links_after {
                Some(consent) => self.links_after_download(tier, job, consent, result).await,
                None => result,
            })
        };
        let written_ok = write
            .as_ref()
            .is_none_or(|w| w.verdict.ok && w.verdict.verified);
        if !written_ok {
            let reason = write
                .as_ref()
                .and_then(|w| w.verdict.reason.clone())
                .unwrap_or_else(|| "the write did not verify".to_string());
            let mut result = after_assign_failure(
                &p,
                &pressed,
                notes,
                format!(
                    "{target} has its address, but the write of its application and links did \
                     not verify: {reason}"
                ),
            );
            result.write = write;
            return result;
        }

        // The record: `replaced` in the device file, the serial in the lock.
        tier.jobs.step(job, "recording the replacement");
        let when = bussard_service::download::backup::rfc3339_utc(std::time::SystemTime::now());
        let recorded =
            replace::record(&state.dir, &p.replacement, pressed.serial.as_deref(), &when);
        let _ = state.model.reload();
        let recorded = match recorded {
            Ok(recorded) => Some(Recorded {
                replaced: when,
                device_file: recorded
                    .device_file
                    .strip_prefix(&state.dir)
                    .unwrap_or(&recorded.device_file)
                    .display()
                    .to_string(),
                serial_recorded: recorded.serial.as_ref().is_some_and(|s| s.changed()),
            }),
            Err(err) => {
                notes.push(format!(
                    "The replacement is on the bus and verified, but it was not recorded in the \
                     model: {}",
                    chain(&err)
                ));
                None
            }
        };
        done_result(&p, &pressed, write, recorded, notes)
    }

    /// The assign half of the write job: the fresh read against the digest,
    /// the download, the address and its read-back.
    async fn replace_assign(&self, job: &str, p: &ReplacePlan) -> Result<Swap, String> {
        let state = self.state();
        let tier = self.tier()?;
        let dir = state.dir.clone();
        let (service, source) = self.address_bus().await?;
        let flow = AssignFlow {
            service: &service,
            source,
        };
        let observer = &mut replace_observer(tier, job);
        let r = &p.replacement;
        let target = r.target;
        let current = p.pressed.address;

        // The fresh read: the same single device in programming mode, the
        // same identity, model and product, else the digest is stale.
        flow.still_the_one(current)
            .await
            .map_err(|stop| refusal(target, stop))?;
        flow.check_free(target, false, observer)
            .await
            .map_err(|stop| refusal(target, stop))?;
        let fresh = replace::identify(&service, source, current).await;
        let model = state.model.reload();
        if replace_digest(&model, r, &fresh, &p.source) != p.digest {
            return Err(
                "a fresh read no longer produces the plan the human answered (the device, the \
                 model or its product data changed). Call knx_replace_device again for a new \
                 plan. Nothing was written."
                    .into(),
            );
        }

        // The download the human agreed to, before anything is written: a
        // flash needs the archive the lock pins.
        if let Source::Download { name, .. } = &p.source {
            tier.jobs
                .step(job, format!("downloading the product data ({name})"));
            let order = r.expected.order_number.clone().unwrap_or_default();
            bussard_service::setup::products::fetch_missing(
                &dir,
                &[order],
                &mut bussard_service::observer::Consented,
                &mut bussard_service::observer::Collected::default(),
            )
            .map_err(|e| {
                format!(
                    "the product data was not downloaded ({}). Nothing was written.",
                    chain(&e)
                )
            })?;
            let model = state.model.reload();
            if let Err(why) = pinned_source(&dir, &model, r) {
                return Err(format!(
                    "the download did not give bussard the archive bussard.lock pins for \
                     {target} ({why}); import it with knx_import_file or `bussard \
                     import-product`, then call knx_replace_device again. Nothing was written."
                ));
            }
        }

        // The address, and the independent read-back at it.
        let failed =
            |assigned: bool, readback: Option<DeviceReadback>, reason: String, recovery: String| {
                Ok(Swap::Failed(Box::new(AddressOutcome {
                    verdict: Verdict {
                        recovery: Some(recovery),
                        ..Verdict::failed(reason)
                    },
                    address: target.to_string(),
                    from: Some(current.to_string()),
                    assigned: Some(assigned),
                    readback,
                    flow: AddressFlow::Replace,
                    ..AddressOutcome::default()
                })))
            };
        match replace::assign_replacement(&flow, &dir, r, p.pressed.clone(), None, true, observer)
            .await
        {
            Ok((pressed, assigned)) => Ok(Swap::Done {
                pressed,
                notes: assigned_notes(&assigned),
            }),
            Err(Stop::Verify(err)) => failed(
                false,
                None,
                chain(&err),
                format!(
                    "The address write to {target} could not be verified. Check the device with \
                     knx_show_device {{live: true}} and call knx_replace_device again."
                ),
            ),
            Err(Stop::OtherDevice { verified, .. }) => failed(
                true,
                Some(DeviceReadback::identity(&verified)),
                format!(
                    "{target} now answers, but the read-back there does not match the identified \
                     serial or mask: another device may have taken the address. Nothing more was \
                     written."
                ),
                format!(
                    "Check {target} with knx_show_device {{live: true}} before anything else is \
                     written to it."
                ),
            ),
            Err(other) => Err(chain(&other)),
        }
    }
}

/// The observer of a replace job.
fn replace_observer<'a>(tier: &'a ProgrammingTier, job: &'a str) -> JobSink<'a> {
    JobSink {
        check_gone: true,
        ..JobSink::new(&tier.jobs, job).press(PRESS_BUTTON.to_string())
    }
}

/// How the assign half of the write job ended.
enum Swap {
    /// The address took and read back as the identified device.
    Done {
        /// What was identified, merged with the read-back.
        pressed: Pressed,
        /// Notes for the human.
        notes: Vec<String>,
    },
    /// The address was written but did not verify: the job's result.
    Failed(Box<AddressOutcome>),
}

/// Where the product data for the flash comes from, or the refusal when
/// there is none: the archive bussard.lock pins for the device, else the
/// vendor index (a download).
fn replace_source(dir: &std::path::Path, model: &Model, r: &Replacement) -> Result<Source, String> {
    let why = match pinned_source(dir, model, r) {
        Ok(source) => return Ok(source),
        Err(why) => why,
    };
    if let Some(order) = r.expected.order_number.as_deref()
        && let ProductPlan::Download { entry } = product_plan(dir, order)
    {
        return Ok(Source::Download {
            name: entry.name.clone(),
            manufacturer: entry.manufacturer.clone(),
            size: entry.size,
            url: entry.url.clone(),
            sha256: entry.sha256.clone(),
        });
    }
    Err(format!(
        "{}: no product data to flash the replacement with ({why}). Import the product with \
         knx_import_file (a .knxprod) or `bussard import-product`, then call \
         knx_replace_device again. Nothing was written.",
        r.target
    ))
}

/// The archive bussard.lock pins for the device, intact in the store and
/// carrying its application; `Err` says what is missing.
fn pinned_source(dir: &std::path::Path, model: &Model, r: &Replacement) -> Result<Source, String> {
    let device = model
        .devices
        .get(&r.target)
        .map(|d| &d.device)
        .ok_or_else(|| format!("the model has no device file for {}", r.target))?;
    let archive = device
        .lock
        .product_entry
        .as_ref()
        .and_then(|e| e.file.clone())
        .ok_or_else(|| "bussard.lock pins no product archive for it".to_string())?;
    let product = product_for(dir, model, r.target);
    let Some(source) = product.source.as_ref() else {
        return Err(product
            .refusal
            .unwrap_or_else(|| "the pinned archive did not load".to_string()));
    };
    let Some(app) = source.app() else {
        return Err(format!(
            "the pinned archive does not carry application {}",
            source.app_id
        ));
    };
    Ok(Source::Pinned {
        archive,
        application: app.id.clone(),
    })
}

/// The `backup` step: a history snapshot of the model, whose device file
/// and lock record of the dead device `bussard history` can put back, and
/// what they hold.
fn backup(dir: &std::path::Path, model: &Model, r: &Replacement) -> Result<ReplaceBackup, String> {
    let device = model.devices.get(&r.target).map(|d| &d.device);
    let lock = device.map(LockIdentity::of).unwrap_or_default();
    let history = History::open(dir);
    let snapshot = if history.has_model_files() {
        let id = history
            .snapshot(
                SnapshotReason::new("knx_replace_device")
                    .with_args([r.target.to_string()])
                    .with_result("before replacing the device"),
            )
            .map_err(|err| {
                format!(
                    "refusing to replace {}: the backup snapshot could not be recorded ({err}). \
                     Nothing was written.",
                    r.target
                )
            })?;
        Some(id.to_string())
    } else {
        None
    };
    let relative = r
        .device_file
        .strip_prefix(dir)
        .unwrap_or(&r.device_file)
        .display()
        .to_string();
    Ok(ReplaceBackup {
        sentence: match &snapshot {
            Some(id) => format!(
                "The model as it is now, {relative} and its bussard.lock record included, is \
                 kept as history snapshot {id}; `bussard history` puts it back."
            ),
            None => format!("{relative} has no history to snapshot into yet."),
        },
        snapshot,
        device_file: relative,
        name: r.name.clone(),
        order_number: r.expected.order_number.clone(),
        mask: r.expected.mask_text.clone(),
        lock: LockFacts {
            application: lock.application,
            application_id: lock.application_id,
            product_sha256: lock.product_sha256,
            serial_number: device.and_then(|d| d.lock.serial_number.clone()),
        },
    })
}

/// The refusal for an address that still answers.
fn gone_refusal(target: IndividualAddress, occupant: &str) -> String {
    format!(
        "{target} still answers on the bus ({occupant}). knx_replace_device is for a device \
         that has failed or been removed; re-addressing whatever is in programming mode onto \
         {target} anyway is `bussard replace --force {target}` at the terminal. Nothing was \
         written."
    )
}

/// The refusal for a replacement that is another product.
fn mismatch_refusal(target: IndividualAddress, problem: &str) -> String {
    format!(
        "refusing to replace {target}: {problem}. A different product means a different \
         application, and flashing it would load the wrong image. Use the right spare or fix \
         the device file; `bussard replace --force {target}` at the terminal overrides this \
         when the model is out of date. Nothing was written."
    )
}

/// The fields the `identified` step reports at the top of the job status.
fn identified_detail(
    model: &Model,
    r: &Replacement,
    p: &Pressed,
    source: &Source,
    digest: &str,
    tier: &ProgrammingTier,
) -> ReplaceIdentified {
    let target = r.target;
    let mask = p.mask.map(|m| format!("{m:04X}"));
    let system = p.mask.map(bussard_service::mgmt::system_type);
    let check = r.identity_check(p);
    let running = p.application.as_deref().map_or_else(
        || ", running no readable application".to_string(),
        |a| format!(", running application {a}"),
    );
    let mut sentences = vec![found_sentence(&p.as_verified(), p.address, &running)];
    sentences.push(format!(
        "{target} ({}) does not answer on the bus, and the device in programming mode matches \
         what its device file and bussard.lock name{}.",
        r.name,
        r.expected
            .order_number
            .as_deref()
            .map(|o| format!(" (order number {o})"))
            .unwrap_or_default()
    ));
    if let Some(check) = &check {
        sentences.push(bussard_service::identity_line(target, check));
    }
    sentences.push(format!("It gets the address {target}."));
    let (application, product_data, download_needed) = match source {
        Source::Pinned {
            archive,
            application,
        } => (
            application.clone(),
            format!("{archive}, pinned in bussard.lock"),
            false,
        ),
        Source::Download {
            name,
            manufacturer,
            size,
            url,
            ..
        } => (
            model
                .devices
                .get(&target)
                .and_then(|d| LockIdentity::of(&d.device).application)
                .unwrap_or_else(|| "the application bussard.lock pins".to_string()),
            format!(
                "would download {name} ({manufacturer}) from the vendor index ({:.1} MB, {url})",
                *size as f64 / 1_000_000.0,
            ),
            true,
        ),
    };
    sentences.push(format!(
        "Then bussard loads {application} into it when it does not run it loaded (the device \
         restarts and is offline for {} to {} s), writes the model's parameters and links, \
         reads it back, and records the replacement in {} and its serial in bussard.lock.",
        bussard_service::flash::DEVICE_OFFLINE_SECONDS.0,
        bussard_service::flash::DEVICE_OFFLINE_SECONDS.1,
        r.device_file.file_name().map_or_else(
            || r.device_file.display().to_string(),
            |n| format!("devices/{}", n.to_string_lossy())
        ),
    ));
    sentences.push(format!("Product data: {product_data}."));
    if download_needed {
        sentences.push(
            "The download is copyrighted vendor data stored under products/; it needs the \
             human's own yes (download: true)."
                .to_string(),
        );
    }
    ReplaceIdentified {
        name: r.name.clone(),
        current_address: p.address.to_string(),
        serial: p.serial.as_deref().map(hex),
        mask,
        system_type: system,
        order_number: p.order.clone(),
        resident_application: p.application.clone(),
        identity: check,
        application,
        product_data,
        download_needed,
        sentences,
        plan_digest: digest.to_string(),
        expires_at: tier.replaces.expires_at(std::time::SystemTime::now()),
    }
}

/// What the start of `knx_replace_device` established.
#[derive(serde::Serialize)]
struct ReplaceStarted {
    /// The dead device.
    address: String,
    /// The resolved gateway.
    gateway: String,
    /// What the backup step kept.
    backup: ReplaceBackup,
}

/// The `backup` step: the history snapshot that keeps the dead device's
/// file and lock record, and what they hold.
#[derive(serde::Serialize)]
struct ReplaceBackup {
    /// The snapshot id.
    snapshot: Option<String>,
    /// The device file, relative to the project.
    device_file: String,
    /// The device's name.
    name: String,
    /// The order number the project expects.
    order_number: Option<String>,
    /// The mask the project expects.
    mask: Option<String>,
    /// The lock record kept.
    lock: LockFacts,
    /// The step in words.
    sentence: String,
}

/// The lock record of the dead device.
#[derive(serde::Serialize)]
struct LockFacts {
    /// The application.
    application: Option<String>,
    /// The application id.
    application_id: Option<String>,
    /// The product archive's SHA-256.
    product_sha256: Option<String>,
    /// The serial number.
    serial_number: Option<String>,
}

/// The fields the `identified` step reports at the top of the job status.
#[derive(serde::Serialize)]
struct ReplaceIdentified {
    /// The device's name in the project.
    name: String,
    /// Where the replacement answered.
    current_address: String,
    /// Its serial, hex.
    serial: Option<String>,
    /// Its mask, hex.
    mask: Option<String>,
    /// The system the mask names.
    system_type: Option<&'static str>,
    /// Its order number.
    order_number: Option<String>,
    /// The application it runs now.
    resident_application: Option<String>,
    /// Its identity against the lock.
    identity: Option<bussard_model::identity::IdentityCheck>,
    /// The application it gets.
    application: String,
    /// Where the product data comes from.
    product_data: String,
    /// The product data needs the human's consent to a download.
    download_needed: bool,
    /// The plan in words.
    sentences: Vec<String>,
    /// The digest the yes presents.
    plan_digest: String,
    /// When the digest expires.
    expires_at: String,
}

/// The result when the address took but the flash or the apply did not
/// complete: not recorded, with the recovery the CLI names.
fn after_assign_failure(
    p: &ReplacePlan,
    pressed: &Pressed,
    notes: Vec<String>,
    reason: String,
) -> AddressOutcome {
    let target = p.replacement.target;
    AddressOutcome {
        verdict: Verdict {
            recovery: Some(format!(
                "{target} has the right address but not yet the model's application and links. \
                 Call knx_plan_device for {target}, show the plan to the human and apply it with \
                 knx_apply_device after a yes; the replacement is recorded only by a complete run \
                 (`bussard replace {target}` at the terminal)."
            )),
            ..Verdict::failed(reason)
        },
        step: Some("done".to_string()),
        address: target.to_string(),
        from: Some(pressed.address.to_string()),
        assigned: Some(true),
        notes,
        flow: AddressFlow::Replace,
        ..AddressOutcome::default()
    }
}

/// The `done` result: names first, one summary sentence.
fn done_result(
    p: &ReplacePlan,
    pressed: &Pressed,
    write: Option<WriteOutcome>,
    recorded: Option<Recorded>,
    notes: Vec<String>,
) -> AddressOutcome {
    let r = &p.replacement;
    let flashed = write
        .as_ref()
        .is_some_and(|w| w.method.as_deref() == Some("flash") && w.verdict.ok);
    AddressOutcome {
        verdict: Verdict {
            ok: recorded.is_some(),
            verified: true,
            ..Verdict::default()
        },
        step: Some("done".to_string()),
        name: Some(r.name.clone()),
        address: r.target.to_string(),
        from: Some(pressed.address.to_string()),
        assigned: Some(true),
        flashed: Some(flashed),
        readback: Some(DeviceReadback {
            mask: pressed.mask.map(|m| format!("{m:04X}")),
            serial: pressed.serial.as_deref().map(hex),
            order_number: pressed.order.clone(),
            ..DeviceReadback::default()
        }),
        write,
        recorded,
        notes,
        flow: AddressFlow::Replace,
        ..AddressOutcome::default()
    }
}
