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
use bussard_service::assign::{
    ProgrammingWait, VerifyKey, hex, in_programming_mode, probe_occupant,
    still_in_programming_mode, verify_assignment_with, wait_for_programming_mode, write_address,
};
use bussard_service::replace::{self, Pressed, Replacement};
use bussard_service::setup::{Collected, DownloadAnswer, DownloadPrompt, SetupError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{BussardMcp, ProgrammingTier, chain, parse_address, product_for, put};

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
pub(super) struct PendingReplace {
    /// The replacement.
    replacement: Replacement,
    /// What the identification read.
    pressed: Pressed,
    /// Where the product data comes from.
    source: Source,
    /// The digest the human's yes answers.
    digest: String,
    /// When the device was identified.
    created: Instant,
}

/// Answers the download question with the human's `download: true`.
struct Consented;

impl DownloadPrompt for Consented {
    fn download(&mut self, _question: &str, _files: usize) -> Result<DownloadAnswer, SetupError> {
        Ok(DownloadAnswer::Yes)
    }
}

/// The plan digest: the address, the device that answered (current
/// address, serial, mask, order number, resident application), the model's
/// device (its file and lock record) and links, and the product data the
/// flash loads. The flash and the apply are planned from exactly these after
/// the address is written, so a yes to this digest is a yes to all three.
fn replace_digest(model: &Model, r: &Replacement, p: &Pressed, source: &Source) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-replace-device-v1");
    put(&mut h, &r.target.raw().to_be_bytes());
    put(&mut h, &p.address.raw().to_be_bytes());
    put(&mut h, p.serial.as_deref().unwrap_or_default());
    put(&mut h, &p.mask.unwrap_or(0).to_be_bytes());
    put(&mut h, p.order.as_deref().unwrap_or("").as_bytes());
    put(&mut h, p.application_id.as_deref().unwrap_or("").as_bytes());
    let device = model.devices.get(&r.target).map(|d| &d.device);
    put(&mut h, format!("{device:?}").as_bytes());
    put(
        &mut h,
        format!("{:?}", model.links.links.get(&r.target)).as_bytes(),
    );
    let product = match source {
        Source::Pinned {
            archive,
            application,
        } => format!("pinned:{archive}:{application}"),
        Source::Download { sha256, .. } => format!("download:{sha256}"),
    };
    put(&mut h, product.as_bytes());
    let bytes: [u8; 32] = h.finalize().into();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
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
        let replacement =
            Replacement::from_model(&model, &dir, target, false).map_err(|e| e.to_string())?;
        if bussard_service::secure::model_activated(Some(&model), target) {
            return Err(format!(
                "{target} is KNX Data Secure-activated in the model. A replacement arrives \
                 factory-fresh, and its Secure activation (the FDSK step) stays with ETS: \
                 download the replacement with ETS, export the project and keyring again and \
                 import them. Nothing was written."
            ));
        }
        let source = replace_source(&dir, &model, &replacement)?;
        let job = tier.jobs.claim_replace(target)?;
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
        self.watch_job(job.clone(), "replace-device", worker);
        Ok(json!({
            "ok": true,
            "started": true,
            "done": false,
            "step": "press_button",
            "job": job,
            "address": target.to_string(),
            "gateway": gateway,
            "backup": backup,
            "question": PRESS_BUTTON,
            "next_step": format!(
                "Tell the human what `backup` kept, then relay `question` word for word. The \
                 server first checks that {target} no longer answers, then waits up to 30 s for \
                 the replacement's programming-mode answer; call knx_job_status with job {job} \
                 every few seconds. When its step is `identified`, show the human its \
                 `sentences` and ask its `question`. Nothing is written before that."
            ),
        }))
    }

    /// The first job: the check that the old device is gone, the wait for
    /// the button and the identification. Ends paused at `identified` (the
    /// slot free) or finished with the reason.
    async fn replace_identify_job(&self, job: &str, replacement: Replacement, source: Source) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return;
        };
        let outcome = {
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            self.replace_identify(job, &replacement).await
        };
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
                tier.replaces().insert(
                    job.to_string(),
                    PendingReplace {
                        replacement,
                        pressed,
                        source,
                        digest,
                        created: Instant::now(),
                    },
                );
                tier.jobs
                    .pause(job, "identified", question, Some(target), detail);
            }
            Err(reason) => tier.jobs.finish(
                job,
                json!({ "ok": false, "refused": true, "written": false, "reason": reason }),
            ),
        }
    }

    /// The bus half of the first job; `Err` is the reason it stopped.
    async fn replace_identify(&self, job: &str, r: &Replacement) -> Result<Pressed, String> {
        let state = self.state();
        let tier = state
            .programming
            .as_ref()
            .ok_or("the programming tier is off")?;
        let service = state.bus.service().ok_or("the bus is not wired")?.clone();
        let source = service
            .checked_source(false)
            .await
            .map_err(|e| format!("the source address check failed: {e}"))?;
        let target = r.target;
        tier.jobs.step(
            job,
            format!("check_gone: checking that {target} no longer answers"),
        );
        if let Some(occupant) = probe_occupant(&service, source, target).await {
            return Err(gone_refusal(target, &occupant.describe()));
        }
        tier.jobs.step(job, "press_button");
        tier.jobs.ask(job, Some(PRESS_BUTTON.to_string()));
        let found = wait_for_programming_mode(&service, source, &mut |_| {})
            .await
            .map_err(|e| chain(&e))?;
        let current = match found {
            ProgrammingWait::One(current) => current,
            ProgrammingWait::Several(found) => {
                let list: Vec<String> = found.iter().map(ToString::to_string).collect();
                return Err(format!(
                    "{} devices are in programming mode ({}); a replacement works on one device \
                     at a time. Ask the human to leave programming mode on all but the \
                     replacement, then call knx_replace_device again. Nothing was written.",
                    found.len(),
                    list.join(", ")
                ));
            }
            ProgrammingWait::Nothing { waited } => {
                return Err(format!(
                    "No device entered programming mode within {} s. Ask the human to press the \
                     programming button on the replacement (its LED usually lights up), then \
                     call knx_replace_device again. Nothing was written.",
                    waited.as_secs()
                ));
            }
        };
        tier.jobs.ask(job, None);
        tier.jobs
            .step(job, format!("identifying the device at {current}"));
        let pressed = replace::identify(&service, source, current).await;
        if let Some(problem) = r.mismatch(&pressed) {
            return Err(mismatch_refusal(target, &problem));
        }
        Ok(pressed)
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
        let pending = {
            let mut replaces = tier.replaces();
            replaces.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            replaces.get(job).cloned()
        };
        let Some(pending) = pending else {
            return Err(format!(
                "no identified replacement waits under job {job} (it was written, refused, or \
                 older than the plan lifetime). Call knx_replace_device with the address to \
                 start again."
            ));
        };
        let Some(digest) = digest.map(str::trim) else {
            return Err(format!(
                "pass the plan_digest of job {job} (knx_job_status shows it) with yes: true"
            ));
        };
        if digest != pending.digest {
            return Err(format!(
                "the plan_digest does not match job {job}: pass the one knx_job_status shows for \
                 it. Nothing was written."
            ));
        }
        if yes != Some(true) {
            return Err(
                "replacing the device writes to the bus: pass yes: true only after the human's \
                 explicit yes to the question. Nothing was written."
                    .into(),
            );
        }
        if matches!(pending.source, Source::Download { .. }) && download != Some(true) {
            return Err(
                "the product data needs a download from the vendor, a separate consent: ask the \
                 human whether bussard may download it, and pass download: true only after a \
                 yes to that too (without it, nothing is written)."
                    .into(),
            );
        }
        tier.jobs.resume(job, "checking the device again")?;
        tier.replaces().remove(job);
        let me = self.clone();
        let id = job.to_string();
        let worker = tokio::spawn(async move {
            let result = me.replace_write_job(&id, pending).await;
            if let Some(tier) = me.state().programming.as_ref() {
                tier.jobs.finish(&id, result);
            }
        });
        self.watch_job(job.to_string(), "replace-device", worker);
        let wait = tier.jobs.reply_wait().saturating_sub(began.elapsed());
        if tier.jobs.wait(job, wait).await {
            let mut result = tier.jobs.result(job).unwrap_or_else(|| json!({}));
            super::merge(
                &mut result,
                json!({ "started": false, "done": true, "job": job }),
            );
            return Ok(result);
        }
        Ok(json!({
            "ok": true,
            "started": true,
            "done": false,
            "job": job,
            "step": "writing",
            "next_step": format!(
                "The device is being replaced in the server as job {job}: the address, the \
                 application and the model's parameters and links, each read back. Call \
                 knx_job_status with job {job} every few seconds until `done` is true; its \
                 `result` is the outcome."
            ),
        }))
    }

    /// The write job: the assign half, then the flash and the apply, then
    /// the record. Returns the job's result.
    async fn replace_write_job(&self, job: &str, p: PendingReplace) -> Value {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return json!({ "ok": false, "reason": "the programming tier is off" });
        };
        let target = p.replacement.target;
        // The address, on the bus lock (released before the plan, which takes
        // it itself).
        let assigned = {
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            self.replace_assign(job, &p).await
        };
        let (pressed, mut notes) = match assigned {
            Ok(Assigned::Done { pressed, notes }) => (pressed, notes),
            Ok(Assigned::Failed(result)) => return result,
            Err(reason) => {
                return json!({
                    "ok": false,
                    "verified": false,
                    "written": false,
                    "reason": reason,
                });
            }
        };
        replace::forget_facts(&state.dir, target);

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
        let write = if plan["noop"] == true {
            None
        } else {
            let Some(digest) = plan["plan_digest"].as_str().map(str::to_string) else {
                return after_assign_failure(
                    &p,
                    &pressed,
                    notes,
                    format!(
                        "{target} has its address, but its plan carries nothing to write over \
                         this tool ({}); plan it with knx_plan_device",
                        plan["method"]
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
                    if plan["method"] == "flash" {
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
            tier.jobs.started(job, prepared.result.clone(), record);
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
            .is_none_or(|w| w["ok"] == true && w["verified"] == true);
        if !written_ok {
            let reason = write
                .as_ref()
                .and_then(|w| w["reason"].as_str())
                .unwrap_or("the write did not verify")
                .to_string();
            let mut result = after_assign_failure(
                &p,
                &pressed,
                notes,
                format!(
                    "{target} has its address, but the write of its application and links did \
                     not verify: {reason}"
                ),
            );
            result["write"] = write.unwrap_or(Value::Null);
            return result;
        }

        // The record: `replaced` in the device file, the serial in the lock.
        tier.jobs.step(job, "recording the replacement");
        let when = bussard_download::backup::rfc3339_utc(std::time::SystemTime::now());
        let recorded =
            replace::record(&state.dir, &p.replacement, pressed.serial.as_deref(), &when);
        let _ = state.model.reload();
        let recorded = match recorded {
            Ok(recorded) => json!({
                "replaced": when,
                "device_file": recorded
                    .device_file
                    .strip_prefix(&state.dir)
                    .unwrap_or(&recorded.device_file)
                    .display()
                    .to_string(),
                "serial_recorded": recorded.serial.as_ref().is_some_and(|s| s.changed()),
            }),
            Err(err) => {
                notes.push(format!(
                    "The replacement is on the bus and verified, but it was not recorded in the \
                     model: {}",
                    chain(&err)
                ));
                Value::Null
            }
        };
        done_result(&p, &pressed, write, recorded, notes)
    }

    /// The assign half of the write job: the fresh read against the digest,
    /// the download, the address and its read-back.
    async fn replace_assign(&self, job: &str, p: &PendingReplace) -> Result<Assigned, String> {
        let state = self.state();
        let tier = state
            .programming
            .as_ref()
            .ok_or("the programming tier is off")?;
        let dir = state.dir.clone();
        let service = state.bus.service().ok_or("the bus is not wired")?.clone();
        let source = service
            .checked_source(false)
            .await
            .map_err(|e| format!("the source address check failed: {e}"))?;
        let r = &p.replacement;
        let target = r.target;
        let current = p.pressed.address;

        // The fresh read: the same single device in programming mode, the
        // same identity, model and product, else the digest is stale.
        let now = in_programming_mode(&service, source)
            .await
            .map_err(|e| chain(&e))?;
        if now != [current] {
            return Err(format!(
                "the replacement is no longer the one device in programming mode at {current} \
                 (now: {}). Ask the human to press its programming button again, then call \
                 knx_replace_device again. Nothing was written.",
                if now.is_empty() {
                    "none".to_string()
                } else {
                    now.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
        }
        if let Some(occupant) = probe_occupant(&service, source, target).await {
            return Err(gone_refusal(target, &occupant.describe()));
        }
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
            let mut said = Collected::default();
            bussard_service::setup::products::fetch_missing(
                &dir,
                &[order],
                &mut Consented,
                &mut said,
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
        tier.jobs.step(job, format!("writing the address {target}"));
        write_address(&service, source, target)
            .await
            .map_err(|e| format!("broadcasting the new individual address: {}", chain(&e)))?;
        tier.jobs
            .step(job, format!("reading the device back at {target}"));
        let mut notes: Vec<String> = Vec::new();
        let verified =
            match verify_assignment_with(&service, source, target, true, &VerifyKey::default())
                .await
            {
                Ok(verified) => verified,
                Err(err) => {
                    return Ok(Assigned::Failed(json!({
                        "ok": false,
                        "verified": false,
                        "assigned": false,
                        "address": target.to_string(),
                        "from": current.to_string(),
                        "reason": chain(&err),
                        "recovery": format!(
                            "The address write to {target} could not be verified. Check the \
                             device with knx_show_device {{live: true}} and call \
                             knx_replace_device again."
                        ),
                    })));
                }
            };
        notes.extend(verified.warnings.iter().cloned());
        if !replace::same_hardware(&p.pressed, &verified) {
            return Ok(Assigned::Failed(json!({
                "ok": false,
                "verified": false,
                "assigned": true,
                "address": target.to_string(),
                "from": current.to_string(),
                "readback": {
                    "mask": verified.mask.map(|m| format!("{m:04X}")),
                    "serial": verified.serial.as_deref().map(hex),
                },
                "reason": format!(
                    "{target} now answers, but the read-back there does not match the identified \
                     serial or mask: another device may have taken the address. Nothing more \
                     was written."
                ),
                "recovery": format!(
                    "Check {target} with knx_show_device {{live: true}} before anything else is \
                     written to it."
                ),
            })));
        }
        if still_in_programming_mode(&service, source, target).await {
            notes.push(format!(
                "{target} is still in programming mode after the assignment; ask the human to \
                 press its programming button once to leave it (on KNX Virtual: toggle it off in \
                 the GUI)."
            ));
        }
        Ok(Assigned::Done {
            pressed: replace::assigned(p.pressed.clone(), &verified),
            notes,
        })
    }
}

/// How the assign half of the write job ended.
enum Assigned {
    /// The address took and read back as the identified device.
    Done {
        /// What was identified, merged with the read-back.
        pressed: Pressed,
        /// Notes for the human.
        notes: Vec<String>,
    },
    /// The address was written but did not verify: the job's result.
    Failed(Value),
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
fn backup(dir: &std::path::Path, model: &Model, r: &Replacement) -> Result<Value, String> {
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
    Ok(json!({
        "snapshot": snapshot,
        "device_file": relative,
        "name": r.name,
        "order_number": r.expected.order_number,
        "mask": r.expected.mask_text,
        "lock": {
            "application": lock.application,
            "application_id": lock.application_id,
            "product_sha256": lock.product_sha256,
            "serial_number": device.and_then(|d| d.lock.serial_number.clone()),
        },
        "sentence": match &snapshot {
            Some(id) => format!(
                "The model as it is now, {relative} and its bussard.lock record included, is \
                 kept as history snapshot {id}; `bussard history` puts it back."
            ),
            None => format!("{relative} has no history to snapshot into yet."),
        },
    }))
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

/// Who the device is, in words: its order number, else "A device".
fn who(pressed: &Pressed) -> String {
    pressed
        .order
        .clone()
        .unwrap_or_else(|| "A device".to_string())
}

/// The fields the `identified` step reports at the top of the job status.
fn identified_detail(
    model: &Model,
    r: &Replacement,
    p: &Pressed,
    source: &Source,
    digest: &str,
    tier: &ProgrammingTier,
) -> Value {
    let target = r.target;
    let mask = p.mask.map(|m| format!("{m:04X}"));
    let system = p.mask.map(bussard_mgmt::system_type);
    let check = r.identity_check(p);
    let mut sentences = vec![format!(
        "{} is in programming mode at {}{}{}, running {}.",
        who(p),
        p.address,
        p.serial
            .as_deref()
            .map(|s| format!(", serial {}", hex(s)))
            .unwrap_or_default(),
        match (&mask, system) {
            (Some(mask), Some(system)) => format!(", mask {mask} ({system})"),
            _ => String::new(),
        },
        p.application
            .as_deref()
            .map(|a| format!("application {a}"))
            .unwrap_or_else(|| "no readable application".to_string())
    )];
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
    let now = std::time::SystemTime::now();
    json!({
        "name": r.name,
        "current_address": p.address.to_string(),
        "serial": p.serial.as_deref().map(hex),
        "mask": mask,
        "system_type": system,
        "order_number": p.order,
        "resident_application": p.application,
        "identity": check.as_ref().map(|c| bussard_service::identity_line(target, c)),
        "application": application,
        "product_data": product_data,
        "download_needed": download_needed,
        "sentences": sentences,
        "plan_digest": digest,
        "expires_at": bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl),
    })
}

/// The result when the address took but the flash or the apply did not
/// complete: not recorded, with the recovery the CLI names.
fn after_assign_failure(
    p: &PendingReplace,
    pressed: &Pressed,
    notes: Vec<String>,
    reason: String,
) -> Value {
    let target = p.replacement.target;
    json!({
        "ok": false,
        "verified": false,
        "step": "done",
        "assigned": true,
        "address": target.to_string(),
        "from": pressed.address.to_string(),
        "reason": reason,
        "recorded": false,
        "notes": notes,
        "recovery": format!(
            "{target} has the right address but not yet the model's application and links. \
             Call knx_plan_device for {target}, show the plan to the human and apply it with \
             knx_apply_device after a yes; the replacement is recorded only by a complete run \
             (`bussard replace {target}` at the terminal)."
        ),
    })
}

/// The `done` result: names first, one summary sentence.
fn done_result(
    p: &PendingReplace,
    pressed: &Pressed,
    write: Option<Value>,
    recorded: Value,
    notes: Vec<String>,
) -> Value {
    let r = &p.replacement;
    let target = r.target;
    let flashed = write
        .as_ref()
        .is_some_and(|w| w["method"] == "flash" && w["ok"] == true);
    let how = match &write {
        None => "it already held the model's application, parameters and links".to_string(),
        Some(_) if flashed => {
            "the application was loaded with the model's parameters and links".to_string()
        }
        Some(_) => "the parameters and links in your project were written".to_string(),
    };
    let ok = !recorded.is_null();
    let summary = format!(
        "{} ({target}) is replaced: the device that was at {} now answers at {target}, {how}, \
         and the read-back matches your project{}.",
        r.name,
        pressed.address,
        if ok {
            "; the replacement is recorded in the device file and bussard.lock"
        } else {
            ", but the record in the model failed (see notes)"
        }
    );
    json!({
        "ok": ok,
        "verified": true,
        "step": "done",
        "name": r.name,
        "address": target.to_string(),
        "from": pressed.address.to_string(),
        "assigned": true,
        "flashed": flashed,
        "readback": {
            "mask": pressed.mask.map(|m| format!("{m:04X}")),
            "serial": pressed.serial.as_deref().map(hex),
            "order_number": pressed.order,
        },
        "write": write,
        "recorded": recorded,
        "notes": notes,
        "summary": summary,
        "next_step": format!(
            "Tell the human the summary. knx_plan_device for {target} should report nothing to \
             do; a fresh knx_backup_device run keeps the new device's state."
        ),
    })
}

impl ProgrammingTier {
    /// The identified replacements waiting for a yes, recovering from a
    /// poisoned lock.
    pub(super) fn replaces(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PendingReplace>> {
        self.replaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
